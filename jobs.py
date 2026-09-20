"""Batch jobs and SQLite persistence for Lehaipreshop."""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote, unquote, urlsplit

import collections
from auth.dependencies import AuthContext
from service import TwoFAService

logger = logging.getLogger("jobs")

JOB_TYPE = "lehaipreshop"
TERMINAL = {"success", "error", "cancelled"}
VALID_MODES = {"check_only", "change_2fa", "change_password", "change_password_and_2fa"}
PROXY_SCHEMES = {"http", "https", "socks5", "socks5h"}
PROXY_FAILURE_COOLDOWN_SECONDS = 300.0
PROXY_WAIT_TIMEOUT = 60.0


def normalize_proxy(proxy: str) -> str:
    """Normalize common one-line proxy formats to a URL."""
    raw = str(proxy or "").strip()
    if not raw:
        raise ValueError("Dòng proxy không được để trống")
    if "://" not in raw:
        parts = raw.split(":", 3)
        if len(parts) == 4 and parts[1].isdigit():
            host, port, username, password = parts
            raw = (
                f"http://{quote(username, safe='')}:{quote(password, safe='')}"
                f"@{host}:{port}"
            )
        elif "@" in raw:
            raw = f"http://{raw}"
        elif len(parts) == 2:
            host, port = parts
            raw = f"http://{host}:{port}"
        else:
            raise ValueError(
                "Proxy phải là host:port, host:port:user:pass hoặc URL đầy đủ"
            )

    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Port proxy không hợp lệ") from exc
    scheme = parsed.scheme.casefold()
    if scheme not in PROXY_SCHEMES:
        raise ValueError("Proxy chỉ hỗ trợ http, https, socks5 hoặc socks5h")
    if not parsed.hostname or port is None or not 1 <= port <= 65535:
        raise ValueError("Proxy phải có host và port hợp lệ")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Proxy không được chứa path, query hoặc fragment")

    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if password and not username:
        raise ValueError("Proxy có password nhưng thiếu username")
    if scheme in {"socks5", "socks5h"} and (username or password):
        raise ValueError("SOCKS proxy có user/password chưa hỗ trợ trong luồng browser")

    hostname = parsed.hostname.casefold()
    host = f"[{hostname}]" if ":" in hostname else hostname
    auth = ""
    if username:
        auth = quote(username, safe="")
        if password:
            auth += f":{quote(password, safe='')}"
        auth += "@"
    return f"{scheme}://{auth}{host}:{port}"


def normalize_proxy_pool(proxies: Any) -> list[str]:
    if not isinstance(proxies, list):
        raise ValueError("Danh sách proxy không hợp lệ")
    if len(proxies) > 500:
        raise ValueError("Danh sách proxy tối đa 500 dòng")
    normalized: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(proxies, start=1):
        if len(str(raw)) > 2048:
            raise ValueError(f"Proxy dòng {index} dài quá 2048 ký tự")
        try:
            proxy = normalize_proxy(str(raw))
        except ValueError as exc:
            raise ValueError(f"Proxy dòng {index}: {exc}") from exc
        if proxy in seen:
            raise ValueError(f"Proxy dòng {index} bị trùng với dòng trước")
        seen.add(proxy)
        normalized.append(proxy)
    return normalized


def proxy_label(proxy: str | None) -> str:
    if not proxy:
        return "DIRECT"
    parsed = urlsplit(proxy)
    host = parsed.hostname or "proxy"
    return f"{parsed.scheme.upper()} · {host}:{parsed.port}"


@dataclass(slots=True)
class TwoFAJob:
    id: str
    email: str
    password: str
    secret: str
    proxy: str | None = None
    proxy_slot: int | None = None
    last_failed_proxy: str | None = None
    mode: str = "change_2fa"
    status: str = "queued"
    error: str | None = None
    error_kind: str | None = None
    account_state: str = "unknown"
    plan: str | None = None
    plan_source: str | None = None
    plan_expires_at: str | None = None
    rotated_pending_verify: bool = False
    password_changed: bool = False   # password đã được đổi thành công
    login_verified: bool = False
    retry_count: int = 0
    new_password: str = ""           # password mới sau khi đổi (nếu mode có đổi pass)
    owner_user_id: int | None = None # ID người sở hữu job
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    logs: list[str] = field(default_factory=list)

    @property
    def retryable(self) -> bool:
        return self.error_kind not in {"account_die", "invalid_credentials"}

    def snapshot(self) -> dict[str, Any]:
        verify_failed = (
            self.status == "error"
            and self.rotated_pending_verify
            and not self.login_verified
        )
        return {
            "id": self.id,
            "email": self.email,
            "has_proxy": bool(self.proxy),
            "proxy_label": proxy_label(self.proxy),
            "proxy_slot": self.proxy_slot,
            "mode": self.mode,
            "status": self.status,
            "error": self.error,
            "error_kind": self.error_kind,
            "account_state": self.account_state,
            "plan": self.plan,
            "plan_source": self.plan_source,
            "plan_expires_at": self.plan_expires_at,
            "retryable": self.retryable,
            "rotated_pending_verify": self.rotated_pending_verify,
            "verify_failed": verify_failed,
            "password_changed": self.password_changed,
            "login_verified": self.login_verified,
            "retry_count": self.retry_count,
            "has_new_password": bool(self.new_password),
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "log_tail": self.logs[-3:],
            "owner_user_id": self.owner_user_id,
        }


@dataclass(slots=True, eq=False)
class Subscriber:
    queue: asyncio.Queue[dict[str, Any]]
    user_id: int | None
    is_admin: bool
    session_id: int | None
    revoked_event: asyncio.Event = field(default_factory=asyncio.Event)


class TwoFAJobManager:
    DEFAULTS = {
        "twofa.max_concurrent": 3,
        "twofa.job_timeout": 180,
        "twofa.auto_retry": False,
        "twofa.auto_retry_max": 1,
        "twofa.auto_retry_delay": 3,
        "twofa.change_enabled": False,
        "twofa.input_draft": "",
        "twofa.proxy_pool": [],
    }

    def __init__(self, job_repo, settings_repo, service: TwoFAService | None = None, user_repo: Any = None) -> None:
        self.job_repo = job_repo
        self.settings_repo = settings_repo
        self.user_repo = user_repo
        self.service = service or TwoFAService()
        self.jobs: dict[str, TwoFAJob] = {}
        self.order: list[str] = []
        self._queues_by_user: dict[int | None, asyncio.Queue[str]] = collections.defaultdict(asyncio.Queue)
        self._ready_users: collections.deque[int | None] = collections.deque()
        self._running_by_user: collections.defaultdict[int | None, int] = collections.defaultdict(int)
        self._workers: list[asyncio.Task] = []
        self._tasks: dict[str, asyncio.Task] = {}
        self._retire_lock = asyncio.Lock()
        self._scheduler_lock = asyncio.Lock()
        self._subscribers: set[Subscriber] = set()
        self._subscribers_by_session: dict[int, set[Subscriber]] = collections.defaultdict(set)
        self._proxy_cooldowns: dict[str, float] = {}
        self.settings = dict(self.DEFAULTS)
        self._load_settings()
        self._recover()

    @staticmethod
    def _legacy_error_metadata(error: Any) -> tuple[str | None, str]:
        if not isinstance(error, str) or not error.strip():
            return None, "unknown"
        from session_phase import classify_account_check_error, is_fatal_login_error

        if classify_account_check_error(error) == "deactivated":
            return "account_die", "die"
        if is_fatal_login_error(error):
            return "invalid_credentials", "unknown"
        return "technical_error", "unknown"

    def _load_settings(self) -> None:
        stored = self.settings_repo.list("twofa")
        self.settings.update({key: value for key, value in stored.items() if key in self.DEFAULTS})

    @staticmethod
    def parse_combo(line: str) -> tuple[str, str, str]:
        parts = [part.strip() for part in line.strip().split("|")]
        if len(parts) != 3 or not all(parts):
            raise ValueError("Định dạng phải là email|password|2FA_cũ")
        email, password, secret = parts
        if "@" not in email:
            raise ValueError("Email không hợp lệ")
        return email.casefold(), password, secret.replace(" ", "").upper()

    def _recover(self) -> None:
        for row in self.job_repo.list_all():
            if row.get("job_type") != JOB_TYPE:
                continue
            state = self._decode_state(row.get("account_check"))
            status = str(row.get("status") or "error")
            error = row.get("error")
            if status in {"running", "queued"}:
                status = "cancelled"
                error = "Đã dừng do hệ thống khởi động lại"
                self.job_repo.update_status(str(row["id"]), "cancelled", error=error)
            legacy_kind, legacy_account_state = self._legacy_error_metadata(row.get("error"))
            job = TwoFAJob(
                id=str(row["id"]),
                email=str(row["email"]),
                password=str(row.get("password") or ""),
                secret=str(row.get("secret") or ""),
                proxy=str(state.get("proxy") or "") or None,
                proxy_slot=int(state["proxy_slot"]) if state.get("proxy_slot") else None,
                last_failed_proxy=str(state.get("last_failed_proxy") or "") or None,
                mode=str(state.get("mode") or "change_2fa"),
                status=status,
                error=row.get("error"),
                error_kind=state.get("error_kind") or legacy_kind,
                account_state=str(state.get("account_state") or legacy_account_state),
                plan=state.get("plan"),
                plan_source=state.get("plan_source"),
                plan_expires_at=state.get("plan_expires_at"),
                rotated_pending_verify=bool(state.get("rotated_pending_verify")),
                password_changed=bool(state.get("password_changed")),
                login_verified=bool(state.get("login_verified")),
                retry_count=int(state.get("retry_count") or 0),
                new_password=str(state.get("new_password") or ""),
                created_at=float(row.get("created_at") or time.time()),
                started_at=row.get("started_at"),
                finished_at=row.get("finished_at"),
                logs=[str(item.get("line") or "") for item in self.job_repo.get_logs(str(row["id"]))],
                owner_user_id=row.get("owner_user_id"),
            )
            self.jobs[job.id] = job
            self.order.append(job.id)

    @staticmethod
    def _decode_state(raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str) and raw:
            try:
                value = json.loads(raw)
                return value if isinstance(value, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}

    def _state(self, job: TwoFAJob) -> str:
        return json.dumps({
            "rotated_pending_verify": job.rotated_pending_verify,
            "password_changed": job.password_changed,
            "login_verified": job.login_verified,
            "retry_count": job.retry_count,
            "mode": job.mode,
            "error_kind": job.error_kind,
            "account_state": job.account_state,
            "plan": job.plan,
            "plan_source": job.plan_source,
            "plan_expires_at": job.plan_expires_at,
            "new_password": job.new_password,
            "proxy": job.proxy,
            "proxy_slot": job.proxy_slot,
            "last_failed_proxy": job.last_failed_proxy,
        }, ensure_ascii=False)

    def _enqueue_job(self, job: TwoFAJob) -> None:
        uid = job.owner_user_id
        self._queues_by_user[uid].put_nowait(job.id)
        if uid not in self._ready_users:
            self._ready_users.append(uid)

    def start(self) -> None:
        self._running_by_user.clear()
        for job in self.jobs.values():
            if job.status == "queued":
                self._enqueue_job(job)
        self._spawn_workers(int(self.settings["twofa.max_concurrent"]))

    def _active_workers(self) -> list[asyncio.Task]:
        self._workers[:] = [task for task in self._workers if not task.done()]
        return self._workers

    def _spawn_workers(self, target: int) -> None:
        workers = self._active_workers()
        while len(workers) < target:
            task = asyncio.create_task(self._worker())
            workers.append(task)

    async def _claim_retirement(self) -> bool:
        async with self._retire_lock:
            workers = self._active_workers()
            target = int(self.settings["twofa.max_concurrent"])
            current = asyncio.current_task()
            if len(workers) <= target or current not in workers:
                return False
            workers.remove(current)
            return True

    async def _resize_workers(self, previous: int, target: int) -> None:
        workers = self._active_workers()
        if target > len(workers):
            self._spawn_workers(target)
            return

    async def shutdown(self) -> None:
        for task in list(self._tasks.values()) + self._workers:
            task.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    def add(self, lines: list[str], mode: str = "change_2fa", actor: AuthContext | None = None) -> list[dict[str, Any]]:
        if mode not in VALID_MODES:
            raise ValueError(f"Chế độ phải là một trong: {', '.join(sorted(VALID_MODES))}")

        owner_uid = actor.user_id if actor else None
        is_admin = actor.is_admin if actor else True

        if not is_admin:
            if len(lines) > 50:
                raise ValueError("Cộng tác viên chỉ được gửi tối đa 50 tài khoản mỗi lần")
            active_count = sum(
                1 for j in self.jobs.values()
                if j.owner_user_id == owner_uid and j.status in ("queued", "running")
            )
            if active_count + len(lines) > 100:
                raise ValueError("Đã vượt hạn mức 100 job đang hoạt động của tài khoản")

        parsed_lines: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        for line in lines:
            email, password, secret = self.parse_combo(line)
            if email in seen:
                continue
            seen.add(email)
            parsed_lines.append((email, password, secret))

        proxies = normalize_proxy_pool(self.settings.get("twofa.proxy_pool") or [])

        created: list[dict[str, Any]] = []
        for index, (email, password, secret) in enumerate(parsed_lines):
            if proxies:
                proxy_index = index % len(proxies)
                proxy_slot, assigned_proxy = proxy_index + 1, proxies[proxy_index]
            else:
                proxy_slot, assigned_proxy = None, None
            job = TwoFAJob(
                id=uuid.uuid4().hex,
                email=email,
                password=password,
                secret=secret,
                proxy=assigned_proxy,
                proxy_slot=proxy_slot,
                mode=mode,
                owner_user_id=owner_uid,
            )

            # 1. Ghi Database trước (Atomicity)
            self.job_repo.create({
                "id": job.id,
                "email": email,
                "combo": "[redacted]",
                "mail_mode": "none",
                "status": "queued",
                "password": password,
                "secret": secret,
                "account_check": self._state(job),
                "created_at": job.created_at,
                "job_type": JOB_TYPE,
                "owner_user_id": owner_uid,
            })

            # 2. Chỉ khi DB thành công mới nạp vào RAM và Queue
            self.jobs[job.id] = job
            self.order.append(job.id)
            self._enqueue_job(job)

            created.append(job.snapshot())
            self._broadcast_job(job, {"type": "job", "job": job.snapshot()})
        return created

    async def _pick_next_job_id(self) -> tuple[str | None, int | None]:
        """Chọn job tiếp theo theo cơ chế Round-Robin users với per-user running cap = 2."""
        async with self._scheduler_lock:
            if not self._ready_users:
                return None, None

            num_users = len(self._ready_users)
            for _ in range(num_users):
                uid = self._ready_users.popleft()
                queue = self._queues_by_user[uid]
                if queue.empty():
                    continue

                if uid is not None and self._running_by_user[uid] >= 2:
                    self._ready_users.append(uid)
                    continue

                try:
                    job_id = queue.get_nowait()
                except asyncio.QueueEmpty:
                    continue

                if not queue.empty():
                    self._ready_users.append(uid)

                return job_id, uid

            return None, None

    async def _worker(self) -> None:
        while True:
            job_id, uid = await self._pick_next_job_id()
            if not job_id:
                await asyncio.sleep(0.25)
                continue

            job = self.jobs.get(job_id)
            if job and job.status == "queued":
                self._running_by_user[uid] += 1
                try:
                    task = asyncio.create_task(self._run(job))
                    self._tasks[job.id] = task
                    await task
                except asyncio.CancelledError:
                    # Truyền tiếp CancelledError để shutdown và resize worker hoạt động đúng
                    raise
                except Exception as exc:
                    # Lớp bảo vệ dự phòng (Defense-in-depth) đảm bảo worker không crash
                    await self._fail_job(job, exc)
                finally:
                    self._running_by_user[uid] = max(0, self._running_by_user[uid] - 1)
                    self._tasks.pop(job_id, None)

    async def _fail_job(self, job: TwoFAJob, exc: BaseException) -> None:
        """Fallback finalizer an toàn ở cấp class: đưa job về trạng thái error và phục hồi."""
        # 1. Guard check: chỉ xử lý nếu job chưa ở terminal state
        if job.status not in {"queued", "running"}:
            return

        logger.exception("Job %s encountered unexpected failure: %s", job.id, exc)

        # 2. Cập nhật RAM trước (đảm bảo tính toàn vẹn trạng thái trong bộ nhớ)
        job.status = "error"
        job.error = (str(exc).strip() or type(exc).__name__)[:240]
        job.error_kind = str(getattr(exc, "error_kind", "technical_error"))
        job.account_state = str(getattr(exc, "account_state", job.account_state))
        job.finished_at = time.time()
        if job.proxy and job.retryable:
            job.last_failed_proxy = job.proxy
            self._mark_proxy_failed(job.proxy)

        # 3. Best-effort ghi DB độc lập
        try:
            self.job_repo.update_status(
                job.id, "error", error=job.error,
                secret=job.secret, account_check=self._state(job),
            )
        except Exception as db_exc:
            logger.error("Failed to persist job failure to DB for job %s: %s", job.id, db_exc)

        # 4. Best-effort ghi log error độc lập
        try:
            stamped = f"{time.strftime('%H:%M:%S')}  [lỗi hệ thống] {job.error}"
            job.logs.append(stamped)
            if job.rotated_pending_verify:
                job.logs.append(
                    f"{time.strftime('%H:%M:%S')}  [verify-failed] 2FA mới đã được lưu nhưng bước xác minh thất bại"
                )
            job.logs[:] = job.logs[-300:]
            self.job_repo.append_log(job.id, stamped)
        except Exception as log_exc:
            logger.error("Failed to append error log for job %s: %s", job.id, log_exc)

        # 5. Best-effort broadcast độc lập
        try:
            self._broadcast(job)
        except Exception as bc_exc:
            logger.error("Failed to broadcast job failure for job %s: %s", job.id, bc_exc)

        # 6. Kích hoạt Auto-Retry nếu job thỏa mãn điều kiện
        try:
            if self._should_auto_retry(job):
                delay = float(self.settings.get("twofa.auto_retry_delay") or 15.0)
                asyncio.create_task(self._delayed_retry(job.id, delay))
        except Exception as retry_exc:
            logger.error("Failed to trigger auto retry for job %s: %s", job.id, retry_exc)

    def _mark_proxy_failed(self, proxy: str) -> None:
        if proxy not in self._proxy_cooldowns:
            self._proxy_cooldowns[proxy] = time.time() + PROXY_FAILURE_COOLDOWN_SECONDS

    def _active_proxy_cooldowns(self) -> set[str]:
        now = time.time()
        expired = [proxy for proxy, until in self._proxy_cooldowns.items() if until <= now]
        for proxy in expired:
            self._proxy_cooldowns.pop(proxy, None)
        return set(self._proxy_cooldowns)

    def _pick_available_proxy(self, job: TwoFAJob, proxies: list[str]) -> tuple[int, str] | None:
        active = {
            item.proxy for item in self.jobs.values()
            if item.id != job.id and item.status == "running" and item.proxy
        }
        blocked = active | self._active_proxy_cooldowns()
        if job.proxy in proxies:
            start = proxies.index(job.proxy)
        elif job.last_failed_proxy in proxies:
            start = (proxies.index(job.last_failed_proxy) + 1) % len(proxies)
        elif job.proxy_slot:
            start = (job.proxy_slot - 1) % len(proxies)
        else:
            start = self.order.index(job.id) % len(proxies)

        for offset in range(len(proxies)):
            index = (start + offset) % len(proxies)
            proxy = proxies[index]
            if proxy not in blocked:
                return index + 1, proxy
        return None

    async def _prepare_proxy(self, job: TwoFAJob, log_fn: Callable[[str], None] | None = None) -> None:
        start_time = time.time()
        notified_waiting = False
        while True:
            proxies = normalize_proxy_pool(self.settings.get("twofa.proxy_pool") or [])
            if not proxies:
                job.proxy = None
                job.proxy_slot = None
                return
            selected = self._pick_available_proxy(job, proxies)
            if selected:
                job.proxy_slot, job.proxy = selected
                return

            if not notified_waiting and log_fn:
                log_fn(f"[chờ proxy] Tất cả proxy ({len(proxies)}) đang bận hoặc tạm nghỉ, đang đợi proxy rảnh...")
                notified_waiting = True

            if time.time() - start_time > PROXY_WAIT_TIMEOUT:
                raise TimeoutError(
                    f"Hết thời gian chờ proxy khả dụng ({int(PROXY_WAIT_TIMEOUT)}s) — tất cả proxy trong pool đều bận hoặc tạm nghỉ"
                )
            await asyncio.sleep(0.5)

    async def _run(self, job: TwoFAJob) -> None:
        # Chuyển trạng thái running ngay khi bắt đầu và broadcast tức thì về giao diện
        job.status = "running"
        job.error = None
        job.started_at = time.time()
        try:
            self.job_repo.update_status(job.id, "running", account_check=self._state(job))
        except Exception as e:
            logger.error("Failed to update status running in DB for %s: %s", job.id, e)
        self._broadcast(job)

        def log(message: str) -> None:
            safe = str(message)
            proxy_parts = urlsplit(job.proxy) if job.proxy else None
            proxy_secrets = {
                proxy_parts.username or "",
                proxy_parts.password or "",
                unquote(proxy_parts.username or ""),
                unquote(proxy_parts.password or ""),
            } if proxy_parts else set()
            proxy_secrets = {item for item in proxy_secrets if len(item) >= 4}
            for sensitive in {
                job.password, job.secret, job.new_password, job.proxy or "", *proxy_secrets
            }:
                if sensitive:
                    safe = safe.replace(sensitive, "***")
            stamped = f"{time.strftime('%H:%M:%S')}  {safe[:500]}"
            job.logs.append(stamped)
            job.logs[:] = job.logs[-300:]
            try:
                self.job_repo.append_log(job.id, stamped)
            except Exception as e:
                logger.error("Failed to append log in DB for %s: %s", job.id, e)
            self._broadcast(job)

        async def checkpoint(new_secret: str) -> None:
            job.secret = new_secret
            job.rotated_pending_verify = True
            job.login_verified = False
            try:
                self.job_repo.update_status(
                    job.id,
                    "running",
                    secret=new_secret,
                    password=job.password,
                    account_check=self._state(job),
                )
            except Exception as e:
                logger.error("Failed to update checkpoint in DB for %s: %s", job.id, e)
            self._broadcast(job)

        async def password_checkpoint(new_pass: str, new_secret: str) -> None:
            """Checkpoint sau khi đổi password (và có thể cả secret)."""
            effective_pass = new_pass or job.password
            effective_secret = new_secret or job.secret
            job.new_password = effective_pass
            job.password_changed = True
            if new_secret and new_secret != job.secret:
                job.secret = effective_secret
                job.rotated_pending_verify = True
            try:
                self.job_repo.update_status(
                    job.id,
                    "running",
                    secret=effective_secret,
                    password=effective_pass,
                    account_check=self._state(job),
                )
            except Exception as e:
                logger.error("Failed to update password checkpoint in DB for %s: %s", job.id, e)
            self._broadcast(job)

        try:
            # 1. Chuẩn bị proxy với timeout và log chờ
            await self._prepare_proxy(job, log_fn=log)

            timeout = float(self.settings.get("twofa.job_timeout") or 180.0)
            if job.proxy:
                log(
                    f"[proxy] Proxy #{job.proxy_slot or 1} · {proxy_label(job.proxy)} "
                    "· gán theo vòng xoay proxy"
                )
            else:
                log("[proxy] DIRECT · chưa cấu hình proxy cho tài khoản này")

            # 2. Quyết định flow dựa trên mode và checkpoint state
            if job.mode == "check_only":
                result = await self.service.check(
                    email=job.email,
                    password=job.password,
                    secret=job.secret,
                    proxy=job.proxy,
                    timeout=timeout,
                    log=log,
                )
            elif job.mode == "change_password":
                result = await self.service.change_password(
                    email=job.email,
                    password=job.new_password or job.password,
                    secret=job.secret,
                    proxy=job.proxy,
                    timeout=timeout,
                    checkpoint=password_checkpoint,
                    log=log,
                )
            elif job.mode == "change_password_and_2fa":
                if job.rotated_pending_verify and job.password_changed:
                    # Password đã đổi và secret mới đã lưu — chỉ cần verify
                    result = await self.service.verify(
                        email=job.email,
                        password=job.new_password or job.password,
                        new_secret=job.secret,
                        proxy=job.proxy,
                        timeout=timeout,
                        log=log,
                    )
                else:
                    result = await self.service.rotate_with_password(
                        email=job.email,
                        password=job.new_password or job.password,
                        old_secret=job.secret,
                        proxy=job.proxy,
                        timeout=timeout,
                        checkpoint=password_checkpoint,
                        log=log,
                    )
            elif job.rotated_pending_verify:
                result = await self.service.verify(
                    email=job.email,
                    password=job.password,
                    new_secret=job.secret,
                    proxy=job.proxy,
                    timeout=timeout,
                    log=log,
                )
            else:
                result = await self.service.rotate(
                    email=job.email,
                    password=job.password,
                    old_secret=job.secret,
                    proxy=job.proxy,
                    timeout=timeout,
                    checkpoint=checkpoint,
                    log=log,
                )

            # 3. Ghi nhận kết quả thành công
            job.secret = result.secret
            if job.mode in {"change_password", "change_password_and_2fa"} and job.new_password:
                job.password = job.new_password
            job.login_verified = result.login_verified
            job.account_state = result.account_state
            job.plan = result.plan
            job.plan_source = result.plan_source
            job.plan_expires_at = result.plan_expires_at
            job.error_kind = None
            job.last_failed_proxy = None
            job.rotated_pending_verify = False
            job.status = "success"
            job.finished_at = time.time()
            try:
                self.job_repo.update_status(
                    job.id, "success", secret=job.secret,
                    password=job.password, account_check=self._state(job),
                )
            except Exception as e:
                logger.error("Failed to update success status in DB for %s: %s", job.id, e)
            self._broadcast(job)

        except asyncio.CancelledError:
            job.status = "cancelled"
            job.error = "Đã dừng bởi người dùng"
            job.finished_at = time.time()
            try:
                self.job_repo.update_status(
                    job.id, "cancelled", error=job.error,
                    secret=job.secret, account_check=self._state(job),
                )
            except Exception as e:
                logger.error("Failed to update cancelled status in DB for %s: %s", job.id, e)
            self._broadcast(job)

        except Exception as exc:
            await self._fail_job(job, exc)

    def _should_auto_retry(self, job: TwoFAJob) -> bool:
        return (
            job.retryable
            and bool(self.settings["twofa.auto_retry"])
            and job.retry_count < int(self.settings["twofa.auto_retry_max"])
        )

    async def _delayed_retry(self, job_id: str, delay: float) -> None:
        await asyncio.sleep(delay)
        if job_id in self.jobs and self.jobs[job_id].status == "error":
            try:
                self._retry_internal(self.jobs[job_id])
            except Exception:
                pass

    def _require_access(self, job_id: str, actor: AuthContext | None = None) -> TwoFAJob:
        job = self._require(job_id)
        if actor is None or actor.is_admin:
            return job
        if job.owner_user_id != actor.user_id:
            raise KeyError(job_id)
        return job

    def retry(self, job_id: str, actor: AuthContext | None = None) -> dict[str, Any]:
        job = self._require_access(job_id, actor)
        return self._retry_internal(job)

    def _retry_internal(self, job: TwoFAJob) -> dict[str, Any]:
        if job.status not in TERMINAL:
            raise ValueError("Job đang chạy hoặc đang chờ")
        if not job.retryable:
            label = "tài khoản die" if job.error_kind == "account_die" else "sai thông tin đăng nhập/2FA"
            raise ValueError(f"Không retry tự động: {label}")

        if job.owner_user_id is not None and self.user_repo is not None:
            owner = self.user_repo.get_by_id(job.owner_user_id)
            if not owner or owner.get("status") != "active":
                job.status = "error"
                job.error = "Tài khoản người tạo đã bị khóa"
                self.job_repo.update_status(job.id, "error", error=job.error)
                self._broadcast_job(job, {"type": "job", "job": job.snapshot()})
                return job.snapshot()

        proxies = normalize_proxy_pool(self.settings.get("twofa.proxy_pool") or [])
        if job.status == "error" and job.proxy:
            job.last_failed_proxy = job.proxy
            self._mark_proxy_failed(job.proxy)
            job.proxy = None
            job.proxy_slot = None
        elif job.proxy:
            if job.proxy in proxies:
                job.proxy_slot = proxies.index(job.proxy) + 1
        if proxies and not job.proxy:
            selected = self._pick_available_proxy(job, proxies)
            if selected:
                job.proxy_slot, job.proxy = selected
        job.retry_count += 1
        job.status = "queued"
        job.error = None
        job.error_kind = None
        job.finished_at = None
        self.job_repo.update_status(
            job.id, "queued", secret=job.secret,
            password=job.new_password or job.password, account_check=self._state(job),
        )
        self._enqueue_job(job)
        self._broadcast_job(job, {"type": "job", "job": job.snapshot()})
        return job.snapshot()

    def stop(self, job_id: str, actor: AuthContext) -> dict[str, Any]:
        job = self._require_access(job_id, actor)
        task = self._tasks.get(job_id)
        if task and not task.done():
            task.cancel()
        if job.status in {"queued", "running"}:
            job.status = "cancelled"
            job.error = "Đã dừng bởi người dùng"
            job.finished_at = time.time()
            self.job_repo.update_status(
                job.id, "cancelled", error=job.error,
                secret=job.secret, account_check=self._state(job),
            )
            self._broadcast_job(job, {"type": "job", "job": job.snapshot()})
        return job.snapshot()

    def stop_all(self, actor: AuthContext) -> None:
        target_jobs = [
            j for j in self.jobs.values()
            if (actor.is_admin or j.owner_user_id == actor.user_id)
            and j.status in {"queued", "running"}
        ]
        for job in target_jobs:
            task = self._tasks.get(job.id)
            if task and not task.done():
                task.cancel()
            job.status = "cancelled"
            job.error = "Đã dừng bởi người dùng"
            job.finished_at = time.time()
            self.job_repo.update_status(
                job.id, "cancelled", error=job.error,
                secret=job.secret, account_check=self._state(job),
            )
            self._broadcast_job(job, {"type": "job", "job": job.snapshot()})

    async def stop_all_for_user(self, user_id: int) -> None:
        """Dừng tất cả job của user_id khi Admin vô hiệu hóa tài khoản."""
        target_jobs = [
            j for j in self.jobs.values()
            if j.owner_user_id == user_id and j.status in {"queued", "running"}
        ]
        for job in target_jobs:
            task = self._tasks.get(job.id)
            if task:
                task.cancel()
            elif job.status == "queued":
                job.status = "cancelled"
                job.error = "Tài khoản bị vô hiệu hóa bởi Quản trị viên"
                self.job_repo.update_status(job.id, "cancelled", error=job.error)
                self._broadcast_job(job, {"type": "job", "job": job.snapshot()})

    def delete(self, job_id: str, actor: AuthContext) -> None:
        job = self._require_access(job_id, actor)
        if job.status not in TERMINAL:
            raise ValueError("Không thể xóa job đang chạy")
        owner_uid = job.owner_user_id
        self.job_repo.delete(job_id)
        self.jobs.pop(job_id, None)
        self.order = [item for item in self.order if item != job_id]
        payload = {"type": "removed", "id": job_id}
        self._broadcast_user(owner_uid, payload)
        if owner_uid is not None:
            self._broadcast_admin(payload)

    def clear(self, actor: AuthContext) -> int:
        if actor.is_admin:
            if any(job.status not in TERMINAL for job in self.jobs.values()):
                raise ValueError("Hãy dừng toàn bộ job trước khi dọn danh sách")
            count = self.job_repo.delete_all(JOB_TYPE)
            self.jobs.clear()
            self.order.clear()
            self._broadcast_raw({"type": "snapshot", "jobs": []})
            return count
        else:
            user_jobs = [
                j for j in self.jobs.values()
                if j.owner_user_id == actor.user_id
            ]
            if any(j.status not in TERMINAL for j in user_jobs):
                raise ValueError("Hãy dừng các job của bạn trước khi dọn danh sách")
            count = 0
            for j in user_jobs:
                self.job_repo.delete(j.id)
                self.jobs.pop(j.id, None)
                count += 1
            self.order = [item for item in self.order if item in self.jobs]
            self._broadcast_user(actor.user_id, {"type": "snapshot", "jobs": []})
            return count

    @staticmethod
    def _combo_line(job: TwoFAJob) -> str:
        effective_pass = job.new_password if (job.new_password and job.mode in {
            "change_password", "change_password_and_2fa"
        }) else job.password
        return "|".join((job.email, effective_pass, job.secret))

    def output(self, actor: AuthContext) -> list[str]:
        lines = []
        for job_id in self.order:
            job = self.jobs.get(job_id)
            if not job:
                continue
            if job.status != "success" or not job.login_verified:
                continue
            if not actor.is_admin and job.owner_user_id != actor.user_id:
                continue
            lines.append(self._combo_line(job))
        return lines

    def failed_output(self, actor: AuthContext) -> list[str]:
        lines = []
        for job_id in self.order:
            job = self.jobs.get(job_id)
            if not job or job.status not in {"error", "cancelled"}:
                continue
            if not actor.is_admin and job.owner_user_id != actor.user_id:
                continue
            lines.append(self._combo_line(job))
        return lines

    def snapshots(self, actor: AuthContext) -> list[dict[str, Any]]:
        if actor.is_admin:
            return [self.jobs[job_id].snapshot() for job_id in self.order if job_id in self.jobs]
        return [
            self.jobs[job_id].snapshot()
            for job_id in self.order
            if job_id in self.jobs and self.jobs[job_id].owner_user_id == actor.user_id
        ]

    def logs(self, job_id: str, actor: AuthContext) -> list[str]:
        return list(self._require_access(job_id, actor).logs)

    async def update_settings(self, values: dict[str, Any]) -> dict[str, Any]:
        previous = int(self.settings["twofa.max_concurrent"])
        for key, value in values.items():
            if key not in self.DEFAULTS:
                raise ValueError(f"Setting không hỗ trợ: {key}")
            if key == "twofa.proxy_pool":
                value = normalize_proxy_pool(value)
            self.settings_repo.set(key, value)
            self.settings[key] = value
        target = int(self.settings["twofa.max_concurrent"])
        if target != previous:
            await self._resize_workers(previous, target)
        return dict(self.settings)

    def subscribe(self, actor: AuthContext) -> Subscriber:
        sub = Subscriber(
            queue=asyncio.Queue(maxsize=100),
            user_id=actor.user_id,
            is_admin=actor.is_admin,
            session_id=actor.session_id,
        )
        self._subscribers.add(sub)
        if actor.session_id is not None:
            self._subscribers_by_session[actor.session_id].add(sub)
        return sub

    def unsubscribe(self, sub: Subscriber) -> None:
        self._subscribers.discard(sub)
        if sub.session_id is not None:
            self._subscribers_by_session[sub.session_id].discard(sub)

    def revoke_session_streams(self, session_id: int) -> None:
        subs = list(self._subscribers_by_session.get(session_id, set()))
        for sub in subs:
            sub.revoked_event.set()

    def revoke_multiple_sessions(self, session_ids: list[int]) -> None:
        for sid in session_ids:
            self.revoke_session_streams(sid)

    def _broadcast(self, job: TwoFAJob) -> None:
        """Phát sự kiện cập nhật job snapshot đến đúng đối tượng theo phân quyền."""
        self._broadcast_job(job, {"type": "job", "job": job.snapshot()})

    def _broadcast_job(self, job: TwoFAJob, payload: dict[str, Any]) -> None:
        for sub in list(self._subscribers):
            if sub.is_admin or (job.owner_user_id is not None and sub.user_id == job.owner_user_id):
                self._send_sub(sub, payload)

    def _broadcast_user(self, user_id: int | None, payload: dict[str, Any]) -> None:
        if user_id is None:
            self._broadcast_admin(payload)
            return
        for sub in list(self._subscribers):
            if sub.user_id == user_id:
                self._send_sub(sub, payload)

    def _broadcast_admin(self, payload: dict[str, Any]) -> None:
        for sub in list(self._subscribers):
            if sub.is_admin:
                self._send_sub(sub, payload)

    def _broadcast_raw(self, payload: dict[str, Any]) -> None:
        for sub in list(self._subscribers):
            self._send_sub(sub, payload)

    @staticmethod
    def _send_sub(sub: Subscriber, payload: dict[str, Any]) -> None:
        if sub.queue.full():
            try:
                sub.queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        sub.queue.put_nowait(payload)

    def _require(self, job_id: str) -> TwoFAJob:
        job = self.jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        return job
