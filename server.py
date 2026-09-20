"""Local FastAPI control plane for Lehaipreshop."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import shutil
import sqlite3
import sys
import threading
import time
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import certifi
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


APP_DIR = Path(__file__).resolve().parent


def _resolve_source_root(app_dir: Path) -> Path:
    """Support both monorepo development and one-folder source releases."""
    standalone_markers = (
        app_dir / "_camoufox_runtime.py",
        app_dir / "db" / "__init__.py",
        app_dir / "camoufox-browser-spec.txt",
    )
    return app_dir if all(path.is_file() for path in standalone_markers) else app_dir.parent


ROOT = _resolve_source_root(APP_DIR)
STATIC_DIR = APP_DIR / "static"
LEGACY_RUNTIME_DIR = APP_DIR / "runtime"


def resolve_runtime_dir(
    platform: str | None = None,
    environ: dict[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Return the native per-user data directory for the current platform."""
    platform_name = platform or sys.platform
    environment = os.environ if environ is None else environ
    user_home = Path.home() if home is None else home
    if platform_name.startswith("win"):
        base = Path(environment.get("LOCALAPPDATA", user_home / "AppData" / "Local"))
    elif platform_name == "darwin":
        base = user_home / "Library" / "Application Support"
    else:
        base = Path(environment.get("XDG_DATA_HOME", user_home / ".local" / "share"))
    return base / "Lehaipreshop" / "Change2FA"


RUNTIME_DIR = resolve_runtime_dir()
DB_PATH = RUNTIME_DIR / "twofa.db"
RUNTIME_PORT = 5033


def _migrate_legacy_database() -> None:
    """Copy the source-mode database once; never bundle it into a release."""
    legacy = LEGACY_RUNTIME_DIR / "twofa.db"
    if DB_PATH.exists() or not legacy.is_file() or legacy.resolve() == DB_PATH.resolve():
        return
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    source = sqlite3.connect(f"file:{legacy.as_posix()}?mode=ro", uri=True)
    target = sqlite3.connect(DB_PATH)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def _prepare_runtime() -> None:
    """Keep Python I/O and TLS certificate paths safe in frozen builds."""
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    source = Path(certifi.where())
    if not source.is_file():
        raise RuntimeError(f"Không tìm thấy CA bundle: {source}")
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    target = RUNTIME_DIR / "cacert.pem"
    if not target.exists() or source.read_bytes() != target.read_bytes():
        shutil.copy2(source, target)
    for key in ("CURL_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        os.environ[key] = str(target)


_prepare_runtime()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from _camoufox_runtime import configure_camoufox_cache  # noqa: E402

configure_camoufox_cache(ROOT)

from db import get_engine, get_repos, get_settings_repo  # noqa: E402
from jobs import TwoFAJobManager, normalize_proxy, proxy_label  # noqa: E402
from auth.crypto import generate_csrf_token  # noqa: E402
from auth.dependencies import AuthContext, create_auth_dependencies, resolve_csrf_secret  # noqa: E402
from auth.models import (  # noqa: E402
    AdminBootstrapResponse,
    CollaboratorBootstrapResponse,
    CollaboratorCapabilities,
    UserPublic,
)
from auth.repositories import AuditRepository, SessionRepository, UserRepository  # noqa: E402
from auth.routes import create_auth_routers  # noqa: E402


RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
_migrate_legacy_database()


class BatchRequest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=500)
    mode: str = Field(pattern="^(check_only|change_2fa|change_password|change_password_and_2fa)$")


class SettingsRequest(BaseModel):
    max_concurrent: int = Field(ge=1, le=10)
    job_timeout: float = Field(ge=30, le=600)
    auto_retry: bool
    auto_retry_max: int = Field(ge=0, le=5)
    auto_retry_delay: float = Field(ge=0, le=60)
    change_enabled: bool
    input_draft: str = Field(default="", max_length=1_000_000)
    proxy_pool: list[str] = Field(default_factory=list, max_length=500)
    proxy_mode: str = Field(default="random_per_account", pattern="^(random_per_account|manual_per_worker)$")
    proxy_bindings: dict[str, Any] = Field(default_factory=dict)


class ProxyTestRequest(BaseModel):
    proxies: list[str] = Field(min_length=1, max_length=500)


engine = get_engine(str(DB_PATH))
_, job_repo, _ = get_repos(engine)
settings_repo = get_settings_repo(engine)

user_repo = UserRepository(engine)
session_repo = SessionRepository(engine)
audit_repo = AuditRepository(engine)

# Khởi tạo Admin ban đầu từ biến môi trường nếu DB chưa có
user_repo.seed_admin_from_env(ROOT)

csrf_secret = resolve_csrf_secret(RUNTIME_DIR)
get_current_user, require_admin, require_csrf = create_auth_dependencies(session_repo, csrf_secret)

manager = TwoFAJobManager(job_repo, settings_repo, user_repo=user_repo)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    manager.start()
    yield
    await manager.shutdown()
    engine.close()


app = FastAPI(
    title="Lehaipreshop",
    description="Local-only Password and TOTP control plane",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

auth_router, admin_router = create_auth_routers(
    user_repo=user_repo,
    session_repo=session_repo,
    audit_repo=audit_repo,
    manager=manager,
    csrf_secret=csrf_secret,
    get_current_user=get_current_user,
    require_admin=require_admin,
    require_csrf=require_csrf,
)
app.include_router(auth_router)
app.include_router(admin_router)


@app.get("/api/bootstrap")
async def bootstrap(actor: AuthContext = Depends(get_current_user)) -> dict[str, Any]:
    csrf_token = generate_csrf_token(csrf_secret, actor.raw_token)
    user_dto = UserPublic(id=actor.user_id, username=actor.username, role=actor.role, status="active")
    if actor.is_admin:
        return AdminBootstrapResponse(
            brand="Lehaipreshop",
            product="Lehaipreshop",
            user=user_dto,
            csrf_token=csrf_token,
            jobs=manager.snapshots(actor),
            settings=manager.settings,
            capabilities={"is_admin": True, "can_configure_settings": True, "can_manage_proxies": True},
        ).model_dump()
    return CollaboratorBootstrapResponse(
        brand="Lehaipreshop",
        product="Lehaipreshop",
        user=user_dto,
        csrf_token=csrf_token,
        jobs=manager.snapshots(actor),
        capabilities=CollaboratorCapabilities(),
    ).model_dump()


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "port": RUNTIME_PORT}


@app.api_route("/actuator/health", methods=["GET", "HEAD"])
@app.api_route("/actuator/health/", methods=["GET", "HEAD"])
def actuator_health() -> dict[str, Any]:
    """Endpoint sức khỏe công khai chuẩn Spring Boot Actuator phục vụ Render và Uptime monitoring."""
    return {"status": "UP"}


def _test_proxy_sync(index: int, raw_proxy: str, timeout: float = 12.0) -> dict[str, Any]:
    from curl_cffi import requests as curl_requests
    from user_agent_profile import CURL_IMPERSONATE_PRIMARY

    started_at = time.perf_counter()
    checked_at = time.strftime("%H:%M:%S")
    try:
        proxy = normalize_proxy(raw_proxy)
    except ValueError as exc:
        return {
            "index": index,
            "ok": False,
            "status": None,
            "latency_ms": None,
            "exit_ip": None,
            "country": None,
            "checked_at": checked_at,
            "label": f"Proxy #{index}",
            "detail": str(exc),
            "kind": "invalid",
        }

    request_proxy = proxy
    if request_proxy.startswith("socks5://"):
        request_proxy = "socks5h://" + request_proxy[len("socks5://"):]
    session = curl_requests.Session(impersonate=CURL_IMPERSONATE_PRIMARY)
    session.trust_env = False
    session.proxies = {"http": request_proxy, "https": request_proxy}
    exit_ip = None
    country = None
    try:
        trace_response = session.get(
            "https://www.cloudflare.com/cdn-cgi/trace",
            timeout=timeout,
            allow_redirects=False,
        )
        trace = {}
        if trace_response.status_code == 200:
            trace = dict(
                line.split("=", 1)
                for line in trace_response.text.splitlines()
                if "=" in line
            )
        exit_ip = trace.get("ip")
        country = trace.get("loc")
        status_code = trace_response.status_code
        latency_ms = round((time.perf_counter() - started_at) * 1000)
        ok = bool(exit_ip) and 200 <= status_code < 400
        if ok:
            detail = "Đã lấy IP thoát hiện tại"
            kind = "ok"
        elif status_code == 403:
            detail = "Dịch vụ kiểm tra IP từ chối proxy (HTTP 403)"
            kind = "blocked"
        elif status_code == 407:
            detail = "Sai user/password proxy (HTTP 407)"
            kind = "auth"
        elif status_code == 429:
            detail = "Dịch vụ kiểm tra IP đang giới hạn proxy (HTTP 429)"
            kind = "blocked"
        elif status_code == 200:
            detail = "Proxy trả về phản hồi không hợp lệ"
            kind = "error"
        else:
            detail = f"Dịch vụ kiểm tra IP trả về HTTP {status_code}"
            kind = "error"
        return {
            "index": index,
            "ok": ok,
            "status": status_code,
            "latency_ms": latency_ms,
            "exit_ip": exit_ip,
            "country": country,
            "checked_at": checked_at,
            "label": proxy_label(proxy),
            "detail": detail,
            "kind": kind,
        }
    except Exception as exc:
        message = str(exc).casefold()
        if "timeout" in message or "timed out" in message:
            detail, kind = "Hết thời gian kết nối", "timeout"
            status_code = None
        elif "407" in message or "proxy authentication" in message:
            detail, kind = "Sai user/password proxy", "auth"
            status_code = 407
        elif "403" in message or "forbidden" in message:
            detail, kind = "Dịch vụ kiểm tra IP từ chối proxy (HTTP 403)", "blocked"
            status_code = 403
        elif "429" in message or "too many requests" in message:
            detail, kind = "Dịch vụ kiểm tra IP đang giới hạn proxy (HTTP 429)", "blocked"
            status_code = 429
        elif "resolve proxy" in message or "could not resolve" in message:
            detail, kind = "Không phân giải được host proxy", "dns"
            status_code = None
        elif "connect" in message or "connection" in message:
            detail, kind = "Không kết nối được proxy", "connect"
            status_code = None
        else:
            detail, kind = f"Lỗi kết nối ({type(exc).__name__})", "error"
            status_code = None
        return {
            "index": index,
            "ok": False,
            "status": status_code,
            "latency_ms": round((time.perf_counter() - started_at) * 1000),
            "exit_ip": exit_ip,
            "country": country,
            "checked_at": checked_at,
            "label": proxy_label(proxy),
            "detail": detail,
            "kind": kind,
        }
    finally:
        try:
            session.close()
        except Exception:
            pass


@app.post("/api/proxies/test", dependencies=[Depends(require_admin), Depends(require_csrf)])
async def test_proxies(request: ProxyTestRequest) -> dict[str, Any]:
    semaphore = asyncio.Semaphore(20)

    async def test_one(index: int, raw_proxy: str) -> dict[str, Any]:
        async with semaphore:
            return await asyncio.to_thread(_test_proxy_sync, index, raw_proxy)

    results = await asyncio.gather(*(
        test_one(index, raw_proxy)
        for index, raw_proxy in enumerate(request.proxies, start=1)
    ))
    return {
        "results": results,
        "ok": sum(1 for result in results if result["ok"]),
        "failed": sum(1 for result in results if not result["ok"]),
    }


@app.post("/api/jobs", dependencies=[Depends(require_csrf)])
async def add_jobs(
    request: BatchRequest,
    actor: AuthContext = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        return {"jobs": manager.add(request.lines, request.mode, actor=actor)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/jobs/{job_id}/retry", dependencies=[Depends(require_csrf)])
async def retry_job(
    job_id: str,
    actor: AuthContext = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        return {"job": manager.retry(job_id, actor=actor)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Không tìm thấy job") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/jobs/{job_id}/stop", dependencies=[Depends(require_csrf)])
async def stop_job(
    job_id: str,
    actor: AuthContext = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        return {"job": manager.stop(job_id, actor=actor)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Không tìm thấy job") from exc


@app.delete("/api/jobs/{job_id}", dependencies=[Depends(require_csrf)])
async def delete_job(
    job_id: str,
    actor: AuthContext = Depends(get_current_user),
) -> dict[str, bool]:
    try:
        manager.delete(job_id, actor=actor)
        return {"ok": True}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Không tìm thấy job") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/jobs/stop-all", dependencies=[Depends(require_csrf)])
async def stop_all(actor: AuthContext = Depends(get_current_user)) -> dict[str, bool]:
    await manager.stop_all(actor=actor)
    return {"ok": True}


@app.delete("/api/jobs", dependencies=[Depends(require_csrf)])
async def clear_jobs(actor: AuthContext = Depends(get_current_user)) -> dict[str, int]:
    try:
        return {"deleted": manager.clear(actor=actor)}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/jobs/{job_id}/logs")
async def job_logs(
    job_id: str,
    actor: AuthContext = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        return {"logs": manager.logs(job_id, actor=actor)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Không tìm thấy job") from exc


@app.get("/api/output")
async def output_file(actor: AuthContext = Depends(get_current_user)) -> PlainTextResponse:
    body = "\n".join(manager.output(actor=actor))
    if body:
        body += "\n"
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": "attachment; filename=twofa-success.txt"},
    )


@app.get("/api/output/errors")
async def error_output_file(actor: AuthContext = Depends(get_current_user)) -> PlainTextResponse:
    body = "\n".join(manager.failed_output(actor=actor))
    if body:
        body += "\n"
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": "attachment; filename=twofa-errors.txt"},
    )


@app.put("/api/settings", dependencies=[Depends(require_admin), Depends(require_csrf)])
async def update_settings(request: SettingsRequest) -> dict[str, Any]:
    try:
        return {"settings": await manager.update_settings({
            "twofa.max_concurrent": request.max_concurrent,
            "twofa.job_timeout": request.job_timeout,
            "twofa.auto_retry": request.auto_retry,
            "twofa.auto_retry_max": request.auto_retry_max,
            "twofa.auto_retry_delay": request.auto_retry_delay,
            "twofa.change_enabled": request.change_enabled,
            "twofa.input_draft": "",  # Không lưu input draft để đảm bảo an toàn thông tin
            "twofa.proxy_pool": request.proxy_pool,
            "twofa.proxy_mode": request.proxy_mode,
            "twofa.proxy_bindings": request.proxy_bindings,
        })}
    except ValueError as exc:
        msg = str(exc)
        if "đang có tác vụ" in msg or "xung đột" in msg:
            raise HTTPException(status_code=409, detail=msg) from exc
        raise HTTPException(status_code=422, detail=msg) from exc


@app.get("/api/events")
async def events(request: Request):
    raw_token = request.cookies.get("session")
    if not raw_token:
        raise HTTPException(status_code=401, detail="Yêu cầu đăng nhập")
    session_info = session_repo.get_session_by_token(raw_token)
    if not session_info:
        raise HTTPException(status_code=401, detail="Phiên đăng nhập đã hết hạn")

    actor = AuthContext(
        user_id=session_info["user_id"],
        username=session_info["username"],
        role=session_info["role"],
        session_id=session_info["session_id"],
        raw_token=raw_token,
    )
    sub = manager.subscribe(actor)

    async def stream():
        try:
            yield f"data: {json.dumps({'type': 'snapshot', 'jobs': manager.snapshots(actor)})}\n\n"
            while True:
                get_task = asyncio.create_task(sub.queue.get())
                revoked_task = asyncio.create_task(sub.revoked_event.wait())
                done, pending = await asyncio.wait(
                    [get_task, revoked_task],
                    timeout=15.0,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for p in pending:
                    p.cancel()

                if sub.revoked_event.is_set():
                    yield f"data: {json.dumps({'type': 'auth_revoked', 'reason': 'session_terminated'})}\n\n"
                    break

                if not done:
                    yield ": keepalive\n\n"
                    continue

                for t in done:
                    if t is get_task and not t.cancelled():
                        try:
                            payload = t.result()
                            yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
                        except Exception:
                            pass
        finally:
            manager.unsubscribe(sub)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "index.html",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


def _open_browser_when_ready(host: str, port: int) -> None:
    url = f"http://{host if host != '::1' else '127.0.0.1'}:{port}/"

    def worker() -> None:
        health = f"{url}api/health"
        for _ in range(50):
            try:
                from urllib.request import urlopen

                with urlopen(health, timeout=0.5) as response:
                    if response.status == 200:
                        webbrowser.open(url)
                        return
            except Exception:
                time.sleep(0.2)

    threading.Thread(target=worker, name="twofa-browser", daemon=True).start()


def main() -> None:
    global RUNTIME_PORT
    default_port = int(os.environ.get("PORT", "5033"))
    parser = argparse.ArgumentParser(description="Lehaipreshop localhost")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--check-runtime-dependencies", action="store_true")
    args = parser.parse_args()
    if args.check_runtime_dependencies:
        import request_phase
        import sentinel_pow
        import sentinel_quickjs

        script = sentinel_quickjs._quickjs_script_path()
        required = (
            request_phase._get_sentinel_token,
            sentinel_pow.get_sentinel_token,
            sentinel_quickjs.get_sentinel_token_via_quickjs,
        )
        if not all(callable(item) for item in required):
            raise RuntimeError("Pure-request login dependency contract is incomplete")
        if not script.is_file():
            raise FileNotFoundError(f"Sentinel runtime asset missing: {script}")
        print("PASS: pure-request login dependencies and Sentinel runtime asset")
        return
    allowed_hosts = {"127.0.0.1", "localhost", "::1"}
    if os.environ.get("ALLOW_PUBLIC_BIND") == "1" or os.environ.get("DOCKER") == "1":
        allowed_hosts.add("0.0.0.0")
    if args.host not in allowed_hosts:
        parser.error("Server chỉ được bind localhost hoặc cần đặt ALLOW_PUBLIC_BIND=1 để bind 0.0.0.0")
    if not 1 <= args.port <= 65535:
        parser.error("Port phải nằm trong khoảng 1..65535")
    RUNTIME_PORT = args.port
    import uvicorn

    if not args.no_browser and args.host in {"127.0.0.1", "localhost"}:
        _open_browser_when_ready(args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
