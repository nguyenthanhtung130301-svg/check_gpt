"""Repositories cho Users, Sessions và Audit Log."""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from .crypto import (
    hash_password,
    hash_token,
    normalize_username,
    validate_password,
)

ABSOLUTE_SESSION_TTL_SECONDS = 7 * 86400.0  # 7 ngày
IDLE_SESSION_TTL_SECONDS = 24 * 3600.0      # 24 giờ
LAST_SEEN_THROTTLE_SECONDS = 900.0          # 15 phút


def load_env_file(root_dir: Path) -> None:
    """Tự động nạp file .env nếu có mà không cần thư viện ngoài."""
    env_path = root_dir / ".env"
    if not env_path.is_file():
        return
    try:
        content = env_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key, val = key.strip(), val.strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            os.environ.setdefault(key, val)
    except Exception:
        pass


class UserRepository:
    def __init__(self, engine) -> None:
        self._engine = engine

    def has_admin(self) -> bool:
        with self._engine.get_connection() as conn:
            row = conn.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1").fetchone()
            return bool(row)

    def seed_admin_from_env(self, root_dir: Path | None = None) -> dict[str, Any] | None:
        """Khởi tạo hoặc cập nhật tài khoản Admin từ biến môi trường/file .env."""
        if root_dir:
            load_env_file(root_dir)

        raw_user = os.environ.get("ADMIN_USERNAME", "").strip()
        raw_pass = os.environ.get("ADMIN_PASSWORD", "")

        if not raw_user or not raw_pass:
            if not self.has_admin():
                error_msg = (
                    "Database chưa có Quản trị viên (Admin). "
                    "Vui lòng thiết lập biến môi trường ADMIN_USERNAME và ADMIN_PASSWORD (hoặc trong file .env)."
                )
                runtime_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "Lehaipreshop" / "Change2FA"
                try:
                    runtime_dir.mkdir(parents=True, exist_ok=True)
                    (runtime_dir / "startup_error.log").write_text(error_msg, encoding="utf-8")
                except Exception:
                    pass
                raise RuntimeError(error_msg)
            return None

        username = normalize_username(raw_user)
        validate_password(raw_pass, min_len=1)
        encoded_hash = hash_password(raw_pass, min_len=1)

        with self._engine.get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE role = 'admin' LIMIT 1").fetchone()
            if not row:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, role, status)
                    VALUES (?, ?, 'admin', 'active')
                    """,
                    (username, encoded_hash),
                )
            else:
                admin_id = row["id"]
                # Nếu mật khẩu trong .env khác với DB -> tự động cập nhật lại cho Admin
                from .crypto import verify_password
                if not verify_password(raw_pass, row["password_hash"]) or row["username"].casefold() != username.casefold():
                    conn.execute(
                        """
                        UPDATE users SET username = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        (username, encoded_hash, admin_id),
                    )
        return self.get_by_username(username)

    def get_by_username(self, username: str) -> dict[str, Any] | None:
        try:
            clean_user = normalize_username(username)
        except ValueError:
            return None
        with self._engine.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                (clean_user,),
            ).fetchone()
            return dict(row) if row else None

    def get_by_id(self, user_id: int) -> dict[str, Any] | None:
        with self._engine.get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row) if row else None

    def create_collaborator(self, username: str, password: str) -> dict[str, Any]:
        clean_user = normalize_username(username)
        validate_password(password, username=clean_user)
        encoded_hash = hash_password(password)
        with self._engine.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO users (username, password_hash, role, status)
                VALUES (?, ?, 'collaborator', 'active')
                """,
                (clean_user, encoded_hash),
            )
            return {
                "id": cur.lastrowid,
                "username": clean_user,
                "role": "collaborator",
                "status": "active",
            }

    def list_collaborators(self) -> list[dict[str, Any]]:
        with self._engine.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT u.id, u.username, u.role, u.status, u.created_at, u.last_login_at,
                       COUNT(j.id) AS total_jobs
                FROM users u
                LEFT JOIN jobs j ON u.id = j.owner_user_id
                WHERE u.role = 'collaborator'
                GROUP BY u.id
                ORDER BY u.id DESC
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def update_password_hash(self, user_id: int, new_hash: str) -> bool:
        with self._engine.get_connection() as conn:
            cur = conn.execute(
                """
                UPDATE users
                SET password_hash = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE id = ?
                """,
                (new_hash, user_id),
            )
            return cur.rowcount > 0

    def update_status(self, user_id: int, status: str) -> bool:
        """Chỉ cho phép vô hiệu hóa tài khoản collaborator, không tác động admin."""
        if status not in ("active", "inactive"):
            raise ValueError("Trạng thái không hợp lệ")
        with self._engine.get_connection() as conn:
            cur = conn.execute(
                """
                UPDATE users
                SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE id = ? AND role = 'collaborator'
                """,
                (status, user_id),
            )
            return cur.rowcount > 0

    def update_last_login(self, user_id: int) -> None:
        with self._engine.get_connection() as conn:
            conn.execute(
                "UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
                (user_id,),
            )

    def delete_user(self, user_id: int) -> bool:
        """Xóa tài khoản collaborator khỏi hệ thống, tuyệt đối không tác động admin."""
        with self._engine.get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM users WHERE id = ? AND role = 'collaborator'",
                (user_id,),
            )
            return cur.rowcount > 0


class SessionRepository:
    def __init__(self, engine) -> None:
        self._engine = engine

    def create_session(self, user_id: int) -> str:
        raw_token = secrets.token_urlsafe(32)
        token_digest = hash_token(raw_token)
        now = time.time()
        expires_at = now + ABSOLUTE_SESSION_TTL_SECONDS
        with self._engine.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (token_digest, user_id, now, expires_at, now),
            )
        return raw_token

    def get_session_by_token(self, raw_token: str) -> dict[str, Any] | None:
        token_digest = hash_token(raw_token)
        now = time.time()
        idle_cutoff = now - IDLE_SESSION_TTL_SECONDS
        with self._engine.get_connection() as conn:
            row = conn.execute(
                """
                SELECT s.id AS session_id, s.token_hash, s.user_id, s.expires_at, s.last_seen_at,
                       u.username, u.role, u.status
                FROM user_sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token_hash = ?
                  AND s.expires_at > ?
                  AND s.last_seen_at > ?
                  AND u.status = 'active'
                """,
                (token_digest, now, idle_cutoff),
            ).fetchone()
            return dict(row) if row else None

    def touch_session(self, session_id: int) -> None:
        """Cập nhật last_seen_at có điều kiện (chỉ update nếu đã qua hơn 15 phút)."""
        now = time.time()
        throttle_threshold = now - LAST_SEEN_THROTTLE_SECONDS
        with self._engine.get_connection() as conn:
            conn.execute(
                """
                UPDATE user_sessions
                SET last_seen_at = ?
                WHERE id = ? AND last_seen_at <= ?
                """,
                (now, session_id, throttle_threshold),
            )

    def delete_session(self, raw_token: str) -> int | None:
        token_digest = hash_token(raw_token)
        with self._engine.get_connection() as conn:
            row = conn.execute("SELECT id FROM user_sessions WHERE token_hash = ?", (token_digest,)).fetchone()
            session_id = row["id"] if row else None
            if session_id is not None:
                conn.execute("DELETE FROM user_sessions WHERE id = ?", (session_id,))
            return session_id

    def delete_all_for_user(self, user_id: int, except_session_id: int | None = None) -> list[int]:
        """Xóa toàn bộ session của user (dùng khi đổi pass / khóa CTV). Trả về danh sách session_id bị xóa."""
        with self._engine.get_connection() as conn:
            if except_session_id is not None:
                rows = conn.execute(
                    "SELECT id FROM user_sessions WHERE user_id = ? AND id != ?",
                    (user_id, except_session_id),
                ).fetchall()
                conn.execute(
                    "DELETE FROM user_sessions WHERE user_id = ? AND id != ?",
                    (user_id, except_session_id),
                )
            else:
                rows = conn.execute("SELECT id FROM user_sessions WHERE user_id = ?", (user_id,)).fetchall()
                conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
            return [r["id"] for r in rows]

    def cleanup_expired(self) -> int:
        now = time.time()
        idle_cutoff = now - IDLE_SESSION_TTL_SECONDS
        with self._engine.get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM user_sessions WHERE expires_at <= ? OR last_seen_at <= ?",
                (now, idle_cutoff),
            )
            return cur.rowcount


class AuditRepository:
    def __init__(self, engine) -> None:
        self._engine = engine

    def log(
        self,
        action: str,
        outcome: str,
        actor_user_id: int | None = None,
        target_user_id: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Ghi nhật ký kiểm toán append-only, redact mọi credential."""
        safe_detail = dict(detail or {})
        for sensitive_key in ("password", "token", "csrf_token", "secret", "combo"):
            if sensitive_key in safe_detail:
                safe_detail[sensitive_key] = "[REDACTED]"
        detail_json = json.dumps(safe_detail, ensure_ascii=False)
        try:
            with self._engine.get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO auth_audit_log (actor_user_id, target_user_id, action, outcome, detail)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (actor_user_id, target_user_id, action, outcome, detail_json),
                )
        except Exception:
            pass
