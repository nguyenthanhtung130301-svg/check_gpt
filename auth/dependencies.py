"""FastAPI dependencies cho xác thực, CSRF và phân quyền."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from fastapi import Depends, HTTPException, Request

from .crypto import verify_csrf_token


@dataclass(frozen=True)
class AuthContext:
    user_id: int
    username: str
    role: str
    session_id: int
    raw_token: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def resolve_csrf_secret(runtime_dir: Path) -> bytes:
    """Khởi tạo hoặc đọc CSRF secret bền vững qua các lần restart."""
    env_secret = os.environ.get("CSRF_SECRET", "").strip()
    if len(env_secret) >= 32:
        return env_secret.encode("utf-8")

    secret_file = runtime_dir / "csrf_secret.key"
    if secret_file.is_file():
        data = secret_file.read_bytes()
        if len(data) >= 32:
            return data

    runtime_dir.mkdir(parents=True, exist_ok=True)
    generated = secrets.token_bytes(32)
    secret_file.write_bytes(generated)
    return generated


def create_auth_dependencies(session_repo, csrf_secret: bytes):
    async def get_current_user(request: Request) -> AuthContext:
        raw_session_token = request.cookies.get("session")
        if not raw_session_token:
            raise HTTPException(status_code=401, detail="Yêu cầu đăng nhập")

        session_info = session_repo.get_session_by_token(raw_session_token)
        if not session_info:
            raise HTTPException(status_code=401, detail="Phiên đăng nhập đã hết hạn hoặc không hợp lệ")

        session_repo.touch_session(session_info["session_id"])
        return AuthContext(
            user_id=session_info["user_id"],
            username=session_info["username"],
            role=session_info["role"],
            session_id=session_info["session_id"],
            raw_token=raw_session_token,
        )

    async def require_admin(actor: AuthContext = Depends(get_current_user)) -> AuthContext:
        if not actor.is_admin:
            raise HTTPException(status_code=403, detail="Chỉ quản trị viên mới có quyền thực hiện tác vụ này")
        return actor

    async def require_csrf(request: Request, actor: AuthContext = Depends(get_current_user)) -> None:
        """Kiểm tra CSRF token cho mọi unsafe HTTP method."""
        if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
            return

        client_csrf = request.headers.get("X-CSRF-Token")
        if not client_csrf:
            raise HTTPException(status_code=403, detail="Thiếu CSRF token trong request")

        if not verify_csrf_token(csrf_secret, actor.raw_token, client_csrf):
            raise HTTPException(status_code=403, detail="CSRF token không hợp lệ hoặc đã hết hạn")

    return get_current_user, require_admin, require_csrf
