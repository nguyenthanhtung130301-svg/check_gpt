"""API Routers cho Auth và Quản trị người dùng."""
from __future__ import annotations

import collections
import time
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from .crypto import (
    dummy_verify,
    generate_csrf_token,
    hash_password,
    needs_rehash,
    normalize_username,
    validate_password,
    verify_password,
)
from .dependencies import AuthContext
from .models import (
    AdminResetPasswordRequest,
    ChangePasswordRequest,
    CreateUserRequest,
    LoginRequest,
    UpdateStatusRequest,
)

# In-memory rate limiting cho login (5 lần sai/user/5 phút; 20 lần sai/IP/5 phút)
_FAILED_USER_LOGINS: dict[str, list[float]] = collections.defaultdict(list)
_FAILED_IP_LOGINS: dict[str, list[float]] = collections.defaultdict(list)
RATE_LIMIT_WINDOW_SECONDS = 300.0
MAX_USER_FAILS = 5
MAX_IP_FAILS = 20


def _check_rate_limit(clean_user: str, ip: str) -> None:
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    user_attempts = [t for t in _FAILED_USER_LOGINS[clean_user] if t > cutoff]
    _FAILED_USER_LOGINS[clean_user] = user_attempts
    if len(user_attempts) >= MAX_USER_FAILS:
        raise HTTPException(
            status_code=429,
            detail="Tài khoản bị tạm khóa đăng nhập do nhập sai nhiều lần. Vui lòng thử lại sau 5 phút.",
        )

    ip_attempts = [t for t in _FAILED_IP_LOGINS[ip] if t > cutoff]
    _FAILED_IP_LOGINS[ip] = ip_attempts
    if len(ip_attempts) >= MAX_IP_FAILS:
        raise HTTPException(
            status_code=429,
            detail="Địa chỉ IP bị tạm khóa đăng nhập do thử sai nhiều lần. Vui lòng thử lại sau 5 phút.",
        )


def _record_failed_login(clean_user: str, ip: str) -> None:
    now = time.time()
    _FAILED_USER_LOGINS[clean_user].append(now)
    _FAILED_IP_LOGINS[ip].append(now)


def _clear_failed_logins(clean_user: str) -> None:
    _FAILED_USER_LOGINS.pop(clean_user, None)


def create_auth_routers(
    user_repo,
    session_repo,
    audit_repo,
    manager,
    csrf_secret: bytes,
    get_current_user,
    require_admin,
    require_csrf,
    is_secure_cookie: bool = False,
) -> tuple[APIRouter, APIRouter]:
    auth_router = APIRouter(prefix="/api/auth", tags=["auth"])
    admin_router = APIRouter(prefix="/api/admin", tags=["admin"])

    @auth_router.post("/login")
    async def login(request: LoginRequest, req: Request, response: Response) -> dict[str, Any]:
        """Đăng nhập hệ thống (Ngoại lệ duy nhất không cần X-CSRF-Token)."""
        client_ip = req.client.host if req.client else "unknown"
        try:
            clean_user = normalize_username(request.username)
        except ValueError:
            dummy_verify()
            raise HTTPException(status_code=401, detail="Tài khoản hoặc mật khẩu không chính xác")

        _check_rate_limit(clean_user, client_ip)

        user = user_repo.get_by_username(clean_user)
        if not user:
            dummy_verify()
            _record_failed_login(clean_user, client_ip)
            audit_repo.log("login_failure", "failure", detail={"username": clean_user, "ip": client_ip, "reason": "not_found"})
            raise HTTPException(status_code=401, detail="Tài khoản hoặc mật khẩu không chính xác")

        if not verify_password(request.password, user["password_hash"]):
            _record_failed_login(clean_user, client_ip)
            audit_repo.log("login_failure", "failure", actor_user_id=user["id"], detail={"username": clean_user, "ip": client_ip, "reason": "invalid_password"})
            raise HTTPException(status_code=401, detail="Tài khoản hoặc mật khẩu không chính xác")

        if user["status"] != "active":
            audit_repo.log("login_failure", "failure", actor_user_id=user["id"], detail={"username": clean_user, "ip": client_ip, "reason": "inactive"})
            raise HTTPException(status_code=403, detail="Tài khoản đã bị vô hiệu hóa")

        _clear_failed_logins(clean_user)
        user_repo.update_last_login(user["id"])

        if needs_rehash(user["password_hash"]):
            new_hash = hash_password(request.password)
            user_repo.update_password_hash(user["id"], new_hash)

        raw_session_token = session_repo.create_session(user["id"])
        csrf_token = generate_csrf_token(csrf_secret, raw_session_token)

        response.set_cookie(
            key="session",
            value=raw_session_token,
            httponly=True,
            samesite="lax",
            path="/",
            max_age=7 * 86400,
            secure=is_secure_cookie,
        )
        response.headers["Cache-Control"] = "no-store"

        audit_repo.log("login_success", "success", actor_user_id=user["id"], detail={"username": clean_user, "ip": client_ip})

        return {
            "csrf_token": csrf_token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "status": user["status"],
            },
        }

    @auth_router.post("/logout", dependencies=[Depends(require_csrf)])
    async def logout(response: Response, actor: AuthContext = Depends(get_current_user)) -> dict[str, bool]:
        session_repo.delete_session(actor.raw_token)
        manager.revoke_session_streams(actor.session_id)
        audit_repo.log("logout", "success", actor_user_id=actor.user_id)

        response.delete_cookie(key="session", path="/")
        response.headers["Cache-Control"] = "no-store"
        return {"ok": True}

    @auth_router.get("/me")
    async def get_me(response: Response, actor: AuthContext = Depends(get_current_user)) -> dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        return {
            "user": {
                "id": actor.user_id,
                "username": actor.username,
                "role": actor.role,
            }
        }

    @auth_router.put("/password", dependencies=[Depends(require_csrf)])
    async def change_my_password(
        request: ChangePasswordRequest,
        actor: AuthContext = Depends(get_current_user),
    ) -> dict[str, bool]:
        full_user = user_repo.get_by_id(actor.user_id)
        if not full_user or not verify_password(request.old_password, full_user["password_hash"]):
            audit_repo.log("password_change", "failure", actor_user_id=actor.user_id, detail={"reason": "wrong_old_password"})
            raise HTTPException(status_code=400, detail="Mật khẩu hiện tại không chính xác")

        try:
            validate_password(request.new_password, username=actor.username)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        new_hash = hash_password(request.new_password)
        user_repo.update_password_hash(actor.user_id, new_hash)

        # Thu hồi các session khác của user, giữ lại session hiện tại
        revoked_sessions = session_repo.delete_all_for_user(actor.user_id, except_session_id=actor.session_id)
        manager.revoke_multiple_sessions(revoked_sessions)

        audit_repo.log("password_change", "success", actor_user_id=actor.user_id)
        return {"ok": True}

    # --- Admin Endpoints ---
    @admin_router.get("/users", dependencies=[Depends(require_admin)])
    async def list_users(response: Response) -> dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        return {"users": user_repo.list_collaborators()}

    @admin_router.post("/users", dependencies=[Depends(require_admin), Depends(require_csrf)])
    async def create_collaborator(
        request: CreateUserRequest,
        actor: AuthContext = Depends(require_admin),
    ) -> dict[str, Any]:
        try:
            clean_user = normalize_username(request.username)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        if user_repo.get_by_username(clean_user):
            raise HTTPException(status_code=409, detail="Tên đăng nhập đã tồn tại")

        try:
            new_user = user_repo.create_collaborator(clean_user, request.password)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        audit_repo.log(
            "collaborator_create",
            "success",
            actor_user_id=actor.user_id,
            target_user_id=new_user["id"],
            detail={"username": clean_user},
        )
        return {"user": new_user}

    @admin_router.put("/users/{user_id}/password", dependencies=[Depends(require_admin), Depends(require_csrf)])
    async def admin_reset_password(
        user_id: int,
        request: AdminResetPasswordRequest,
        actor: AuthContext = Depends(require_admin),
    ) -> dict[str, bool]:
        target = user_repo.get_by_id(user_id)
        if not target or target["role"] != "collaborator":
            raise HTTPException(status_code=404, detail="Không tìm thấy cộng tác viên")

        try:
            validate_password(request.password, username=target["username"])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        new_hash = hash_password(request.password)
        user_repo.update_password_hash(user_id, new_hash)

        # Thu hồi toàn bộ session của CTV bị reset password
        revoked = session_repo.delete_all_for_user(user_id)
        manager.revoke_multiple_sessions(revoked)

        audit_repo.log(
            "admin_password_reset",
            "success",
            actor_user_id=actor.user_id,
            target_user_id=user_id,
            detail={"username": target["username"]},
        )
        return {"ok": True}

    @admin_router.put("/users/{user_id}/status", dependencies=[Depends(require_admin), Depends(require_csrf)])
    async def update_user_status(
        user_id: int,
        request: UpdateStatusRequest,
        actor: AuthContext = Depends(require_admin),
    ) -> dict[str, bool]:
        target = user_repo.get_by_id(user_id)
        if not target or target["role"] != "collaborator":
            raise HTTPException(status_code=404, detail="Không tìm thấy cộng tác viên")

        user_repo.update_status(user_id, request.status)

        if request.status == "inactive":
            # 1. Thu hồi toàn bộ phiên đăng nhập
            revoked = session_repo.delete_all_for_user(user_id)
            manager.revoke_multiple_sessions(revoked)
            # 2. DỪNG NGAY LẬP TỨC toàn bộ job queued và running của CTV này
            await manager.stop_all_for_user(user_id)

        action_name = "collaborator_disable" if request.status == "inactive" else "collaborator_enable"
        audit_repo.log(
            action_name,
            "success",
            actor_user_id=actor.user_id,
            target_user_id=user_id,
            detail={"username": target["username"], "status": request.status},
        )
        return {"ok": True}

    @admin_router.delete("/users/{user_id}", dependencies=[Depends(require_admin), Depends(require_csrf)])
    async def delete_collaborator(
        user_id: int,
        actor: AuthContext = Depends(require_admin),
    ) -> dict[str, bool]:
        target = user_repo.get_by_id(user_id)
        if not target or target["role"] != "collaborator":
            raise HTTPException(status_code=404, detail="Không tìm thấy cộng tác viên")

        # 1. Thu hồi toàn bộ phiên đăng nhập của CTV này
        revoked = session_repo.delete_all_for_user(user_id)
        manager.revoke_multiple_sessions(revoked)

        # 2. DỪNG NGAY LẬP TỨC toàn bộ job queued và running của CTV này
        await manager.stop_all_for_user(user_id)

        # 3. Xóa user khỏi database
        user_repo.delete_user(user_id)

        # 4. Ghi vết audit log
        audit_repo.log(
            "collaborator_delete",
            "success",
            actor_user_id=actor.user_id,
            target_user_id=user_id,
            detail={"username": target["username"]},
        )
        return {"ok": True}

    return auth_router, admin_router
