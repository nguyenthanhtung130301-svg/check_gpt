"""Pydantic schemas cho Auth và Quản trị người dùng."""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=4, max_length=128)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=4, max_length=128)


class AdminResetPasswordRequest(BaseModel):
    password: str = Field(min_length=4, max_length=128)


class UpdateStatusRequest(BaseModel):
    status: str = Field(pattern="^(active|inactive)$")


class UserPublic(BaseModel):
    id: int
    username: str
    role: str
    status: str


class CollaboratorCapabilities(BaseModel):
    max_lines_per_batch: int = 50
    max_active_jobs: int = 100
    max_running_jobs: int = 2
    can_configure_settings: bool = False
    can_manage_proxies: bool = False


class CollaboratorBootstrapResponse(BaseModel):
    brand: str
    product: str
    user: UserPublic
    csrf_token: str
    jobs: list[dict[str, Any]]
    capabilities: CollaboratorCapabilities


class AdminBootstrapResponse(BaseModel):
    brand: str
    product: str
    user: UserPublic
    csrf_token: str
    jobs: list[dict[str, Any]]
    settings: dict[str, Any]
    capabilities: dict[str, Any]
