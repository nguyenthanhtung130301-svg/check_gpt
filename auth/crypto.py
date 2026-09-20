"""Mật mã và bảo mật xác thực (Zero external dependencies)."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import unicodedata

DEFAULT_PBKDF2_ITERATIONS = 120_000
MIN_ITERATIONS = 50_000
MAX_ITERATIONS = 500_000
MIN_PASSWORD_LEN = 4
MAX_PASSWORD_LEN = 128

# Chuỗi hash giả lập phục vụ constant-time verification khi username không tồn tại
DUMMY_SALT = "0" * 32
DUMMY_HASH = "pbkdf2_sha256$120000$" + DUMMY_SALT + "$" + ("0" * 64)


def normalize_username(username: str) -> str:
    """Chuẩn hóa username bằng Unicode NFKC, strip khoảng trắng và casefold."""
    if not isinstance(username, str):
        raise ValueError("Tên đăng nhập phải là chuỗi ký tự")
    cleaned = unicodedata.normalize("NFKC", username).strip().casefold()
    if not 3 <= len(cleaned) <= 50:
        raise ValueError("Tên đăng nhập phải từ 3 đến 50 ký tự")
    if not re.match(r"^[a-z0-9_.-]+$", cleaned):
        raise ValueError("Tên đăng nhập chỉ được chứa chữ cái, số, dấu gạch dưới, gạch ngang hoặc dấu chấm")
    return cleaned


def validate_password(password: str, username: str = "", min_len: int = MIN_PASSWORD_LEN, check_username: bool = False) -> None:
    """Kiểm tra chính sách mật khẩu: 4-128 ký tự."""
    if not isinstance(password, str):
        raise ValueError("Mật khẩu phải là chuỗi ký tự")
    if len(password) < min_len:
        raise ValueError(f"Mật khẩu phải có tối thiểu {min_len} ký tự")
    if len(password) > MAX_PASSWORD_LEN:
        raise ValueError(f"Mật khẩu không được dài quá {MAX_PASSWORD_LEN} ký tự")
    if check_username and username and username.casefold() in password.casefold():
        raise ValueError("Mật khẩu không được chứa tên đăng nhập")


def hash_password(password: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS, min_len: int = MIN_PASSWORD_LEN) -> str:
    """Băm mật khẩu bằng PBKDF2 HMAC SHA-256 có version."""
    validate_password(password, min_len=min_len)
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${key.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    """Xác thực mật khẩu với encoded hash (kiểm tra biên chống CPU exhaustion)."""
    if not isinstance(password, str) or not isinstance(encoded_hash, str):
        return False
    if len(password) > MAX_PASSWORD_LEN:
        return False
    try:
        parts = encoded_hash.split("$")
        if len(parts) != 4:
            return False
        algo, iter_str, salt, expected_hex = parts
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
        if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
            return False
        if len(salt) != 32 or len(expected_hex) != 64:
            return False
        computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
        return hmac.compare_digest(computed.hex(), expected_hex)
    except Exception:
        return False


def dummy_verify() -> None:
    """Thực hiện phép tính hash giả lập để chống tấn công timing khi username không tồn tại."""
    verify_password("dummy_password_for_timing_protection", DUMMY_HASH)


def needs_rehash(encoded_hash: str, target_iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> bool:
    """Kiểm tra mật khẩu có cần nâng cấp số vòng lặp không."""
    try:
        parts = encoded_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return True
        return int(parts[1]) < target_iterations
    except Exception:
        return True


def hash_token(raw_token: str) -> str:
    """Băm session token bằng SHA-256 trước khi lưu vào Database."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_csrf_token(csrf_secret: bytes, raw_session_token: str) -> str:
    """Dẫn xuất CSRF token bằng HMAC-SHA256 từ Session Token."""
    return hmac.new(csrf_secret, raw_session_token.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_csrf_token(csrf_secret: bytes, raw_session_token: str, client_token: str) -> bool:
    """Xác thực CSRF token gửi lên từ client."""
    if not raw_session_token or not client_token:
        return False
    expected = generate_csrf_token(csrf_secret, raw_session_token)
    return hmac.compare_digest(expected, client_token)
