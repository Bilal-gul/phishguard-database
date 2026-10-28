"""Authentication endpoints for PhishGuard.

Uses SQL Server users/sessions tables, PBKDF2 password hashes, and a signed
HttpOnly cookie. The session table remains the source of truth for revocation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

import pyodbc
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from .database import get_connection
from .schemas import LoginRequest, RegisterRequest

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

COOKIE_NAME = "phishguard_session"
SESSION_TTL_SECONDS = 60 * 60 * 12  # 12 hours
COOKIE_SECURE = os.getenv("PHISHGUARD_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}
logger = logging.getLogger("phishguard.auth")


def _load_session_secret() -> bytes:
    env_secret = os.getenv("PHISHGUARD_SESSION_SECRET")
    if env_secret:
        if len(env_secret) < 32:
            raise RuntimeError("PHISHGUARD_SESSION_SECRET must be at least 32 characters.")
        return env_secret.encode("utf-8")

    # Stable local-development secret so sessions survive a server reload.
    # For deployment, configure PHISHGUARD_SESSION_SECRET securely instead.
    secret_path = Path(__file__).resolve().parents[1] / ".phishguard_session_secret"
    try:
        if secret_path.exists():
            secret = secret_path.read_text(encoding="utf-8").strip()
            if len(secret) < 64:
                raise RuntimeError("Local session secret file is invalid.")
            return secret.encode("utf-8")

        secret = secrets.token_hex(32)
        try:
            with secret_path.open("x", encoding="utf-8") as secret_file:
                secret_file.write(secret)
            try:
                os.chmod(secret_path, 0o600)
            except OSError:
                pass
        except FileExistsError:
            secret = secret_path.read_text(encoding="utf-8").strip()
            if len(secret) < 64:
                raise RuntimeError("Local session secret file is invalid.")
        return secret.encode("utf-8")
    except OSError as exc:
        raise RuntimeError(
            "Cannot store session secret. Set PHISHGUARD_SESSION_SECRET in the environment."
        ) from exc


SESSION_SECRET = _load_session_secret()


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _make_cookie_token(user_id: int, session_id: int, issued_at: int | None = None) -> str:
    issued = int(time.time()) if issued_at is None else int(issued_at)
    payload = _b64encode(f"{user_id}:{session_id}:{issued}".encode("utf-8"))
    signature = _b64encode(hmac.new(SESSION_SECRET, payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def _read_cookie_token(token: str) -> tuple[int, int]:
    try:
        payload, supplied_signature = token.split(".", 1)
        expected_signature = _b64encode(
            hmac.new(SESSION_SECRET, payload.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ValueError("Invalid signature")

        user_id_text, session_id_text, issued_text = _b64decode(payload).decode("utf-8").split(":")
        user_id, session_id, issued = int(user_id_text), int(session_id_text), int(issued_text)
        now = int(time.time())
        if user_id < 1 or session_id < 1 or issued > now + 60:
            raise ValueError("Invalid session timestamp")
        if now - issued > SESSION_TTL_SECONDS:
            raise ValueError("Session expired")
        return user_id, session_id
    except (ValueError, TypeError, UnicodeDecodeError, base64.binascii.Error) as exc:
        raise HTTPException(status_code=401, detail="Oturum geçersiz veya süresi dolmuş. Lütfen tekrar giriş yap.") from exc


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 390_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored_hash: str | None) -> bool:
    if not stored_hash:
        return False
    try:
        scheme, iterations_text, salt_hex, expected_hex = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        if iterations < 100_000 or iterations > 2_000_000:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
    )


def get_current_user(request: Request) -> dict[str, Any]:
    """Validate signed cookie and confirm that its SQL session is still active."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Devam etmek için giriş yapmalısın.")

    user_id, session_id = _read_cookie_token(token)
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT u.user_id, u.username, u.email
            FROM dbo.sessions AS s
            INNER JOIN dbo.users AS u ON u.user_id = s.user_id
            WHERE s.session_id = ?
              AND s.user_id = ?
              AND s.logout_at IS NULL
              AND u.is_active = 1
            """,
            session_id,
            user_id,
        )
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Oturum kapatılmış veya geçersiz. Tekrar giriş yap.")
        return {"user_id": int(row[0]), "username": str(row[1]), "email": str(row[2])}
    except HTTPException:
        raise
    except pyodbc.Error as exc:
        logger.error("Session verification failed (%s).", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Oturum doğrulanamadı.") from exc
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()


@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
def register(request: RegisterRequest) -> dict[str, Any]:
    username = request.username.strip()
    email = request.email.strip().lower()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
        raise HTTPException(
            status_code=422,
            detail="Kullanıcı adı 3-50 karakter olmalı; harf, rakam, nokta, alt çizgi ve tire kullanılabilir.",
        )
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=422, detail="Geçerli bir e-posta adresi gir.")
    if len(request.password) < 8 or len(request.password) > 128:
        raise HTTPException(status_code=422, detail="Şifre 8-128 karakter arasında olmalı.")

    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            "SELECT username, email FROM dbo.users WHERE username = ? OR email = ?",
            username,
            email,
        )
        existing = cursor.fetchone()
        if existing:
            if str(existing[0]).casefold() == username.casefold():
                raise HTTPException(status_code=409, detail="Bu kullanıcı adı zaten kullanılıyor.")
            raise HTTPException(status_code=409, detail="Bu e-posta adresiyle zaten hesap var.")

        password_hash = _hash_password(request.password)
        cursor.execute(
            """
            INSERT INTO dbo.users (username, email, password_hash, is_active)
            OUTPUT INSERTED.user_id
            VALUES (?, ?, ?, 1)
            """,
            username,
            email,
            password_hash,
        )
        row = cursor.fetchone()
        if row is None:
            raise RuntimeError("Kullanıcı kaydının ID bilgisi alınamadı.")
        user_id = int(row[0])

        cursor.execute(
            "INSERT INTO dbo.activity_logs (user_id, action) VALUES (?, 'REGISTER')",
            user_id,
        )
        connection.commit()
        return {
            "message": "Hesap oluşturuldu. Şimdi giriş yapabilirsin.",
            "user": {"user_id": user_id, "username": username, "email": email},
        }
    except HTTPException:
        if connection is not None:
            connection.rollback()
        raise
    except pyodbc.IntegrityError as exc:
        if connection is not None:
            connection.rollback()
        raise HTTPException(status_code=409, detail="Kullanıcı adı veya e-posta zaten kullanılıyor.") from exc
    except (pyodbc.Error, RuntimeError) as exc:
        if connection is not None:
            connection.rollback()
        logger.error("Account registration failed (%s).", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Hesap oluşturulamadı.") from exc
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()


@auth_router.post("/login")
def login(request: LoginRequest, response: Response) -> dict[str, Any]:
    email = request.email.strip().lower()
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT user_id, username, email, password_hash, is_active
            FROM dbo.users
            WHERE email = ?
            """,
            email,
        )
        row = cursor.fetchone()
        # Same message for missing account and bad password.
        if row is None or not bool(row[4]) or not _verify_password(request.password, row[3]):
            raise HTTPException(status_code=401, detail="E-posta veya şifre hatalı.")

        user_id, username, stored_email = int(row[0]), str(row[1]), str(row[2])
        cursor.execute(
            """
            INSERT INTO dbo.sessions (user_id, login_at, logout_at)
            OUTPUT INSERTED.session_id
            VALUES (?, GETDATE(), NULL)
            """,
            user_id,
        )
        session_row = cursor.fetchone()
        if session_row is None:
            raise RuntimeError("Oturum kaydının ID bilgisi alınamadı.")
        session_id = int(session_row[0])

        cursor.execute(
            "INSERT INTO dbo.activity_logs (user_id, action) VALUES (?, 'LOGIN')",
            user_id,
        )
        connection.commit()

        token = _make_cookie_token(user_id, session_id)
        _set_session_cookie(response, token)
        return {
            "message": "Giriş başarılı.",
            "user": {"user_id": user_id, "username": username, "email": stored_email},
        }
    except HTTPException:
        if connection is not None:
            connection.rollback()
        raise
    except (pyodbc.Error, RuntimeError) as exc:
        if connection is not None:
            connection.rollback()
        logger.error("Login failed (%s).", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Giriş yapılamadı.") from exc
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()


@auth_router.get("/me")
def who_am_i(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return {"authenticated": True, "user": current_user}


@auth_router.post("/logout")
def logout(request: Request, response: Response) -> dict[str, bool]:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        try:
            user_id, session_id = _read_cookie_token(token)
            connection = get_connection()
            cursor = None
            try:
                cursor = connection.cursor()
                cursor.execute(
                    """
                    UPDATE dbo.sessions
                    SET logout_at = GETDATE()
                    WHERE session_id = ? AND user_id = ? AND logout_at IS NULL
                    """,
                    session_id,
                    user_id,
                )
                cursor.execute(
                    "INSERT INTO dbo.activity_logs (user_id, action) VALUES (?, 'LOGOUT')",
                    user_id,
                )
                connection.commit()
            finally:
                if cursor is not None:
                    cursor.close()
                connection.close()
        except HTTPException:
            # Always clear a malformed/expired cookie.
            pass
        except pyodbc.Error as exc:
            logger.error("Logout persistence failed (%s).", type(exc).__name__)
            raise HTTPException(status_code=500, detail="Oturum kapatılamadı.") from exc
    _clear_session_cookie(response)
    return {"ok": True}
