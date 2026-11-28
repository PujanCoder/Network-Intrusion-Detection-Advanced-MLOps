"""Dashboard login: exchange the platform API key for a browser session cookie.

The key is posted once over HTTPS, compared with ``hmac.compare_digest`` and
never echoed. Repeated failures from one client are throttled so the endpoint
cannot be used to brute-force the key.
"""

from __future__ import annotations

import threading
import time

from fastapi import APIRouter, Header, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.serving.security import (
    SESSION_COOKIE,
    auth_summary,
    cookie_settings,
    issue_session,
    require_access,
    session_expiry,
    verify_session,
)

router = APIRouter(prefix="/api/v1")

MAX_FAILURES = 10
WINDOW_S = 60.0
_failures: dict[str, list[float]] = {}
_lock = threading.Lock()


class LoginRequest(BaseModel):
    api_key: str = Field(..., min_length=1, max_length=512)


def _client(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _throttle(key: str) -> bool:
    """Record an attempt; return True when the client is over the limit."""

    now = time.time()
    with _lock:
        attempts = [stamp for stamp in _failures.get(key, []) if now - stamp < WINDOW_S]
        attempts.append(now)
        _failures[key] = attempts
        return len(attempts) > MAX_FAILURES


def reset_throttle() -> None:
    with _lock:
        _failures.clear()


@router.get("/session")
def session_state(request: Request, x_api_key: str | None = Header(default=None)):
    """Whether this browser already holds a usable session. Safe to call cold."""

    settings = request.app.state.settings
    token = request.cookies.get(SESSION_COOKIE)
    authenticated = bool(token) and verify_session(settings, token)
    method = None
    if authenticated:
        method = "session"
    elif x_api_key and settings.auth_configured and x_api_key.strip() == settings.api_key.strip():
        method = "api_key"
        authenticated = True
    return {
        "configured": settings.auth_configured,
        "authenticated": authenticated,
        "method": method,
        "expires_at": session_expiry(settings, token),
        **auth_summary(settings),
    }


@router.post("/session")
def login(body: LoginRequest, request: Request, response: Response):
    settings = request.app.state.settings
    if not settings.auth_configured:
        return JSONResponse(
            status_code=503,
            content={
                "detail": {
                    "code": "auth_not_configured",
                    "message": "No API key is configured on this deployment.",
                }
            },
        )
    client = _client(request)
    if _throttle(client):
        return JSONResponse(
            status_code=429,
            content={"detail": {"code": "too_many_attempts", "message": "Too many sign-in attempts; wait a minute."}},
        )
    import hmac

    if not hmac.compare_digest(body.api_key.strip(), (settings.api_key or "").strip()):
        return JSONResponse(
            status_code=401,
            content={"detail": {"code": "invalid_api_key", "message": "That key does not match this deployment."}},
        )
    token, expires = issue_session(settings)
    response.set_cookie(value=token, max_age=expires - int(time.time()), **cookie_settings(settings, request))
    return {
        "authenticated": True,
        "method": "session",
        "expires_at": expires,
        "expires_in": expires - int(time.time()),
    }


@router.delete("/session")
def logout(request: Request, response: Response):
    settings = request.app.state.settings
    response.delete_cookie(cookie_settings(settings, request)["key"], path="/")
    return {"authenticated": False}


@router.get("/session/whoami")
def whoami(request: Request, x_api_key: str | None = Header(default=None)):
    method = require_access(request.app.state.settings, x_api_key, request)
    return {"authenticated": True, "method": method}
