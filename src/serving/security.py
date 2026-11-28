"""API-key and browser-session handling for the serving app.

Machine clients (sensors, CLI, CI) send ``X-API-Key``. Browsers must never hold
that key: the dashboard logs in once, the server verifies the key and returns an
HttpOnly cookie holding a signed, expiring token. The permanent secret therefore
never enters JavaScript, a bundle or ``localStorage``.

Outcomes are explicit and none of them silent:

* key or valid session            -> the request proceeds (``require_access``);
* key configured, nothing valid   -> ``401``;
* no key configured at all        -> ``503`` with a machine-readable code, because
  the deployment cannot serve data safely. This is a configuration fault, not an
  outage: the process is healthy and ``/api/v1/health`` reports it.

Writes (ingestion) call ``require_key`` and therefore ignore cookies: a cookie
authenticates reads only, which keeps a cross-site request from pushing events.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import HTTPException, Request

from src.serving.config import Settings

AUTH_NOT_CONFIGURED = "auth_not_configured"
INVALID_API_KEY = "invalid_api_key"
INVALID_SESSION = "invalid_session"

SESSION_COOKIE = "ndr_session"
DEFAULT_SESSION_TTL_S = 8 * 3600


def _expected(settings: Settings) -> str:
    return (settings.api_key or "").strip()


def _session_key(settings: Settings) -> bytes:
    """Signing key for session tokens.

    Derived from the API key unless an explicit secret is configured, so rotating
    the platform key invalidates every outstanding session.
    """

    configured = (settings.session_secret or "").strip()
    if configured:
        return configured.encode()
    return hmac.new(_expected(settings).encode(), b"ndr-session-v1", hashlib.sha256).digest()


def issue_session(settings: Settings, ttl_s: int | None = None) -> tuple[str, int]:
    """Return ``(token, expires_at_epoch)`` for a freshly authenticated browser."""

    ttl = int(ttl_s if ttl_s is not None else settings.session_ttl_s or DEFAULT_SESSION_TTL_S)
    expires = int(time.time()) + max(60, ttl)
    mac = hmac.new(_session_key(settings), str(expires).encode(), hashlib.sha256).hexdigest()
    return f"{expires}.{mac}", expires


def verify_session(settings: Settings, token: str | None) -> bool:
    if not token or "." not in token:
        return False
    expires_text, mac = token.split(".", 1)
    try:
        expires = int(expires_text)
    except ValueError:
        return False
    expected = hmac.new(_session_key(settings), str(expires).encode(), hashlib.sha256).hexdigest()
    # Signature first (constant time), expiry second: an unsigned token never
    # reaches the clock comparison.
    if not hmac.compare_digest(mac, expected):
        return False
    return expires > time.time()


def session_expiry(settings: Settings, token: str | None) -> int | None:
    if not verify_session(settings, token):
        return None
    return int(str(token).split(".", 1)[0])


def _not_configured() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={
            "code": AUTH_NOT_CONFIGURED,
            "message": "The service has no API key configured, so data endpoints are closed.",
            "remediation": [
                "Set IDS_API_KEY (or NDR_API_KEY) in the hosting environment, e.g. Render -> Environment.",
                "Redeploy the service so the new variable is loaded.",
                "Open the dashboard and sign in with that key; it stays in an HttpOnly cookie.",
            ],
            "health": "/api/v1/health",
        },
    )


def require_key(settings: Settings, provided: str | None) -> None:
    """Header-only check, used by write endpoints."""

    expected = _expected(settings)
    if not expected:
        raise _not_configured()
    if not hmac.compare_digest((provided or "").strip(), expected):
        raise HTTPException(
            status_code=401,
            detail={
                "code": INVALID_API_KEY,
                "message": "The X-API-Key header is missing or does not match the configured key.",
            },
        )


def require_access(
    settings: Settings,
    provided: str | None,
    request: Request,
    *,
    allow_cookie: bool = True,
) -> str:
    """Authorise a read. Returns the mechanism used: ``api_key`` or ``session``."""

    expected = _expected(settings)
    if not expected:
        raise _not_configured()
    if (provided or "").strip() and hmac.compare_digest(provided.strip(), expected):
        return "api_key"
    if allow_cookie:
        token = request.cookies.get(SESSION_COOKIE)
        if verify_session(settings, token):
            return "session"
        if token:
            raise HTTPException(
                status_code=401,
                detail={
                    "code": INVALID_SESSION,
                    "message": "The dashboard session expired or was invalidated. Sign in again.",
                },
            )
    raise HTTPException(
        status_code=401,
        detail={
            "code": INVALID_API_KEY,
            "message": "Provide X-API-Key, or sign in to obtain a dashboard session.",
        },
    )


def request_is_https(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    if forwarded:
        return forwarded == "https"
    return request.url.scheme == "https"


def cookie_settings(settings: Settings, request: Request) -> dict[str, object]:
    secure = settings.session_cookie_secure
    return {
        "key": SESSION_COOKIE,
        "httponly": True,
        "samesite": settings.session_samesite,
        "secure": request_is_https(request) if secure is None else bool(secure),
        "path": "/",
    }


def auth_summary(settings: Settings) -> dict[str, object]:
    """Non-secret description of the auth state, safe to expose on /health."""

    return {
        "configured": settings.auth_configured,
        "source": settings.api_key_source,
    }


def session_summary(settings: Settings) -> dict[str, object]:
    """Browser-session parameters. No secret, only how they are derived."""

    secure = settings.session_cookie_secure
    return {
        "cookie": SESSION_COOKIE,
        "ttl_s": settings.session_ttl_s or DEFAULT_SESSION_TTL_S,
        "same_site": settings.session_samesite,
        "secure": "per-request" if secure is None else bool(secure),
        "signing_key": "configured" if (settings.session_secret or "").strip() else "derived from the API key",
        "login_endpoint": "/api/v1/session",
    }
