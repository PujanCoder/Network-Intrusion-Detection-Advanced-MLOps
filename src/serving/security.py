"""API-key handling for the serving app.

Three outcomes, all explicit and none of them silent:

* key configured and matching  -> the request proceeds;
* key configured, wrong/missing -> ``401`` (the caller is not authorised);
* no key configured at all      -> ``503`` with a machine-readable code, because
  the deployment cannot serve data safely. This is a configuration fault, not an
  outage: the process is healthy and ``/api/v1/health`` reports it.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException

from src.serving.config import Settings

AUTH_NOT_CONFIGURED = "auth_not_configured"
INVALID_API_KEY = "invalid_api_key"


def require_key(settings: Settings, provided: str | None) -> None:
    expected = (settings.api_key or "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail={
                "code": AUTH_NOT_CONFIGURED,
                "message": "The service has no API key configured, so data endpoints are closed.",
                "remediation": [
                    "Set IDS_API_KEY (or NDR_API_KEY) in the hosting environment, e.g. Render -> Environment.",
                    "Redeploy the service so the new variable is loaded.",
                    "Open the dashboard once as /?api_key=<value>; it stores the key in localStorage.",
                ],
                "health": "/api/v1/health",
            },
        )
    if not hmac.compare_digest((provided or "").strip(), expected):
        raise HTTPException(
            status_code=401,
            detail={
                "code": INVALID_API_KEY,
                "message": "The X-API-Key header is missing or does not match the configured key.",
            },
        )


def auth_summary(settings: Settings) -> dict[str, object]:
    """Non-secret description of the auth state, safe to expose on /health."""

    return {
        "configured": settings.auth_configured,
        "source": settings.api_key_source,
    }
