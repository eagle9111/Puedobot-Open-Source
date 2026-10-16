"""API Key authentication middleware for PuedoBot Core."""
from __future__ import annotations

import secrets
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from app.core.config import settings


async def authenticate_request(request: Request, call_next: RequestResponseEndpoint) -> Response:
    """Validate PUEDOBOT_API_KEY for all endpoints (except preflight)."""
    provided_key = request.headers.get("x-api-key", "")
    if not provided_key:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            provided_key = auth[7:].strip()

    valid_key = bool(settings.PUEDOBOT_API_KEY and provided_key) and secrets.compare_digest(
        provided_key.encode(), (settings.PUEDOBOT_API_KEY or "").encode()
    )

    preflight = request.method == "OPTIONS" and "access-control-request-method" in request.headers
    if not valid_key and not preflight:
        return JSONResponse(
            {"detail": "Unauthorized: Provide a valid PUEDOBOT_API_KEY header."},
            status_code=401,
            headers={"Cache-Control": "no-store"},
        )

    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response
