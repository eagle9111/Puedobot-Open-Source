"""Protect the private dashboard with a separate access code and signed sessions."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections import OrderedDict
from threading import Lock

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from app.core.config import settings

try:
    from app.server.dashboard_login import LOGIN_HTML
except ImportError:
    LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>PuedoBot · Private Workspace</title></head><body style="background:#080d0b;color:#e3eee6;font-family:monospace;padding:40px;text-align:center;"><h1>&gt;_ PUEDOBOT</h1><p>Web dashboard is private and not included in this build. Please operate PuedoBot via the CLI.</p></body></html>"""

_COOKIE_NAME = "puedobot_dashboard"
_ATTEMPTS: OrderedDict[str, tuple[float, int]] = OrderedDict()
_ATTEMPT_LOCK = Lock()


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    return (request.headers.get("sec-fetch-site") in {None, "same-origin", "none"}
            and (origin is None or origin == str(request.base_url).rstrip("/")))


def _signature(payload: str) -> str:
    secret = (settings.PUEDOBOT_DASHBOARD_CODE or "").encode()
    return hmac.new(secret, b"puedobot-dashboard-session-v1:" + payload.encode(), hashlib.sha256).hexdigest()


def _has_session(request: Request) -> bool:
    if len(settings.PUEDOBOT_DASHBOARD_CODE or "") < 32 or not _same_origin(request):
        return False
    token = request.cookies.get(_COOKIE_NAME, "")
    if len(token) > 256:
        return False
    try:
        expiry, nonce, signature = token.split(".")
        return (int(expiry) > time.time() and len(nonce) == 32
                and secrets.compare_digest(signature.encode(), _signature(f"{expiry}.{nonce}").encode()))
    except (ValueError, UnicodeError):
        return False


def _login_allowed(peer: str) -> bool:
    """Bound memory and attempts: five sign-ins per minute per peer, per worker."""
    now = time.monotonic()
    with _ATTEMPT_LOCK:
        start, count = _ATTEMPTS.pop(peer, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        _ATTEMPTS[peer] = (start, count + 1)
        while len(_ATTEMPTS) > 1024:
            _ATTEMPTS.popitem(last=False)
        return count < 5


async def _login(request: Request) -> Response:
    if not _same_origin(request):
        return JSONResponse({"detail": "Sign in from the PuedoBot page."}, status_code=403)
    code = settings.PUEDOBOT_DASHBOARD_CODE or ""
    if len(code) < 32:
        return JSONResponse({"detail": "Configure PUEDOBOT_DASHBOARD_CODE with at least 32 characters on the server."}, status_code=503)
    if not _login_allowed(request.client.host if request.client else "unknown"):
        return JSONResponse({"detail": "Too many attempts. Try again in one minute."}, status_code=429, headers={"Retry-After": "60"})
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 2048:
            return JSONResponse({"detail": "Invalid sign-in request."}, status_code=413)
    try:
        data = json.loads(body)
        submitted = data.get("code") if isinstance(data, dict) else None
    except (ValueError, UnicodeError):
        submitted = None
    if not isinstance(submitted, str) or not secrets.compare_digest(submitted.encode(), code.encode()):
        return JSONResponse({"detail": "Incorrect access code."}, status_code=401)
    lifetime = settings.PUEDOBOT_DASHBOARD_SESSION_HOURS * 3600
    payload = f"{int(time.time()) + lifetime}.{secrets.token_hex(16)}"
    response = JSONResponse({"success": True})
    response.set_cookie(_COOKIE_NAME, f"{payload}.{_signature(payload)}", max_age=lifetime,
                        httponly=True, samesite="strict", secure=request.url.scheme == "https", path="/")
    return response


async def authenticate_request(request: Request, call_next: RequestResponseEndpoint) -> Response:
    path = request.url.path
    session = _has_session(request)
    if path == "/auth/login" and request.method == "POST":
        response = await _login(request)
    elif path == "/auth/logout" and request.method == "POST":
        if not _same_origin(request):
            return JSONResponse({"detail": "Forbidden"}, status_code=403)
        response = JSONResponse({"success": True})
        response.delete_cookie(_COOKIE_NAME, path="/", httponly=True, samesite="strict")
    elif path == "/auth/session" and request.method == "GET":
        response = JSONResponse({"local_session": session})
    elif path in {"/dashboard", "/dashboard/", "/dashboard/index.html"} and request.method == "GET" and not session:
        response = HTMLResponse(LOGIN_HTML)
    else:
        provided_key = request.headers.get("x-api-key", "")
        if not provided_key:
            auth = request.headers.get("authorization", "")
            if auth.startswith("Bearer "):
                provided_key = auth[7:].strip()
        valid_key = bool(settings.PUEDOBOT_API_KEY and provided_key) and secrets.compare_digest(
            provided_key.encode(), (settings.PUEDOBOT_API_KEY or "").encode())
        # The dashboard itself requires its access code; API keys remain for CLI clients.
        authorized = session if path.startswith("/dashboard") else session or valid_key
        preflight = request.method == "OPTIONS" and "access-control-request-method" in request.headers
        if not authorized and not preflight:
            return JSONResponse({"detail": "Unauthorized: Sign in or provide a valid PUEDOBOT_API_KEY."}, status_code=401, headers={"Cache-Control": "no-store"})
        response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response
