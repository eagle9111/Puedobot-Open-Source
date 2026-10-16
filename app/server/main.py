import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.db.migrate import ensure_schema
from app.server.routes import activity, findings, repositories, scan


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Refuse to start if PUEDOBOT_API_KEY is unset or empty
if not settings.PUEDOBOT_API_KEY or not settings.PUEDOBOT_API_KEY.strip():
    raise RuntimeError(
        "CRITICAL STARTUP ERROR: PUEDOBOT_API_KEY is not set in environment. "
        "Server refuses to start without API authentication key. "
        "Set PUEDOBOT_API_KEY in your environment before launching PuedoBot."
    )

from contextlib import asynccontextmanager

if settings.is_remote_allowed:
    logging.getLogger(__name__).warning(
        "⚠️  STARTUP WARNING: Remote access is enabled (PUEDOBOT_ALLOW_REMOTE=true). Server can bind to 0.0.0.0 and accept external network connections."
    )

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        ensure_schema()
    except Exception as exc:
        logging.getLogger("puedobot.server").critical(
            f"\n❌ DATABASE STARTUP ERROR: Unable to connect to PostgreSQL at {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}.\n"
            f"Please verify PostgreSQL service is active and credentials are correct.\n"
            f"Error details: {exc}\n"
        )
        raise SystemExit(1)
    yield

app = FastAPI(title="PuedoBot Server", version="1.0.0", lifespan=lifespan)

# Restrict CORS to dashboard origins only (reject wildcard '*')
ALLOWED_DASHBOARD_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_DASHBOARD_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["X-API-Key", "Content-Type", "Authorization"],
)

# CLI clients use API keys; the private dashboard requires its access code.
from app.server.auth import authenticate_request

app.middleware("http")(authenticate_request)

# Register modular routes
app.include_router(activity.router)
app.include_router(scan.router)
app.include_router(findings.router)
app.include_router(repositories.router)

# Mount local standalone dashboard if folder exists
import os
from fastapi.staticfiles import StaticFiles

dashboard_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "dashboard")
if os.path.isdir(dashboard_dir):
    app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")