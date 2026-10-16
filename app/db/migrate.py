"""Tiny, idempotent schema upgrader.

The project has no Alembic yet, and ``create_all`` never alters existing tables.
``ADD COLUMN IF NOT EXISTS`` (PostgreSQL) is safe to run on every startup, so an
existing database picks up new columns without losing any stored findings.
"""
import logging

from sqlalchemy import text

from app.db.models import Base, PERFORMANCE_INDEXES
from app.db.session import engine

logger = logging.getLogger(__name__)

_COLUMN_UPGRADES = [
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS confidence INTEGER",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS source VARCHAR(32)",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS verification_note TEXT",
    "ALTER TABLE repositories ADD COLUMN IF NOT EXISTS repo_name VARCHAR(256)",
    "ALTER TABLE repositories ADD COLUMN IF NOT EXISTS size_kb INTEGER",
    "ALTER TABLE repositories ADD COLUMN IF NOT EXISTS stars INTEGER",
    "ALTER TABLE repositories ADD COLUMN IF NOT EXISTS status VARCHAR(32)",
]


def ensure_schema() -> None:
    """Create missing tables, then add any columns introduced after the first release."""
    try:
        Base.metadata.create_all(bind=engine)
        with engine.begin() as conn:
            for statement in _COLUMN_UPGRADES:
                conn.execute(text(statement))
        with engine.begin() as conn:
            if conn.dialect.name == "postgresql":
                conn.execute(text("SET LOCAL lock_timeout = '5s'"))
                conn.execute(text("SET LOCAL statement_timeout = '60s'"))
            for index in PERFORMANCE_INDEXES:
                index.create(bind=conn, checkfirst=True)
    except Exception as exc:
        logger.error(f"Schema upgrade failed: {exc}")
        raise exc
