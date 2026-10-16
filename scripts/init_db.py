"""Database schema initialization script.

Executes Base.metadata.create_all to ensure all PostgreSQL tables exist.
Can be executed standalone:
    python scripts/init_db.py
"""
import logging
from app.db.session import engine
from app.db.models import Base

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")
logger = logging.getLogger("puedobot.scripts.init_db")


def init_database() -> None:
    """Creates all tables defined in models.py if they do not exist."""
    logger.info("Connecting to PostgreSQL and creating tables...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise


if __name__ == "__main__":
    init_database()
