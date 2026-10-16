from collections.abc import Generator
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

# 1. Create the engine with connection pooling
engine = create_engine(
    settings.database_url,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,  # Tests connection health before using it
    echo=settings.DEBUG,  # Logs generated SQL queries if DEBUG=True
)

# 2. Session factory bound to our engine
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)

# 3. Base class for all ORM models to inherit from
class Base(DeclarativeBase):
    pass

# 4. Context manager helper for safe transaction lifecycles
@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Yields a database session with automatic commit on success and rollback on error."""
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()