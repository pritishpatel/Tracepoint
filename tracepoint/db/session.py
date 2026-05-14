"""Database engine and session management.

The application uses SQLAlchemy sessions for unit-of-work boundaries and
Alembic for schema management. Runtime application startup should not create or
modify database tables automatically.

For local development or isolated tests, `create_schema_for_development()` and
`drop_schema_for_development()` are available as explicit utility methods.
"""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from typing_extensions import Self

from tracepoint.core.config import get_settings
from tracepoint.db.base import Base
from tracepoint.db.errors import DatabaseConnectionError


class DatabaseManager:
    """Own SQLAlchemy engine creation, sessions, and database health checks."""

    def __init__(self, database_url: str | None = None) -> None:
        """Initialize the manager with an explicit or configured database URL."""
        settings = get_settings()
        self.database_url = database_url or settings.db.url
        self.engine = self.create_engine()
        self.session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )

    def create_engine(self) -> Engine:
        """Create the SQLAlchemy engine for the configured database URL."""
        connect_args: dict[str, object] = {}

        if self.database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False

        return create_engine(
            self.database_url,
            pool_pre_ping=True,
            connect_args=connect_args,
        )

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        """Provide a transactional SQLAlchemy session scope."""
        session = self.session_factory()

        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def health_check(self) -> bool:
        """Verify that the configured database accepts a basic query."""
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except SQLAlchemyError as exc:
            raise DatabaseConnectionError("Database health check failed") from exc

    def create_schema_for_development(self) -> None:
        """Create all registered tables for local-only development workflows.

        Production deployments should use Alembic migrations instead:

            alembic upgrade head

        This method exists for isolated test fixtures and quick local
        experiments where migration execution would add unnecessary overhead.
        """
        Base.metadata.create_all(bind=self.engine)

    def drop_schema_for_development(self) -> None:
        """Drop all registered tables for local-only development workflows."""
        Base.metadata.drop_all(bind=self.engine)

    def dispose(self) -> None:
        """Release pooled database connections held by the engine."""
        self.engine.dispose()

    @classmethod
    def from_url(cls, database_url: str) -> Self:
        """Create a manager from an explicit database URL."""
        return cls(database_url=database_url)


database_manager = DatabaseManager()


def get_database_manager() -> DatabaseManager:
    """Return the process-wide database manager."""
    return database_manager


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a database session."""
    with database_manager.session_scope() as session:
        yield session
