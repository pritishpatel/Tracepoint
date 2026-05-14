"""Database engine and session management.

This module owns SQLAlchemy engine construction and session lifecycle helpers.
Application code should depend on DatabaseManager instead of constructing
engines or sessions directly.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from tracepoint.core.config import Settings, get_settings
from tracepoint.db.base import Base
from tracepoint.db.errors import DatabaseConnectionError


class DatabaseManager:
    """Create and manage SQLAlchemy engine/session resources."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.engine = self.create_engine()
        self.session_factory = self.create_session_factory(self.engine)

    def create_engine(self) -> Engine:
        """Create a SQLAlchemy engine from application settings."""
        engine_options: dict[str, Any] = {
            "echo": self.settings.db.echo,
            "pool_pre_ping": self.settings.db.pre_ping,
            "future": True,
        }

        if self.settings.db.url.startswith("sqlite"):
            engine_options["connect_args"] = {"check_same_thread": False}

        return create_engine(self.settings.db.url, **engine_options)

    @staticmethod
    def create_session_factory(engine: Engine) -> sessionmaker[Session]:
        """Create a SQLAlchemy session factory bound to the provided engine."""
        return sessionmaker(
            bind=engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
            class_=Session,
        )

    def create_all_tables(self) -> None:
        """Create all registered tables for local development and tests."""
        import tracepoint.models  # noqa: F401

        Base.metadata.create_all(bind=self.engine)

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """Provide a transactional session scope."""
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
        """Return True when the database accepts a simple query."""
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except SQLAlchemyError as exc:
            raise DatabaseConnectionError("Database health check failed") from exc


database_manager = DatabaseManager()


def get_database_manager() -> DatabaseManager:
    """Return the process-wide database manager."""
    return database_manager


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a database session."""
    with database_manager.session_scope() as session:
        yield session
