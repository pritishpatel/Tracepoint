"""Alembic migration environment for Tracepoint.

Alembic uses this module to discover SQLAlchemy metadata and configure database
connections for offline and online migrations. The database URL is resolved from
Tracepoint's typed configuration loader instead of being duplicated in
alembic.ini.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Connection
from tracepoint.core.config import get_settings
from tracepoint.db.base import Base
from tracepoint.models import Finding, TriageResult

alembic_config = context.config

if alembic_config.config_file_name is not None:
    fileConfig(alembic_config.config_file_name)

metadata = Base.metadata

# Keep imported ORM models referenced so SQLAlchemy registers their tables.
_ = (Finding, TriageResult)


def database_url() -> str:
    """Return the configured database URL for migration execution."""
    return get_settings().db.url


def run_offline_migrations() -> None:
    """Run migrations without opening a live database connection."""
    context.configure(
        url=database_url(),
        target_metadata=metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_online_migrations() -> None:
    """Run migrations using a live SQLAlchemy connection."""
    configuration = alembic_config.get_section(alembic_config.config_ini_section, {})
    configuration["sqlalchemy.url"] = database_url()

    engine = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with engine.connect() as connection:
        run_migrations_with_connection(connection)


def run_migrations_with_connection(connection: Connection) -> None:
    """Configure Alembic with a live connection and execute migrations."""
    context.configure(
        connection=connection,
        target_metadata=metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_offline_migrations()
else:
    run_online_migrations()
