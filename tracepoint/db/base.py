"""SQLAlchemy declarative base for Tracepoint models.

All ORM models should inherit from Base directly or through project mixins. This
keeps database metadata centralized for table creation, migrations, and future
Alembic integration.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
