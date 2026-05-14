"""Database-specific exceptions for Tracepoint."""

from __future__ import annotations


class DatabaseError(RuntimeError):
    """Base exception for database infrastructure failures."""


class DatabaseConnectionError(DatabaseError):
    """Raised when the application cannot connect to the configured database."""
