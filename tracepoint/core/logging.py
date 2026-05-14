"""Application logging configuration for Tracepoint.

This module centralizes logging setup so the rest of the application can request
named loggers without knowing whether logs are emitted as human-readable console
text or JSON objects for production log aggregation.
"""

from __future__ import annotations

import json
import logging
import logging.config
from datetime import datetime, timezone
from typing import Any, ClassVar

from tracepoint.core.config.schema import Settings

CONSOLE_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


class JsonLogFormatter(logging.Formatter):
    """Format log records as compact JSON objects with stable field names."""

    reserved_record_fields: ClassVar[set[str]] = set(
        logging.LogRecord("", 0, "", 0, "", (), None).__dict__
    )

    def format(self, record: logging.LogRecord) -> str:
        log_event: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        extra_fields = {
            key: value
            for key, value in record.__dict__.items()
            if key not in self.reserved_record_fields
        }
        log_event.update(extra_fields)

        if record.exc_info:
            log_event["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_event, default=str, separators=(",", ":"))


class LoggingConfigurator:
    """Configure process-wide logging from validated application settings."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def configure(self) -> None:
        formatter_name = "json" if self.settings.log.format == "json" else "console"

        logging.config.dictConfig(
            {
                "version": 1,
                "disable_existing_loggers": False,
                "formatters": {
                    "console": {"format": CONSOLE_LOG_FORMAT},
                    "json": {"()": JsonLogFormatter},
                },
                "handlers": {
                    "console": {
                        "class": "logging.StreamHandler",
                        "formatter": formatter_name,
                        "level": self.settings.log.level,
                    },
                },
                "root": {
                    "handlers": ["console"],
                    "level": self.settings.log.level,
                },
                "loggers": {
                    "tracepoint": {
                        "handlers": ["console"],
                        "level": self.settings.log.level,
                        "propagate": False,
                    },
                    "uvicorn": {
                        "handlers": ["console"],
                        "level": self.settings.log.level,
                        "propagate": False,
                    },
                    "uvicorn.error": {
                        "handlers": ["console"],
                        "level": self.settings.log.level,
                        "propagate": False,
                    },
                    "uvicorn.access": {
                        "handlers": ["console"],
                        "level": self.settings.log.level,
                        "propagate": False,
                    },
                },
            }
        )


def configure_logging(settings: Settings) -> None:
    """Configure application logging.

    This wrapper keeps the public API small while allowing the implementation to
    remain class-based and testable.
    """
    LoggingConfigurator(settings).configure()


def get_logger(name: str) -> logging.Logger:
    """Return a named application logger."""
    return logging.getLogger(name)
