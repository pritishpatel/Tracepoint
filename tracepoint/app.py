"""FastAPI application factory for Tracepoint.

This module owns HTTP application assembly: configuration loading, structured
logging setup, middleware registration, router mounting, and lifecycle logging.

Database schema creation is intentionally not performed during application
startup. Production and local development should use Alembic migrations instead:

    alembic upgrade head

Keeping schema management outside runtime startup prevents accidental mutation
of production databases and makes deployments reproducible.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.types import Lifespan

from tracepoint.api.findings import router as findings_router
from tracepoint.api.health import router as health_router
from tracepoint.api.triage import router as triage_router
from tracepoint.core.config import Settings, get_settings
from tracepoint.core.logging import configure_logging
from tracepoint.db import DatabaseManager, get_database_manager

logger = logging.getLogger(__name__)


class ApplicationFactory:
    """Create a configured FastAPI application instance.

    The factory keeps application construction explicit and testable. It wires
    together configuration, logging, middleware, routers, and shared application
    state without performing database schema mutations.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        database_manager: DatabaseManager | None = None,
    ) -> None:
        """Initialize the factory with optional dependency overrides.

        Args:
            settings: Optional settings object used by tests or custom runtime
                entrypoints. When omitted, settings are loaded from config files.
            database_manager: Optional database manager override. When omitted,
                the process-wide manager is used.
        """
        self.settings = settings or get_settings()
        self.database_manager = database_manager or get_database_manager()

    def create(self) -> FastAPI:
        """Build and return the FastAPI application."""
        configure_logging(self.settings)

        app = FastAPI(
            title="Tracepoint",
            version=self.settings.service.version,
            debug=self.settings.runtime.debug,
            docs_url=self.settings.server.docs.swagger
            if self.settings.server.docs.enabled
            else None,
            redoc_url=self.settings.server.docs.redoc
            if self.settings.server.docs.enabled
            else None,
            openapi_url=self.settings.server.docs.openapi
            if self.settings.server.docs.enabled
            else None,
            lifespan=cast(Lifespan[FastAPI], self.lifespan),
        )

        app.state.settings = self.settings
        app.state.database_manager = self.database_manager

        self.register_middleware(app)
        self.register_routers(app)

        return app

    def register_middleware(self, app: FastAPI) -> None:
        """Register HTTP middleware for the application."""
        if not self.settings.server.cors.enabled:
            return

        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.settings.server.cors.origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def register_routers(self, app: FastAPI) -> None:
        """Register all API routers.

        Health endpoints intentionally remain unversioned because deployment
        platforms commonly expect simple paths such as /health, /live, and
        /ready. Product APIs are mounted under the configured API prefix.
        """
        app.include_router(health_router)
        app.include_router(findings_router, prefix=self.settings.server.prefix)
        app.include_router(triage_router, prefix=self.settings.server.prefix)

    @asynccontextmanager
    async def lifespan(self, app: FastAPI) -> AsyncIterator[None]:
        """Run application startup and shutdown hooks."""
        app.state.settings = self.settings
        app.state.database_manager = self.database_manager

        logger.info(
            "application_started",
            extra={
                "service": self.settings.service.name,
                "environment": self.settings.service.env,
            },
        )

        yield

        logger.info(
            "application_stopped",
            extra={
                "service": self.settings.service.name,
                "environment": self.settings.service.env,
            },
        )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the Tracepoint FastAPI application."""
    return ApplicationFactory(settings=settings).create()


app = create_app()
