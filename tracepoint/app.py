"""FastAPI application factory for Tracepoint.

This module owns HTTP application assembly: configuration loading, structured
logging setup, middleware registration, router mounting, and lifecycle logging.

Database schema creation is intentionally not performed during application
startup. Production and local development should use Alembic migrations instead:

    alembic upgrade head

Keeping schema management outside application startup prevents accidental
runtime mutation of production databases and makes deployments reproducible.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from tracepoint.api.findings import router as findings_router
from tracepoint.api.health import router as health_router
from tracepoint.core.config import Settings, get_settings
from tracepoint.core.logging import configure_logging
from tracepoint.db import get_database_manager

logger = logging.getLogger(__name__)


class ApplicationFactory:
    """Build and configure the Tracepoint FastAPI application.

    The factory keeps application assembly explicit and testable. It wires
    configuration, logging, middleware, routes, and shared application state in
    one place while keeping database migrations outside the runtime lifecycle.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        """Create an application factory.

        Args:
            settings: Optional pre-loaded settings object. Tests may pass a
                custom settings instance. When omitted, settings are loaded from
                the configured YAML/environment sources.
        """
        self.settings = settings or get_settings()

    def create(self) -> FastAPI:
        """Create and return a configured FastAPI application."""
        configure_logging(self.settings)

        app = FastAPI(
            title="Tracepoint",
            version=self.settings.service.version,
            debug=self.settings.runtime.debug,
            docs_url=self.docs_url,
            redoc_url=self.redoc_url,
            openapi_url=self.openapi_url,
            lifespan=self.lifespan,
        )

        self.configure_application_state(app)
        self.configure_middleware(app)
        self.configure_routes(app)

        return app

    @property
    def docs_url(self) -> str | None:
        """Return the Swagger UI path when API docs are enabled."""
        if not self.settings.server.docs.enabled:
            return None

        return self.settings.server.docs.swagger

    @property
    def redoc_url(self) -> str | None:
        """Return the ReDoc path when API docs are enabled."""
        if not self.settings.server.docs.enabled:
            return None

        return self.settings.server.docs.redoc

    @property
    def openapi_url(self) -> str | None:
        """Return the OpenAPI schema path when API docs are enabled."""
        if not self.settings.server.docs.enabled:
            return None

        return self.settings.server.docs.openapi

    def configure_application_state(self, app: FastAPI) -> None:
        """Attach shared runtime dependencies to FastAPI application state.

        Health checks and future API modules should read process-wide runtime
        dependencies from ``app.state`` instead of reloading configuration or
        constructing infrastructure objects on every request.
        """
        app.state.settings = self.settings
        app.state.database_manager = get_database_manager()

    def configure_middleware(self, app: FastAPI) -> None:
        """Register application middleware."""
        if not self.settings.server.cors.enabled:
            return

        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.settings.server.cors.origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def configure_routes(self, app: FastAPI) -> None:
        """Register HTTP routers."""
        app.include_router(health_router)
        app.include_router(
            findings_router,
            prefix=self.settings.server.prefix,
        )

    @asynccontextmanager
    async def lifespan(self, app: FastAPI) -> AsyncIterator[None]:
        """Log application startup and shutdown lifecycle events."""
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
