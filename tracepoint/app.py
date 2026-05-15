"""FastAPI application factory for Tracepoint.

This module owns the HTTP application assembly: configuration loading,
structured logging setup, middleware registration, router mounting, and
lifecycle logging.

Database schema creation is intentionally not performed here. Production and
local development should use Alembic migrations instead:

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

from tracepoint.api.activity import router as activity_router
from tracepoint.api.dashboard import router as dashboard_router
from tracepoint.api.duplicates import router as duplicates_router
from tracepoint.api.evidence import router as evidence_router
from tracepoint.api.export import router as export_router
from tracepoint.api.findings import router as findings_router
from tracepoint.api.health import router as health_router
from tracepoint.api.intake import router as intake_router
from tracepoint.api.trends import router as trends_router
from tracepoint.api.triage import router as triage_router
from tracepoint.core.config import Settings, get_settings
from tracepoint.core.logging import configure_logging

logger = logging.getLogger(__name__)


class ApplicationFactory:
    """Build and configure the Tracepoint FastAPI application."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize the application factory."""
        self.settings = settings or get_settings()

    def create(self) -> FastAPI:
        """Create and configure a FastAPI application instance."""
        configure_logging(self.settings)

        app = FastAPI(
            title="Tracepoint",
            version=self.settings.service.version,
            docs_url=(
                self.settings.server.docs.swagger if self.settings.server.docs.enabled else None
            ),
            redoc_url=(
                self.settings.server.docs.redoc if self.settings.server.docs.enabled else None
            ),
            openapi_url=(
                self.settings.server.docs.openapi if self.settings.server.docs.enabled else None
            ),
            lifespan=self.lifespan,
        )

        self.configure_state(app)
        self.configure_middleware(app)
        self.configure_routes(app)

        return app

    def configure_state(self, app: FastAPI) -> None:
        """Attach process-wide application state."""
        app.state.settings = self.settings

    def configure_middleware(self, app: FastAPI) -> None:
        """Configure HTTP middleware."""
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
        """Mount health and versioned API routers."""
        api_prefix = self.settings.server.prefix

        app.include_router(health_router)
        app.include_router(findings_router, prefix=api_prefix)
        app.include_router(triage_router, prefix=api_prefix)
        app.include_router(duplicates_router, prefix=api_prefix)
        app.include_router(dashboard_router, prefix=api_prefix)
        app.include_router(trends_router, prefix=api_prefix)
        app.include_router(activity_router, prefix=api_prefix)
        app.include_router(evidence_router, prefix=api_prefix)
        app.include_router(export_router, prefix=api_prefix)
        app.include_router(intake_router, prefix=api_prefix)

    @asynccontextmanager
    async def lifespan(self, app: FastAPI) -> AsyncIterator[None]:
        """Run application startup and shutdown hooks."""
        app.state.settings = self.settings

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
