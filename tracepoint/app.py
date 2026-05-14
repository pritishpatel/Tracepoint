"""FastAPI application factory for Tracepoint.

This module owns API bootstrap: loading validated settings, attaching them to
application state, configuring middleware, registering routers, and wiring
startup/shutdown behavior through FastAPI's lifespan interface.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from tracepoint.api.findings import router as findings_router
from tracepoint.api.health import router as health_router
from tracepoint.core.config import Settings, get_settings
from tracepoint.core.logging import configure_logging, get_logger
from tracepoint.db import get_database_manager

APPLICATION_TITLE = "Tracepoint"

logger = get_logger(__name__)


class ApplicationFactory:
    """Build and configure the Tracepoint FastAPI application."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def create(self) -> FastAPI:
        """Create a fully configured FastAPI application instance."""
        application = FastAPI(
            title=APPLICATION_TITLE,
            version=self.settings.service.version,
            debug=self.settings.runtime.debug,
            docs_url=self.documentation_url(self.settings.server.docs.swagger),
            redoc_url=self.documentation_url(self.settings.server.docs.redoc),
            openapi_url=self.documentation_url(self.settings.server.docs.openapi),
            lifespan=lifespan,
        )
        application.state.settings = self.settings

        self.configure_cors(application)
        self.register_routers(application)

        return application

    def documentation_url(self, route: str) -> str | None:
        """Return the documentation route if documentation is enabled."""
        if not self.settings.server.docs.enabled:
            return None
        return route

    def configure_cors(self, application: FastAPI) -> None:
        """Attach CORS middleware when enabled in configuration."""
        if not self.settings.server.cors.enabled:
            return

        application.add_middleware(
            CORSMiddleware,
            allow_origins=self.settings.server.cors.origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def register_routers(self, application: FastAPI) -> None:
        """Register API routers."""
        application.include_router(health_router)
        application.include_router(findings_router, prefix=self.settings.server.prefix)


def get_application_settings(application: FastAPI) -> Settings:
    """Return validated settings stored on FastAPI application state."""
    return cast(Settings, application.state.settings)


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Run startup and shutdown lifecycle hooks for the API process."""
    settings = get_application_settings(application)
    configure_logging(settings)

    if settings.service.env == "local":
        get_database_manager().create_all_tables()

    logger.info(
        "application_started",
        extra={
            "service": settings.service.name,
            "environment": settings.service.env,
            "version": settings.service.version,
        },
    )

    yield

    logger.info(
        "application_stopped",
        extra={
            "service": settings.service.name,
            "environment": settings.service.env,
        },
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the Tracepoint FastAPI application."""
    return ApplicationFactory(settings=settings).create()


app = create_app()
