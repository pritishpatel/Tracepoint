"""Health endpoints for service, liveness, and readiness checks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, cast

from fastapi import APIRouter, Request

from tracepoint.core.config import Settings

router = APIRouter(tags=["health"])


class HealthResponseBuilder:
    """Build health-check response payloads from request-scoped application state."""

    def __init__(self, request: Request | None = None) -> None:
        self.request = request

    @staticmethod
    def current_utc_timestamp() -> str:
        """Return a timezone-aware UTC timestamp in ISO 8601 format."""
        return datetime.now(timezone.utc).isoformat()

    def settings(self) -> Settings:
        """Return validated application settings attached to FastAPI state."""
        if self.request is None:
            raise RuntimeError("request is required to access application settings")

        return cast(Settings, self.request.app.state.settings)

    def service_health(self) -> dict[str, Any]:
        """Build the full service health response."""
        settings = self.settings()

        return {
            "status": "ok",
            "service": settings.service.name,
            "version": settings.service.version,
            "environment": settings.service.env,
            "timestamp": self.current_utc_timestamp(),
        }

    def liveness(self) -> dict[str, str]:
        """Build the process liveness response."""
        return {
            "status": "alive",
            "timestamp": self.current_utc_timestamp(),
        }

    def readiness(self) -> dict[str, Any]:
        """Build the readiness response.

        At this stage readiness only verifies that configuration loaded
        successfully. Database readiness will be added after the database layer.
        """
        settings = self.settings()

        return {
            "status": "ready",
            "service": settings.service.name,
            "checks": {
                "config": "ok",
            },
            "timestamp": self.current_utc_timestamp(),
        }


@router.get("/health")
def health(request: Request) -> dict[str, Any]:
    """Return service metadata for smoke tests and monitoring systems."""
    return HealthResponseBuilder(request).service_health()


@router.get("/live")
def live() -> dict[str, str]:
    """Return process liveness state."""
    return HealthResponseBuilder().liveness()


@router.get("/ready")
def ready(request: Request) -> dict[str, Any]:
    """Return readiness state for deployment and traffic-routing checks."""
    return HealthResponseBuilder(request).readiness()
