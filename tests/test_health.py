"""Health endpoint tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_health_endpoint() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["service"] == "tracepoint-api"
    assert payload["version"] == "0.1.0"
    assert payload["environment"] == "local"


def test_live_endpoint() -> None:
    client = TestClient(create_app())

    response = client.get("/live")

    assert response.status_code == 200
    assert response.json()["status"] == "alive"


def test_ready_endpoint() -> None:
    client = TestClient(create_app())

    response = client.get("/ready")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["service"] == "tracepoint-api"
    assert payload["checks"]["config"] == "ok"
    assert payload["checks"]["database"] == "ok"
