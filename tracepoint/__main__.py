"""Command-line entrypoint for running the Tracepoint API locally."""

from __future__ import annotations

import uvicorn

from tracepoint.core.config import get_settings


class TracepointServer:
    """Start the local Tracepoint API server from validated settings."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def run(self) -> None:
        """Run the ASGI application with Uvicorn."""
        uvicorn.run(
            "tracepoint.app:app",
            host=self.settings.server.host,
            port=self.settings.server.port,
            reload=self.settings.server.reload,
        )


def main() -> None:
    """Run the Tracepoint API server."""
    TracepointServer().run()


if __name__ == "__main__":
    main()
