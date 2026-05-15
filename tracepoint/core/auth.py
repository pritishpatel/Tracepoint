"""OIDC-oriented role dependencies.

Local development keeps authentication optional. Production deployments should
set TRACEPOINT_AUTH_REQUIRED=true and provide a verifying OIDC gateway or token
validation layer in front of this dependency.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    """Authenticated user and authorization roles."""

    subject: str
    roles: frozenset[str]


def auth_required() -> bool:
    """Return whether API auth is enforced for this deployment."""
    return os.getenv("TRACEPOINT_AUTH_REQUIRED", "false").lower() == "true"


def current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> Principal:
    """Return the current principal or a local development principal."""
    if credentials is None:
        if auth_required():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        return Principal(subject="local-analyst", roles=frozenset({"admin", "analyst", "viewer"}))

    # Placeholder for production JWKS verification. In local mode, the bearer
    # token value acts as the subject so route policies can be exercised.
    return Principal(subject=credentials.credentials, roles=frozenset({"analyst", "viewer"}))


def require_roles(*allowed_roles: str) -> Callable[[Principal], Principal]:
    """Create a dependency that requires at least one allowed role."""

    def dependency(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
        if principal.roles.isdisjoint(allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return principal

    return dependency
