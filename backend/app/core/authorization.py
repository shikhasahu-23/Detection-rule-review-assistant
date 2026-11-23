from dataclasses import dataclass
from typing import Annotated
from enum import StrEnum
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status


class Role(StrEnum):
    ADMIN = "Admin"
    DETECTION_ENGINEER = "Detection Engineer"
    REVIEWER_APPROVER = "Reviewer/Approver"
    VIEWER = "Viewer"


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated user identity attached by a trusted authentication layer."""

    user_id: UUID
    organization_id: UUID
    role: Role


def get_current_principal(request: Request) -> Principal:
    """Return the principal established by trusted middleware; never trust identity headers."""
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, Principal):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def require_roles(*allowed_roles: Role):
    """Build a FastAPI dependency that enforces an explicit role allow-list."""
    if not allowed_roles:
        raise ValueError("At least one allowed role is required")

    def authorize(
        principal: Annotated[Principal, Depends(get_current_principal)],
    ) -> Principal:
        if principal.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role permissions",
            )
        return principal

    return authorize


def assert_organization_access(principal: Principal, organization_id: UUID) -> None:
    """Enforce tenant boundaries without revealing whether another tenant exists."""
    if principal.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found",
        )
