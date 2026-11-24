from dataclasses import dataclass
from uuid import UUID

from fastapi import HTTPException, status

from app.models.identity import MembershipRole


@dataclass(frozen=True)
class Principal:
    """Identity resolved by a trusted authentication adapter, never from request body fields."""

    user_id: UUID
    organization_id: UUID
    role: MembershipRole


def require_roles(principal: Principal, allowed: set[MembershipRole]) -> Principal:
    if principal.role not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    return principal


def require_same_organization(principal: Principal, organization_id: UUID) -> None:
    if principal.organization_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")


def can_manage_workspace(principal: Principal) -> bool:
    return principal.role is MembershipRole.ADMIN


def can_edit_detections(principal: Principal) -> bool:
    return principal.role in {
        MembershipRole.ADMIN,
        MembershipRole.DETECTION_ENGINEER,
    }


def can_review_detections(principal: Principal) -> bool:
    return principal.role in {MembershipRole.ADMIN, MembershipRole.REVIEWER}
