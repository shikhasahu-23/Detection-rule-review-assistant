from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.authorization import (
    Principal,
    Role,
    assert_organization_access,
    get_current_principal,
    require_roles,
)
from app.db.session import get_db
from app.models.identity import TeamMembership, User

router = APIRouter(prefix="/api/v1", tags=["identity"])


class CurrentIdentityResponse(BaseModel):
    user_id: UUID
    organization_id: UUID
    role: Role


class TeamMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: UUID
    email: str
    display_name: str
    role: str


@router.get("/identity/me", response_model=CurrentIdentityResponse)
def read_current_identity(
    principal: Principal = Depends(get_current_principal),
) -> CurrentIdentityResponse:
    return CurrentIdentityResponse(
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        role=principal.role,
    )


@router.get(
    "/organizations/{organization_id}/members",
    response_model=list[TeamMemberResponse],
    dependencies=[Depends(require_roles(Role.ADMIN))],
)
def list_organization_members(
    organization_id: UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[TeamMemberResponse]:
    assert_organization_access(principal, organization_id)
    statement = (
        select(
            User.id.label("user_id"),
            User.email,
            User.display_name,
            TeamMembership.role,
        )
        .join(TeamMembership, TeamMembership.user_id == User.id)
        .where(
            TeamMembership.organization_id == organization_id,
            User.is_active.is_(True),
        )
        .order_by(User.email)
    )
    return [TeamMemberResponse.model_validate(row) for row in db.execute(statement).mappings()]
