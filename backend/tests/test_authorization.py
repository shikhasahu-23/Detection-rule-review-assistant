from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.authorization import (
    Principal,
    can_edit_detections,
    can_manage_workspace,
    can_review_detections,
    require_roles,
    require_same_organization,
)
from app.models.identity import MembershipRole


@pytest.fixture
def principal() -> Principal:
    return Principal(
        user_id=uuid4(),
        organization_id=uuid4(),
        role=MembershipRole.DETECTION_ENGINEER,
    )


def test_detection_engineer_can_edit_but_not_manage_or_approve(principal: Principal) -> None:
    assert can_edit_detections(principal)
    assert not can_manage_workspace(principal)
    assert not can_review_detections(principal)


def test_reviewer_can_review_but_not_edit(principal: Principal) -> None:
    reviewer = Principal(principal.user_id, principal.organization_id, MembershipRole.REVIEWER)
    assert can_review_detections(reviewer)
    assert not can_edit_detections(reviewer)


def test_viewer_has_read_only_role(principal: Principal) -> None:
    viewer = Principal(principal.user_id, principal.organization_id, MembershipRole.VIEWER)
    assert not can_edit_detections(viewer)
    assert not can_review_detections(viewer)
    assert not can_manage_workspace(viewer)


def test_role_guard_rejects_forbidden_action(principal: Principal) -> None:
    with pytest.raises(HTTPException) as exc:
        require_roles(principal, {MembershipRole.ADMIN})
    assert exc.value.status_code == 403


def test_tenant_guard_hides_cross_organization_resources(principal: Principal) -> None:
    with pytest.raises(HTTPException) as exc:
        require_same_organization(principal, uuid4())
    assert exc.value.status_code == 404


def test_tenant_guard_allows_same_organization(principal: Principal) -> None:
    require_same_organization(principal, principal.organization_id)
