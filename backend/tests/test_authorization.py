from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core.authorization import (
    Principal,
    Role,
    assert_organization_access,
    get_current_principal,
    require_roles,
)


def make_request(principal: Principal | None = None) -> Request:
    request = Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [],
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
        }
    )
    if principal is not None:
        request.state.principal = principal
    return request


def test_missing_trusted_principal_is_unauthorized() -> None:
    with pytest.raises(HTTPException) as exc_info:
        get_current_principal(make_request())

    assert exc_info.value.status_code == 401
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}


def test_current_principal_is_taken_from_request_state() -> None:
    principal = Principal(uuid4(), uuid4(), Role.DETECTION_ENGINEER)

    assert get_current_principal(make_request(principal)) is principal


def test_role_dependency_allows_only_explicit_roles() -> None:
    authorize = require_roles(Role.ADMIN, Role.REVIEWER_APPROVER)
    reviewer = Principal(uuid4(), uuid4(), Role.REVIEWER_APPROVER)
    viewer = Principal(uuid4(), uuid4(), Role.VIEWER)

    assert authorize(reviewer) is reviewer
    with pytest.raises(HTTPException) as exc_info:
        authorize(viewer)

    assert exc_info.value.status_code == 403


def test_role_dependency_rejects_empty_allow_list() -> None:
    with pytest.raises(ValueError, match="At least one allowed role"):
        require_roles()


def test_organization_scope_allows_same_tenant() -> None:
    organization_id = uuid4()
    principal = Principal(uuid4(), organization_id, Role.VIEWER)

    assert_organization_access(principal, organization_id)


def test_organization_scope_hides_cross_tenant_resources() -> None:
    principal = Principal(uuid4(), uuid4(), Role.VIEWER)

    with pytest.raises(HTTPException) as exc_info:
        assert_organization_access(principal, uuid4())

    assert exc_info.value.status_code == 404
