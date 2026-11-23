from uuid import uuid4

from fastapi.testclient import TestClient

from app.core.authorization import Principal, Role, get_current_principal
from app.db.session import get_db
from app.main import app


class FakeResult:
    def mappings(self):
        return [
            {
                "user_id": uuid4(),
                "email": "analyst@example.test",
                "display_name": "Analyst",
                "role": "Detection Engineer",
            }
        ]


class FakeSession:
    def execute(self, statement):
        return FakeResult()


def client_for(principal: Principal | None):
    if principal is None:
        app.dependency_overrides.pop(get_current_principal, None)
    else:
        app.dependency_overrides[get_current_principal] = lambda: principal
    app.dependency_overrides[get_db] = lambda: FakeSession()
    return TestClient(app)


def teardown_function():
    app.dependency_overrides.clear()


def test_current_identity_requires_authentication():
    response = client_for(None).get("/api/v1/identity/me")

    assert response.status_code == 401


def test_current_identity_returns_authenticated_principal():
    principal = Principal(uuid4(), uuid4(), Role.DETECTION_ENGINEER)
    response = client_for(principal).get("/api/v1/identity/me")

    assert response.status_code == 200
    assert response.json() == {
        "user_id": str(principal.user_id),
        "organization_id": str(principal.organization_id),
        "role": Role.DETECTION_ENGINEER.value,
    }


def test_viewer_cannot_list_team_members():
    principal = Principal(uuid4(), uuid4(), Role.VIEWER)
    response = client_for(principal).get(
        f"/api/v1/organizations/{principal.organization_id}/members"
    )

    assert response.status_code == 403


def test_admin_cannot_list_another_organizations_members():
    principal = Principal(uuid4(), uuid4(), Role.ADMIN)
    response = client_for(principal).get(
        f"/api/v1/organizations/{uuid4()}/members"
    )

    assert response.status_code == 404


def test_admin_can_list_members_in_own_organization():
    principal = Principal(uuid4(), uuid4(), Role.ADMIN)
    response = client_for(principal).get(
        f"/api/v1/organizations/{principal.organization_id}/members"
    )

    assert response.status_code == 200
    assert response.json()[0]["email"] == "analyst@example.test"
    assert response.json()[0]["role"] == "Detection Engineer"
