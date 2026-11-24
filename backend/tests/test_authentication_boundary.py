import app.main
import fastapi.testclient


client = fastapi.testclient.TestClient(app.main.app)


def test_identity_endpoint_rejects_requests_without_trusted_principal():
    response = client.get("/api/v1/identity/me")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_intelligence_read_endpoints_reject_unauthenticated_requests():
    organization_id = "00000000-0000-0000-0000-000000000001"
    paths = [
        f"/api/v1/intelligence/organizations/{organization_id}/feeds/health",
        f"/api/v1/intelligence/organizations/{organization_id}/ingestion-runs",
        f"/api/v1/intelligence/organizations/{organization_id}/quarantine",
        f"/api/v1/intelligence/organizations/{organization_id}/indicators",
        f"/api/v1/intelligence/organizations/{organization_id}/entities",
    ]

    for path in paths:
        response = client.get(path)
        assert response.status_code == 401, path
        assert response.json()["detail"] == "Authentication required"


def test_identity_headers_cannot_create_a_trusted_principal():
    response = client.get(
        "/api/v1/identity/me",
        headers={
            "X-User-ID": "00000000-0000-0000-0000-000000000001",
            "X-Organization-ID": str(uuid4()),
            "X-Role": "Admin",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_intelligence_write_endpoint_rejects_unauthenticated_request():
    organization_id = "00000000-0000-0000-0000-000000000001"
    response = client.post(
        f"/api/v1/intelligence/organizations/{organization_id}/entities",
        json={"entity_type": "malware", "name": "Example"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"
