from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.authorization import Principal, Role, get_current_principal
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.identity import Organization
from app.models.intelligence import IntelRecord


def test_threat_entity_correlation_and_attack_mapping_are_tenant_scoped():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        organization = Organization(name="Acme", slug="acme-correlation")
        other = Organization(name="Other", slug="other-correlation")
        db.add_all([organization, other])
        db.flush()
        record = IntelRecord(
            organization_id=organization.id,
            record_type="domain",
            value="bad.example",
            normalized_value="bad.example",
        )
        db.add(record)
        db.commit()
        organization_id, other_id, record_id = organization.id, other.id, record.id

    app.dependency_overrides[get_current_principal] = lambda: Principal(
        user_id=uuid4(), organization_id=organization_id, role=Role.DETECTION_ENGINEER
    )

    def override_db():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        base = f"/api/v1/intelligence/organizations/{organization_id}"
        entity_response = client.post(
            f"{base}/entities",
            json={
                "entity_type": "malware",
                "name": "  Example Malware  ",
                "description": "Observed in test intelligence",
            },
        )
        assert entity_response.status_code == 201
        entity = entity_response.json()
        assert entity["normalized_name"] == "example malware"

        duplicate = client.post(
            f"{base}/entities",
            json={"entity_type": "malware", "name": "EXAMPLE MALWARE"},
        )
        assert duplicate.status_code == 201
        assert duplicate.json()["id"] == entity["id"]

        link_response = client.post(
            f"{base}/entity-links",
            json={
                "record_id": str(record_id),
                "entity_id": entity["id"],
                "relationship_type": "associated_with",
                "rationale": "Indicator was reported with this malware",
                "confidence": 75,
            },
        )
        assert link_response.status_code == 201
        assert link_response.json()["confidence"] == 75

        mapping_response = client.post(
            f"{base}/attack-mappings",
            json={
                "entity_id": entity["id"],
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "rationale": "Execution behavior was described in source reporting",
                "confidence": 62,
                "mapping_status": "uncertain",
            },
        )
        assert mapping_response.status_code == 201
        assert mapping_response.json()["mapping_status"] == "uncertain"

        assert client.get(f"{base}/entities/{entity['id']}/relationships").json()[0]["record_id"] == str(record_id)
        assert client.get(f"{base}/entities/{entity['id']}/attack-mappings").json()[0]["technique_id"] == "T1059.001"

        invalid_mapping = client.post(
            f"{base}/attack-mappings",
            json={
                "entity_id": entity["id"],
                "technique_id": "not-a-technique",
                "technique_name": "Invalid",
                "rationale": "Invalid identifier should be rejected",
                "confidence": 50,
            },
        )
        assert invalid_mapping.status_code == 422

        cross_tenant = client.get(
            f"/api/v1/intelligence/organizations/{other_id}/entities"
        )
        assert cross_tenant.status_code == 404

        # Viewers may inspect intelligence but must not mutate correlation data.
        app.dependency_overrides[get_current_principal] = lambda: Principal(
            user_id=uuid4(), organization_id=organization_id, role=Role.VIEWER
        )
        viewer_entity = client.post(
            f"{base}/entities",
            json={"entity_type": "malware", "name": "Viewer-created entity"},
        )
        viewer_link = client.post(
            f"{base}/entity-links",
            json={
                "record_id": str(record_id),
                "entity_id": entity["id"],
                "relationship_type": "associated_with",
                "rationale": "Viewer write should be blocked",
                "confidence": 50,
            },
        )
        viewer_mapping = client.post(
            f"{base}/attack-mappings",
            json={
                "entity_id": entity["id"],
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "rationale": "Viewer write should be blocked",
                "confidence": 50,
            },
        )
        assert viewer_entity.status_code == 403
        assert viewer_link.status_code == 403
        assert viewer_mapping.status_code == 403
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
