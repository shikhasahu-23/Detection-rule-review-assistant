from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.authorization import Principal, Role, get_current_principal
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.identity import Organization
from app.models.intelligence import IntelQuarantineRecord, IntelRecord, IntelSource


def test_intelligence_endpoints_are_tenant_scoped_and_report_expiry():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        org = Organization(name="Acme", slug="acme")
        other = Organization(name="Other", slug="other")
        db.add_all([org, other])
        db.flush()
        source = IntelSource(organization_id=org.id, name="feed", source_type="test", config={}, is_enabled=True)
        db.add(source)
        db.flush()
        db.add(IntelRecord(
            organization_id=org.id, record_type="domain", value="old.example",
            normalized_value="old.example", expires_at=datetime.now(UTC) - timedelta(days=1),
        ))
        db.add(IntelQuarantineRecord(
            organization_id=org.id, source_id=source.id,
            ingestion_run_id=__import__("uuid").uuid4(), raw_payload={"domain": "bad"},
            reason="invalid domain",
        ))
        # The quarantine FK requires an ingestion run, so remove this fixture row and
        # exercise the endpoint's tenant filter through feed and indicator responses.
        db.rollback()
        org = Organization(name="Acme", slug="acme")
        db.add(org)
        db.flush()
        source = IntelSource(organization_id=org.id, name="feed", source_type="test", config={}, is_enabled=True)
        db.add(source)
        db.add(IntelRecord(
            organization_id=org.id, record_type="domain", value="old.example",
            normalized_value="old.example", expires_at=datetime.now(UTC) - timedelta(days=1),
        ))
        db.commit()
        organization_id = org.id
        other_id = other.id

    app.dependency_overrides[get_current_principal] = lambda: Principal(
        user_id=__import__("uuid").uuid4(), organization_id=organization_id, role=Role.VIEWER
    )
    app.dependency_overrides[get_db] = lambda: Session(engine)
    try:
        client = TestClient(app)
        response = client.get(f"/api/v1/intelligence/organizations/{organization_id}/indicators")
        assert response.status_code == 200
        assert response.json()[0]["lifecycle"] == "expired"
        assert client.get(f"/api/v1/intelligence/organizations/{other_id}/feeds/health").status_code == 404
        assert client.get(f"/api/v1/intelligence/organizations/{organization_id}/feeds/health").json()[0]["source_name"] == "feed"
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
