from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import audit, detection, identity, intelligence, rule  # noqa: F401

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(engine)


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def create_intent():
    response = client.post("/api/v1/detection-intents", json={
        "title": "Suspicious PowerShell download",
        "description": "Detects PowerShell downloading executable content from external hosts.",
        "behavior": "A PowerShell process retrieves a remote payload and writes it to disk.",
        "required_telemetry": [{"source": "endpoint", "description": "Process events"}],
        "target_platforms": ["splunk"],
    })
    assert response.status_code == 201
    return response.json()["id"]


def test_candidate_is_saved_as_unapproved_and_validation_reported():
    intent_id = create_intent()
    response = client.post(f"/api/v1/detection-intents/{intent_id}/candidates", json={
        "name": "PowerShell download", "platform": "splunk",
        "query": "search index=endpoint process_name=powershell.exe",
    })
    assert response.status_code == 201
    candidate = response.json()
    assert candidate["status"] == "candidate"
    assert candidate["validation_status"] == "passed_with_warnings"
    assert candidate["validation_report"]["is_deployable"] is False


def test_candidate_rejects_platform_not_in_intent():
    intent_id = create_intent()
    response = client.post(f"/api/v1/detection-intents/{intent_id}/candidates", json={
        "name": "Chronicle rule", "platform": "chronicle",
        "query": "rule x { events: $e.metadata.event_type = \"PROCESS_LAUNCH\" condition: $e }",
    })
    assert response.status_code == 422


def test_candidate_rejects_unknown_intent():
    from uuid import uuid4
    response = client.post(f"/api/v1/detection-intents/{uuid4()}/candidates", json={
        "name": "Example rule", "platform": "splunk", "query": "search index=endpoint",
    })
    assert response.status_code == 404
