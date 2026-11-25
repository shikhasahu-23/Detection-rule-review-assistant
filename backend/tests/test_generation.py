from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import audit, detection, identity, intelligence, rule  # noqa: F401
from app.schemas.generation import GeneratedRule
from app.services.generation import get_generation_provider

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(engine)


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


class FakeProvider:
    provider_name = "test-provider"

    def generate(self, intent, platform):
        return GeneratedRule(
            name=f"{platform.value.title()} PowerShell download",
            query="search index=endpoint process_name=powershell.exe",
        )


app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_generation_provider] = lambda: FakeProvider()
client = TestClient(app)


def create_intent():
    response = client.post("/api/v1/detection-intents", json={
        "title": "Suspicious PowerShell download",
        "description": "Detects PowerShell downloading executable content from external hosts.",
        "behavior": "A PowerShell process retrieves a remote payload and writes it to disk.",
        "required_telemetry": [{"source": "endpoint", "description": "Process events"}],
        "target_platforms": ["splunk", "sentinel"],
    })
    assert response.status_code == 201
    return response.json()["id"]


def test_generate_candidates_for_requested_platforms():
    intent_id = create_intent()
    response = client.post(f"/api/v1/detection-intents/{intent_id}/generate", json={
        "target_platforms": ["splunk"],
    })
    assert response.status_code == 201
    items = response.json()
    assert len(items) == 1
    assert items[0]["platform"] == "splunk"
    assert items[0]["generator"] == "test-provider"
    assert items[0]["status"] == "candidate"
    assert items[0]["validation_report"]["is_deployable"] is False


def test_generation_rejects_platform_outside_intent():
    intent_id = create_intent()
    response = client.post(f"/api/v1/detection-intents/{intent_id}/generate", json={
        "target_platforms": ["chronicle"],
    })
    assert response.status_code == 422
