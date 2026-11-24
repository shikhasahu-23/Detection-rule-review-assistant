from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import audit, identity  # noqa: F401
from app.models.detection import DetectionIntent  # noqa: F401
from app.models.intelligence import FeedRun, Indicator, SourceEvidence  # noqa: F401

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


def test_create_and_retrieve_detection_intent():
    response = client.post("/api/v1/detection-intents", json={
        "title": "Suspicious PowerShell download",
        "description": "Detects PowerShell downloading executable content from external hosts.",
        "behavior": "A PowerShell process retrieves a remote payload and writes it to disk.",
        "severity": "high",
        "attack_techniques": ["T1059.001"],
        "required_telemetry": [{
            "source": "endpoint_process", "description": "Process creation and network events",
            "required_fields": ["process_name", "command_line", "destination_ip"],
        }],
        "evidence": [{"kind": "cve", "reference": "CVE-2024-1234", "source": "CISA KEV", "confidence": 90}],
        "test_scenarios": ["PowerShell downloads an executable"],
        "target_platforms": ["splunk", "sentinel"],
    })
    assert response.status_code == 201
    created = response.json()
    assert created["status"] == "draft"
    assert created["attack_techniques"] == ["T1059.001"]
    detail = client.get(f"/api/v1/detection-intents/{created['id']}")
    assert detail.status_code == 200
    assert detail.json()["target_platforms"] == ["splunk", "sentinel"]


def test_detection_intent_rejects_invalid_attack_technique():
    response = client.post("/api/v1/detection-intents", json={
        "title": "Bad technique", "description": "A sufficiently long description.",
        "behavior": "A sufficiently long behavior description.",
        "required_telemetry": [{"source": "endpoint", "description": "Endpoint events"}],
        "target_platforms": ["splunk"], "attack_techniques": ["bad-id"],
    })
    assert response.status_code == 422
