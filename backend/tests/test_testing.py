from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import audit, detection, identity, intelligence, rule, testing  # noqa: F401

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


def create_candidate(query: str = "search index=endpoint process_name=powershell.exe destination_ip"):
    intent = client.post("/api/v1/detection-intents", json={
        "title": "Suspicious PowerShell download",
        "description": "Detects PowerShell downloading executable content from external hosts.",
        "behavior": "A PowerShell process retrieves a remote payload and writes it to disk.",
        "required_telemetry": [{"source": "endpoint", "description": "Process telemetry"}],
        "target_platforms": ["splunk"],
    })
    assert intent.status_code == 201
    response = client.post(f"/api/v1/detection-intents/{intent.json()['id']}/candidates", json={
        "name": "PowerShell download", "platform": "splunk", "query": query,
    })
    assert response.status_code == 201
    return response.json()


def test_offline_test_suite_runs_assertions_and_stores_fingerprint():
    candidate = create_candidate()
    response = client.post(f"/api/v1/rules/{candidate['id']}/test-runs", json={
        "cases": [
            {
                "name": "Positive: process and destination fields",
                "scenario_type": "positive",
                "fixture": {"process_name": "powershell.exe", "destination_ip": "203.0.113.10"},
                "assertions": [
                    {"operator": "contains", "value": "process_name"},
                    {"operator": "contains", "value": "destination_ip"},
                ],
            },
            {
                "name": "Negative: benign marker is excluded",
                "scenario_type": "negative",
                "fixture": {"process_name": "notepad.exe", "benign": True},
                "assertions": [{"operator": "not_contains", "value": "known_benign_marker"}],
            },
        ],
    })
    assert response.status_code == 201
    run = response.json()
    assert run["status"] == "passed"
    assert run["passed_cases"] == 2
    assert run["failed_cases"] == 0
    assert run["regression_report"]["status"] == "baseline"
    assert len(run["query_fingerprint"]) == 64


def test_offline_test_suite_reports_failed_assertion():
    candidate = create_candidate()
    response = client.post(f"/api/v1/rules/{candidate['id']}/test-runs", json={
        "cases": [{
            "name": "Missing process field",
            "scenario_type": "positive",
            "fixture": {"process_name": "powershell.exe"},
            "assertions": [{"operator": "contains", "value": "original_file_name"}],
        }],
    })
    assert response.status_code == 201
    assert response.json()["status"] == "failed"
    assert response.json()["failed_cases"] == 1


def test_test_run_history_is_listed():
    candidate = create_candidate()
    payload = {"cases": [{
        "name": "Positive process",
        "scenario_type": "positive",
        "fixture": {"process_name": "powershell.exe"},
        "assertions": [{"operator": "contains", "value": "process_name"}],
    }]}
    created = client.post(f"/api/v1/rules/{candidate['id']}/test-runs", json=payload)
    assert created.status_code == 201
    history = client.get(f"/api/v1/rules/{candidate['id']}/test-runs")
    assert history.status_code == 200
    assert len(history.json()) == 1
