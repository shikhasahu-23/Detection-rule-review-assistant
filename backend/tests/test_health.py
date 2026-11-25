from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readiness_returns_ready() -> None:
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_scheduler_is_disabled_without_secret() -> None:
    response = client.post("/internal/scheduler/run/cisa-kev")
    assert response.status_code == 503
    assert response.json()["detail"] == "Scheduler is not configured"


def test_scheduler_rejects_invalid_secret(monkeypatch) -> None:
    from app.api import scheduler

    monkeypatch.setattr(
        scheduler,
        "get_settings",
        lambda: type("Settings", (), {"scheduler_secret": "configured-secret"})(),
    )
    response = client.post(
        "/internal/scheduler/run/cisa-kev",
        headers={"X-Scheduler-Secret": "wrong-secret"},
    )
    assert response.status_code == 401
