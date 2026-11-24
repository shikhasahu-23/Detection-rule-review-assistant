from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import app.main as main

client = TestClient(main.app)


def test_health_returns_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readiness_returns_ready_when_database_is_available(monkeypatch) -> None:
    connection = MagicMock()
    context_manager = MagicMock()
    context_manager.__enter__.return_value = connection
    monkeypatch.setattr(main.engine, "connect", MagicMock(return_value=context_manager))

    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    connection.execute.assert_called_once()


def test_readiness_returns_503_when_database_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(main.engine, "connect", MagicMock(side_effect=OSError("database offline")))

    response = client.get("/ready")

    assert response.status_code == 503
    assert response.json()["detail"] == "Database is unavailable"
