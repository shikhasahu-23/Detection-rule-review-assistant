from unittest.mock import Mock

import pytest

from app.tasks import intel


def test_build_connector_supports_configured_feed_types():
    assert isinstance(intel._build_connector("cisa_kev"), intel.CisaKevConnector)
    assert isinstance(intel._build_connector("nvd"), intel.NvdConnector)
    assert isinstance(intel._build_connector("urlhaus"), intel.UrlhausConnector)
    assert isinstance(intel._build_connector("threatfox"), intel.ThreatFoxConnector)


def test_build_connector_rejects_unknown_source_type():
    with pytest.raises(ValueError, match="Unsupported intelligence source type"):
        intel._build_connector("unknown-feed")


def test_daily_dispatch_enqueues_enabled_sources(monkeypatch):
    session = Mock()
    session.scalars.return_value = iter(["source-1", "source-2"])
    session_context = Mock()
    session_context.__enter__ = Mock(return_value=session)
    session_context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(intel, "SessionLocal", Mock(return_value=session_context))
    delay = Mock()
    monkeypatch.setattr(intel.ingest_source, "delay", delay)

    result = intel.ingest_enabled_sources()

    assert result == {"queued": 2}
    assert delay.call_count == 2
