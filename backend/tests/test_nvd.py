from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.intelligence import FeedRun, Indicator, SourceEvidence
from app.services.nvd import sync_nvd_cves


def make_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return Session(engine)


def sample_payload():
    return {"totalResults": 1, "vulnerabilities": [{
        "cve": {
            "id": "CVE-2025-12345",
            "published": "2025-01-01T00:00:00.000",
            "lastModified": "2025-01-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
        }
    }]}


def test_nvd_ingestion_normalizes_and_preserves_evidence():
    db = make_session()
    result = sync_nvd_cves(db, sample_payload())
    assert result["records_seen"] == 1
    assert result["indicators_created"] == 1
    assert result["evidence_created"] == 1
    indicator = db.scalar(select(Indicator).where(Indicator.value == "CVE-2025-12345"))
    assert indicator.indicator_type == "cve"
    assert indicator.severity == "high"
    assert "nvd" in indicator.tags
    evidence = db.scalar(select(SourceEvidence))
    assert evidence.source_reference == "NVD:CVE-2025-12345"
    assert db.scalar(select(FeedRun).where(FeedRun.status == "succeeded")) is not None


def test_nvd_ingestion_is_idempotent():
    db = make_session()
    payload = sample_payload()
    first = sync_nvd_cves(db, payload)
    second = sync_nvd_cves(db, payload)
    assert first["indicators_created"] == 1
    assert second["indicators_created"] == 0
    assert len(db.scalars(select(SourceEvidence)).all()) == 1


def test_nvd_rejects_invalid_response_schema():
    db = make_session()
    try:
        sync_nvd_cves(db, {"unexpected": []})
    except TypeError:
        pass
    else:
        raise AssertionError("invalid NVD schema should fail")
    assert db.scalar(select(FeedRun).where(FeedRun.status == "failed")) is not None
