from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.intelligence import FeedRun, Indicator, SourceEvidence
from app.services.cisa_kev import sync_cisa_kev


def make_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_cisa_ingestion_normalizes_and_preserves_evidence():
    db = make_session()
    payload = {"vulnerabilities": [{
        "cveID": "CVE-2024-9999", "vulnerabilityName": "Example vulnerability",
        "dateAdded": "2024-05-01", "knownRansomwareCampaignUse": "Known",
        "shortDescription": "Test record",
    }, {"cveID": "not-a-cve"}]}
    result = sync_cisa_kev(db, payload)
    assert result["records_seen"] == 2
    assert result["indicators_created"] == 1
    assert result["evidence_created"] == 1
    indicator = db.scalar(select(Indicator).where(Indicator.value == "CVE-2024-9999"))
    assert indicator.indicator_type == "cve"
    assert indicator.confidence == 100
    assert "known-exploited" in indicator.tags
    assert db.scalar(select(FeedRun).where(FeedRun.status == "succeeded")) is not None
    assert db.scalar(select(SourceEvidence)).source_reference == "CISA-KEV:CVE-2024-9999"


def test_cisa_ingestion_is_idempotent():
    db = make_session()
    payload = {"vulnerabilities": [{"cveID": "CVE-2024-9999", "dateAdded": "2024-05-01"}]}
    first = sync_cisa_kev(db, payload)
    second = sync_cisa_kev(db, payload)
    assert first["indicators_created"] == 1
    assert second["indicators_created"] == 0
    assert db.scalar(select(Indicator).where(Indicator.value == "CVE-2024-9999")) is not None
    assert len(db.scalars(select(SourceEvidence)).all()) == 1


def test_bad_feed_schema_is_rejected_and_recorded():
    db = make_session()
    try:
        sync_cisa_kev(db, {"unexpected": []})
    except ValueError:
        pass
    else:
        raise AssertionError("invalid feed schema should fail")
    assert db.scalar(select(FeedRun).where(FeedRun.status == "failed")) is not None
