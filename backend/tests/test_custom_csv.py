from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.intelligence import FeedRun, Indicator, SourceEvidence
from app.services.custom_csv import sync_custom_csv


def make_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_custom_csv_ingests_valid_records_and_reports_invalid_rows():
    db = make_session()
    csv_text = (
        "indicator_type,value,confidence,severity,source_name,source_reference,tags\n"
        "domain,Example.COM,90,high,Partner Feed,partner-1,malware;phishing\n"
        "ip,not-an-ip,50,medium,Partner Feed,partner-2,test\n"
    )
    result = sync_custom_csv(db, csv_text)
    assert result["records_seen"] == 2
    assert result["indicators_created"] == 1
    assert result["evidence_created"] == 1
    assert result["rejected_count"] == 1
    indicator = db.scalar(select(Indicator).where(Indicator.value == "example.com"))
    assert indicator.indicator_type == "domain"
    assert "phishing" in indicator.tags
    assert db.scalar(select(SourceEvidence)).source_reference == "partner-1"
    assert db.scalar(select(FeedRun).where(FeedRun.status == "partial")) is not None


def test_custom_csv_import_is_idempotent():
    db = make_session()
    content = "indicator_type,value,source_name,source_reference\ndomain,example.org,Partner,one\n"
    first = sync_custom_csv(db, content)
    second = sync_custom_csv(db, content)
    assert first["indicators_created"] == 1
    assert second["indicators_created"] == 0
    assert len(db.scalars(select(SourceEvidence)).all()) == 1


def test_custom_csv_requires_expected_headers():
    db = make_session()
    try:
        sync_custom_csv(db, "name,value\nexample,thing\n")
    except ValueError as exc:
        assert "indicator_type" in str(exc)
    else:
        raise AssertionError("CSV without required headers should fail")
    assert db.scalar(select(FeedRun).where(FeedRun.status == "failed")) is not None
