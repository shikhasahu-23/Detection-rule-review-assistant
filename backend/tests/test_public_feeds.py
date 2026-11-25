from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.intelligence import FeedRun, Indicator, SourceEvidence
from app.services.public_feeds import sync_public_feed


def make_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_urlhaus_ingestion_and_idempotency():
    db = make_session()
    payload = "# comment\nhttps://malware.example/payload\nnot-a-url"
    first = sync_public_feed(db, "urlhaus", payload)
    second = sync_public_feed(db, "urlhaus", payload)
    assert first["records_seen"] == 1
    assert first["indicators_created"] == 1
    assert second["indicators_created"] == 0
    indicator = db.scalar(select(Indicator))
    assert indicator.indicator_type == "url"
    assert db.scalar(select(SourceEvidence)).source_name == "URLhaus"


def test_feodo_ingestion_normalizes_ip_and_preserves_source():
    db = make_session()
    result = sync_public_feed(db, "feodo", "# comment\n192.0.2.10\ninvalid-ip")
    assert result["records_seen"] == 1
    indicator = db.scalar(select(Indicator))
    assert indicator.indicator_type == "ip"
    assert indicator.value == "192.0.2.10"
    assert db.scalar(select(FeedRun).where(FeedRun.status == "succeeded")) is not None


def test_empty_public_feed_is_rejected_and_recorded():
    db = make_session()
    try:
        sync_public_feed(db, "urlhaus", "# no indicators")
    except TypeError:
        pass
    else:
        raise AssertionError("empty feed should fail")
    assert db.scalar(select(FeedRun).where(FeedRun.status == "failed")) is not None
