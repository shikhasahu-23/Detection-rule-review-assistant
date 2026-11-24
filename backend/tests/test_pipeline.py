from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from uuid import UUID

from app.db.base import Base
from app.models.detection import DetectionIntent
from app.models.intelligence import Indicator
from app.models.pipeline import PipelineRun
from app.models.rule import RuleCandidate
from app.schemas.detection import TargetPlatform
from app.schemas.generation import GeneratedRule
from app.services.pipeline import run_intelligence_pipeline


def make_session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return Session(engine)


class FakeProvider:
    def __init__(self):
        self.calls = 0

    def generate(self, intent, platform):
        self.calls += 1
        return GeneratedRule(name="CVE exploitation detection", query="index=security sourcetype=endpoint")


def seed_correlated_data(db):
    indicator = Indicator(
        indicator_type="cve", value="CVE-2025-12345", confidence=90,
        severity="high", status="active", tags=[],
    )
    intent = DetectionIntent(
        title="Detect exploitation", description="Detect exploitation of tracked CVEs",
        behavior="Identify activity linked to CVE-2025-12345",
        severity="high", attack_techniques=[],
        required_telemetry=[{"source": "endpoint"}],
        evidence=[{"kind": "cve", "reference": "CVE-2025-12345", "source": "NVD", "confidence": 90}],
        test_scenarios=[], target_platforms=["splunk"], status="draft",
    )
    db.add_all([indicator, intent])
    db.commit()
    return intent


def test_pipeline_runs_enrichment_correlation_and_creates_unapproved_candidate():
    db = make_session()
    intent = seed_correlated_data(db)
    provider = FakeProvider()
    result = run_intelligence_pipeline(
        db, trigger="test", feed_syncers={}, provider=provider
    )

    candidate = db.scalar(select(RuleCandidate))
    run = db.get(PipelineRun, UUID(result["run_id"]))
    assert result["status"] == "succeeded"
    assert result["indicators_enriched"] == 1
    assert result["opportunities_found"] == 1
    assert result["candidates_created"] == 1
    assert provider.calls == 1
    assert candidate.intent_id == intent.id
    assert candidate.status == "candidate"
    assert candidate.generator == "pipeline"
    assert candidate.validation_report["is_deployable"] is False
    assert run.completed_at is not None
    assert run.stage_results["feed_ingestion"]["status"] == "skipped"


def test_pipeline_does_not_duplicate_pipeline_candidates_on_repeat_run():
    db = make_session()
    seed_correlated_data(db)
    provider = FakeProvider()

    first = run_intelligence_pipeline(db, feed_syncers={}, provider=provider)
    second = run_intelligence_pipeline(db, feed_syncers={}, provider=provider)

    assert first["candidates_created"] == 1
    assert second["candidates_created"] == 0
    assert second["candidates_skipped"] == 1
    assert provider.calls == 1
    assert len(db.scalars(select(RuleCandidate)).all()) == 1


def test_pipeline_records_feed_failures_and_continues_downstream():
    db = make_session()
    seed_correlated_data(db)
    provider = FakeProvider()

    def failed_feed(_db):
        raise RuntimeError("feed unavailable")

    result = run_intelligence_pipeline(
        db, feed_syncers={"test_feed": failed_feed}, provider=provider
    )

    assert result["status"] == "partial_success"
    assert result["stage_results"]["test_feed"]["status"] == "failed"
    assert result["stage_results"]["enrichment"]["status"] == "succeeded"
    assert result["candidates_created"] == 1
