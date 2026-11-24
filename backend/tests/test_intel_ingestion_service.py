from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.base import Base
from app.intel.connectors.base import ConnectorHealth, ConnectorStatus, IntelConnector
from app.intel.schemas import IndicatorType, IntelEvidenceInput, IntelIndicatorInput
from app.models.identity import Organization
from app.models.intelligence import IntelEvidence, IntelQuarantineRecord, IntelRecord, IntelSource
from app.services.intel_ingestion import _safe_payload, run_intel_ingestion


class FakeConnector(IntelConnector):
    def __init__(self, records: list[Mapping[str, object]]) -> None:
        self.records = records
        self.configured = False

    async def configure(self, config: Mapping[str, object]) -> None:
        self.configured = True

    async def fetch(self, checkpoint=None) -> AsyncIterator[Mapping[str, object]]:
        for record in self.records:
            yield record

    def parse(self, raw_record: Mapping[str, object]) -> list[IntelIndicatorInput]:
        if raw_record.get("invalid"):
            raise ValueError("bad record")
        return [
            IntelIndicatorInput(
                indicator_type=IndicatorType.DOMAIN,
                value=str(raw_record["domain"]),
                confidence=80,
                evidence=[
                    IntelEvidenceInput(
                        source_name="fixture",
                        source_reference="https://example.test/evidence",
                        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
                        payload_hash=str(raw_record["hash"]),
                    )
                ],
            )
        ]

    def get_checkpoint(self):
        return {"cursor": "done"}

    async def health(self):
        return ConnectorHealth(ConnectorStatus.HEALTHY)


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def make_source(db: Session, organization_id):
    source = IntelSource(
        organization_id=organization_id,
        name="fixture",
        source_type="test",
        config={},
        is_enabled=True,
    )
    db.add(source)
    db.commit()
    return source


@pytest.mark.asyncio
async def test_ingestion_persists_records_and_evidence_idempotently(db):
    organization = Organization(name="Acme", slug="acme")
    db.add(organization)
    db.commit()
    source = make_source(db, organization.id)
    connector = FakeConnector([{"domain": "Example.COM", "hash": "a" * 64}])

    first = await run_intel_ingestion(
        db, organization_id=organization.id, source=source, connector=connector
    )
    second = await run_intel_ingestion(
        db, organization_id=organization.id, source=source, connector=connector
    )

    assert first.status == second.status == "success"
    assert first.records_seen == second.records_seen == 1
    assert first.records_created == 1
    assert second.records_created == 0
    assert second.checkpoint == {"cursor": "done"}
    record = db.scalar(
        select(IntelRecord).where(IntelRecord.organization_id == organization.id)
    )
    assert record.normalized_value == "example.com"
    assert len(list(db.scalars(select(IntelEvidence)))) == 1


@pytest.mark.asyncio
async def test_ingestion_quarantines_invalid_records_with_diagnostics(db):
    organization = Organization(name="Acme", slug="acme")
    db.add(organization)
    db.commit()
    source = make_source(db, organization.id)

    run = await run_intel_ingestion(
        db, organization_id=organization.id, source=source,
        connector=FakeConnector([{"invalid": True}]),
    )

    quarantined = db.scalar(select(IntelQuarantineRecord))
    assert run.status == "success"
    assert run.records_seen == run.records_rejected == 1
    assert quarantined.raw_payload == {"invalid": True}
    assert "bad record" in quarantined.reason
    assert quarantined.source_id == source.id

@pytest.mark.asyncio
async def test_ingestion_rejects_source_from_another_organization(db):
    owner = Organization(name="Owner", slug="owner")
    other = Organization(name="Other", slug="other")
    db.add_all([owner, other])
    db.commit()
    source = make_source(db, owner.id)

    with pytest.raises(ValueError, match="does not belong"):
        await run_intel_ingestion(
            db,
            organization_id=other.id,
            source=source,
            connector=FakeConnector([]),
        )

    assert db.scalar(select(IntelRecord)) is None


@pytest.mark.asyncio
async def test_ingestion_persists_failed_run_without_exposing_connector_error(db):
    organization = Organization(name="Acme", slug="acme")
    db.add(organization)
    db.commit()
    source = make_source(db, organization.id)

    class FailingConnector(FakeConnector):
        async def fetch(self, checkpoint=None):
            raise RuntimeError("upstream response contained sensitive details")
            yield {}

    run = await run_intel_ingestion(
        db,
        organization_id=organization.id,
        source=source,
        connector=FailingConnector([]),
    )

    assert run.status == "failed"
    assert run.completed_at is not None
    assert run.error_summary == "RuntimeError: intelligence ingestion failed"
    assert "sensitive details" not in run.error_summary



def test_quarantine_payload_redacts_nested_credentials_and_bounds_values():
    payload = _safe_payload(
        {
            "indicator": "malicious.example",
            "api_key": "top-secret",
            "nested": {
                "Authorization": "Bearer sensitive",
                "description": "x" * 2500,
            },
            "items": [{"access_token": "another-secret"}],
        }
    )

    assert payload["indicator"] == "malicious.example"
    assert payload["api_key"] == "[REDACTED]"
    assert payload["nested"]["Authorization"] == "[REDACTED]"
    assert len(payload["nested"]["description"]) == 2000
    assert payload["items"][0]["access_token"] == "[REDACTED]"
