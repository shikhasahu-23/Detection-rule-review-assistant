from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.intel.connectors.base import IntelConnector
from app.models.intelligence import IngestionRun, IntelEvidence, IntelRecord, IntelSource


def _latest_checkpoint(db: Session, source_id: UUID, organization_id: UUID) -> dict[str, str] | None:
    previous = db.scalar(
        select(IngestionRun)
        .where(
            IngestionRun.source_id == source_id,
            IngestionRun.organization_id == organization_id,
            IngestionRun.status == "success",
        )
        .order_by(IngestionRun.completed_at.desc())
        .limit(1)
    )
    return previous.checkpoint or None if previous is not None else None


async def run_intel_ingestion(
    db: Session,
    *,
    organization_id: UUID,
    source: IntelSource,
    connector: IntelConnector,
    parser_version: str = "1",
) -> IngestionRun:
    """Fetch, normalize and idempotently persist one source run.

    The service commits its own run so failed fetches remain visible in ingestion history.
    Connector credentials must be supplied through the source's protected configuration
    by the caller; this service never logs or returns that configuration.
    """
    if source.organization_id != organization_id:
        raise ValueError("Intel source does not belong to the requested organization")
    run = IngestionRun(
        organization_id=organization_id,
        source_id=source.id,
        status="running",
        started_at=datetime.now(UTC),
    )
    db.add(run)
    db.flush()
    try:
        await connector.configure(source.config or {})
        checkpoint = _latest_checkpoint(db, source.id, organization_id)
        async for raw_record in connector.fetch(checkpoint):
            run.records_seen += 1
            try:
                indicators = connector.parse(raw_record)
                if not indicators:
                    run.records_rejected += 1
                    continue
                for indicator in indicators:
                    record = db.scalar(
                        select(IntelRecord).where(
                            IntelRecord.organization_id == organization_id,
                            IntelRecord.record_type == indicator.indicator_type.value,
                            IntelRecord.normalized_value == indicator.value,
                        )
                    )
                    if record is None:
                        record = IntelRecord(
                            organization_id=organization_id,
                            record_type=indicator.indicator_type.value,
                            value=indicator.value,
                            normalized_value=indicator.value,
                            confidence=indicator.confidence,
                            severity=indicator.severity,
                            first_seen_at=indicator.first_seen_at,
                            last_seen_at=indicator.last_seen_at,
                            expires_at=indicator.expires_at,
                        )
                        db.add(record)
                        db.flush()
                        run.records_created += 1
                    else:
                        if indicator.confidence is not None:
                            record.confidence = max(record.confidence or 0, indicator.confidence)
                        if indicator.severity is not None:
                            record.severity = indicator.severity
                        if indicator.first_seen_at is not None and (
                            record.first_seen_at is None or indicator.first_seen_at < record.first_seen_at
                        ):
                            record.first_seen_at = indicator.first_seen_at
                        if indicator.last_seen_at is not None and (
                            record.last_seen_at is None or indicator.last_seen_at > record.last_seen_at
                        ):
                            record.last_seen_at = indicator.last_seen_at
                        if indicator.expires_at is not None:
                            record.expires_at = indicator.expires_at
                    for evidence_input in indicator.evidence:
                        existing = db.scalar(
                            select(IntelEvidence.id).where(
                                IntelEvidence.record_id == record.id,
                                IntelEvidence.source_id == source.id,
                                IntelEvidence.payload_hash == evidence_input.payload_hash,
                            )
                        )
                        if existing is None:
                            db.add(
                                IntelEvidence(
                                    organization_id=organization_id,
                                    record_id=record.id,
                                    source_id=source.id,
                                    source_reference=evidence_input.source_reference,
                                    source_timestamp=evidence_input.observed_at,
                                    payload_hash=evidence_input.payload_hash,
                                    parser_version=parser_version,
                                )
                            )
            except (TypeError, ValueError):
                run.records_rejected += 1
        run.checkpoint = dict(connector.get_checkpoint() or {})
        run.status = "success"
        run.completed_at = datetime.now(UTC)
        db.commit()
    except Exception as exc:
        db.rollback()
        run.status = "failed"
        run.completed_at = datetime.now(UTC)
        # Keep diagnostics bounded and avoid serializing connector configuration.
        run.error_summary = f"{type(exc).__name__}: intelligence ingestion failed"
        db.add(run)
        db.commit()
    db.refresh(run)
    return run
