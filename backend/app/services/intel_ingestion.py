from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.intel.connectors.base import IntelConnector
from app.models.intelligence import (
    IngestionRun,
    IntelEvidence,
    IntelQuarantineRecord,
    IntelRecord,
    IntelSource,
)


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


_SENSITIVE_KEY_PARTS = ("authorization", "api_key", "apikey", "secret", "password", "token", "credential")
_MAX_PAYLOAD_DEPTH = 5
_MAX_PAYLOAD_ITEMS = 50
_MAX_PAYLOAD_STRING = 2000


def _safe_payload_value(value: object, *, depth: int = 0) -> object:
    """Convert untrusted connector data into bounded, JSON-safe quarantine content."""
    if depth >= _MAX_PAYLOAD_DEPTH:
        return "[maximum nesting depth reached]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:_MAX_PAYLOAD_STRING]
    if isinstance(value, dict):
        sanitized = {}
        for key, item in list(value.items())[:_MAX_PAYLOAD_ITEMS]:
            safe_key = str(key)[:120]
            if any(part in safe_key.casefold() for part in _SENSITIVE_KEY_PARTS):
                sanitized[safe_key] = "[REDACTED]"
            else:
                sanitized[safe_key] = _safe_payload_value(item, depth=depth + 1)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_safe_payload_value(item, depth=depth + 1) for item in value[:_MAX_PAYLOAD_ITEMS]]
    return str(value)[:_MAX_PAYLOAD_STRING]


def _safe_payload(raw_record: object) -> dict:
    """Bound quarantine size and redact credential-like fields from untrusted payloads."""
    if isinstance(raw_record, dict):
        return _safe_payload_value(raw_record)
    return {"value": _safe_payload_value(raw_record)}


async def run_intel_ingestion(
    db: Session,
    *,
    organization_id: UUID,
    source: IntelSource,
    connector: IntelConnector,
    parser_version: str = "1",
) -> IngestionRun:
    """Fetch and idempotently persist indicators; quarantine malformed source records."""
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
                    raise ValueError("Connector returned no indicators")
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
            except (TypeError, ValueError) as exc:
                run.records_rejected += 1
                db.add(
                    IntelQuarantineRecord(
                        organization_id=organization_id,
                        source_id=source.id,
                        ingestion_run_id=run.id,
                        raw_payload=_safe_payload(raw_record),
                        reason=f"{type(exc).__name__}: {str(exc)[:450]}",
                    )
                )
        run.checkpoint = dict(connector.get_checkpoint() or {})
        run.status = "success"
        run.completed_at = datetime.now(UTC)
        db.commit()
    except Exception as exc:  # noqa: BLE001 - persist a failed run for any connector/DB failure
        db.rollback()
        run.status = "failed"
        run.completed_at = datetime.now(UTC)
        run.error_summary = f"{type(exc).__name__}: intelligence ingestion failed"
        db.add(run)
        db.commit()
    db.refresh(run)
    return run
