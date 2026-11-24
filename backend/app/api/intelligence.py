from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.authorization import Principal, assert_organization_access, get_current_principal
from app.db.session import get_db
from app.models.intelligence import IngestionRun, IntelQuarantineRecord, IntelRecord, IntelSource

router = APIRouter(prefix="/api/v1/intelligence", tags=["intelligence"])


class FeedHealthItem(BaseModel):
    source_id: UUID
    source_name: str
    enabled: bool
    latest_status: str | None
    last_success_at: datetime | None
    last_run_at: datetime | None


class IngestionHistoryItem(BaseModel):
    id: UUID
    source_id: UUID
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    records_seen: int
    records_created: int
    records_rejected: int
    error_summary: str | None


class QuarantineItem(BaseModel):
    id: UUID
    source_id: UUID
    ingestion_run_id: UUID
    raw_payload: dict
    reason: str
    created_at: datetime


class IndicatorLifecycleItem(BaseModel):
    id: UUID
    indicator_type: str
    value: str
    confidence: float | None
    severity: str | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    expires_at: datetime | None
    lifecycle: str


def _authorize(principal: Principal, organization_id: UUID) -> None:
    assert_organization_access(principal, organization_id)


@router.get("/organizations/{organization_id}/feeds/health", response_model=list[FeedHealthItem])
def feed_health(
    organization_id: UUID,
    principal: Annotated[Principal, Depends(get_current_principal)],
    db: Annotated[Session, Depends(get_db)],
) -> list[FeedHealthItem]:
    _authorize(principal, organization_id)
    sources = db.scalars(
        select(IntelSource).where(IntelSource.organization_id == organization_id).order_by(IntelSource.name)
    ).all()
    output = []
    for source in sources:
        latest = db.scalar(
            select(IngestionRun)
            .where(IngestionRun.organization_id == organization_id, IngestionRun.source_id == source.id)
            .order_by(IngestionRun.started_at.desc())
            .limit(1)
        )
        last_success = db.scalar(
            select(func.max(IngestionRun.completed_at)).where(
                IngestionRun.organization_id == organization_id,
                IngestionRun.source_id == source.id,
                IngestionRun.status == "success",
            )
        )
        output.append(FeedHealthItem(
            source_id=source.id,
            source_name=source.name,
            enabled=source.is_enabled,
            latest_status=latest.status if latest else None,
            last_success_at=last_success,
            last_run_at=latest.started_at if latest else None,
        ))
    return output


@router.get("/organizations/{organization_id}/ingestion-runs", response_model=list[IngestionHistoryItem])
def ingestion_history(
    organization_id: UUID,
    principal: Annotated[Principal, Depends(get_current_principal)],
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[IngestionHistoryItem]:
    _authorize(principal, organization_id)
    runs = db.scalars(
        select(IngestionRun)
        .where(IngestionRun.organization_id == organization_id)
        .order_by(IngestionRun.started_at.desc())
        .limit(limit).offset(offset)
    ).all()
    return [IngestionHistoryItem.model_validate(run, from_attributes=True) for run in runs]


@router.get("/organizations/{organization_id}/quarantine", response_model=list[QuarantineItem])
def quarantine_records(
    organization_id: UUID,
    principal: Annotated[Principal, Depends(get_current_principal)],
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[QuarantineItem]:
    _authorize(principal, organization_id)
    records = db.scalars(
        select(IntelQuarantineRecord)
        .where(IntelQuarantineRecord.organization_id == organization_id)
        .order_by(IntelQuarantineRecord.created_at.desc())
        .limit(limit).offset(offset)
    ).all()
    return [QuarantineItem.model_validate(record, from_attributes=True) for record in records]


@router.get("/organizations/{organization_id}/indicators", response_model=list[IndicatorLifecycleItem])
def indicator_lifecycle(
    organization_id: UUID,
    principal: Annotated[Principal, Depends(get_current_principal)],
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[IndicatorLifecycleItem]:
    _authorize(principal, organization_id)
    now = datetime.now(UTC)
    records = db.scalars(
        select(IntelRecord)
        .where(IntelRecord.organization_id == organization_id)
        .order_by(IntelRecord.last_seen_at.desc().nullslast())
        .limit(limit).offset(offset)
    ).all()
    return [
        IndicatorLifecycleItem(
            id=record.id,
            indicator_type=record.record_type,
            value=record.value,
            confidence=record.confidence,
            severity=record.severity,
            first_seen_at=record.first_seen_at,
            last_seen_at=record.last_seen_at,
            expires_at=record.expires_at,
            lifecycle="expired" if record.expires_at and record.expires_at <= now else "active",
        )
        for record in records
    ]
