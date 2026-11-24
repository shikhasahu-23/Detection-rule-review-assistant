from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.authorization import Principal, assert_organization_access, get_current_principal
from app.db.session import get_db
from app.models.intelligence import (
    AttackTechniqueMapping,
    IngestionRun,
    IntelEntityLink,
    IntelQuarantineRecord,
    IntelRecord,
    IntelSource,
    ThreatEntity,
)

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


def _is_expired(expires_at: datetime | None, now: datetime) -> bool:
    if expires_at is None:
        return False
    # SQLite may return timezone-naive values for timezone-aware columns.
    normalized_expiry = expires_at.replace(tzinfo=UTC) if expires_at.tzinfo is None else expires_at
    return normalized_expiry <= now


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
            lifecycle="expired" if _is_expired(record.expires_at, now) else "active",
        )
        for record in records
    ]


ENTITY_TYPES = {"actor", "malware", "campaign", "tool", "vulnerability", "infrastructure"}
RELATIONSHIP_TYPES = {"uses", "attributed_to", "communicates_with", "hosts", "exploits", "associated_with"}


class ThreatEntityCreate(BaseModel):
    entity_type: str
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)

    @field_validator("entity_type")
    @classmethod
    def validate_entity_type(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in ENTITY_TYPES:
            raise ValueError("Unsupported threat entity type")
        return value

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return value.strip()


class EntityLinkCreate(BaseModel):
    record_id: UUID
    entity_id: UUID
    relationship_type: str
    rationale: str = Field(min_length=1, max_length=1000)
    confidence: float = Field(ge=0, le=100)

    @field_validator("relationship_type")
    @classmethod
    def validate_relationship(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in RELATIONSHIP_TYPES:
            raise ValueError("Unsupported relationship type")
        return value


class AttackMappingCreate(BaseModel):
    entity_id: UUID
    technique_id: str = Field(pattern=r"^T[0-9]{4}(\\.[0-9]{3})?$")
    technique_name: str = Field(min_length=1, max_length=255)
    rationale: str = Field(min_length=1, max_length=1000)
    confidence: float = Field(ge=0, le=100)
    mapping_status: str = "uncertain"
    source_reference: str | None = Field(default=None, max_length=2048)

    @field_validator("mapping_status")
    @classmethod
    def validate_mapping_status(cls, value: str) -> str:
        if value not in {"uncertain", "proposed", "confirmed", "rejected"}:
            raise ValueError("Unsupported ATT&CK mapping status")
        return value


class ThreatEntityItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    entity_type: str
    name: str
    normalized_name: str
    description: str | None


class EntityLinkItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    record_id: UUID
    entity_id: UUID
    relationship_type: str
    rationale: str
    confidence: float


class AttackMappingItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    entity_id: UUID
    technique_id: str
    technique_name: str
    rationale: str
    confidence: float
    mapping_status: str
    source_reference: str | None


@router.post("/organizations/{organization_id}/entities", response_model=ThreatEntityItem, status_code=201)
def create_threat_entity(
    organization_id: UUID,
    payload: ThreatEntityCreate,
    principal: Annotated[Principal, Depends(get_current_principal)],
    db: Annotated[Session, Depends(get_db)],
) -> ThreatEntityItem:
    _authorize(principal, organization_id)
    normalized = payload.name.casefold()
    entity = db.scalar(select(ThreatEntity).where(
        ThreatEntity.organization_id == organization_id,
        ThreatEntity.entity_type == payload.entity_type,
        ThreatEntity.normalized_name == normalized,
    ))
    if entity is not None:
        return ThreatEntityItem.model_validate(entity)
    entity = ThreatEntity(
        organization_id=organization_id,
        entity_type=payload.entity_type,
        name=payload.name,
        normalized_name=normalized,
        description=payload.description,
    )
    db.add(entity)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        entity = db.scalar(select(ThreatEntity).where(
            ThreatEntity.organization_id == organization_id,
            ThreatEntity.entity_type == payload.entity_type,
            ThreatEntity.normalized_name == normalized,
        ))
        if entity is None:
            raise
    db.refresh(entity)
    return ThreatEntityItem.model_validate(entity)


@router.post("/organizations/{organization_id}/entity-links", response_model=EntityLinkItem, status_code=201)
def link_indicator_to_entity(
    organization_id: UUID,
    payload: EntityLinkCreate,
    principal: Annotated[Principal, Depends(get_current_principal)],
    db: Annotated[Session, Depends(get_db)],
) -> EntityLinkItem:
    _authorize(principal, organization_id)
    record = db.scalar(select(IntelRecord).where(
        IntelRecord.id == payload.record_id,
        IntelRecord.organization_id == organization_id,
    ))
    entity = db.scalar(select(ThreatEntity).where(
        ThreatEntity.id == payload.entity_id,
        ThreatEntity.organization_id == organization_id,
    ))
    if record is None or entity is None:
        raise HTTPException(status_code=404, detail="Resource not found")
    link = db.scalar(select(IntelEntityLink).where(
        IntelEntityLink.organization_id == organization_id,
        IntelEntityLink.record_id == record.id,
        IntelEntityLink.entity_id == entity.id,
        IntelEntityLink.relationship_type == payload.relationship_type,
    ))
    if link is None:
        link = IntelEntityLink(
            organization_id=organization_id,
            record_id=record.id,
            entity_id=entity.id,
            relationship_type=payload.relationship_type,
            rationale=payload.rationale,
            confidence=payload.confidence,
        )
        db.add(link)
        db.commit()
        db.refresh(link)
    return EntityLinkItem.model_validate(link)


@router.post("/organizations/{organization_id}/attack-mappings", response_model=AttackMappingItem, status_code=201)
def create_attack_mapping(
    organization_id: UUID,
    payload: AttackMappingCreate,
    principal: Annotated[Principal, Depends(get_current_principal)],
    db: Annotated[Session, Depends(get_db)],
) -> AttackMappingItem:
    _authorize(principal, organization_id)
    entity = db.scalar(select(ThreatEntity).where(
        ThreatEntity.id == payload.entity_id,
        ThreatEntity.organization_id == organization_id,
    ))
    if entity is None:
        raise HTTPException(status_code=404, detail="Resource not found")
    mapping = db.scalar(select(AttackTechniqueMapping).where(
        AttackTechniqueMapping.organization_id == organization_id,
        AttackTechniqueMapping.entity_id == entity.id,
        AttackTechniqueMapping.technique_id == payload.technique_id,
    ))
    if mapping is None:
        mapping = AttackTechniqueMapping(
            organization_id=organization_id,
            entity_id=entity.id,
            technique_id=payload.technique_id,
            technique_name=payload.technique_name.strip(),
            rationale=payload.rationale,
            confidence=payload.confidence,
            mapping_status=payload.mapping_status,
            source_reference=payload.source_reference,
        )
        db.add(mapping)
        db.commit()
        db.refresh(mapping)
    return AttackMappingItem.model_validate(mapping)


@router.get("/organizations/{organization_id}/entities", response_model=list[ThreatEntityItem])
def list_threat_entities(
    organization_id: UUID,
    principal: Annotated[Principal, Depends(get_current_principal)],
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ThreatEntityItem]:
    _authorize(principal, organization_id)
    entities = db.scalars(select(ThreatEntity).where(
        ThreatEntity.organization_id == organization_id
    ).order_by(ThreatEntity.name).limit(limit).offset(offset)).all()
    return [ThreatEntityItem.model_validate(item) for item in entities]


@router.get("/organizations/{organization_id}/entities/{entity_id}/relationships", response_model=list[EntityLinkItem])
def list_entity_relationships(
    organization_id: UUID,
    entity_id: UUID,
    principal: Annotated[Principal, Depends(get_current_principal)],
    db: Annotated[Session, Depends(get_db)],
) -> list[EntityLinkItem]:
    _authorize(principal, organization_id)
    entity = db.scalar(select(ThreatEntity.id).where(
        ThreatEntity.id == entity_id, ThreatEntity.organization_id == organization_id
    ))
    if entity is None:
        raise HTTPException(status_code=404, detail="Resource not found")
    links = db.scalars(select(IntelEntityLink).where(
        IntelEntityLink.organization_id == organization_id,
        IntelEntityLink.entity_id == entity_id,
    ).order_by(IntelEntityLink.created_at.desc())).all()
    return [EntityLinkItem.model_validate(item) for item in links]


@router.get("/organizations/{organization_id}/entities/{entity_id}/attack-mappings", response_model=list[AttackMappingItem])
def list_attack_mappings(
    organization_id: UUID,
    entity_id: UUID,
    principal: Annotated[Principal, Depends(get_current_principal)],
    db: Annotated[Session, Depends(get_db)],
) -> list[AttackMappingItem]:
    _authorize(principal, organization_id)
    entity = db.scalar(select(ThreatEntity.id).where(
        ThreatEntity.id == entity_id, ThreatEntity.organization_id == organization_id
    ))
    if entity is None:
        raise HTTPException(status_code=404, detail="Resource not found")
    mappings = db.scalars(select(AttackTechniqueMapping).where(
        AttackTechniqueMapping.organization_id == organization_id,
        AttackTechniqueMapping.entity_id == entity_id,
    ).order_by(AttackTechniqueMapping.technique_id)).all()
    return [AttackMappingItem.model_validate(item) for item in mappings]
