from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.attack import AttackTechnique
from app.models.intelligence import FeedRun, Indicator, SourceEvidence
from app.models.pipeline import PipelineRun
from app.models.threat_graph import ThreatEntity, ThreatEntityEvidence, ThreatRelationship
from app.services.cisa_kev import sync_cisa_kev
from app.services.custom_csv import sync_custom_csv
from app.services.enrichment import detection_opportunities, enrich_indicator
from app.services.mitre_attack import sync_attack_catalog
from app.services.nvd import sync_nvd_cves
from app.services.threat_graph import ENTITY_TYPES, import_stix_bundle
from app.tasks.pipeline import execute_pipeline

router = APIRouter(prefix="/api/v1/intelligence", tags=["threat intelligence"])


class STIXImportRequest(BaseModel):
    source_name: str = Field(min_length=1, max_length=100)
    bundle: dict


class IndicatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    indicator_type: str
    value: str
    confidence: int
    severity: str
    status: str
    description: str | None
    tags: list
    created_at: datetime


@router.get("/summary")
def intelligence_summary(db: Annotated[Session, Depends(get_db)]) -> dict:
    return {
        "indicators_total": db.scalar(select(func.count()).select_from(Indicator)) or 0,
        "active_indicators": db.scalar(select(func.count()).select_from(Indicator).where(Indicator.status == "active")) or 0,
        "sources_total": db.scalar(select(func.count(func.distinct(SourceEvidence.source_name)))) or 0,
        "latest_run": _latest_run(db),
    }


@router.get("/indicators", response_model=list[IndicatorOut])
def list_indicators(
    db: Annotated[Session, Depends(get_db)],
    q: str | None = Query(default=None, max_length=256),
    indicator_type: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(Indicator).order_by(desc(Indicator.created_at)).limit(limit).offset(offset)
    if q:
        stmt = stmt.where(Indicator.value.ilike(f"%{q}%"))
    if indicator_type:
        stmt = stmt.where(Indicator.indicator_type == indicator_type.lower())
    return db.scalars(stmt).all()


@router.get("/indicators/{indicator_id}/evidence")
def indicator_evidence(indicator_id: UUID, db: Annotated[Session, Depends(get_db)]) -> list[dict]:
    if db.get(Indicator, indicator_id) is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    rows = db.scalars(select(SourceEvidence).where(SourceEvidence.indicator_id == indicator_id)).all()
    return [{"source": row.source_name, "reference": row.source_reference,
             "url": row.source_url, "observed_at": row.observed_at, "raw_data": row.raw_data}
            for row in rows]


@router.get("/feeds")
def list_feeds(db: Annotated[Session, Depends(get_db)]) -> list[dict]:
    latest = db.scalars(select(FeedRun).order_by(desc(FeedRun.started_at)).limit(50)).all()
    by_source: dict[str, dict] = {}
    for run in latest:
        if run.source_name not in by_source:
            by_source[run.source_name] = {
                "name": run.source_name, "status": run.status,
                "last_run": run.started_at, "records_seen": run.records_seen,
                "indicators_created": run.indicators_created,
            }
    return list(by_source.values())


@router.post("/feeds/cisa-kev/sync")
def sync_cisa_feed(db: Annotated[Session, Depends(get_db)]) -> dict:
    try:
        return sync_cisa_kev(db)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="CISA feed ingestion failed") from exc


@router.post("/feeds/nvd/sync")
def sync_nvd_feed(db: Annotated[Session, Depends(get_db)]) -> dict:
    try:
        return sync_nvd_cves(db)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="NVD feed ingestion failed") from exc


def _latest_run(db: Session) -> dict | None:
    run = db.scalar(select(FeedRun).order_by(desc(FeedRun.started_at)).limit(1))
    if run is None:
        return None
    return {"source": run.source_name, "status": run.status, "started_at": run.started_at,
            "records_seen": run.records_seen, "indicators_created": run.indicators_created}


@router.post("/feeds/mitre-attack/sync")
def sync_mitre_attack_feed(db: Annotated[Session, Depends(get_db)]) -> dict:
    try:
        return sync_attack_catalog(db)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="MITRE ATT&CK ingestion failed") from exc


@router.get("/attack-techniques")
def list_attack_techniques(
    db: Annotated[Session, Depends(get_db)],
    q: str | None = Query(default=None, max_length=200),
    platform: str | None = Query(default=None, max_length=100),
    tactic: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    stmt = select(AttackTechnique).order_by(AttackTechnique.external_id).limit(limit).offset(offset)
    if q:
        stmt = stmt.where(
            AttackTechnique.name.ilike(f"%{q}%") |
            AttackTechnique.external_id.ilike(f"%{q}%")
        )
    rows = db.scalars(stmt).all()
    if platform:
        rows = [row for row in rows if platform.lower() in [value.lower() for value in row.platforms]]
    if tactic:
        rows = [row for row in rows if tactic.lower() in [value.lower() for value in row.tactics]]
    return [{
        "id": row.id, "external_id": row.external_id, "name": row.name,
        "description": row.description, "platforms": row.platforms, "tactics": row.tactics,
        "is_subtechnique": row.is_subtechnique, "revoked": row.revoked,
        "deprecated": row.deprecated, "source_url": row.source_url,
        "modified_at": row.modified_at,
    } for row in rows]


@router.post("/feeds/custom/csv")
async def import_custom_csv(request: Request, db: Annotated[Session, Depends(get_db)]) -> dict:
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "text/csv":
        raise HTTPException(status_code=415, detail="Content-Type must be text/csv")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 2_000_000:
            raise HTTPException(status_code=413, detail="CSV import is limited to 2 MB")
        body.extend(chunk)
    try:
        csv_text = bytes(body).decode("utf-8-sig")
        return sync_custom_csv(db, csv_text)
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 encoded") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Custom CSV ingestion failed") from exc



@router.get("/indicators/{indicator_id}/enrichment")
def get_indicator_enrichment(
    indicator_id: UUID,
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    result = enrich_indicator(db, indicator_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return result


@router.get("/detection-opportunities")
def list_detection_opportunities(
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict]:
    return detection_opportunities(db, limit=limit)


@router.post("/feeds/custom/stix")
def import_custom_stix(
    payload: STIXImportRequest,
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    try:
        return import_stix_bundle(db, payload.bundle, source_name=payload.source_name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="STIX import failed") from exc


@router.get("/threat-graph/entities")
def list_threat_entities(
    db: Annotated[Session, Depends(get_db)],
    q: str | None = Query(default=None, max_length=256),
    entity_type: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    if entity_type and entity_type not in set(ENTITY_TYPES.values()):
        raise HTTPException(status_code=422, detail="Unsupported threat entity type")
    stmt = select(ThreatEntity).order_by(ThreatEntity.name).limit(limit).offset(offset)
    if q:
        stmt = stmt.where(
            ThreatEntity.name.ilike(f"%{q}%")
            | ThreatEntity.external_id.ilike(f"%{q}%")
        )
    if entity_type:
        stmt = stmt.where(ThreatEntity.entity_type == entity_type)
    rows = db.scalars(stmt).all()
    return [{
        "id": str(row.id), "entity_type": row.entity_type,
        "external_id": row.external_id, "name": row.name,
        "description": row.description, "confidence": row.confidence,
        "source_name": row.source_name, "source_reference": row.source_reference,
        "source_url": row.source_url, "revoked": row.revoked,
        "deprecated": row.deprecated, "first_seen": row.first_seen,
        "last_seen": row.last_seen,
    } for row in rows]


@router.get("/threat-graph/relationships")
def list_threat_relationships(
    db: Annotated[Session, Depends(get_db)],
    entity_id: UUID | None = None,
    relationship_type: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    stmt = select(ThreatRelationship).order_by(desc(ThreatRelationship.observed_at)).limit(limit).offset(offset)
    if entity_id:
        stmt = stmt.where(
            (ThreatRelationship.source_entity_id == entity_id)
            | (ThreatRelationship.target_entity_id == entity_id)
        )
    if relationship_type:
        stmt = stmt.where(ThreatRelationship.relationship_type == relationship_type)
    rows = db.scalars(stmt).all()
    entity_ids = {row.source_entity_id for row in rows} | {row.target_entity_id for row in rows}
    entities = {
        str(row.id): row.name for row in db.scalars(
            select(ThreatEntity).where(ThreatEntity.id.in_(entity_ids))
        ).all()
    } if entity_ids else {}
    return [{
        "id": str(row.id),
        "source_entity_id": str(row.source_entity_id),
        "source_entity_name": entities.get(str(row.source_entity_id)),
        "target_entity_id": str(row.target_entity_id),
        "target_entity_name": entities.get(str(row.target_entity_id)),
        "relationship_type": row.relationship_type,
        "confidence": row.confidence,
        "assertion_status": row.assertion_status,
        "source_name": row.source_name,
        "source_reference": row.source_reference,
        "source_url": row.source_url,
        "description": row.description,
        "observed_at": row.observed_at,
    } for row in rows]


@router.get("/threat-graph")
def get_threat_graph(
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=200, ge=1, le=500),
) -> dict:
    entities = db.scalars(select(ThreatEntity).order_by(ThreatEntity.name).limit(limit)).all()
    entity_ids = [row.id for row in entities]
    relationships = db.scalars(
        select(ThreatRelationship).where(
            ThreatRelationship.source_entity_id.in_(entity_ids),
            ThreatRelationship.target_entity_id.in_(entity_ids),
        ).order_by(desc(ThreatRelationship.observed_at)).limit(1000)
    ).all() if entity_ids else []
    return {
        "nodes": [{
            "id": str(row.id), "entity_type": row.entity_type,
            "external_id": row.external_id, "name": row.name,
            "confidence": row.confidence, "source_name": row.source_name,
            "source_reference": row.source_reference, "source_url": row.source_url,
            "revoked": row.revoked, "deprecated": row.deprecated,
        } for row in entities],
        "edges": [{
            "id": str(row.id), "source": str(row.source_entity_id),
            "target": str(row.target_entity_id),
            "relationship_type": row.relationship_type,
            "confidence": row.confidence, "assertion_status": row.assertion_status,
            "source_name": row.source_name, "source_reference": row.source_reference,
            "source_url": row.source_url,
        } for row in relationships],
        "truncated": len(entities) == limit or len(relationships) == 1000,
    }


@router.get("/threat-graph/entities/{entity_id}/evidence")
def threat_entity_evidence(
    entity_id: UUID,
    db: Annotated[Session, Depends(get_db)],
) -> list[dict]:
    if db.get(ThreatEntity, entity_id) is None:
        raise HTTPException(status_code=404, detail="Threat entity not found")
    rows = db.scalars(select(ThreatEntityEvidence).where(
        ThreatEntityEvidence.entity_id == entity_id
    ).order_by(desc(ThreatEntityEvidence.observed_at))).all()
    return [{
        "source_name": row.source_name,
        "source_reference": row.source_reference,
        "source_url": row.source_url,
        "confidence": row.confidence,
        "observed_at": row.observed_at,
    } for row in rows]



@router.post("/pipeline/runs", status_code=202)
def enqueue_intelligence_pipeline(background_tasks: BackgroundTasks) -> dict:
    """Run the manual pipeline in the API process; no paid Celery worker is required."""
    background_tasks.add_task(execute_pipeline, trigger="manual", sync_feeds=True)
    return {
        "status": "queued",
        "execution": "in_process",
        "message": (
            "Full feed ingestion and intelligence pipeline started in the API background. "
            "This run is not durable across API restarts."
        ),
    }


@router.get("/pipeline/runs")
def list_pipeline_runs(
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=20, ge=1, le=100),
) -> list[dict]:
    rows = db.scalars(
        select(PipelineRun).order_by(desc(PipelineRun.started_at)).limit(limit)
    ).all()
    return [{
        "run_id": str(row.id), "status": row.status, "trigger": row.trigger,
        "stage_results": row.stage_results, "indicators_enriched": row.indicators_enriched,
        "opportunities_found": row.opportunities_found,
        "candidates_created": row.candidates_created,
        "candidates_skipped": row.candidates_skipped,
        "started_at": row.started_at, "completed_at": row.completed_at,
        "error_message": row.error_message,
    } for row in rows]


@router.get("/pipeline/runs/{run_id}")
def get_pipeline_run(
    run_id: UUID,
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    row = db.get(PipelineRun, run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return {
        "run_id": str(row.id), "status": row.status, "trigger": row.trigger,
        "stage_results": row.stage_results, "indicators_enriched": row.indicators_enriched,
        "opportunities_found": row.opportunities_found,
        "candidates_created": row.candidates_created,
        "candidates_skipped": row.candidates_skipped,
        "started_at": row.started_at, "completed_at": row.completed_at,
        "error_message": row.error_message,
    }
