from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.attack import AttackTechnique
from app.models.intelligence import FeedRun, Indicator, SourceEvidence
from app.services.cisa_kev import sync_cisa_kev
from app.services.custom_csv import sync_custom_csv
from app.services.enrichment import detection_opportunities, enrich_indicator
from app.services.mitre_attack import sync_attack_catalog
from app.services.nvd import sync_nvd_cves

router = APIRouter(prefix="/api/v1/intelligence", tags=["threat intelligence"])


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
