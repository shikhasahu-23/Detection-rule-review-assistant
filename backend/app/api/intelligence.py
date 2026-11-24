from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.intelligence import FeedRun, Indicator, SourceEvidence
from app.services.cisa_kev import sync_cisa_kev

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
    q: str | None = Query(default=None, max_length=256),
    indicator_type: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Annotated[Session, Depends(get_db)],
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


def _latest_run(db: Session) -> dict | None:
    run = db.scalar(select(FeedRun).order_by(desc(FeedRun.started_at)).limit(1))
    if run is None:
        return None
    return {"source": run.source_name, "status": run.status, "started_at": run.started_at,
            "records_seen": run.records_seen, "indicators_created": run.indicators_created}
