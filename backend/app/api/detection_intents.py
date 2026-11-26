from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.detection import DetectionIntent
from app.schemas.detection import DetectionIntentCreate, DetectionIntentOut

router = APIRouter(prefix="/api/v1/detection-intents", tags=["detection engineering"])
DbSession = Annotated[Session, Depends(get_db, scope="function")]


@router.post("", response_model=DetectionIntentOut, status_code=status.HTTP_201_CREATED)
def create_detection_intent(payload: DetectionIntentCreate, db: DbSession):
    intent = DetectionIntent(
        title=payload.title,
        description=payload.description,
        behavior=payload.behavior,
        severity=payload.severity,
        attack_techniques=payload.attack_techniques,
        required_telemetry=[item.model_dump() for item in payload.required_telemetry],
        evidence=[item.model_dump() for item in payload.evidence],
        test_scenarios=payload.test_scenarios,
        target_platforms=[item.value for item in payload.target_platforms],
    )
    db.add(intent)
    db.commit()
    db.refresh(intent)
    return intent


@router.get("", response_model=list[DetectionIntentOut])
def list_detection_intents(
    db: DbSession,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(DetectionIntent).order_by(desc(DetectionIntent.created_at)).limit(limit).offset(offset)
    if q:
        stmt = stmt.where(DetectionIntent.title.ilike(f"%{q}%"))
    return db.scalars(stmt).all()


@router.get("/{intent_id}", response_model=DetectionIntentOut)
def get_detection_intent(intent_id: UUID, db: DbSession):
    intent = db.get(DetectionIntent, intent_id)
    if intent is None:
        raise HTTPException(status_code=404, detail="Detection intent not found")
    return intent
