from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.detection import DetectionIntent
from app.models.rule import RuleCandidate
from app.schemas.detection import TargetPlatform
from app.schemas.rule import RuleCandidateCreate, RuleCandidateOut
from app.services.validation import validate_candidate

router = APIRouter(prefix="/api/v1/detection-intents", tags=["rule candidates"])
DbSession = Annotated[Session, Depends(get_db)]


@router.post("/{intent_id}/candidates", response_model=RuleCandidateOut, status_code=status.HTTP_201_CREATED)
def create_candidate(intent_id: UUID, payload: RuleCandidateCreate, db: DbSession):
    intent = db.get(DetectionIntent, intent_id)
    if intent is None:
        raise HTTPException(status_code=404, detail="Detection intent not found")
    if payload.platform.value not in intent.target_platforms:
        raise HTTPException(status_code=422, detail="Platform is not included in the detection intent")
    version = db.scalar(select(func.max(RuleCandidate.version)).where(
        RuleCandidate.intent_id == intent_id, RuleCandidate.platform == payload.platform.value
    )) or 0
    report = validate_candidate(payload.platform, payload.query)
    candidate = RuleCandidate(
        intent_id=intent_id,
        name=payload.name,
        platform=payload.platform.value,
        query=payload.query,
        version=version + 1,
        status="candidate",
        validation_status=report["status"],
        validation_report=report,
        generator="manual",
    )
    db.add(candidate)
    db.commit()
    db.refresh(candidate)
    return candidate


@router.get("/{intent_id}/candidates", response_model=list[RuleCandidateOut])
def list_candidates(intent_id: UUID, db: DbSession):
    if db.get(DetectionIntent, intent_id) is None:
        raise HTTPException(status_code=404, detail="Detection intent not found")
    stmt = select(RuleCandidate).where(RuleCandidate.intent_id == intent_id).order_by(desc(RuleCandidate.created_at))
    return db.scalars(stmt).all()
