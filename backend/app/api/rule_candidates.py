from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.detection import DetectionIntent
from app.models.rule import RuleCandidate
from app.schemas.rule import RuleCandidateCreate, RuleCandidateOut
from app.services.validation import validate_candidate

router = APIRouter(prefix="/api/v1/detection-intents", tags=["rule candidates"])
DbSession = Annotated[Session, Depends(get_db, scope="function")]


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
    intent_data = {"required_telemetry": intent.required_telemetry}
    report = validate_candidate(payload.platform, payload.query, intent_data)
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


library_router = APIRouter(prefix="/api/v1/rules", tags=["rule library"])


@library_router.get("", response_model=list[RuleCandidateOut])
def list_rule_library(
    db: DbSession,
    q: str | None = None,
    platform: str | None = None,
    validation_status: str | None = None,
    candidate_status: str | None = None,
    intent_id: UUID | None = None,
    limit: int = 100,
    offset: int = 0,
):
    """Search candidate rule versions across all detection intents."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    if offset < 0:
        raise HTTPException(status_code=422, detail="offset must be non-negative")

    stmt = select(RuleCandidate).order_by(
        desc(RuleCandidate.created_at), desc(RuleCandidate.version)
    ).limit(limit).offset(offset)
    if q:
        term = f"%{q.strip()}%"
        stmt = stmt.where(
            RuleCandidate.name.ilike(term) | RuleCandidate.query.ilike(term)
        )
    if platform:
        stmt = stmt.where(RuleCandidate.platform == platform.lower())
    if validation_status:
        stmt = stmt.where(RuleCandidate.validation_status == validation_status.lower())
    if candidate_status:
        stmt = stmt.where(RuleCandidate.status == candidate_status.lower())
    if intent_id:
        stmt = stmt.where(RuleCandidate.intent_id == intent_id)
    return db.scalars(stmt).all()
