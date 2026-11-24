from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.detection import DetectionIntent
from app.models.rule import RuleCandidate
from app.schemas.detection import TargetPlatform
from app.schemas.generation import GenerationRequest
from app.schemas.rule import RuleCandidateOut
from app.services.generation import (
    GenerationProvider,
    GenerationUnavailable,
    get_generation_provider,
)
from app.services.validation import validate_candidate

router = APIRouter(prefix="/api/v1/detection-intents", tags=["detection generation"])
DbSession = Annotated[Session, Depends(get_db)]
Provider = Annotated[GenerationProvider, Depends(get_generation_provider)]


@router.post("/{intent_id}/generate", response_model=list[RuleCandidateOut], status_code=status.HTTP_201_CREATED)
def generate_candidates(intent_id: UUID, payload: GenerationRequest, db: DbSession, provider: Provider):
    intent = db.get(DetectionIntent, intent_id)
    if intent is None:
        raise HTTPException(status_code=404, detail="Detection intent not found")

    platforms = payload.target_platforms or [TargetPlatform(value) for value in intent.target_platforms]
    if not platforms:
        raise HTTPException(status_code=422, detail="The detection intent has no target platforms")
    if any(platform.value not in intent.target_platforms for platform in platforms):
        raise HTTPException(status_code=422, detail="Requested platform is not included in the detection intent")
    if len({platform.value for platform in platforms}) != len(platforms):
        raise HTTPException(status_code=422, detail="Duplicate target platforms are not allowed")

    intent_data = {
        "title": intent.title,
        "description": intent.description,
        "behavior": intent.behavior,
        "severity": intent.severity,
        "attack_techniques": intent.attack_techniques,
        "required_telemetry": intent.required_telemetry,
        "evidence": intent.evidence,
        "test_scenarios": intent.test_scenarios,
    }
    generated = []
    try:
        for platform in platforms:
            generated.append((platform, provider.generate(intent_data, platform)))
    except GenerationUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    candidates = []
    for platform, draft in generated:
        version = db.scalar(select(func.max(RuleCandidate.version)).where(
            RuleCandidate.intent_id == intent_id, RuleCandidate.platform == platform.value
        )) or 0
        report = validate_candidate(platform, draft.query)
        candidates.append(RuleCandidate(
            intent_id=intent_id,
            name=draft.name,
            platform=platform.value,
            query=draft.query,
            version=version + 1,
            status="candidate",
            validation_status=report["status"],
            validation_report=report,
            generator="openai",
        ))
    db.add_all(candidates)
    db.commit()
    for candidate in candidates:
        db.refresh(candidate)
    return candidates
