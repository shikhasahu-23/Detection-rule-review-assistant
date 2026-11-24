from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.rule import RuleCandidate
from app.models.testing import DetectionTestRun
from app.schemas.testing import DetectionTestRunOut, DetectionTestSuite
from app.services.testing import compare_regression, run_query_contract_suite

router = APIRouter(prefix="/api/v1/rules", tags=["detection testing"])
DbSession = Annotated[Session, Depends(get_db)]


@router.post("/{candidate_id}/test-runs", response_model=DetectionTestRunOut, status_code=status.HTTP_201_CREATED)
def create_test_run(candidate_id: UUID, payload: DetectionTestSuite, db: DbSession):
    candidate = db.get(RuleCandidate, candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail="Rule candidate not found")

    result = run_query_contract_suite(candidate.query, payload)
    previous = db.scalar(
        select(DetectionTestRun)
        .join(RuleCandidate, DetectionTestRun.candidate_id == RuleCandidate.id)
        .where(
            RuleCandidate.intent_id == candidate.intent_id,
            RuleCandidate.platform == candidate.platform,
            RuleCandidate.version < candidate.version,
            DetectionTestRun.suite_fingerprint == result["suite_fingerprint"],
        )
        .order_by(desc(RuleCandidate.version), desc(DetectionTestRun.created_at))
        .limit(1)
    )
    regression = compare_regression(
        result,
        {
            "case_results": previous.case_results,
        } if previous else None,
    )
    run = DetectionTestRun(
        candidate_id=candidate.id,
        suite_fingerprint=result["suite_fingerprint"],
        query_fingerprint=result["query_fingerprint"],
        status=result["status"],
        total_cases=result["total_cases"],
        passed_cases=result["passed_cases"],
        failed_cases=result["failed_cases"],
        case_results=result["case_results"],
        regression_report=regression,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@router.get("/{candidate_id}/test-runs", response_model=list[DetectionTestRunOut])
def list_test_runs(candidate_id: UUID, db: DbSession):
    if db.get(RuleCandidate, candidate_id) is None:
        raise HTTPException(status_code=404, detail="Rule candidate not found")
    stmt = (
        select(DetectionTestRun)
        .where(DetectionTestRun.candidate_id == candidate_id)
        .order_by(desc(DetectionTestRun.created_at))
        .limit(50)
    )
    return db.scalars(stmt).all()
