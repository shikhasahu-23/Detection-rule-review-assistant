from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class QueryAssertion(BaseModel):
    operator: str = Field(pattern="^(contains|not_contains)$")
    value: str = Field(min_length=1, max_length=160)


class DetectionTestCase(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    scenario_type: str = Field(pattern="^(positive|negative|edge)$")
    fixture: dict = Field(default_factory=dict)
    assertions: list[QueryAssertion] = Field(min_length=1, max_length=30)


class DetectionTestSuite(BaseModel):
    cases: list[DetectionTestCase] = Field(min_length=1, max_length=100)


class DetectionTestRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    candidate_id: UUID
    suite_fingerprint: str
    query_fingerprint: str
    status: str
    total_cases: int
    passed_cases: int
    failed_cases: int
    case_results: list[dict]
    regression_report: dict
    created_at: datetime
