from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.detection import TargetPlatform


class RuleCandidateCreate(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    platform: TargetPlatform
    query: str = Field(min_length=5, max_length=20000)


class RuleCandidateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    intent_id: UUID
    name: str
    platform: str
    query: str
    version: int
    status: str
    validation_status: str
    validation_report: dict
    generation_metadata: dict
    generator: str
