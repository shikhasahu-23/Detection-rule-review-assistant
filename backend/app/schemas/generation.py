from pydantic import BaseModel, Field

from app.schemas.detection import TargetPlatform


class GenerationRequest(BaseModel):
    target_platforms: list[TargetPlatform] | None = Field(default=None, min_length=1, max_length=5)


class GeneratedRule(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    query: str = Field(min_length=5, max_length=20000)
