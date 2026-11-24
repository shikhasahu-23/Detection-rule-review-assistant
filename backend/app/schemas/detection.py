from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TargetPlatform(StrEnum):
    SPLUNK = "splunk"
    CHRONICLE = "chronicle"
    SENTINEL = "sentinel"
    CROWDSTRIKE = "crowdstrike"


class TelemetryRequirement(BaseModel):
    source: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=500)
    required_fields: list[str] = Field(default_factory=list, max_length=100)


class EvidenceReference(BaseModel):
    kind: str = Field(min_length=1, max_length=40)
    reference: str = Field(min_length=1, max_length=500)
    source: str = Field(min_length=1, max_length=120)
    confidence: int = Field(default=50, ge=0, le=100)


class DetectionIntentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10, max_length=4000)
    behavior: str = Field(min_length=10, max_length=4000)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    attack_techniques: list[str] = Field(default_factory=list, max_length=50)
    required_telemetry: list[TelemetryRequirement] = Field(min_length=1, max_length=30)
    evidence: list[EvidenceReference] = Field(default_factory=list, max_length=100)
    test_scenarios: list[str] = Field(default_factory=list, max_length=30)
    target_platforms: list[TargetPlatform] = Field(min_length=1, max_length=4)

    @field_validator("attack_techniques")
    @classmethod
    def validate_attack_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value.startswith("T") or len(value) > 16:
                raise ValueError("ATT&CK technique IDs must use the Txxxx or Txxxx.xxx format")
        return values


class DetectionIntentOut(DetectionIntentCreate):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    status: str
