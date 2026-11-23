from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class IndicatorType(StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    CVE = "cve"
    EMAIL = "email"


class IntelEvidenceInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    source_name: str = Field(min_length=1, max_length=120)
    source_reference: str | None = Field(default=None, max_length=2048)
    observed_at: datetime | None = None
    payload_hash: str = Field(min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]{64}$")
    raw_payload: dict[str, object] = Field(default_factory=dict)


class IntelIndicatorInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    indicator_type: IndicatorType
    value: str = Field(min_length=1, max_length=2048)
    confidence: float | None = Field(default=None, ge=0, le=100)
    severity: str | None = Field(default=None, max_length=24)
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    expires_at: datetime | None = None
    evidence: list[IntelEvidenceInput] = Field(min_length=1)

    @model_validator(mode="after")
    def normalize_and_validate_value(self) -> "IntelIndicatorInput":
        value = self.value.strip()
        if self.indicator_type == IndicatorType.IP_ADDRESS:
            value = str(ip_address(value))
        elif self.indicator_type == IndicatorType.DOMAIN:
            value = value.rstrip(".").encode("idna").decode("ascii").lower()
            if not value or any(not label or len(label) > 63 for label in value.split(".")):
                raise ValueError("Invalid domain indicator")
        elif self.indicator_type == IndicatorType.URL:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                raise ValueError("URL indicators must use http or https and include a hostname")
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            netloc = host if parsed.port is None else f"{host}:{parsed.port}"
            if parsed.username or parsed.password:
                raise ValueError("URL indicators must not contain embedded credentials")
            value = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
        elif self.indicator_type == IndicatorType.SHA256:
            value = value.lower()
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValueError("SHA-256 indicators must contain exactly 64 hexadecimal characters")
        elif self.indicator_type == IndicatorType.CVE:
            value = value.upper()
            if not value.startswith("CVE-"):
                raise ValueError("CVE indicators must start with CVE-")
        elif self.indicator_type == IndicatorType.EMAIL:
            value = value.casefold()
            if value.count("@") != 1 or any(char.isspace() for char in value):
                raise ValueError("Invalid email indicator")

        self.value = value
        if (
            self.first_seen_at is not None
            and self.last_seen_at is not None
            and self.first_seen_at > self.last_seen_at
        ):
            raise ValueError("first_seen_at cannot be later than last_seen_at")
        return self
