from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Mapping
from enum import StrEnum
from typing import Any

from app.intel.schemas import IntelIndicatorInput


class ConnectorStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class ConnectorHealth:
    def __init__(
        self,
        status: ConnectorStatus,
        message: str | None = None,
        last_success_at: str | None = None,
    ) -> None:
        self.status = status
        self.message = message
        self.last_success_at = last_success_at


class IntelConnector(ABC):
    """Contract implemented by every external or uploaded-intelligence connector."""

    @abstractmethod
    async def configure(self, config: Mapping[str, Any]) -> None:
        """Validate and apply connector-specific configuration."""

    @abstractmethod
    async def fetch(
        self,
        checkpoint: Mapping[str, str] | None = None,
    ) -> AsyncIterator[Mapping[str, Any]]:
        """Yield raw source records after the supplied checkpoint."""

    @abstractmethod
    def parse(self, raw_record: Mapping[str, Any]) -> list[IntelIndicatorInput]:
        """Convert one raw source record into zero or more canonical indicators."""

    @abstractmethod
    def get_checkpoint(self) -> Mapping[str, str] | None:
        """Return the resumable position reached by the most recent fetch."""

    @abstractmethod
    async def health(self) -> ConnectorHealth:
        """Return a safe operational health summary without exposing credentials."""
