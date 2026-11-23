from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from hashlib import sha256
import json
from typing import Any

import httpx

from app.intel.connectors.base import ConnectorHealth, ConnectorStatus, IntelConnector
from app.intel.schemas import IndicatorType, IntelEvidenceInput, IntelIndicatorInput

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxConnector(IntelConnector):
    """Fetch recent ThreatFox IOCs through the authenticated community API."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._auth_key: str | None = None
        self._days = 3
        self._last_success_at: str | None = None

    async def configure(self, config: Mapping[str, Any]) -> None:
        unknown = set(config) - {"auth_key", "days"}
        if unknown:
            raise ValueError(f"Unsupported ThreatFox configuration keys: {', '.join(sorted(unknown))}")
        auth_key = config.get("auth_key")
        if not isinstance(auth_key, str) or not auth_key.strip():
            raise ValueError("ThreatFox auth_key is required")
        days = config.get("days", 3)
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 7:
            raise ValueError("ThreatFox days must be between 1 and 7")
        self._auth_key = auth_key.strip()
        self._days = days

    async def _post(self) -> dict[str, Any]:
        if self._auth_key is None:
            raise RuntimeError("ThreatFox connector must be configured before fetch")
        headers = {"Auth-Key": self._auth_key}
        payload = {"query": "get_iocs", "days": self._days}
        if self._client is not None:
            response = await self._client.post(THREATFOX_API_URL, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(THREATFOX_API_URL, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()

    async def fetch(
        self,
        checkpoint: Mapping[str, str] | None = None,
    ) -> AsyncIterator[Mapping[str, Any]]:
        del checkpoint  # ThreatFox recent IOC queries are bounded by a 1-7 day window.
        payload = await self._post()
        if payload.get("query_status") != "ok" or not isinstance(payload.get("data"), list):
            raise ValueError("ThreatFox returned an unsuccessful response or missing data list")
        self._last_success_at = datetime.now(UTC).isoformat()
        for record in payload["data"]:
            if isinstance(record, dict):
                yield record

    @staticmethod
    def _indicator_type(ioc_type: str) -> IndicatorType | None:
        mapping = {
            "ip": IndicatorType.IP_ADDRESS,
            "domain": IndicatorType.DOMAIN,
            "url": IndicatorType.URL,
            "sha256_hash": IndicatorType.SHA256,
            "sha256": IndicatorType.SHA256,
            "email": IndicatorType.EMAIL,
        }
        return mapping.get(ioc_type.lower())

    def parse(self, raw_record: Mapping[str, Any]) -> list[IntelIndicatorInput]:
        ioc = raw_record.get("ioc")
        ioc_type = raw_record.get("ioc_type")
        if not isinstance(ioc, str) or not isinstance(ioc_type, str):
            return []
        indicator_type = self._indicator_type(ioc_type)
        if indicator_type is None:
            # Do not guess at composite types such as ip:port or unsupported hashes.
            return []
        payload = dict(raw_record)
        record_id = raw_record.get("id")
        reference = f"https://threatfox.abuse.ch/ioc/{record_id}/" if record_id else None
        first_seen_value = raw_record.get("first_seen")
        last_seen_value = raw_record.get("last_seen")
        try:
            first_seen = (
                datetime.fromisoformat(first_seen_value.replace(" ", "T"))
                if isinstance(first_seen_value, str)
                else None
            )
        except ValueError:
            first_seen = None
        try:
            last_seen = (
                datetime.fromisoformat(last_seen_value.replace(" ", "T"))
                if isinstance(last_seen_value, str)
                else None
            )
        except ValueError:
            last_seen = None
        confidence = raw_record.get("confidence_level")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            confidence = None
        return [
            IntelIndicatorInput(
                indicator_type=indicator_type,
                value=ioc,
                confidence=confidence,
                first_seen_at=first_seen,
                last_seen_at=last_seen,
                evidence=[
                    IntelEvidenceInput(
                        source_name="ThreatFox",
                        source_reference=reference,
                        observed_at=last_seen or first_seen,
                        payload_hash=sha256(
                            json.dumps(payload, sort_keys=True, default=str).encode()
                        ).hexdigest(),
                        raw_payload=payload,
                    )
                ],
            )
        ]

    def get_checkpoint(self) -> Mapping[str, str] | None:
        if self._last_success_at is None:
            return None
        return {"last_fetch_at": self._last_success_at}

    async def health(self) -> ConnectorHealth:
        status = ConnectorStatus.HEALTHY if self._last_success_at else ConnectorStatus.UNAVAILABLE
        return ConnectorHealth(status, last_success_at=self._last_success_at)
