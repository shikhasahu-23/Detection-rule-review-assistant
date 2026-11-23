import json
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

import httpx

from app.intel.connectors.base import ConnectorHealth, ConnectorStatus, IntelConnector
from app.intel.schemas import IndicatorType, IntelEvidenceInput, IntelIndicatorInput

URLHAUS_RECENT_URLS_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


class UrlhausConnector(IntelConnector):
    """Fetch recent malware-distribution URLs from the authenticated URLhaus API."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._auth_key: str | None = None
        self._limit = 1000
        self._last_success_at: str | None = None

    async def configure(self, config: Mapping[str, Any]) -> None:
        unknown = set(config) - {"auth_key", "limit"}
        if unknown:
            raise ValueError(f"Unsupported URLhaus configuration keys: {', '.join(sorted(unknown))}")
        auth_key = config.get("auth_key")
        if not isinstance(auth_key, str) or not auth_key.strip():
            raise ValueError("URLhaus auth_key is required")
        limit = config.get("limit", 1000)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("URLhaus limit must be between 1 and 1000")
        self._auth_key = auth_key.strip()
        self._limit = limit

    async def _post(self) -> dict[str, Any]:
        if self._auth_key is None:
            raise RuntimeError("URLhaus connector must be configured before fetch")
        headers = {"Auth-Key": self._auth_key}
        payload = {"limit": self._limit}
        if self._client is not None:
            response = await self._client.post(URLHAUS_RECENT_URLS_API, data=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(URLHAUS_RECENT_URLS_API, data=payload, headers=headers)
            response.raise_for_status()
            return response.json()

    async def fetch(
        self,
        checkpoint: Mapping[str, str] | None = None,
    ) -> AsyncIterator[Mapping[str, Any]]:
        del checkpoint  # URLhaus exposes a bounded recent-feed query, not a cursor.
        payload = await self._post()
        if payload.get("query_status") != "ok" or not isinstance(payload.get("urls"), list):
            raise ValueError("URLhaus returned an unsuccessful response or missing urls list")
        self._last_success_at = datetime.now(UTC).isoformat()
        for record in payload["urls"]:
            if isinstance(record, dict):
                yield record

    def parse(self, raw_record: Mapping[str, Any]) -> list[IntelIndicatorInput]:
        value = raw_record.get("url")
        if not isinstance(value, str):
            return []
        payload = dict(raw_record)
        record_id = raw_record.get("id")
        reference = f"https://urlhaus.abuse.ch/url/{record_id}/" if record_id else None
        added = raw_record.get("date_added")
        try:
            first_seen = datetime.fromisoformat(added.replace(" ", "T")) if isinstance(added, str) else None
        except ValueError:
            first_seen = None
        return [
            IntelIndicatorInput(
                indicator_type=IndicatorType.URL,
                value=value,
                first_seen_at=first_seen,
                evidence=[
                    IntelEvidenceInput(
                        source_name="URLhaus",
                        source_reference=reference,
                        observed_at=first_seen,
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
