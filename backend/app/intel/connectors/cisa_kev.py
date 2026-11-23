from collections.abc import AsyncIterator, Mapping
from datetime import date
from hashlib import sha256
from typing import Any

import httpx

from app.intel.connectors.base import ConnectorHealth, ConnectorStatus, IntelConnector
from app.intel.schemas import IndicatorType, IntelEvidenceInput, IntelIndicatorInput

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevConnector(IntelConnector):
    """Fetch and normalize CISA's public Known Exploited Vulnerabilities catalog."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._catalog_version: str | None = None
        self._last_success_at: str | None = None

    async def configure(self, config: Mapping[str, Any]) -> None:
        if config:
            raise ValueError("CISA KEV connector does not accept configuration values")

    async def _get_json(self) -> dict[str, Any]:
        if self._client is not None:
            response = await self._client.get(CISA_KEV_URL)
            response.raise_for_status()
            return response.json()
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(CISA_KEV_URL)
            response.raise_for_status()
            return response.json()

    async def fetch(
        self,
        checkpoint: Mapping[str, str] | None = None,
    ) -> AsyncIterator[Mapping[str, Any]]:
        catalog = await self._get_json()
        version = catalog.get("catalogVersion")
        if not isinstance(version, str) or not isinstance(catalog.get("vulnerabilities"), list):
            raise ValueError("CISA KEV response is missing catalogVersion or vulnerabilities")
        self._catalog_version = version
        self._last_success_at = str(catalog.get("dateReleased") or "")
        if checkpoint and checkpoint.get("catalog_version") == version:
            return
        for record in catalog["vulnerabilities"]:
            if isinstance(record, dict):
                yield {**record, "_catalogVersion": version, "_dateReleased": catalog.get("dateReleased")}

    def parse(self, raw_record: Mapping[str, Any]) -> list[IntelIndicatorInput]:
        cve_id = raw_record.get("cveID")
        if not isinstance(cve_id, str):
            return []
        observed_at = None
        if isinstance(raw_record.get("dateAdded"), str):
            try:
                observed_at = date.fromisoformat(raw_record["dateAdded"])
            except ValueError:
                pass
        return [
            IntelIndicatorInput(
                indicator_type=IndicatorType.CVE,
                value=cve_id,
                severity="critical" if raw_record.get("knownRansomwareCampaignUse") == "Known" else None,
                first_seen_at=observed_at,
                evidence=[
                    IntelEvidenceInput(
                        source_name="CISA KEV",
                        source_reference=f"{CISA_KEV_URL}#{cve_id}",
                        observed_at=observed_at,
                        payload_hash=sha256(repr(sorted(raw_record.items())).encode()).hexdigest(),
                        raw_payload=dict(raw_record),
                    )
                ],
            )
        ]

    def get_checkpoint(self) -> Mapping[str, str] | None:
        if self._catalog_version is None:
            return None
        return {"catalog_version": self._catalog_version}

    async def health(self) -> ConnectorHealth:
        status = ConnectorStatus.HEALTHY if self._last_success_at else ConnectorStatus.UNAVAILABLE
        return ConnectorHealth(status, last_success_at=self._last_success_at)
