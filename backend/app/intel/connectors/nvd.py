from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

import httpx

from app.intel.connectors.base import ConnectorHealth, ConnectorStatus, IntelConnector
from app.intel.schemas import IndicatorType, IntelEvidenceInput, IntelIndicatorInput

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdConnector(IntelConnector):
    """Fetch NVD CVE records using the paginated CVE API 2.0."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._api_key: str | None = None
        self._results_per_page = 2000
        self._start_index = 0
        self._total_results: int | None = None
        self._completed = False
        self._last_success_at: str | None = None

    async def configure(self, config: Mapping[str, Any]) -> None:
        allowed = {"api_key", "results_per_page"}
        unknown = set(config) - allowed
        if unknown:
            raise ValueError(f"Unsupported NVD configuration keys: {', '.join(sorted(unknown))}")
        api_key = config.get("api_key")
        if api_key is not None and not isinstance(api_key, str):
            raise TypeError("NVD api_key must be a string")
        page_size = config.get("results_per_page", 2000)
        if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= 2000:
            raise ValueError("NVD results_per_page must be between 1 and 2000")
        self._api_key = api_key
        self._results_per_page = page_size

    async def _get_json(self, params: dict[str, Any]) -> dict[str, Any]:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        if self._client is not None:
            response = await self._client.get(NVD_API_URL, params=params, headers=headers)
            response.raise_for_status()
            return response.json()
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(NVD_API_URL, params=params, headers=headers)
            response.raise_for_status()
            return response.json()

    async def fetch(
        self,
        checkpoint: Mapping[str, str] | None = None,
    ) -> AsyncIterator[Mapping[str, Any]]:
        start_index = 0
        if checkpoint and checkpoint.get("start_index", "").isdigit():
            start_index = int(checkpoint["start_index"])
        self._start_index = start_index
        self._completed = False
        while True:
            payload = await self._get_json(
                {"startIndex": start_index, "resultsPerPage": self._results_per_page}
            )
            vulnerabilities = payload.get("vulnerabilities")
            total_results = payload.get("totalResults")
            if not isinstance(vulnerabilities, list) or not isinstance(total_results, int):
                raise TypeError("NVD response is missing pagination metadata or vulnerabilities")
            self._total_results = total_results
            self._last_success_at = datetime.now(UTC).isoformat()
            for item in vulnerabilities:
                if isinstance(item, dict):
                    yield item
            start_index += len(vulnerabilities)
            self._start_index = start_index
            if not vulnerabilities or start_index >= total_results:
                self._completed = True
                break

    def parse(self, raw_record: Mapping[str, Any]) -> list[IntelIndicatorInput]:
        cve = raw_record.get("cve")
        if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
            return []
        cve_id = cve["id"]
        published = cve.get("published")
        last_modified = cve.get("lastModified")
        try:
            observed_at = datetime.fromisoformat(published) if isinstance(published, str) else None
        except ValueError:
            observed_at = None
        try:
            modified_at = datetime.fromisoformat(last_modified) if isinstance(last_modified, str) else None
        except ValueError:
            modified_at = None
        payload = dict(raw_record)
        return [
            IntelIndicatorInput(
                indicator_type=IndicatorType.CVE,
                value=cve_id,
                first_seen_at=observed_at,
                last_seen_at=modified_at,
                evidence=[
                    IntelEvidenceInput(
                        source_name="NVD",
                        source_reference=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        observed_at=observed_at,
                        payload_hash=sha256(repr(sorted(payload.items())).encode()).hexdigest(),
                        raw_payload=payload,
                    )
                ],
            )
        ]

    def get_checkpoint(self) -> Mapping[str, str] | None:
        if self._total_results is None:
            return None
        # A completed catalog sweep must restart at zero on the next run so newly
        # published/modified CVEs are not skipped. Mid-run positions remain resumable.
        start_index = 0 if self._completed else self._start_index
        return {"start_index": str(start_index), "total_results": str(self._total_results)}

    async def health(self) -> ConnectorHealth:
        status = ConnectorStatus.HEALTHY if self._last_success_at else ConnectorStatus.UNAVAILABLE
        return ConnectorHealth(status, last_success_at=self._last_success_at)
