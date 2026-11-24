"""NVD CVE API 2.0 connector with bounded, idempotent ingestion."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.intelligence import FeedRun, Indicator, SourceEvidence

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE_NAME = "NVD CVE"


def fetch_nvd(timeout: int = 30) -> dict:
    now = datetime.now(UTC)
    params = urlencode({
        "lastModStartDate": (now - timedelta(days=7)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "lastModEndDate": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    })
    request = Request(
        f"{API_URL}?{params}",
        headers={"Accept": "application/json", "User-Agent": "ThreatWeave/0.1"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise ValueError(f"NVD API returned HTTP {response.status}")
            payload = json.loads(response.read(25_000_000).decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to retrieve or parse NVD CVE data: {type(exc).__name__}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise TypeError("NVD response did not match the expected schema")
    return payload


def sync_nvd_cves(db: Session, payload: dict | None = None) -> dict:
    run = FeedRun(source_name=SOURCE_NAME, status="running")
    db.add(run)
    db.flush()
    try:
        data = payload if payload is not None else fetch_nvd()
        records = data.get("vulnerabilities")
        if not isinstance(records, list):
            raise TypeError("NVD response has no vulnerabilities array")
        created_indicators = created_evidence = 0
        for wrapper in records:
            if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
                continue
            cve = wrapper["cve"]
            cve_id = cve.get("id")
            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-") or len(cve_id) > 32:
                continue
            description = next((
                item.get("value", "") for item in cve.get("descriptions", [])
                if isinstance(item, dict) and item.get("lang") == "en"
            ), "")
            severity = _severity(cve.get("metrics", {}))
            indicator = db.scalar(select(Indicator).where(
                Indicator.indicator_type == "cve", Indicator.value == cve_id
            ))
            if indicator is None:
                indicator = Indicator(
                    indicator_type="cve", value=cve_id, confidence=90,
                    severity=severity, status="active",
                    description=str(description)[:4000],
                    tags=["nvd", "vulnerability"],
                    first_seen=_parse_timestamp(cve.get("published")),
                    last_seen=_parse_timestamp(cve.get("lastModified")),
                )
                db.add(indicator)
                db.flush()
                created_indicators += 1
            else:
                tags = list(indicator.tags or [])
                if "nvd" not in tags:
                    tags.append("nvd")
                    indicator.tags = tags
                if not indicator.description and description:
                    indicator.description = str(description)[:4000]
                if indicator.severity in {"unknown", "medium"} and severity != "unknown":
                    indicator.severity = severity
            reference = f"NVD:{cve_id}"
            evidence = db.scalar(select(SourceEvidence).where(
                SourceEvidence.indicator_id == indicator.id,
                SourceEvidence.source_name == SOURCE_NAME,
                SourceEvidence.source_reference == reference,
            ))
            if evidence is None:
                db.add(SourceEvidence(
                    indicator_id=indicator.id,
                    source_name=SOURCE_NAME,
                    source_reference=reference,
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    raw_data=cve,
                ))
                created_evidence += 1

        run.status = "succeeded"
        run.records_seen = len(records)
        run.indicators_created = created_indicators
        run.evidence_created = created_evidence
        run.completed_at = datetime.now(UTC)
        db.commit()
        return {
            "run_id": str(run.id),
            "source": SOURCE_NAME,
            "status": run.status,
            "records_seen": run.records_seen,
            "indicators_created": created_indicators,
            "evidence_created": created_evidence,
            "total_results": data.get("totalResults", len(records)),
            "complete_window": data.get("totalResults", len(records)) <= len(records),
        }
    except Exception as exc:
        db.rollback()
        failed = FeedRun(
            source_name=SOURCE_NAME,
            status="failed",
            error_message=f"{type(exc).__name__}: {str(exc)[:500]}",
            completed_at=datetime.now(UTC),
        )
        db.add(failed)
        db.commit()
        raise


def _severity(metrics: object) -> str:
    if not isinstance(metrics, dict):
        return "unknown"
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries and isinstance(entries[0], dict):
            data = entries[0].get("cvssData", {})
            value = data.get("baseSeverity") if isinstance(data, dict) else None
            if isinstance(value, str):
                normalized = value.lower()
                if normalized in {"low", "medium", "high", "critical"}:
                    return normalized
    return "unknown"


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
