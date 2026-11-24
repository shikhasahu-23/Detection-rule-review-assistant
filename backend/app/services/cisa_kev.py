"""CISA Known Exploited Vulnerabilities feed connector.

The connector uses a fixed, trusted HTTPS endpoint. Feed content is treated as
untrusted data and is stored as evidence, never executed or interpreted as code.
"""
from __future__ import annotations

import json
from datetime import UTC, date, datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.intelligence import FeedRun, Indicator, SourceEvidence

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCE_NAME = "CISA KEV"


def fetch_feed(timeout: int = 25) -> dict:
    request = Request(FEED_URL, headers={"Accept": "application/json", "User-Agent": "ThreatWeave/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise ValueError(f"CISA feed returned HTTP {response.status}")
            payload = json.loads(response.read(20_000_000).decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to retrieve or parse CISA KEV feed: {type(exc).__name__}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise TypeError("CISA KEV response did not match the expected schema")
    return payload


def sync_cisa_kev(db: Session, payload: dict | None = None) -> dict:
    run = FeedRun(source_name=SOURCE_NAME, status="running")
    db.add(run)
    db.flush()
    try:
        data = payload if payload is not None else fetch_feed()
        records = data.get("vulnerabilities")
        if not isinstance(records, list):
            raise TypeError("Feed has no vulnerabilities array")
        created_indicators = created_evidence = 0
        for item in records:
            if not isinstance(item, dict):
                continue
            cve = item.get("cveID")
            if not isinstance(cve, str) or not cve.startswith("CVE-") or len(cve) > 32:
                continue
            indicator = db.scalar(select(Indicator).where(
                Indicator.indicator_type == "cve", Indicator.value == cve
            ))
            if indicator is None:
                indicator = Indicator(
                    indicator_type="cve", value=cve, confidence=100,
                    severity="high" if item.get("knownRansomwareCampaignUse") == "Known" else "medium",
                    status="active", description=str(item.get("vulnerabilityName", ""))[:4000],
                    tags=["cisa-kev", "known-exploited"],
                    first_seen=_parse_date(item.get("dateAdded")),
                    last_seen=_parse_date(item.get("dateAdded")),
                )
                db.add(indicator)
                db.flush()
                created_indicators += 1
            ref = f"CISA-KEV:{cve}"
            evidence = db.scalar(select(SourceEvidence).where(
                SourceEvidence.indicator_id == indicator.id,
                SourceEvidence.source_name == SOURCE_NAME,
                SourceEvidence.source_reference == ref,
            ))
            if evidence is None:
                db.add(SourceEvidence(
                    indicator_id=indicator.id, source_name=SOURCE_NAME,
                    source_reference=ref, source_url=FEED_URL, raw_data=item,
                ))
                created_evidence += 1
        run.status = "succeeded"
        run.records_seen = len(records)
        run.indicators_created = created_indicators
        run.evidence_created = created_evidence
        run.completed_at = datetime.now(UTC)
        db.commit()
        return {
            "run_id": str(run.id), "source": SOURCE_NAME, "status": run.status,
            "records_seen": run.records_seen, "indicators_created": created_indicators,
            "evidence_created": created_evidence,
        }
    except Exception as exc:
        db.rollback()
        failed = FeedRun(source_name=SOURCE_NAME, status="failed",
                         error_message=f"{type(exc).__name__}: {str(exc)[:500]}",
                         completed_at=datetime.now(timezone.utc))
        db.add(failed)
        db.commit()
        raise


def _parse_date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.combine(date.fromisoformat(value), datetime.min.time(), tzinfo=timezone.utc)
    except ValueError:
        return None
