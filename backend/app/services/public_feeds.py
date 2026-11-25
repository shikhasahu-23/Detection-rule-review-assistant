"""Public, no-key IOC feeds from abuse.ch (URLhaus and Feodo Tracker).

Feed values are treated as untrusted indicators. ThreatWeave stores them as evidence;
it never visits, resolves, or executes an indicator URL.
"""
from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.intelligence import FeedRun, Indicator, SourceEvidence

FEEDS = {
    "urlhaus": {
        "name": "URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "type": "url",
        "confidence": 95,
        "severity": "high",
        "tags": ["urlhaus", "malware-distribution"],
    },
    "feodo": {
        "name": "Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "ip",
        "confidence": 95,
        "severity": "high",
        "tags": ["feodo-tracker", "botnet-c2"],
    },
}


def fetch_text(url: str, timeout: int = 25) -> str:
    request = Request(url, headers={"Accept": "text/plain", "User-Agent": "ThreatWeave/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise ValueError(f"Feed returned HTTP {response.status}")
            return response.read(15_000_000).decode("utf-8")
    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError) as exc:
        raise ValueError(f"Unable to retrieve feed: {type(exc).__name__}") from exc


def _valid_value(kind: str, value: str) -> str | None:
    item = value.strip()
    if not item or len(item) > 2048 or item.startswith("#"):
        return None
    if kind == "ip":
        try:
            return ipaddress.ip_address(item).compressed
        except ValueError:
            return None
    parsed = urlsplit(item)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return item


def sync_public_feed(db: Session, feed_key: str, text_payload: str | None = None) -> dict:
    if feed_key not in FEEDS:
        raise ValueError("Unsupported public feed")
    config = FEEDS[feed_key]
    run = FeedRun(source_name=config["name"], status="running")
    db.add(run)
    db.flush()
    try:
        payload = text_payload if text_payload is not None else fetch_text(config["url"])
        if not isinstance(payload, str) or not payload.strip():
            raise TypeError("Feed response was empty or invalid")
        seen = created_indicators = created_evidence = rejected = 0
        for line in payload.splitlines():
            value = _valid_value(config["type"], line)
            if value is None:
                continue
            seen += 1
            indicator = db.scalar(select(Indicator).where(
                Indicator.indicator_type == config["type"], Indicator.value == value
            ))
            if indicator is None:
                indicator = Indicator(
                    indicator_type=config["type"], value=value,
                    confidence=config["confidence"], severity=config["severity"],
                    status="active", tags=list(config["tags"]),
                    description=f"Indicator sourced from {config['name']}",
                    first_seen=datetime.now(UTC), last_seen=datetime.now(UTC),
                )
                db.add(indicator)
                db.flush()
                created_indicators += 1
            else:
                tags = list(indicator.tags or [])
                for tag in config["tags"]:
                    if tag not in tags:
                        tags.append(tag)
                indicator.tags = tags
                indicator.last_seen = datetime.now(UTC)
            reference = f"{feed_key.upper()}:{value}"
            evidence = db.scalar(select(SourceEvidence).where(
                SourceEvidence.indicator_id == indicator.id,
                SourceEvidence.source_name == config["name"],
                SourceEvidence.source_reference == reference,
            ))
            if evidence is None:
                db.add(SourceEvidence(
                    indicator_id=indicator.id, source_name=config["name"],
                    source_reference=reference, source_url=config["url"],
                    raw_data={"indicator_type": config["type"], "value": value,
                              "feed": config["name"]},
                ))
                created_evidence += 1
        if seen == 0:
            raise TypeError("Feed contained no valid indicators")
        run.status = "succeeded"
        run.records_seen = seen
        run.indicators_created = created_indicators
        run.evidence_created = created_evidence
        run.completed_at = datetime.now(UTC)
        db.commit()
        return {"run_id": str(run.id), "source": config["name"], "status": run.status,
                "records_seen": seen, "indicators_created": created_indicators,
                "evidence_created": created_evidence, "rejected_count": rejected}
    except Exception as exc:
        db.rollback()
        db.add(FeedRun(source_name=config["name"], status="failed",
                       error_message=f"{type(exc).__name__}: {str(exc)[:500]}",
                       completed_at=datetime.now(UTC)))
        db.commit()
        raise
