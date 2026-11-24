"""Validated CSV ingestion for user-supplied indicator records."""
from __future__ import annotations

import csv
import ipaddress
import re
from datetime import UTC, datetime
from io import StringIO
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.intelligence import FeedRun, Indicator, SourceEvidence

REQUIRED_COLUMNS = {"indicator_type", "value"}
ALLOWED_TYPES = {"ip", "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "hash", "email", "cve"}
ALLOWED_SEVERITIES = {"unknown", "low", "medium", "high", "critical"}
ALLOWED_STATUSES = {"active", "inactive", "expired"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def sync_custom_csv(db: Session, csv_text: str) -> dict:
    run = FeedRun(source_name="Custom CSV", status="running")
    db.add(run)
    db.flush()
    try:
        reader = csv.DictReader(StringIO(csv_text))
        headers = {str(header).strip().lower() for header in (reader.fieldnames or [])}
        if not REQUIRED_COLUMNS.issubset(headers):
            raise ValueError("CSV must include indicator_type and value columns")
        records_seen = created_indicators = created_evidence = rejected = 0
        diagnostics: list[dict[str, object]] = []
        for row_number, raw in enumerate(reader, start=2):
            records_seen += 1
            if records_seen > 5000:
                raise ValueError("CSV exceeds the 5,000-row import limit")
            row = {str(key).strip().lower(): (value or "").strip() for key, value in raw.items() if key}
            try:
                indicator_type, value = _normalize(row.get("indicator_type", ""), row.get("value", ""))
                confidence = _int_range(row.get("confidence", "50"), 0, 100, "confidence")
                severity = (row.get("severity") or "unknown").lower()
                status = (row.get("status") or "active").lower()
                if severity not in ALLOWED_SEVERITIES:
                    raise ValueError("severity must be unknown, low, medium, high or critical")
                if status not in ALLOWED_STATUSES:
                    raise ValueError("status must be active, inactive or expired")
                source_name = (row.get("source_name") or "Custom CSV")[:100]
                source_reference = (row.get("source_reference") or f"CSV-row-{row_number}")[:512]
                source_url = _safe_source_url(row.get("source_url", ""))
                indicator = db.scalar(select(Indicator).where(
                    Indicator.indicator_type == indicator_type, Indicator.value == value
                ))
                if indicator is None:
                    indicator = Indicator(
                        indicator_type=indicator_type,
                        value=value,
                        confidence=confidence,
                        severity=severity,
                        status=status,
                        description=(row.get("description") or "")[:4000] or None,
                        tags=_tags(row.get("tags", "")),
                    )
                    db.add(indicator)
                    db.flush()
                    created_indicators += 1
                else:
                    tags = list(indicator.tags or [])
                    for tag in _tags(row.get("tags", "")):
                        if tag not in tags:
                            tags.append(tag)
                    indicator.tags = tags
                evidence = db.scalar(select(SourceEvidence).where(
                    SourceEvidence.indicator_id == indicator.id,
                    SourceEvidence.source_name == source_name,
                    SourceEvidence.source_reference == source_reference,
                ))
                if evidence is None:
                    db.add(SourceEvidence(
                        indicator_id=indicator.id,
                        source_name=source_name,
                        source_reference=source_reference,
                        source_url=source_url,
                        raw_data={
                            "indicator_type": indicator_type,
                            "value": value,
                            "confidence": confidence,
                            "severity": severity,
                            "status": status,
                            "description": (row.get("description") or "")[:4000],
                            "tags": _tags(row.get("tags", "")),
                        },
                    ))
                    created_evidence += 1
            except ValueError as exc:
                rejected += 1
                if len(diagnostics) < 100:
                    diagnostics.append({"row": row_number, "reason": str(exc)})

        run.status = "succeeded" if rejected == 0 else "partial"
        run.records_seen = records_seen
        run.indicators_created = created_indicators
        run.evidence_created = created_evidence
        run.completed_at = datetime.now(UTC)
        db.commit()
        return {
            "run_id": str(run.id),
            "source": "Custom CSV",
            "status": run.status,
            "records_seen": records_seen,
            "indicators_created": created_indicators,
            "evidence_created": created_evidence,
            "rejected_count": rejected,
            "rejections": diagnostics,
        }
    except Exception as exc:
        db.rollback()
        failed = FeedRun(
            source_name="Custom CSV",
            status="failed",
            error_message=f"{type(exc).__name__}: {str(exc)[:500]}",
            completed_at=datetime.now(UTC),
        )
        db.add(failed)
        db.commit()
        raise


def _normalize(indicator_type: str, value: str) -> tuple[str, str]:
    kind = indicator_type.strip().lower()
    item = value.strip()
    if kind not in ALLOWED_TYPES:
        raise ValueError("unsupported indicator_type")
    if not item or len(item) > 2048 or any(ord(char) < 32 for char in item):
        raise ValueError("value is empty, too long or contains control characters")
    if kind in {"ip", "ipv4", "ipv6"}:
        address = ipaddress.ip_address(item)
        if kind == "ipv4" and address.version != 4 or kind == "ipv6" and address.version != 6:
            raise ValueError("IP address does not match indicator_type")
        return "ip", address.compressed
    if kind == "domain":
        normalized = item.rstrip(".").lower()
        if not DOMAIN_RE.fullmatch(normalized):
            raise ValueError("invalid domain value")
        return kind, normalized
    if kind == "url":
        parsed = urlsplit(item)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL indicators must use http or https and include a host")
        return kind, item
    if kind in {"md5", "sha1", "sha256", "hash"}:
        if not re.fullmatch(r"[a-fA-F0-9]+", item):
            raise ValueError("hash must contain hexadecimal characters only")
        expected = {"md5": 32, "sha1": 40, "sha256": 64}
        if kind in expected and len(item) != expected[kind]:
            raise ValueError(f"{kind} must be {expected[kind]} hexadecimal characters")
        if kind == "hash":
            inferred = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(item))
            if inferred is None:
                raise ValueError("hash length must match MD5, SHA-1 or SHA-256")
            kind = inferred
        return kind, item.lower()
    if kind == "email":
        if not EMAIL_RE.fullmatch(item):
            raise ValueError("invalid email indicator")
        return kind, item.lower()
    if kind == "cve":
        if not CVE_RE.fullmatch(item):
            raise ValueError("invalid CVE identifier")
        return kind, item.upper()
    return kind, item


def _int_range(value: str, minimum: int, maximum: int, field: str) -> int:
    try:
        number = int(value) if value else 50
    except ValueError as exc:
        raise ValueError(f"{field} must be an integer") from exc
    if not minimum <= number <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}")
    return number


def _tags(value: str) -> list[str]:
    return list(dict.fromkeys(tag.strip()[:80] for tag in re.split(r"[,;]", value) if tag.strip()))[:50]


def _safe_source_url(value: str) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("source_url must be an absolute http or https URL")
    return value[:2048]
