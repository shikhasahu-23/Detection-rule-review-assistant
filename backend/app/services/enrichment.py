"""Evidence-led enrichment and correlation for detection opportunities."""
from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.attack import AttackTechnique
from app.models.detection import DetectionIntent
from app.models.intelligence import Indicator, SourceEvidence

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from _strings(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            yield from _strings(nested)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _structured_references(value: object) -> tuple[set[str], set[str]]:
    attack_ids: set[str] = set()
    cves: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized_key = str(key).lower()
            if isinstance(nested, str):
                if "technique" in normalized_key or normalized_key in {"attack_id", "attack_ids", "mitre_id", "external_id"}:
                    attack_ids.update(item.upper() for item in ATTACK_ID_RE.findall(nested))
                if normalized_key in {"cve", "cve_id", "cveid", "cve_ids", "id", "reference", "references"}:
                    cves.update(item.upper() for item in CVE_RE.findall(nested))
            else:
                nested_attack, nested_cves = _structured_references(nested)
                attack_ids.update(nested_attack)
                cves.update(nested_cves)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            nested_attack, nested_cves = _structured_references(nested)
            attack_ids.update(nested_attack)
            cves.update(nested_cves)
    return attack_ids, cves


def _evidence_context(evidence: list[SourceEvidence]) -> tuple[set[str], set[str]]:
    attack_ids: set[str] = set()
    cves: set[str] = set()
    for row in evidence:
        structured_attack, structured_cves = _structured_references(row.raw_data)
        attack_ids.update(structured_attack)
        cves.update(structured_cves)
        attack_ids.update(item.upper() for item in ATTACK_ID_RE.findall(row.source_reference or ""))
        cves.update(item.upper() for item in CVE_RE.findall(row.source_reference or ""))
    return attack_ids, cves


def enrich_indicator(db: Session, indicator_id: UUID) -> dict | None:
    indicator = db.get(Indicator, indicator_id)
    if indicator is None:
        return None

    evidence = db.scalars(
        select(SourceEvidence).where(SourceEvidence.indicator_id == indicator.id)
        .order_by(desc(SourceEvidence.observed_at))
    ).all()
    attack_ids, cves = _evidence_context(evidence)
    for value in (indicator.value, *(indicator.tags or [])):
        attack_ids.update(item.upper() for item in ATTACK_ID_RE.findall(value))
        cves.update(item.upper() for item in CVE_RE.findall(value))
    if indicator.indicator_type == "cve":
        cves.add(indicator.value.upper())

    techniques = []
    if attack_ids:
        rows = db.scalars(select(AttackTechnique).where(AttackTechnique.external_id.in_(attack_ids))).all()
        techniques = [{
            "external_id": row.external_id, "name": row.name,
            "tactics": row.tactics, "platforms": row.platforms,
            "source_url": row.source_url,
            "catalog_status": "revoked" if row.revoked else "deprecated" if row.deprecated else "active",
        } for row in rows]

    intents = db.scalars(select(DetectionIntent).order_by(desc(DetectionIntent.created_at))).all()
    matched_intents = []
    for intent in intents:
        intent_attack_ids = {value.upper() for value in (intent.attack_techniques or [])}
        intent_evidence_attack_ids, intent_evidence_cves = _structured_references(intent.evidence)
        intent_attack_ids.update(intent_evidence_attack_ids)
        matched_techniques = sorted(intent_attack_ids & attack_ids)
        intent_evidence_cves.update(item.upper() for item in _strings(intent.evidence) if CVE_RE.fullmatch(item.strip()))
        matched_cves = sorted(cves & intent_evidence_cves)
        if matched_techniques or matched_cves:
            reasons = []
            if matched_techniques:
                reasons.append("Exact ATT&CK technique ID is present in both intelligence evidence and detection intent")
            if matched_cves:
                reasons.append("Exact CVE identifier is present in both intelligence evidence and detection intent evidence")
            matched_intents.append({
                "intent_id": str(intent.id), "title": intent.title,
                "severity": intent.severity, "status": intent.status,
                "target_platforms": intent.target_platforms,
                "matched_techniques": matched_techniques,
                "matched_cves": matched_cves,
                "association_type": "explicit_reference",
                "rationale": reasons,
            })

    observed_at = indicator.last_seen or indicator.first_seen or indicator.created_at
    age_days = max(0, (datetime.now(UTC) - _utc(observed_at)).days) if observed_at else None
    freshness = "unknown" if age_days is None else "fresh" if age_days <= 7 else "aging" if age_days <= 30 else "stale"
    return {
        "indicator_id": str(indicator.id),
        "indicator_type": indicator.indicator_type,
        "value": indicator.value,
        "status": indicator.status,
        "confidence": indicator.confidence,
        "severity": indicator.severity,
        "freshness": freshness,
        "age_days": age_days,
        "evidence_count": len(evidence),
        "sources": sorted({row.source_name for row in evidence}),
        "attack_techniques": techniques,
        "detection_intents": matched_intents,
        "correlation_method": "exact references only; no inferred actor, malware, or campaign attribution",
    }


def detection_opportunities(db: Session, limit: int = 100) -> list[dict]:
    indicators = db.scalars(
        select(Indicator).where(Indicator.status == "active")
        .order_by(desc(Indicator.created_at)).limit(5000)
    ).all()
    opportunities: dict[str, dict] = {}
    for indicator in indicators:
        result = enrich_indicator(db, indicator.id)
        if result is None:
            continue
        for match in result["detection_intents"]:
            key = match["intent_id"]
            item = opportunities.setdefault(key, {
                "intent_id": key, "title": match["title"], "severity": match["severity"],
                "status": match["status"], "target_platforms": match["target_platforms"],
                "association_type": "explicit_reference", "indicators": [],
                "matched_techniques": set(), "matched_cves": set(),
            })
            item["indicators"].append({
                "indicator_id": result["indicator_id"], "indicator_type": result["indicator_type"],
                "value": result["value"], "confidence": result["confidence"],
                "severity": result["severity"], "freshness": result["freshness"],
                "evidence_count": result["evidence_count"],
            })
            item["matched_techniques"].update(match["matched_techniques"])
            item["matched_cves"].update(match["matched_cves"])

    output = []
    for item in opportunities.values():
        item["matched_techniques"] = sorted(item["matched_techniques"])
        item["matched_cves"] = sorted(item["matched_cves"])
        item["indicator_count"] = len(item["indicators"])
        item["evidence_count"] = sum(row["evidence_count"] for row in item["indicators"])
        item["rationale"] = "Correlated through exact ATT&CK technique or CVE references shared with the detection intent."
        output.append(item)
    output.sort(key=lambda item: (-item["indicator_count"], item["title"].lower()))
    return output[:limit]
