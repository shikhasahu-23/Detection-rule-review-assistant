"""Create and version IOC-focused rules for all active intelligence indicators."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.detection import DetectionIntent
from app.models.intelligence import Indicator
from app.models.rule import RuleCandidate
from app.schemas.detection import TargetPlatform
from app.services.generation import GenerationUnavailable, get_generation_provider
from app.services.platforms import get_platform_contract
from app.services.validation import validate_candidate

SUPPORTED_IOC_TYPES = {"ip", "domain", "url", "hash", "file_hash", "cve"}
IOC_PLATFORMS = [
    TargetPlatform.SPLUNK, TargetPlatform.SENTINEL,
    TargetPlatform.CHRONICLE, TargetPlatform.SIGMA,
]


def sync_ioc_rules(db: Session, *, provider=None, indicator_limit: int = 5000) -> dict:
    """Generate grouped rules and append a version only when the active IOC set changes."""
    active_provider = provider or get_generation_provider()
    indicators = db.scalars(
        select(Indicator).where(Indicator.status == "active")
        .order_by(desc(Indicator.last_seen), desc(Indicator.created_at))
        .limit(indicator_limit)
    ).all()
    groups: dict[str, list[Indicator]] = {}
    for indicator in indicators:
        kind = indicator.indicator_type.lower()
        if kind in SUPPORTED_IOC_TYPES:
            groups.setdefault(kind, []).append(indicator)

    created = skipped = failed = 0
    errors: list[str] = []
    processed: dict[str, dict] = {}
    for kind, rows in groups.items():
        values = sorted({row.value.strip() for row in rows if row.value.strip()})
        if not values:
            continue
        title = f"ThreatWeave Active IOC Coverage: {kind}"
        intent = db.scalar(select(DetectionIntent).where(DetectionIntent.title == title).limit(1))
        evidence = [
            {"kind": kind, "reference": row.value, "source": "Threat Intelligence",
             "confidence": row.confidence, "indicator_id": str(row.id)}
            for row in rows
        ]
        if intent is None:
            intent = DetectionIntent(
                title=title,
                description=f"Automatically maintained detection coverage for active {kind} indicators.",
                behavior=f"Match observed telemetry against the current active {kind} threat-intelligence indicators.",
                severity="high",
                attack_techniques=[],
                required_telemetry=[{"source": "network_and_endpoint", "description": "IOC-bearing event fields", "required_fields": ["indicator_value"]}],
                evidence=evidence,
                test_scenarios=[],
                target_platforms=[item.value for item in IOC_PLATFORMS],
                status="active",
            )
            db.add(intent)
            db.flush()
        else:
            intent.evidence = evidence
            intent.target_platforms = [item.value for item in IOC_PLATFORMS]
            intent.status = "active"

        fingerprint = hashlib.sha256(
            json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode()
        ).hexdigest()
        intent_data = {
            "title": title,
            "description": intent.description,
            "behavior": intent.behavior,
            "severity": intent.severity,
            "attack_techniques": [],
            "required_telemetry": intent.required_telemetry,
            "evidence": evidence,
            "test_scenarios": [],
            "indicator_type": kind,
            "indicator_values": values,
        }
        for platform in IOC_PLATFORMS:
            latest = db.scalar(
                select(RuleCandidate).where(
                    RuleCandidate.intent_id == intent.id,
                    RuleCandidate.platform == platform.value,
                    RuleCandidate.generator == "ioc-intel",
                ).order_by(desc(RuleCandidate.version)).limit(1)
            )
            if latest and latest.generation_metadata.get("ioc_fingerprint") == fingerprint:
                skipped += 1
                continue
            try:
                draft = active_provider.generate(intent_data, platform)
                report = validate_candidate(platform, draft.query, intent_data)
                version = db.scalar(select(func.max(RuleCandidate.version)).where(
                    RuleCandidate.intent_id == intent.id,
                    RuleCandidate.platform == platform.value,
                )) or 0
                db.add(RuleCandidate(
                    intent_id=intent.id,
                    name=draft.name,
                    platform=platform.value,
                    query=draft.query,
                    version=version + 1,
                    status="candidate",
                    validation_status=report["status"],
                    validation_report=report,
                    generation_metadata={
                        "provider": getattr(active_provider, "provider_name", "free-template"),
                        "model": getattr(active_provider, "model", "deterministic-v2"),
                        "prompt_version": get_platform_contract(platform).prompt_version,
                        "generated_at": datetime.now(UTC).isoformat(),
                        "validation_scope": get_platform_contract(platform).validation_scope,
                        "rule_family": "active_ioc_coverage",
                        "indicator_type": kind,
                        "indicator_count": len(values),
                        "ioc_fingerprint": fingerprint,
                        "previous_version": latest.version if latest else None,
                        "version_reason": "active IOC set changed" if latest else "initial active IOC coverage",
                        "is_deployable": False,
                    },
                    generator="ioc-intel",
                ))
                db.commit()
                created += 1
            except GenerationUnavailable as exc:
                db.rollback()
                failed += 1
                errors.append(f"{kind}/{platform.value}: {str(exc)[:250]}")
            except Exception as exc:  # noqa: BLE001 - isolate platform/type failures
                db.rollback()
                failed += 1
                errors.append(f"{kind}/{platform.value}: {type(exc).__name__}: {str(exc)[:250]}")
        processed[kind] = {"active_indicators": len(values)}
    return {
        "status": "partial" if failed else "succeeded",
        "indicator_types_processed": processed,
        "rule_versions_created": created,
        "unchanged_platform_rules_skipped": skipped,
        "generation_failures": failed,
        "errors": errors[:50],
        "indicator_limit": indicator_limit,
        "note": "IOC coverage rules are versioned drafts; deployment is never automatic.",
    }
