"""Create and version IOC-focused rules for all active intelligence indicators."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.models.detection import DetectionIntent
from app.models.intelligence import Indicator
from app.models.rule import RuleCandidate
from app.schemas.detection import TargetPlatform
from app.services.generation import GenerationUnavailable, get_generation_provider
from app.services.platforms import get_platform_contract
from app.services.validation import validate_candidate

SUPPORTED_IOC_TYPES = {"ip", "ipv4", "ipv6", "domain", "hostname", "url", "hash", "file_hash", "cve"}
IOC_PLATFORMS = [
    TargetPlatform.SPLUNK,
    TargetPlatform.SENTINEL,
    TargetPlatform.CHRONICLE,
    TargetPlatform.SIGMA,
]
IOC_CHUNK_SIZE = 100


def _sync_chunk(db: Session, provider, kind: str, values: list[str], rows: list[Indicator], chunk_number: int) -> tuple[int, int, int, list[str]]:
    title = f"ThreatWeave Active IOC Coverage: {kind}:{chunk_number:04d}"
    intent = db.scalar(select(DetectionIntent).where(DetectionIntent.title == title).limit(1))
    evidence = [
        {
            "kind": kind,
            "reference": row.value,
            "source": "Threat Intelligence",
            "confidence": row.confidence,
            "indicator_id": str(row.id),
        }
        for row in rows
        if row.value.strip() in set(values)
    ]
    if intent is None:
        intent = DetectionIntent(
            title=title,
            description=f"Automatically maintained detection coverage for active {kind} indicators, batch {chunk_number}.",
            behavior=f"Match observed telemetry against the current active {kind} threat-intelligence indicators.",
            severity="high",
            attack_techniques=[],
            required_telemetry=[{
                "source": "network_and_endpoint",
                "description": "IOC-bearing event fields",
                "required_fields": ["indicator_value"],
            }],
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
    db.commit()

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

    created = skipped = failed = 0
    errors: list[str] = []
    for platform in IOC_PLATFORMS:
        latest = db.scalar(
            select(RuleCandidate)
            .where(
                RuleCandidate.intent_id == intent.id,
                RuleCandidate.platform == platform.value,
                RuleCandidate.generator == "ioc-intel",
            )
            .order_by(desc(RuleCandidate.version))
            .limit(1)
        )
        if latest and latest.generation_metadata.get("ioc_fingerprint") == fingerprint:
            skipped += 1
            continue
        try:
            draft = provider.generate(intent_data, platform)
            report = validate_candidate(platform, draft.query, intent_data)
            version = db.scalar(
                select(func.max(RuleCandidate.version)).where(
                    RuleCandidate.intent_id == intent.id,
                    RuleCandidate.platform == platform.value,
                )
            ) or 0
            if latest is not None:
                latest.status = "superseded"
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
                    "provider": getattr(provider, "provider_name", "free-template"),
                    "model": getattr(provider, "model", "deterministic-v2"),
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
            errors.append(f"{kind}/{chunk_number}/{platform.value}: {str(exc)[:250]}")
        except Exception as exc:  # noqa: BLE001 - isolate platform/type failures
            db.rollback()
            failed += 1
            errors.append(f"{kind}/{chunk_number}/{platform.value}: {type(exc).__name__}: {str(exc)[:250]}")
    return created, skipped, failed, errors


def sync_ioc_rules(db: Session, *, provider=None, indicator_limit: int = 50000) -> dict:
    """Generate grouped, bounded-size rules and append a version only when an IOC batch changes."""
    active_provider = provider or get_generation_provider()
    indicators = db.scalars(
        select(Indicator)
        .where(
            Indicator.status == "active",
            or_(Indicator.expires_at.is_(None), Indicator.expires_at > datetime.now(UTC)),
        )
        .order_by(desc(Indicator.last_seen), desc(Indicator.created_at))
        .limit(indicator_limit)
    ).all()

    groups: dict[str, list[Indicator]] = {}
    for indicator in indicators:
        kind = indicator.indicator_type.lower()
        if kind in SUPPORTED_IOC_TYPES and indicator.value.strip():
            groups.setdefault(kind, []).append(indicator)

    created = skipped = failed = 0
    errors: list[str] = []
    processed: dict[str, dict] = {}
    active_chunks: set[str] = set()

    for kind, rows in groups.items():
        values = sorted({row.value.strip() for row in rows})
        chunk_count = 0
        for offset in range(0, len(values), IOC_CHUNK_SIZE):
            chunk_count += 1
            chunk_values = values[offset:offset + IOC_CHUNK_SIZE]
            chunk_key = f"{kind}:{chunk_count:04d}"
            active_chunks.add(chunk_key)
            new_count, skip_count, fail_count, chunk_errors = _sync_chunk(
                db, active_provider, kind, chunk_values, rows, chunk_count
            )
            created += new_count
            skipped += skip_count
            failed += fail_count
            errors.extend(chunk_errors)
        processed[kind] = {"active_indicators": len(values), "rule_batches": chunk_count}

    # Mark old batches stale when their indicators expire or disappear from the active set.
    stale_intents = db.scalars(
        select(DetectionIntent).where(
            DetectionIntent.title.like("ThreatWeave Active IOC Coverage:%"),
            DetectionIntent.status == "active",
        )
    ).all()
    for stale_intent in stale_intents:
        chunk_key = stale_intent.title.split(":", 1)[1].strip()
        if chunk_key not in active_chunks:
            stale_intent.status = "inactive"
            old_rules = db.scalars(
                select(RuleCandidate).where(
                    RuleCandidate.intent_id == stale_intent.id,
                    RuleCandidate.generator == "ioc-intel",
                    RuleCandidate.status == "candidate",
                )
            ).all()
            for old_rule in old_rules:
                old_rule.status = "stale"
    db.commit()

    return {
        "status": "partial" if failed else "succeeded",
        "indicator_types_processed": processed,
        "rule_versions_created": created,
        "unchanged_platform_rules_skipped": skipped,
        "generation_failures": failed,
        "errors": errors[:50],
        "indicator_limit": indicator_limit,
        "batch_size": IOC_CHUNK_SIZE,
        "note": "IOC coverage rules are versioned drafts; deployment is never automatic.",
    }
