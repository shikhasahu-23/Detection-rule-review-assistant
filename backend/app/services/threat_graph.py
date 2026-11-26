"""Bounded STIX 2.1 ingestion for provenance-preserving threat graph data."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.threat_graph import ThreatEntity, ThreatEntityEvidence, ThreatRelationship

ENTITY_TYPES = {
    "threat-actor": "threat_actor",
    "malware": "malware",
    "campaign": "campaign",
    "tool": "tool",
    "infrastructure": "infrastructure",
    "vulnerability": "vulnerability",
}
MAX_STIX_OBJECTS = 5000
MAX_CONFIDENCE = 100


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    except ValueError:
        return None


def _confidence(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return max(0, min(MAX_CONFIDENCE, value))


def _severity(obj: dict[str, Any]) -> str | None:
    """Use explicit source severity, or a vulnerability's explicit CVSS base score."""
    raw = next((obj.get(key) for key in (
        "severity", "x_severity", "x_opencti_severity",
    ) if obj.get(key) is not None), None)
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        aliases = {
            "informational": "low", "info": "low", "minor": "low",
            "moderate": "medium", "med": "medium",
            "severe": "high", "major": "high",
        }
        normalized = aliases.get(normalized, normalized)
        if normalized in {"critical", "high", "medium", "low"}:
            return normalized
    if obj.get("type") == "vulnerability":
        score = obj.get("x_cvss_v3_base_score", obj.get("x_cvss_v2_base_score"))
        if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10:
            return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return None


def _impact(obj: dict[str, Any]) -> str | None:
    """Preserve only an explicit source-provided impact statement."""
    for key in ("impact", "impact_description", "x_impact", "x_opencti_impact"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:4000]
        if isinstance(value, list):
            items = [item.strip() for item in value if isinstance(item, str) and item.strip()]
            if items:
                return "; ".join(items)[:4000]
    return None


def _external_url(obj: dict[str, Any]) -> str | None:
    refs = obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            url = ref["url"]
            if url.startswith(("https://", "http://")):
                return url[:2048]
    return None


def import_stix_bundle(
    db: Session,
    bundle: dict[str, Any],
    *,
    source_name: str,
) -> dict[str, Any]:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError("Expected a STIX 2.1 bundle object")
    if bundle.get("spec_version") not in (None, "2.1"):
        raise ValueError("Only STIX 2.1 bundles are supported")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise ValueError("STIX bundle must contain a non-empty objects array")
    if len(objects) > MAX_STIX_OBJECTS:
        raise ValueError(f"STIX bundle is limited to {MAX_STIX_OBJECTS} objects")
    if not isinstance(source_name, str) or not source_name.strip() or len(source_name) > 100:
        raise ValueError("source_name must contain 1–100 characters")

    created_entities = updated_entities = created_relationships = updated_relationships = 0
    skipped = 0
    stix_to_entity: dict[str, ThreatEntity] = {}
    try:
        for obj in objects:
            if not isinstance(obj, dict):
                skipped += 1
                continue
            stix_type = obj.get("type")
            entity_type = ENTITY_TYPES.get(stix_type)
            stix_id = obj.get("id")
            name = obj.get("name")
            if not entity_type or not isinstance(stix_id, str) or not isinstance(name, str):
                continue
            if not stix_id.startswith(f"{stix_type}--"):
                skipped += 1
                continue
            entity = db.scalar(select(ThreatEntity).where(
                ThreatEntity.entity_type == entity_type,
                ThreatEntity.external_id == stix_id,
            ))
            values = {
                "name": name[:300],
                "description": str(obj.get("description") or "")[:12000],
                "confidence": _confidence(obj.get("confidence")),
                "severity": _severity(obj),
                "impact": _impact(obj),
                "source_name": source_name.strip(),
                "source_reference": stix_id[:512],
                "source_url": _external_url(obj),
                "revoked": bool(obj.get("revoked", False)),
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "first_seen": _timestamp(obj.get("first_seen") or obj.get("created")),
                "last_seen": _timestamp(obj.get("last_seen") or obj.get("modified")),
            }
            if entity is None:
                entity = ThreatEntity(
                    entity_type=entity_type, external_id=stix_id, **values
                )
                db.add(entity)
                created_entities += 1
            else:
                # Preserve canonical source fields; source-specific provenance is
                # recorded separately for every importing feed.
                for key in (
                    "name", "description", "confidence", "severity", "impact", "revoked", "deprecated",
                    "first_seen", "last_seen",
                ):
                    setattr(entity, key, values[key])
                updated_entities += 1
            db.flush()
            entity_evidence = db.scalar(select(ThreatEntityEvidence).where(
                ThreatEntityEvidence.entity_id == entity.id,
                ThreatEntityEvidence.source_name == source_name.strip(),
                ThreatEntityEvidence.source_reference == stix_id[:512],
            ))
            if entity_evidence is None:
                db.add(ThreatEntityEvidence(
                    entity_id=entity.id,
                    source_name=source_name.strip(),
                    source_reference=stix_id[:512],
                    source_url=values["source_url"],
                    confidence=values["confidence"],
                ))
            else:
                entity_evidence.source_url = values["source_url"]
                entity_evidence.confidence = values["confidence"]
            stix_to_entity[stix_id] = entity

        db.flush()
        for obj in objects:
            if not isinstance(obj, dict) or obj.get("type") != "relationship":
                continue
            source_id, target_id = obj.get("source_ref"), obj.get("target_ref")
            relationship_type, stix_id = obj.get("relationship_type"), obj.get("id")
            if (
                not isinstance(source_id, str) or not isinstance(target_id, str)
                or not isinstance(relationship_type, str) or not isinstance(stix_id, str)
                or source_id == target_id
            ):
                skipped += 1
                continue
            source_entity = stix_to_entity.get(source_id) or db.scalar(
                select(ThreatEntity).where(ThreatEntity.external_id == source_id)
            )
            target_entity = stix_to_entity.get(target_id) or db.scalar(
                select(ThreatEntity).where(ThreatEntity.external_id == target_id)
            )
            if source_entity is None or target_entity is None:
                skipped += 1
                continue
            relationship = db.scalar(select(ThreatRelationship).where(
                ThreatRelationship.source_entity_id == source_entity.id,
                ThreatRelationship.target_entity_id == target_entity.id,
                ThreatRelationship.relationship_type == relationship_type[:100],
                ThreatRelationship.source_name == source_name.strip(),
                ThreatRelationship.source_reference == stix_id[:512],
            ))
            values = {
                "confidence": _confidence(obj.get("confidence")),
                "assertion_status": "source_observed",
                "source_url": _external_url(obj),
                "description": str(obj.get("description") or "")[:12000],
                "observed_at": _timestamp(obj.get("modified") or obj.get("created")) or datetime.now(UTC),
            }
            if relationship is None:
                db.add(ThreatRelationship(
                    source_entity_id=source_entity.id,
                    target_entity_id=target_entity.id,
                    relationship_type=relationship_type[:100],
                    source_name=source_name.strip(),
                    source_reference=stix_id[:512],
                    **values,
                ))
                created_relationships += 1
            else:
                for key, value in values.items():
                    setattr(relationship, key, value)
                updated_relationships += 1
        db.commit()
        return {
            "source_name": source_name.strip(),
            "objects_seen": len(objects),
            "entities_created": created_entities,
            "entities_updated": updated_entities,
            "relationships_created": created_relationships,
            "relationships_updated": updated_relationships,
            "objects_skipped": skipped,
            "assertion_status": "source_observed",
        }
    except Exception:
        db.rollback()
        raise
