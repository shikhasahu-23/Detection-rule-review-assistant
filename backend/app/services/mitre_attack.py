"""MITRE ATT&CK Enterprise STIX catalog connector."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.attack import AttackTechnique
from app.models.intelligence import FeedRun

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
SOURCE_NAME = "MITRE ATT&CK Enterprise"


def fetch_attack_bundle(timeout: int = 45) -> dict:
    request = Request(
        ATTACK_URL,
        headers={"Accept": "application/json", "User-Agent": "ThreatWeave/0.1"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise ValueError(f"MITRE ATT&CK feed returned HTTP {response.status}")
            payload = json.loads(response.read(100_000_000).decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to retrieve or parse MITRE ATT&CK data: {type(exc).__name__}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("objects"), list):
        raise TypeError("MITRE ATT&CK bundle did not match the expected STIX schema")
    return payload


def sync_attack_catalog(db: Session, payload: dict | None = None) -> dict:
    run = FeedRun(source_name=SOURCE_NAME, status="running")
    db.add(run)
    db.flush()
    try:
        bundle = payload if payload is not None else fetch_attack_bundle()
        objects = bundle.get("objects")
        if not isinstance(objects, list):
            raise TypeError("MITRE ATT&CK bundle has no objects array")
        seen = created = updated = 0
        for obj in objects:
            if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                # Retain deprecated/revoked entries for historical rule references.
                pass
            external_id = _external_id(obj)
            stix_id = obj.get("id")
            name = obj.get("name")
            if not external_id or not isinstance(stix_id, str) or not isinstance(name, str):
                continue
            tactics = sorted({
                phase.get("phase_name", "").replace("-", " ").title()
                for phase in obj.get("kill_chain_phases", [])
                if isinstance(phase, dict) and phase.get("kill_chain_name") == "mitre-attack"
            })
            platforms = obj.get("x_mitre_platforms", [])
            if not isinstance(platforms, list):
                platforms = []
            technique = db.scalar(select(AttackTechnique).where(
                AttackTechnique.external_id == external_id
            ))
            values = {
                "stix_id": stix_id,
                "name": name[:300],
                "description": str(obj.get("description", ""))[:12000],
                "platforms": [str(item)[:100] for item in platforms[:50]],
                "tactics": tactics[:30],
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                "revoked": bool(obj.get("revoked", False)),
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "source_url": f"https://attack.mitre.org/techniques/{external_id.replace('.', '/')}/",
                "modified_at": _parse_timestamp(obj.get("modified")),
                "synced_at": datetime.now(UTC),
            }
            if technique is None:
                technique = AttackTechnique(external_id=external_id, **values)
                db.add(technique)
                created += 1
            else:
                for key, value in values.items():
                    setattr(technique, key, value)
                updated += 1
            seen += 1

        run.status = "succeeded"
        run.records_seen = seen
        run.indicators_created = created
        run.evidence_created = updated
        run.completed_at = datetime.now(UTC)
        db.commit()
        return {
            "run_id": str(run.id),
            "source": SOURCE_NAME,
            "status": run.status,
            "records_seen": seen,
            "techniques_created": created,
            "techniques_updated": updated,
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


def _external_id(obj: dict) -> str | None:
    references = obj.get("external_references", [])
    if not isinstance(references, list):
        return None
    for reference in references:
        if not isinstance(reference, dict):
            continue
        external_id = reference.get("external_id")
        if (
            reference.get("source_name") == "mitre-attack"
            and isinstance(external_id, str)
            and external_id.startswith("T")
            and len(external_id) <= 16
        ):
            return external_id
    return None


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
