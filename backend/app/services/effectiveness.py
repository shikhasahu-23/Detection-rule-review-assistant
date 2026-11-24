"""Detection coverage and readiness reporting.

Scores are workflow-readiness indicators, not measured detection efficacy.
ATT&CK coverage uses explicit technique IDs supplied on detection intents.
"""
from __future__ import annotations

from collections import Counter

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.attack import AttackTechnique
from app.models.detection import DetectionIntent
from app.models.rule import RuleCandidate
from app.models.testing import DetectionTestRun


def build_detection_effectiveness(db: Session) -> dict:
    techniques = db.scalars(
        select(AttackTechnique).where(
            AttackTechnique.revoked.is_(False),
            AttackTechnique.deprecated.is_(False),
        ).order_by(AttackTechnique.external_id)
    ).all()
    intents = db.scalars(
        select(DetectionIntent).order_by(desc(DetectionIntent.created_at))
    ).all()
    candidates = db.scalars(
        select(RuleCandidate).order_by(desc(RuleCandidate.version), desc(RuleCandidate.created_at))
    ).all()
    runs = db.scalars(
        select(DetectionTestRun).order_by(desc(DetectionTestRun.created_at))
    ).all()

    technique_by_id = {item.external_id.upper(): item for item in techniques}
    mapped: dict[str, list[DetectionIntent]] = {}
    intent_candidate_map: dict[str, list[RuleCandidate]] = {}
    for intent in intents:
        for technique_id in {value.upper() for value in (intent.attack_techniques or [])}:
            if technique_id in technique_by_id:
                mapped.setdefault(technique_id, []).append(intent)
    for candidate in candidates:
        intent_candidate_map.setdefault(str(candidate.intent_id), []).append(candidate)

    latest_run_by_candidate = {}
    for run in runs:
        latest_run_by_candidate.setdefault(str(run.candidate_id), run)

    technique_rows = []
    tactic_counts: Counter[str] = Counter()
    covered_tactics: set[str] = set()
    for technique in techniques:
        linked_intents = mapped.get(technique.external_id.upper(), [])
        covered = bool(linked_intents)
        for tactic in technique.tactics or []:
            tactic_counts[tactic] += 1
            if covered:
                covered_tactics.add(tactic)
        technique_rows.append({
            "technique_id": technique.external_id,
            "name": technique.name,
            "tactics": technique.tactics or [],
            "platforms": technique.platforms or [],
            "covered": covered,
            "linked_intents": [{"id": str(item.id), "title": item.title} for item in linked_intents],
            "source_url": technique.source_url,
        })

    intent_rows = []
    for intent in intents:
        linked_ids = sorted({
            value.upper() for value in (intent.attack_techniques or [])
            if value.upper() in technique_by_id
        })
        intent_candidates = intent_candidate_map.get(str(intent.id), [])
        latest_by_platform = {}
        for candidate in intent_candidates:
            latest_by_platform.setdefault(candidate.platform, candidate)
        current_candidates = list(latest_by_platform.values())

        telemetry_values = []
        validation_values = []
        test_values = []
        platform_rows = []
        for candidate in current_candidates:
            coverage = candidate.validation_report.get("telemetry_coverage", {})
            if coverage.get("score") is not None:
                telemetry_values.append(float(coverage["score"]))
            validation_status = candidate.validation_status
            validation_score = 100 if validation_status == "passed" else 60 if validation_status == "warning" else 0
            validation_values.append(validation_score)
            run = latest_run_by_candidate.get(str(candidate.id))
            test_score = round(run.passed_cases / run.total_cases * 100) if run and run.total_cases else None
            if test_score is not None:
                test_values.append(test_score)
            platform_rows.append({
                "platform": candidate.platform,
                "candidate_id": str(candidate.id),
                "version": candidate.version,
                "validation_status": validation_status,
                "telemetry_coverage": coverage.get("score"),
                "test_status": run.status if run else "not_run",
                "test_score": test_score,
                "regression_status": (run.regression_report or {}).get("status") if run else None,
            })

        mapping_score = 100 if linked_ids else 0
        telemetry_score = round(sum(telemetry_values) / len(telemetry_values)) if telemetry_values else 0
        validation_score = round(sum(validation_values) / len(validation_values)) if validation_values else 0
        testing_score = round(sum(test_values) / len(test_values)) if test_values else 0
        readiness_score = round((mapping_score + telemetry_score + validation_score + testing_score) / 4)
        dimensions = [
            {"name": "ATT&CK mapping", "score": mapping_score, "status": "mapped" if linked_ids else "missing"},
            {"name": "Telemetry coverage", "score": telemetry_score, "status": "assessed" if telemetry_values else "not_assessed"},
            {"name": "Static validation", "score": validation_score, "status": "assessed" if validation_values else "not_assessed"},
            {"name": "Offline tests", "score": testing_score, "status": "tested" if test_values else "not_tested"},
        ]
        intent_rows.append({
            "intent_id": str(intent.id),
            "title": intent.title,
            "severity": intent.severity,
            "status": intent.status,
            "technique_ids": linked_ids,
            "candidate_count": len(intent_candidates),
            "platforms": platform_rows,
            "readiness_score": readiness_score,
            "dimensions": dimensions,
            "readiness_label": "well_covered" if readiness_score >= 80 else "needs_work" if readiness_score >= 40 else "incomplete",
        })

    active_techniques = len(techniques)
    covered_techniques = sum(1 for item in technique_rows if item["covered"])
    coverage_percent = round(covered_techniques / active_techniques * 100) if active_techniques else 0
    tactic_rows = [{
        "tactic": tactic,
        "technique_count": count,
        "covered_count": sum(
            1 for row in technique_rows if tactic in row["tactics"] and row["covered"]
        ),
    } for tactic, count in sorted(tactic_counts.items())]
    for row in tactic_rows:
        row["coverage_percent"] = round(row["covered_count"] / row["technique_count"] * 100) if row["technique_count"] else 0

    return {
        "summary": {
            "active_techniques": active_techniques,
            "covered_techniques": covered_techniques,
            "coverage_gaps": active_techniques - covered_techniques,
            "coverage_percent": coverage_percent,
            "detection_intents": len(intents),
            "intents_with_candidates": sum(1 for row in intent_rows if row["candidate_count"]),
            "average_readiness": round(sum(row["readiness_score"] for row in intent_rows) / len(intent_rows)) if intent_rows else 0,
        },
        "tactics": tactic_rows,
        "techniques": technique_rows,
        "detections": intent_rows,
        "methodology": {
            "readiness_score": "Equal-weight average of explicit ATT&CK mapping, lexical telemetry coverage, static validation status and latest offline query-contract test score.",
            "attck_coverage": "A technique is covered only when its exact ATT&CK ID is explicitly assigned to at least one detection intent. This does not prove behavioral detection.",
            "limitations": [
                "Coverage is limited to the currently synced active Enterprise ATT&CK catalog.",
                "Technique mapping is explicit metadata, not inferred from query semantics.",
                "Telemetry coverage is lexical matching, not schema or data availability verification.",
                "Static validation is not a vendor compiler.",
                "Offline test assertions inspect query text, not live event execution.",
                "Readiness scores are prioritization aids, not true-positive, false-positive or operational effectiveness measurements.",
            ],
        },
    }
