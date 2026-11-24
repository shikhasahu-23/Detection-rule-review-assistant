"""Orchestrate feed ingestion, enrichment, correlation and safe candidate generation."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Callable
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.detection import DetectionIntent
from app.models.intelligence import Indicator
from app.models.pipeline import PipelineRun
from app.models.rule import RuleCandidate
from app.schemas.detection import TargetPlatform
from app.services.cisa_kev import sync_cisa_kev
from app.services.enrichment import detection_opportunities, enrich_indicator
from app.services.generation import GenerationProvider, GenerationUnavailable, get_generation_provider
from app.services.mitre_attack import sync_attack_catalog
from app.services.nvd import sync_nvd_cves
from app.services.validation import validate_candidate

FeedSyncer = Callable[[Session], dict]


def _intent_payload(intent: DetectionIntent) -> dict:
    return {
        "title": intent.title,
        "description": intent.description,
        "behavior": intent.behavior,
        "severity": intent.severity,
        "attack_techniques": intent.attack_techniques,
        "required_telemetry": intent.required_telemetry,
        "evidence": intent.evidence,
        "test_scenarios": intent.test_scenarios,
    }


def run_intelligence_pipeline(
    db: Session,
    *,
    trigger: str = "scheduled",
    feed_syncers: dict[str, FeedSyncer] | None = None,
    provider: GenerationProvider | None = None,
    enrich_limit: int = 1000,
) -> dict:
    """Run all stages; individual feed/provider failures are recorded without hiding partial work."""
    run = PipelineRun(status="running", trigger=trigger[:32], stage_results={})
    db.add(run)
    db.commit()
    db.refresh(run)

    syncers = feed_syncers if feed_syncers is not None else {
        "cisa_kev": sync_cisa_kev,
        "nvd_cves": sync_nvd_cves,
        "mitre_attack": sync_attack_catalog,
    }
    stage_results: dict = {}
    failures: list[str] = []

    if not syncers:
        stage_results["feed_ingestion"] = {
            "status": "skipped",
            "reason": "Feed sync jobs run independently before the scheduled enrichment pipeline.",
        }

    for name, syncer in syncers.items():
        try:
            stage_results[name] = {"status": "succeeded", "result": syncer(db)}
        except Exception as exc:
            db.rollback()
            message = f"{type(exc).__name__}: {str(exc)[:400]}"
            stage_results[name] = {"status": "failed", "error": message}
            failures.append(f"{name}: {message}")

    try:
        indicators = db.scalars(
            select(Indicator).where(Indicator.status == "active")
            .order_by(desc(Indicator.created_at)).limit(enrich_limit)
        ).all()
        enriched = 0
        for indicator in indicators:
            if enrich_indicator(db, indicator.id) is not None:
                enriched += 1
        db.commit()
        run.indicators_enriched = enriched
        stage_results["enrichment"] = {
            "status": "succeeded", "indicators_processed": enriched,
            "limit": enrich_limit,
        }
    except Exception as exc:
        db.rollback()
        message = f"{type(exc).__name__}: {str(exc)[:400]}"
        stage_results["enrichment"] = {"status": "failed", "error": message}
        failures.append(f"enrichment: {message}")

    opportunities: list[dict] = []
    try:
        opportunities = detection_opportunities(db, limit=500)
        run.opportunities_found = len(opportunities)
        stage_results["correlation"] = {
            "status": "succeeded", "opportunities_found": len(opportunities),
            "method": "exact ATT&CK technique and CVE references only",
        }
    except Exception as exc:
        db.rollback()
        message = f"{type(exc).__name__}: {str(exc)[:400]}"
        stage_results["correlation"] = {"status": "failed", "error": message}
        failures.append(f"correlation: {message}")

    created = skipped = 0
    generation_errors: list[str] = []
    try:
        active_provider = provider or get_generation_provider()
        for opportunity in opportunities:
            try:
                intent_id = UUID(opportunity["intent_id"])
            except (KeyError, ValueError, TypeError):
                skipped += 1
                continue
            intent = db.get(DetectionIntent, intent_id)
            if intent is None:
                skipped += 1
                continue
            for platform_value in intent.target_platforms:
                try:
                    platform = TargetPlatform(platform_value)
                except ValueError:
                    skipped += 1
                    continue
                existing = db.scalar(select(RuleCandidate.id).where(
                    RuleCandidate.intent_id == intent.id,
                    RuleCandidate.platform == platform.value,
                    RuleCandidate.generator == "pipeline",
                ).limit(1))
                if existing is not None:
                    skipped += 1
                    continue
                try:
                    draft = active_provider.generate(_intent_payload(intent), platform)
                    version = db.scalar(select(func.max(RuleCandidate.version)).where(
                        RuleCandidate.intent_id == intent.id,
                        RuleCandidate.platform == platform.value,
                    )) or 0
                    report = validate_candidate(platform, draft.query)
                    db.add(RuleCandidate(
                        intent_id=intent.id,
                        name=draft.name,
                        platform=platform.value,
                        query=draft.query,
                        version=version + 1,
                        status="candidate",
                        validation_status=report["status"],
                        validation_report=report,
                        generator="pipeline",
                    ))
                    db.flush()
                    created += 1
                except GenerationUnavailable as exc:
                    generation_errors.append(f"{intent.id}/{platform.value}: {str(exc)[:300]}")
                except Exception as exc:
                    db.rollback()
                    generation_errors.append(
                        f"{intent.id}/{platform.value}: {type(exc).__name__}: {str(exc)[:300]}"
                    )
        db.commit()
        run.candidates_created = created
        run.candidates_skipped = skipped
        stage_results["candidate_generation"] = {
            "status": "partial" if generation_errors else "succeeded",
            "candidates_created": created,
            "candidates_skipped": skipped,
            "errors": generation_errors[:50],
            "validation": "static checks only; candidates remain unapproved and non-deployable",
        }
        if generation_errors:
            failures.extend(generation_errors[:10])
    except Exception as exc:
        db.rollback()
        message = f"{type(exc).__name__}: {str(exc)[:400]}"
        stage_results["candidate_generation"] = {"status": "failed", "error": message}
        failures.append(f"candidate_generation: {message}")

    run = db.get(PipelineRun, run.id)
    run.stage_results = stage_results
    run.status = "failed" if failures and all(value.get("status") == "failed" for value in stage_results.values()) else "partial_success" if failures else "succeeded"
    run.error_message = "; ".join(failures)[:4000] if failures else None
    run.completed_at = datetime.now(UTC)
    db.commit()
    db.refresh(run)
    return {
        "run_id": str(run.id),
        "status": run.status,
        "trigger": run.trigger,
        "stage_results": run.stage_results,
        "indicators_enriched": run.indicators_enriched,
        "opportunities_found": run.opportunities_found,
        "candidates_created": run.candidates_created,
        "candidates_skipped": run.candidates_skipped,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "error_message": run.error_message,
    }
