"""Orchestrate feed ingestion, enrichment, correlation and safe candidate generation."""
from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
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
from app.services.generation import GenerationProvider, get_generation_provider
from app.services.mitre_attack import sync_attack_catalog
from app.services.nvd import sync_nvd_cves
from app.services.platforms import get_platform_contract
from app.services.public_feeds import sync_public_feed
from app.services.validation import validate_candidate
from app.services.ioc_rule_sync import sync_ioc_rules

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
        "urlhaus": lambda session: sync_public_feed(session, "urlhaus"),
        "feodo_tracker": lambda session: sync_public_feed(session, "feodo"),
        "openphish": lambda session: sync_public_feed(session, "openphish"),
        "sslbl": lambda session: sync_public_feed(session, "sslbl"),

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
        except Exception as exc:  # noqa: BLE001 - pipeline stages isolate and record failures
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
    except Exception as exc:  # noqa: BLE001 - pipeline stages isolate and record failures
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
    except Exception as exc:  # noqa: BLE001 - pipeline stages isolate and record failures
        db.rollback()
        message = f"{type(exc).__name__}: {str(exc)[:400]}"
        stage_results["correlation"] = {"status": "failed", "error": message}
        failures.append(f"correlation: {message}")

    try:
        if provider is None:
            stage_results["ioc_rule_sync"] = sync_ioc_rules(db)
            if stage_results["ioc_rule_sync"].get("status") == "partial":
                failures.append("IOC rule synchronization had generation failures")
        else:
            stage_results["ioc_rule_sync"] = {
                "status": "skipped",
                "reason": "A test/custom generation provider was injected; IOC sync uses the production template provider.",
            }
    except Exception as exc:  # noqa: BLE001 - keep other stages available
        db.rollback()
        message = f"{type(exc).__name__}: {str(exc)[:400]}"
        stage_results["ioc_rule_sync"] = {"status": "failed", "error": message}
        failures.append(f"ioc_rule_sync: {message}")

    created = skipped = 0
    generation_errors: list[str] = []
    try:
        active_provider = provider or get_generation_provider()
        provider_name = getattr(active_provider, "provider_name", type(active_provider).__name__.lower())
        provider_model = getattr(active_provider, "model", "deterministic-v1")
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
                    RuleCandidate.generator.in_(["pipeline", provider_name]),
                ).limit(1))
                if existing is not None:
                    skipped += 1
                    continue
                try:
                    draft = active_provider.generate(_intent_payload(intent), platform)
                except Exception as exc:  # noqa: BLE001 - pipeline stages isolate and record failures
                    generation_errors.append(
                        f"{intent.id}/{platform.value}: {type(exc).__name__}: {str(exc)[:300]}"
                    )
                    continue
                try:
                    version = db.scalar(select(func.max(RuleCandidate.version)).where(
                        RuleCandidate.intent_id == intent.id,
                        RuleCandidate.platform == platform.value,
                    )) or 0
                    report = validate_candidate(platform, draft.query, _intent_payload(intent))
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
                            "provider": provider_name,
                            "model": provider_model,
                            "prompt_version": get_platform_contract(platform).prompt_version,
                            "generated_at": datetime.now(UTC).isoformat(),
                            "validation_scope": get_platform_contract(platform).validation_scope,
                        },
                        generator=provider_name,
                    ))
                    db.commit()
                    created += 1
                except Exception as exc:  # noqa: BLE001 - pipeline stages isolate and record failures
                    db.rollback()
                    run = db.get(PipelineRun, run.id)
                    generation_errors.append(
                        f"{intent.id}/{platform.value}: {type(exc).__name__}: {str(exc)[:300]}"
                    )
        db.commit()
        run.candidates_created = created
        run.candidates_skipped = skipped
        stage_results["candidate_generation"] = {
            "provider": provider_name,
            "model": provider_model,
            "status": "partial" if generation_errors else "succeeded",
            "candidates_created": created,
            "candidates_skipped": skipped,
            "errors": generation_errors[:50],
            "validation": "static checks only; candidates remain unapproved and non-deployable",
        }
        if generation_errors:
            failures.extend(generation_errors[:10])
    except Exception as exc:  # noqa: BLE001 - pipeline stages isolate and record failures
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
