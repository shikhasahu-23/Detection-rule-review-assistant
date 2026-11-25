"""Secret-protected entry point for scheduled jobs triggered by GitHub Actions."""

import logging
from secrets import compare_digest
from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.services.cisa_kev import sync_cisa_kev
from app.services.mitre_attack import sync_attack_catalog
from app.services.nvd import sync_nvd_cves
from app.tasks.pipeline import execute_pipeline

router = APIRouter(prefix="/internal/scheduler", tags=["operations"])
logger = logging.getLogger(__name__)

ScheduledJob = Literal["cisa-kev", "nvd-cves", "mitre-attack", "pipeline"]


def _run_feed_sync(sync_function) -> dict:
    db = SessionLocal()
    try:
        return sync_function(db)
    finally:
        db.close()


@router.post("/run/{job}")
def run_scheduled_job(
    job: ScheduledJob,
    scheduler_secret: Annotated[str | None, Header(alias="X-Scheduler-Secret")] = None,
) -> dict:
    configured_secret = get_settings().scheduler_secret
    if not configured_secret:
        raise HTTPException(status_code=503, detail="Scheduler is not configured")
    if not scheduler_secret or not compare_digest(scheduler_secret, configured_secret):
        raise HTTPException(status_code=401, detail="Invalid scheduler credentials")

    try:
        if job == "cisa-kev":
            result = _run_feed_sync(sync_cisa_kev)
        elif job == "nvd-cves":
            result = _run_feed_sync(sync_nvd_cves)
        elif job == "mitre-attack":
            result = _run_feed_sync(sync_attack_catalog)
        else:
            result = execute_pipeline(trigger="scheduled", sync_feeds=False)
    except Exception as exc:
        logger.exception("Scheduled job %s failed", job)
        raise HTTPException(status_code=500, detail=f"Scheduled job {job} failed") from exc

    return {"status": "completed", "job": job, "result": result}
