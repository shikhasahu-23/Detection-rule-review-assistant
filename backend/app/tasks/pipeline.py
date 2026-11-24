"""Celery and in-process entry points for the intelligence pipeline."""
from app.db.session import SessionLocal
from app.services.pipeline import run_intelligence_pipeline
from app.worker import celery_app


def execute_pipeline(trigger: str = "scheduled", sync_feeds: bool = False) -> dict:
    """Run the pipeline in the current API/worker process with its own DB session."""
    db = SessionLocal()
    try:
        # Manual runs refresh feeds; scheduled enrichment consumes independently synced feeds.
        syncers = None if sync_feeds else {}
        return run_intelligence_pipeline(db, trigger=trigger, feed_syncers=syncers)
    finally:
        db.close()


@celery_app.task(
    name="app.tasks.intelligence.run_pipeline",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 2},
)
def run_pipeline(trigger: str = "scheduled", sync_feeds: bool = False) -> dict:
    """Celery-compatible wrapper retained for deployments with a worker."""
    return execute_pipeline(trigger=trigger, sync_feeds=sync_feeds)
