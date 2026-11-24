"""Celery tasks for the end-to-end intelligence pipeline."""
from app.db.session import SessionLocal
from app.services.pipeline import run_intelligence_pipeline
from app.worker import celery_app


@celery_app.task(
    name="app.tasks.intelligence.run_pipeline",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 2},
)
def run_pipeline(trigger: str = "scheduled", sync_feeds: bool = False) -> dict:
    db = SessionLocal()
    try:
        # Individual CISA, NVD and ATT&CK jobs run at 02:00–04:00 UTC.
        # The 05:00 UTC pipeline consumes their completed data without re-fetching.
        syncers = None if sync_feeds else {}
        return run_intelligence_pipeline(db, trigger=trigger, feed_syncers=syncers)
    finally:
        db.close()
