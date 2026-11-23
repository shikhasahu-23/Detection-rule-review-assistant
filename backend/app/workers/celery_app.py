from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

settings = get_settings()
celery_app = Celery(
    "detection_rule_review_assistant",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.intel"],
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    beat_schedule={
        "daily-intelligence-ingestion": {
            "task": "app.tasks.intel.ingest_enabled_sources",
            "schedule": crontab(hour=2, minute=0),
        }
    },
)
