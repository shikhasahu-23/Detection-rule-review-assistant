from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

settings = get_settings()
celery_app = Celery(
    "threatweave",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.intelligence", "app.tasks.pipeline"],
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "sync-cisa-kev-daily": {
            "task": "app.tasks.intelligence.sync_cisa_kev",
            "schedule": crontab(hour=2, minute=0),
        },
        "sync-nvd-cves-daily": {
            "task": "app.tasks.intelligence.sync_nvd_cves",
            "schedule": crontab(hour=3, minute=0),
        },
        "run-intelligence-pipeline-daily": {
            "task": "app.tasks.pipeline.run_pipeline",
            "schedule": crontab(hour=5, minute=0),
            "kwargs": {"trigger": "scheduled", "sync_feeds": False},
        },
        "sync-mitre-attack-daily": {
            "task": "app.tasks.intelligence.sync_mitre_attack",
            "schedule": crontab(hour=4, minute=0),
        },
    },
)
