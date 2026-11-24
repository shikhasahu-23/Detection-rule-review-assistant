from app.db.session import SessionLocal
from app.services.cisa_kev import sync_cisa_kev as ingest_cisa_kev
from app.services.nvd import sync_nvd_cves as ingest_nvd_cves
from app.services.mitre_attack import sync_attack_catalog
from app.worker import celery_app


@celery_app.task(
    name="app.tasks.intelligence.sync_cisa_kev",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3},
)
def sync_cisa_kev() -> dict:
    db = SessionLocal()
    try:
        return ingest_cisa_kev(db)
    finally:
        db.close()


@celery_app.task(
    name="app.tasks.intelligence.sync_mitre_attack",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3},
)
def sync_mitre_attack() -> dict:
    db = SessionLocal()
    try:
        return sync_attack_catalog(db)
    finally:
        db.close()


@celery_app.task(
    name="app.tasks.intelligence.sync_nvd_cves",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3},
)
def sync_nvd_cves() -> dict:
    db = SessionLocal()
    try:
        return ingest_nvd_cves(db)
    finally:
        db.close()
