import asyncio
import logging
from collections.abc import Callable
from typing import Any

from celery import shared_task
from sqlalchemy import select

from app.db.session import SessionLocal
from app.intel.connectors.base import IntelConnector
from app.intel.connectors.cisa_kev import CisaKevConnector
from app.intel.connectors.nvd import NvdConnector
from app.intel.connectors.threatfox import ThreatFoxConnector
from app.intel.connectors.urlhaus import UrlhausConnector
from app.models.intelligence import IntelSource
from app.services.intel_ingestion import run_intel_ingestion

logger = logging.getLogger(__name__)

CONNECTORS: dict[str, Callable[[], IntelConnector]] = {
    "cisa_kev": CisaKevConnector,
    "nvd": NvdConnector,
    "urlhaus": UrlhausConnector,
    "threatfox": ThreatFoxConnector,
}


def _build_connector(source_type: str) -> IntelConnector:
    try:
        return CONNECTORS[source_type]()
    except KeyError as exc:
        raise ValueError(f"Unsupported intelligence source type: {source_type}") from exc


@shared_task(
    bind=True,
    name="app.tasks.intel.ingest_source",
    autoretry_for=(RuntimeError,),
    retry_backoff=True,
    retry_backoff_max=900,
    retry_jitter=True,
    max_retries=5,
)
def ingest_source(self: Any, source_id: str) -> dict[str, Any]:
    """Run one enabled source with bounded exponential retries."""
    with SessionLocal() as db:
        source = db.scalar(
            select(IntelSource).where(
                IntelSource.id == source_id,
                IntelSource.is_enabled.is_(True),
            )
        )
        if source is None:
            return {"source_id": source_id, "status": "skipped", "reason": "source_missing_or_disabled"}
        try:
            connector = _build_connector(source.source_type)
        except ValueError:
            logger.warning("Unsupported intelligence connector source_type=%s", source.source_type)
            return {"source_id": source_id, "status": "skipped", "reason": "unsupported_source_type"}
        result = asyncio.run(
            run_intel_ingestion(
                db,
                organization_id=source.organization_id,
                source=source,
                connector=connector,
            )
        )
        if result.status != "success":
            raise RuntimeError(f"Intelligence ingestion failed for source {source_id}")
        return {
            "source_id": source_id,
            "run_id": str(result.id),
            "status": result.status,
            "records_seen": result.records_seen,
            "records_created": result.records_created,
            "records_rejected": result.records_rejected,
        }


@shared_task(name="app.tasks.intel.ingest_enabled_sources")
def ingest_enabled_sources() -> dict[str, int]:
    """Enqueue one isolated task per enabled feed source."""
    queued = 0
    with SessionLocal() as db:
        source_ids = list(
            db.scalars(select(IntelSource.id).where(IntelSource.is_enabled.is_(True)))
        )
    for source_id in source_ids:
        ingest_source.delay(str(source_id))
        queued += 1
    return {"queued": queued}
