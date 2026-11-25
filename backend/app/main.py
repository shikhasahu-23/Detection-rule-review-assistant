from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis import Redis
from sqlalchemy import text

from app.api.detection_intents import router as detection_intents_router
from app.api.effectiveness import router as effectiveness_router
from app.api.generation import router as generation_router
from app.api.intelligence import router as intelligence_router
from app.api.rule_candidates import library_router
from app.api.rule_candidates import router as rule_candidates_router
from app.api.testing import router as testing_router
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import engine
from app.models import (  # noqa: F401
    attack,
    audit,
    detection,
    identity,
    intelligence,
    pipeline,
    rule,
    testing,
    threat_graph,
)

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Development bootstrap only; production uses reviewed Alembic migrations.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Threat intelligence and detection engineering API",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(intelligence_router)
app.include_router(detection_intents_router)
app.include_router(rule_candidates_router)
app.include_router(library_router)
app.include_router(generation_router)
app.include_router(testing_router)
app.include_router(effectiveness_router)


@app.get("/health", tags=["operations"])
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "api", "environment": settings.app_env}


@app.get("/ready", tags=["operations"])
async def ready():
    checks = {"database": "ok", "redis": "ok"}

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        checks["database"] = "error"

    redis_client = Redis.from_url(settings.redis_url, socket_connect_timeout=3, socket_timeout=3)
    try:
        redis_client.ping()
    except Exception:
        checks["redis"] = "error"
    finally:
        redis_client.close()

    if any(status != "ok" for status in checks.values()):
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "checks": checks},
        )

    return {"status": "ready", "checks": checks}
