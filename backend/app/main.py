from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.identity import router as identity_router
from app.api.intelligence import router as intelligence_router
from app.core.config import get_settings

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0", description="Detection engineering API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(identity_router)
app.include_router(intelligence_router)


@app.get("/health", tags=["operations"])
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "api", "environment": settings.app_env}


@app.get("/ready", tags=["operations"])
async def ready() -> dict[str, str]:
    # Database and queue dependency checks will be added in the next phase.
    return {"status": "ready"}
