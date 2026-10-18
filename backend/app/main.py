from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import get_probe, router as health_router
from app.api.scans import router as scans_router
from app.config import settings

app = FastAPI(title="BlastRadius", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.include_router(health_router)
app.include_router(scans_router)

__all__ = ["app", "get_probe"]
