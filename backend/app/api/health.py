from typing import Callable

from fastapi import APIRouter, Depends

from app.config import settings
from app.db.falkordb import FalkorDBProbeResult, probe_configured_instance

router = APIRouter()


def get_probe() -> Callable[[], FalkorDBProbeResult]:
    return probe_configured_instance


@router.get("/api/health")
def health(probe: Callable[[], FalkorDBProbeResult] = Depends(get_probe)):
    result = probe()
    return {
        "status": "ok" if result.connected else "degraded",
        "backend": "ok",
        "mcp_required": False,
        "falkordb": {
            "connected": result.connected,
            "host": settings.falkordb_host,
            "port": settings.falkordb_port,
            "graphs": result.graphs,
            "error": result.error,
        },
    }
