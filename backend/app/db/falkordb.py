from __future__ import annotations

from dataclasses import dataclass, field

import redis

from app.config import settings


@dataclass(frozen=True)
class FalkorDBProbeResult:
    connected: bool
    graphs: list[str] = field(default_factory=list)
    error: str | None = None
    detail: str | None = None


def _safe_detail(exc: BaseException) -> str:
    text = str(exc)
    lowered = text.lower()
    if "password" in lowered or "auth" in lowered:
        return "authentication or connection failed"
    return text[:240]


def _graph_names(raw) -> list[str]:
    if not raw:
        return []
    names: list[str] = []
    for item in raw:
        if isinstance(item, bytes):
            names.append(item.decode("utf-8"))
        else:
            names.append(str(item))
    return names


def probe_falkordb(client) -> FalkorDBProbeResult:
    """Ping FalkorDB and list graphs via GRAPH.LIST. Does not use MCP."""
    try:
        client.ping()
        graphs = _graph_names(client.execute_command("GRAPH.LIST"))
        return FalkorDBProbeResult(connected=True, graphs=graphs, error=None, detail=None)
    except Exception as exc:
        return FalkorDBProbeResult(
            connected=False,
            graphs=[],
            error="falkordb_unavailable",
            detail=_safe_detail(exc),
        )


def create_redis_client() -> redis.Redis:
    return redis.Redis(
        host=settings.falkordb_host,
        port=settings.falkordb_port,
        password=settings.falkordb_password or None,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )


def probe_configured_instance() -> FalkorDBProbeResult:
    client = create_redis_client()
    try:
        return probe_falkordb(client)
    finally:
        client.close()
