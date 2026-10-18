"""GET /api/health reports backend + FalkorDB status. MCP is not required."""

from fastapi.testclient import TestClient

from app.db.falkordb import FalkorDBProbeResult
from app.main import app, get_probe


def test_health_ok_when_falkordb_connected():
    app.dependency_overrides[get_probe] = lambda: (
        lambda: FalkorDBProbeResult(connected=True, graphs=["social"], error=None, detail=None)
    )
    try:
        client = TestClient(app)
        response = client.get("/api/health")
        assert response.status_code == 200
        body = response.json()
        assert body["backend"] == "ok"
        assert body["status"] == "ok"
        assert body["falkordb"]["connected"] is True
        assert body["mcp_required"] is False
    finally:
        app.dependency_overrides.clear()


def test_health_degraded_when_falkordb_down():
    app.dependency_overrides[get_probe] = lambda: (
        lambda: FalkorDBProbeResult(
            connected=False,
            graphs=[],
            error="falkordb_unavailable",
            detail="connection refused",
        )
    )
    try:
        client = TestClient(app)
        response = client.get("/api/health")
        assert response.status_code == 200
        body = response.json()
        assert body["backend"] == "ok"
        assert body["status"] == "degraded"
        assert body["falkordb"]["connected"] is False
        assert body["falkordb"]["error"] == "falkordb_unavailable"
        assert body["mcp_required"] is False
    finally:
        app.dependency_overrides.clear()
