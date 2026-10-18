from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.db.falkordb import FalkorDBProbeResult


def test_repeated_scans_are_idempotent():
    client = TestClient(app)
    # First scan
    res1 = client.post("/api/scans", json={"source": "fixture"})
    if res1.status_code == 503:
        pytest.skip("FalkorDB unavailable")
    assert res1.status_code == 200
    scan1 = res1.json()

    # Second scan
    res2 = client.post("/api/scans", json={"source": "fixture"})
    assert res2.status_code == 200
    scan2 = res2.json()

    assert scan1["fixture"] is True
    assert scan2["fixture"] is True
    assert scan1["finding_count"] == scan2["finding_count"]

    # Verify findings remain consistent and not duplicated
    findings_res = client.get(f"/api/scans/{scan2['scan_id']}/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()["findings"]
    assert len(findings) == 1
    assert findings[0]["advisory_id"] == "FIXTURE-LODASH-PROTOTYPE"


def test_scan_not_found_returns_404():
    client = TestClient(app)
    res = client.get("/api/scans/non-existent-scan-id/findings")
    assert res.status_code == 404
    assert res.json()["detail"]["error"] == "scan_not_found"


def test_remediations_not_found_returns_404():
    client = TestClient(app)
    res = client.get("/api/scans/non-existent-scan-id/remediations")
    assert res.status_code == 404
    assert res.json()["detail"]["error"] == "scan_not_found"


def test_unknown_finding_paths_returns_empty():
    client = TestClient(app)
    res = client.get("/api/findings/vuln:NON-EXISTENT/paths")
    if res.status_code == 503:
        pytest.skip("FalkorDB unavailable")
    assert res.status_code == 200
    body = res.json()
    assert body["path_count"] == 0
    assert body["paths"] == []
    assert "no_path_found" in body["evidence_note"]


def test_backend_handles_falkordb_failure_gracefully():
    client = TestClient(app)
    with patch("app.api.scans.probe_falkordb") as mock_probe:
        mock_probe.return_value = FalkorDBProbeResult(
            connected=False,
            graphs=[],
            error="falkordb_unavailable",
            detail="Connection refused (simulated)",
        )
        res = client.post("/api/scans", json={"source": "fixture"})
        assert res.status_code == 503
        detail = res.json()["detail"]
        assert detail["error"] == "falkordb_unavailable"
        assert detail["mcp_required"] is False
