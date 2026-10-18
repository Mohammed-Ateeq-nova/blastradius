from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.services.fixture_loader import FIXTURE_ROOT
from tests.test_project_scanner import MockOsvProvider


def test_scan_local_missing_path():
    client = TestClient(app)
    res = client.post("/api/scans", json={"source": "local"})
    assert res.status_code == 400
    assert res.json()["detail"]["error"] == "missing_path"


def test_scan_local_invalid_path():
    client = TestClient(app)
    res = client.post("/api/scans", json={"source": "local", "path": "c:/does_not_exist_xyz123"})
    assert res.status_code == 400
    assert res.json()["detail"]["error"] == "invalid_path"


def test_scan_local_missing_lockfile(tmp_path):
    (tmp_path / "package.json").write_text("{\"name\": \"test-app\"}", encoding="utf-8")
    client = TestClient(app)
    res = client.post("/api/scans", json={"source": "local", "path": str(tmp_path)})
    assert res.status_code == 400
    assert res.json()["detail"]["error"] == "missing_lockfile"


def test_scan_local_full_flow():
    client = TestClient(app)

    with patch("app.services.project_scanner.OsvProvider", return_value=MockOsvProvider()):
        res = client.post("/api/scans", json={"source": "local", "path": str(FIXTURE_ROOT)})
        if res.status_code == 503:
            pytest.skip("FalkorDB unavailable")

        assert res.status_code == 200
        scan = res.json()
        assert scan["fixture"] is False
        assert scan["scan_id"].startswith("scan-local-")
        assert "local repository" in scan["label"].lower()
        assert scan["coverage"]["packages_scanned"] == 3
        assert scan["finding_count"] == 2

        scan_id = scan["scan_id"]

        # Check findings
        findings_res = client.get(f"/api/scans/{scan_id}/findings")
        assert findings_res.status_code == 200
        body = findings_res.json()
        assert body["fixture"] is False
        findings = body["findings"]
        assert len(findings) == 2

        for f in findings:
            assert f["fixture"] is False
            assert f["source"] == "osv.dev"
            assert f["risk_score"] > 0

        # Check remediations
        remed_res = client.get(f"/api/scans/{scan_id}/remediations")
        assert remed_res.status_code == 200
        remed_body = remed_res.json()
        candidates = remed_body["remediation_candidates"]
        assert len(candidates) >= 1
        # minimist 1.2.5 -> 1.2.6
        minimist_cand = next((c for c in candidates if c["package_name"] == "minimist"), None)
        assert minimist_cand is not None
        assert minimist_cand["to_version"] == "1.2.6"
        assert minimist_cand["compatibility_cost"] == "patch"
