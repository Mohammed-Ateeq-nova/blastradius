from fastapi.testclient import TestClient

from app.main import app


def test_scan_rejects_non_fixture_source():
    client = TestClient(app)
    response = client.post("/api/scans", json={"source": "random-path"})
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "unsupported_source"


def test_fixture_scan_loads_and_returns_labelled_path():
    client = TestClient(app)
    created = client.post("/api/scans", json={"source": "fixture"})
    if created.status_code == 503:
        import pytest

        pytest.skip("FalkorDB unavailable")
    assert created.status_code == 200
    body = created.json()
    assert body["fixture"] is True
    assert "DEMO FIXTURE" in body["label"]
    scan_id = body["scan_id"]

    findings = client.get(f"/api/scans/{scan_id}/findings")
    assert findings.status_code == 200
    items = findings.json()["findings"]
    assert len(items) == 1
    finding = items[0]
    finding_id = finding["finding_id"]
    assert finding["evidence_category"] == "confirmed_entry_path"
    assert finding["risk_score"] == 8.0
    assert finding["rank"] == 1

    paths = client.get(f"/api/findings/{finding_id}/paths")
    assert paths.status_code == 200
    payload = paths.json()
    assert payload["path_count"] == 1
    assert payload["paths"][0]["package_key"] == "npm:lodash@4.17.21"
    assert payload["paths"][0]["evidence_category"] == "confirmed_entry_path"

    remediations = client.get(f"/api/scans/{scan_id}/remediations")
    assert remediations.status_code == 200
    cands = remediations.json()["remediation_candidates"]
    assert len(cands) == 1
    assert cands[0]["package_name"] == "lodash"
    assert cands[0]["to_version"] == "4.17.22"
    assert cands[0]["compatibility_cost"] == "patch"
    assert cands[0]["resolved_findings_count"] == 1
    assert cands[0]["risk_eliminated"] == 8.0

