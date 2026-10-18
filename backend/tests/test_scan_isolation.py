import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db.falkordb import create_redis_client, probe_falkordb
from app.db.graph import FalkorGraph
from app.main import app
from app.services.fixture_loader import FIXTURE_ROOT


@pytest.fixture
def falkordb_available():
    try:
        client = create_redis_client()
        probe = probe_falkordb(client)
        client.close()
        return probe.connected
    except Exception:
        return False


def create_second_test_project(tmp_path: Path) -> Path:
    proj_dir = tmp_path / "second-project"
    proj_dir.mkdir()
    manifest = {
        "name": "second-service",
        "version": "1.0.0",
        "dependencies": {
            "debug": "2.6.9",
        },
    }
    (proj_dir / "package.json").write_text(json.dumps(manifest), encoding="utf-8")

    lockfile = {
        "name": "second-service",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "packages": {
            "": {
                "name": "second-service",
                "version": "1.0.0",
                "dependencies": {
                    "debug": "2.6.9",
                },
            },
            "node_modules/debug": {
                "version": "2.6.9",
                "resolved": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
                "integrity": "sha512-bC7ElrdJaJnPbAP+1EotYvqZsb3ecl5wi6Bfi6BJTUcNowp6cvspg0jXznRTZEFQxE5vWyF3BK9Pl4GnpTR9oA==",
            },
        },
    }
    (proj_dir / "package-lock.json").write_text(json.dumps(lockfile), encoding="utf-8")

    src = proj_dir / "src"
    src.mkdir()
    (src / "index.js").write_text('const debug = require("debug");\n', encoding="utf-8")
    return proj_dir


def test_sequential_scans_isolation_and_404_for_old_scan(falkordb_available, tmp_path):
    if not falkordb_available:
        pytest.skip("FalkorDB is not running on 127.0.0.1:6379")

    client = TestClient(app)

    # 1. Scan Project 1 (Fixture repo)
    res1 = client.post("/api/scans", json={"source": "local", "path": str(FIXTURE_ROOT)})
    assert res1.status_code == 200, res1.text
    data1 = res1.json()
    scan_id_1 = data1["scan_id"]
    assert data1["label"].startswith("demo-app")
    assert data1["coverage"]["project_name"] == "demo-app"

    # Verify findings for scan 1
    find_res1 = client.get(f"/api/scans/{scan_id_1}/findings")
    assert find_res1.status_code == 200
    pkgs_1 = {f["package_name"] for f in find_res1.json()["findings"]}
    assert "lodash" in pkgs_1

    # 2. Scan Project 2 (different project in tmp_path)
    proj2 = create_second_test_project(tmp_path)
    res2 = client.post("/api/scans", json={"source": "local", "path": str(proj2)})
    assert res2.status_code == 200, res2.text
    data2 = res2.json()
    scan_id_2 = data2["scan_id"]
    assert scan_id_2 != scan_id_1
    assert data2["label"].startswith("second-service")
    assert data2["coverage"]["project_name"] == "second-service"

    # Verify findings for scan 2
    find_res2 = client.get(f"/api/scans/{scan_id_2}/findings")
    assert find_res2.status_code == 200
    pkgs_2 = {f["package_name"] for f in find_res2.json()["findings"]}
    # Project 2 must NOT have lodash or minimist from Project 1
    assert "lodash" not in pkgs_2
    assert "minimist" not in pkgs_2

    # Verify in FalkorDB directly that zero packages or files from Project 1 exist in graph
    r_client = create_redis_client()
    graph = FalkorGraph(r_client, settings.falkordb_graph)
    packages_in_graph = {
        row["name"] for row in graph.query("MATCH (p:Package) RETURN p.name AS name")
    }
    assert "lodash" not in packages_in_graph
    assert "minimist" not in packages_in_graph
    assert "debug" in packages_in_graph
    assert "second-service" in packages_in_graph
    r_client.close()

    # 3. Querying old scan_id_1 must now return 404 scan_not_found
    old_scan_res = client.get(f"/api/scans/{scan_id_1}")
    assert old_scan_res.status_code == 404
    assert old_scan_res.json()["detail"]["error"] == "scan_not_found"

    old_findings_res = client.get(f"/api/scans/{scan_id_1}/findings")
    assert old_findings_res.status_code == 404
    assert old_findings_res.json()["detail"]["error"] == "scan_not_found"

    old_remed_res = client.get(f"/api/scans/{scan_id_1}/remediations")
    assert old_remed_res.status_code == 404
    assert old_remed_res.json()["detail"]["error"] == "scan_not_found"


def test_failed_scan_does_not_corrupt_existing_graph(falkordb_available):
    if not falkordb_available:
        pytest.skip("FalkorDB is not running on 127.0.0.1:6379")

    client = TestClient(app)

    # 1. Establish a valid scan
    res_valid = client.post("/api/scans", json={"source": "fixture"})
    assert res_valid.status_code == 200
    scan_id_valid = res_valid.json()["scan_id"]

    # 2. Attempt a failing scan with an invalid/nonexistent path
    res_invalid = client.post("/api/scans", json={"source": "local", "path": "c:/nonexistent/invalid/dir"})
    assert res_invalid.status_code == 400

    # 3. Existing valid scan must still be intact and queryable
    res_check = client.get(f"/api/scans/{scan_id_valid}")
    assert res_check.status_code == 200
    assert res_check.json()["scan_id"] == scan_id_valid


def test_scan_does_not_delete_unrelated_graphs(falkordb_available):
    if not falkordb_available:
        pytest.skip("FalkorDB is not running on 127.0.0.1:6379")

    r_client = create_redis_client()
    unrelated_name = "test_unrelated_audit_graph"
    unrelated_graph = FalkorGraph(r_client, unrelated_name)

    try:
        # Create an unrelated graph with a sentinel node
        unrelated_graph.query("CREATE (:Sentinel {name: 'keep_me'})")
        rows = unrelated_graph.query("MATCH (s:Sentinel) RETURN s.name AS name")
        assert len(rows) == 1
        assert rows[0]["name"] == "keep_me"

        # Run a scan on blast_radius
        client = TestClient(app)
        res = client.post("/api/scans", json={"source": "fixture"})
        assert res.status_code == 200

        # Verify the unrelated graph and its sentinel node are completely untouched
        rows_after = unrelated_graph.query("MATCH (s:Sentinel) RETURN s.name AS name")
        assert len(rows_after) == 1
        assert rows_after[0]["name"] == "keep_me"
    finally:
        unrelated_graph.delete()
        r_client.close()
