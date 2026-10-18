import pytest

from app.db.falkordb import create_redis_client, probe_falkordb
from app.db.graph import FalkorGraph
from app.services.fixture_loader import load_demo_fixture
from app.services.graph_builder import upsert_fixture_graph
from app.services.graph_queries import finding_paths, list_findings, package_count, reversed_affects_count

GRAPH = "blast_radius_test"


@pytest.fixture
def client():
    redis_client = create_redis_client()
    if not probe_falkordb(redis_client).connected:
        redis_client.close()
        pytest.skip("FalkorDB unavailable")
    graph = FalkorGraph(redis_client, GRAPH)
    graph.delete()
    yield redis_client
    FalkorGraph(redis_client, GRAPH).delete()
    redis_client.close()


def test_fixture_upsert_is_idempotent_and_path_direction_is_correct(client):
    model = load_demo_fixture()
    upsert_fixture_graph(client, GRAPH, model, scan_id="scan-test")
    upsert_fixture_graph(client, GRAPH, model, scan_id="scan-test")

    graph = FalkorGraph(client, GRAPH)
    assert package_count(graph) == 3
    assert reversed_affects_count(graph) == 0

    findings = list_findings(graph)
    assert len(findings) == 1
    assert findings[0]["advisory_id"] == "FIXTURE-LODASH-PROTOTYPE"
    assert findings[0]["fixture"] is True
    assert findings[0]["evidence_label"] == "potentially_reachable"

    paths = finding_paths(graph, findings[0]["finding_id"])
    assert len(paths) == 1
    path = paths[0]
    assert path["package_key"] == "npm:lodash@4.17.21"
    assert path["file_path"] == "src/index.js"
    assert path["entry_path"] == "src/index.js"
    assert path["edges"][0] == {"type": "AFFECTS", "from": "Vuln", "to": "Package"}
    assert path["edges"][1] == {"type": "IMPORTS", "from": "File", "to": "Package"}
    assert path["edges"][2] == {"type": "REACHES", "from": "EntryPoint", "to": "File"}
    assert path["evidence_label"] == "potentially_reachable"
