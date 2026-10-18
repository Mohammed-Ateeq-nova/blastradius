from __future__ import annotations

from typing import Any
from uuid import uuid4

from app.db.graph import FalkorGraph
from app.services.graph_ids import (
    candidate_key,
    entry_key,
    file_key,
    package_key,
    vuln_key,
)


def upsert_fixture_graph(client, graph_name: str, model: dict[str, Any], scan_id: str | None = None) -> str:
    graph = FalkorGraph(client, graph_name)
    project = model["project"]
    project_id = project["project_id"]
    scan_id = scan_id or f"scan-{uuid4().hex[:12]}"

    graph.query(
        """
        MERGE (p:Project {project_id: $project_id})
        SET p.name = $name, p.root_label = $root_label
        MERGE (s:Scan {scan_id: $scan_id})
        SET s.status = $status, s.fixture = $fixture, s.source = $source, s.label = $label
        MERGE (p)-[:HAS_SCAN]->(s)
        """,
        {
            "project_id": project_id,
            "name": project["name"],
            "root_label": project["root_label"],
            "scan_id": scan_id,
            "status": "complete",
            "fixture": bool(model.get("fixture")),
            "source": model.get("source", "demo-fixture"),
            "label": model.get("label", "DEMO FIXTURE" if model.get("fixture") else "LOCAL REPOSITORY"),
        },
    )

    for pkg in model["packages"]:
        key = package_key(pkg["ecosystem"], pkg["name"], pkg["version"])
        graph.query(
            """
            MATCH (proj:Project {project_id: $project_id})
            MERGE (pkg:Package {package_key: $package_key})
            SET pkg.name = $name, pkg.version = $version, pkg.ecosystem = $ecosystem,
                pkg.direct = $direct, pkg.declared_constraint = $declared_constraint
            MERGE (proj)-[:CONTAINS_PACKAGE]->(pkg)
            """,
            {
                "project_id": project_id,
                "package_key": key,
                "name": pkg["name"],
                "version": pkg["version"],
                "ecosystem": pkg["ecosystem"],
                "direct": pkg["direct"],
                "declared_constraint": pkg["declared_constraint"],
            },
        )

    for dep in model["dependencies"]:
        src = package_key(*dep["from"])
        dst = package_key(*dep["to"])
        graph.query(
            """
            MATCH (a:Package {package_key: $src})
            MATCH (b:Package {package_key: $dst})
            MERGE (a)-[d:DEPENDS_ON]->(b)
            SET d.constraint = $constraint, d.direct = $direct, d.source = $source
            """,
            {
                "src": src,
                "dst": dst,
                "constraint": dep["constraint"],
                "direct": dep["direct"],
                "source": dep["source"],
            },
        )

    for file in model["files"]:
        key = file_key(project_id, file["relative_path"])
        graph.query(
            """
            MATCH (proj:Project {project_id: $project_id})
            MERGE (f:File {file_key: $file_key})
            SET f.relative_path = $relative_path, f.language = $language
            MERGE (proj)-[:CONTAINS_FILE]->(f)
            """,
            {
                "project_id": project_id,
                "file_key": key,
                "relative_path": file["relative_path"],
                "language": file["language"],
            },
        )

    for imp in model["imports"]:
        graph.query(
            """
            MATCH (f:File {file_key: $file_key})
            MATCH (pkg:Package {package_key: $package_key})
            MERGE (f)-[:IMPORTS]->(pkg)
            """,
            {
                "file_key": file_key(project_id, imp["file"]),
                "package_key": package_key(*imp["package"]),
            },
        )

    for entry in model["entry_points"]:
        graph.query(
            """
            MERGE (e:EntryPoint {entry_key: $entry_key})
            SET e.relative_path = $relative_path, e.kind = $kind, e.evidence_source = $evidence_source
            """,
            {
                "entry_key": entry_key(project_id, entry["relative_path"]),
                "relative_path": entry["relative_path"],
                "kind": entry["kind"],
                "evidence_source": entry["evidence_source"],
            },
        )

    for reach in model["reaches"]:
        graph.query(
            """
            MATCH (e:EntryPoint {entry_key: $entry_key})
            MATCH (f:File {file_key: $file_key})
            MERGE (e)-[r:REACHES]->(f)
            SET r.evidence_type = $evidence_type, r.confidence_label = $confidence_label
            """,
            {
                "entry_key": entry_key(project_id, reach["entry"]),
                "file_key": file_key(project_id, reach["file"]),
                "evidence_type": reach["evidence_type"],
                "confidence_label": reach["confidence_label"],
            },
        )

    for vuln in model["vulnerabilities"]:
        key = vuln_key(vuln["advisory_id"])
        pkg = package_key(*vuln["affected"]["package"])
        graph.query(
            """
            MATCH (pkg:Package {package_key: $package_key})
            MERGE (v:Vuln {vuln_key: $vuln_key})
            SET v.advisory_id = $advisory_id, v.severity = $severity, v.summary = $summary,
                v.source = $source, v.source_timestamp = $source_timestamp, v.fixture = $fixture
            MERGE (v)-[a:AFFECTS]->(pkg)
            SET a.range = $range, a.source = $source
            """,
            {
                "package_key": pkg,
                "vuln_key": key,
                "advisory_id": vuln["advisory_id"],
                "severity": vuln["severity"],
                "summary": vuln["summary"],
                "source": vuln["source"],
                "source_timestamp": vuln["source_timestamp"],
                "fixture": vuln["fixture"],
                "range": vuln["affected"]["range"],
            },
        )

    for cand in model.get("upgrade_candidates", []):
        graph.query(
            """
            MATCH (pkg:Package {name: $package_name, version: $from_version})
            MERGE (c:UpgradeCandidate {candidate_key: $candidate_key})
            SET c.package_name = $package_name, c.from_version = $from_version,
                c.to_version = $to_version, c.compatibility_cost = $compatibility_cost
            MERGE (pkg)-[:HAS_UPGRADE_OPTION]->(c)
            """,
            {
                "package_name": cand["package_name"],
                "from_version": cand["from_version"],
                "to_version": cand["to_version"],
                "compatibility_cost": cand["compatibility_cost"],
                "candidate_key": candidate_key(
                    cand["package_name"], cand["from_version"], cand["to_version"]
                ),
            },
        )

    return scan_id
