from __future__ import annotations

from pathlib import Path
from typing import Any

from app.db.graph import FalkorGraph
from app.services.graph_ids import vuln_key
from app.services.proposal_generator import build_remediation_proposal
from app.services.risk_engine import (
    CATEGORY_CONFIRMED_ENTRY,
    CATEGORY_IMPORTED_ONLY,
    CATEGORY_NO_PATH,
    CATEGORY_TRANSITIVE_ONLY,
    classify_evidence,
    evaluate_upgrade_candidates,
    rank_findings,
)


def _scalar(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in row:
            return row[name]
    return None


def package_count(graph: FalkorGraph) -> int:
    rows = graph.query("MATCH (p:Package) RETURN count(p) AS n")
    if not rows:
        return 0
    return int(_scalar(rows[0], "n") or 0)


def reversed_affects_count(graph: FalkorGraph) -> int:
    """Wrong-direction check: Package-[:AFFECTS]->Vuln must be empty."""
    rows = graph.query("MATCH (p:Package)-[:AFFECTS]->(v:Vuln) RETURN count(p) AS n")
    if not rows:
        return 0
    return int(_scalar(rows[0], "n") or 0)


def _is_true(val: Any) -> bool:
    if val is True:
        return True
    if val is False or val is None:
        return False
    return str(val).lower() in ("true", "1")


def list_findings(graph: FalkorGraph) -> list[dict[str, Any]]:
    """Query findings, classify evidence categories, and return deterministically ranked findings."""
    rows = graph.query(
        """
        MATCH (v:Vuln)-[a:AFFECTS]->(p:Package)
        OPTIONAL MATCH (f:File)-[:IMPORTS]->(p)
        OPTIONAL MATCH (e:EntryPoint)-[:REACHES]->(f)
        OPTIONAL MATCH (parent:Package)-[:DEPENDS_ON]->(p)
        RETURN v.vuln_key AS vuln_key, v.advisory_id AS advisory_id, v.severity AS severity,
               v.summary AS summary, v.source AS source, v.fixture AS fixture,
               a.range AS affected_range,
               p.package_key AS package_key, p.name AS package_name, p.version AS package_version,
               p.direct AS direct,
               count(DISTINCT f) AS import_files,
               count(DISTINCT e) AS entry_points,
               count(DISTINCT parent) AS dependency_parents
        """
    )
    findings = []
    for row in rows:
        import_files = int(_scalar(row, "import_files") or 0)
        entry_points = int(_scalar(row, "entry_points") or 0)
        dependency_parents = int(_scalar(row, "dependency_parents") or 0)
        direct_val = _scalar(row, "direct")
        is_direct = direct_val is True or str(direct_val).lower() in ("true", "1")
        is_transitive = (direct_val is False or str(direct_val).lower() in ("false", "0")) or (
            dependency_parents > 0 and not is_direct
        )
        in_dep_tree = dependency_parents > 0

        evidence_cat = classify_evidence(
            import_files_count=import_files,
            entry_points_count=entry_points,
            in_dependency_tree=in_dep_tree,
        )

        findings.append(
            {
                "finding_id": row.get("vuln_key"),
                "advisory_id": row.get("advisory_id"),
                "severity": row.get("severity"),
                "summary": row.get("summary"),
                "source": row.get("source"),
                "fixture": _is_true(row.get("fixture")),
                "package_key": row.get("package_key"),
                "package_name": row.get("package_name"),
                "package_version": row.get("package_version"),
                "affected_range": row.get("affected_range"),
                "evidence_category": evidence_cat,
                # evidence_label maintains backward compatibility with M2 tests
                "evidence_label": "potentially_reachable"
                if evidence_cat in (CATEGORY_CONFIRMED_ENTRY, CATEGORY_IMPORTED_ONLY)
                else evidence_cat,
                "import_files_count": import_files,
                "entry_points_count": entry_points,
            }
        )
    return rank_findings(findings)


def finding_paths(graph: FalkorGraph, finding_id: str) -> list[dict[str, Any]]:
    """Return bounded evidence paths for a finding across evidence categories."""
    key = finding_id if finding_id.startswith("vuln:") else vuln_key(finding_id)

    # 1. First attempt: full entry point -> file -> package paths (confirmed_entry_path)
    rows = graph.query(
        """
        MATCH (v:Vuln {vuln_key: $vuln_key})-[a:AFFECTS]->(p:Package)
              <-[i:IMPORTS]-(f:File)<-[r:REACHES]-(e:EntryPoint)
        RETURN v.advisory_id AS advisory_id,
               type(a) AS affects_type,
               p.package_key AS package_key,
               type(i) AS imports_type,
               f.relative_path AS file_path,
               type(r) AS reaches_type,
               e.relative_path AS entry_path,
               r.confidence_label AS confidence_label,
               r.evidence_type AS evidence_type
        LIMIT 25
        """,
        {"vuln_key": key},
    )
    if rows:
        paths = []
        for row in rows:
            paths.append(
                {
                    "advisory_id": row.get("advisory_id"),
                    "package_key": row.get("package_key"),
                    "file_path": row.get("file_path"),
                    "entry_path": row.get("entry_path"),
                    "edges": [
                        {"type": row.get("affects_type"), "from": "Vuln", "to": "Package"},
                        {"type": row.get("imports_type"), "from": "File", "to": "Package"},
                        {"type": row.get("reaches_type"), "from": "EntryPoint", "to": "File"},
                    ],
                    "evidence_category": CATEGORY_CONFIRMED_ENTRY,
                    "evidence_label": row.get("confidence_label") or "potentially_reachable",
                    "evidence_type": row.get("evidence_type") or "entry_is_file",
                    "limitations": (
                        "Verified structural path from entry point to package import. "
                        "Not proof of runtime execution or exploitability."
                    ),
                }
            )
        return paths

    # 2. Second attempt: file -> package imports without verified entry point (imported_only)
    import_rows = graph.query(
        """
        MATCH (v:Vuln {vuln_key: $vuln_key})-[a:AFFECTS]->(p:Package)<-[i:IMPORTS]-(f:File)
        RETURN v.advisory_id AS advisory_id,
               type(a) AS affects_type,
               p.package_key AS package_key,
               type(i) AS imports_type,
               f.relative_path AS file_path
        LIMIT 25
        """,
        {"vuln_key": key},
    )
    if import_rows:
        paths = []
        for row in import_rows:
            paths.append(
                {
                    "advisory_id": row.get("advisory_id"),
                    "package_key": row.get("package_key"),
                    "file_path": row.get("file_path"),
                    "entry_path": None,
                    "edges": [
                        {"type": row.get("affects_type"), "from": "Vuln", "to": "Package"},
                        {"type": row.get("imports_type"), "from": "File", "to": "Package"},
                    ],
                    "evidence_category": CATEGORY_IMPORTED_ONLY,
                    "evidence_label": "imported_only",
                    "evidence_type": "static_import_unreached",
                    "limitations": (
                        "Package is statically imported by a source file, but no path was found "
                        "from any known application entry point."
                    ),
                }
            )
        return paths

    # 3. Third attempt: dependency tree path (transitive_dependency_only)
    dep_rows = graph.query(
        """
        MATCH (v:Vuln {vuln_key: $vuln_key})-[a:AFFECTS]->(p:Package)<-[d:DEPENDS_ON]-(parent:Package)
        RETURN v.advisory_id AS advisory_id,
               type(a) AS affects_type,
               p.package_key AS package_key,
               type(d) AS depends_type,
               parent.package_key AS parent_package_key
        LIMIT 25
        """,
        {"vuln_key": key},
    )
    if dep_rows:
        paths = []
        for row in dep_rows:
            paths.append(
                {
                    "advisory_id": row.get("advisory_id"),
                    "package_key": row.get("package_key"),
                    "file_path": None,
                    "entry_path": None,
                    "edges": [
                        {"type": row.get("affects_type"), "from": "Vuln", "to": "Package"},
                        {"type": row.get("depends_type"), "from": "ParentPackage", "to": "Package"},
                    ],
                    "evidence_category": CATEGORY_TRANSITIVE_ONLY,
                    "evidence_label": "transitive_dependency_only",
                    "evidence_type": "dependency_tree_only",
                    "limitations": (
                        "Package exists in the dependency graph, but no matching source import "
                        "was found in analyzed repository files."
                    ),
                }
            )
        return paths

    # 4. Fourth case: no path found
    return []


def list_upgrade_candidates(
    graph: FalkorGraph,
    findings: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Query upgrade candidates, evaluate resolution against findings, and return ranked candidates."""
    if findings is None:
        findings = list_findings(graph)

    rows = graph.query(
        """
        MATCH (p:Package)-[:HAS_UPGRADE_OPTION]->(c:UpgradeCandidate)
        RETURN c.candidate_key AS candidate_key,
               c.package_name AS package_name,
               c.from_version AS from_version,
               c.to_version AS to_version,
               c.compatibility_cost AS compatibility_cost,
               p.package_key AS package_key
        """
    )
    candidates = []
    for row in rows:
        candidates.append(
            {
                "candidate_key": row.get("candidate_key"),
                "package_name": row.get("package_name"),
                "from_version": row.get("from_version"),
                "to_version": row.get("to_version"),
                "compatibility_cost": row.get("compatibility_cost"),
                "package_key": row.get("package_key"),
            }
        )
    evaluated = evaluate_upgrade_candidates(candidates, findings)

    # Look up project root and fixture flag to generate proposals
    proj_rows = graph.query("MATCH (pr:Project) RETURN pr.root_label AS root_label LIMIT 1")
    scan_rows = graph.query("MATCH (s:Scan) RETURN s.fixture AS fixture LIMIT 1")
    root_label = proj_rows[0].get("root_label") if proj_rows else None
    is_fixture = _is_true(scan_rows[0].get("fixture")) if scan_rows else False

    manifest_text = None
    if root_label:
        try:
            m_path = Path(root_label) / "package.json"
            if m_path.is_file():
                manifest_text = m_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            manifest_text = None

    for cand in evaluated:
        cand["proposal"] = build_remediation_proposal(cand, manifest_text, is_fixture=is_fixture)

    return evaluated
