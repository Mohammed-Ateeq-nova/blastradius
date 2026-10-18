"""Tests for Milestone M5: Risk-path reasoning, evidence classification, and ranking.

Covers:
- Direct dependency with source import and verified entry-point path (confirmed_entry_path)
- Imported package without verified entry-point path (imported_only)
- Transitive dependency with no source import (transitive_dependency_only)
- Disconnected package (no_path_found, explicitly not safe)
- Multiple paths to one finding without duplicate findings
- Deterministic scoring, tie-breaking, and expected rank order
- Missing severity or incomplete graph evidence
- Upgrade candidates that do and do not resolve an advisory
- End-to-end integration on FalkorGraph (when FalkorDB available)
"""
from __future__ import annotations

import pytest

from app.db.falkordb import create_redis_client, probe_falkordb
from app.db.graph import FalkorGraph
from app.services.graph_builder import upsert_fixture_graph
from app.services.graph_queries import (
    finding_paths,
    list_findings,
    list_upgrade_candidates,
)
from app.services.risk_engine import (
    CATEGORY_CONFIRMED_ENTRY,
    CATEGORY_IMPORTED_ONLY,
    CATEGORY_NO_PATH,
    CATEGORY_TRANSITIVE_ONLY,
    EVIDENCE_WEIGHTS,
    check_version_resolves,
    classify_evidence,
    compute_compatibility_cost,
    compute_risk_score,
    evaluate_upgrade_candidates,
    parse_severity,
    rank_findings,
)

# ---------------------------------------------------------------------------
# Unit tests: Evidence Classification
# ---------------------------------------------------------------------------


def test_classify_confirmed_entry_path():
    """Direct import with verified entry point path -> confirmed_entry_path."""
    cat = classify_evidence(
        import_files_count=1,
        entry_points_count=1,
        in_dependency_tree=True,
        is_transitive=False,
    )
    assert cat == CATEGORY_CONFIRMED_ENTRY


def test_classify_imported_only():
    """Import exists in a source file, but no verified entry point reaches it."""
    cat = classify_evidence(
        import_files_count=2,
        entry_points_count=0,
        in_dependency_tree=True,
        is_transitive=False,
    )
    assert cat == CATEGORY_IMPORTED_ONLY


def test_classify_transitive_dependency_only():
    """Package is in dependency tree, but no source file imports it."""
    cat = classify_evidence(
        import_files_count=0,
        entry_points_count=0,
        in_dependency_tree=True,
        is_transitive=True,
    )
    assert cat == CATEGORY_TRANSITIVE_ONLY


def test_classify_no_path_found():
    """Package is disconnected from dependency graph and has no imports."""
    cat = classify_evidence(
        import_files_count=0,
        entry_points_count=0,
        in_dependency_tree=False,
        is_transitive=False,
    )
    assert cat == CATEGORY_NO_PATH


# ---------------------------------------------------------------------------
# Unit tests: Severity Parsing and Risk Scoring
# ---------------------------------------------------------------------------


def test_parse_severity_numeric():
    score, est = parse_severity(7.5)
    assert score == 7.5
    assert est is False

    score_str, est_str = parse_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8")
    assert score_str == 9.8
    assert est_str is False


def test_parse_severity_qualitative():
    assert parse_severity("critical") == (9.5, False)
    assert parse_severity("HIGH") == (8.0, False)
    assert parse_severity("moderate") == (5.5, False)
    assert parse_severity("medium") == (5.5, False)
    assert parse_severity("low") == (2.5, False)
    assert parse_severity("none") == (0.0, False)


def test_parse_severity_missing_or_unknown():
    score, est = parse_severity(None)
    assert score == 5.0
    assert est is True

    score_unk, est_unk = parse_severity("unspecified_vendor_rating")
    assert score_unk == 5.0
    assert est_unk is True


def test_compute_risk_score_confirmed_entry():
    """High severity with confirmed_entry_path has full weight (1.0)."""
    res = compute_risk_score("high", CATEGORY_CONFIRMED_ENTRY)
    assert res["severity_score"] == 8.0
    assert res["evidence_weight"] == 1.0
    assert res["risk_score"] == 8.0
    assert res["evidence_category"] == CATEGORY_CONFIRMED_ENTRY


def test_compute_risk_score_no_path_not_safe():
    """no_path_found is downweighted (0.1) but explicitly never 0 (not safe)."""
    res = compute_risk_score("high", CATEGORY_NO_PATH)
    assert res["severity_score"] == 8.0
    assert res["evidence_weight"] == 0.1
    assert res["risk_score"] == 0.8
    # Must disclose that no_path_found is not proof of safety
    assert any("NOT proof that the package is safe" in note for note in res["limitations"])


def test_risk_weight_ranking_inversion():
    """A High finding with confirmed reachability outranks a Critical finding with no path."""
    high_reachable = compute_risk_score("high", CATEGORY_CONFIRMED_ENTRY)  # 8.0 * 1.0 = 8.0
    critical_dormant = compute_risk_score("critical", CATEGORY_NO_PATH)    # 9.5 * 0.1 = 0.95
    assert high_reachable["risk_score"] > critical_dormant["risk_score"]


# ---------------------------------------------------------------------------
# Unit tests: Deterministic Finding Ranking and Tie-breaking
# ---------------------------------------------------------------------------


def test_deterministic_rank_order():
    """Findings are ranked deterministically by risk_score DESC."""
    findings = [
        {
            "finding_id": "vuln:3",
            "advisory_id": "GHSA-dormant",
            "severity": "critical",
            "evidence_category": CATEGORY_TRANSITIVE_ONLY,  # 9.5 * 0.4 = 3.8
            "package_key": "npm:minimist@1.2.5",
        },
        {
            "finding_id": "vuln:1",
            "advisory_id": "GHSA-reachable",
            "severity": "high",
            "evidence_category": CATEGORY_CONFIRMED_ENTRY,  # 8.0 * 1.0 = 8.0
            "package_key": "npm:lodash@4.17.21",
        },
        {
            "finding_id": "vuln:2",
            "advisory_id": "GHSA-imported",
            "severity": "high",
            "evidence_category": CATEGORY_IMPORTED_ONLY,    # 8.0 * 0.7 = 5.6
            "package_key": "npm:axios@0.21.1",
        },
        {
            "finding_id": "vuln:4",
            "advisory_id": "GHSA-unreachable",
            "severity": "low",
            "evidence_category": CATEGORY_NO_PATH,          # 2.5 * 0.1 = 0.25
            "package_key": "npm:debug@2.6.9",
        },
    ]

    ranked = rank_findings(findings)

    assert [r["advisory_id"] for r in ranked] == [
        "GHSA-reachable",    # 8.0
        "GHSA-imported",     # 5.6
        "GHSA-dormant",      # 3.8
        "GHSA-unreachable",  # 0.25
    ]
    assert [r["rank"] for r in ranked] == [1, 2, 3, 4]


def test_tie_breaking_order():
    """When risk scores match, tie-break by evidence priority, then advisory_id."""
    findings = [
        {
            "finding_id": "vuln:b",
            "advisory_id": "GHSA-bbbb",
            "severity": "high",
            "evidence_category": CATEGORY_CONFIRMED_ENTRY,  # 8.0
            "package_key": "npm:pkg-b@1.0.0",
        },
        {
            "finding_id": "vuln:a",
            "advisory_id": "GHSA-aaaa",
            "severity": "high",
            "evidence_category": CATEGORY_CONFIRMED_ENTRY,  # 8.0
            "package_key": "npm:pkg-a@1.0.0",
        },
    ]

    ranked = rank_findings(findings)
    # Both have risk_score 8.0 and same category; GHSA-aaaa should come first alphabetically
    assert ranked[0]["advisory_id"] == "GHSA-aaaa"
    assert ranked[1]["advisory_id"] == "GHSA-bbbb"


# ---------------------------------------------------------------------------
# Unit tests: Upgrade Candidate Resolution & Compatibility Cost
# ---------------------------------------------------------------------------


def test_compatibility_cost_heuristics():
    assert compute_compatibility_cost("4.17.21", "4.17.22") == "patch"
    assert compute_compatibility_cost("4.17.21", "4.18.0") == "minor"
    assert compute_compatibility_cost("1.2.5", "2.0.0") == "major"
    assert compute_compatibility_cost("invalid", "1.0.0") == "unknown"


def test_check_version_resolves_range():
    # Affected <=4.17.21: 4.17.22 resolves it, 4.17.20 does not
    assert check_version_resolves("4.17.22", "<=4.17.21") is True
    assert check_version_resolves("4.17.21", "<=4.17.21") is False
    assert check_version_resolves("4.17.15", "<=4.17.21") is False

    # Affected <1.2.6: 1.2.6 resolves it, 1.2.5 does not
    assert check_version_resolves("1.2.6", "<1.2.6") is True
    assert check_version_resolves("1.2.5", "<1.2.6") is False


def test_check_version_resolves_fixed_version():
    assert check_version_resolves("4.17.22", None, fixed_version="4.17.22") is True
    assert check_version_resolves("4.17.21", None, fixed_version="4.17.22") is False


def test_check_version_resolves_unverified_when_missing():
    """Missing or unparseable range must return None (unverified), never True."""
    assert check_version_resolves("4.17.22", None, fixed_version=None) is None
    assert check_version_resolves("4.17.22", "", fixed_version=None) is None
    assert check_version_resolves("4.17.22", "unparseable_custom_syntax") is None


def test_evaluate_upgrade_candidates_ranking():
    findings = [
        {
            "package_name": "lodash",
            "advisory_id": "GHSA-lodash-1",
            "affected_range": "<=4.17.21",
            "risk_score": 8.0,
            "evidence_category": CATEGORY_CONFIRMED_ENTRY,
        },
        {
            "package_name": "minimist",
            "advisory_id": "GHSA-minimist-1",
            "affected_range": "<1.2.6",
            "risk_score": 3.8,
            "evidence_category": CATEGORY_TRANSITIVE_ONLY,
        },
    ]

    candidates = [
        {
            "candidate_key": "upgrade:lodash:4.17.21->4.17.22",
            "package_name": "lodash",
            "from_version": "4.17.21",
            "to_version": "4.17.22",
            "compatibility_cost": "patch",
        },
        {
            "candidate_key": "upgrade:minimist:1.2.5->1.2.6",
            "package_name": "minimist",
            "from_version": "1.2.5",
            "to_version": "1.2.6",
            "compatibility_cost": "patch",
        },
    ]

    ranked_cands = evaluate_upgrade_candidates(candidates, findings)
    assert len(ranked_cands) == 2
    # Lodash candidate resolves 8.0 risk; Minimist resolves 3.8 risk -> Lodash ranks #1
    assert ranked_cands[0]["package_name"] == "lodash"
    assert ranked_cands[0]["resolved_findings_count"] == 1
    assert ranked_cands[0]["risk_eliminated"] == 8.0
    assert ranked_cands[0]["rank"] == 1

    assert ranked_cands[1]["package_name"] == "minimist"
    assert ranked_cands[1]["risk_eliminated"] == 3.8
    assert ranked_cands[1]["rank"] == 2


# ---------------------------------------------------------------------------
# Integration tests with FalkorGraph (when FalkorDB is live)
# ---------------------------------------------------------------------------

GRAPH_NAME = "blast_radius_m5_test"


@pytest.fixture
def test_graph_client():
    client = create_redis_client()
    probe = probe_falkordb(client)
    if not probe.connected:
        client.close()
        pytest.skip("FalkorDB unavailable for integration tests")
    graph = FalkorGraph(client, GRAPH_NAME)
    graph.delete()
    yield client
    FalkorGraph(client, GRAPH_NAME).delete()
    client.close()


def test_graph_query_all_four_evidence_categories(test_graph_client):
    """Build a synthetic graph with packages representing all 4 categories:

    1. lodash: direct, imported, entry point -> confirmed_entry_path
    2. express: direct, imported, NO entry point -> imported_only
    3. minimist: transitive dependency, no import -> transitive_dependency_only
    4. orphan: disconnected from dependency graph and files -> no_path_found
    """
    model = {
        "project": {"project_id": "test-repo", "name": "test-repo", "root_label": "test"},
        "packages": [
            {"name": "test-repo", "version": "1.0.0", "ecosystem": "npm", "direct": True, "declared_constraint": "1.0.0"},
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm", "direct": True, "declared_constraint": "^4.17.0"},
            {"name": "express", "version": "4.17.1", "ecosystem": "npm", "direct": True, "declared_constraint": "^4.17.0"},
            {"name": "minimist", "version": "1.2.5", "ecosystem": "npm", "direct": False, "declared_constraint": "1.2.5"},
            {"name": "orphan", "version": "0.1.0", "ecosystem": "npm", "direct": False, "declared_constraint": "0.1.0"},
        ],
        "dependencies": [
            {"from": ["npm", "test-repo", "1.0.0"], "to": ["npm", "lodash", "4.17.21"], "direct": True, "constraint": "^4.17.0", "source": "test"},
            {"from": ["npm", "test-repo", "1.0.0"], "to": ["npm", "express", "4.17.1"], "direct": True, "constraint": "^4.17.0", "source": "test"},
            {"from": ["npm", "lodash", "4.17.21"], "to": ["npm", "minimist", "1.2.5"], "direct": False, "constraint": "1.2.5", "source": "test"},
            # Notice orphan has no DEPENDS_ON edge from test-repo or any package
        ],
        "files": [
            {"relative_path": "src/index.js", "language": "javascript"},
            {"relative_path": "src/helper.js", "language": "javascript"},
        ],
        "imports": [
            {"file": "src/index.js", "package": ["npm", "lodash", "4.17.21"]},
            {"file": "src/helper.js", "package": ["npm", "express", "4.17.1"]},
        ],
        "entry_points": [
            {"relative_path": "src/index.js", "kind": "main", "evidence_source": "package.json main"},
        ],
        "reaches": [
            {"entry": "src/index.js", "file": "src/index.js", "evidence_type": "entry_is_file", "confidence_label": "potentially_reachable"},
            # helper.js is NOT reached by any entry point
        ],
        "vulnerabilities": [
            {
                "advisory_id": "VULN-LODASH",
                "severity": "high",
                "summary": "Lodash vuln",
                "source": "test",
                "source_timestamp": "2026-10-16T00:00:00Z",
                "fixture": True,
                "affected": {"package": ["npm", "lodash", "4.17.21"], "range": "<=4.17.21"},
            },
            {
                "advisory_id": "VULN-EXPRESS",
                "severity": "high",
                "summary": "Express vuln",
                "source": "test",
                "source_timestamp": "2026-10-16T00:00:00Z",
                "fixture": True,
                "affected": {"package": ["npm", "express", "4.17.1"], "range": "<=4.17.1"},
            },
            {
                "advisory_id": "VULN-MINIMIST",
                "severity": "critical",
                "summary": "Minimist vuln",
                "source": "test",
                "source_timestamp": "2026-10-16T00:00:00Z",
                "fixture": True,
                "affected": {"package": ["npm", "minimist", "1.2.5"], "range": "<=1.2.5"},
            },
            {
                "advisory_id": "VULN-ORPHAN",
                "severity": "high",
                "summary": "Orphan vuln",
                "source": "test",
                "source_timestamp": "2026-10-16T00:00:00Z",
                "fixture": True,
                "affected": {"package": ["npm", "orphan", "0.1.0"], "range": "<=0.1.0"},
            },
        ],
        "upgrade_candidates": [
            {
                "package_name": "lodash",
                "from_version": "4.17.21",
                "to_version": "4.17.22",
                "compatibility_cost": "patch",
            }
        ],
    }

    upsert_fixture_graph(test_graph_client, GRAPH_NAME, model, scan_id="scan-m5-test")
    graph = FalkorGraph(test_graph_client, GRAPH_NAME)

    findings = list_findings(graph)
    assert len(findings) == 4

    by_id = {f["advisory_id"]: f for f in findings}

    # 1. Lodash has verified entry-point path
    assert by_id["VULN-LODASH"]["evidence_category"] == CATEGORY_CONFIRMED_ENTRY
    assert by_id["VULN-LODASH"]["evidence_weight"] == 1.0
    assert by_id["VULN-LODASH"]["risk_score"] == 8.0

    # 2. Express has source import but no entry point
    assert by_id["VULN-EXPRESS"]["evidence_category"] == CATEGORY_IMPORTED_ONLY
    assert by_id["VULN-EXPRESS"]["evidence_weight"] == 0.7
    assert by_id["VULN-EXPRESS"]["risk_score"] == 5.6

    # 3. Minimist is transitive dependency with no source import
    assert by_id["VULN-MINIMIST"]["evidence_category"] == CATEGORY_TRANSITIVE_ONLY
    assert by_id["VULN-MINIMIST"]["evidence_weight"] == 0.4
    assert by_id["VULN-MINIMIST"]["risk_score"] == 3.8  # 9.5 * 0.4 = 3.8

    # 4. Orphan has no path in dependency graph or imports
    assert by_id["VULN-ORPHAN"]["evidence_category"] == CATEGORY_NO_PATH
    assert by_id["VULN-ORPHAN"]["evidence_weight"] == 0.1
    assert by_id["VULN-ORPHAN"]["risk_score"] == 0.8

    # Check rank order: Lodash (8.0) > Express (5.6) > Minimist (3.8) > Orphan (0.8)
    assert [f["advisory_id"] for f in findings] == [
        "VULN-LODASH",
        "VULN-EXPRESS",
        "VULN-MINIMIST",
        "VULN-ORPHAN",
    ]


def test_multiple_paths_do_not_duplicate_finding(test_graph_client):
    """When multiple files import a package, the finding appears exactly once."""
    model = {
        "project": {"project_id": "multi-path-repo", "name": "multi-path-repo", "root_label": "test"},
        "packages": [
            {"name": "multi-path-repo", "version": "1.0.0", "ecosystem": "npm", "direct": True, "declared_constraint": "1.0.0"},
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm", "direct": True, "declared_constraint": "^4.17.0"},
        ],
        "dependencies": [
            {"from": ["npm", "multi-path-repo", "1.0.0"], "to": ["npm", "lodash", "4.17.21"], "direct": True, "constraint": "^4.17.0", "source": "test"},
        ],
        "files": [
            {"relative_path": "src/a.js", "language": "javascript"},
            {"relative_path": "src/b.js", "language": "javascript"},
            {"relative_path": "src/c.js", "language": "javascript"},
        ],
        "imports": [
            {"file": "src/a.js", "package": ["npm", "lodash", "4.17.21"]},
            {"file": "src/b.js", "package": ["npm", "lodash", "4.17.21"]},
            {"file": "src/c.js", "package": ["npm", "lodash", "4.17.21"]},
        ],
        "entry_points": [
            {"relative_path": "src/a.js", "kind": "main", "evidence_source": "test"},
            {"relative_path": "src/b.js", "kind": "bin", "evidence_source": "test"},
        ],
        "reaches": [
            {"entry": "src/a.js", "file": "src/a.js", "evidence_type": "entry_is_file", "confidence_label": "potentially_reachable"},
            {"entry": "src/b.js", "file": "src/b.js", "evidence_type": "entry_is_file", "confidence_label": "potentially_reachable"},
        ],
        "vulnerabilities": [
            {
                "advisory_id": "VULN-MULTI-PATH",
                "severity": "high",
                "summary": "Multi path vuln",
                "source": "test",
                "source_timestamp": "2026-10-16T00:00:00Z",
                "fixture": True,
                "affected": {"package": ["npm", "lodash", "4.17.21"], "range": "<=4.17.21"},
            }
        ],
        "upgrade_candidates": [],
    }

    upsert_fixture_graph(test_graph_client, GRAPH_NAME, model, scan_id="scan-multi-test")
    graph = FalkorGraph(test_graph_client, GRAPH_NAME)

    findings = list_findings(graph)
    # MUST have exactly 1 finding, NOT 2 or 3!
    assert len(findings) == 1
    assert findings[0]["advisory_id"] == "VULN-MULTI-PATH"
    assert findings[0]["import_files_count"] == 3
    assert findings[0]["entry_points_count"] == 2
    assert findings[0]["evidence_category"] == CATEGORY_CONFIRMED_ENTRY

    # But finding_paths returns both reaching paths
    paths = finding_paths(graph, findings[0]["finding_id"])
    assert len(paths) == 2
