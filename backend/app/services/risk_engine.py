"""Deterministic risk-path scoring, evidence classification, and remediation ranking.

Principles
----------
1. Purely deterministic Python: scores, weights, and rank orders are
   calculated from graph evidence and advisory metadata, never LLM conjecture.
2. Evidence categories reflect structural graph facts:
   - ``confirmed_entry_path``: verified path from known entry point -> source file import -> package.
   - ``imported_only``: source file imports package, but no entry-point path found.
   - ``transitive_dependency_only``: package in dependency graph, but no direct source import found.
   - ``no_path_found``: no qualifying path found in analyzed graph. Never claimed as "safe".
3. Upgrade candidates:
   - An upgrade is only marked as resolving an advisory if the candidate target version
     can be verified against the advisory's affected ranges or fixed version.
   - Semver distance is a heuristic, not a guarantee of compatibility.
4. Transparent formulas with explicit tie-breakers and disclosures of limitations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.services.semver_evaluator import (
    NpmRange,
    NpmVersion,
    is_upgrade_a_fix,
)

# ---------------------------------------------------------------------------
# Constants and Weights
# ---------------------------------------------------------------------------

CATEGORY_CONFIRMED_ENTRY = "confirmed_entry_path"
CATEGORY_IMPORTED_ONLY = "imported_only"
CATEGORY_TRANSITIVE_ONLY = "transitive_dependency_only"
CATEGORY_NO_PATH = "no_path_found"

ALL_CATEGORIES = (
    CATEGORY_CONFIRMED_ENTRY,
    CATEGORY_IMPORTED_ONLY,
    CATEGORY_TRANSITIVE_ONLY,
    CATEGORY_NO_PATH,
)

EVIDENCE_WEIGHTS: dict[str, float] = {
    CATEGORY_CONFIRMED_ENTRY: 1.0,
    CATEGORY_IMPORTED_ONLY: 0.7,
    CATEGORY_TRANSITIVE_ONLY: 0.4,
    CATEGORY_NO_PATH: 0.1,
}

EVIDENCE_PRIORITIES: dict[str, int] = {
    CATEGORY_CONFIRMED_ENTRY: 4,
    CATEGORY_IMPORTED_ONLY: 3,
    CATEGORY_TRANSITIVE_ONLY: 2,
    CATEGORY_NO_PATH: 1,
}

QUALITATIVE_SEVERITY_SCORES: dict[str, float] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "moderate": 5.5,
    "low": 2.5,
    "none": 0.0,
}

DEFAULT_SEVERITY_SCORE = 5.0

COMPATIBILITY_COST_ORDER = {"patch": 1, "minor": 2, "major": 3, "unknown": 4}


# ---------------------------------------------------------------------------
# Classification & Scoring Helpers
# ---------------------------------------------------------------------------


def classify_evidence(
    import_files_count: int,
    entry_points_count: int,
    in_dependency_tree: bool = False,
    is_transitive: bool = False,
) -> str:
    """Classify structural path evidence into one of 4 strict categories.

    Parameters
    ----------
    import_files_count:
        Number of distinct project source files that statically import this package.
    entry_points_count:
        Number of distinct verified entry points reaching at least one importing file.
    in_dependency_tree:
        Whether the package is connected in the project's dependency graph.
    is_transitive:
        Optional extra flag; preserved for signature compatibility.

    Returns
    -------
    str
        One of ``confirmed_entry_path``, ``imported_only``,
        ``transitive_dependency_only``, or ``no_path_found``.
    """
    if import_files_count > 0:
        if entry_points_count > 0:
            return CATEGORY_CONFIRMED_ENTRY
        return CATEGORY_IMPORTED_ONLY

    if in_dependency_tree:
        return CATEGORY_TRANSITIVE_ONLY

    return CATEGORY_NO_PATH


def parse_severity(raw_severity: Any) -> tuple[float, bool]:
    """Parse severity string/float into a normalized score [0.0 - 10.0].

    Returns (score, is_estimated).
    """
    if raw_severity is None:
        return DEFAULT_SEVERITY_SCORE, True

    if isinstance(raw_severity, (int, float)):
        score = max(0.0, min(10.0, float(raw_severity)))
        return round(score, 1), False

    s = str(raw_severity).strip().lower()
    if not s:
        return DEFAULT_SEVERITY_SCORE, True

    # If it is a CVSS vector string, extract the score component
    # e.g. "CVSS:3.1/.../9.8" -> 9.8 (or standalone "7.5")
    # Avoid picking up "3.1" or "3.0" which is the CVSS version prefix
    if "cvss" in s:
        cleaned_cvss = re.sub(r"^cvss:\s*[0-9]+(?:\.[0-9]+)?/?", "", s)
        matches = re.findall(r"\b\d{1,2}(?:\.\d+)?\b", cleaned_cvss)
        if matches:
            try:
                val = float(matches[-1])
                if 0.0 <= val <= 10.0:
                    return round(val, 1), False
            except ValueError:
                pass
    else:
        num_match = re.search(r"^\s*(\d{1,2}(?:\.\d+)?)\s*$", s)
        if num_match:
            try:
                val = float(num_match.group(1))
                if 0.0 <= val <= 10.0:
                    return round(val, 1), False
            except ValueError:
                pass

    # Check qualitative keywords
    for keyword, val in QUALITATIVE_SEVERITY_SCORES.items():
        if keyword in s:
            return val, False

    return DEFAULT_SEVERITY_SCORE, True


def compute_risk_score(
    raw_severity: Any,
    evidence_category: str,
) -> dict[str, Any]:
    """Calculate deterministic risk score from severity and evidence category.

    Formula
    -------
    ``risk_score = round(severity_score * evidence_weight, 2)``

    Returns dictionary with score breakdown and limitations disclosure.
    """
    severity_score, severity_estimated = parse_severity(raw_severity)
    weight = EVIDENCE_WEIGHTS.get(evidence_category, 0.1)
    risk_score = round(severity_score * weight, 2)

    limitations: list[str] = [
        "Risk score reflects structural path evidence and advisory severity; not proof of runtime exploitability.",
    ]
    if evidence_category == CATEGORY_NO_PATH:
        limitations.append(
            "no_path_found indicates no qualifying path in the analyzed graph. It is NOT proof that the package is safe."
        )
    if severity_estimated:
        limitations.append(
            "Advisory did not specify standard severity; assigned baseline score 5.0."
        )

    return {
        "risk_score": risk_score,
        "severity_score": severity_score,
        "severity_estimated": severity_estimated,
        "evidence_weight": weight,
        "evidence_category": evidence_category,
        "limitations": limitations,
    }


def rank_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort findings deterministically by risk score and tie-breakers.

    Tie-breaking hierarchy
    ----------------------
    1. ``risk_score`` DESC
    2. ``evidence_priority`` DESC (confirmed_entry_path > imported_only > transitive_dependency_only > no_path_found)
    3. ``severity_score`` DESC
    4. ``advisory_id`` ASC (lexicographical)
    5. ``package_key`` ASC (lexicographical)

    Returns a new list with ``rank`` (1-based) attached to each finding.
    """
    enriched: list[dict[str, Any]] = []
    for f in findings:
        item = dict(f)
        category = item.get("evidence_category") or CATEGORY_NO_PATH
        if category not in ALL_CATEGORIES:
            category = CATEGORY_NO_PATH

        calc = compute_risk_score(item.get("severity"), category)
        item["risk_score"] = calc["risk_score"]
        item["severity_score"] = calc["severity_score"]
        item["severity_estimated"] = calc["severity_estimated"]
        item["evidence_weight"] = calc["evidence_weight"]
        item["evidence_category"] = category
        item["evidence_priority"] = EVIDENCE_PRIORITIES.get(category, 0)
        item["limitations"] = calc["limitations"]

        enriched.append(item)

    # Deterministic sort
    enriched.sort(
        key=lambda x: (
            -x["risk_score"],
            -x["evidence_priority"],
            -x["severity_score"],
            str(x.get("advisory_id") or ""),
            str(x.get("package_key") or ""),
        )
    )

    for i, item in enumerate(enriched, start=1):
        item["rank"] = i

    return enriched


# ---------------------------------------------------------------------------
# Upgrade Candidate Resolution & Semver Heuristics
# ---------------------------------------------------------------------------


def parse_clean_version(ver_str: str) -> NpmVersion | None:
    """Safely parse semver string with NpmVersion."""
    return NpmVersion.parse(ver_str)


def compute_compatibility_cost(from_version: str, to_version: str) -> str:
    """Determine semver change distance as a compatibility heuristic.

    Heuristic
    ---------
    - ``patch``: same major and minor, different patch (e.g. 4.17.21 -> 4.17.22)
    - ``minor``: same major, different minor (e.g. 4.17.21 -> 4.18.0)
    - ``major``: different major (e.g. 1.2.5 -> 2.0.0)
    - ``unknown``: unparseable version string
    """
    v_from = NpmVersion.parse(from_version)
    v_to = NpmVersion.parse(to_version)
    if not v_from or not v_to:
        return "unknown"

    if v_from.major != v_to.major:
        return "major"
    if v_from.minor != v_to.minor:
        return "minor"
    return "patch"


def check_version_resolves(
    target_version: str,
    affected_range: str | None = None,
    fixed_version: str | None = None,
    osv_ranges: list[Any] | None = None,
    affected_versions: list[str] | None = None,
) -> bool | None:
    """Check if target_version resolves an advisory using NpmRange and OSV events.

    Returns
    -------
    bool:
        True if target_version is verified outside the affected range / >= fixed version.
        False if target_version is verified inside the affected range.
    None:
        If insufficient advisory information is available to make a verified claim.
    """
    return is_upgrade_a_fix(
        target_version=target_version,
        affected_range=affected_range,
        fixed_version=fixed_version,
        osv_ranges=osv_ranges,
        affected_versions=affected_versions,
    )


def evaluate_upgrade_candidates(
    candidates: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Evaluate and rank upgrade options against verified advisory findings.

    Rules
    -----
    - Only claim a finding is addressed if target version is verified outside the affected range.
    - If version information is insufficient, mark as unverified and do NOT count as resolved.
    - Rank candidates by:
      1. Number of verified resolved findings DESC
      2. Total risk score eliminated DESC
      3. Compatibility cost penalty (patch > minor > major > unknown)
      4. Target version DESC
    """
    evaluated: list[dict[str, Any]] = []

    for cand in candidates:
        pkg_name = cand.get("package_name")
        from_ver = cand.get("from_version", "")
        to_ver = cand.get("to_version", "")

        # Filter out downgrades and same-version candidates before evaluation.
        # Only genuine upgrades (to_version > from_version) are valid candidates.
        from_parsed = NpmVersion.parse(from_ver)
        to_parsed = NpmVersion.parse(to_ver)
        if from_parsed and to_parsed and not (to_parsed > from_parsed):
            continue

        cost = cand.get("compatibility_cost") or compute_compatibility_cost(from_ver, to_ver)

        matching_findings = [
            f for f in findings
            if f.get("package_name") == pkg_name
        ]

        resolved_findings: list[dict[str, Any]] = []
        unresolved_findings: list[dict[str, Any]] = []
        unverified_findings: list[dict[str, Any]] = []
        risk_eliminated = 0.0

        for f in matching_findings:
            range_info = f.get("affected_range") or f.get("range")
            fixed_ver = f.get("fixed_version")
            osv_ranges = f.get("affected_ranges") or f.get("osv_ranges")
            affected_versions = f.get("affected_versions")
            resolves = check_version_resolves(
                target_version=to_ver,
                affected_range=range_info,
                fixed_version=fixed_ver,
                osv_ranges=osv_ranges,
                affected_versions=affected_versions,
            )

            if resolves is True:
                resolved_findings.append({
                    "advisory_id": f.get("advisory_id"),
                    "risk_score": f.get("risk_score", 0.0),
                    "evidence_category": f.get("evidence_category"),
                })
                risk_eliminated += float(f.get("risk_score", 0.0))
            elif resolves is False:
                unresolved_findings.append({
                    "advisory_id": f.get("advisory_id"),
                    "reason": "target version remains inside affected range",
                })
            else:
                unverified_findings.append({
                    "advisory_id": f.get("advisory_id"),
                    "reason": "insufficient advisory version range data",
                })

        evaluated.append({
            "candidate_key": cand.get("candidate_key"),
            "package_name": pkg_name,
            "from_version": from_ver,
            "to_version": to_ver,
            "compatibility_cost": cost,
            "resolved_findings_count": len(resolved_findings),
            "resolved_findings": resolved_findings,
            "unresolved_findings_count": len(unresolved_findings),
            "unresolved_findings": unresolved_findings,
            "unverified_findings_count": len(unverified_findings),
            "unverified_findings": unverified_findings,
            "risk_eliminated": round(risk_eliminated, 2),
            "cost_order": COMPATIBILITY_COST_ORDER.get(cost, 99),
        })

    # Deterministic candidate ranking
    evaluated.sort(
        key=lambda x: (
            -x["resolved_findings_count"],
            -x["risk_eliminated"],
            x["cost_order"],
            str(x.get("to_version") or ""),
        )
    )

    for i, item in enumerate(evaluated, start=1):
        item["rank"] = i

    return evaluated
