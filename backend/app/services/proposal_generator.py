"""Remediation proposal and patch generator service.

Generates reviewable manifest diffs, evidence-based rationales, and lockfile guidance
without ever executing target code or invoking package managers.
"""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import Any

from app.services.semver_evaluator import NpmVersion


def _update_manifest_json(manifest_data: dict[str, Any], package_name: str, to_version: str) -> tuple[dict[str, Any], str]:
    """Return updated manifest dict and modification type ('direct' | 'override')."""
    updated = json.loads(json.dumps(manifest_data))  # deep copy
    is_direct = False

    # Check dependencies
    if isinstance(updated.get("dependencies"), dict) and package_name in updated["dependencies"]:
        current_constraint = str(updated["dependencies"][package_name])
        prefix = "^" if current_constraint.startswith("^") else ("~" if current_constraint.startswith("~") else "")
        updated["dependencies"][package_name] = f"{prefix}{to_version}"
        return updated, "direct"

    # Check devDependencies
    if isinstance(updated.get("devDependencies"), dict) and package_name in updated["devDependencies"]:
        current_constraint = str(updated["devDependencies"][package_name])
        prefix = "^" if current_constraint.startswith("^") else ("~" if current_constraint.startswith("~") else "")
        updated["devDependencies"][package_name] = f"{prefix}{to_version}"
        return updated, "direct"

    # Transitive dependency: add or update npm "overrides"
    overrides = updated.get("overrides")
    if not isinstance(overrides, dict):
        overrides = {}
        updated["overrides"] = overrides

    overrides[package_name] = f"^{to_version}"
    return updated, "override"


def generate_manifest_diff(
    manifest_text: str,
    package_name: str,
    to_version: str,
) -> tuple[str, str]:
    """Generate a unified diff for package.json upgrading package_name to to_version.

    Returns (diff_text, patch_type).
    """
    try:
        manifest_data = json.loads(manifest_text)
    except Exception:
        # Fallback raw line replacement if invalid JSON
        lines = manifest_text.splitlines(keepends=True)
        return "", "error"

    updated_data, patch_type = _update_manifest_json(manifest_data, package_name, to_version)

    # Format updated JSON preserving standard 2-space indentation
    original_lines = manifest_text.splitlines()
    updated_formatted = json.dumps(updated_data, indent=2)
    updated_lines = updated_formatted.splitlines()

    diff = list(
        difflib.unified_diff(
            original_lines,
            updated_lines,
            fromfile="a/package.json",
            tofile="b/package.json",
            lineterm="",
        )
    )

    diff_text = "\n".join(diff) if diff else ""
    return diff_text, patch_type


def generate_evidence_rationale(
    candidate: dict[str, Any],
    resolved_findings: list[dict[str, Any]],
    is_fixture: bool,
) -> str:
    """Generate an evidence-backed explanation grounded in graph paths and advisory data."""
    pkg = candidate.get("package_name")
    from_ver = candidate.get("from_version")
    to_ver = candidate.get("to_version")
    cost = candidate.get("compatibility_cost", "unknown")
    risk_pts = candidate.get("risk_eliminated", 0.0)

    if not resolved_findings:
        return (
            f"Upgrade of {pkg} from {from_ver} to {to_ver} does not resolve any verified findings "
            f"under current advisory version range metadata."
        )

    advisory_ids = ", ".join(f.get("advisory_id", "") for f in resolved_findings)
    categories = list({f.get("evidence_category", "").replace("_", " ") for f in resolved_findings if f.get("evidence_category")})
    cats_str = " and ".join(categories) if categories else "dependency tree"

    prefix = "[SIMULATED DEMO] " if is_fixture else ""

    rationale = (
        f"{prefix}Upgrading {pkg} from {from_ver} to {to_ver} eliminates {risk_pts:.1f} risk score points "
        f"across {len(resolved_findings)} verified advisory finding(s): {advisory_ids}. "
        f"Graph analysis confirmed {cats_str} reachability for these findings. "
        f"The upgrade has an estimated compatibility cost of '{cost}' (SemVer distance). "
        f"Verified target version {to_ver} falls outside all reported affected vulnerability ranges."
    )
    return rationale


def build_remediation_proposal(
    candidate: dict[str, Any],
    manifest_text: str | None,
    is_fixture: bool = False,
) -> dict[str, Any]:
    """Build a complete, reviewable remediation proposal for a candidate."""
    pkg_name = candidate.get("package_name", "")
    from_ver = candidate.get("from_version", "")
    to_ver = candidate.get("to_version", "")
    cost = candidate.get("compatibility_cost", "unknown")
    resolved = candidate.get("resolved_findings", [])
    unresolved = candidate.get("unresolved_findings", [])
    unverified = candidate.get("unverified_findings", [])

    diff_text = ""
    patch_type = "unknown"
    if manifest_text:
        diff_text, patch_type = generate_manifest_diff(manifest_text, pkg_name, to_ver)

    lockfile_guidance = (
        "Safe Lockfile Guidance: BlastRadius does not invoke npm or run lifecycle scripts. "
        "After reviewing and applying the package.json diff, update package-lock.json safely by running:\n"
        "  npm install --package-lock-only --ignore-scripts"
    )

    if patch_type == "override":
        manifest_note = (
            f"Transitive Dependency: '{pkg_name}' is not directly declared in root dependencies. "
            f"A npm 'overrides' entry has been generated to enforce version ^{to_ver} across all dependency trees."
        )
    else:
        manifest_note = f"Direct Dependency: updates '{pkg_name}' version constraint in package.json."

    rationale = generate_evidence_rationale(candidate, resolved, is_fixture)

    return {
        "candidate_key": candidate.get("candidate_key"),
        "package_name": pkg_name,
        "from_version": from_ver,
        "to_version": to_ver,
        "compatibility_cost": cost,
        "is_synthetic_fixture": is_fixture,
        "manifest_path": "package.json",
        "manifest_diff": diff_text,
        "patch_type": patch_type,
        "manifest_note": manifest_note,
        "lockfile_guidance": lockfile_guidance,
        "resolved_findings_count": len(resolved),
        "unresolved_findings_count": len(unresolved),
        "unverified_findings_count": len(unverified),
        "risk_eliminated": candidate.get("risk_eliminated", 0.0),
        "rationale": rationale,
        "reachability_caveat": (
            "Reachability Caveat: Structural graph reachability confirms the package is in an import "
            "or dependency path from an entry point, but does not guarantee runtime exploitability."
        ),
        "approval_required": True,
        "approval_state": "pending_review",
    }
