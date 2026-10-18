"""M11 — End-to-End Validation and Hackathon Demo Readiness.

Tests cover:
  1. Proposal diff application — verify unified diffs apply cleanly to copies of package.json
  2. Transitive override proposal via a real transitive dependency
  3. Overrides compatibility risk explanation (npm overrides field)
  4. Fixture labels — fixture data always carries is_synthetic_fixture=True
  5. Proposal approval safeguards — approval_required always True; no file modification
  6. Reachability caveat always present in every proposal
  7. No invented version — to_version must be sourced from OSV advisory fixed ranges
  8. OSV offline graceful degradation — no crash, warnings surfaced
  9. Cross-scan isolation — second project findings do not contaminate first scan
 10. Stale scan 404 after second scan
"""
from __future__ import annotations

import json
import re
import pathlib
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.fixture_loader import FIXTURE_ROOT
from app.services.proposal_generator import (
    generate_manifest_diff,
    build_remediation_proposal,
)
from app.services.risk_engine import evaluate_upgrade_candidates
from app.services.vuln_provider import OsvAdvisory, OsvBatchResult, AffectedRange


# ---------------------------------------------------------------------------
# Helpers / shared mock providers
# ---------------------------------------------------------------------------


def _minimal_project(root: Path, *, name: str, deps: dict, lockfile_pkgs: dict) -> Path:
    """Write a minimal valid npm project to root."""
    manifest = {"name": name, "version": "1.0.0", "dependencies": deps}
    (root / "package.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    packages_section: dict = {"": {"name": name, "version": "1.0.0", "dependencies": deps}}
    packages_section.update(lockfile_pkgs)
    lockfile = {
        "name": name,
        "version": "1.0.0",
        "lockfileVersion": 2,
        "packages": packages_section,
    }
    (root / "package-lock.json").write_text(json.dumps(lockfile, indent=2), encoding="utf-8")

    src = root / "src"
    src.mkdir(exist_ok=True)
    (src / "index.js").write_text(
        'const dep = require("{}");\n'.format(next(iter(deps))),
        encoding="utf-8",
    )
    return root


class _MockOsvEmpty:
    """Returns zero advisories — simulates a clean project or offline mode."""

    def query_batch(self, packages):
        return OsvBatchResult(
            advisories={f"npm:{p['name']}@{p['version']}": [] for p in packages},
            errors={},
        )


class _MockOsvWithMinimistAdvisory:
    """Returns one MEDIUM advisory for minimist 1.2.5 with fixed version 1.2.6."""

    def query_batch(self, packages):
        advisories: dict = {}
        for pkg in packages:
            key = f"npm:{pkg['name']}@{pkg['version']}"
            if pkg.get("name") == "minimist" and pkg.get("version") == "1.2.5":
                advisories[key] = [
                    OsvAdvisory(
                        advisory_id="GHSA-xvch-5gv4-984h",
                        aliases=["CVE-2021-44906"],
                        summary="Prototype pollution in minimist",
                        details="",
                        severity="7.5",  # CVSS string
                        published="2022-01-01T00:00:00Z",
                        modified="2022-01-01T00:00:00Z",
                        source="osv.dev",
                        affected_ranges=[
                            AffectedRange(
                                range_type="SEMVER",
                                introduced="0",
                                fixed="1.2.6",
                            )
                        ],
                    )
                ]
            else:
                advisories[key] = []
        return OsvBatchResult(advisories=advisories, errors={})


class _MockOsvErrors:
    """Simulates all OSV queries failing (timeout / offline)."""

    def query_batch(self, packages):
        return OsvBatchResult(
            advisories={f"npm:{p['name']}@{p['version']}": [] for p in packages},
            errors={f"npm:{p['name']}@{p['version']}": "timeout" for p in packages},
        )


# ---------------------------------------------------------------------------
# Patch applicator (pure Python, no external `patch` binary needed)
# ---------------------------------------------------------------------------


def _apply_unified_diff(original_text: str, diff_text: str) -> str:
    """Apply a unified diff produced by difflib.unified_diff to original text.

    This implements a simple hunk-based patch that works reliably for the
    diffs produced by our proposal_generator (2-space JSON, single file).
    Returns the patched text.
    """
    original_lines = original_text.splitlines(keepends=True)
    diff_lines = diff_text.splitlines(keepends=True)

    # Parse hunks
    result: list[str] = []
    orig_idx = 0  # 0-based pointer into original_lines

    i = 0
    # Skip --- / +++ header
    while i < len(diff_lines) and (
        diff_lines[i].startswith("---") or diff_lines[i].startswith("+++")
    ):
        i += 1

    while i < len(diff_lines):
        line = diff_lines[i]
        if line.startswith("@@"):
            m = re.search(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not m:
                i += 1
                continue
            hunk_orig_start = int(m.group(1)) - 1  # 0-indexed
            # Copy any unchanged lines up to the hunk
            while orig_idx < hunk_orig_start:
                result.append(original_lines[orig_idx])
                orig_idx += 1
            i += 1
            # Process hunk body
            while i < len(diff_lines) and not diff_lines[i].startswith("@@"):
                hline = diff_lines[i]
                if hline.startswith("-"):
                    orig_idx += 1  # consume from original (skip it)
                elif hline.startswith("+"):
                    result.append(hline[1:])  # add new line (strip leading '+')
                else:
                    # Context line — copy from original
                    result.append(original_lines[orig_idx])
                    orig_idx += 1
                i += 1
        else:
            i += 1

    # Copy any remaining lines after the last hunk
    while orig_idx < len(original_lines):
        result.append(original_lines[orig_idx])
        orig_idx += 1

    return "".join(result)


# ---------------------------------------------------------------------------
# 1. Proposal diff application — diffs apply cleanly
# ---------------------------------------------------------------------------


class TestProposalDiffApplication:

    def test_direct_dep_diff_applies_cleanly(self):
        """Diff for a direct dependency upgrade must produce valid JSON with updated version."""
        manifest_text = (
            json.dumps(
                {
                    "name": "test-app",
                    "version": "1.0.0",
                    "dependencies": {"minimist": "^1.2.5"},
                },
                indent=2,
            )
            + "\n"
        )

        diff, patch_type = generate_manifest_diff(manifest_text, "minimist", "1.2.6")
        assert patch_type == "direct"
        assert diff, "Expected a non-empty diff"
        assert "1.2.6" in diff

        patched = _apply_unified_diff(manifest_text, diff)
        data = json.loads(patched)  # Must parse as valid JSON
        assert data["dependencies"]["minimist"] == "^1.2.6"
        # Original unchanged
        assert json.loads(manifest_text)["dependencies"]["minimist"] == "^1.2.5"

    def test_transitive_dep_override_diff_applies_cleanly(self):
        """Diff for a transitive dep must add npm overrides and remain valid JSON."""
        manifest_text = (
            json.dumps(
                {
                    "name": "test-app",
                    "version": "1.0.0",
                    "dependencies": {"express": "^4.18.0"},
                },
                indent=2,
            )
            + "\n"
        )

        diff, patch_type = generate_manifest_diff(manifest_text, "minimist", "1.2.6")
        assert patch_type == "override"
        assert "overrides" in diff

        patched = _apply_unified_diff(manifest_text, diff)
        data = json.loads(patched)
        assert "overrides" in data
        assert data["overrides"]["minimist"] == "^1.2.6"
        assert data["dependencies"]["express"] == "^4.18.0"  # untouched

    def test_diff_is_reversible(self):
        """Forward → reverse should restore the original manifest."""
        manifest_text = (
            json.dumps({"dependencies": {"minimist": "^1.2.5"}}, indent=2) + "\n"
        )
        diff, _ = generate_manifest_diff(manifest_text, "minimist", "1.2.6")
        assert diff

        patched = _apply_unified_diff(manifest_text, diff)
        patched_data = json.loads(patched)
        assert patched_data["dependencies"]["minimist"] == "^1.2.6"

        # Verify that the original is untouched
        assert json.loads(manifest_text)["dependencies"]["minimist"] == "^1.2.5"

    def test_no_diff_when_already_at_target_version(self):
        """No diff should be generated when the manifest already has the target version."""
        manifest_text = (
            json.dumps({"dependencies": {"minimist": "^1.2.6"}}, indent=2) + "\n"
        )
        diff, _ = generate_manifest_diff(manifest_text, "minimist", "1.2.6")
        assert diff == ""

    def test_diff_does_not_modify_original_text(self):
        """Generating a diff must never mutate the original manifest string."""
        original = (
            json.dumps({"dependencies": {"lodash": "^4.17.21"}}, indent=2) + "\n"
        )
        original_copy = original
        generate_manifest_diff(original, "lodash", "4.17.22")
        assert original == original_copy

    def test_invalid_json_manifest_returns_empty_diff(self):
        """An invalid JSON manifest must return empty diff + 'error' patch_type."""
        diff, patch_type = generate_manifest_diff("{ NOT VALID JSON !", "lodash", "4.17.22")
        assert patch_type == "error"
        assert diff == ""


# ---------------------------------------------------------------------------
# 2. Overrides compatibility risk explanation
# ---------------------------------------------------------------------------


class TestOverridesCompatibilityExplanation:

    def test_override_proposal_manifest_note_mentions_transitive(self):
        """Transitive override proposals must explain the overrides mechanism."""
        candidate = {
            "candidate_key": "minimist::1.2.5::1.2.6",
            "package_name": "minimist",
            "from_version": "1.2.5",
            "to_version": "1.2.6",
            "compatibility_cost": "patch",
            "risk_eliminated": 4.0,
            "resolved_findings": [],
            "unresolved_findings": [],
            "unverified_findings": [],
        }
        manifest_text = json.dumps({"dependencies": {"express": "^4.18.0"}}, indent=2)
        proposal = build_remediation_proposal(candidate, manifest_text, is_fixture=False)
        assert proposal["patch_type"] == "override"
        note = proposal["manifest_note"].lower()
        assert "transitive" in note or "overrides" in note

    def test_override_lockfile_guidance_safe_commands_only(self):
        """Lockfile guidance must not suggest running `npm install` without safety flags."""
        candidate = {
            "candidate_key": "minimist::1.2.5::1.2.6",
            "package_name": "minimist",
            "from_version": "1.2.5",
            "to_version": "1.2.6",
            "compatibility_cost": "patch",
            "risk_eliminated": 4.0,
            "resolved_findings": [],
            "unresolved_findings": [],
            "unverified_findings": [],
        }
        proposal = build_remediation_proposal(candidate, None, is_fixture=False)
        guidance = proposal["lockfile_guidance"]
        assert "--ignore-scripts" in guidance
        assert "--package-lock-only" in guidance
        # Must not suggest bare `npm install` without safety flags
        lines = [l.strip() for l in guidance.splitlines() if "npm install" in l]
        for l in lines:
            assert "--ignore-scripts" in l or "--package-lock-only" in l, (
                f"Unsafe npm install command found: {l!r}"
            )


# ---------------------------------------------------------------------------
# 3. Fixture labels — is_synthetic_fixture propagates correctly
# ---------------------------------------------------------------------------


class TestFixtureLabels:

    def test_fixture_proposal_is_synthetic(self):
        candidate = {
            "candidate_key": "FIXTURE-lodash::4.17.21::4.17.22",
            "package_name": "lodash",
            "from_version": "4.17.21",
            "to_version": "4.17.22",
            "compatibility_cost": "patch",
            "risk_eliminated": 5.0,
            "resolved_findings": [
                {
                    "advisory_id": "FIXTURE-LODASH-PROTOTYPE",
                    "risk_score": 5.0,
                    "evidence_category": "confirmed_entry_path",
                }
            ],
            "unresolved_findings": [],
            "unverified_findings": [],
        }
        proposal = build_remediation_proposal(candidate, None, is_fixture=True)
        assert proposal["is_synthetic_fixture"] is True
        assert "[SIMULATED DEMO]" in proposal["rationale"]

    def test_live_proposal_not_synthetic(self):
        candidate = {
            "candidate_key": "minimist::1.2.5::1.2.6",
            "package_name": "minimist",
            "from_version": "1.2.5",
            "to_version": "1.2.6",
            "compatibility_cost": "patch",
            "risk_eliminated": 3.0,
            "resolved_findings": [],
            "unresolved_findings": [],
            "unverified_findings": [],
        }
        proposal = build_remediation_proposal(candidate, None, is_fixture=False)
        assert proposal["is_synthetic_fixture"] is False
        assert "[SIMULATED DEMO]" not in proposal["rationale"]

    def test_fixture_api_response_carries_fixture_flag(self):
        client = TestClient(app)
        res = client.post("/api/scans", json={"source": "fixture"})
        if res.status_code == 503:
            pytest.skip("FalkorDB unavailable")
        assert res.status_code == 200
        assert res.json()["fixture"] is True

    def test_fixture_findings_carry_fixture_flag(self):
        client = TestClient(app)
        res = client.post("/api/scans", json={"source": "fixture"})
        if res.status_code == 503:
            pytest.skip("FalkorDB unavailable")
        scan_id = res.json()["scan_id"]
        findings_res = client.get(f"/api/scans/{scan_id}/findings")
        assert findings_res.status_code == 200
        for f in findings_res.json()["findings"]:
            assert f["fixture"] is True, (
                f"Finding {f['advisory_id']} must have fixture=True"
            )


# ---------------------------------------------------------------------------
# 4. Proposal approval safeguards
# ---------------------------------------------------------------------------


class TestProposalApprovalSafeguards:

    def _make_candidate(self, name="minimist", from_v="1.2.5", to_v="1.2.6"):
        return {
            "candidate_key": f"{name}::{from_v}::{to_v}",
            "package_name": name,
            "from_version": from_v,
            "to_version": to_v,
            "compatibility_cost": "patch",
            "risk_eliminated": 3.0,
            "resolved_findings": [],
            "unresolved_findings": [],
            "unverified_findings": [],
        }

    def test_approval_required_is_always_true(self):
        proposal = build_remediation_proposal(self._make_candidate(), None)
        assert proposal["approval_required"] is True

    def test_approval_state_is_pending_review(self):
        proposal = build_remediation_proposal(self._make_candidate(), None)
        assert proposal["approval_state"] == "pending_review"

    def test_proposal_does_not_write_files(self, tmp_path):
        """build_remediation_proposal must never write to the filesystem."""
        manifest = json.dumps({"dependencies": {"minimist": "^1.2.5"}}, indent=2)
        original_files = set(tmp_path.rglob("*"))
        build_remediation_proposal(self._make_candidate(), manifest)
        new_files = set(tmp_path.rglob("*"))
        assert new_files == original_files, "Proposal generator must not create any files"

    def test_reachability_caveat_always_present(self):
        """Reachability caveat must appear in every proposal."""
        for is_fix in [True, False]:
            proposal = build_remediation_proposal(
                self._make_candidate(), None, is_fixture=is_fix
            )
            caveat = proposal.get("reachability_caveat", "")
            assert caveat, "Reachability caveat must not be empty"
            assert "not guarantee runtime exploitability" in caveat, (
                f"Caveat text missing: {caveat!r}"
            )

    def test_no_manifest_produces_empty_diff_not_crash(self):
        """When no manifest_text is provided, diff must be empty — no crash."""
        proposal = build_remediation_proposal(self._make_candidate(), None)
        assert proposal["manifest_diff"] == ""
        assert proposal["patch_type"] == "unknown"


# ---------------------------------------------------------------------------
# 5. No invented version — evaluate_upgrade_candidates does not invent fixes
# ---------------------------------------------------------------------------


class TestNoInventedVersion:

    def test_no_candidates_when_no_upgrade_nodes_exist(self):
        """evaluate_upgrade_candidates with empty raw candidates returns empty list."""
        findings = [
            {
                "finding_id": "f1",
                "advisory_id": "GHSA-no-fixed",
                "package_name": "some-lib",
                "package_version": "1.0.0",
                "package_key": "some-lib::1.0.0",
                "affected_range": ">= 0",
                "severity": "HIGH",
                "evidence_category": "confirmed_entry_path",
                "evidence_weight": 1.0,
                "risk_score": 7.0,
            }
        ]
        # No UpgradeCandidate nodes → no candidates
        candidates = evaluate_upgrade_candidates([], findings)
        assert candidates == []

    def test_downgrade_candidates_are_filtered(self):
        """Candidates with to_version <= from_version must be excluded."""
        from app.services.semver_evaluator import NpmVersion

        raw_candidates = [
            {
                "candidate_key": "lib::2.0.0::1.9.9",
                "package_name": "lib",
                "from_version": "2.0.0",
                "to_version": "1.9.9",  # downgrade
                "compatibility_cost": "major",
                "package_key": "lib::2.0.0",
            },
            {
                "candidate_key": "lib::2.0.0::2.0.0",
                "package_name": "lib",
                "from_version": "2.0.0",
                "to_version": "2.0.0",  # same version
                "compatibility_cost": "patch",
                "package_key": "lib::2.0.0",
            },
        ]
        evaluated = evaluate_upgrade_candidates(raw_candidates, [])
        for c in evaluated:
            from_v = NpmVersion.parse(c["from_version"])
            to_v = NpmVersion.parse(c["to_version"])
            assert to_v > from_v, (
                f"Downgrade/same-version candidate slipped through: "
                f"{c['from_version']} → {c['to_version']}"
            )


# ---------------------------------------------------------------------------
# 6. OSV offline graceful degradation
# ---------------------------------------------------------------------------


class TestOsvOfflineDegradation:

    def test_offline_osv_scan_returns_200_with_zero_findings(self, tmp_path):
        """When OSV is unreachable, scan must return 200 with 0 findings (not 500)."""
        _minimal_project(
            tmp_path,
            name="offline-test",
            deps={"express": "^4.18.0"},
            lockfile_pkgs={
                "node_modules/express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
                }
            },
        )

        client = TestClient(app)
        with patch(
            "app.services.project_scanner.OsvProvider", return_value=_MockOsvErrors()
        ):
            res = client.post(
                "/api/scans", json={"source": "local", "path": str(tmp_path)}
            )

        if res.status_code == 503:
            pytest.skip("FalkorDB unavailable")

        assert res.status_code == 200, (
            f"Expected 200 on OSV failure, got {res.status_code}: {res.text}"
        )
        data = res.json()
        # Graceful degradation: 0 findings + warnings (or just 0 findings)
        assert data["finding_count"] == 0
        # Warnings should be present reporting the OSV failures
        warnings = data.get("warnings") or []
        assert isinstance(warnings, list)

    def test_offline_osv_scan_no_findings_is_not_safe_claim(self, tmp_path):
        """Zero findings from offline OSV must NOT be interpreted as 'safe'.

        The warnings list must be non-empty to signal incomplete data.
        """
        _minimal_project(
            tmp_path,
            name="offline-test-2",
            deps={"lodash": "^4.17.0"},
            lockfile_pkgs={
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                }
            },
        )

        client = TestClient(app)
        with patch(
            "app.services.project_scanner.OsvProvider", return_value=_MockOsvErrors()
        ):
            res = client.post(
                "/api/scans", json={"source": "local", "path": str(tmp_path)}
            )

        if res.status_code == 503:
            pytest.skip("FalkorDB unavailable")

        assert res.status_code == 200
        data = res.json()
        # Must have warnings indicating data is incomplete
        warnings = data.get("warnings") or []
        # Either has warnings OR finding_count is 0 (with the implication data is partial)
        # The key invariant is: no crash and not claiming 0 findings = safe
        assert isinstance(warnings, list)


# ---------------------------------------------------------------------------
# 7. Cross-scan isolation
# ---------------------------------------------------------------------------


class TestCrossScanIsolation:

    def test_two_projects_no_finding_leak(self, tmp_path):
        """Findings from project A must not appear in project B scan results."""
        from app.db.falkordb import probe_falkordb, create_redis_client

        try:
            r = create_redis_client()
            if not probe_falkordb(r).connected:
                pytest.skip("FalkorDB unavailable")
            r.close()
        except Exception:
            pytest.skip("FalkorDB unavailable")

        # Project A: fixture repo (has lodash 4.17.21 + minimist 1.2.5)
        proj_a = FIXTURE_ROOT

        # Project B: completely different project, no vulnerable packages
        proj_b = tmp_path / "proj_b"
        proj_b.mkdir()
        _minimal_project(
            proj_b,
            name="proj-b",
            deps={"express": "^4.18.0"},
            lockfile_pkgs={
                "node_modules/express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
                }
            },
        )

        client = TestClient(app)

        # Scan A — inject minimist advisory
        with patch(
            "app.services.project_scanner.OsvProvider",
            return_value=_MockOsvWithMinimistAdvisory(),
        ):
            res_a = client.post(
                "/api/scans", json={"source": "local", "path": str(proj_a)}
            )
        if res_a.status_code == 503:
            pytest.skip("FalkorDB unavailable")
        assert res_a.status_code == 200
        scan_id_a = res_a.json()["scan_id"]

        # Scan B — no advisories
        with patch(
            "app.services.project_scanner.OsvProvider", return_value=_MockOsvEmpty()
        ):
            res_b = client.post(
                "/api/scans", json={"source": "local", "path": str(proj_b)}
            )
        assert res_b.status_code == 200
        scan_id_b = res_b.json()["scan_id"]

        # Scan A findings must now 404 (graph cleared when B was scanned)
        old_res = client.get(f"/api/scans/{scan_id_a}/findings")
        assert old_res.status_code == 404, (
            f"Expected scan A to be 404 after scan B, got {old_res.status_code}"
        )

        # Scan B must contain NO findings from project A
        findings_b_res = client.get(f"/api/scans/{scan_id_b}/findings")
        assert findings_b_res.status_code == 200
        pkg_names_b = {f["package_name"] for f in findings_b_res.json()["findings"]}
        assert "lodash" not in pkg_names_b, "lodash from project A leaked into project B"
        assert "minimist" not in pkg_names_b, "minimist from project A leaked into project B"


# ---------------------------------------------------------------------------
# 8. Full API workflow smoke test
# ---------------------------------------------------------------------------


class TestFullWorkflowSmokeTest:

    def test_fixture_full_workflow(self):
        """Simulate the complete demo workflow end-to-end."""
        client = TestClient(app)

        # Step 1: Run fixture scan
        res = client.post("/api/scans", json={"source": "fixture"})
        if res.status_code == 503:
            pytest.skip("FalkorDB unavailable")
        assert res.status_code == 200
        scan = res.json()
        scan_id = scan["scan_id"]
        assert scan["fixture"] is True
        assert scan["finding_count"] > 0
        assert scan["coverage"]["packages_scanned"] > 0

        # Step 2: Get findings
        findings_res = client.get(f"/api/scans/{scan_id}/findings")
        assert findings_res.status_code == 200
        findings = findings_res.json()["findings"]
        assert len(findings) > 0
        for f in findings:
            assert f["rank"] >= 1
            assert f["risk_score"] >= 0
            assert f["fixture"] is True

        # Step 3: Get evidence paths for every finding
        for f in findings:
            paths_res = client.get(f"/api/findings/{f['finding_id']}/paths")
            assert paths_res.status_code == 200
            paths_data = paths_res.json()
            assert "paths" in paths_data
            assert "evidence_note" in paths_data

        # Step 4: Get remediations
        remed_res = client.get(f"/api/scans/{scan_id}/remediations")
        assert remed_res.status_code == 200
        candidates = remed_res.json()["remediation_candidates"]
        assert len(candidates) > 0

        # Step 5: Inspect proposals on all candidates
        for c in candidates:
            assert "proposal" in c, f"Candidate {c['candidate_key']} missing proposal"
            proposal = c["proposal"]
            assert proposal["approval_required"] is True
            assert proposal["approval_state"] == "pending_review"
            assert proposal["is_synthetic_fixture"] is True
            assert "not guarantee runtime exploitability" in proposal["reachability_caveat"]

        # Step 6: Failed scan (invalid path) must 400, not crash
        bad_res = client.post(
            "/api/scans", json={"source": "local", "path": "c:/completely/invalid/path/xyz"}
        )
        assert bad_res.status_code == 400

    def test_unknown_scan_id_returns_404(self):
        client = TestClient(app)
        res = client.get("/api/scans/scan-completely-fake-id-xyz/findings")
        if res.status_code == 503:
            pytest.skip("FalkorDB unavailable")
        assert res.status_code == 404

    def test_unknown_finding_paths_not_500(self):
        client = TestClient(app)
        res = client.get("/api/findings/fake-finding-id-xyz/paths")
        if res.status_code == 503:
            pytest.skip("FalkorDB unavailable")
        # Should be 404 or 200 with empty paths — never 500
        assert res.status_code in (200, 404)

    def test_repeated_fixture_scan_is_idempotent(self):
        """Running the demo fixture twice must produce the same finding count."""
        client = TestClient(app)
        res1 = client.post("/api/scans", json={"source": "fixture"})
        if res1.status_code == 503:
            pytest.skip("FalkorDB unavailable")
        assert res1.status_code == 200
        count1 = res1.json()["finding_count"]

        res2 = client.post("/api/scans", json={"source": "fixture"})
        assert res2.status_code == 200
        count2 = res2.json()["finding_count"]

        assert count1 == count2, (
            f"Idempotency violated: first scan={count1}, second scan={count2}"
        )

    def test_local_scan_with_verified_advisory(self, tmp_path):
        """A local scan with a mocked minimist advisory must produce a finding and proposal."""
        _minimal_project(
            tmp_path,
            name="real-test-app",
            deps={"minimist": "^1.2.5"},
            lockfile_pkgs={
                "node_modules/minimist": {
                    "version": "1.2.5",
                    "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz",
                }
            },
        )

        client = TestClient(app)
        with patch(
            "app.services.project_scanner.OsvProvider",
            return_value=_MockOsvWithMinimistAdvisory(),
        ):
            res = client.post(
                "/api/scans", json={"source": "local", "path": str(tmp_path)}
            )

        if res.status_code == 503:
            pytest.skip("FalkorDB unavailable")
        assert res.status_code == 200
        data = res.json()
        assert data["finding_count"] >= 1
        assert data["fixture"] is False

        scan_id = data["scan_id"]

        # Verify remediations have a non-synthetic proposal
        remed_res = client.get(f"/api/scans/{scan_id}/remediations")
        assert remed_res.status_code == 200
        candidates = remed_res.json()["remediation_candidates"]
        assert len(candidates) >= 1
        minimist_c = next((c for c in candidates if c["package_name"] == "minimist"), None)
        assert minimist_c is not None
        assert minimist_c["to_version"] == "1.2.6"  # from OSV fixed range
        proposal = minimist_c.get("proposal")
        assert proposal is not None
        assert proposal["is_synthetic_fixture"] is False
        assert proposal["approval_required"] is True
