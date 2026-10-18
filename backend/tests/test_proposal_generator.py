"""Unit tests for proposal_generator.py — M10 Evidence-Driven Remediation Proposals."""
import json
import pytest
from app.services.proposal_generator import (
    generate_manifest_diff,
    generate_evidence_rationale,
    build_remediation_proposal,
    _update_manifest_json,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MANIFEST_DIRECT = json.dumps(
    {
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {"lodash": "^4.17.21", "axios": "^1.4.0"},
        "devDependencies": {"jest": "^29.0.0"},
    },
    indent=2,
)

MANIFEST_DEV_ONLY = json.dumps(
    {
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {"axios": "^1.4.0"},
        "devDependencies": {"lodash": "^4.17.21"},
    },
    indent=2,
)

MANIFEST_TRANSITIVE = json.dumps(
    {
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {"express": "^4.18.0"},
    },
    indent=2,
)

CANDIDATE_DIRECT = {
    "candidate_key": "lodash::4.17.21::4.17.22",
    "package_name": "lodash",
    "from_version": "4.17.21",
    "to_version": "4.17.22",
    "compatibility_cost": "patch",
    "risk_eliminated": 6.5,
    "resolved_findings": [
        {
            "advisory_id": "GHSA-fake-1234",
            "risk_score": 6.5,
            "evidence_category": "confirmed_entry_path",
        }
    ],
    "unresolved_findings": [],
    "unverified_findings": [],
}

CANDIDATE_NO_FINDINGS = {
    "candidate_key": "lodash::4.17.21::4.17.22",
    "package_name": "lodash",
    "from_version": "4.17.21",
    "to_version": "4.17.22",
    "compatibility_cost": "patch",
    "risk_eliminated": 0.0,
    "resolved_findings": [],
    "unresolved_findings": [],
    "unverified_findings": [],
}


# ---------------------------------------------------------------------------
# _update_manifest_json
# ---------------------------------------------------------------------------


class TestUpdateManifestJson:
    def test_updates_direct_dependency(self):
        data = json.loads(MANIFEST_DIRECT)
        updated, patch_type = _update_manifest_json(data, "lodash", "4.17.22")
        assert patch_type == "direct"
        assert updated["dependencies"]["lodash"] == "^4.17.22"
        # Other deps untouched
        assert updated["dependencies"]["axios"] == "^1.4.0"

    def test_updates_dev_dependency(self):
        data = json.loads(MANIFEST_DEV_ONLY)
        updated, patch_type = _update_manifest_json(data, "lodash", "4.17.22")
        assert patch_type == "direct"
        assert updated["devDependencies"]["lodash"] == "^4.17.22"

    def test_transitive_adds_overrides(self):
        data = json.loads(MANIFEST_TRANSITIVE)
        updated, patch_type = _update_manifest_json(data, "lodash", "4.17.22")
        assert patch_type == "override"
        assert "overrides" in updated
        assert updated["overrides"]["lodash"] == "^4.17.22"

    def test_preserves_tilde_prefix(self):
        data = {
            "dependencies": {"lodash": "~4.17.21"},
        }
        updated, patch_type = _update_manifest_json(data, "lodash", "4.17.22")
        assert patch_type == "direct"
        assert updated["dependencies"]["lodash"] == "~4.17.22"

    def test_preserves_no_prefix(self):
        data = {
            "dependencies": {"lodash": "4.17.21"},
        }
        updated, patch_type = _update_manifest_json(data, "lodash", "4.17.22")
        assert patch_type == "direct"
        assert updated["dependencies"]["lodash"] == "4.17.22"

    def test_does_not_mutate_input(self):
        data = json.loads(MANIFEST_DIRECT)
        original_ver = data["dependencies"]["lodash"]
        _update_manifest_json(data, "lodash", "4.17.22")
        assert data["dependencies"]["lodash"] == original_ver

    def test_extends_existing_overrides(self):
        data = {
            "dependencies": {"express": "^4.18.0"},
            "overrides": {"qs": "^6.11.2"},
        }
        updated, patch_type = _update_manifest_json(data, "lodash", "4.17.22")
        assert patch_type == "override"
        assert updated["overrides"]["qs"] == "^6.11.2"
        assert updated["overrides"]["lodash"] == "^4.17.22"


# ---------------------------------------------------------------------------
# generate_manifest_diff
# ---------------------------------------------------------------------------


class TestGenerateManifestDiff:
    def test_direct_dep_diff_produced(self):
        diff, patch_type = generate_manifest_diff(MANIFEST_DIRECT, "lodash", "4.17.22")
        assert patch_type == "direct"
        assert "4.17.22" in diff
        assert "4.17.21" in diff
        # Should be a valid unified diff
        assert "--- a/package.json" in diff
        assert "+++ b/package.json" in diff
        assert diff.count("@@") >= 1

    def test_transitive_diff_shows_overrides(self):
        diff, patch_type = generate_manifest_diff(MANIFEST_TRANSITIVE, "lodash", "4.17.22")
        assert patch_type == "override"
        assert "overrides" in diff
        assert "4.17.22" in diff

    def test_invalid_json_returns_empty_diff(self):
        diff, patch_type = generate_manifest_diff("NOT VALID JSON", "lodash", "4.17.22")
        assert patch_type == "error"
        assert diff == ""

    def test_no_diff_when_nothing_changes(self):
        # Package already at target version
        manifest = json.dumps(
            {"dependencies": {"lodash": "^4.17.22"}}, indent=2
        )
        diff, patch_type = generate_manifest_diff(manifest, "lodash", "4.17.22")
        # diff should be empty — nothing to change
        assert diff == ""

    def test_dev_dep_diff_produced(self):
        diff, patch_type = generate_manifest_diff(MANIFEST_DEV_ONLY, "lodash", "4.17.22")
        assert patch_type == "direct"
        assert "4.17.22" in diff

    def test_diff_does_not_touch_unrelated_deps(self):
        diff, _ = generate_manifest_diff(MANIFEST_DIRECT, "lodash", "4.17.22")
        # axios should not appear in added/removed lines
        added_lines = [l for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
        removed_lines = [l for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")]
        assert not any("axios" in l for l in added_lines)
        assert not any("axios" in l for l in removed_lines)


# ---------------------------------------------------------------------------
# generate_evidence_rationale
# ---------------------------------------------------------------------------


class TestGenerateEvidenceRationale:
    def test_live_rationale_contains_package_info(self):
        rationale = generate_evidence_rationale(CANDIDATE_DIRECT, CANDIDATE_DIRECT["resolved_findings"], is_fixture=False)
        assert "lodash" in rationale
        assert "4.17.21" in rationale
        assert "4.17.22" in rationale
        assert "GHSA-fake-1234" in rationale

    def test_fixture_rationale_has_simulated_prefix(self):
        rationale = generate_evidence_rationale(CANDIDATE_DIRECT, CANDIDATE_DIRECT["resolved_findings"], is_fixture=True)
        assert rationale.startswith("[SIMULATED DEMO]")

    def test_no_resolved_findings_returns_no_fix_message(self):
        rationale = generate_evidence_rationale(CANDIDATE_NO_FINDINGS, [], is_fixture=False)
        assert "does not resolve any verified findings" in rationale

    def test_rationale_mentions_evidence_category(self):
        rationale = generate_evidence_rationale(CANDIDATE_DIRECT, CANDIDATE_DIRECT["resolved_findings"], is_fixture=False)
        assert "confirmed entry path" in rationale

    def test_rationale_mentions_risk_eliminated(self):
        rationale = generate_evidence_rationale(CANDIDATE_DIRECT, CANDIDATE_DIRECT["resolved_findings"], is_fixture=False)
        assert "6.5" in rationale


# ---------------------------------------------------------------------------
# build_remediation_proposal
# ---------------------------------------------------------------------------


class TestBuildRemediationProposal:
    def test_proposal_fields_present(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, MANIFEST_DIRECT, is_fixture=False)
        required_keys = [
            "candidate_key", "package_name", "from_version", "to_version",
            "compatibility_cost", "is_synthetic_fixture", "manifest_path",
            "manifest_diff", "patch_type", "manifest_note", "lockfile_guidance",
            "resolved_findings_count", "unresolved_findings_count",
            "unverified_findings_count", "risk_eliminated", "rationale",
            "reachability_caveat", "approval_required", "approval_state",
        ]
        for key in required_keys:
            assert key in proposal, f"Missing key: {key}"

    def test_approval_required_always_true(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, MANIFEST_DIRECT)
        assert proposal["approval_required"] is True
        assert proposal["approval_state"] == "pending_review"

    def test_live_proposal_not_synthetic(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, MANIFEST_DIRECT, is_fixture=False)
        assert proposal["is_synthetic_fixture"] is False

    def test_fixture_proposal_is_synthetic(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, MANIFEST_DIRECT, is_fixture=True)
        assert proposal["is_synthetic_fixture"] is True
        assert "[SIMULATED DEMO]" in proposal["rationale"]

    def test_direct_patch_type(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, MANIFEST_DIRECT)
        assert proposal["patch_type"] == "direct"
        assert "Direct Dependency" in proposal["manifest_note"]

    def test_transitive_patch_type(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, MANIFEST_TRANSITIVE)
        assert proposal["patch_type"] == "override"
        assert "overrides" in proposal["manifest_note"].lower() or "Transitive" in proposal["manifest_note"]

    def test_no_manifest_text_empty_diff(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, None)
        assert proposal["manifest_diff"] == ""
        assert proposal["patch_type"] == "unknown"

    def test_lockfile_guidance_mentions_npm(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, MANIFEST_DIRECT)
        assert "npm install" in proposal["lockfile_guidance"]
        assert "--ignore-scripts" in proposal["lockfile_guidance"]

    def test_reachability_caveat_present(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, MANIFEST_DIRECT)
        assert "not guarantee runtime exploitability" in proposal["reachability_caveat"]

    def test_resolved_findings_count_correct(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, MANIFEST_DIRECT)
        assert proposal["resolved_findings_count"] == 1

    def test_risk_eliminated_value(self):
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, MANIFEST_DIRECT)
        assert proposal["risk_eliminated"] == pytest.approx(6.5)

    def test_invalid_manifest_json_handled_gracefully(self):
        """Should not raise — returns proposal with empty diff."""
        proposal = build_remediation_proposal(CANDIDATE_DIRECT, "{invalid json!")
        assert "manifest_diff" in proposal
        # Should have an error or empty diff, but not crash
        assert isinstance(proposal["manifest_diff"], str)
