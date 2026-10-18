import json
from pathlib import Path
import pytest

from app.services.fixture_loader import FIXTURE_ROOT
from app.services.project_scanner import (
    ProjectScanError,
    scan_local_project,
    validate_project_directory,
)
from app.services.vuln_provider import AffectedRange, OsvAdvisory, OsvBatchResult


def test_validate_empty_path():
    with pytest.raises(ProjectScanError) as exc:
        validate_project_directory("")
    assert exc.value.code == "invalid_path"


def test_validate_nonexistent_path():
    with pytest.raises(ProjectScanError) as exc:
        validate_project_directory("c:/non/existent/path/that/cannot/exist/xyz123")
    assert exc.value.code == "invalid_path"


def test_validate_file_instead_of_dir(tmp_path):
    some_file = tmp_path / "foo.txt"
    some_file.write_text("hello", encoding="utf-8")
    with pytest.raises(ProjectScanError) as exc:
        validate_project_directory(str(some_file))
    assert exc.value.code == "not_a_directory"


def test_validate_missing_manifest(tmp_path):
    with pytest.raises(ProjectScanError) as exc:
        validate_project_directory(str(tmp_path))
    assert exc.value.code == "missing_manifest"


def test_validate_missing_lockfile(tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ProjectScanError) as exc:
        validate_project_directory(str(tmp_path))
    assert exc.value.code == "missing_lockfile"


def test_validate_valid_project():
    resolved = validate_project_directory(str(FIXTURE_ROOT))
    assert resolved == FIXTURE_ROOT.resolve()


def test_validate_relative_path():
    # Relative path should resolve to repo root fixture repo
    resolved = validate_project_directory("demo/fixture-repo")
    assert resolved == FIXTURE_ROOT.resolve()


class MockOsvProvider:
    def query_batch(self, packages):
        return OsvBatchResult(
            advisories={
                "npm:lodash@4.17.21": [
                    OsvAdvisory(
                        advisory_id="GHSA-35jh-r3h4-6jhm",
                        aliases=["CVE-2021-23337"],
                        summary="Command Injection in lodash",
                        details="A command injection vulnerability exists...",
                        severity="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/7.2",
                        published="2021-02-15T00:00:00Z",
                        modified="2021-02-15T00:00:00Z",
                        source="osv.dev",
                        affected_ranges=[
                            AffectedRange(
                                range_type="SEMVER",
                                introduced="0",
                                fixed="4.17.21",
                            )
                        ],
                    )
                ],
                "npm:minimist@1.2.5": [
                    OsvAdvisory(
                        advisory_id="GHSA-vh95-rmgr-6w49",
                        aliases=["CVE-2021-44906"],
                        summary="Prototype Pollution in minimist",
                        details="Minimist before 1.2.6 is vulnerable to Prototype Pollution...",
                        severity="high",
                        published="2022-03-18T00:00:00Z",
                        modified="2022-03-18T00:00:00Z",
                        source="osv.dev",
                        affected_ranges=[
                            AffectedRange(
                                range_type="SEMVER",
                                introduced="0",
                                fixed="1.2.6",
                            )
                        ],
                    )
                ],
            },
            errors=[],
        )


def test_scan_local_project_model_structure():
    mock_provider = MockOsvProvider()
    model = scan_local_project(FIXTURE_ROOT, osv_provider=mock_provider)

    assert model["fixture"] is False
    assert model["source"] == "local"
    assert "demo-app" in model["label"]
    assert model["project"]["name"] == "demo-app"

    # Packages
    pkg_names = {p["name"] for p in model["packages"]}
    assert "demo-app" in pkg_names
    assert "lodash" in pkg_names
    assert "minimist" in pkg_names

    # Static files and entry points
    assert any(f["relative_path"] == "src/index.js" for f in model["files"])
    assert any(e["relative_path"] == "src/index.js" for e in model["entry_points"])
    assert any(r["entry"] == "src/index.js" and r["file"] == "src/index.js" for r in model["reaches"])

    # Vulnerabilities
    assert len(model["vulnerabilities"]) == 2
    vuln_ids = {v["advisory_id"] for v in model["vulnerabilities"]}
    assert "GHSA-35jh-r3h4-6jhm" in vuln_ids
    assert "GHSA-vh95-rmgr-6w49" in vuln_ids
    for v in model["vulnerabilities"]:
        assert v["fixture"] is False
        assert v["source"] == "osv.dev"

    # Genuine upgrade candidates (derived from fixed versions, never invented)
    cands = model["upgrade_candidates"]
    assert len(cands) >= 1
    # minimist 1.2.5 has fixed="1.2.6" in advisory
    cand_packages = {c["package_name"]: c["to_version"] for c in cands}
    assert cand_packages.get("minimist") == "1.2.6"
    assert any(c["package_name"] == "minimist" and c["compatibility_cost"] == "patch" for c in cands)


def test_validate_forbidden_system_dirs():
    # Attempting to scan system directories must raise forbidden_root
    for forbidden in ["C:\\Windows", "C:\\Windows\\System32", "C:\\Program Files"]:
        p = Path(forbidden)
        if p.exists():
            with pytest.raises(ProjectScanError) as exc:
                validate_project_directory(str(p))
            assert exc.value.code == "forbidden_root"


def test_upgrade_candidates_filter_downgrades():
    # If OSV advisory specifies a fixed version <= installed version,
    # it must NOT be offered as an upgrade candidate
    class DowngradeOsvProvider:
        def query_batch(self, packages):
            return OsvBatchResult(
                advisories={
                    "npm:minimist@1.2.5": [
                        OsvAdvisory(
                            advisory_id="GHSA-historical-vuln",
                            aliases=[],
                            summary="Old branch vuln",
                            details="Fixed in earlier 0.x release",
                            severity="low",
                            published="2020-01-01T00:00:00Z",
                            modified="2020-01-01T00:00:00Z",
                            source="osv.dev",
                            affected_ranges=[
                                AffectedRange(
                                    range_type="SEMVER",
                                    introduced="0",
                                    fixed="0.2.4",  # Lower than installed 1.2.5
                                )
                            ],
                        )
                    ]
                },
                errors=[],
            )

    model = scan_local_project(FIXTURE_ROOT, osv_provider=DowngradeOsvProvider())
    # Should have 0 upgrade candidates because 0.2.4 < 1.2.5
    assert not any(c["package_name"] == "minimist" for c in model["upgrade_candidates"])

