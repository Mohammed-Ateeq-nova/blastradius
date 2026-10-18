from pathlib import Path

import pytest

from app.services.dependency_parser import NpmInventoryError, parse_npm_project

FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "demo" / "fixture-repo"


def test_parses_fixture_lockfile_without_guessing_missing_packages():
    inventory = parse_npm_project(FIXTURE_ROOT)
    keys = {(p["name"], p["version"], p["direct"]) for p in inventory["packages"]}
    assert ("demo-app", "1.0.0", True) in keys
    assert ("lodash", "4.17.21", True) in keys
    assert ("minimist", "1.2.5", False) in keys
    deps = {(tuple(d["from"][1:]), tuple(d["to"][1:]), d["direct"]) for d in inventory["dependencies"]}
    assert (("demo-app", "1.0.0"), ("lodash", "4.17.21"), True) in deps
    assert (("lodash", "4.17.21"), ("minimist", "1.2.5"), False) in deps


def test_missing_lockfile_is_an_error(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name":"x","version":"1.0.0"}', encoding="utf-8")
    with pytest.raises(NpmInventoryError) as exc:
        parse_npm_project(tmp_path)
    assert exc.value.code == "missing_lockfile"


def test_malformed_json_is_an_error(tmp_path: Path):
    (tmp_path / "package.json").write_text("{", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{", encoding="utf-8")
    with pytest.raises(NpmInventoryError) as exc:
        parse_npm_project(tmp_path)
    assert exc.value.code == "malformed_manifest"


def test_duplicate_name_keeps_distinct_versions(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"name":"host","version":"1.0.0","dependencies":{"leftpad":"1.0.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        """
{
  "name": "host",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {"name": "host", "version": "1.0.0", "dependencies": {"leftpad": "1.0.0"}},
    "node_modules/leftpad": {"version": "1.0.0", "dependencies": {"leftpad": "2.0.0"}},
    "node_modules/leftpad/node_modules/leftpad": {"version": "2.0.0"}
  }
}
""",
        encoding="utf-8",
    )
    inventory = parse_npm_project(tmp_path)
    versions = {(p["name"], p["version"]) for p in inventory["packages"]}
    assert ("leftpad", "1.0.0") in versions
    assert ("leftpad", "2.0.0") in versions
