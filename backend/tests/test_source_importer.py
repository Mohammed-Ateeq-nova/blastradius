from pathlib import Path

from app.services.source_importer import extract_static_imports

FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "demo" / "fixture-repo"


def test_extracts_cjs_require_from_fixture():
    files = extract_static_imports(FIXTURE_ROOT)
    index = next(item for item in files if item["relative_path"] == "src/index.js")
    assert "lodash" in index["specifiers"]
    assert index["language"] == "javascript"


def test_ignores_dynamic_and_template_requires(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "dyn.js").write_text(
        'const name = "lodash";\nrequire(name);\nrequire(`lodash`);\nimport("./x");\n',
        encoding="utf-8",
    )
    files = extract_static_imports(tmp_path)
    dyn = next(item for item in files if item["relative_path"] == "src/dyn.js")
    assert dyn["specifiers"] == []
    assert "dynamic_or_unsupported" in dyn["unsupported"]


def test_skips_excluded_directories(tmp_path: Path):
    # Files inside .git, node_modules, dist, build, coverage, .venv must be skipped
    for d in [".git", "node_modules", "dist", "build", "coverage", ".venv"]:
        sub = tmp_path / d
        sub.mkdir()
        (sub / "bundle.js").write_text('const x = require("bad-pkg");', encoding="utf-8")

    src = tmp_path / "src"
    src.mkdir()
    (src / "app.js").write_text('const x = require("good-pkg");', encoding="utf-8")

    files = extract_static_imports(tmp_path)
    assert len(files) == 1
    assert files[0]["relative_path"] == "src/app.js"
    assert files[0]["specifiers"] == ["good-pkg"]


def test_skips_oversized_files(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    huge = src / "huge.js"
    # Write a file larger than 1MB
    huge.write_text('// filler\n' * 150_000 + 'const x = require("huge-pkg");\n', encoding="utf-8")
    assert huge.stat().st_size > 1_048_576

    normal = src / "normal.js"
    normal.write_text('const x = require("normal-pkg");\n', encoding="utf-8")

    files = extract_static_imports(tmp_path)
    rel_paths = [f["relative_path"] for f in files]
    assert "src/normal.js" in rel_paths
    assert "src/huge.js" not in rel_paths


def test_skips_external_symlinks(tmp_path: Path):
    # Test symlink pointing outside repository root
    external_dir = tmp_path / "external"
    external_dir.mkdir()
    external_file = external_dir / "secret.js"
    external_file.write_text('const secret = require("leak-pkg");\n', encoding="utf-8")

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    src = project_dir / "src"
    src.mkdir()

    symlink_file = src / "linked.js"
    try:
        symlink_file.symlink_to(external_file)
    except (OSError, NotImplementedError):
        # On Windows without SeCreateSymbolicLinkPrivilege, symlinks might not be permitted
        return

    files = extract_static_imports(project_dir)
    assert not any(f["relative_path"] == "src/linked.js" for f in files)

