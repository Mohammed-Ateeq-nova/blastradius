"""Real npm repository scanner service.

Orchestrates local manifest parsing, static import analysis, OSV vulnerability queries,
and real upgrade candidate derivation without ever executing target code.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.dependency_parser import NpmInventoryError, parse_npm_project
from app.services.risk_engine import compute_compatibility_cost
from app.services.semver_evaluator import NpmVersion
from app.services.source_importer import extract_static_imports
from app.services.vuln_provider import OsvProvider


class ProjectScanError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def validate_project_directory(path_str: str) -> Path:
    """Validate that the given path is a safe, existing directory containing npm project files."""
    if not path_str or not str(path_str).strip():
        raise ProjectScanError("invalid_path", "Project directory path must not be empty.")

    raw = Path(path_str.strip())
    # If relative and not found in current directory, check repository root
    if not raw.is_absolute() and not raw.exists():
        candidate_root = Path(__file__).resolve().parents[3] / raw
        if candidate_root.exists():
            raw = candidate_root

    try:
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProjectScanError("invalid_path", f"Directory does not exist or is inaccessible: {path_str}") from exc

    if not resolved.is_dir():
        raise ProjectScanError("not_a_directory", f"Specified path is not a directory: {resolved}")

    # Guard against scanning system roots directly (e.g. 'C:\', '/', 'C:\Windows', '/etc')
    if resolved == resolved.parent:
        raise ProjectScanError("forbidden_root", "Scanning filesystem root directory directly is forbidden.")

    # Guard against system directories
    parts_lower = [p.lower().rstrip(":\\/") for p in resolved.parts if p]
    forbidden_system_dirs = {
        "windows",
        "winnt",
        "system32",
        "syswow64",
        "program files",
        "program files (x86)",
        "etc",
        "bin",
        "sbin",
        "usr",
        "var",
        "proc",
        "sys",
        "dev",
        "boot",
    }
    # Check top-level system paths (e.g. C:\Windows, /etc, /usr)
    if len(parts_lower) > 1 and parts_lower[1] in forbidden_system_dirs:
        raise ProjectScanError("forbidden_root", "Scanning system directories is forbidden.")
    if any(p in ("system32", "syswow64") for p in parts_lower):
        raise ProjectScanError("forbidden_root", "Scanning system directories is forbidden.")

    # Require package.json
    manifest_path = resolved / "package.json"
    if not manifest_path.is_file():
        raise ProjectScanError(
            "missing_manifest",
            f"package.json not found in {resolved}. BlastRadius requires an npm project manifest."
        )

    # Require package-lock.json
    lock_path = resolved / "package-lock.json"
    if not lock_path.is_file():
        raise ProjectScanError(
            "missing_lockfile",
            f"package-lock.json not found in {resolved}. BlastRadius requires package-lock.json (lockfileVersion 2+) for deterministic dependency resolution."
        )

    return resolved


def _package_identity(packages: list[dict[str, Any]], spec: str) -> list[str] | None:
    """Match a static import specifier to a package in the inventory."""
    matches = [pkg for pkg in packages if pkg.get("name") == spec]
    if len(matches) != 1:
        return None
    pkg = matches[0]
    return ["npm", pkg["name"], pkg["version"]]


def _determine_entry_points(
    root: Path,
    manifest: dict[str, Any],
    files: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Identify entry points from package.json and filesystem, connecting them to source files."""
    entry_points: list[dict[str, Any]] = []
    reaches: list[dict[str, Any]] = []
    file_relpaths = {f["relative_path"] for f in files}

    # 1. Check package.json main, module, or bin
    declared_entries: list[tuple[str, str, str]] = []
    if manifest.get("main"):
        declared_entries.append((str(manifest["main"]), "package_main", "package.json main"))
    if manifest.get("module"):
        declared_entries.append((str(manifest["module"]), "package_module", "package.json module"))
    if isinstance(manifest.get("bin"), str):
        declared_entries.append((str(manifest["bin"]), "package_bin", "package.json bin"))
    elif isinstance(manifest.get("bin"), dict):
        for bin_name, bin_path in manifest["bin"].items():
            declared_entries.append((str(bin_path), "package_bin", f"package.json bin ({bin_name})"))

    # Fallback to standard convention files if no entry points declared
    if not declared_entries:
        common_defaults = [
            "src/index.js", "src/index.ts", "src/main.js", "src/main.ts",
            "index.js", "index.ts", "main.js", "main.ts",
        ]
        for candidate in common_defaults:
            if (root / candidate).is_file():
                declared_entries.append((candidate, "convention_default", f"convention ({candidate})"))
                break

    for rel_path, kind, source in declared_entries:
        clean_rel = rel_path.replace("\\", "/").lstrip("./")
        entry_points.append({
            "relative_path": clean_rel,
            "kind": kind,
            "evidence_source": source,
        })
        # If this entry point matches a scanned file, add a REACHES edge
        if clean_rel in file_relpaths:
            reaches.append({
                "entry": clean_rel,
                "file": clean_rel,
                "evidence_type": "entry_is_file",
                "confidence_label": "potentially_reachable",
            })

    return entry_points, reaches


def scan_local_project(
    project_dir: Path,
    osv_provider: OsvProvider | None = None,
) -> dict[str, Any]:
    """Scan a validated local npm repository without executing any code.

    Returns a normalized model dictionary compatible with FalkorDB graph builder.
    """
    root = validate_project_directory(str(project_dir))

    # 1. Parse dependencies from manifest and lockfile
    try:
        inventory = parse_npm_project(root)
    except NpmInventoryError as exc:
        raise ProjectScanError(exc.code, exc.message) from exc

    # 2. Extract static imports from source files
    imported = extract_static_imports(root)
    files = [{"relative_path": item["relative_path"], "language": item["language"]} for item in imported]

    imports: list[dict[str, Any]] = []
    for item in imported:
        for spec in item.get("specifiers", []):
            identity = _package_identity(inventory["packages"], spec)
            if identity:
                imports.append({"file": item["relative_path"], "package": identity})

    # Read manifest for entry points
    manifest_data = json.loads((root / "package.json").read_text(encoding="utf-8", errors="replace"))
    entry_points, reaches = _determine_entry_points(root, manifest_data, files)

    # 3. Query OSV for dependencies (exclude root project package itself)
    provider = osv_provider or OsvProvider()
    root_name = inventory["project_name"]
    dep_packages = [
        p for p in inventory["packages"]
        if p.get("name") != root_name and p.get("name") and p.get("version")
    ]

    osv_batch = provider.query_batch(dep_packages)

    vulnerabilities: list[dict[str, Any]] = []
    upgrade_candidates_map: dict[str, dict[str, Any]] = {}

    for pkg in dep_packages:
        pkg_name = pkg["name"]
        pkg_version = pkg["version"]
        key = f"npm:{pkg_name}@{pkg_version}"
        advisories = osv_batch.advisories.get(key, [])

        for adv in advisories:
            # Determine range expression from affected ranges
            range_strs = []
            fixed_versions: list[str] = []
            for ar in adv.affected_ranges:
                if ar.introduced and ar.fixed:
                    range_strs.append(f">={ar.introduced} <{ar.fixed}")
                elif ar.fixed:
                    range_strs.append(f"<{ar.fixed}")
                elif ar.introduced:
                    range_strs.append(f">={ar.introduced}")
                if ar.fixed and NpmVersion.parse(ar.fixed) is not None:
                    fixed_versions.append(ar.fixed)

            range_summary = ", ".join(range_strs) if range_strs else None

            vulnerabilities.append({
                "advisory_id": adv.advisory_id,
                "severity": adv.severity or "medium",
                "summary": adv.summary or f"Vulnerability in {pkg_name}@{pkg_version}",
                "source": "osv.dev",
                "source_timestamp": adv.modified or adv.published or datetime.now(timezone.utc).isoformat(),
                "fixture": False,
                "affected": {
                    "package": ["npm", pkg_name, pkg_version],
                    "range": range_summary,
                },
            })

            # Derive genuine upgrade candidates from verified advisory fixed versions
            parsed_current = NpmVersion.parse(pkg_version)
            for fix_ver in fixed_versions:
                parsed_fix = NpmVersion.parse(fix_ver)
                # Only propose candidate if it is genuinely a higher version (not a downgrade or same)
                if parsed_current and parsed_fix and parsed_fix > parsed_current:
                    cand_id = f"{pkg_name}:{pkg_version}->{fix_ver}"
                    if cand_id not in upgrade_candidates_map:
                        cost = compute_compatibility_cost(pkg_version, fix_ver)
                        upgrade_candidates_map[cand_id] = {
                            "package_name": pkg_name,
                            "from_version": pkg_version,
                            "to_version": fix_ver,
                            "compatibility_cost": cost,
                        }

    model = {
        "label": f"{inventory['project_name']} (local repository: {root.name})",
        "fixture": False,
        "source": "local",
        "project": {
            "project_id": inventory["project_name"],
            "name": inventory["project_name"],
            "root_label": str(root),
        },
        "packages": inventory["packages"],
        "dependencies": inventory["dependencies"],
        "files": files,
        "imports": imports,
        "entry_points": entry_points,
        "reaches": reaches,
        "vulnerabilities": vulnerabilities,
        "upgrade_candidates": list(upgrade_candidates_map.values()),
        "osv_errors": osv_batch.errors,
    }

    return model
