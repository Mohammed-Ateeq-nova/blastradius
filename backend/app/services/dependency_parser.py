from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class NpmInventoryError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _load_json(path: Path, code: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NpmInventoryError(code, f"cannot parse {path.name}") from exc


def _package_name_from_lock_path(lock_path: str, meta: dict[str, Any]) -> str | None:
    if meta.get("name"):
        return str(meta["name"])
    parts = lock_path.replace("\\", "/").split("/")
    if "node_modules" not in parts:
        return None
    return parts[-1] or None


def _resolve_dep(packages: dict[str, Any], parent_path: str, dep_name: str) -> str | None:
    prefix = f"{parent_path}/" if parent_path else ""
    nested = f"{prefix}node_modules/{dep_name}"
    if nested in packages:
        return nested
    if not parent_path:
        return None
    current = parent_path
    while True:
        if current.endswith("/node_modules") or current == "node_modules":
            parent = current.rsplit("/", 1)[0] if "/" in current else ""
        elif "/node_modules/" in current:
            parent = current.rsplit("/node_modules/", 1)[0]
        else:
            parent = ""
        candidate = f"{parent + '/' if parent else ''}node_modules/{dep_name}"
        if candidate in packages:
            return candidate
        if not parent:
            return None
        current = parent


def parse_npm_project(root: Path) -> dict[str, Any]:
    root = Path(root)
    if not root.is_dir():
        raise NpmInventoryError("invalid_path", "repository root is not a directory")
    manifest_path = root / "package.json"
    lock_path = root / "package-lock.json"
    if not manifest_path.is_file():
        raise NpmInventoryError("missing_manifest", "package.json not found")
    if not lock_path.is_file():
        raise NpmInventoryError("missing_lockfile", "package-lock.json not found")

    manifest = _load_json(manifest_path, "malformed_manifest")
    lock = _load_json(lock_path, "malformed_manifest")
    if not isinstance(manifest, dict) or not isinstance(lock, dict):
        raise NpmInventoryError("malformed_manifest", "manifest or lockfile is not an object")

    packages_map = lock.get("packages")
    if not isinstance(packages_map, dict):
        raise NpmInventoryError("unsupported_lockfile", "lockfile must include a packages map (lockfileVersion 2+)")

    root_meta = packages_map.get("") or {}
    root_name = str(manifest.get("name") or root_meta.get("name") or root.name)
    root_version = str(manifest.get("version") or root_meta.get("version") or "0.0.0")
    declared = manifest.get("dependencies") if isinstance(manifest.get("dependencies"), dict) else {}

    packages: list[dict[str, Any]] = [
        {
            "name": root_name,
            "version": root_version,
            "ecosystem": "npm",
            "direct": True,
            "declared_constraint": root_version,
            "lock_path": "",
        }
    ]
    path_to_identity: dict[str, tuple[str, str, str]] = {
        "": ("npm", root_name, root_version),
    }

    for lock_pkg_path, meta in packages_map.items():
        if lock_pkg_path == "" or not isinstance(meta, dict):
            continue
        name = _package_name_from_lock_path(str(lock_pkg_path), meta)
        version = meta.get("version")
        if not name or not version:
            continue
        identity = ("npm", name, str(version))
        path_to_identity[str(lock_pkg_path)] = identity
        packages.append(
            {
                "name": name,
                "version": str(version),
                "ecosystem": "npm",
                "direct": name in declared,
                "declared_constraint": str(declared.get(name) or meta.get("version") or ""),
                "lock_path": str(lock_pkg_path),
            }
        )

    seen_keys: set[tuple[str, str, str]] = set()
    unique_packages: list[dict[str, Any]] = []
    for pkg in packages:
        key = (pkg["ecosystem"], pkg["name"], pkg["version"])
        if key in seen_keys:
            if pkg["direct"]:
                for existing in unique_packages:
                    if (existing["ecosystem"], existing["name"], existing["version"]) == key:
                        existing["direct"] = True
            continue
        seen_keys.add(key)
        unique_packages.append(pkg)

    dependencies: list[dict[str, Any]] = []
    seen_edges: set[tuple] = set()
    for lock_pkg_path, meta in packages_map.items():
        if not isinstance(meta, dict):
            continue
        parent_id = path_to_identity.get(str(lock_pkg_path))
        if not parent_id:
            continue
        reqs = meta.get("dependencies") if isinstance(meta.get("dependencies"), dict) else {}
        for dep_name, constraint in reqs.items():
            resolved = _resolve_dep(packages_map, str(lock_pkg_path), str(dep_name))
            if not resolved or resolved not in path_to_identity:
                continue
            child_id = path_to_identity[resolved]
            edge = (parent_id, child_id)
            if edge in seen_edges:
                continue
            seen_edges.add(edge)
            dependencies.append(
                {
                    "from": list(parent_id),
                    "to": list(child_id),
                    "direct": str(lock_pkg_path) == "" and dep_name in declared,
                    "constraint": str(constraint),
                    "source": "package-lock.json",
                }
            )

    return {
        "project_name": root_name,
        "project_version": root_version,
        "packages": unique_packages,
        "dependencies": dependencies,
    }
