from __future__ import annotations

from pathlib import PurePosixPath


def package_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}@{version}"


def normalize_relpath(relative_path: str) -> str:
    raw = relative_path.replace("\\", "/").strip()
    path = PurePosixPath(raw)
    parts: list[str] = []
    for part in path.parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError("path traversal is not allowed")
        parts.append(part)
    if not parts:
        raise ValueError("empty relative path")
    return "/".join(parts)


def file_key(project_id: str, relative_path: str) -> str:
    return f"{project_id}:{normalize_relpath(relative_path)}"


def entry_key(project_id: str, relative_path: str) -> str:
    return f"{project_id}:entry:{normalize_relpath(relative_path)}"


def vuln_key(advisory_id: str) -> str:
    return f"vuln:{advisory_id}"


def candidate_key(package_name: str, from_version: str, to_version: str) -> str:
    return f"upgrade:{package_name}:{from_version}->{to_version}"
