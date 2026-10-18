from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.services.graph_ids import normalize_relpath

STATIC_REQUIRE = re.compile(r"""(?:^|[^\w.$])require\(\s*(['"])([^'"]+)\1\s*\)""")
STATIC_IMPORT_FROM = re.compile(r"""(?:^|[^\w.$])import(?:[\s\S]*?)from\s*(['"])([^'"]+)\1""")
STATIC_IMPORT_ONLY = re.compile(r"""(?:^|[^\w.$])import\s*(['"])([^'"]+)\1""")
DYNAMIC_HINTS = re.compile(
    r"""require\(\s*[^'"\s]|require\(\s*`|import\s*\(""",
)

EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
EXCLUDED_DIRS = {
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "dist",
    "build",
    ".next",
    "coverage",
    ".venv",
}
MAX_SOURCE_FILE_SIZE = 1_048_576  # 1 MB DoS limit for static source analysis


def _language(path: Path) -> str:
    if path.suffix in {".ts", ".tsx"}:
        return "typescript"
    return "javascript"


def extract_static_imports(root: Path) -> list[dict[str, Any]]:
    root = Path(root)
    resolved_root = root.resolve(strict=True)
    results: list[dict[str, Any]] = []

    for path in root.rglob("*"):
        # Skip if not a regular file or supported extension
        if not path.is_file() or path.suffix not in EXTENSIONS:
            continue

        # Skip excluded vendor/vcs/build directories
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue

        # Guard against symlinks pointing outside the repository root
        try:
            resolved_path = path.resolve(strict=True)
            if not resolved_path.is_relative_to(resolved_root):
                continue
        except (OSError, RuntimeError):
            continue

        # Guard against oversized files (DoS protection)
        try:
            if path.stat().st_size > MAX_SOURCE_FILE_SIZE:
                continue
        except OSError:
            continue

        relative = normalize_relpath(str(path.relative_to(root)))
        text = path.read_text(encoding="utf-8", errors="replace")
        specifiers: list[str] = []
        for match in STATIC_REQUIRE.finditer(text):
            specifiers.append(match.group(2))
        for match in STATIC_IMPORT_FROM.finditer(text):
            specifiers.append(match.group(2))
        for match in STATIC_IMPORT_ONLY.finditer(text):
            specifiers.append(match.group(2))
        unique = list(dict.fromkeys(specifiers))
        package_specs = [item for item in unique if not item.startswith(".")]
        unsupported: list[str] = []
        if DYNAMIC_HINTS.search(text):
            unsupported.append("dynamic_or_unsupported")
        results.append(
            {
                "relative_path": relative,
                "language": _language(path),
                "specifiers": package_specs,
                "unsupported": unsupported,
            }
        )
    return results
