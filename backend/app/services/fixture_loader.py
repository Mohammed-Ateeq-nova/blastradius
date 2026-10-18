from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.services.dependency_parser import parse_npm_project
from app.services.source_importer import extract_static_imports

FIXTURE_ROOT = Path(__file__).resolve().parents[3] / "demo" / "fixture-repo"

DEMO_FIXTURE: dict[str, Any] = {
    "label": "DEMO FIXTURE — not a live vulnerability scan",
    "fixture": True,
    "project": {
        "project_id": "demo-app",
        "name": "demo-app",
        "root_label": "demo/fixture-repo",
    },
    "packages": [
        {
            "name": "demo-app",
            "version": "1.0.0",
            "ecosystem": "npm",
            "direct": True,
            "declared_constraint": "1.0.0",
        },
        {
            "name": "lodash",
            "version": "4.17.21",
            "ecosystem": "npm",
            "direct": True,
            "declared_constraint": "^4.17.0",
        },
        {
            "name": "minimist",
            "version": "1.2.5",
            "ecosystem": "npm",
            "direct": False,
            "declared_constraint": "1.2.5",
        },
    ],
    "dependencies": [
        {
            "from": ["npm", "demo-app", "1.0.0"],
            "to": ["npm", "lodash", "4.17.21"],
            "direct": True,
            "constraint": "^4.17.0",
            "source": "fixture-lockfile",
        },
        {
            "from": ["npm", "lodash", "4.17.21"],
            "to": ["npm", "minimist", "1.2.5"],
            "direct": False,
            "constraint": "1.2.5",
            "source": "fixture-lockfile",
        },
    ],
    "files": [{"relative_path": "src/index.js", "language": "javascript"}],
    "imports": [
        {"file": "src/index.js", "package": ["npm", "lodash", "4.17.21"]},
    ],
    "entry_points": [
        {
            "relative_path": "src/index.js",
            "kind": "package_main",
            "evidence_source": "package.json main",
        }
    ],
    "reaches": [
        {
            "entry": "src/index.js",
            "file": "src/index.js",
            "evidence_type": "entry_is_file",
            "confidence_label": "potentially_reachable",
        }
    ],
    "vulnerabilities": [
        {
            "advisory_id": "FIXTURE-LODASH-PROTOTYPE",
            "severity": "high",
            "summary": "Labelled demo finding on lodash. Not fetched from an advisory API.",
            "source": "demo-fixture",
            "source_timestamp": "2026-10-16T00:00:00Z",
            "fixture": True,
            "affected": {
                "package": ["npm", "lodash", "4.17.21"],
                "range": "<=4.17.21",
            },
        }
    ],
    "upgrade_candidates": [
        {
            "package_name": "lodash",
            "from_version": "4.17.21",
            "to_version": "4.17.22",
            "compatibility_cost": "patch",
        }
    ],
}


def _package_identity(packages: list[dict[str, Any]], spec: str) -> list[str] | None:
    matches = [pkg for pkg in packages if pkg["name"] == spec]
    if len(matches) != 1:
        return None
    pkg = matches[0]
    return ["npm", pkg["name"], pkg["version"]]


def load_demo_fixture() -> dict[str, Any]:
    inventory = parse_npm_project(FIXTURE_ROOT)
    imported = extract_static_imports(FIXTURE_ROOT)
    files = [{"relative_path": item["relative_path"], "language": item["language"]} for item in imported]
    imports = []
    for item in imported:
        for spec in item["specifiers"]:
            identity = _package_identity(inventory["packages"], spec)
            if identity:
                imports.append({"file": item["relative_path"], "package": identity})
    manifest = json.loads((FIXTURE_ROOT / "package.json").read_text(encoding="utf-8"))
    main = str(manifest.get("main") or "src/index.js").replace("\\", "/")
    if not any(file["relative_path"] == main for file in files):
        files.append({"relative_path": main, "language": "javascript"})
    model = {
        "label": DEMO_FIXTURE["label"],
        "fixture": True,
        "project": {
            "project_id": inventory["project_name"],
            "name": inventory["project_name"],
            "root_label": "demo/fixture-repo",
        },
        "packages": inventory["packages"],
        "dependencies": inventory["dependencies"],
        "files": files,
        "imports": imports,
        "entry_points": [
            {
                "relative_path": main,
                "kind": "package_main",
                "evidence_source": "package.json main",
            }
        ],
        "reaches": [
            {
                "entry": main,
                "file": main,
                "evidence_type": "entry_is_file",
                "confidence_label": "potentially_reachable",
            }
        ],
        "vulnerabilities": DEMO_FIXTURE["vulnerabilities"],
        "upgrade_candidates": DEMO_FIXTURE["upgrade_candidates"],
    }
    return model
