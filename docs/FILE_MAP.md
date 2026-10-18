# BlastRadius — File Map (verified 2026-10-16, M5 complete)

> All sizes and status verified by directory listing and test run this session.
> **86 pytest tests pass.**

## Project root: `blast-radius/`

| Path | Purpose | Status |
|---|---|---|
| `backend/` | FastAPI Python API | ✅ M1–M3 |
| `frontend/` | Vite + React + TypeScript UI | ✅ M1 |
| `demo/` | Fixture repository used by tests | ✅ M3 |
| `docs/FILE_MAP.md` | This file | ✅ |
| `start.ps1` | Dev launch helper (PowerShell) | ✅ |
| `.gitignore` | Ignores venv, dist, __pycache__ | ✅ |

---

## Backend: `blast-radius/backend/`

### App: `blast-radius/backend/app/`

| File | Purpose | Status |
|---|---|---|
| `__init__.py` | Package init (`version = "0.1.0"`) | ✅ |
| `main.py` | FastAPI app factory; mounts health + scans routers | ✅ |
| `config.py` | `Settings` (pydantic-settings): FALKORDB_HOST, PORT, GRAPH; loads `.env` | ✅ |

#### API layer: `app/api/`

| File | Purpose |
|---|---|
| `health.py` | `GET /api/health` — Redis PING + GRAPH.LIST probe |
| `scans.py` | `POST /api/scans` (source=fixture only), `GET /api/scans/{id}`, `GET /api/scans/{id}/findings`, `GET /api/findings/{id}/paths` |

#### DB layer: `app/db/`

| File | Purpose |
|---|---|
| `falkordb.py` | `create_redis_client()`, `probe_falkordb()` → `FalkorProbe` dataclass |
| `graph.py` | `FalkorGraph` wrapper: `.query()` with `parse_query_result()`; `.delete()` |

#### Services: `app/services/`

| File | Purpose | M-status |
|---|---|---|
| `graph_ids.py` | `package_key`, `file_key`, `entry_key`, `vuln_key`, `candidate_key`, `normalize_relpath` | M2 |
| `dependency_parser.py` | `parse_npm_project(root)` — reads `package.json` + `package-lock.json` (lockfileVersion 2+), resolves nested duplicate versions, returns `{project_name, project_version, packages[], dependencies[]}` | **M3** |
| `source_importer.py` | `extract_static_imports(root)` — regex scans `.js/.ts/.jsx/.tsx` (skips `node_modules/`, relative specifiers), flags dynamic requires | **M3** |
| `fixture_loader.py` | `load_demo_fixture()` — calls both parsers on `demo/fixture-repo`, merges results with fixed vuln/upgrade_candidates | **M3** |
| `graph_builder.py` | `upsert_fixture_graph(client, graph_name, model, scan_id)` — idempotent MERGE for Project, Scan, Package, DEPENDS_ON, File, IMPORTS, EntryPoint, REACHES, Vuln, AFFECTS, UpgradeCandidate | M2 |
| `graph_queries.py` | `list_findings()`, `finding_paths()`, `list_upgrade_candidates()`, `package_count()`, `reversed_affects_count()` | **M5** |
| `vuln_provider.py` | `OsvProvider.query_batch()` — queries OSV.dev REST API (`POST /v1/query`) per package, normalizes into `OsvAdvisory` and `OsvBatchResult`, handles timeouts/errors cleanly with stdlib urllib | **M4** |
| `risk_engine.py` | `classify_evidence()`, `compute_risk_score()`, `rank_findings()`, `check_version_resolves()`, `compute_compatibility_cost()`, `evaluate_upgrade_candidates()` | **M5** |
| `semver_evaluator.py` | `NpmVersion`, `NpmRange`, `evaluate_osv_interval()`, `is_upgrade_a_fix()` — SemVer 2.0.0 parser, prerelease precedence, OSV events & npm range desugaring | **M5** |
| `project_scanner.py` | `validate_project_directory()`, `scan_local_project()` — safe validation, entry point detection, static import extraction, OSV live queries, verified upgrade candidate derivation | **M8** |

### Tests: `blast-radius/backend/tests/`

| File | Tests | Pass |
|---|---|---|
| `test_dependency_parser.py` | 4 — fixture lockfile, missing lockfile error, malformed JSON, duplicate versions | ✅ |
| `test_source_importer.py` | 2 — CJS require from fixture, dynamic require ignored | ✅ |
| `test_graph_builder.py` | 1 (skips without FalkorDB) — idempotent upsert, path direction, 3 packages, 1 finding | ✅ |
| `test_graph_ids.py` | 4 — key format, normalize_relpath, traversal guard | ✅ |
| `test_graph_parse.py` | 2 — parse_query_result shapes | ✅ |
| `test_falkordb_probe.py` | 3 — probe result shape, mock unavailable | ✅ |
| `test_health.py` | 2 — health endpoint with mock | ✅ |
| `test_risk_engine.py` | 19 — evidence classification, severity parsing, risk scoring, tie-breaking, semver heuristics, range resolution, FalkorDB 4-category integration, multi-path deduplication | ✅ |
| `test_scans_api.py` | 2 — reject non-fixture source, full fixture scan flow with M5 findings & remediations | ✅ |
| `test_scans_api_m8.py` | 4 — missing path, invalid path, missing lockfile, and full local scan flow | ✅ **M8** |
| `test_semver_evaluator.py` | 21 — SemVer 2.0.0 precedence, prereleases, OSV events (introduced, fixed, last_affected), multi-interval union, npm ranges (^, ~, -, ||, *), false-pos/neg regressions | ✅ |
| `test_vuln_provider.py` | 26 — mock matching/empty/malformed/HTTP errors/timeouts/batch errors, and live OSV integration | ✅ |
| `test_m7_integration.py` | 5 — repeated scan idempotence, 404 on unknown scan, unknown finding path handling, FalkorDB 503 error handling | ✅ **M7** |
| `test_project_scanner.py` | 10 — directory validation (empty, nonexistent, file, missing manifest, missing lockfile, relative path, forbidden system dirs), local scan model structure & downgrade filtering | ✅ **M8/M9** |
| `test_source_importer.py` | 5 — CJS require, dynamic require, excluded directories, oversized files (>1MB), and symlink escape checks | ✅ **M9** |
| `test_scan_isolation.py` | 3 — sequential multi-project isolation, failed scan graph preservation, and unrelated graph safety | ✅ **M9** |

**Total: 111 passed, 0 failed** (CPython 3.11, pytest 9.1.1, 2026-10-18)

---

## Frontend: `blast-radius/frontend/`

| File | Purpose | Status |
|---|---|---|
| `index.html` | Vite entry HTML with Inter & JetBrains Mono fonts and metadata | ✅ M6 |
| `vite.config.ts` | Dev server proxies `/api` → `http://127.0.0.1:8000` | ✅ |
| `package.json` | React 19, TypeScript, Vite 6 | ✅ |
| `src/main.tsx` | React root mount | ✅ |
| `src/types.ts` | TypeScript interfaces matching backend models & endpoints | ✅ M6 |
| `src/api.ts` | Typed client for all 5 backend endpoints | ✅ M6 |
| `src/styles.css` | Security dashboard design tokens, cards, badges, animations | ✅ M6 |
| `src/components/StatusBar.tsx` | FalkorDB status, host/port, graphs count, backend health | ✅ M6 |
| `src/components/ScanControls.tsx` | Scan trigger button, loading spinner, coverage statistics | ✅ M6 |
| `src/components/Badges.tsx` | Severity, evidence categories, compatibility cost, score colors | ✅ M6 |
| `src/components/FindingsList.tsx` | Ranked findings list with scores, reachability, fixture badges | ✅ M6 |
| `src/components/DetailPanel.tsx` | Tabbed panel for Evidence & Details vs Remediation Plan | ✅ M6/M7 |
| `src/components/EvidencePathView.tsx` | Reachability traversal chain, limitations, No-Path disclaimer | ✅ M6/M7 |
| `src/components/RemediationsView.tsx` | Upgrade candidates, compatibility cost, verified fix separation | ✅ M6 |
| `src/App.tsx` | Master dashboard orchestration, state clearing, auto-selection | ✅ M6 |
| `dist/` | Production bundle (`npm run build` passes cleanly) | ✅ M6/M7 |

---

## Demo fixture: `blast-radius/demo/fixture-repo/`

| File | Purpose |
|---|---|
| `package.json` | `demo-app@1.0.0`, `dependencies: { lodash: "^4.17.0" }`, `main: "src/index.js"` |
| `package-lock.json` | lockfileVersion 2: lodash@4.17.21, minimist@1.2.5 (transitive) |
| `src/index.js` | CJS `require("lodash")` — static only, never executed |

---

## Docs: `blast-radius/docs/`

| File | Purpose |
|---|---|
| `GRAPH_SCHEMA.md` | Node/edge/property schema for the blast_radius graph |
| `FILE_MAP.md` | This file |

---

## Handoff docs: `BlastRadius_Agent_Handoff_Pack/BlastRadius_Project_Pack/`

| File | Purpose |
|---|---|
| `README_FOR_AGENTS.md` | Agent orientation / constraints |
| `PROJECT_CONTEXT.md` | Milestone state, decisions, environment |
| `SRD.md` | Software Requirements Document |
| `SDD.md` | Software Design Document |
| `IMPLEMENTATION_PLAN.md` | M0–M9 milestone plan |
| `AGENT_LOOP.md` | Loop instructions for AI agents |

---

## Next milestone: M4 — Vulnerability Adapter

**Goal:** Define a `VulnerabilityProvider` interface. Implement one real advisory source
(OSV.dev REST API — free, no auth required) **or** an improved labelled fixture with
real CVE metadata (GHSA IDs, published timestamps, CVSS scores).

**Acceptance criteria:**
1. Each vulnerability record carries `source`, `source_timestamp`, `advisory_id` traceable to the data origin.
2. A provider test can run offline (mock HTTP) and also against the live OSV API (skipped if network unavailable).
3. The fixture scan (`POST /api/scans` source=fixture) continues to pass all 20 existing tests.
4. At least one real OSV advisory (e.g. `GHSA-p6mc-m468-83gw` for lodash prototype pollution) is resolved to the `demo-app` graph when FalkorDB is available.
