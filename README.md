# BlastRadius

> **Graph-Powered npm Vulnerability Triage & Reachability Analysis**  
> Built for the **FalkorDB Hackathon 2026** — *Track 01: Agents That Act on Connected Data*

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![FalkorDB](https://img.shields.io/badge/FalkorDB-RedisGraph_Protocol-red.svg)](https://www.falkordb.com/)
[![React](https://img.shields.io/badge/React-19.0-61dafb.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178c6.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Backend_Tests-168_Passed-brightgreen.svg)]()

---

## 1. Problem: The Transitive Dependency Alert Avalanche

Modern JavaScript and TypeScript applications routinely contain hundreds to thousands of transitive dependencies in their lockfiles. When standard Software Composition Analysis (SCA) scanners inspect `package-lock.json`, they produce flat, decontextualized lists of dozens or hundreds of CVE/GHSA alerts.

Security engineers and developers face three critical bottlenecks:
1. **No Reachability Context:** Traditional scanners report that a package is vulnerable, but cannot answer: *Is this package ever imported by our codebase? Does any application entry point reach the file importing it? Or is it a dormant dependency of a build tool?*
2. **Alert Fatigue & Inverted Priorities:** A low-severity vulnerability in an actively imported web-facing handler often presents far higher operational risk than a critical CVE in an unreachable helper library.
3. **Risky, Blind Upgrades:** Automated tools frequently suggest blind major version bumps or fail to distinguish between patch updates and breaking API changes, leading to broken builds or stalled remediations.

---

## 2. Solution: Graph-Powered Triage with FalkorDB

**BlastRadius** transforms flat npm dependency trees and repository code into a connected property graph stored in **FalkorDB**. 

By unifying three distinct data layers into a single graph model:
1. **The Manifest & Lockfile Layer** (`Project`, `Package`, `DEPENDS_ON`),
2. **The Code Structure Layer** (`File`, `EntryPoint`, `IMPORTS`, `REACHES`), and
3. **The Vulnerability & Remediation Layer** (`Vuln`, `AFFECTS`, `UpgradeCandidate`),

BlastRadius uses Cypher graph traversals to evaluate structural reachability, classify evidence categories, calculate deterministic risk scores, and propose minimal-cost remediation patches.

### Core Workflow
```
[Local npm Project] 
       │
       ├──> Dependency Parser (package.json + package-lock.json v2/v3)
       ├──> Static Import Scanner (AST/Regex over .js, .ts, .jsx, .tsx)
       └──> OSV.dev REST API (live CVE/GHSA advisory query)
                    │
                    ▼
          [ FalkorDB Graph ]
    (Nodes: Project, Package, File, EntryPoint, Vuln, UpgradeCandidate)
    (Edges: DEPENDS_ON, IMPORTS, REACHES, AFFECTS, HAS_UPGRADE_OPTION)
                    │
       ┌────────────┴────────────┐
       ▼                         ▼
[Risk Engine & Cypher]    [Remediation Planner]
• 4-tier reachability     • SemVer 2.0.0 evaluator
• Deterministic scoring   • Compatibility cost (patch/minor/major)
• Structural path trace   • Reviewable package.json unified diff
                    │
                    ▼
          [ Product UI (React 19) ]
```

---

## 3. Technology Stack & Architecture

- **Graph Database:** [FalkorDB](https://www.falkordb.com/) (low-latency Graph database using Redis protocol via Cypher queries).
- **Backend Service:** Python 3.11+, [FastAPI](https://fastapi.tiangolo.com/), Uvicorn, Pydantic v2.
- **Vulnerability Data:** [OSV.dev REST API](https://osv.dev/) (batch queries per package version, offline fallback to labelled fixtures).
- **Frontend Dashboard:** [React 19](https://react.dev/), [TypeScript](https://www.typescriptlang.org/), [Vite 6](https://vitejs.dev/), CSS Custom Properties (dark-mode security operations console).

---

## 4. Graph Data Model & Schema

BlastRadius operates on the `blast_radius` graph inside FalkorDB.

### Node Labels & Identity Keys

| Label | Primary Key Format | Properties | Description |
|---|---|---|---|
| `Project` | `project_id` (`demo-app`) | `name`, `root_label` | Root repository project definition |
| `Package` | `package_key` (`npm:lodash@4.17.21`) | `ecosystem`, `name`, `version`, `direct` | Resolved installed npm package |
| `File` | `file_key` (`demo-app:src/index.js`) | `relative_path`, `extension` | Project source file |
| `EntryPoint` | `entry_key` (`demo-app:entry:src/index.js`) | `relative_path`, `type` | Application entry point (`main`, `bin`, or web entry) |
| `Vuln` | `vuln_key` (`vuln:GHSA-xxx`) | `advisory_id`, `severity`, `summary`, `source`, `fixture` | Security vulnerability advisory |
| `Scan` | `scan_id` (`scan-local-xxx` / `scan-demo-fixture`) | `status`, `fixture`, `source`, `label` | Scan execution metadata |
| `UpgradeCandidate` | `candidate_key` (`upgrade:lodash:4.17.21->4.17.22`) | `package_name`, `from_version`, `to_version`, `compatibility_cost` | Safe target version candidate |

### Relationships & Directionality

```
(Project)-[:CONTAINS_PACKAGE]->(Package)
(Project)-[:CONTAINS_FILE]->(File)
(Project)-[:HAS_SCAN]->(Scan)
(Package)-[:DEPENDS_ON]->(Package)
(File)-[:IMPORTS]->(Package)
(Vuln)-[:AFFECTS]->(Package)
(EntryPoint)-[:REACHES]->(File)
(Package)-[:HAS_UPGRADE_OPTION]->(UpgradeCandidate)
```

> **Directional Integrity:** Notice that `(Vuln)-[:AFFECTS]->(Package)` points from the advisory to the package, and `(File)-[:IMPORTS]->(Package)` points from the source file to the package. The backend enforces automated sanity checks (`reversed_affects_count == 0`) to prevent graph schema inversions.

---

## 5. Cypher Queries: How Connected Data Solves Triage

BlastRadius relies on FalkorDB's Cypher engine for graph traversals:

### 1. Multi-Dimensional Findings Aggregation
```cypher
MATCH (v:Vuln)-[a:AFFECTS]->(p:Package)
OPTIONAL MATCH (f:File)-[:IMPORTS]->(p)
OPTIONAL MATCH (e:EntryPoint)-[:REACHES]->(f)
OPTIONAL MATCH (parent:Package)-[:DEPENDS_ON]->(p)
RETURN v.vuln_key AS vuln_key, v.advisory_id AS advisory_id, v.severity AS severity,
       v.summary AS summary, v.source AS source, v.fixture AS fixture,
       a.range AS affected_range,
       p.package_key AS package_key, p.name AS package_name, p.version AS package_version,
       p.direct AS direct,
       count(DISTINCT f) AS import_files,
       count(DISTINCT e) AS entry_points,
       count(DISTINCT parent) AS dependency_parents
```

### 2. Full Entry-Point Reachability Traversal (`confirmed_entry_path`)
Traces the complete structural chain from an application entry point to the vulnerable package:
```cypher
MATCH (v:Vuln {vuln_key: $vuln_key})-[a:AFFECTS]->(p:Package)
      <-[i:IMPORTS]-(f:File)<-[r:REACHES]-(e:EntryPoint)
RETURN v.advisory_id AS advisory_id,
       type(a) AS affects_type,
       p.package_key AS package_key,
       type(i) AS imports_type,
       f.relative_path AS file_path,
       type(r) AS reaches_type,
       e.relative_path AS entry_path,
       r.confidence_label AS confidence_label
LIMIT 25
```

### 3. Upgrade Candidate & Resolution Evaluation
Queries available target versions and maps them to affected packages:
```cypher
MATCH (p:Package)-[:HAS_UPGRADE_OPTION]->(c:UpgradeCandidate)
RETURN c.candidate_key AS candidate_key,
       c.package_name AS package_name,
       c.from_version AS from_version,
       c.to_version AS to_version,
       c.compatibility_cost AS compatibility_cost,
       p.package_key AS package_key
```

---

## 6. Risk Engine & Evidence Categories

BlastRadius classifies each finding into one of four mutually exclusive, deterministic **Evidence Categories**:

| Category | Definition | Risk Weight |
|---|---|---|
| `confirmed_entry_path` | A verified entry point has a graph path reaching a file that statically imports the package. | **1.0** (Full severity) |
| `imported_only` | A repository file statically imports the package, but no path was found from a known entry point. | **0.7** |
| `transitive_dependency_only` | Package exists in the dependency graph, but no source file in the repository imports it. | **0.4** |
| `no_path_found` | In isolated or dangling graphs, no structural path exists from code to package. | **0.2** |

### Risk Score Calculation
$$\text{Risk Score} = \text{Severity Score} \times \text{Evidence Weight}$$
- Severity scores: `critical` = 10.0, `high` = 8.0, `medium` = 5.0, `low` = 2.0.
- Scores are strictly deterministic. Ties are broken by `(evidence_priority, severity_score, advisory_id)`.

---

## 7. Remediation Planner & SemVer Compatibility Cost

BlastRadius evaluates upgrade paths without executing untrusted code or invoking package managers:

1. **SemVer 2.0.0 Evaluation:** A custom, dependency-free SemVer parser (`semver_evaluator.py`) verifies that proposed target versions fall outside all OSV advisory intervals (`introduced`, `fixed`, `last_affected`).
2. **Compatibility Cost Heuristics:**
   - **`patch`** (e.g. `4.17.21` $\rightarrow$ `4.17.22`): Same major and minor. Lowest regression risk.
   - **`minor`** (e.g. `4.17.21` $\rightarrow$ `4.18.0`): Same major, backward-compatible feature release.
   - **`major`** (e.g. `1.2.5` $\rightarrow$ `2.0.0`): Breaking changes possible. Highest review necessity.
3. **Reviewable Manifest Diffs:** Generates a unified diff for `package.json` (or `overrides` block for transitive packages).
4. **Safe Lockfile Guidance:** Instructs the developer to run `npm install --package-lock-only --ignore-scripts` to update the lockfile safely without running arbitrary npm lifecycle scripts.

---

## 8. Prerequisites & Local Setup

### System Prerequisites
- **Docker** & **Docker Compose** (for FalkorDB)
- **Python 3.11+**
- **Node.js 18+** & **npm**
- **PowerShell** (Windows) or **Bash** (macOS/Linux)

### Step 1: Start FalkorDB
Clone the repository and launch the FalkorDB container:
```bash
# If using the repo's docker-compose.yml:
docker compose up -d

# Or run FalkorDB directly via Docker:
docker run -d -p 6379:6379 --name falkordb falkordb/falkordb:latest
```

Verify FalkorDB is responding on port 6379:
```bash
docker ps
```

### Step 2: Set Up Backend (FastAPI)
```powershell
cd blast-radius\backend

# Create virtual environment (if not already created)
python -m venv .venv

# Activate virtual environment
# Windows:
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
# source .venv/bin/activate

# Install backend dependencies
pip install -r requirements.txt

# Run backend test suite (168 tests)
pytest -v

# Start FastAPI server on port 8000
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
- API Health Check: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

### Step 3: Set Up Frontend (React / Vite)
In a separate terminal window:
```powershell
cd blast-radius\frontend

# Install dependencies
npm install

# Verify production build and TypeScript checks
npm run build

# Start Vite dev server on port 5173
npm run dev
```
- Open Dashboard in Browser: [http://127.0.0.1:5173](http://127.0.0.1:5173)

### One-Click Launch Script (Windows)
```powershell
cd blast-radius
.\start.ps1
```

---

## 9. Demo Walkthrough

BlastRadius provides two distinct scanning modes in the UI:

### Mode A: Demo Fixture Mode (Offline & Reproducible)
1. Open [http://127.0.0.1:5173](http://127.0.0.1:5173).
2. The top status bar confirms `FalkorDB: connected (127.0.0.1:6379)`.
3. In the **Scan Controls** card, select the **📦 Demo Fixture** tab.
4. Click **Run Fixture Scan**.
5. Within milliseconds, the backend parses `demo/fixture-repo`, inserts the graph into FalkorDB, and returns the prioritized finding `FIXTURE-LODASH-PROTOTYPE`.
6. Inspect the **Evidence & Path Explorer** panel to observe the full chain:
   $$\text{Entry Point } (src/index.js) \xrightarrow{\text{REACHES}} \text{File } (src/index.js) \xrightarrow{\text{IMPORTS}} \text{Package } (lodash@4.17.21) \xrightarrow{\text{AFFECTS}} \text{Advisory}$$
7. Switch to the **Remediation & Upgrades** tab to view the proposed `lodash@4.17.22` patch, rationale, and reviewable `package.json` diff.

### Mode B: Local npm Project Mode (Live OSV.dev Integration)
1. In the **Scan Controls** card, click the **📁 Local npm Project** tab.
2. In the **Project Directory Path** input, click **Fill Demo Path** (which populates `demo/fixture-repo`) or enter an absolute path to any local npm project containing a `package.json` and `package-lock.json`.
3. Click **Scan Local Repository**.
4. The scanner extracts dependencies, scans source imports, queries the official **OSV.dev REST API** in batches, synchronizes findings with FalkorDB, and displays all real-world CVE/GHSA advisories ranked by risk score.
5. Review the remediation plan showing verified resolved advisories vs unverified advisories.

---

## 10. Safety Boundaries & Important Limitations

1. **Structural Reachability $\neq$ Exploitability:** Graph paths indicate that an import chain exists from an application entry point to a package. It does **not** prove runtime execution, dynamic method invocation, or that user input reaches the vulnerable sink.
2. **`no_path_found` is NOT "Safe":** If static analysis finds no import path, a package may still be executed via dynamic `require()`, worker threads, or CLI bin scripts. BlastRadius renders `no_path_found` with distinct amber warning styling rather than a green "safe" badge.
3. **Simulated vs. Live Data:** Fixture data is clearly labelled with `[SIMULATED DEMO]` badges. Live scans query OSV.dev and carry explicit advisory timestamps and source attribution.
4. **Human-in-the-Loop Remediations:** BlastRadius **never** edits files on disk, commits to git, creates pull requests, or installs packages automatically. All remediation candidates are non-destructive proposals for developer review.
5. **No Code Execution:** Scanning an npm project reads AST/text only. Lifecycle scripts (`preinstall`, `postinstall`) are never executed.

---

## 11. Verification & Test Suite

The BlastRadius test suite contains **168 automated pytest tests** covering unit, integration, and graph regression cases:

```powershell
cd blast-radius\backend
.\.venv\Scripts\pytest -v
```

### Test Coverage Highlights
- `test_dependency_parser.py`: Lockfile parsing (v2/v3), duplicate resolutions, error handling.
- `test_source_importer.py`: CJS/ESM import extraction, ignore rules (`node_modules`, dotfiles), size guards (>1MB).
- `test_graph_builder.py`: Idempotent Cypher upsert, graph schema directionality checks.
- `test_falkordb_probe.py` & `test_health.py`: Redis protocol ping, graph probing, 503 error handling.
- `test_vuln_provider.py`: OSV.dev batch API integration, network timeouts, malformed payloads, retry logic.
- `test_risk_engine.py`: Evidence weighting, tie-breaking, CVSS severity parsing.
- `test_semver_evaluator.py`: SemVer 2.0.0 precedence, prerelease comparisons, OSV event ranges (`introduced`, `fixed`, `last_affected`).
- `test_proposal_generator.py`: Reviewable unified diff generation, lockfile guidance.
- `test_project_scanner.py`: Local folder security traversal guards, forbidden directory rejections.
- `test_m11_e2e_validation.py`: End-to-end integration across all 11 milestone specifications.

Frontend builds and typechecks cleanly:
```powershell
cd blast-radius\frontend
npm run build
# tsc --noEmit && vite build -> 0 errors
```

---

## 12. Team & Hackathon Submission

- **Hackathon:** [FalkorDB Hackathon 2026](https://www.wemakedevs.org/hackathons/falkordb)
- **Track:** Track 01 — *Agents That Act on Connected Data*
- **Team Members:**
  - **Mohammed Ateeq** — [mohd.ateeq.march@gmail.com](mailto:mohd.ateeq.march@gmail.com)
  - **Mohammed Altaf Ul Rahman** — [mohd.altafulrahman@gmail.com](mailto:mohd.altafulrahman@gmail.com)
- **GitHub Repository:** [https://github.com/Mohammed-Ateeq-nova/blastradius](https://github.com/Mohammed-Ateeq-nova/blastradius)
- **Demo Video:** *YouTube link submitted via hackathon portal*
