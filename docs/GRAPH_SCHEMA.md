# BlastRadius graph schema (M2)

See also `BlastRadius_Agent_Handoff_Pack/BlastRadius_Project_Pack/docs/GRAPH_SCHEMA.md`.

Implemented on FalkorDB graph `blast_radius` (tests use `blast_radius_test`).
The application uses `GRAPH.QUERY` directly. MCP is not part of this path.

## Node identity

| Label | Key | Format |
|---|---|---|
| Project | `project_id` | `demo-app` |
| Package | `package_key` | `npm:{name}@{version}` |
| File | `file_key` | `{project_id}:{normalized/relative/path}` |
| Vuln | `vuln_key` | `vuln:{advisory_id}` |
| EntryPoint | `entry_key` | `{project_id}:entry:{relative_path}` |
| Scan | `scan_id` | `scan-demo-fixture` |
| UpgradeCandidate | `candidate_key` | `upgrade:{name}:{from}->{to}` |

## Relationships (direction)

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

Risk-path query:

```
MATCH (v:Vuln)-[:AFFECTS]->(p:Package)<-[:IMPORTS]-(f:File)<-[:REACHES]-(e:EntryPoint)
```
