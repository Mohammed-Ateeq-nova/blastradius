// ---------------------------------------------------------------------------
// BlastRadius — shared TypeScript types (derived from backend API schemas)
// ---------------------------------------------------------------------------

// --- Health ---

export interface FalkorDBStatus {
  connected: boolean;
  host: string;
  port: number;
  graphs: string[];
  error: string | null;
}

export interface HealthResponse {
  status: string;
  backend: string;
  mcp_required: boolean;
  falkordb: FalkorDBStatus;
}

// --- Scan Coverage ---

export interface ScanCoverage {
  project_name: string;
  root_label: string;
  packages_scanned: number;
  files_scanned: number;
  entry_points_scanned: number;
}

// --- Scan ---

export type ScanSource = "fixture" | "local";

export interface ScanRequest {
  source: ScanSource;
  path?: string;
}

export interface ScanResponse {
  scan_id: string;
  status: string;
  fixture: boolean;
  label: string;
  graph?: string;
  finding_count: number;
  coverage: ScanCoverage;
  warnings?: string[];
}

// --- Evidence Categories (maps to risk_engine.py constants) ---

export type EvidenceCategory =
  | "confirmed_entry_path"
  | "imported_only"
  | "transitive_dependency_only"
  | "no_path_found";

// --- Finding (from graph_queries.list_findings → rank_findings) ---

export interface Finding {
  finding_id: string;
  advisory_id: string;
  severity: string;
  summary: string;
  source: string;
  fixture: boolean;
  package_key: string;
  package_name: string;
  package_version: string;
  affected_range: string | null;
  evidence_category: EvidenceCategory;
  evidence_label: string;
  import_files_count: number;
  entry_points_count: number;
  // Added by rank_findings()
  risk_score: number;
  severity_score: number;
  severity_estimated: boolean;
  evidence_weight: number;
  evidence_priority: number;
  limitations: string[];
  rank: number;
}

export interface FindingsResponse {
  scan_id: string;
  fixture: boolean;
  findings: Finding[];
}

// --- Evidence Paths (from graph_queries.finding_paths) ---

export interface PathEdge {
  type: string;
  from: string;
  to: string;
}

export interface EvidencePath {
  advisory_id: string;
  package_key: string;
  file_path: string | null;
  entry_path: string | null;
  edges: PathEdge[];
  evidence_category: EvidenceCategory;
  evidence_label: string;
  evidence_type: string;
  limitations: string;
}

export interface PathsResponse {
  finding_id: string;
  paths: EvidencePath[];
  path_count: number;
  evidence_note: string;
}

// --- Remediation Candidates (from risk_engine.evaluate_upgrade_candidates) ---

export interface ResolvedFinding {
  advisory_id: string;
  risk_score: number;
  evidence_category: string;
}

export interface UnresolvedFinding {
  advisory_id: string;
  reason: string;
}

// --- Remediation Proposal (from proposal_generator.build_remediation_proposal) ---

export type PatchType = "direct" | "override" | "unknown" | "error";
export type ApprovalState = "pending_review" | "approved" | "rejected";

export interface RemediationProposal {
  candidate_key: string | null;
  package_name: string;
  from_version: string;
  to_version: string;
  compatibility_cost: string;
  is_synthetic_fixture: boolean;
  manifest_path: string;
  /** Unified diff text for package.json — empty string if not applicable */
  manifest_diff: string;
  patch_type: PatchType;
  manifest_note: string;
  lockfile_guidance: string;
  resolved_findings_count: number;
  unresolved_findings_count: number;
  unverified_findings_count: number;
  risk_eliminated: number;
  rationale: string;
  reachability_caveat: string;
  approval_required: boolean;
  approval_state: ApprovalState;
}

export interface RemediationCandidate {
  candidate_key: string;
  package_name: string;
  from_version: string;
  to_version: string;
  compatibility_cost: string;
  resolved_findings_count: number;
  resolved_findings: ResolvedFinding[];
  unresolved_findings_count: number;
  unresolved_findings: UnresolvedFinding[];
  unverified_findings_count: number;
  unverified_findings: UnresolvedFinding[];
  risk_eliminated: number;
  cost_order: number;
  rank: number;
  /** Present when the backend could build a proposal for this candidate */
  proposal?: RemediationProposal;
}

export interface RemediationsResponse {
  scan_id: string;
  remediation_candidates: RemediationCandidate[];
  candidate_count: number;
}
