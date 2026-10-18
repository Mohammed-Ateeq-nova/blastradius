import { useState } from "react";
import type {
  EvidencePath,
  Finding,
  RemediationCandidate,
} from "../types";
import { EvidenceBadge, getScoreClass, SeverityBadge } from "./Badges";
import { EvidencePathView } from "./EvidencePathView";
import { RemediationsView } from "./RemediationsView";

interface DetailPanelProps {
  selectedFinding: Finding | null;
  paths: EvidencePath[];
  pathsLoading: boolean;
  pathsError: string | null;
  evidenceNote?: string;
  remediations: RemediationCandidate[];
  remediationsLoading: boolean;
  remediationsError: string | null;
}

export function DetailPanel({
  selectedFinding,
  paths,
  pathsLoading,
  pathsError,
  evidenceNote,
  remediations,
  remediationsLoading,
  remediationsError,
}: DetailPanelProps) {
  const [activeTab, setActiveTab] = useState<"evidence" | "remediations">(
    "evidence"
  );

  return (
    <main className="detail-panel" aria-label="Inspection and Remediations">
      <nav className="tabs" aria-label="Detail Sections">
        <button
          type="button"
          className={`tab ${activeTab === "evidence" ? "tab--active" : ""}`}
          onClick={() => setActiveTab("evidence")}
          aria-selected={activeTab === "evidence"}
        >
          Graph Evidence &amp; Details
        </button>

        <button
          type="button"
          className={`tab ${activeTab === "remediations" ? "tab--active" : ""}`}
          onClick={() => setActiveTab("remediations")}
          aria-selected={activeTab === "remediations"}
        >
          Remediation Plan{" "}
          {remediations.length > 0 && `(${remediations.length})`}
        </button>
      </nav>

      {activeTab === "evidence" ? (
        selectedFinding ? (
          <div className="animate-in">
            {/* Finding Header & Score Breakdown */}
            <section className="detail-section">
              <div className="finding-info">
                <h3 className="finding-info__advisory">
                  {selectedFinding.advisory_id}
                </h3>

                <p className="finding-info__summary">
                  {selectedFinding.summary}
                </p>

                <div className="finding-info__meta">
                  <SeverityBadge severity={selectedFinding.severity} />
                  <EvidenceBadge
                    category={selectedFinding.evidence_category}
                    label={selectedFinding.evidence_label}
                  />
                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.8125rem",
                      color: "var(--text-secondary)",
                    }}
                  >
                    {selectedFinding.package_key}
                  </span>
                  {selectedFinding.affected_range && (
                    <span
                      style={{
                        fontSize: "0.75rem",
                        color: "var(--text-tertiary)",
                      }}
                    >
                      Affected: {selectedFinding.affected_range}
                    </span>
                  )}
                  {selectedFinding.fixture && (
                    <span className="finding-row__fixture">Demo Fixture</span>
                  )}
                </div>

                <div className="score-breakdown" style={{ marginTop: "0.75rem" }}>
                  <div className="score-breakdown__item">
                    <span
                      className={`score-breakdown__value ${getScoreClass(
                        selectedFinding.risk_score
                      )}`}
                    >
                      {selectedFinding.risk_score.toFixed(1)}
                    </span>
                    <span className="score-breakdown__label">Risk Score</span>
                  </div>

                  <div className="score-breakdown__item">
                    <span className="score-breakdown__value">
                      {selectedFinding.severity_score.toFixed(1)}
                      {selectedFinding.severity_estimated && "*"}
                    </span>
                    <span className="score-breakdown__label">
                      Base Severity
                    </span>
                  </div>

                  <div className="score-breakdown__item">
                    <span className="score-breakdown__value">
                      x{selectedFinding.evidence_weight.toFixed(1)}
                    </span>
                    <span className="score-breakdown__label">
                      Reachability Weight
                    </span>
                  </div>

                  <div className="score-breakdown__item">
                    <span className="score-breakdown__value">
                      {selectedFinding.import_files_count}
                    </span>
                    <span className="score-breakdown__label">
                      Importing Files
                    </span>
                  </div>

                  <div className="score-breakdown__item">
                    <span className="score-breakdown__value">
                      {selectedFinding.entry_points_count}
                    </span>
                    <span className="score-breakdown__label">
                      Entry Points
                    </span>
                  </div>
                </div>

                <div className="risk-formula-box">
                  <div className="risk-formula-box__formula">
                    <strong>Formula:</strong>{" "}
                    <code>
                      {selectedFinding.severity_score.toFixed(1)} (Severity) ×{" "}
                      {selectedFinding.evidence_weight.toFixed(1)} (Weight) ={" "}
                      {selectedFinding.risk_score.toFixed(1)} / 10.0
                    </code>
                  </div>
                  <p className="risk-formula-box__note">
                    {selectedFinding.evidence_category === "confirmed_entry_path" &&
                      "Confirmed Entry Path (Weight 1.0): Static graph analysis traced a direct path from an application entry point to this package."}
                    {selectedFinding.evidence_category === "imported_only" &&
                      "Imported Only (Weight 0.7): Package is imported by internal project source files, but no confirmed entry point reaches it."}
                    {selectedFinding.evidence_category === "transitive_dependency_only" &&
                      "Transitive Only (Weight 0.4): Package exists as a sub-dependency without direct imports in project code."}
                    {selectedFinding.evidence_category === "no_path_found" &&
                      "No Path Found (Weight 0.1): Package is listed in dependencies, but no static imports were found in scanned files."}
                  </p>
                  <p className="risk-formula-box__disclaimer">
                    Caveat: Reachability measures structural import chains in the graph. It is not runtime proof of exploitability or active code execution.
                  </p>
                </div>
              </div>
            </section>

            {/* Evidence Path Section */}
            <section className="detail-section">
              <h4 className="detail-section__title">Graph Reachability Chain</h4>
              <EvidencePathView
                finding={selectedFinding}
                paths={paths}
                loading={pathsLoading}
                error={pathsError}
                evidenceNote={evidenceNote}
              />
            </section>
          </div>
        ) : (
          <div className="detail-panel__empty">
            <div>
              <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>👈</div>
              <p>
                Select a vulnerability finding on the left to inspect its graph
                reachability chain and risk breakdown.
              </p>
            </div>
          </div>
        )
      ) : (
        <section className="detail-section">
          <h4 className="detail-section__title">
            Recommended Upgrade Paths
          </h4>
          <RemediationsView
            candidates={remediations}
            loading={remediationsLoading}
            error={remediationsError}
          />
        </section>
      )}
    </main>
  );
}
