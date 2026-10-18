import type { EvidencePath, Finding } from "../types";
import { EvidenceBadge } from "./Badges";

interface EvidencePathViewProps {
  finding: Finding;
  paths: EvidencePath[];
  loading: boolean;
  error: string | null;
  evidenceNote?: string;
}

export function EvidencePathView({
  finding,
  paths,
  loading,
  error,
  evidenceNote,
}: EvidencePathViewProps) {
  if (loading) {
    return (
      <div className="loading-state">
        <div className="loading-spinner" />
        <span>Traversing graph reachability paths…</span>
      </div>
    );
  }

  if (error) {
    return <div className="error-banner">Failed to load paths: {error}</div>;
  }

  const isNoPath =
    finding.evidence_category === "no_path_found" || paths.length === 0;

  return (
    <div className="animate-in">
      {isNoPath && (
        <div className="no-path-warning" style={{ marginBottom: "1rem" }}>
          <strong>No Reachability Path Found ≠ Safe.</strong>
          <p style={{ marginTop: "0.25rem" }}>
            Static graph analysis did not detect an entry-point trace to this
            package in the scanned files. However, runtime invocation, dynamic
            evaluation, external CLI tools, or untested codepaths may still
            trigger vulnerable methods.
          </p>
        </div>
      )}

      {paths.length > 0 ? (
        paths.map((p, idx) => (
          <div key={idx} className="evidence-path">
            <div className="evidence-path__header">
              <span style={{ fontSize: "0.75rem", fontWeight: 600 }}>
                Path #{idx + 1}
              </span>
              <EvidenceBadge
                category={p.evidence_category}
                label={p.evidence_label}
              />
            </div>

            <div className="evidence-path__chain">
              {/* Entry Point Node */}
              {p.entry_path && (
                <>
                  <div className="path-node">
                    <span className="path-node__icon path-node__icon--entry">
                      🚀
                    </span>
                    <span className="path-node__label">Entry</span>
                    <span className="path-node__value">{p.entry_path}</span>
                  </div>

                  <div className="path-edge">
                    <span className="path-edge__label">
                      {p.edges.find((e) => e.from === "EntryPoint")?.type ||
                        "REACHES"}
                    </span>
                  </div>
                </>
              )}

              {/* File / Call Node */}
              {p.file_path && (
                <>
                  <div className="path-node">
                    <span className="path-node__icon path-node__icon--file">
                      📄
                    </span>
                    <span className="path-node__label">File</span>
                    <span className="path-node__value">{p.file_path}</span>
                  </div>

                  <div className="path-edge">
                    <span className="path-edge__label">
                      {p.edges.find((e) => e.from === "File")?.type ||
                        "IMPORTS"}
                    </span>
                  </div>
                </>
              )}

              {/* Target Package Node */}
              <div className="path-node">
                <span className="path-node__icon path-node__icon--package">
                  📦
                </span>
                <span className="path-node__label">Package</span>
                <span className="path-node__value">
                  {p.package_key || finding.package_key}
                </span>
              </div>

              {/* Vulnerability Node */}
              <div className="path-edge">
                <span className="path-edge__label">
                  {p.edges.find((e) => e.from === "Vuln")?.type || "AFFECTS"}
                </span>
              </div>

              <div className="path-node">
                <span className="path-node__icon path-node__icon--vuln">
                  🛡️
                </span>
                <span className="path-node__label">Advisory</span>
                <span className="path-node__value">{finding.advisory_id}</span>
              </div>
            </div>

            {p.limitations && (
              <div className="limitations" style={{ marginTop: "0.75rem" }}>
                <div className="limitations__title">Path Caveat</div>
                <div className="limitations__item">{p.limitations}</div>
              </div>
            )}
          </div>
        ))
      ) : (
        !isNoPath && (
          <div className="empty-state">
            <p className="empty-state__text">
              No detailed edges recorded for this finding in the graph.
            </p>
          </div>
        )
      )}

      {evidenceNote && (
        <p className="info-note" style={{ marginTop: "1rem" }}>
          Note: {evidenceNote}
        </p>
      )}

      {/* Findings limitations summary */}
      {finding.limitations && finding.limitations.length > 0 && (
        <div className="limitations" style={{ marginTop: "1rem" }}>
          <div className="limitations__title">Analysis Limitations</div>
          <ul style={{ paddingLeft: "1.2rem", margin: 0 }}>
            {finding.limitations.map((lim, idx) => (
              <li key={idx} className="limitations__item">
                {lim}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
