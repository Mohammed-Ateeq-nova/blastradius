import { useState } from "react";
import type { RemediationCandidate, RemediationProposal } from "../types";
import { CompatibilityCostBadge } from "./Badges";

interface RemediationsViewProps {
  candidates: RemediationCandidate[];
  loading: boolean;
  error: string | null;
}

// ---------------------------------------------------------------------------
// ProposalPanel — renders the manifest diff + rationale for one candidate
// ---------------------------------------------------------------------------
function ProposalPanel({ proposal }: { proposal: RemediationProposal }) {
  const [diffExpanded, setDiffExpanded] = useState(false);

  const hasDiff = !!proposal.manifest_diff && proposal.manifest_diff.trim().length > 0;

  return (
    <div className="proposal-panel animate-in">
      {/* Rationale */}
      <div className="proposal-section">
        <h5 className="proposal-section__title">Evidence Rationale</h5>
        <p className="proposal-section__body">{proposal.rationale}</p>
      </div>

      {/* Reachability caveat */}
      <div className="proposal-caveat">
        <span className="proposal-caveat__icon">⚠</span>
        <span>{proposal.reachability_caveat}</span>
      </div>

      {/* Manifest diff */}
      <div className="proposal-section">
        <div className="proposal-section__row">
          <h5 className="proposal-section__title">
            Proposed <code>package.json</code> Patch
            {proposal.patch_type === "override" && (
              <span className="badge badge--warn" style={{ marginLeft: 6, fontSize: "0.7rem" }}>
                transitive override
              </span>
            )}
          </h5>
          {hasDiff && (
            <button
              className="proposal-diff-toggle"
              onClick={() => setDiffExpanded((v) => !v)}
              aria-expanded={diffExpanded}
            >
              {diffExpanded ? "▲ Hide diff" : "▼ Show diff"}
            </button>
          )}
        </div>

        <p className="proposal-note">{proposal.manifest_note}</p>

        {hasDiff ? (
          diffExpanded && (
            <pre className="proposal-diff" role="region" aria-label="package.json patch diff">
              {proposal.manifest_diff.split("\n").map((line, i) => {
                let cls = "diff-line";
                if (line.startsWith("+++") || line.startsWith("---")) cls += " diff-line--file";
                else if (line.startsWith("@@")) cls += " diff-line--hunk";
                else if (line.startsWith("+")) cls += " diff-line--add";
                else if (line.startsWith("-")) cls += " diff-line--del";
                return (
                  <span key={i} className={cls}>
                    {line}
                    {"\n"}
                  </span>
                );
              })}
            </pre>
          )
        ) : (
          <p className="proposal-note proposal-note--muted">
            {proposal.is_synthetic_fixture
              ? "No real package.json diff available for the fixture simulation."
              : "No package.json was found for the scanned project — diff unavailable."}
          </p>
        )}
      </div>

      {/* Lockfile guidance */}
      <div className="proposal-section">
        <h5 className="proposal-section__title">Lockfile Guidance</h5>
        <pre className="proposal-lockfile">{proposal.lockfile_guidance}</pre>
      </div>

      {/* Approval notice */}
      <div className="proposal-approval">
        🔒 <strong>Approval required.</strong> BlastRadius never applies patches
        automatically. Review the diff, then run{" "}
        <code>npm install --package-lock-only --ignore-scripts</code> yourself.
      </div>

      {/* Fixture simulation label */}
      {proposal.is_synthetic_fixture && (
        <div className="proposal-fixture-warning">
          <strong>[SIMULATED DEMO]</strong> This proposal is generated from the
          fixture dataset — not a live repository. Target version data is synthetic.
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// RemediationsView
// ---------------------------------------------------------------------------
export function RemediationsView({
  candidates,
  loading,
  error,
}: RemediationsViewProps) {
  const [expandedKeys, setExpandedKeys] = useState<Record<string, boolean>>({});
  const [proposalKeys, setProposalKeys] = useState<Record<string, boolean>>({});

  const toggleExpand = (key: string) => {
    setExpandedKeys((prev) => ({ ...prev, [key]: !prev[key] }));
  };
  const toggleProposal = (key: string) => {
    setProposalKeys((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  if (loading) {
    return (
      <div className="loading-state">
        <div className="loading-spinner" />
        <span>Evaluating safe upgrade candidates…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error-banner">Failed to load remediations: {error}</div>
    );
  }

  if (candidates.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state__icon">🛡️</div>
        <p className="empty-state__text">
          No automated remediation upgrade candidates available for this scan.
        </p>
      </div>
    );
  }

  return (
    <div className="animate-in" aria-label="Remediation Plan">
      <p
        style={{
          fontSize: "0.8125rem",
          color: "var(--text-secondary)",
          marginBottom: "1rem",
        }}
      >
        Ranked upgrade recommendations balancing risk elimination against
        compatibility cost:
      </p>

      {candidates.map((c) => {
        const isExpanded = !!expandedKeys[c.candidate_key];
        const isProposalOpen = !!proposalKeys[c.candidate_key];
        const isFixtureCandidate =
          c.candidate_key?.includes("fixture") ||
          c.resolved_findings.some((f) => f.advisory_id.startsWith("FIXTURE-")) ||
          (c.package_name === "lodash" && c.to_version === "4.17.22");

        return (
          <article key={c.candidate_key} className="remediation-card">
            <header
              className="remediation-card__header"
              onClick={() => toggleExpand(c.candidate_key)}
              role="button"
              tabIndex={0}
              aria-expanded={isExpanded}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  toggleExpand(c.candidate_key);
                }
              }}
            >
              <div>
                <div className="remediation-card__package">
                  #{c.rank} {c.package_name}
                  {isFixtureCandidate && (
                    <span
                      className="finding-row__fixture"
                      style={{ marginLeft: 8 }}
                    >
                      Demo Fixture Scenario
                    </span>
                  )}
                </div>
                <div className="remediation-card__versions">
                  <span>{c.from_version}</span>
                  <span className="remediation-card__arrow">→</span>
                  <strong>{c.to_version}</strong>
                </div>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <CompatibilityCostBadge cost={c.compatibility_cost} />
                <span
                  style={{
                    fontSize: "0.75rem",
                    color: "var(--text-tertiary)",
                    userSelect: "none",
                  }}
                >
                  {isExpanded ? "▲ Collapse" : "▼ Details"}
                </span>
              </div>
            </header>

            {isFixtureCandidate && (
              <div
                style={{
                  marginTop: "0.5rem",
                  padding: "0.5rem 0.75rem",
                  background: "rgba(251, 191, 36, 0.08)",
                  border: "1px solid rgba(251, 191, 36, 0.25)",
                  borderRadius: "var(--radius-sm)",
                  fontSize: "0.75rem",
                  color: "var(--text-secondary)",
                  lineHeight: 1.45,
                }}
              >
                <strong style={{ color: "var(--status-warn)" }}>
                  Synthetic Fixture Scenario:
                </strong>{" "}
                <code>lodash@4.17.22</code> is a simulated patch target in the
                demo fixture used to demonstrate deterministic SemVer resolution
                against <code>&lt;=4.17.21</code>. (Lodash 4.17.21 was the final v4
                official release). In production, candidates are verified
                against actual published registry releases and official OSV fixed
                versions.
              </div>
            )}

            <div className="remediation-card__stats">
              <div className="remediation-card__stat">
                Risk Eliminated:{" "}
                <strong style={{ color: "var(--status-ok)" }}>
                  {c.risk_eliminated.toFixed(1)} pts
                </strong>
              </div>

              <div className="remediation-card__stat">
                Verified Fixes:{" "}
                <strong style={{ color: "var(--status-ok)" }}>
                  {c.resolved_findings_count}
                </strong>
              </div>

              {c.unverified_findings_count > 0 && (
                <div className="remediation-card__stat">
                  Unverified:{" "}
                  <strong style={{ color: "var(--status-warn)" }}>
                    {c.unverified_findings_count}
                  </strong>
                </div>
              )}

              {c.unresolved_findings_count > 0 && (
                <div className="remediation-card__stat">
                  Unresolved:{" "}
                  <strong style={{ color: "var(--status-error)" }}>
                    {c.unresolved_findings_count}
                  </strong>
                </div>
              )}
            </div>

            {isExpanded && (
              <div className="remediation-card__detail animate-in">
                {c.resolved_findings.length > 0 && (
                  <>
                    <h4 className="remediation-card__detail-heading">
                      ✓ Verified Resolved Vulnerabilities ({c.resolved_findings.length})
                    </h4>
                    <ul className="remediation-card__findings-list">
                      {c.resolved_findings.map((f, i) => (
                        <li
                          key={i}
                          className="remediation-finding remediation-finding--resolved"
                        >
                          <strong>{f.advisory_id}</strong>
                          <span>
                            (Risk eliminated: {f.risk_score.toFixed(1)} ·{" "}
                            {f.evidence_category.replace(/_/g, " ")})
                          </span>
                        </li>
                      ))}
                    </ul>
                  </>
                )}

                {c.unverified_findings && c.unverified_findings.length > 0 && (
                  <>
                    <h4 className="remediation-card__detail-heading">
                      ? Unverified Impact Findings ({c.unverified_findings.length})
                    </h4>
                    <ul className="remediation-card__findings-list">
                      {c.unverified_findings.map((f, i) => (
                        <li
                          key={i}
                          className="remediation-finding remediation-finding--unverified"
                        >
                          <strong>{f.advisory_id}</strong>: {f.reason}
                        </li>
                      ))}
                    </ul>
                    <p className="info-note">
                      Unverified findings require manual developer check. BlastRadius
                      does not claim resolution without advisory fixed-version verification.
                    </p>
                  </>
                )}

                {c.unresolved_findings && c.unresolved_findings.length > 0 && (
                  <>
                    <h4 className="remediation-card__detail-heading">
                      ✗ Remaining Unresolved ({c.unresolved_findings.length})
                    </h4>
                    <ul className="remediation-card__findings-list">
                      {c.unresolved_findings.map((f, i) => (
                        <li
                          key={i}
                          className="remediation-finding remediation-finding--unresolved"
                        >
                          <strong>{f.advisory_id}</strong>: {f.reason}
                        </li>
                      ))}
                    </ul>
                  </>
                )}

                {/* Proposal section */}
                {c.proposal && (
                  <div style={{ marginTop: "0.75rem" }}>
                    <button
                      className="proposal-toggle-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleProposal(c.candidate_key);
                      }}
                      aria-expanded={isProposalOpen}
                    >
                      {isProposalOpen
                        ? "▲ Hide remediation proposal"
                        : "▼ View remediation proposal"}
                    </button>
                    {isProposalOpen && <ProposalPanel proposal={c.proposal} />}
                  </div>
                )}
              </div>
            )}
          </article>
        );
      })}

      <div
        style={{
          marginTop: "1.5rem",
          padding: "0.75rem 1rem",
          background: "var(--bg-card)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "var(--radius-md)",
          fontSize: "0.75rem",
          color: "var(--text-tertiary)",
          lineHeight: 1.5,
        }}
      >
        🔒 <strong>Safety Guarantee:</strong> BlastRadius generates proposed
        remediation plans for human review. It never modifies <code>package.json</code>,
        runs package managers, opens pull requests, or applies code changes
        without explicit user approval.
      </div>
    </div>
  );
}
