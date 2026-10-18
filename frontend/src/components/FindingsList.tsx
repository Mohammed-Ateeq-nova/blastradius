import type { Finding } from "../types";
import { EvidenceBadge, getScoreClass, SeverityBadge } from "./Badges";

interface FindingsListProps {
  findings: Finding[];
  selectedFindingId: string | null;
  onSelectFinding: (finding: Finding) => void;
  loading: boolean;
  hasScanned?: boolean;
}

export function FindingsList({
  findings,
  selectedFindingId,
  onSelectFinding,
  loading,
  hasScanned = false,
}: FindingsListProps) {
  return (
    <aside className="findings-panel" aria-label="Prioritized Findings">
      <div className="panel-header">
        <h2 className="panel-header__title">Prioritized Findings</h2>
        {findings.length > 0 && (
          <span className="panel-header__count">{findings.length} total</span>
        )}
      </div>

      {loading ? (
        <div className="loading-state">
          <div className="loading-spinner" />
          <span>Ranking reachability &amp; blast radius…</span>
        </div>
      ) : findings.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state__icon">{hasScanned ? "🛡️" : "🔍"}</div>
          <h3
            style={{
              fontSize: "0.9375rem",
              fontWeight: 600,
              color: "var(--text-primary)",
              marginBottom: "0.25rem",
            }}
          >
            {hasScanned ? "No Vulnerability Findings" : "Ready for Analysis"}
          </h3>
          <p className="empty-state__text">
            {hasScanned
              ? "The scanned repository dependency tree contains zero known advisories matching OSV records."
              : "Select a scan source above (Demo Fixture or Local npm Project) and run graph triage across project dependencies and application entry points."}
          </p>
          {hasScanned && (
            <span
              style={{
                fontSize: "0.75rem",
                color: "var(--text-tertiary)",
                marginTop: "0.35rem",
                display: "block",
                lineHeight: 1.4,
              }}
            >
              Note: Absence of public advisories does not guarantee absence of zero-days or runtime attack paths.
            </span>
          )}
        </div>
      ) : (
        <>
          <div role="list">
            {findings.map((f) => {
              const isSelected = f.finding_id === selectedFindingId;
              const scoreClass = getScoreClass(f.risk_score);

              return (
                <div
                  key={f.finding_id}
                  role="listitem"
                  tabIndex={0}
                  className={`finding-row ${
                    isSelected ? "finding-row--selected" : ""
                  }`}
                  onClick={() => onSelectFinding(f)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onSelectFinding(f);
                    }
                  }}
                >
                  <div className="finding-row__top">
                    <span className="finding-row__rank">#{f.rank}</span>
                    <strong className="finding-row__advisory">
                      {f.advisory_id}
                    </strong>
                    <span
                      className={`finding-row__score ${scoreClass}`}
                      title={`Risk Score: ${f.risk_score.toFixed(
                        1
                      )} / 10.0 (Severity: ${f.severity_score.toFixed(
                        1
                      )} × Reachability Weight: ${f.evidence_weight})`}
                    >
                      {f.risk_score.toFixed(1)}
                    </span>
                  </div>

                  <div className="finding-row__bottom">
                    <SeverityBadge severity={f.severity} />
                    <EvidenceBadge
                      category={f.evidence_category}
                      label={f.evidence_label}
                    />
                    <span className="finding-row__package">
                      {f.package_name}@{f.package_version}
                    </span>
                    {f.fixture && (
                      <span className="finding-row__fixture">Demo Fixture</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="findings-summary-card">
            <div className="findings-summary-card__header">
              <span>🛡️ Triage Priority Scope</span>
            </div>
            <p className="findings-summary-card__text">
              {findings.length === 1
                ? "Showing 1 prioritized vulnerability. Packages without entry-point paths or confirmed reachability receive lower risk scores."
                : `Showing ${findings.length} prioritized vulnerabilities ranked strictly by graph reachability risk.`}
            </p>
            <div className="findings-summary-card__legend">
              <span className="legend-item">
                <span
                  className="legend-dot"
                  style={{ background: "var(--severity-critical)" }}
                />{" "}
                9.0–10.0 Critical
              </span>
              <span className="legend-item">
                <span
                  className="legend-dot"
                  style={{ background: "var(--severity-high)" }}
                />{" "}
                7.0–8.9 High
              </span>
              <span className="legend-item">
                <span
                  className="legend-dot"
                  style={{ background: "var(--severity-medium)" }}
                />{" "}
                4.0–6.9 Med
              </span>
              <span className="legend-item">
                <span
                  className="legend-dot"
                  style={{ background: "var(--severity-low)" }}
                />{" "}
                &lt;4.0 Low
              </span>
            </div>
          </div>
        </>
      )}
    </aside>
  );
}
