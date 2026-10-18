import { useState } from "react";
import type { ScanCoverage, ScanSource } from "../types";

interface ScanControlsProps {
  onScan: (source: ScanSource, path?: string) => void;
  busy: boolean;
  graphOk: boolean;
  scanLabel: string | null;
  coverage: ScanCoverage | null;
  error: string | null;
  warnings?: string[];
}

export function ScanControls({
  onScan,
  busy,
  graphOk,
  scanLabel,
  coverage,
  error,
  warnings = [],
}: ScanControlsProps) {
  const [source, setSource] = useState<ScanSource>("fixture");
  const [projectPath, setProjectPath] = useState<string>("");

  const handleFillDemoPath = () => {
    // Fill with the fixture repo path for easy testing
    setProjectPath("demo/fixture-repo");
  };

  const handleScanSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (busy || !graphOk) return;

    if (source === "local") {
      const trimmed = projectPath.trim();
      if (!trimmed) return;
      onScan("local", trimmed);
    } else {
      onScan("fixture");
    }
  };

  const isLocalSubmitDisabled =
    busy || !graphOk || (source === "local" && !projectPath.trim());

  return (
    <section className="scan-controls" aria-label="Scan Controls">
      {/* Source Selector Tabs */}
      <div className="scan-controls__source-selector" role="tablist" aria-label="Scan Source">
        <button
          type="button"
          role="tab"
          aria-selected={source === "fixture"}
          className={`source-tab ${source === "fixture" ? "source-tab--active" : ""}`}
          onClick={() => setSource("fixture")}
          disabled={busy}
        >
          <span>📦</span>
          <span>Demo Fixture</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={source === "local"}
          className={`source-tab ${source === "local" ? "source-tab--active" : ""}`}
          onClick={() => setSource("local")}
          disabled={busy}
        >
          <span>📁</span>
          <span>Local npm Project</span>
        </button>
      </div>

      <form onSubmit={handleScanSubmit} className="scan-controls__body">
        {source === "local" ? (
          <div className="local-scan-config">
            <div className="input-group">
              <label htmlFor="project-path-input" className="input-label">
                Project Directory Path:
              </label>
              <div className="input-row">
                <input
                  id="project-path-input"
                  type="text"
                  className="text-input"
                  placeholder="e.g. demo/fixture-repo or C:\projects\my-app"
                  value={projectPath}
                  onChange={(e) => setProjectPath(e.target.value)}
                  disabled={busy}
                />
                <button
                  type="button"
                  className="btn btn--secondary btn--sm"
                  onClick={handleFillDemoPath}
                  disabled={busy}
                  title="Autofill path to demo fixture repository"
                >
                  Fill Demo Path
                </button>
              </div>
            </div>
            <p className="scan-controls__help">
              Requires <code>package.json</code> and <code>package-lock.json</code> (lockfile v2+).
              Static analysis runs safely with zero target code execution.
            </p>
          </div>
        ) : (
          <p className="scan-controls__help">
            Load the built-in reproducible demo fixture representing a multi-tier Node.js application with simulated reachable vulnerability paths.
          </p>
        )}

        <div className="scan-controls__actions">
          <button
            type="submit"
            className="btn btn--primary"
            disabled={isLocalSubmitDisabled}
            aria-busy={busy}
          >
            {busy ? (
              <>
                <span className="btn__spinner" aria-hidden="true" />
                <span>
                  {source === "local"
                    ? "Scanning project & querying OSV…"
                    : "Analyzing graph blast radius…"}
                </span>
              </>
            ) : (
              <>
                <span>⚡</span>
                <span>
                  {source === "local"
                    ? "Scan Local Repository"
                    : "Load & Analyze Demo Fixture"}
                </span>
              </>
            )}
          </button>

          {!graphOk && (
            <span style={{ fontSize: "0.8125rem", color: "var(--status-error)" }}>
              FalkorDB connection required to run analysis
            </span>
          )}

          {scanLabel && (
            <span className="scan-label" title="Source of graph data">
              Active Dataset: <strong>{scanLabel}</strong>
            </span>
          )}
        </div>
      </form>

      {error && (
        <div className="error-banner" role="alert" style={{ marginTop: "var(--space-md)" }}>
          <span>{error}</span>
        </div>
      )}

      {warnings && warnings.length > 0 && (
        <div
          className="warning-banner"
          role="status"
          style={{
            marginTop: "var(--space-md)",
            padding: "var(--space-sm) var(--space-md)",
            background: "rgba(245, 158, 11, 0.12)",
            border: "1px solid rgba(245, 158, 11, 0.3)",
            borderRadius: "var(--radius-sm)",
            color: "#fbbf24",
            fontSize: "0.8125rem",
            display: "flex",
            flexDirection: "column",
            gap: "4px",
          }}
        >
          {warnings.map((w, idx) => (
            <div key={idx} style={{ display: "flex", gap: "6px", alignItems: "center" }}>
              <span>⚠️</span>
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      {coverage && (
        <div className="coverage animate-in" aria-label="Scan Coverage">
          <div className="coverage__stat">
            <span className="coverage__value">{coverage.packages_scanned}</span>
            <span className="coverage__label">Packages Scanned</span>
          </div>

          <div className="coverage__stat">
            <span className="coverage__value">{coverage.files_scanned}</span>
            <span className="coverage__label">Files Scanned</span>
          </div>

          <div className="coverage__stat">
            <span className="coverage__value">{coverage.entry_points_scanned}</span>
            <span className="coverage__label">Entry Points</span>
          </div>

          <div className="coverage__stat">
            <span
              className="coverage__value"
              style={{ fontSize: "1.125rem", fontWeight: 600, paddingTop: 4 }}
            >
              {coverage.project_name || coverage.root_label}
            </span>
            <span className="coverage__label">Project Target</span>
          </div>
        </div>
      )}
    </section>
  );
}

