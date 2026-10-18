import type { HealthResponse } from "../types";

interface StatusBarProps {
  health: HealthResponse | null;
  loading: boolean;
  error: string | null;
}

export function StatusBar({ health, loading, error }: StatusBarProps) {
  const falkor = health?.falkordb;
  const isConnected = falkor?.connected === true;

  return (
    <header className="status-bar" role="banner">
      <div className="status-bar__brand">
        <h1 className="status-bar__logo">BlastRadius</h1>
        <span className="status-bar__tagline">
          Graph-powered vulnerability triage for npm dependencies
        </span>
      </div>

      <div className="status-bar__indicators" role="status">
        {loading ? (
          <div className="status-indicator">
            <span className="status-dot status-dot--loading" />
            <span>Checking services…</span>
          </div>
        ) : error ? (
          <div className="status-indicator">
            <span className="status-dot status-dot--error" />
            <span>Backend offline</span>
          </div>
        ) : health ? (
          <>
            <div className="status-indicator">
              <span
                className={`status-dot ${
                  isConnected ? "status-dot--ok" : "status-dot--error"
                }`}
              />
              <span>
                FalkorDB:{" "}
                <strong>
                  {isConnected ? "Connected" : "Disconnected"}
                </strong>
                {falkor && (
                  <span style={{ opacity: 0.7, marginLeft: 4 }}>
                    ({falkor.host}:{falkor.port})
                  </span>
                )}
              </span>
            </div>

            {falkor?.graphs && falkor.graphs.length > 0 && (
              <div className="status-indicator">
                <span>
                  Graphs: <strong>{falkor.graphs.length}</strong>
                </span>
              </div>
            )}

            <div className="status-indicator">
              <span>
                Backend: <strong>{health.backend}</strong>
              </span>
            </div>
          </>
        ) : null}
      </div>
    </header>
  );
}
