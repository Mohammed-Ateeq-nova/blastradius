import { useEffect, useState } from "react";
import {
  fetchFindings,
  fetchHealth,
  fetchPaths,
  fetchRemediations,
  triggerScan,
} from "./api";
import { DetailPanel } from "./components/DetailPanel";
import { FindingsList } from "./components/FindingsList";
import { ScanControls } from "./components/ScanControls";
import { StatusBar } from "./components/StatusBar";
import type {
  EvidencePath,
  Finding,
  HealthResponse,
  RemediationCandidate,
  ScanCoverage,
  ScanSource,
} from "./types";

export default function App() {
  // --- Service Health ---
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthError, setHealthError] = useState<string | null>(null);

  // --- Scan State ---
  const [scanBusy, setScanBusy] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanLabel, setScanLabel] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<ScanCoverage | null>(null);
  const [scanWarnings, setScanWarnings] = useState<string[]>([]);
  const [hasScanned, setHasScanned] = useState(false);

  // --- Findings ---
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // --- Paths for Selected Finding ---
  const [paths, setPaths] = useState<EvidencePath[]>([]);
  const [pathsLoading, setPathsLoading] = useState(false);
  const [pathsError, setPathsError] = useState<string | null>(null);
  const [evidenceNote, setEvidenceNote] = useState<string | undefined>(undefined);

  // --- Remediations for Current Scan ---
  const [remediations, setRemediations] = useState<RemediationCandidate[]>([]);
  const [remediationsLoading, setRemediationsLoading] = useState(false);
  const [remediationsError, setRemediationsError] = useState<string | null>(null);

  // Load health on initial mount
  useEffect(() => {
    let mounted = true;
    setHealthLoading(true);

    fetchHealth()
      .then((data) => {
        if (mounted) {
          setHealth(data);
          setHealthError(null);
        }
      })
      .catch((err: unknown) => {
        if (mounted) {
          setHealthError(err instanceof Error ? err.message : "Service check failed");
        }
      })
      .finally(() => {
        if (mounted) setHealthLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, []);

  // Fetch paths whenever a finding is selected
  const handleSelectFinding = async (finding: Finding) => {
    setSelectedFinding(finding);
    setPathsLoading(true);
    setPathsError(null);
    setPaths([]);

    try {
      const res = await fetchPaths(finding.finding_id);
      setPaths(res.paths || []);
      setEvidenceNote(res.evidence_note);
    } catch (err: unknown) {
      setPathsError(
        err instanceof Error ? err.message : "Failed to load reachability paths"
      );
    } finally {
      setPathsLoading(false);
    }
  };

  // Run or re-run a scan
  const handleRunScan = async (source: ScanSource = "fixture", path?: string) => {
    setScanBusy(true);
    setScanError(null);
    setScanWarnings([]);

    // Clear stale scan state
    setScanLabel(null);
    setFindings([]);
    setSelectedFinding(null);
    setPaths([]);
    setPathsError(null);
    setRemediations([]);
    setRemediationsError(null);
    setCoverage(null);

    try {
      // 1. Trigger scan
      const scanRes = await triggerScan(source, path);
      setScanLabel(scanRes.label);
      setHasScanned(true);
      if (scanRes.coverage) {
        setCoverage(scanRes.coverage);
      }
      if (scanRes.warnings && scanRes.warnings.length > 0) {
        setScanWarnings(scanRes.warnings);
      }

      // 2. Fetch findings and remediations in parallel
      setFindingsLoading(true);
      setRemediationsLoading(true);

      const [findingsResult, remediationsResult] = await Promise.allSettled([
        fetchFindings(scanRes.scan_id),
        fetchRemediations(scanRes.scan_id),
      ]);

      // Handle findings
      if (findingsResult.status === "fulfilled") {
        const items = findingsResult.value.findings || [];
        setFindings(items);
        if (items.length > 0 && items[0]) {
          // Auto-select rank #1 finding
          handleSelectFinding(items[0]);
        }
      } else {
        setScanError(
          findingsResult.reason instanceof Error
            ? findingsResult.reason.message
            : "Failed to load findings"
        );
      }

      // Handle remediations
      if (remediationsResult.status === "fulfilled") {
        setRemediations(
          remediationsResult.value.remediation_candidates || []
        );
      } else {
        setRemediationsError(
          remediationsResult.reason instanceof Error
            ? remediationsResult.reason.message
            : "Failed to evaluate upgrade remediations"
        );
      }
    } catch (err: unknown) {
      setScanError(
        err instanceof Error ? err.message : "Scan failed to initiate"
      );
    } finally {
      setScanBusy(false);
      setFindingsLoading(false);
      setRemediationsLoading(false);
    }
  };

  const graphConnected = health?.falkordb?.connected === true;

  return (
    <div className="app-container">
      <StatusBar
        health={health}
        loading={healthLoading}
        error={healthError}
      />

      <ScanControls
        onScan={handleRunScan}
        busy={scanBusy}
        graphOk={graphConnected}
        scanLabel={scanLabel}
        coverage={coverage}
        error={scanError}
        warnings={scanWarnings}
      />

      <div className="main-content">
        <FindingsList
          findings={findings}
          selectedFindingId={selectedFinding?.finding_id ?? null}
          onSelectFinding={handleSelectFinding}
          loading={findingsLoading || scanBusy}
          hasScanned={hasScanned}
        />

        <DetailPanel
          selectedFinding={selectedFinding}
          paths={paths}
          pathsLoading={pathsLoading}
          pathsError={pathsError}
          evidenceNote={evidenceNote}
          remediations={remediations}
          remediationsLoading={remediationsLoading}
          remediationsError={remediationsError}
        />
      </div>
    </div>
  );
}
