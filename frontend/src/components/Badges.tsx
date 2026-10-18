import type { EvidenceCategory } from "../types";

export function getScoreClass(score: number): string {
  // Standard CVSS v3.1-aligned thresholds on 0.0-10.0 scale:
  // Critical: >= 9.0 | High: >= 7.0 | Medium: >= 4.0 | Low: < 4.0
  const normalized = score > 10 ? score / 10 : score;
  if (normalized >= 9.0) return "score--critical";
  if (normalized >= 7.0) return "score--high";
  if (normalized >= 4.0) return "score--medium";
  return "score--low";
}

export function SeverityBadge({ severity }: { severity: string }) {
  const norm = (severity || "").toLowerCase();
  let badgeClass = "badge--low";
  if (norm === "critical") badgeClass = "badge--critical";
  else if (norm === "high") badgeClass = "badge--high";
  else if (norm === "medium" || norm === "moderate") badgeClass = "badge--medium";

  return <span className={`badge ${badgeClass}`}>{severity.toUpperCase()}</span>;
}

export function EvidenceBadge({
  category,
  label,
}: {
  category: EvidenceCategory;
  label?: string;
}) {
  let badgeClass = "badge--nopath";
  let displayLabel = label || category;

  switch (category) {
    case "confirmed_entry_path":
      badgeClass = "badge--confirmed";
      displayLabel = displayLabel || "Confirmed Path";
      break;
    case "imported_only":
      badgeClass = "badge--imported";
      displayLabel = displayLabel || "Imported Only";
      break;
    case "transitive_dependency_only":
      badgeClass = "badge--transitive";
      displayLabel = displayLabel || "Transitive Only";
      break;
    case "no_path_found":
    default:
      badgeClass = "badge--nopath";
      displayLabel = displayLabel || "No Path Found";
      break;
  }

  return <span className={`badge ${badgeClass}`}>{displayLabel}</span>;
}

export function CompatibilityCostBadge({ cost }: { cost: string }) {
  const norm = (cost || "").toLowerCase();
  let badgeClass = "badge--unknown-cost";
  if (norm === "patch") badgeClass = "badge--patch";
  else if (norm === "minor") badgeClass = "badge--minor";
  else if (norm === "major") badgeClass = "badge--major";

  return <span className={`badge ${badgeClass}`}>{cost.toUpperCase()}</span>;
}
