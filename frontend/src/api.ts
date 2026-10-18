// ---------------------------------------------------------------------------
// BlastRadius — typed API client
// ---------------------------------------------------------------------------

import type {
  HealthResponse,
  ScanResponse,
  FindingsResponse,
  PathsResponse,
  RemediationsResponse,
} from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  const body = await res.json();
  if (!res.ok) {
    const detail = body?.detail;
    const msg = typeof detail === "string"
      ? detail
      : detail?.error ?? `HTTP ${res.status}`;
    throw new ApiError(res.status, String(msg));
  }
  return body as T;
}

// --- Endpoints ---

export function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/api/health");
}

export function triggerScan(
  source: import("./types").ScanSource = "fixture",
  path?: string,
): Promise<ScanResponse> {
  const payload: import("./types").ScanRequest = { source };
  if (source === "local" && path) {
    payload.path = path;
  }
  return request<ScanResponse>("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function fetchFindings(scanId: string): Promise<FindingsResponse> {
  return request<FindingsResponse>(
    `/api/scans/${encodeURIComponent(scanId)}/findings`,
  );
}

export function fetchPaths(findingId: string): Promise<PathsResponse> {
  return request<PathsResponse>(
    `/api/findings/${encodeURIComponent(findingId)}/paths`,
  );
}

export function fetchRemediations(scanId: string): Promise<RemediationsResponse> {
  return request<RemediationsResponse>(
    `/api/scans/${encodeURIComponent(scanId)}/remediations`,
  );
}
