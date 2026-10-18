"""OSV.dev vulnerability provider.

Uses the OSV.dev REST API (https://api.osv.dev/v1/query) to look up
advisories for individual npm packages.  No API key is required.

Design principles
-----------------
* Network access is isolated in ``OsvProvider.query_batch``; nothing
  else in the application calls the network.
* We never execute code from the scanned repository.
* Timeouts and HTTP errors are surfaced as ``OsvError``, not silently
  treated as "zero vulnerabilities."
* Partial-batch failures (one package query fails) are collected and
  exposed in ``OsvBatchResult.errors``; successful results are still
  returned.
* Missing optional fields (summary, severity, affected ranges) are
  stored as ``None``; we never invent metadata.
"""
from __future__ import annotations

import http.client
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_TIMEOUT = 10  # seconds


class OsvError(Exception):
    """Raised when a single package query fails unrecoverably."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AffectedRange:
    """A single semver or ecosystem version range from OSV *affected.ranges*."""

    range_type: str  # e.g. "SEMVER", "ECOSYSTEM", "GIT"
    introduced: str | None = None  # version at which the vuln was introduced
    fixed: str | None = None  # version at which the vuln was fixed (None = not fixed)
    last_affected: str | None = None  # last affected version (None = not specified)


@dataclass(frozen=True)
class OsvAdvisory:
    """Normalised advisory record from one OSV vuln entry."""

    advisory_id: str  # primary OSV ID, e.g. "GHSA-p6mc-m468-83gw"
    aliases: list[str]  # CVE IDs, secondary GHSA IDs, etc.
    summary: str | None  # short human-readable summary; None if absent
    details: str | None  # markdown details; None if absent
    severity: str | None  # first CVSS_V3 score string, or None
    published: str | None  # ISO-8601 timestamp; None if absent
    modified: str | None  # ISO-8601 timestamp; None if absent
    source: str  # always "osv.dev"
    # Per-package affected ranges (SEMVER preferred)
    affected_ranges: list[AffectedRange] = field(default_factory=list)
    # Raw affected versions list if ranges are absent
    affected_versions: list[str] = field(default_factory=list)


@dataclass
class OsvBatchResult:
    """Result of querying multiple packages at once."""

    advisories: dict[str, list[OsvAdvisory]]
    """Mapping of ``"{ecosystem}:{name}@{version}"`` → list of advisories."""

    errors: list[dict[str, Any]]
    """Per-package errors that did not prevent the rest of the batch from running."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ssl_ctx() -> ssl.SSLContext:
    return ssl.create_default_context()


def _post_json(url: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    """POST *payload* as JSON to *url*; return parsed JSON response."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raise OsvError(
            "http_error",
            f"OSV API returned HTTP {exc.code} for {url}",
        ) from exc
    except urllib.error.URLError as exc:
        reason = str(exc.reason)
        code = "timeout" if "timed out" in reason.lower() else "network_error"
        raise OsvError(code, f"OSV API request failed: {reason}") from exc
    except TimeoutError as exc:
        raise OsvError("timeout", "OSV API request timed out") from exc

    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise OsvError("malformed_response", "OSV API returned non-JSON response") from exc


def _extract_severity(vuln: dict[str, Any]) -> str | None:
    """Return the first CVSS_V3 score string, or None."""
    for entry in vuln.get("severity") or []:
        if isinstance(entry, dict) and entry.get("type") == "CVSS_V3":
            score = entry.get("score")
            if score:
                return str(score)
    return None


def _extract_ranges(affected_list: list[dict[str, Any]], ecosystem: str) -> tuple[list[AffectedRange], list[str]]:
    """Return (ranges, versions) from the OSV *affected* array for a given ecosystem."""
    ranges: list[AffectedRange] = []
    versions: list[str] = []
    for aff in affected_list:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem:
            continue
        for r in aff.get("ranges") or []:
            rtype = str(r.get("type") or "")
            curr_introduced: str | None = None
            curr_fixed: str | None = None
            curr_last_affected: str | None = None

            events = r.get("events") or []
            for event in events:
                if "introduced" in event:
                    if curr_introduced is not None or curr_fixed is not None or curr_last_affected is not None:
                        ranges.append(
                            AffectedRange(
                                range_type=rtype,
                                introduced=curr_introduced,
                                fixed=curr_fixed,
                                last_affected=curr_last_affected,
                            )
                        )
                        curr_fixed = None
                        curr_last_affected = None
                    curr_introduced = str(event["introduced"])
                elif "fixed" in event:
                    curr_fixed = str(event["fixed"])
                    ranges.append(
                        AffectedRange(
                            range_type=rtype,
                            introduced=curr_introduced,
                            fixed=curr_fixed,
                            last_affected=None,
                        )
                    )
                    curr_introduced = None
                    curr_fixed = None
                    curr_last_affected = None
                elif "last_affected" in event:
                    curr_last_affected = str(event["last_affected"])
                    ranges.append(
                        AffectedRange(
                            range_type=rtype,
                            introduced=curr_introduced,
                            fixed=None,
                            last_affected=curr_last_affected,
                        )
                    )
                    curr_introduced = None
                    curr_fixed = None
                    curr_last_affected = None

            if curr_introduced is not None or curr_fixed is not None or curr_last_affected is not None:
                ranges.append(
                    AffectedRange(
                        range_type=rtype,
                        introduced=curr_introduced,
                        fixed=curr_fixed,
                        last_affected=curr_last_affected,
                    )
                )

        versions.extend(str(v) for v in aff.get("versions") or [])
    return ranges, list(dict.fromkeys(versions))


def _parse_advisory(vuln: dict[str, Any], ecosystem: str) -> OsvAdvisory:
    """Convert a raw OSV vuln dict into an ``OsvAdvisory``."""
    if not isinstance(vuln, dict):
        raise OsvError("malformed_response", "vuln entry is not a JSON object")
    advisory_id = vuln.get("id")
    if not advisory_id or not isinstance(advisory_id, str):
        raise OsvError("malformed_response", "vuln entry missing 'id'")
    affected_list = vuln.get("affected") or []
    ranges, affected_versions = _extract_ranges(affected_list, ecosystem)
    return OsvAdvisory(
        advisory_id=advisory_id,
        aliases=[str(a) for a in (vuln.get("aliases") or [])],
        summary=vuln.get("summary") or None,
        details=vuln.get("details") or None,
        severity=_extract_severity(vuln),
        published=vuln.get("published") or None,
        modified=vuln.get("modified") or None,
        source="osv.dev",
        affected_ranges=ranges,
        affected_versions=affected_versions,
    )


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class OsvProvider:
    """Queries OSV.dev for advisories matching a list of npm packages.

    Each package is queried individually via ``POST /v1/query``.  OSV's
    ``/v1/querybatch`` only returns ``{id, modified}`` stubs, so we use
    per-package queries to get full advisory records in one round-trip.

    Parameters
    ----------
    timeout:
        Per-request timeout in seconds.
    url:
        Override the OSV query endpoint (useful for testing).
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, url: str = OSV_QUERY_URL):
        self._timeout = timeout
        self._url = url

    def query_batch(
        self,
        packages: list[dict[str, Any]],
    ) -> OsvBatchResult:
        """Query OSV for each package in *packages*.

        Parameters
        ----------
        packages:
            List of dicts with keys ``name`` (str), ``version`` (str),
            ``ecosystem`` (str, e.g. ``"npm"``).

        Returns
        -------
        OsvBatchResult
            ``advisories`` maps ``"ecosystem:name@version"`` to a list of
            ``OsvAdvisory``.  ``errors`` records per-package failures so
            that a single failing query does not abort the entire batch.
        """
        advisories: dict[str, list[OsvAdvisory]] = {}
        errors: list[dict[str, Any]] = []

        for pkg in packages:
            name = str(pkg.get("name") or "")
            version = str(pkg.get("version") or "")
            ecosystem = str(pkg.get("ecosystem") or "npm")
            key = f"{ecosystem}:{name}@{version}"

            if not name or not version:
                errors.append({"key": key, "code": "invalid_package", "message": "name and version are required"})
                continue

            try:
                data = self._query_one(name, version, ecosystem)
            except OsvError as exc:
                errors.append({"key": key, "code": exc.code, "message": exc.message})
                continue

            vuln_list = data.get("vulns")
            if not vuln_list:
                # OSV returns {} or {"vulns": null} when no advisories match
                advisories[key] = []
                continue

            if not isinstance(vuln_list, list):
                errors.append({"key": key, "code": "malformed_response", "message": "'vulns' is not a list"})
                continue

            parsed: list[OsvAdvisory] = []
            for raw_vuln in vuln_list:
                try:
                    parsed.append(_parse_advisory(raw_vuln, ecosystem))
                except OsvError as exc:
                    # One malformed vuln does not discard all others for this package
                    errors.append({"key": key, "code": exc.code, "message": exc.message})

            advisories[key] = parsed

        return OsvBatchResult(advisories=advisories, errors=errors)

    def _query_one(self, name: str, version: str, ecosystem: str) -> dict[str, Any]:
        payload = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        }
        return _post_json(self._url, payload, self._timeout)
