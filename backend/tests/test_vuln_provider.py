"""Tests for the OSV.dev vulnerability provider.

Test classes
------------
- Deterministic mocked tests (no network): ``TestOsvProviderMocked``
- Optional live integration test: ``TestOsvProviderLive`` (requires REQUIRES_NETWORK marker)

The live test is skipped automatically when the OSV API cannot be reached.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from io import BytesIO
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.services.vuln_provider import (
    AffectedRange,
    OsvAdvisory,
    OsvBatchResult,
    OsvError,
    OsvProvider,
    _extract_ranges,
    _extract_severity,
    _parse_advisory,
)

# ---------------------------------------------------------------------------
# Fixtures: canned OSV API responses
# ---------------------------------------------------------------------------

# A realistic full advisory record (SEMVER range, CVSS_V3 score)
LODASH_VULN = {
    "id": "GHSA-p6mc-m468-83gw",
    "aliases": ["CVE-2019-10744"],
    "summary": "Prototype Pollution in lodash",
    "details": "Versions of `lodash` prior to 4.17.12 are vulnerable…",
    "published": "2019-07-09T00:00:00Z",
    "modified": "2021-01-08T05:00:00Z",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
    "affected": [
        {
            "package": {"name": "lodash", "ecosystem": "npm", "purl": "pkg:npm/lodash"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "4.17.12"}],
                }
            ],
            "versions": [],
        }
    ],
}

# Advisory with no summary, no severity, no affected ranges
MINIMAL_VULN = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "modified": "2024-01-01T00:00:00Z",
}

# A non-npm ecosystem entry that should be skipped when parsing ranges
MIXED_ECOSYSTEM_VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "modified": "2024-06-01T00:00:00Z",
    "affected": [
        {
            "package": {"name": "lodash", "ecosystem": "PyPI"},  # different ecosystem
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}],
        },
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}],
        },
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(body: dict[str, Any], status: int = 200) -> MagicMock:
    """Return a mock context-manager mimicking ``urllib.request.urlopen``."""
    raw = json.dumps(body).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = raw
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _make_provider(mock_resp: MagicMock) -> OsvProvider:
    """Return a provider whose HTTP calls are intercepted."""
    return OsvProvider(url="https://test.osv.dev/v1/query")


# ---------------------------------------------------------------------------
# Unit tests: _extract_severity
# ---------------------------------------------------------------------------


class TestExtractSeverity:
    def test_returns_cvss_v3_score(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"}]}
        assert _extract_severity(vuln) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"

    def test_returns_none_when_no_severity(self):
        assert _extract_severity({}) is None

    def test_returns_none_when_severity_is_null(self):
        assert _extract_severity({"severity": None}) is None

    def test_skips_non_cvss_v3_entries(self):
        vuln = {"severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:N/I:P/A:P"}]}
        assert _extract_severity(vuln) is None


# ---------------------------------------------------------------------------
# Unit tests: _extract_ranges
# ---------------------------------------------------------------------------


class TestExtractRanges:
    def test_extracts_semver_range(self):
        affected = LODASH_VULN["affected"]
        ranges, versions = _extract_ranges(affected, "npm")
        assert len(ranges) == 1
        r = ranges[0]
        assert r.range_type == "SEMVER"
        assert r.introduced == "0"
        assert r.fixed == "4.17.12"
        assert versions == []

    def test_skips_wrong_ecosystem(self):
        ranges, _ = _extract_ranges(MIXED_ECOSYSTEM_VULN["affected"], "npm")
        # Only the npm entry should be included
        assert len(ranges) == 1
        assert ranges[0].fixed == "4.17.12"

    def test_empty_affected_returns_empty(self):
        ranges, versions = _extract_ranges([], "npm")
        assert ranges == []
        assert versions == []


# ---------------------------------------------------------------------------
# Unit tests: _parse_advisory
# ---------------------------------------------------------------------------


class TestParseAdvisory:
    def test_parses_full_vuln(self):
        adv = _parse_advisory(LODASH_VULN, "npm")
        assert adv.advisory_id == "GHSA-p6mc-m468-83gw"
        assert "CVE-2019-10744" in adv.aliases
        assert adv.summary == "Prototype Pollution in lodash"
        assert adv.severity is not None
        assert adv.source == "osv.dev"
        assert adv.published is not None
        assert adv.modified is not None
        assert len(adv.affected_ranges) == 1
        assert adv.affected_ranges[0].fixed == "4.17.12"

    def test_parses_minimal_vuln_without_error(self):
        adv = _parse_advisory(MINIMAL_VULN, "npm")
        assert adv.advisory_id == "GHSA-aaaa-bbbb-cccc"
        assert adv.summary is None
        assert adv.severity is None
        assert adv.affected_ranges == []
        assert adv.affected_versions == []

    def test_raises_on_missing_id(self):
        with pytest.raises(OsvError) as exc_info:
            _parse_advisory({"modified": "2024-01-01"}, "npm")
        assert exc_info.value.code == "malformed_response"

    def test_raises_on_non_dict(self):
        with pytest.raises(OsvError) as exc_info:
            _parse_advisory("not a dict", "npm")  # type: ignore[arg-type]
        assert exc_info.value.code == "malformed_response"


# ---------------------------------------------------------------------------
# Mocked tests: OsvProvider.query_batch
# ---------------------------------------------------------------------------


class TestOsvProviderMocked:
    """All tests patch urllib.request.urlopen — no network access."""

    def test_returns_advisories_for_matching_package(self):
        provider = OsvProvider(url="https://test.local/v1/query")
        mock_resp = _make_response({"vulns": [LODASH_VULN]})
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = provider.query_batch([{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}])

        assert result.errors == []
        key = "npm:lodash@4.17.21"
        assert key in result.advisories
        advisories = result.advisories[key]
        assert len(advisories) == 1
        adv = advisories[0]
        assert adv.advisory_id == "GHSA-p6mc-m468-83gw"
        assert adv.source == "osv.dev"
        assert adv.severity is not None

    def test_returns_empty_list_when_no_advisories(self):
        provider = OsvProvider(url="https://test.local/v1/query")
        mock_resp = _make_response({})  # OSV returns {} when nothing matches
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = provider.query_batch([{"name": "safe-pkg", "version": "1.0.0", "ecosystem": "npm"}])

        key = "npm:safe-pkg@1.0.0"
        assert key in result.advisories
        assert result.advisories[key] == []
        assert result.errors == []

    def test_returns_empty_list_when_vulns_is_null(self):
        provider = OsvProvider(url="https://test.local/v1/query")
        mock_resp = _make_response({"vulns": None})
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = provider.query_batch([{"name": "x", "version": "1.0.0", "ecosystem": "npm"}])
        assert result.advisories["npm:x@1.0.0"] == []

    def test_records_error_on_http_error_not_raises(self):
        """A single HTTP error is collected in errors; other packages still run."""
        provider = OsvProvider(url="https://test.local/v1/query")
        http_error = urllib.error.HTTPError(
            url="https://test.local/v1/query",
            code=500,
            msg="Internal Server Error",
            hdrs={},  # type: ignore[arg-type]
            fp=None,
        )
        safe_resp = _make_response({})

        def side_effect(*args, **kwargs):
            if side_effect.call_count == 0:
                side_effect.call_count += 1
                raise http_error
            return safe_resp

        side_effect.call_count = 0

        with patch("urllib.request.urlopen", side_effect=side_effect):
            result = provider.query_batch([
                {"name": "bad-pkg", "version": "1.0.0", "ecosystem": "npm"},
                {"name": "good-pkg", "version": "2.0.0", "ecosystem": "npm"},
            ])

        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "http_error"
        assert result.errors[0]["key"] == "npm:bad-pkg@1.0.0"
        assert "npm:good-pkg@2.0.0" in result.advisories

    def test_records_error_on_timeout_not_raises(self):
        provider = OsvProvider(url="https://test.local/v1/query")
        url_error = urllib.error.URLError("timed out")
        with patch("urllib.request.urlopen", side_effect=url_error):
            result = provider.query_batch([{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}])

        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "timeout"
        assert result.advisories == {}

    def test_records_error_on_url_error_not_raises(self):
        provider = OsvProvider(url="https://test.local/v1/query")
        url_error = urllib.error.URLError("Name or service not known")
        with patch("urllib.request.urlopen", side_effect=url_error):
            result = provider.query_batch([{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}])

        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "network_error"

    def test_records_error_on_malformed_json_response(self):
        provider = OsvProvider(url="https://test.local/v1/query")
        bad_resp = MagicMock()
        bad_resp.read.return_value = b"not json{"
        bad_resp.__enter__ = lambda s: s
        bad_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=bad_resp):
            result = provider.query_batch([{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}])

        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "malformed_response"

    def test_records_error_when_vulns_not_a_list(self):
        provider = OsvProvider(url="https://test.local/v1/query")
        mock_resp = _make_response({"vulns": "unexpected_string"})
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = provider.query_batch([{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}])

        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "malformed_response"

    def test_partial_malformed_vuln_does_not_discard_all(self):
        """One broken vuln entry in a list should not drop the valid ones."""
        provider = OsvProvider(url="https://test.local/v1/query")
        mock_resp = _make_response({"vulns": [{"broken": True}, LODASH_VULN]})
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = provider.query_batch([{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}])

        key = "npm:lodash@4.17.21"
        # One vuln parsed, one error recorded
        assert len(result.advisories[key]) == 1
        assert result.advisories[key][0].advisory_id == "GHSA-p6mc-m468-83gw"
        assert len(result.errors) == 1

    def test_skips_package_with_missing_name_or_version(self):
        provider = OsvProvider(url="https://test.local/v1/query")
        with patch("urllib.request.urlopen") as mock_open:
            result = provider.query_batch([
                {"name": "", "version": "1.0.0", "ecosystem": "npm"},
                {"name": "pkg", "version": "", "ecosystem": "npm"},
            ])
        mock_open.assert_not_called()
        assert len(result.errors) == 2
        assert all(e["code"] == "invalid_package" for e in result.errors)

    def test_multi_package_batch_queries_each_independently(self):
        """Each package in the batch gets its own API call."""
        provider = OsvProvider(url="https://test.local/v1/query")
        responses = [
            _make_response({"vulns": [LODASH_VULN]}),
            _make_response({}),
        ]
        with patch("urllib.request.urlopen", side_effect=responses):
            result = provider.query_batch([
                {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
                {"name": "minimist", "version": "1.2.5", "ecosystem": "npm"},
            ])

        assert len(result.advisories["npm:lodash@4.17.21"]) == 1
        assert result.advisories["npm:minimist@1.2.5"] == []
        assert result.errors == []

    def test_advisory_does_not_claim_exploitability(self):
        """Evidence label must NOT be set by the provider."""
        provider = OsvProvider(url="https://test.local/v1/query")
        mock_resp = _make_response({"vulns": [LODASH_VULN]})
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = provider.query_batch([{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}])

        adv = result.advisories["npm:lodash@4.17.21"][0]
        # OsvAdvisory must NOT have an exploitability or reachability claim
        assert not hasattr(adv, "exploitable")
        assert not hasattr(adv, "reachable")
        assert not hasattr(adv, "evidence_label")


# ---------------------------------------------------------------------------
# Live integration tests (require network)
# ---------------------------------------------------------------------------

def _can_reach_osv() -> bool:
    """Return True if the OSV API can be reached (best-effort check)."""
    try:
        import ssl
        import urllib.request

        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=b'{"package":{"name":"__probe__","ecosystem":"npm"},"version":"0.0.0"}',
            headers={"Content-Type": "application/json"},
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=5, context=ctx):
            return True
    except Exception:
        return False


REQUIRES_NETWORK = pytest.mark.skipif(
    not _can_reach_osv(),
    reason="REQUIRES_NETWORK: OSV API not reachable",
)


@REQUIRES_NETWORK
class TestOsvProviderLive:
    """Integration tests against the real OSV API.

    These are skipped automatically when the network is not available.
    They must not assert that a specific package ALWAYS has a vulnerability
    (advisories are continuously updated), but they must validate the
    response shape and source provenance.
    """

    def test_query_returns_osv_batch_result(self):
        provider = OsvProvider()
        result = provider.query_batch([{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}])

        assert isinstance(result, OsvBatchResult)
        key = "npm:lodash@4.17.21"
        assert key in result.advisories
        # Each advisory (if any) must carry required fields
        for adv in result.advisories[key]:
            assert isinstance(adv, OsvAdvisory)
            assert adv.advisory_id
            assert adv.source == "osv.dev"
            # modified is present in all OSV records
            assert adv.modified is not None

    def test_known_safe_package_and_version_returns_empty_or_list(self):
        """A non-existent package must not raise — it returns an empty list."""
        provider = OsvProvider()
        result = provider.query_batch([
            {"name": "__blast_radius_probe_nonexistent__", "version": "0.0.1", "ecosystem": "npm"}
        ])
        key = "npm:__blast_radius_probe_nonexistent__@0.0.1"
        assert key in result.advisories
        assert result.advisories[key] == []
        assert result.errors == []

    def test_no_new_dependencies_needed(self):
        """The provider must import without any third-party packages."""
        import importlib
        import sys

        # Ensure the module loads cleanly in the current venv
        mod = importlib.import_module("app.services.vuln_provider")
        assert hasattr(mod, "OsvProvider")
        assert hasattr(mod, "OsvAdvisory")
