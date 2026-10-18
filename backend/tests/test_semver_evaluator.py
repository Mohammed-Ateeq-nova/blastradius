"""Tests for npm SemVer 2.0.0 and OSV affected-range evaluator.

Covers:
- SemVer 2.0.0 parsing, comparison, and prerelease precedence
- OSV event intervals (introduced, fixed, last_affected)
- Single and multi-interval OSV advisories
- Open intervals (no fix available)
- npm range syntax desugaring (^, ~, -, ||, spaces, wildcards)
- False-positive and false-negative regression scenarios
- Unsupported/unverified range handling (never silently counted as a fix)
"""
from __future__ import annotations

import pytest

from app.services.semver_evaluator import (
    NpmRange,
    NpmVersion,
    evaluate_osv_interval,
    evaluate_version_against_osv_ranges,
    is_upgrade_a_fix,
)

# ---------------------------------------------------------------------------
# 1. NpmVersion parsing and SemVer 2.0.0 precedence
# ---------------------------------------------------------------------------


def test_npm_version_parse_basic():
    v1 = NpmVersion.parse("1.2.3")
    assert v1 is not None
    assert (v1.major, v1.minor, v1.patch) == (1, 2, 3)
    assert v1.prerelease == ()

    v2 = NpmVersion.parse("v4.17.21")
    assert v2 is not None
    assert (v2.major, v2.minor, v2.patch) == (4, 17, 21)

    v3 = NpmVersion.parse("=0.1.0")
    assert v3 is not None
    assert (v3.major, v3.minor, v3.patch) == (0, 1, 0)


def test_npm_version_parse_prerelease_and_build():
    v = NpmVersion.parse("1.0.0-beta.1+sha.exp.02")
    assert v is not None
    assert (v.major, v.minor, v.patch) == (1, 0, 0)
    assert v.prerelease == ("beta", 1)
    assert v.build == "sha.exp.02"


def test_npm_version_invalid():
    assert NpmVersion.parse(None) is None
    assert NpmVersion.parse("") is None
    assert NpmVersion.parse("invalid.semver.string") is None
    assert NpmVersion.parse("1.2.3.4") is None


def test_npm_version_semver_2_precedence():
    """Verify strict SemVer 2.0.0 precedence rules."""
    v1 = NpmVersion.parse("1.0.0-alpha")
    v2 = NpmVersion.parse("1.0.0-alpha.1")
    v3 = NpmVersion.parse("1.0.0-alpha.beta")
    v4 = NpmVersion.parse("1.0.0-beta")
    v5 = NpmVersion.parse("1.0.0-beta.2")
    v6 = NpmVersion.parse("1.0.0-beta.11")
    v7 = NpmVersion.parse("1.0.0-rc.1")
    v8 = NpmVersion.parse("1.0.0")
    v9 = NpmVersion.parse("1.0.1")
    v10 = NpmVersion.parse("1.1.0")
    v11 = NpmVersion.parse("2.0.0")

    # Order must strictly hold
    versions = [v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11]
    for i in range(len(versions) - 1):
        assert versions[i] < versions[i + 1], f"{versions[i]} should be < {versions[i+1]}"
        assert versions[i + 1] > versions[i]
        assert versions[i] != versions[i + 1]


def test_npm_version_build_metadata_ignored_in_comparison():
    v_a = NpmVersion.parse("1.0.0+build.1")
    v_b = NpmVersion.parse("1.0.0+build.2")
    assert v_a == v_b
    assert not (v_a < v_b)
    assert not (v_a > v_b)


# ---------------------------------------------------------------------------
# 2. OSV Event Intervals
# ---------------------------------------------------------------------------


def test_osv_interval_introduced_and_fixed():
    """[0, 4.17.21): 4.17.20 is affected, 4.17.21 is fixed."""
    v_aff = NpmVersion.parse("4.17.20")
    v_fix = NpmVersion.parse("4.17.21")
    v_after = NpmVersion.parse("4.17.22")

    assert evaluate_osv_interval(v_aff, introduced="0", fixed="4.17.21") is True
    assert evaluate_osv_interval(v_fix, introduced="0", fixed="4.17.21") is False
    assert evaluate_osv_interval(v_after, introduced="0", fixed="4.17.21") is False


def test_osv_interval_introduced_and_last_affected():
    """[1.0.0, 1.2.3]: 1.2.3 is affected, 1.2.4 is resolved."""
    v_before = NpmVersion.parse("0.9.0")
    v_start = NpmVersion.parse("1.0.0")
    v_last = NpmVersion.parse("1.2.3")
    v_fixed = NpmVersion.parse("1.2.4")

    assert evaluate_osv_interval(v_before, introduced="1.0.0", last_affected="1.2.3") is False
    assert evaluate_osv_interval(v_start, introduced="1.0.0", last_affected="1.2.3") is True
    assert evaluate_osv_interval(v_last, introduced="1.0.0", last_affected="1.2.3") is True
    assert evaluate_osv_interval(v_fixed, introduced="1.0.0", last_affected="1.2.3") is False


def test_osv_interval_open_ended():
    """No fix version available (unpatched). Everything >= introduced is affected."""
    v_before = NpmVersion.parse("2.9.9")
    v_intro = NpmVersion.parse("3.0.0")
    v_future = NpmVersion.parse("3.5.0")

    assert evaluate_osv_interval(v_before, introduced="3.0.0") is False
    assert evaluate_osv_interval(v_intro, introduced="3.0.0") is True
    assert evaluate_osv_interval(v_future, introduced="3.0.0") is True


def test_osv_multi_intervals_union():
    """Advisory affecting two distinct version streams:

    Interval 1: [0, 1.0.5)
    Interval 2: [2.0.0, 2.0.3)
    """
    ranges = [
        {"type": "SEMVER", "introduced": "0", "fixed": "1.0.5"},
        {"type": "SEMVER", "introduced": "2.0.0", "fixed": "2.0.3"},
    ]

    # In Interval 1
    assert evaluate_version_against_osv_ranges(NpmVersion.parse("1.0.4"), ranges) is True
    # Resolved in 1.x stream
    assert evaluate_version_against_osv_ranges(NpmVersion.parse("1.0.5"), ranges) is False
    # Between streams (not affected)
    assert evaluate_version_against_osv_ranges(NpmVersion.parse("1.5.0"), ranges) is False
    # In Interval 2
    assert evaluate_version_against_osv_ranges(NpmVersion.parse("2.0.2"), ranges) is True
    # Resolved in 2.x stream
    assert evaluate_version_against_osv_ranges(NpmVersion.parse("2.0.3"), ranges) is False


# ---------------------------------------------------------------------------
# 3. npm Range Parsing and Evaluation
# ---------------------------------------------------------------------------


def test_npm_range_comparators_and_spaces():
    r = NpmRange.parse(">=1.0.0 <2.0.0")
    assert r is not None
    assert r.contains("1.0.0") is True
    assert r.contains("1.5.0") is True
    assert r.contains("1.9.9") is True
    assert r.contains("0.9.9") is False
    assert r.contains("2.0.0") is False


def test_npm_range_union():
    r = NpmRange.parse("<1.0.0 || >=2.0.0")
    assert r is not None
    assert r.contains("0.9.0") is True
    assert r.contains("1.5.0") is False
    assert r.contains("2.0.0") is True
    assert r.contains("2.1.0") is True


def test_npm_range_caret():
    # ^1.2.3 -> >=1.2.3 <2.0.0
    r1 = NpmRange.parse("^1.2.3")
    assert r1 is not None
    assert r1.contains("1.2.2") is False
    assert r1.contains("1.2.3") is True
    assert r1.contains("1.9.0") is True
    assert r1.contains("2.0.0") is False

    # ^0.2.3 -> >=0.2.3 <0.3.0
    r2 = NpmRange.parse("^0.2.3")
    assert r2 is not None
    assert r2.contains("0.2.3") is True
    assert r2.contains("0.2.9") is True
    assert r2.contains("0.3.0") is False

    # ^0.0.3 -> >=0.0.3 <0.0.4
    r3 = NpmRange.parse("^0.0.3")
    assert r3 is not None
    assert r3.contains("0.0.3") is True
    assert r3.contains("0.0.4") is False


def test_npm_range_tilde():
    # ~1.2.3 -> >=1.2.3 <1.3.0
    r1 = NpmRange.parse("~1.2.3")
    assert r1 is not None
    assert r1.contains("1.2.3") is True
    assert r1.contains("1.2.9") is True
    assert r1.contains("1.3.0") is False


def test_npm_range_hyphen():
    # 1.0.0 - 2.0.0 -> >=1.0.0 <=2.0.0
    r = NpmRange.parse("1.0.0 - 2.0.0")
    assert r is not None
    assert r.contains("1.0.0") is True
    assert r.contains("1.5.0") is True
    assert r.contains("2.0.0") is True
    assert r.contains("2.0.1") is False


def test_npm_range_wildcards():
    r1 = NpmRange.parse("1.x")
    assert r1 is not None
    assert r1.contains("1.0.0") is True
    assert r1.contains("1.9.9") is True
    assert r1.contains("2.0.0") is False

    r2 = NpmRange.parse("*")
    assert r2 is not None
    assert r2.contains("0.0.1") is True
    assert r2.contains("99.0.0") is True


# ---------------------------------------------------------------------------
# 4. Regression Tests: False-Positive & False-Negative Avoidance
# ---------------------------------------------------------------------------


def test_regression_false_positive_rejected():
    """An upgrade that stays inside the affected range must NEVER be a fix."""
    # Scenario: vulnerability affects <4.17.21
    # Candidate upgrades from 4.17.15 to 4.17.19
    # 4.17.19 is still < 4.17.21 -> FALSE POSITIVE if claimed as fix!
    is_fix = is_upgrade_a_fix(
        target_version="4.17.19",
        affected_range="<4.17.21",
    )
    assert is_fix is False, "Must NOT claim fix when target is still affected"


def test_regression_false_positive_with_multi_interval():
    """Upgrading to a version in a second vulnerable branch must NOT be a fix."""
    osv_ranges = [
        {"type": "SEMVER", "introduced": "0", "fixed": "1.2.0"},
        {"type": "SEMVER", "introduced": "2.0.0", "fixed": "2.1.0"},
    ]
    # Upgrading from 1.1.0 to 2.0.5:
    # 2.0.5 is in interval 2!
    is_fix = is_upgrade_a_fix(
        target_version="2.0.5",
        osv_ranges=osv_ranges,
    )
    assert is_fix is False, "Must NOT claim fix when target falls into second vulnerable interval"


def test_regression_false_negative_accepted():
    """Exact fixed version boundary must be verified as a fix."""
    # When fixed = 4.17.21, upgrading to 4.17.21 IS a fix
    is_fix = is_upgrade_a_fix(
        target_version="4.17.21",
        fixed_version="4.17.21",
    )
    assert is_fix is True, "Exact fixed version must be recognized as resolved"


def test_regression_false_negative_last_affected_boundary():
    """Version strictly greater than last_affected must be verified as a fix."""
    osv_ranges = [
        {"type": "SEMVER", "introduced": "1.0.0", "last_affected": "1.2.3"}
    ]
    # 1.2.3 is affected
    assert is_upgrade_a_fix("1.2.3", osv_ranges=osv_ranges) is False
    # 1.2.4 is resolved
    assert is_upgrade_a_fix("1.2.4", osv_ranges=osv_ranges) is True


def test_regression_explicit_versions_list():
    """Target version in explicit affected_versions list must NOT be a fix."""
    is_fix = is_upgrade_a_fix(
        target_version="1.0.2",
        affected_versions=["1.0.0", "1.0.1", "1.0.2"],
    )
    assert is_fix is False


# ---------------------------------------------------------------------------
# 5. Unsupported / Unverified Range Handling
# ---------------------------------------------------------------------------


def test_unverified_on_missing_or_unparseable_data():
    """Missing or unparseable ranges return None, NEVER True."""
    assert is_upgrade_a_fix("1.2.3") is None
    assert is_upgrade_a_fix("1.2.3", affected_range="") is None
    assert is_upgrade_a_fix("1.2.3", affected_range="git:commit:1234567890abcdef") is None
    assert is_upgrade_a_fix("invalid.ver", affected_range="<2.0.0") is None
