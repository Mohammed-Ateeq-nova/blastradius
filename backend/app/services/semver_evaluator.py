"""npm SemVer 2.0.0 and OSV affected-range evaluator.

Principles
----------
1. Standard SemVer 2.0.0 rules: numeric major/minor/patch, prerelease precedence,
   and build metadata handling.
2. OSV schema events:
   - ``introduced``: lower bound (inclusive; "0" means beginning of history).
   - ``fixed``: exclusive upper bound (version >= fixed resolves the vuln).
   - ``last_affected``: inclusive upper bound (version > last_affected resolves the vuln).
   - Multiple intervals in one advisory are evaluated as a union.
3. npm range syntax:
   - Comparators: ``<``, ``<=``, ``>``, ``>=``, ``=``, ``!=``.
   - Sets with spaces (AND) and ``||`` unions (OR).
   - Desugaring for ``^`` (caret), ``~`` (tilde), ``-`` (hyphen), and wildcards (``*``, ``x``).
4. Strict safety:
   - Unsupported or invalid ranges return ``None`` (unverified).
   - A target upgrade is NEVER claimed as resolving unless verified outside the range.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, order=False)
class NpmVersion:
    """Parsed npm semantic version following SemVer 2.0.0 specification."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[str | int, ...] = ()
    build: str | None = None
    raw: str = ""

    @classmethod
    def parse(cls, version_str: Any) -> NpmVersion | None:
        """Parse a SemVer string into an NpmVersion instance, or None if invalid."""
        if version_str is None:
            return None
        raw = str(version_str).strip()
        if not raw:
            return None

        # Strip leading 'v' or '='
        clean = re.sub(r"^[v=]+", "", raw)

        # Match major.minor.patch[-prerelease][+build]
        pattern = (
            r"^(\d+)"
            r"(?:\.(\d+))?"
            r"(?:\.(\d+))?"
            r"(?:-([0-9a-zA-Z\.\-]+))?"
            r"(?:\+([0-9a-zA-Z\.\-]+))?$"
        )
        m = re.match(pattern, clean)
        if not m:
            return None

        major = int(m.group(1))
        minor = int(m.group(2) or 0)
        patch = int(m.group(3) or 0)

        prerelease_str = m.group(4)
        prerelease: list[str | int] = []
        if prerelease_str:
            for part in prerelease_str.split("."):
                if part.isdigit():
                    prerelease.append(int(part))
                else:
                    prerelease.append(part)

        build_str = m.group(5)

        return cls(
            major=major,
            minor=minor,
            patch=patch,
            prerelease=tuple(prerelease),
            build=build_str,
            raw=raw,
        )

    def _cmp_key(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, NpmVersion):
            parsed = NpmVersion.parse(other)
            if parsed is None:
                raise TypeError(f"Cannot compare NpmVersion with {other!r}")
            other = parsed

        if self._cmp_key() != other._cmp_key():
            return self._cmp_key() < other._cmp_key()

        # SemVer 2.0.0 rule: normal version has higher precedence than prerelease
        # e.g. 1.0.0-alpha < 1.0.0
        if not self.prerelease and other.prerelease:
            return False
        if self.prerelease and not other.prerelease:
            return True
        if not self.prerelease and not other.prerelease:
            return False

        # Both have prerelease: compare identifier by identifier
        for a, b in zip(self.prerelease, other.prerelease):
            if a == b:
                continue
            if isinstance(a, int) and isinstance(b, int):
                return a < b
            if isinstance(a, int) and isinstance(b, str):
                return True  # Numeric identifiers have lower precedence than alphanumeric
            if isinstance(a, str) and isinstance(b, int):
                return False
            return str(a) < str(b)

        return len(self.prerelease) < len(other.prerelease)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, NpmVersion):
            parsed = NpmVersion.parse(other)
            if parsed is None:
                return False
            other = parsed
        return self._cmp_key() == other._cmp_key() and self.prerelease == other.prerelease

    def __le__(self, other: Any) -> bool:
        return self < other or self == other

    def __gt__(self, other: Any) -> bool:
        return not (self <= other)

    def __ge__(self, other: Any) -> bool:
        return not (self < other)

    def __str__(self) -> str:
        s = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            s += "-" + ".".join(str(p) for p in self.prerelease)
        if self.build:
            s += f"+{self.build}"
        return s

    def __repr__(self) -> str:
        return f"NpmVersion({str(self)!r})"


# ---------------------------------------------------------------------------
# npm Range Parsing & Desugaring
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Comparator:
    op: str  # "<", "<=", ">", ">=", "=", "!="
    version: NpmVersion

    def matches(self, v: NpmVersion) -> bool:
        if self.op == "=":
            return v == self.version
        if self.op == "!=":
            return v != self.version
        if self.op == "<":
            return v < self.version
        if self.op == "<=":
            return v <= self.version
        if self.op == ">":
            return v > self.version
        if self.op == ">=":
            return v >= self.version
        return False


def _desugar_caret(s: str) -> str:
    """Expand ^1.2.3 according to npm SemVer caret rules."""
    def repl(m: re.Match[str]) -> str:
        maj = int(m.group(1))
        min_ = int(m.group(2) or 0)
        pat = int(m.group(3) or 0)
        pre = m.group(4) or ""
        pre_suffix = f"-{pre}" if pre else ""
        if maj > 0:
            return f">={maj}.{min_}.{pat}{pre_suffix} <{maj + 1}.0.0"
        elif min_ > 0:
            return f">={maj}.{min_}.{pat}{pre_suffix} <{maj}.{min_ + 1}.0"
        else:
            return f">={maj}.{min_}.{pat}{pre_suffix} <{maj}.{min_}.{pat + 1}"

    return re.sub(
        r"\^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9a-zA-Z\.\-]+))?",
        repl,
        s,
    )


def _desugar_tilde(s: str) -> str:
    """Expand ~1.2.3 according to npm SemVer tilde rules."""
    def repl(m: re.Match[str]) -> str:
        maj = int(m.group(1))
        has_min = m.group(2) is not None
        min_ = int(m.group(2) or 0)
        pat = int(m.group(3) or 0)
        pre = m.group(4) or ""
        pre_suffix = f"-{pre}" if pre else ""

        if has_min:
            return f">={maj}.{min_}.{pat}{pre_suffix} <{maj}.{min_ + 1}.0"
        else:
            return f">={maj}.0.0{pre_suffix} <{maj + 1}.0.0"

    return re.sub(
        r"~(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9a-zA-Z\.\-]+))?",
        repl,
        s,
    )


def _desugar_hyphen(s: str) -> str:
    """Expand '1.2.3 - 2.3.4' into '>=1.2.3 <=2.3.4'."""
    pattern = r"(\bv?\d+(?:\.[0-9a-zA-Z\.\-]+)*)\s+-\s+(\bv?\d+(?:\.[0-9a-zA-Z\.\-]+)*)"

    def repl(m: re.Match[str]) -> str:
        v1_str, v2_str = m.group(1), m.group(2)
        v1 = NpmVersion.parse(v1_str)
        v2 = NpmVersion.parse(v2_str)
        if not v1 or not v2:
            return m.group(0)
        return f">={v1} <={v2}"

    return re.sub(pattern, repl, s)


class NpmRange:
    """Represents a full npm SemVer range (conjunctions of comparators and unions)."""

    def __init__(self, comparator_sets: list[list[Comparator]]):
        self._sets = comparator_sets

    @classmethod
    def parse(cls, range_str: str) -> NpmRange | None:
        """Parse npm range string. Returns None if invalid or unsupported."""
        if not range_str or not str(range_str).strip():
            return None

        raw = str(range_str).strip()
        # Handle simple wildcards
        if raw in ("*", "x", "X", ">=0.0.0"):
            zero = NpmVersion(0, 0, 0)
            return cls([[Comparator(">=", zero)]])

        # Step 1: Desugar hyphen, caret, tilde
        s = _desugar_hyphen(raw)
        s = _desugar_caret(s)
        s = _desugar_tilde(s)

        # Replace commas with spaces (e.g. ">=1.0.0, <2.0.0" -> ">=1.0.0 <2.0.0")
        s = s.replace(",", " ")

        comparator_sets: list[list[Comparator]] = []
        or_clauses = s.split("||")

        for or_clause in or_clauses:
            clause = or_clause.strip()
            if not clause:
                continue

            # Tokenize comparators: op (optional) + version
            comp_pattern = r"(<=|>=|<|>|!=|=)?\s*([0-9a-zA-Z\.\-+]+)"
            tokens = re.findall(comp_pattern, clause)
            if not tokens:
                return None

            current_set: list[Comparator] = []
            for op, ver_str in tokens:
                op = op or "="
                # Handle wildcard parts like 1.x or 1.2.x
                if ver_str.lower() in ("*", "x"):
                    continue
                if re.match(r"^\d+\.[xX\*]$", ver_str):
                    maj = int(ver_str.split(".")[0])
                    current_set.append(Comparator(">=", NpmVersion(maj, 0, 0)))
                    current_set.append(Comparator("<", NpmVersion(maj + 1, 0, 0)))
                    continue
                if re.match(r"^\d+\.\d+\.[xX\*]$", ver_str):
                    parts = ver_str.split(".")
                    maj, min_ = int(parts[0]), int(parts[1])
                    current_set.append(Comparator(">=", NpmVersion(maj, min_, 0)))
                    current_set.append(Comparator("<", NpmVersion(maj, min_ + 1, 0)))
                    continue

                v = NpmVersion.parse(ver_str)
                if v is None:
                    # Unparseable version string in range
                    return None
                current_set.append(Comparator(op, v))

            if current_set:
                comparator_sets.append(current_set)

        if not comparator_sets:
            return None

        return cls(comparator_sets)

    def contains(self, version: NpmVersion | str) -> bool:
        """Check if *version* satisfies this range."""
        v = version if isinstance(version, NpmVersion) else NpmVersion.parse(version)
        if v is None:
            return False

        # Any comparator set satisfying all its comparators satisfies the range (OR of ANDs)
        for comp_set in self._sets:
            if all(comp.matches(v) for comp in comp_set):
                return True
        return False


# ---------------------------------------------------------------------------
# OSV Events & High-Level Resolution Evaluator
# ---------------------------------------------------------------------------


def evaluate_osv_interval(
    version: NpmVersion,
    introduced: str | None,
    fixed: str | None = None,
    last_affected: str | None = None,
) -> bool | None:
    """Evaluate whether *version* is inside a single OSV event interval.

    Returns:
    - True if inside the interval (affected).
    - False if outside the interval (safe from this interval).
    - None if versions cannot be parsed confidently.
    """
    # 1. Lower bound (introduced)
    if introduced and introduced != "0":
        v_intro = NpmVersion.parse(introduced)
        if v_intro is None:
            return None
        if version < v_intro:
            # Below the introduced version -> outside this affected interval
            return False

    # 2. Upper bound (fixed or last_affected)
    if fixed:
        v_fixed = NpmVersion.parse(fixed)
        if v_fixed is None:
            return None
        if version >= v_fixed:
            # Fixed version or higher -> outside this affected interval
            return False

    if last_affected:
        v_last = NpmVersion.parse(last_affected)
        if v_last is None:
            return None
        if version > v_last:
            # Higher than last affected -> outside this affected interval
            return False

    # If it is >= introduced and (< fixed or <= last_affected), it is affected
    return True


def evaluate_version_against_osv_ranges(
    version: NpmVersion,
    ranges: list[Any],
) -> bool | None:
    """Evaluate whether *version* is affected by any interval in OSV ranges.

    Returns:
    - True: version is inside at least one affected interval (affected).
    - False: version is outside ALL affected intervals (not affected).
    - None: insufficient or unparseable interval data (unverified).
    """
    if not ranges:
        return None

    at_least_one_interval = False

    for r in ranges:
        # Support either AffectedRange dataclass or raw dict
        rtype = getattr(r, "range_type", None) or (r.get("type") if isinstance(r, dict) else None)
        if rtype and str(rtype).upper() not in ("SEMVER", "ECOSYSTEM"):
            # We only evaluate SEMVER and ECOSYSTEM ranges for npm
            continue

        # Extract introduced, fixed, last_affected
        intro = getattr(r, "introduced", None) or (r.get("introduced") if isinstance(r, dict) else None)
        fixed = getattr(r, "fixed", None) or (r.get("fixed") if isinstance(r, dict) else None)
        last_aff = getattr(r, "last_affected", None) or (r.get("last_affected") if isinstance(r, dict) else None)

        if intro is None and fixed is None and last_aff is None:
            continue

        at_least_one_interval = True
        is_in_interval = evaluate_osv_interval(version, intro, fixed, last_aff)
        if is_in_interval is None:
            return None
        if is_in_interval is True:
            # Found in at least one affected interval
            return True

    if not at_least_one_interval:
        return None

    # Checked all intervals; version was not in any of them
    return False


def is_upgrade_a_fix(
    target_version: str,
    affected_range: str | None = None,
    fixed_version: str | None = None,
    osv_ranges: list[Any] | None = None,
    affected_versions: list[str] | None = None,
) -> bool | None:
    """Check if *target_version* resolves an advisory.

    Returns
    -------
    bool:
        True: verified outside the advisory's affected range (resolves the vuln).
        False: verified inside the affected range (does NOT resolve the vuln).
    None:
        Insufficient advisory information or unparseable range (unverified).
    """
    v_target = NpmVersion.parse(target_version)
    if v_target is None:
        return None

    # 1. Explicit affected_versions check
    if affected_versions:
        # Normalize all listed versions
        for aff_str in affected_versions:
            aff_v = NpmVersion.parse(aff_str)
            if aff_v and aff_v == v_target:
                return False  # Target is explicitly listed as affected

    # 2. OSV ranges / events check
    if osv_ranges:
        res = evaluate_version_against_osv_ranges(v_target, osv_ranges)
        if res is not None:
            # If res is True (affected) -> return False (not a fix)
            # If res is False (not affected) -> return True (is a fix)
            return not res

    # 3. Direct fixed_version check
    if fixed_version:
        v_fixed = NpmVersion.parse(fixed_version)
        if v_fixed:
            return v_target >= v_fixed

    # 4. npm range string check
    if affected_range:
        nr = NpmRange.parse(affected_range)
        if nr is not None:
            is_affected = nr.contains(v_target)
            return not is_affected

    # 5. Insufficient data to verify
    return None
