from functools import lru_cache

from semantic_version import Version

from alaira_warden.correlation.models import Match, PackageRule, VersionRange
from alaira_warden.correlation.npm_ranges import npm_matches


@lru_cache(maxsize=2048)
def version(value: str) -> Version:
    if len(value) > 256:
        raise ValueError("Version too long.")
    parsed = Version(value)
    # Build metadata does not affect SemVer precedence or version matching.
    return Version(
        major=parsed.major, minor=parsed.minor, patch=parsed.patch, prerelease=parsed.prerelease
    )


def osv_intervals(installed: Version, rule: VersionRange) -> bool:
    if not rule.events:
        raise ValueError("Missing interval events.")
    opened = False
    lower = previous_upper = None
    previous_inclusive = False
    matched = False
    for event in rule.events:
        if len(event) != 1:
            raise ValueError("Each OSV event must contain exactly one boundary.")
        kind, boundary = next(iter(event.items()))
        if kind == "introduced":
            if opened:
                raise ValueError("An interval was introduced twice.")
            lower = None if boundary == "0" else version(boundary)
            if previous_upper is not None and (
                lower is None
                or lower < previous_upper
                or (lower == previous_upper and previous_inclusive)
            ):
                raise ValueError("Overlapping or unordered OSV intervals.")
            opened = True
        elif kind in {"fixed", "last_affected", "limit"}:
            if not opened:
                raise ValueError("Interval end lacks an introduced event.")
            upper = version(boundary)
            inclusive = kind == "last_affected"
            if lower is not None and (upper < lower or (upper == lower and not inclusive)):
                raise ValueError("Invalid OSV interval boundaries.")
            matched |= (lower is None or installed >= lower) and (
                installed <= upper if inclusive else installed < upper
            )
            previous_upper, previous_inclusive = upper, inclusive
            opened = False
        else:
            raise ValueError("Unsupported OSV boundary.")
    if opened:
        matched |= lower is None or installed >= lower
    return bool(matched)


def match_rules(
    installed: str | None,
    rules: tuple[PackageRule, ...],
    npm_results: dict[tuple[str, str], bool | None] | None = None,
) -> Match:
    if not installed:
        return Match(affected=None, reasons=("resolved_version_unknown",))
    try:
        parsed = version(installed)
    except ValueError:
        return Match(affected=None, reasons=("resolved_version_not_strict_semver",))
    results = []
    warnings = []
    for package in rules:
        for candidate in package.versions:
            try:
                results.append(parsed == version(candidate))
            except ValueError:
                warnings.append("explicit_version_not_supported")
        for item in package.ranges:
            try:
                if item.type == "npm" and item.expression is not None:
                    key = (installed, item.expression)
                    lookup = npm_results if npm_results is not None else npm_matches({key})
                    matched = lookup.get(key)
                    if matched is None:
                        warnings.append("npm_range_invalid_or_engine_unavailable")
                    else:
                        results.append(matched)
                elif item.type == "SEMVER":
                    results.append(osv_intervals(parsed, item))
                else:
                    warnings.append("range_type_not_supported")
            except (ValueError, TypeError):
                warnings.append("affected_range_invalid")
    if any(results):
        return Match(
            affected=True, reasons=("version_matches_affected_rule", *sorted(set(warnings)))
        )
    if warnings or not results:
        return Match(
            affected=None, reasons=tuple(sorted(set(warnings))) or ("affected_rules_missing",)
        )
    return Match(affected=False, reasons=("version_outside_affected_rules",))
