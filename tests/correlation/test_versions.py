import pytest

from alaira_warden.correlation.models import PackageRule, VersionRange
from alaira_warden.correlation.versions import match_rules


@pytest.mark.parametrize(
    ("installed", "expression", "expected"),
    [
        ("1.2.3", ">=1.2.3 <2.0.0", True),
        ("2.0.0", ">=1.2.3 <2.0.0", False),
        ("0.2.9", "^0.2.3", True),
        ("0.3.0", "^0.2.3", False),
        ("0.0.4", "^0.0.3", False),
        ("1.9.0", "~1.2.3", False),
        ("1.2.9", "1.2.x", True),
        ("2.0.0", "1.0.0 - 2.0.0", True),
        ("3.0.0", "<1.0.0 || >=3.0.0", True),
        ("1.3.0-beta.1", ">=1.2.3 <2.0.0", False),
        ("1.2.3-beta.2", ">=1.2.3-beta.1 <1.2.3", True),
        ("1.2.3+build.2", "=1.2.3", True),
        ("1.2.3", "", None),
        ("latest", "*", None),
        (None, "*", None),
    ],
)
def test_npm_boundaries_and_prereleases(installed, expression, expected):
    rules = (
        PackageRule(
            ecosystem="npm",
            package_name="fixture",
            ranges=(VersionRange(type="npm", expression=expression),),
        ),
    )
    assert match_rules(installed, rules).affected is expected


@pytest.mark.parametrize(
    ("installed", "events", "expected"),
    [
        ("1.0.0", ({"introduced": "0"}, {"fixed": "1.0.0"}), False),
        ("0.9.0-beta.1", ({"introduced": "0"}, {"fixed": "1.0.0"}), True),
        ("1.0.0", ({"introduced": "1.0.0"}, {"last_affected": "1.0.0"}), True),
        ("1.0.1", ({"introduced": "1.0.0"}, {"last_affected": "1.0.0"}), False),
        ("2.0.0", ({"introduced": "1.0.0"}, {"limit": "2.0.0"}), False),
        ("3.0.0", ({"introduced": "2.0.0"},), True),
        ("1.0.0", ({"fixed": "2.0.0"},), None),
        ("1.0.0", ({"introduced": "2.0.0"}, {"fixed": "1.0.0"}), None),
        ("1.0.0", ({"introduced": "0"}, {"introduced": "1.0.0"}), None),
    ],
)
def test_osv_interval_rules(installed, events, expected):
    rules = (
        PackageRule(
            ecosystem="npm",
            package_name="fixture",
            ranges=(VersionRange(type="SEMVER", events=events),),
        ),
    )
    assert match_rules(installed, rules).affected is expected


def test_unknown_range_cannot_produce_a_negative_conclusion():
    package = PackageRule(
        ecosystem="npm",
        package_name="fixture",
        ranges=(
            VersionRange(type="GIT"),
            VersionRange(type="npm", expression="<1.0.0"),
        ),
    )
    assert match_rules("2.0.0", (package,)).affected is None
    assert match_rules("0.9.0", (package,)).affected is True


def test_explicit_versions_ignore_build_metadata():
    package = PackageRule(ecosystem="npm", package_name="fixture", versions=("1.0.0+first",))
    assert match_rules("1.0.0+second", (package,)).affected is True
