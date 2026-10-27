"""Optional differential check against npm's real semver implementation, never downloaded here."""

import json
import os
import subprocess

import pytest

from alaira_warden.correlation.models import PackageRule, VersionRange
from alaira_warden.correlation.npm_ranges import npm_matches
from alaira_warden.correlation.versions import match_rules

pytestmark = pytest.mark.skipif(
    not os.getenv("WARDEN_NODE_SEMVER_MODULE"),
    reason="An approved local node-semver path is required",
)


def test_npm_range_semantics_against_node_semver():
    versions = [
        "0.0.0",
        "0.0.1",
        "0.2.3",
        "0.2.4",
        "0.3.0",
        "1.0.0",
        "1.2.3",
        "1.2.3-beta.1",
        "1.2.3-beta.2",
        "1.2.4-beta.1",
        "1.9.0",
        "2.0.0-beta.1",
        "2.0.0",
        "2.9.1",
        "3.0.0",
        "1.2.3+meta",
    ]
    ranges = [
        "*",
        "^0.0.1",
        "^0.2.3",
        "^1.2.3",
        "~1.2.3",
        "1.2.x",
        "1 - 2",
        "<1.0.0 || >=3.0.0",
        ">=1.2.3-beta.1 <1.2.3",
        ">=1.2.3",
        "<2.0.0",
        "<=2.0.0",
        "=1.2.3+different",
        ">=0.0.0-0",
    ]
    cases = [(version, expression) for version in versions for expression in ranges]
    script = """
const semver = require(process.argv[1]);
const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));
console.log(JSON.stringify(cases.map(([version, range]) => semver.satisfies(version, range))));
"""
    response = subprocess.run(
        ["node", "-e", script, os.environ["WARDEN_NODE_SEMVER_MODULE"]],
        input=json.dumps(cases),
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    )
    expected = json.loads(response.stdout)
    actual_batch = npm_matches(set(cases))
    differences = []
    for (version, expression), node_result in zip(cases, expected, strict=True):
        rule = PackageRule(
            ecosystem="npm",
            package_name="fixture",
            ranges=(VersionRange(type="npm", expression=expression),),
        )
        actual = match_rules(version, (rule,), actual_batch).affected
        if actual != node_result:
            differences.append((version, expression, actual, node_result))
    assert not differences, differences
