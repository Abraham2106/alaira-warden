"""Batch calls to npm's reference matcher; never evaluate advisory text as JavaScript."""

import json
import os
import shutil
import subprocess
from pathlib import Path

SCRIPT = """
const semver = require(process.argv[1]);
const pairs = JSON.parse(require('fs').readFileSync(0, 'utf8'));
console.log(JSON.stringify(pairs.map(([v, r]) =>
    semver.valid(v) && r.trim() && semver.validRange(r)
        ? semver.satisfies(v, r) : null)));
"""


def npm_matches(pairs: set[tuple[str, str]]) -> dict[tuple[str, str], bool | None]:
    if not pairs:
        return {}
    ordered = sorted(pairs)
    if len(ordered) > 20000:
        return dict.fromkeys(ordered)
    executable = shutil.which("node")
    module = Path.cwd() / "node_modules" / "semver"
    if not executable or not (module / "package.json").is_file():
        return dict.fromkeys(ordered)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE"}
    }
    try:
        response = subprocess.run(
            [executable, "-e", SCRIPT, str(module)],
            input=json.dumps(ordered),
            text=True,
            capture_output=True,
            timeout=10,
            check=True,
            env=environment,
        )
        result = json.loads(response.stdout)
        if len(result) != len(ordered) or any(
            item is not None and type(item) is not bool for item in result
        ):
            raise ValueError("Unexpected npm matcher response.")
        return dict(zip(ordered, result, strict=True))
    except (OSError, subprocess.SubprocessError, ValueError):
        return dict.fromkeys(ordered)
