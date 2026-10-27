"""Run official H-MEM vectors against the Python port. Optional TypeScript runner."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from alaira_warden.hmem.conformance import scorecard  # noqa: E402

VENDOR = ROOT / "vendor" / "meterless-hmem"


def main() -> int:
    card = scorecard()
    Path("artifacts").mkdir(exist_ok=True)
    Path("artifacts/hmem-conformance.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    print(f"H-MEM Python conformance: {card['passed']}/{card['total']}")
    for item in card["results"]:
        extra = f" — {item['detail']}" if item.get("detail") else ""
        print(f"  {item['status']} {item['id']} {item['description']}{extra}")
    if not card["verified"]:
        return 1
    sys.stdout.flush()
    npx = shutil.which("npx")
    runner = VENDOR / "conformance" / "runner.ts"
    if npx and runner.exists():
        result = subprocess.run(
            [npx, "--yes", "tsx", str(runner)],
            cwd=VENDOR / "conformance",
            check=False,
        )
        print(f"official TypeScript runner exit {result.returncode}")
        return result.returncode
    print("npx/tsx not available; Python vectors are the local proof.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
