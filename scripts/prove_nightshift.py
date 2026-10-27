"""Prove a live Nightshift Runtime. Fail closed when it is not actually serving."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from alaira_warden.config import Settings  # noqa: E402
from alaira_warden.nightshift import prove_nightshift  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe Nightshift and write an e2e artifact")
    parser.add_argument(
        "--no-generate",
        action="store_true",
        help="Stop after GET /v1/models. verified stays false.",
    )
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--model", default=None)
    args = parser.parse_args(argv)
    settings = Settings()
    base_url = settings.warden_meterless_base_url if args.base_url is None else args.base_url
    model = settings.warden_meterless_model if args.model is None else args.model
    report = prove_nightshift(
        base_url=base_url,
        api_key=settings.warden_meterless_api_key.get_secret_value(),
        model=model,
        generate=not args.no_generate,
    )
    destination = ROOT / "artifacts" / "nightshift-e2e.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "verified": report["verified"],
                "status": report["status"],
                "reason": report["reason"],
                "artifact": "artifacts/nightshift-e2e.json",
            }
        )
    )
    return 0 if report["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
