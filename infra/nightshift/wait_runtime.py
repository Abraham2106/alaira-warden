"""Wait until a host Nightshift Runtime answers GET /healthz.

A 200 only means the process is up. It does not authenticate or verify generation.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from alaira_warden.nightshift import healthz_url  # noqa: E402

DEFAULT_BASE = "http://127.0.0.1:8088/v1"


def open_healthz(url: str) -> int:
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(url, timeout=3) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def wait_for_runtime(
    base_url: str,
    *,
    attempts: int = 30,
    delay_seconds: float = 2,
    opener: Callable[[str], int] = open_healthz,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict:
    url = healthz_url(base_url)
    status: int | None = None
    reason = "healthz did not return 200"
    for attempt in range(1, attempts + 1):
        try:
            status = opener(url)
        except OSError as exc:
            status = None
            reason = exc.__class__.__name__
        else:
            reason = "process responded" if status == 200 else f"healthz returned {status}"
        if status == 200:
            return {
                "ready": True,
                "verified": False,
                "status_code": status,
                "url": url,
                "attempts": attempt,
                "reason": "process responded; authentication and generation were not proven",
            }
        if attempt < attempts and delay_seconds > 0:
            sleeper(delay_seconds)
    return {
        "ready": False,
        "verified": False,
        "status_code": status,
        "url": url,
        "attempts": attempts,
        "reason": reason,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Wait for Nightshift GET /healthz")
    parser.add_argument("--base-url", default=DEFAULT_BASE)
    parser.add_argument("--attempts", type=int, default=30)
    parser.add_argument("--delay-seconds", type=float, default=2)
    args = parser.parse_args(argv)
    if args.attempts < 1:
        print("attempts must be at least 1", file=sys.stderr)
        return 2
    try:
        report = wait_for_runtime(
            args.base_url, attempts=args.attempts, delay_seconds=args.delay_seconds
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(report))
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
