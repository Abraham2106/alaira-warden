"""Run the labeled agent demo against the configured database."""

import json
from pathlib import Path

from alaira_warden.agents.demo import run_guided_demo
from alaira_warden.config import Settings


def main() -> None:
    settings = Settings()
    result = run_guided_demo(settings, actor="demo-script")
    destination = Path("artifacts/demo/agents.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "synthetic": result["synthetic"],
        "sponsors_verified": result["sponsors_verified"],
        "nightshift_deployment_verified": result["nightshift_deployment_verified"],
        "investigation_id": str(result["investigation_id"]),
        "application_id": str(result["application_id"]),
        "events": [
            {
                "agent": event["agent"],
                "status": event["status"],
                "summary": event["summary"],
            }
            for event in result["events"]
        ],
    }
    encoded = json.dumps(payload, indent=2, default=str)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(encoded, encoding="utf-8")
        print(f"Guided demo stored {len(payload['events'])} agent acts in {destination}")
    except OSError:
        print(encoded)
    print("Open http://localhost:8000 and select the new investigation.")
    print(f"investigation_id={payload['investigation_id']}")


if __name__ == "__main__":
    main()
