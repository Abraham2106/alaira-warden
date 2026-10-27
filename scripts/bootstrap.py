"""Create an untracked local configuration without printing or overwriting secrets."""

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def bootstrap(root: Path = ROOT) -> bool:
    destination = root / ".env"
    if destination.exists():
        print(".env already exists; no values were changed.")
        return False
    owner_password = secrets.token_urlsafe(32)
    app_password = secrets.token_urlsafe(32)
    values = {
        "WARDEN_API_TOKEN": secrets.token_urlsafe(32),
        "POSTGRES_PASSWORD": owner_password,
        "WARDEN_DB_APP_PASSWORD": app_password,
        "WARDEN_DATABASE_URL": f"postgresql://warden_app:{app_password}@localhost:5432/warden",
        "WARDEN_MIGRATION_DATABASE_URL": (
            f"postgresql://warden_owner:{owner_password}@localhost:5432/warden"
        ),
    }
    template = (root / ".env.example").read_text(encoding="utf-8")
    lines = []
    for line in template.splitlines():
        key = line.partition("=")[0]
        lines.append(f"{key}={values[key]}" if key in values else line)
    # O_EXCL also protects against another setup process creating the file concurrently.
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as file:
        file.write("\n".join(lines) + "\n")
    print("Created .env with random local credentials. No secrets were printed.")
    return True


if __name__ == "__main__":
    bootstrap()
