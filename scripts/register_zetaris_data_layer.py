"""Register Warden's read-only views as a Zetaris datasource and prove one SELECT."""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

from psycopg import sql

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from alaira_warden.config import Settings  # noqa: E402
from alaira_warden.db import connect  # noqa: E402
from alaira_warden.providers.zetaris import ZetarisClient  # noqa: E402

DATASOURCE = "warden_pg"
INVENTORY = f"{DATASOURCE}.warden_inventory_data"
EVIDENCE = f"{DATASOURCE}.warden_evidence_data"
READER = "warden_zetaris_reader"
JDBC = "jdbc:postgresql://alaira-warden-db-1:5432/warden"
DRIVER_CONTAINER = "zetaris-driver-1"
WARDEN_NET = "alaira-warden_database"


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def upsert_env(path: Path, updates: dict[str, str]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    seen: set[str] = set()
    written = []
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line and not line.startswith("#") else None
        if key in updates:
            written.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            written.append(line)
    for key, value in updates.items():
        if key not in seen:
            written.append(f"{key}={value}")
    path.write_text("\n".join(written) + "\n", encoding="utf-8")


def sql_literal(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_@!.$?%*&-]{8,128}", value):
        raise ValueError("refusing an unsafe SQL literal")
    return value.replace("'", "''")


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def connect_driver_network() -> None:
    result = run(["docker", "network", "connect", WARDEN_NET, DRIVER_CONTAINER])
    text = (result.stdout or "") + (result.stderr or "")
    if (
        result.returncode != 0
        and "already exists" not in text.lower()
        and "already connected" not in text.lower()
    ):
        raise RuntimeError(text.strip() or "failed to attach the Zetaris driver to Warden Postgres")


def ensure_reader(settings: Settings, password: str) -> None:
    owner = settings.model_copy(
        update={"warden_database_url": settings.warden_migration_database_url}
    )
    with connect(owner) as connection:
        exists = connection.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (READER,)).fetchone()
        role = sql.Identifier(READER)
        secret = sql.Literal(password)
        if exists:
            connection.execute(sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(role, secret))
        else:
            connection.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} IN ROLE warden_data_reader").format(
                    role, secret
                )
            )
        connection.execute(sql.SQL("GRANT CONNECT ON DATABASE warden TO {}").format(role))
        connection.execute("GRANT USAGE ON SCHEMA public TO warden_data_reader")
        connection.execute(
            "GRANT SELECT ON warden_inventory_data, warden_evidence_data TO warden_data_reader"
        )


def execute_sql(client: ZetarisClient, statement: str) -> dict:
    """Admin Lightning SQL, including CREATE/REGISTER. Not a Warden investigation query."""
    token, org_id = client._login()  # noqa: SLF001 - same local UI session as query()
    origin = client._origin()  # noqa: SLF001
    from alaira_warden.providers.chat import decode_object, failure_from_status, send_with_budget
    from alaira_warden.providers.http import HttpRequest, ensure_timeout

    response = send_with_budget(
        client._transport,  # noqa: SLF001
        HttpRequest(
            method="POST",
            url=f"{origin}/api/proxy/sql-editor/sqls/run-query",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Org-ID": org_id,
            },
            body=json.dumps({"sql": statement}, separators=(",", ":")).encode(),
            timeout=ensure_timeout(60, ceiling=60, provider="zetaris"),
        ),
        provider="zetaris",
        secrets=client._secrets,  # noqa: SLF001
        max_attempts=1,
    )
    error = failure_from_status(response, provider="zetaris", secrets=client._secrets)
    if error is not None:
        preview = response.body[:400].decode("utf-8", "replace")
        raise RuntimeError(f"SQL HTTP {response.status}: {error.kind}: {preview}") from error
    return decode_object(response, provider="zetaris", secrets=client._secrets)


def datasource_present(payload: dict) -> bool:
    blob = json.dumps(payload).lower()
    return DATASOURCE.lower() in blob


def main() -> int:
    platform = load_env(ROOT / "zetaris-platform" / ".env")
    settings = Settings(_env_file=ROOT / ".env")
    if not settings.warden_migration_database_url.get_secret_value():
        raise SystemExit("WARDEN_MIGRATION_DATABASE_URL is required to grant the read-only login")
    password = secrets.token_urlsafe(18).replace("-", "A").replace("_", "b") + "1a"
    connect_driver_network()
    ensure_reader(settings, password)
    client = ZetarisClient(
        base_url="http://127.0.0.1:3000",
        org_id=os.getenv("WARDEN_ZETARIS_ORG_ID", ""),
        username=platform["ZETARIS_ADMIN_EMAIL"],
        password=platform["ZETARIS_ADMIN_PASSWORD"],
    )
    listed = execute_sql(client, "SHOW DATASOURCES")
    if not datasource_present(listed):
        create = (
            f"CREATE DATASOURCE {DATASOURCE} DESCRIBE BY 'Warden inventory and evidence views' "
            "OPTIONS ("
            'jdbcdriver "org.postgresql.Driver", '
            f'jdbcurl "{JDBC}", '
            f'username "{READER}", '
            f'password "{sql_literal(password)}"'
            ")"
        )
        execute_sql(client, create)
        execute_sql(
            client,
            "REGISTER DATASOURCE TABLES "
            "('warden_inventory_data','warden_evidence_data') "
            f"FROM {DATASOURCE}",
        )
    smoke = client.query("SELECT 1 AS one LIMIT 1")
    if smoke.columns[0].lower() != "one" or str(smoke.rows[0][0]) not in {"1", "1.0"}:
        raise SystemExit(f"Zetaris SELECT 1 failed: {smoke.columns!r} {smoke.rows!r}")
    inventory = client.query(f"SELECT payload FROM {INVENTORY} LIMIT 1")
    evidence = client.query(f"SELECT payload FROM {EVIDENCE} LIMIT 1")
    login = client.check()
    org_id = client._login()[1]  # noqa: SLF001
    upsert_env(
        ROOT / ".env",
        {
            "WARDEN_ZETARIS_BASE_URL": "http://127.0.0.1:3000",
            "WARDEN_ZETARIS_USERNAME": platform["ZETARIS_ADMIN_EMAIL"],
            "WARDEN_ZETARIS_PASSWORD": platform["ZETARIS_ADMIN_PASSWORD"],
            "WARDEN_ZETARIS_ORG_ID": org_id,
            "WARDEN_ZETARIS_INVENTORY_TABLE": INVENTORY,
            "WARDEN_ZETARIS_EVIDENCE_TABLE": EVIDENCE,
            "WARDEN_DATA_MODE": "zetaris",
        },
    )
    evidence_path = ROOT / "artifacts" / "zetaris" / "data-layer.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(
            {
                "login": {"status": login.status, "verified": login.verified},
                "select_1": {"columns": smoke.columns, "rows": smoke.rows},
                "inventory_table": INVENTORY,
                "evidence_table": EVIDENCE,
                "inventory_rows": len(inventory.rows),
                "evidence_rows": len(evidence.rows),
                "inventory_sources": inventory.sources,
                "evidence_sources": evidence.sources,
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    print(f"Zetaris data layer registered. Evidence: {evidence_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
