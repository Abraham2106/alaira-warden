"""One-time administrator provisioning; writes a private local credential, never stdout."""

import os
from pathlib import Path

from alaira_warden.config import get_settings
from alaira_warden.db import connect
from alaira_warden.identity import PostgresIdentityStore, provision_initial_administrator
from alaira_warden.integration.auth import identity_settings


def provision(destination: Path):
    settings = get_settings()
    identity = identity_settings(settings)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            with connect(settings) as connection:
                issued = provision_initial_administrator(
                    PostgresIdentityStore(connection),
                    display_name="Administrador local",
                    pepper=identity.pepper_bytes(),
                )
                connection.execute(
                    "INSERT INTO audit_events(entity_id,actor,action) VALUES (%s,%s,%s)",
                    (
                        issued.subject_id,
                        f"subject:{issued.subject_id}",
                        "identity.initial_provisioned",
                    ),
                )
                file.write(issued.reveal_token() + "\n")
                file.flush()
                os.fsync(file.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    print(f"Administrator credential created in {destination.resolve()}. No secret was printed.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    provision(parser.parse_args().destination)
