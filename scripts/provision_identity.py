"""Host convenience wrapper for one-time identity provisioning."""

from pathlib import Path

from alaira_warden.identity.bootstrap import provision

if __name__ == "__main__":
    provision(Path("artifacts/private/administrator.token"))
