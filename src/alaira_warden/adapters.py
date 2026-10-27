"""Credential-aware adapter stubs. None of these perform network calls."""

from alaira_warden.config import Settings
from alaira_warden.integrations import AdapterSpec, catalog, secret_present


class AdapterNotImplemented(RuntimeError):
    """Raised when a connector is configured or not, but has no implementation."""


def spec(adapter_id: str) -> AdapterSpec:
    for item in catalog():
        if item.id == adapter_id:
            return item
    raise KeyError(f"Unknown adapter: {adapter_id}")


def invoke(settings: Settings, adapter_id: str) -> None:
    item = spec(adapter_id)
    if item.secret_env and not secret_present(settings, item):
        raise AdapterNotImplemented(
            f"{item.name} is not implemented and has no value in {item.secret_env}."
        )
    raise AdapterNotImplemented(
        f"{item.name} is not implemented. A configured secret does not enable it."
    )
