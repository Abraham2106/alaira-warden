"""npm inventory, Syft normalization and deployment import for ALAIRA Warden."""

from alaira_warden.inventory.deployments import (
    SCHEMA_VERSION,
    KnownSnapshot,
    append_deployments,
    parse_deployment_document,
)
from alaira_warden.inventory.errors import InventoryError
from alaira_warden.inventory.github_read import read_github_repository
from alaira_warden.inventory.limits import InventoryLimits
from alaira_warden.inventory.lockfile import SUPPORTED_LOCKFILE_VERSIONS, parse_npm_project
from alaira_warden.inventory.materialize import materialize_files
from alaira_warden.inventory.models import (
    AuthorizedApplication,
    Component,
    DeploymentRecord,
    InventoryAssessment,
    InventorySnapshot,
    InventoryWarning,
)
from alaira_warden.inventory.persist import (
    import_deployments,
    insert_deployment,
    insert_snapshot,
    retire_deployment,
)
from alaira_warden.inventory.quality import assess_snapshot, retain_snapshots
from alaira_warden.inventory.service import (
    registration_gaps,
    snapshot_from_github,
    snapshot_from_manifests,
)
from alaira_warden.inventory.syft import SYFT_VERSION, execute_syft

__all__ = [
    "SCHEMA_VERSION",
    "SUPPORTED_LOCKFILE_VERSIONS",
    "SYFT_VERSION",
    "AuthorizedApplication",
    "Component",
    "DeploymentRecord",
    "InventoryAssessment",
    "InventoryError",
    "InventoryLimits",
    "InventorySnapshot",
    "InventoryWarning",
    "KnownSnapshot",
    "append_deployments",
    "assess_snapshot",
    "execute_syft",
    "import_deployments",
    "insert_deployment",
    "insert_snapshot",
    "materialize_files",
    "parse_deployment_document",
    "parse_npm_project",
    "read_github_repository",
    "registration_gaps",
    "retain_snapshots",
    "retire_deployment",
    "snapshot_from_github",
    "snapshot_from_manifests",
]
