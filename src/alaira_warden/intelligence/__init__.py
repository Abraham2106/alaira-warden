"""Intelligence sources for ALAIRA Warden.

Public clients return ``SourceBatch`` values. They do not correlate packages,
open a database, or download reference URLs.
"""

from alaira_warden.intelligence.errors import SourceError
from alaira_warden.intelligence.github import fetch_github_advisories, fetch_github_advisory
from alaira_warden.intelligence.grouping import group_advisories
from alaira_warden.intelligence.hashing import content_hash
from alaira_warden.intelligence.http import UrllibTransport, WorkBudget
from alaira_warden.intelligence.intake import (
    consultation_report,
    default_sync_plan,
    manual_advisory,
    resume,
)
from alaira_warden.intelligence.kev import fetch_kev_catalog, index_kev, lookup_kev
from alaira_warden.intelligence.models import (
    AdvisoryGroup,
    AffectedEntry,
    Attribution,
    ConsultationReport,
    GroupingResult,
    IdentifierLink,
    KevLookup,
    KnownExploited,
    Severity,
    SourceBatch,
    SourceRecord,
    SyncPlan,
)
from alaira_warden.intelligence.nvd import fetch_nvd_cve, fetch_nvd_modified
from alaira_warden.intelligence.osv import fetch_osv_vulnerability, query_osv, query_osv_batch
from alaira_warden.intelligence.persist import PersistResult, persist_records

__all__ = [
    "AdvisoryGroup",
    "AffectedEntry",
    "Attribution",
    "ConsultationReport",
    "GroupingResult",
    "IdentifierLink",
    "KevLookup",
    "KnownExploited",
    "PersistResult",
    "Severity",
    "SourceBatch",
    "SourceError",
    "SourceRecord",
    "SyncPlan",
    "UrllibTransport",
    "WorkBudget",
    "consultation_report",
    "content_hash",
    "default_sync_plan",
    "fetch_github_advisories",
    "fetch_github_advisory",
    "fetch_kev_catalog",
    "fetch_nvd_cve",
    "fetch_nvd_modified",
    "fetch_osv_vulnerability",
    "group_advisories",
    "index_kev",
    "lookup_kev",
    "manual_advisory",
    "persist_records",
    "query_osv",
    "query_osv_batch",
    "resume",
]
