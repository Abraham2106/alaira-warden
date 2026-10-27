"""Meterless H-MEM engine, ported from the official Apache-2.0 reference."""

from alaira_warden.hmem.conformance import scorecard
from alaira_warden.hmem.engine import HMEM
from alaira_warden.hmem.memory_mining import parse_strict_json_array
from alaira_warden.hmem.product import InvestigationMemory
from alaira_warden.hmem.types import DEFAULTS, FEEDBACK_DELTAS, clamp01

__all__ = [
    "DEFAULTS",
    "FEEDBACK_DELTAS",
    "HMEM",
    "InvestigationMemory",
    "clamp01",
    "parse_strict_json_array",
    "scorecard",
]
