"""Trusted worker API for isolated npm remediation; no public tool configuration."""

from alaira_warden.remediation.pipeline import RemediationRequest, remediate, verify_artifact

__all__ = ["RemediationRequest", "remediate", "verify_artifact"]
