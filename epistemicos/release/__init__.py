"""
EpistemicOS Change & Release Governance Subsystem.

Provides deterministic release manifest generation, evidence binding,
change-impact analysis, evidence invalidation, and Ed25519 asymmetric
release approval verification.
"""

from epistemicos.release.models import (
    ComponentSpec,
    ComponentType,
    EvidenceVerificationStatus,
    ReleaseApprovalRecord,
    ReleaseManifest,
    VerificationEvidenceRecord,
)
from epistemicos.release.invalidation import (
    ChangeCategory,
    ChangeImpactReport,
    ComponentDelta,
    EvidenceInvalidator,
)
from epistemicos.release.engine import (
    ReleaseGovernanceEngine,
)

__all__ = [
    "ComponentSpec",
    "ComponentType",
    "EvidenceVerificationStatus",
    "ReleaseApprovalRecord",
    "ReleaseManifest",
    "VerificationEvidenceRecord",
    "ChangeCategory",
    "ChangeImpactReport",
    "ComponentDelta",
    "EvidenceInvalidator",
    "ReleaseGovernanceEngine",
]
