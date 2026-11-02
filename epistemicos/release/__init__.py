"""
EpistemicOS Change & Release Governance Subsystem.

Provides deterministic release manifest generation, evidence binding,
change-impact analysis, evidence invalidation, authoritative revocation,
and Ed25519 asymmetric release approval verification.
"""

from epistemicos.release.models import (
    ComponentSpec,
    ComponentType,
    EvidenceVerificationStatus,
    ReleaseApprovalRecord,
    ReleaseManifest,
    VerificationEvidenceRecord,
    validate_sha256_hex,
)
from epistemicos.release.invalidation import (
    ChangeCategory,
    ChangeImpactReport,
    ComponentDelta,
    EvidenceInvalidator,
)
from epistemicos.release.revocation import (
    ReleaseApprovalRevocationRegistry,
    RevocationRecord,
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
    "validate_sha256_hex",
    "ChangeCategory",
    "ChangeImpactReport",
    "ComponentDelta",
    "EvidenceInvalidator",
    "ReleaseApprovalRevocationRegistry",
    "RevocationRecord",
    "ReleaseGovernanceEngine",
]
