"""
Data models and canonical serialization for EpistemicOS Change & Release Governance.

This module defines deterministic, verifiable data structures representing:
- Component specifications and release manifests
- Verification evidence references
- Cryptographically signed release approval records
"""

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ComponentType(str, Enum):
    MODEL = "model"
    RUNTIME = "runtime"
    DEPENDENCY = "dependency"
    POLICY = "policy"
    INFRASTRUCTURE = "infrastructure"
    DATASET = "dataset"
    TOOL = "tool"


class EvidenceVerificationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class ComponentSpec:
    """
    Deterministic specification of a deployable or configured component.
    All fields are included in the component identity digest.
    """
    component_id: str
    component_type: str
    version: str
    digest: str  # Hex-encoded SHA-256 digest of component artifact or configuration
    config_digest: Optional[str] = None  # Optional secondary configuration digest

    def __post_init__(self):
        if not self.component_id or not isinstance(self.component_id, str) or not self.component_id.strip():
            raise ValueError("ComponentSpec: component_id must be a non-empty string")
        if not self.component_type or not isinstance(self.component_type, str) or not self.component_type.strip():
            raise ValueError("ComponentSpec: component_type must be a non-empty string")
        if not self.version or not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("ComponentSpec: version must be a non-empty string")
        if not self.digest or not isinstance(self.digest, str) or not self.digest.strip():
            raise ValueError("ComponentSpec: digest must be a non-empty hex-digest string")

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id.strip(),
            "component_type": self.component_type.strip(),
            "version": self.version.strip(),
            "digest": self.digest.strip().lower(),
            "config_digest": self.config_digest.strip().lower() if self.config_digest else None,
        }

    def compute_spec_digest(self) -> str:
        serialized = json.dumps(self.to_canonical_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass
class ReleaseManifest:
    """
    Deterministic, canonical representation of a deployable system release candidate.

    Distinction between Canonical Digest Fields and Informational Metadata:
    - Canonical Fields (included in manifest digest):
      * schema_version
      * release_id
      * target_environment
      * components (sorted deterministically by component_id)
      * runtime_identity
      * policy_version
      * policy_digest
      * required_evidence_types (sorted set)

    - Informational Metadata (EXCLUDED from canonical manifest digest):
      * created_at_utc
      * display_name
      * description
      * tags
      * notes
    """
    schema_version: str
    release_id: str
    target_environment: str
    components: List[ComponentSpec] = field(default_factory=list)
    runtime_identity: str = "epistemicos-core"
    policy_version: str = "1.0.0"
    policy_digest: Optional[str] = None
    required_evidence_types: Set[str] = field(default_factory=set)

    # Informational metadata (non-canonical, excluded from manifest digest)
    created_at_utc: Optional[str] = None
    display_name: Optional[str] = None
    description: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    notes: Optional[str] = None

    def __post_init__(self):
        if not self.schema_version or not isinstance(self.schema_version, str) or not self.schema_version.strip():
            raise ValueError("ReleaseManifest: schema_version must be a non-empty string")
        if not self.release_id or not isinstance(self.release_id, str) or not self.release_id.strip():
            raise ValueError("ReleaseManifest: release_id must be a non-empty string")
        if not self.target_environment or not isinstance(self.target_environment, str) or not self.target_environment.strip():
            raise ValueError("ReleaseManifest: target_environment must be a non-empty string")

        # Validate duplicate component IDs
        seen_ids = set()
        for comp in self.components:
            if not isinstance(comp, ComponentSpec):
                raise TypeError(f"ReleaseManifest: components must contain ComponentSpec instances, got {type(comp).__name__}")
            if comp.component_id in seen_ids:
                raise ValueError(f"ReleaseManifest: duplicate component_id '{comp.component_id}' detected")
            seen_ids.add(comp.component_id)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """
        Returns strictly the canonical fields included in the release manifest digest calculation.
        Informational metadata fields are strictly excluded.
        """
        # Sort components deterministically by component_id
        sorted_components = sorted(
            [c.to_canonical_dict() for c in self.components],
            key=lambda x: x["component_id"]
        )
        sorted_evidence_types = sorted(list(self.required_evidence_types))

        return {
            "schema_version": self.schema_version.strip(),
            "release_id": self.release_id.strip(),
            "target_environment": self.target_environment.strip(),
            "runtime_identity": self.runtime_identity.strip(),
            "policy_version": self.policy_version.strip(),
            "policy_digest": self.policy_digest.strip().lower() if self.policy_digest else None,
            "required_evidence_types": sorted_evidence_types,
            "components": sorted_components,
        }

    def compute_manifest_digest(self) -> str:
        """
        Computes SHA-256 digest over canonical JSON serialization.
        Separators (',', ':') eliminate whitespace ambiguity.
        """
        canonical_dict = self.to_canonical_dict()
        serialized = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def get_component(self, component_id: str) -> Optional[ComponentSpec]:
        for c in self.components:
            if c.component_id == component_id:
                return c
        return None


@dataclass
class VerificationEvidenceRecord:
    """
    Verification evidence bound to an exact release manifest digest and/or component scope.
    """
    evidence_id: str
    manifest_digest: str  # Digest of the manifest this evidence was evaluated against
    evidence_type: str    # e.g., "layer4_security_audit", "clinical_diagnostic_benchmark"
    status: EvidenceVerificationStatus
    artifact_digest: str  # SHA-256 digest of raw test report / benchmark artifact on disk
    evaluated_component_ids: Set[str] = field(default_factory=set)  # Components explicitly covered
    evaluator_id: str = "automated_benchmark_harness"
    evaluated_at_utc: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None  # Optional evaluator signature

    def __post_init__(self):
        if not self.evidence_id or not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
            raise ValueError("VerificationEvidenceRecord: evidence_id must be a non-empty string")
        if not self.manifest_digest or not isinstance(self.manifest_digest, str) or not self.manifest_digest.strip():
            raise ValueError("VerificationEvidenceRecord: manifest_digest must be a non-empty string")
        if not self.evidence_type or not isinstance(self.evidence_type, str) or not self.evidence_type.strip():
            raise ValueError("VerificationEvidenceRecord: evidence_type must be a non-empty string")
        if not self.artifact_digest or not isinstance(self.artifact_digest, str) or not self.artifact_digest.strip():
            raise ValueError("VerificationEvidenceRecord: artifact_digest must be a non-empty string")
        if isinstance(self.status, str):
            self.status = EvidenceVerificationStatus(self.status)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id.strip(),
            "manifest_digest": self.manifest_digest.strip().lower(),
            "evidence_type": self.evidence_type.strip(),
            "status": self.status.value,
            "artifact_digest": self.artifact_digest.strip().lower(),
            "evaluated_component_ids": sorted(list(self.evaluated_component_ids)),
            "evaluator_id": self.evaluator_id.strip(),
            "evaluated_at_utc": self.evaluated_at_utc,
            "metadata": self.metadata,
        }

    def compute_evidence_digest(self) -> str:
        serialized = json.dumps(self.to_canonical_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def is_valid_for_manifest(self, current_manifest_digest: str) -> bool:
        """Checks if evidence is directly bound to the exact manifest digest and is PASS."""
        return (
            self.manifest_digest.lower() == current_manifest_digest.lower() and
            self.status == EvidenceVerificationStatus.PASS
        )


@dataclass
class ReleaseApprovalRecord:
    """
    Asymmetrically or cryptographically verifiable release approval authorization object.
    Binds exact manifest digest, approver identity, approval policy, and evidence state.
    """
    approval_id: str
    manifest_digest: str
    approver_id: str
    approver_issuer: str
    policy_version: str
    required_evidence_digests: List[str]  # Digests of the evidence records accepted
    timestamp: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    signature: Optional[str] = None  # Ed25519 signature (hex or base64)
    revoked: bool = False
    revocation_reason: Optional[str] = None

    def __post_init__(self):
        if not self.approval_id or not isinstance(self.approval_id, str) or not self.approval_id.strip():
            raise ValueError("ReleaseApprovalRecord: approval_id must be a non-empty string")
        if not self.manifest_digest or not isinstance(self.manifest_digest, str) or not self.manifest_digest.strip():
            raise ValueError("ReleaseApprovalRecord: manifest_digest must be a non-empty string")
        if not self.approver_id or not isinstance(self.approver_id, str) or not self.approver_id.strip():
            raise ValueError("ReleaseApprovalRecord: approver_id must be a non-empty string")
        if not self.approver_issuer or not isinstance(self.approver_issuer, str) or not self.approver_issuer.strip():
            raise ValueError("ReleaseApprovalRecord: approver_issuer must be a non-empty string")
        if not self.policy_version or not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise ValueError("ReleaseApprovalRecord: policy_version must be a non-empty string")

    def compute_signature_payload(self) -> bytes:
        """
        Deterministic binary payload for asymmetric Ed25519 verification.
        Binds approval_id, manifest_digest, approver_id, approver_issuer,
        policy_version, sorted required_evidence_digests, timestamp, and expires_at.
        """
        exp_str = f"{self.expires_at:.6f}" if self.expires_at is not None else ""
        sorted_ev = ",".join(sorted(self.required_evidence_digests))
        payload = (
            f"{self.approval_id}:{self.manifest_digest.lower()}:{self.approver_id}:"
            f"{self.approver_issuer}:{self.policy_version}:{sorted_ev}:"
            f"{self.timestamp:.6f}:{exp_str}"
        )
        return payload.encode("utf-8")

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
