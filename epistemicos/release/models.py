"""
Data models and canonical serialization for EpistemicOS Change & Release Governance.

This module defines deterministic, verifiable data structures representing:
- Component specifications and release manifests
- Verification evidence references
- Cryptographically signed release approval records
"""

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

SHA256_HEX_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_TIMESTAMP_MAGNITUDE = float((1 << 63) - 1)


def validate_sha256_hex(val: str, field_name: str) -> str:
    """Strictly validates that a digest is a 64-character hexadecimal SHA-256 string."""
    if not val or not isinstance(val, str) or not SHA256_HEX_REGEX.match(val):
        raise ValueError(f"{field_name} must be a valid 64-character hexadecimal SHA-256 digest, got '{val}'")
    return val.strip().lower()


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
        validate_sha256_hex(self.digest, "ComponentSpec.digest")
        if self.config_digest:
            validate_sha256_hex(self.config_digest, "ComponentSpec.config_digest")

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

        if self.policy_digest:
            validate_sha256_hex(self.policy_digest, "ReleaseManifest.policy_digest")

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
    evaluator_issuer: Optional[str] = None  # Issuer for asymmetric evaluator signature verification
    evaluated_at_utc: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None  # Asymmetric Ed25519 signature from evaluator

    def __post_init__(self):
        if not self.evidence_id or not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
            raise ValueError("VerificationEvidenceRecord: evidence_id must be a non-empty string")
        validate_sha256_hex(self.manifest_digest, "VerificationEvidenceRecord.manifest_digest")
        if not self.evidence_type or not isinstance(self.evidence_type, str) or not self.evidence_type.strip():
            raise ValueError("VerificationEvidenceRecord: evidence_type must be a non-empty string")
        validate_sha256_hex(self.artifact_digest, "VerificationEvidenceRecord.artifact_digest")
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
            "evaluator_issuer": self.evaluator_issuer.strip() if self.evaluator_issuer else None,
            "evaluated_at_utc": self.evaluated_at_utc,
            "metadata": self.metadata,
        }

    def compute_evidence_digest(self) -> str:
        serialized = json.dumps(self.to_canonical_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def compute_signature_payload(self) -> bytes:
        """
        Domain-separated JSON canonical binary payload for evaluator signature.
        Binds ALL security-relevant evidence fields:
        - evidence_id
        - manifest_digest
        - evidence_type
        - status
        - artifact_digest
        - evaluator_id
        - evaluator_issuer
        - evaluated_at_utc
        - evaluated_component_ids (sorted)
        - metadata
        """
        data = {
            "domain": "EpistemicOS:VerificationEvidenceRecord:v1",
            "evidence_id": self.evidence_id.strip(),
            "manifest_digest": self.manifest_digest.strip().lower(),
            "evidence_type": self.evidence_type.strip(),
            "status": self.status.value,
            "artifact_digest": self.artifact_digest.strip().lower(),
            "evaluator_id": self.evaluator_id.strip(),
            "evaluator_issuer": self.evaluator_issuer.strip() if self.evaluator_issuer else None,
            "evaluated_at_utc": self.evaluated_at_utc or "",
            "evaluated_component_ids": sorted(list(self.evaluated_component_ids)),
            "metadata": self.metadata,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

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

    def __post_init__(self):
        if not self.approval_id or not isinstance(self.approval_id, str) or not self.approval_id.strip():
            raise ValueError("ReleaseApprovalRecord: approval_id must be a non-empty string")
        validate_sha256_hex(self.manifest_digest, "ReleaseApprovalRecord.manifest_digest")
        if not self.approver_id or not isinstance(self.approver_id, str) or not self.approver_id.strip():
            raise ValueError("ReleaseApprovalRecord: approver_id must be a non-empty string")
        if not self.approver_issuer or not isinstance(self.approver_issuer, str) or not self.approver_issuer.strip():
            raise ValueError("ReleaseApprovalRecord: approver_issuer must be a non-empty string")
        if not self.policy_version or not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise ValueError("ReleaseApprovalRecord: policy_version must be a non-empty string")
        for ev_dig in self.required_evidence_digests:
            validate_sha256_hex(ev_dig, "ReleaseApprovalRecord.required_evidence_digests[]")

        self._validate_timestamps()

    def _validate_timestamps(self) -> None:
        """Strictly validates timestamp and expires_at against type ambiguity and overflow."""
        # Validate timestamp field
        if isinstance(self.timestamp, bool) or not isinstance(self.timestamp, (int, float)):
            raise TypeError(
                f"ReleaseApprovalRecord: timestamp must be a numeric timestamp, got {type(self.timestamp).__name__}"
            )
        if isinstance(self.timestamp, int):
            if self.timestamp.bit_length() > 64:
                raise ValueError("ReleaseApprovalRecord: timestamp integer overflows 64-bit limits")
        else:
            if not math.isfinite(self.timestamp):
                raise ValueError(f"ReleaseApprovalRecord: timestamp must be a finite number, got {self.timestamp}")
            if abs(self.timestamp) > MAX_TIMESTAMP_MAGNITUDE:
                raise ValueError("ReleaseApprovalRecord: timestamp float overflows magnitude limits")

        # Validate expires_at field if present
        if self.expires_at is not None:
            if isinstance(self.expires_at, bool) or not isinstance(self.expires_at, (int, float)):
                raise TypeError(
                    f"ReleaseApprovalRecord: expires_at must be a numeric timestamp, got {type(self.expires_at).__name__}"
                )
            if isinstance(self.expires_at, int):
                if self.expires_at.bit_length() > 64:
                    raise ValueError("ReleaseApprovalRecord: expires_at integer overflows 64-bit limits")
            else:
                if not math.isfinite(self.expires_at):
                    raise ValueError(f"ReleaseApprovalRecord: expires_at must be a finite number, got {self.expires_at}")
                if abs(self.expires_at) > MAX_TIMESTAMP_MAGNITUDE:
                    raise ValueError("ReleaseApprovalRecord: expires_at float overflows magnitude limits")

    def compute_signature_payload(self) -> bytes:
        """
        Deterministic, domain-separated canonical structured JSON payload for Ed25519 verification.
        Eliminates delimiter injection vulnerabilities.
        """
        self._validate_timestamps()
        data = {
            "domain": "EpistemicOS:ReleaseApprovalRecord:v1",
            "approval_id": self.approval_id.strip(),
            "manifest_digest": self.manifest_digest.strip().lower(),
            "approver_id": self.approver_id.strip(),
            "approver_issuer": self.approver_issuer.strip(),
            "policy_version": self.policy_version.strip(),
            "required_evidence_digests": sorted([d.strip().lower() for d in self.required_evidence_digests]),
            "timestamp": f"{self.timestamp:.6f}",
            "expires_at": f"{self.expires_at:.6f}" if self.expires_at is not None else None,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        if current_time is not None:
            if isinstance(current_time, bool) or not isinstance(current_time, (int, float)):
                return True
            if isinstance(current_time, int):
                if current_time.bit_length() > 64:
                    return True
                now: Union[int, float] = current_time
            else:
                if not math.isfinite(current_time) or abs(current_time) > MAX_TIMESTAMP_MAGNITUDE:
                    return True
                now = current_time
        else:
            now = time.time()
        return now >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
