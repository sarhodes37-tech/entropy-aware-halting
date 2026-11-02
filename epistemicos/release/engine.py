"""
Release Governance Engine.

Coordinates manifest evaluation, evidence verification, release approval verification,
authoritative revocation checking, and fail-closed audit trail integration.
"""

import base64
import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel
from epistemicos.authorization import (
    AuthenticatedPrincipal,
    PrincipalVerifier,
    verify_ed25519_signature,
)
from epistemicos.release.models import (
    ReleaseManifest,
    VerificationEvidenceRecord,
    ReleaseApprovalRecord,
    EvidenceVerificationStatus,
)
from epistemicos.release.invalidation import EvidenceInvalidator, ChangeImpactReport
from epistemicos.release.revocation import ReleaseApprovalRevocationRegistry


class EvidenceValidationResultStatus(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    UNAVAILABLE = "UNAVAILABLE"


class AssuranceLevel(str, Enum):
    FULL_AUTHENTICATED = "FULL_AUTHENTICATED"
    REDUCED_ASSURANCE = "REDUCED_ASSURANCE"


@dataclass
class EvidenceValidationResult:
    """Explicit typed result of verifying an individual evidence record and its artifact bytes."""
    evidence_id: str
    status: EvidenceValidationResultStatus
    evidence_digest: Optional[str] = None
    reason: str = ""
    artifact_bytes_verified: bool = False
    evaluator_signature_verified: bool = False
    assurance_level: AssuranceLevel = AssuranceLevel.FULL_AUTHENTICATED


@dataclass
class ReleaseReadinessEvaluation:
    """Overall evaluation of a release candidate against required evidence."""
    is_ready: bool
    reason: str
    verified_evidence_records: List[VerificationEvidenceRecord] = field(default_factory=list)
    accepted_evidence_digests: List[str] = field(default_factory=list)
    validation_results: List[EvidenceValidationResult] = field(default_factory=list)
    effective_assurance_level: Optional[AssuranceLevel] = None


@dataclass
class ReleaseApprovalVerificationResult:
    """Explicit typed outcome of verifying a ReleaseApprovalRecord."""
    is_verified: bool
    reason: str
    effective_assurance_level: Optional[AssuranceLevel] = None
    verified_evidence_count: int = 0
    validation_results: List[EvidenceValidationResult] = field(default_factory=list)


class ReleaseGovernanceEngine:
    """
    Subsystem responsible for Change & Release Governance:
    - Registers and hashes Release Manifests.
    - Associates and validates Verification Evidence (both record integrity and artifact byte authenticity).
    - Verifies evaluator signatures against trusted identity providers (mandatory by default).
    - Evaluates Release Candidates against required evidence with explicit typed outcomes.
    - Verifies Release Approvals against exact manifest digests using Ed25519 asymmetric verification.
    - Propagates effective AssuranceLevel (FULL_AUTHENTICATED vs REDUCED_ASSURANCE) through public APIs.
    - Enforces required evidence completeness at both readiness and approval verification boundaries.
    - Checks authoritative revocation registry (fail-closed against object mutation/resurrection).
    - Enforces policy version consistency between manifest and approval.
    - Emits tamper-evident audit events with fail-closed audit semantics (mandating configured audit trail).
    """

    def __init__(
        self,
        principal_verifier: Optional[PrincipalVerifier] = None,
        audit_trail: Optional[TamperEvidentAuditTrail] = None,
        allowed_approver_principals: Optional[List[str]] = None,
        revocation_registry: Optional[ReleaseApprovalRevocationRegistry] = None,
        fail_closed_audit: bool = True,
        require_artifact_bytes_verification: bool = True,
        require_evaluator_signatures: bool = True
    ):
        self.principal_verifier = principal_verifier
        self.audit_trail = audit_trail
        self.allowed_approver_principals = set(allowed_approver_principals) if allowed_approver_principals is not None else None
        self.revocation_registry = revocation_registry or ReleaseApprovalRevocationRegistry()
        self.fail_closed_audit = fail_closed_audit
        self.require_artifact_bytes_verification = require_artifact_bytes_verification
        self.require_evaluator_signatures = require_evaluator_signatures

    def _log_event(self, level: AuditLogLevel, event_name: str, details: Dict[str, Any]):
        """Logs audit event. If fail_closed_audit=True, mandates audit_trail presence and raises RuntimeError on failure."""
        if self.fail_closed_audit:
            if not self.audit_trail:
                raise RuntimeError(f"Audit log failure on mandatory event '{event_name}': fail_closed_audit=True but no audit_trail configured")
            try:
                self.audit_trail.record_event(
                    event_type=level,
                    gate_name="ReleaseGovernanceEngine",
                    reason=f"{event_name}: {details.get('reason', '')}",
                    metadata=details
                )
            except Exception as e:
                raise RuntimeError(f"Audit log failure on mandatory event '{event_name}': {str(e)}") from e
        else:
            if self.audit_trail:
                try:
                    self.audit_trail.record_event(
                        event_type=level,
                        gate_name="ReleaseGovernanceEngine",
                        reason=f"{event_name}: {details.get('reason', '')}",
                        metadata=details
                    )
                except Exception:
                    pass

    def verify_single_evidence(
        self,
        manifest_digest: str,
        evidence: VerificationEvidenceRecord,
        artifact_bytes_provider: Optional[Callable[[str], Optional[bytes]]] = None
    ) -> EvidenceValidationResult:
        """
        Shared internal verification function for an individual evidence record.
        Ensures readiness evaluation and approval verification use identical trust rules.
        """
        ev_id = evidence.evidence_id

        # 1. Manifest digest binding
        if evidence.manifest_digest.lower() != manifest_digest.lower():
            return EvidenceValidationResult(
                evidence_id=ev_id,
                status=EvidenceValidationResultStatus.REJECTED,
                reason=f"Evidence '{ev_id}' bound to foreign manifest digest '{evidence.manifest_digest[:12]}...', expected '{manifest_digest[:12]}...'"
            )

        # 2. Status check (Must be PASS; reject FAIL, PARTIAL, INCONCLUSIVE)
        if evidence.status != EvidenceVerificationStatus.PASS:
            return EvidenceValidationResult(
                evidence_id=ev_id,
                status=EvidenceValidationResultStatus.REJECTED,
                reason=f"Evidence '{ev_id}' has non-passing status '{evidence.status.value}'"
            )

        # 3. Explicit artifact-byte verification
        artifact_verified = False
        if self.require_artifact_bytes_verification:
            if not artifact_bytes_provider:
                return EvidenceValidationResult(
                    evidence_id=ev_id,
                    status=EvidenceValidationResultStatus.UNAVAILABLE,
                    reason=f"Evidence '{ev_id}' artifact verification unavailable: no artifact_bytes_provider supplied"
                )
            art_bytes = artifact_bytes_provider(ev_id)
            if art_bytes is None:
                return EvidenceValidationResult(
                    evidence_id=ev_id,
                    status=EvidenceValidationResultStatus.UNAVAILABLE,
                    reason=f"Evidence '{ev_id}' artifact retrieval returned None: artifact not found or inaccessible"
                )
            computed_art_digest = hashlib.sha256(art_bytes).hexdigest()
            if computed_art_digest.lower() != evidence.artifact_digest.lower():
                return EvidenceValidationResult(
                    evidence_id=ev_id,
                    status=EvidenceValidationResultStatus.REJECTED,
                    reason=f"Evidence '{ev_id}' artifact byte digest mismatch: computed '{computed_art_digest[:12]}...', declared '{evidence.artifact_digest[:12]}...'"
                )
            artifact_verified = True
        else:
            if artifact_bytes_provider:
                art_bytes = artifact_bytes_provider(ev_id)
                if art_bytes is not None:
                    computed_art_digest = hashlib.sha256(art_bytes).hexdigest()
                    if computed_art_digest.lower() != evidence.artifact_digest.lower():
                        return EvidenceValidationResult(
                            evidence_id=ev_id,
                            status=EvidenceValidationResultStatus.REJECTED,
                            reason=f"Evidence '{ev_id}' artifact byte digest mismatch: computed '{computed_art_digest[:12]}...', declared '{evidence.artifact_digest[:12]}...'"
                        )
                    artifact_verified = True

        # 4. Evaluator signature verification
        eval_sig_verified = False
        if self.require_evaluator_signatures:
            if not evidence.signature and not evidence.evaluator_issuer:
                return EvidenceValidationResult(
                    evidence_id=ev_id,
                    status=EvidenceValidationResultStatus.REJECTED,
                    reason=f"Evidence '{ev_id}' rejected: evaluator signature and issuer are mandatory under default policy"
                )
            if not evidence.signature:
                return EvidenceValidationResult(
                    evidence_id=ev_id,
                    status=EvidenceValidationResultStatus.REJECTED,
                    reason=f"Evidence '{ev_id}' rejected: missing evaluator signature"
                )
            if not evidence.evaluator_issuer:
                return EvidenceValidationResult(
                    evidence_id=ev_id,
                    status=EvidenceValidationResultStatus.REJECTED,
                    reason=f"Evidence '{ev_id}' rejected: missing evaluator_issuer"
                )
            if not self.principal_verifier:
                return EvidenceValidationResult(
                    evidence_id=ev_id,
                    status=EvidenceValidationResultStatus.REJECTED,
                    reason=f"Evidence '{ev_id}' rejected: engine has no PrincipalVerifier to verify evaluator signature"
                )

            trusted_pubkeys = getattr(self.principal_verifier, "_trusted_public_keys", {})
            trusted_pubkey = trusted_pubkeys.get(evidence.evaluator_issuer)
            if not trusted_pubkey:
                return EvidenceValidationResult(
                    evidence_id=ev_id,
                    status=EvidenceValidationResultStatus.REJECTED,
                    reason=f"Evidence '{ev_id}' rejected: untrusted evaluator issuer '{evidence.evaluator_issuer}'"
                )

            try:
                sig_bytes = bytes.fromhex(evidence.signature) if len(evidence.signature) == 128 else base64.b64decode(evidence.signature)
            except Exception:
                return EvidenceValidationResult(
                    evidence_id=ev_id,
                    status=EvidenceValidationResultStatus.REJECTED,
                    reason=f"Evidence '{ev_id}' rejected: malformed signature encoding"
                )

            payload = evidence.compute_signature_payload()
            if not verify_ed25519_signature(sig_bytes, payload, trusted_pubkey):
                return EvidenceValidationResult(
                    evidence_id=ev_id,
                    status=EvidenceValidationResultStatus.REJECTED,
                    reason=f"Evidence '{ev_id}' rejected: cryptographic evaluator signature verification failed"
                )
            eval_sig_verified = True
        else:
            if evidence.signature or evidence.evaluator_issuer:
                if not evidence.signature:
                    return EvidenceValidationResult(
                        evidence_id=ev_id,
                        status=EvidenceValidationResultStatus.REJECTED,
                        reason=f"Evidence '{ev_id}' declares evaluator_issuer but has no signature"
                    )
                if not self.principal_verifier:
                    return EvidenceValidationResult(
                        evidence_id=ev_id,
                        status=EvidenceValidationResultStatus.REJECTED,
                        reason=f"Evidence '{ev_id}' has evaluator signature but engine has no PrincipalVerifier"
                    )
                if not evidence.evaluator_issuer:
                    return EvidenceValidationResult(
                        evidence_id=ev_id,
                        status=EvidenceValidationResultStatus.REJECTED,
                        reason=f"Evidence '{ev_id}' has signature but missing evaluator_issuer"
                    )

                trusted_pubkeys = getattr(self.principal_verifier, "_trusted_public_keys", {})
                trusted_pubkey = trusted_pubkeys.get(evidence.evaluator_issuer)
                if not trusted_pubkey:
                    return EvidenceValidationResult(
                        evidence_id=ev_id,
                        status=EvidenceValidationResultStatus.REJECTED,
                        reason=f"Evidence '{ev_id}' untrusted evaluator issuer '{evidence.evaluator_issuer}'"
                    )

                try:
                    sig_bytes = bytes.fromhex(evidence.signature) if len(evidence.signature) == 128 else base64.b64decode(evidence.signature)
                except Exception:
                    return EvidenceValidationResult(
                        evidence_id=ev_id,
                        status=EvidenceValidationResultStatus.REJECTED,
                        reason=f"Evidence '{ev_id}' malformed signature encoding"
                    )

                payload = evidence.compute_signature_payload()
                if not verify_ed25519_signature(sig_bytes, payload, trusted_pubkey):
                    return EvidenceValidationResult(
                        evidence_id=ev_id,
                        status=EvidenceValidationResultStatus.REJECTED,
                        reason=f"Evidence '{ev_id}' cryptographic evaluator signature verification failed"
                    )
                eval_sig_verified = True

        effective_level = (
            AssuranceLevel.FULL_AUTHENTICATED
            if (artifact_verified and eval_sig_verified)
            else AssuranceLevel.REDUCED_ASSURANCE
        )

        return EvidenceValidationResult(
            evidence_id=ev_id,
            status=EvidenceValidationResultStatus.VERIFIED,
            evidence_digest=evidence.compute_evidence_digest(),
            reason="Verified successfully",
            artifact_bytes_verified=artifact_verified,
            evaluator_signature_verified=eval_sig_verified,
            assurance_level=effective_level
        )

    def evaluate_release_readiness(
        self,
        manifest: ReleaseManifest,
        evidence_records: List[VerificationEvidenceRecord],
        artifact_bytes_provider: Optional[Callable[[str], Optional[bytes]]] = None
    ) -> ReleaseReadinessEvaluation:
        """
        Evaluates whether a release manifest has all required verification evidence satisfied.
        Returns a structured ReleaseReadinessEvaluation exposing effective assurance level.
        """
        manifest_digest = manifest.compute_manifest_digest()
        required_types = set(manifest.required_evidence_types)

        accepted_digests: List[str] = []
        satisfied_types = set()
        rejected_reasons = []
        validation_results: List[EvidenceValidationResult] = []
        verified_records: List[VerificationEvidenceRecord] = []

        all_full_authenticated = True

        for ev in evidence_records:
            res = self.verify_single_evidence(
                manifest_digest=manifest_digest,
                evidence=ev,
                artifact_bytes_provider=artifact_bytes_provider
            )
            validation_results.append(res)
            if res.status != EvidenceValidationResultStatus.VERIFIED:
                rejected_reasons.append(res.reason)
                continue

            satisfied_types.add(ev.evidence_type)
            accepted_digests.append(res.evidence_digest)
            verified_records.append(ev)

            if res.assurance_level != AssuranceLevel.FULL_AUTHENTICATED:
                all_full_authenticated = False

        missing = required_types - satisfied_types
        if missing:
            msg = f"Release candidate missing required verification evidence: {sorted(list(missing))}"
            if rejected_reasons:
                msg += f" (Rejected records: {'; '.join(rejected_reasons)})"
            return ReleaseReadinessEvaluation(
                is_ready=False,
                reason=msg,
                verified_evidence_records=verified_records,
                accepted_evidence_digests=accepted_digests,
                validation_results=validation_results,
                effective_assurance_level=None
            )

        overall_assurance = (
            AssuranceLevel.FULL_AUTHENTICATED
            if all_full_authenticated and len(verified_records) > 0
            else AssuranceLevel.REDUCED_ASSURANCE
        )

        return ReleaseReadinessEvaluation(
            is_ready=True,
            reason="All required verification evidence satisfied and bound to manifest",
            verified_evidence_records=verified_records,
            accepted_evidence_digests=accepted_digests,
            validation_results=validation_results,
            effective_assurance_level=overall_assurance
        )

    def verify_release_approval(
        self,
        manifest: ReleaseManifest,
        approval: ReleaseApprovalRecord,
        evidence_records: List[VerificationEvidenceRecord],
        artifact_bytes_provider: Optional[Callable[[str], Optional[bytes]]] = None,
        current_time: Optional[float] = None
    ) -> ReleaseApprovalVerificationResult:
        """
        Verifies that a ReleaseApprovalRecord authoritatively authorizes the given ReleaseManifest.
        Returns a structured ReleaseApprovalVerificationResult communicating effective assurance level.
        """
        manifest_digest = manifest.compute_manifest_digest()

        # Check 1: Manifest digest binding
        if approval.manifest_digest.lower() != manifest_digest.lower():
            reason = (
                f"Release approval rejected: Manifest digest mismatch. "
                f"Approval was issued for '{approval.manifest_digest[:16]}...', "
                f"candidate manifest has digest '{manifest_digest[:16]}...'"
            )
            self._log_event(AuditLogLevel.HALT, "APPROVAL_DIGEST_MISMATCH", {
                "reason": reason,
                "manifest_digest": manifest_digest,
                "approval_id": approval.approval_id
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        # Check 2: Authoritative Revocation Registry check
        if self.revocation_registry.is_revoked(approval.approval_id):
            rev_rec = self.revocation_registry.get_revocation_record(approval.approval_id)
            reason = f"Release approval rejected: Approval '{approval.approval_id}' has been authoritatively revoked ({rev_rec.reason if rev_rec else 'No reason provided'})"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_REVOKED", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        # Check 3: Expiration
        if approval.is_expired(current_time=current_time):
            reason = f"Release approval rejected: Approval '{approval.approval_id}' has expired"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_EXPIRED", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        # Check 4: Policy version consistency between approval and manifest
        if approval.policy_version.strip() != manifest.policy_version.strip():
            reason = (
                f"Release approval rejected: Policy version mismatch. "
                f"Approval policy version '{approval.policy_version}' != manifest policy version '{manifest.policy_version}'"
            )
            self._log_event(AuditLogLevel.HALT, "APPROVAL_POLICY_VERSION_MISMATCH", {
                "reason": reason,
                "approval_policy_version": approval.policy_version,
                "manifest_policy_version": manifest.policy_version
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        # Check 5: Authorized approver principal allowlist
        if self.allowed_approver_principals is not None:
            if approval.approver_id not in self.allowed_approver_principals:
                reason = f"Release approval rejected: Approver '{approval.approver_id}' is not in allowed approvers allowlist"
                self._log_event(AuditLogLevel.HALT, "UNAUTHORIZED_APPROVER", {
                    "reason": reason,
                    "approver_id": approval.approver_id
                })
                return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        # Check 6: Mandatory evidence record verification at approval boundary
        if not evidence_records or len(evidence_records) == 0:
            reason = "Release approval rejected: Mandatory evidence records missing at approval boundary"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_EVIDENCE_MISSING", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        verified_digests_map: Dict[str, Tuple[VerificationEvidenceRecord, EvidenceValidationResult]] = {}
        all_validation_results: List[EvidenceValidationResult] = []
        all_full_authenticated = True

        for ev in evidence_records:
            val_res = self.verify_single_evidence(
                manifest_digest=manifest_digest,
                evidence=ev,
                artifact_bytes_provider=artifact_bytes_provider
            )
            all_validation_results.append(val_res)
            if val_res.status != EvidenceValidationResultStatus.VERIFIED:
                reason = f"Release approval rejected: Evidence record '{ev.evidence_id}' failed verification: {val_res.reason}"
                self._log_event(AuditLogLevel.HALT, "APPROVAL_EVIDENCE_FAILED", {
                    "reason": reason,
                    "evidence_id": ev.evidence_id
                })
                return ReleaseApprovalVerificationResult(
                    is_verified=False,
                    reason=reason,
                    validation_results=all_validation_results
                )
            verified_digests_map[val_res.evidence_digest.lower()] = (ev, val_res)

        # Ensure all digests in approval.required_evidence_digests correspond to verified records
        approval_digests = {d.lower() for d in approval.required_evidence_digests}
        unresolved_digests = approval_digests - set(verified_digests_map.keys())
        if unresolved_digests:
            reason = f"Release approval rejected: Approval references evidence digests not present in verified records: {sorted(list(unresolved_digests))}"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_EVIDENCE_UNRESOLVED", {
                "reason": reason,
                "missing_evidence_digests": sorted(list(unresolved_digests))
            })
            return ReleaseApprovalVerificationResult(
                is_verified=False,
                reason=reason,
                validation_results=all_validation_results
            )

        # Check 7: Required evidence completeness at approval boundary
        referenced_verified_pairs = [
            verified_digests_map[d] for d in approval_digests if d in verified_digests_map
        ]
        referenced_types = {pair[0].evidence_type for pair in referenced_verified_pairs}
        missing_required_types = set(manifest.required_evidence_types) - referenced_types
        if missing_required_types:
            reason = f"Release approval rejected: Approval omits required evidence category(ies): {sorted(list(missing_required_types))}"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_REQUIRED_EVIDENCE_INCOMPLETE", {
                "reason": reason,
                "missing_required_evidence_types": sorted(list(missing_required_types))
            })
            return ReleaseApprovalVerificationResult(
                is_verified=False,
                reason=reason,
                validation_results=all_validation_results
            )

        # Calculate effective assurance level from all referenced verified evidence records
        for _, val_res in referenced_verified_pairs:
            if val_res.assurance_level != AssuranceLevel.FULL_AUTHENTICATED:
                all_full_authenticated = False

        effective_approval_assurance = (
            AssuranceLevel.FULL_AUTHENTICATED
            if all_full_authenticated and len(referenced_verified_pairs) > 0
            else AssuranceLevel.REDUCED_ASSURANCE
        )

        # Check 8: Asymmetric Ed25519 cryptographic signature verification
        if not approval.signature or not isinstance(approval.signature, str):
            reason = f"Release approval rejected: Missing or invalid signature on approval '{approval.approval_id}'"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_SIGNATURE_INVALID", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        if not self.principal_verifier:
            reason = "Release approval rejected: ReleaseGovernanceEngine has no configured PrincipalVerifier to verify signature"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_SIGNATURE_INVALID", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        trusted_pubkeys = getattr(self.principal_verifier, "_trusted_public_keys", {})
        trusted_pubkey = trusted_pubkeys.get(approval.approver_issuer)
        if not trusted_pubkey:
            reason = f"Release approval rejected: Untrusted identity issuer '{approval.approver_issuer}' on approval"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_SIGNATURE_INVALID", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        try:
            sig_bytes = bytes.fromhex(approval.signature) if len(approval.signature) == 128 else base64.b64decode(approval.signature)
        except Exception:
            reason = "Release approval rejected: Malformed signature encoding"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_SIGNATURE_INVALID", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        if len(sig_bytes) != 64:
            reason = f"Release approval rejected: Signature length invalid ({len(sig_bytes)} bytes, expected 64)"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_SIGNATURE_INVALID", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        payload_bytes = approval.compute_signature_payload()
        if not verify_ed25519_signature(sig_bytes, payload_bytes, trusted_pubkey):
            reason = "Release approval rejected: Cryptographic Ed25519 signature verification failed"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_SIGNATURE_INVALID", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return ReleaseApprovalVerificationResult(is_verified=False, reason=reason)

        self._log_event(AuditLogLevel.INFO, "RELEASE_APPROVAL_VERIFIED", {
            "reason": f"Approval '{approval.approval_id}' verified for release manifest '{manifest.release_id}'",
            "manifest_digest": manifest_digest,
            "approver_id": approval.approver_id,
            "assurance_level": effective_approval_assurance.value
        })
        return ReleaseApprovalVerificationResult(
            is_verified=True,
            reason="Release approval successfully verified for candidate manifest",
            effective_assurance_level=effective_approval_assurance,
            verified_evidence_count=len(referenced_verified_pairs),
            validation_results=all_validation_results
        )

    def revoke_release_approval(
        self,
        approval_id: str,
        revoked_by_principal: str,
        reason: str
    ):
        """Authoritatively revokes an approval ID in the revocation registry."""
        if not approval_id or not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("approval_id must be a non-empty string")
        if not revoked_by_principal or not isinstance(revoked_by_principal, str) or not revoked_by_principal.strip():
            raise ValueError("revoked_by_principal must be a non-empty string")
        if not reason or not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be a non-empty string")

        clean_id = approval_id.strip()
        clean_principal = revoked_by_principal.strip()
        clean_reason = reason.strip()

        rec = self.revocation_registry.revoke_approval(
            approval_id=clean_id,
            revoked_by_principal=clean_principal,
            reason=clean_reason
        )
        self._log_event(AuditLogLevel.HALT, "RELEASE_APPROVAL_REVOKED", {
            "reason": clean_reason,
            "approval_id": clean_id,
            "revoked_by": clean_principal
        })
        return rec

    def analyze_change_impact(
        self,
        old_manifest: ReleaseManifest,
        new_manifest: ReleaseManifest,
        available_evidence: List[VerificationEvidenceRecord]
    ) -> ChangeImpactReport:
        """Analyzes differences between two manifests and invalidates affected evidence."""
        return EvidenceInvalidator.analyze_change(
            old_manifest=old_manifest,
            new_manifest=new_manifest,
            available_evidence=available_evidence
        )
