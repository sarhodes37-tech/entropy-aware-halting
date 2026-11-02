"""
Release Governance Engine.

Coordinates manifest evaluation, evidence verification, release approval verification,
and audit trail integration.
"""

import time
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

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


class ReleaseGovernanceEngine:
    """
    Subsystem responsible for Change & Release Governance:
    - Registers and hashes Release Manifests.
    - Associates and validates Verification Evidence.
    - Evaluates Release Candidates against required evidence.
    - Verifies Release Approvals against exact manifest digests using Ed25519 asymmetric verification.
    - Emits tamper-evident audit events for manifest creation, approval, and rejection.
    """

    def __init__(
        self,
        principal_verifier: Optional[PrincipalVerifier] = None,
        audit_trail: Optional[TamperEvidentAuditTrail] = None,
        allowed_approver_principals: Optional[List[str]] = None
    ):
        self.principal_verifier = principal_verifier
        self.audit_trail = audit_trail
        self.allowed_approver_principals = set(allowed_approver_principals) if allowed_approver_principals is not None else None

    def _log_event(self, level: AuditLogLevel, event_name: str, details: Dict[str, Any]):
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

    def evaluate_release_readiness(
        self,
        manifest: ReleaseManifest,
        evidence_records: List[VerificationEvidenceRecord]
    ) -> Tuple[bool, str, List[str]]:
        """
        Evaluates whether a release manifest has all required verification evidence satisfied.
        Returns: (is_ready, reason, list_of_accepted_evidence_digests)
        """
        manifest_digest = manifest.compute_manifest_digest()
        required_types = set(manifest.required_evidence_types)

        accepted_digests: List[str] = []
        satisfied_types = set()
        rejected_reasons = []

        for ev in evidence_records:
            # Check 1: Must be directly bound to this exact manifest digest
            if ev.manifest_digest.lower() != manifest_digest.lower():
                rejected_reasons.append(
                    f"Evidence '{ev.evidence_id}' bound to foreign manifest digest '{ev.manifest_digest[:12]}...', expected '{manifest_digest[:12]}...'"
                )
                continue

            # Check 2: Must have status PASS
            if ev.status != EvidenceVerificationStatus.PASS:
                rejected_reasons.append(
                    f"Evidence '{ev.evidence_id}' has failing status '{ev.status.value}'"
                )
                continue

            satisfied_types.add(ev.evidence_type)
            accepted_digests.append(ev.compute_evidence_digest())

        missing = required_types - satisfied_types
        if missing:
            msg = f"Release candidate missing required verification evidence: {sorted(list(missing))}"
            if rejected_reasons:
                msg += f" (Rejected records: {'; '.join(rejected_reasons)})"
            return False, msg, []

        return True, "All required verification evidence satisfied and bound to manifest", accepted_digests

    def verify_release_approval(
        self,
        manifest: ReleaseManifest,
        approval: ReleaseApprovalRecord,
        current_time: Optional[float] = None
    ) -> Tuple[bool, str]:
        """
        Verifies that a ReleaseApprovalRecord authoritatively authorizes the given ReleaseManifest.
        Strictly enforces:
        1. Exact manifest digest matching.
        2. Revocation state.
        3. Expiration state.
        4. Approver principal authorization.
        5. Asymmetric Ed25519 signature verification via PrincipalVerifier.
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
            return False, reason

        # Check 2: Revocation
        if approval.revoked:
            reason = f"Release approval rejected: Approval '{approval.approval_id}' has been revoked ({approval.revocation_reason or 'No reason provided'})"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_REVOKED", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return False, reason

        # Check 3: Expiration
        if approval.is_expired(current_time=current_time):
            reason = f"Release approval rejected: Approval '{approval.approval_id}' has expired"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_EXPIRED", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return False, reason

        # Check 4: Authorized approver principal allowlist
        if self.allowed_approver_principals is not None:
            if approval.approver_id not in self.allowed_approver_principals:
                reason = f"Release approval rejected: Approver '{approval.approver_id}' is not in allowed approvers allowlist"
                self._log_event(AuditLogLevel.HALT, "UNAUTHORIZED_APPROVER", {
                    "reason": reason,
                    "approver_id": approval.approver_id
                })
                return False, reason

        # Check 5: Asymmetric Ed25519 cryptographic signature verification
        if not approval.signature or not isinstance(approval.signature, str):
            reason = f"Release approval rejected: Missing or invalid signature on approval '{approval.approval_id}'"
            return False, reason

        if not self.principal_verifier:
            reason = "Release approval rejected: ReleaseGovernanceEngine has no configured PrincipalVerifier to verify signature"
            return False, reason

        # Check if issuer is trusted by verifier
        trusted_pubkeys = getattr(self.principal_verifier, "_trusted_public_keys", {})
        trusted_pubkey = trusted_pubkeys.get(approval.approver_issuer)
        if not trusted_pubkey:
            reason = f"Release approval rejected: Untrusted identity issuer '{approval.approver_issuer}' on approval"
            return False, reason

        # Decode signature
        import base64
        try:
            sig_bytes = bytes.fromhex(approval.signature)
            if len(sig_bytes) != 64:
                sig_bytes = base64.b64decode(approval.signature)
        except Exception:
            try:
                sig_bytes = base64.b64decode(approval.signature)
            except Exception:
                return False, "Release approval rejected: Malformed signature encoding"

        if len(sig_bytes) != 64:
            return False, f"Release approval rejected: Signature length invalid ({len(sig_bytes)} bytes, expected 64)"

        payload_bytes = approval.compute_signature_payload()
        if not verify_ed25519_signature(sig_bytes, payload_bytes, trusted_pubkey):
            reason = "Release approval rejected: Cryptographic Ed25519 signature verification failed"
            self._log_event(AuditLogLevel.HALT, "APPROVAL_SIGNATURE_INVALID", {
                "reason": reason,
                "approval_id": approval.approval_id
            })
            return False, reason

        self._log_event(AuditLogLevel.INFO, "RELEASE_APPROVAL_VERIFIED", {
            "reason": f"Approval '{approval.approval_id}' verified for release manifest '{manifest.release_id}'",
            "manifest_digest": manifest_digest,
            "approver_id": approval.approver_id
        })
        return True, "Release approval successfully verified for candidate manifest"

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
