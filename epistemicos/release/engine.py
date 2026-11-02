"""
Release Governance Engine.

Coordinates manifest evaluation, evidence verification, release approval verification,
authoritative revocation checking, and fail-closed audit trail integration.
"""

import base64
import hashlib
import time
import uuid
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


class ReleaseGovernanceEngine:
    """
    Subsystem responsible for Change & Release Governance:
    - Registers and hashes Release Manifests.
    - Associates and validates Verification Evidence (both record integrity and artifact byte authenticity).
    - Verifies evaluator signatures against trusted identity providers.
    - Evaluates Release Candidates against required evidence.
    - Verifies Release Approvals against exact manifest digests using Ed25519 asymmetric verification.
    - Checks authoritative revocation registry (fail-closed against object mutation/resurrection).
    - Enforces policy version consistency between manifest and approval.
    - Emits tamper-evident audit events with fail-closed audit semantics option.
    """

    def __init__(
        self,
        principal_verifier: Optional[PrincipalVerifier] = None,
        audit_trail: Optional[TamperEvidentAuditTrail] = None,
        allowed_approver_principals: Optional[List[str]] = None,
        revocation_registry: Optional[ReleaseApprovalRevocationRegistry] = None,
        fail_closed_audit: bool = True
    ):
        self.principal_verifier = principal_verifier
        self.audit_trail = audit_trail
        self.allowed_approver_principals = set(allowed_approver_principals) if allowed_approver_principals is not None else None
        self.revocation_registry = revocation_registry or ReleaseApprovalRevocationRegistry()
        self.fail_closed_audit = fail_closed_audit

    def _log_event(self, level: AuditLogLevel, event_name: str, details: Dict[str, Any]):
        """Logs audit event. If fail_closed_audit=True, raises RuntimeError on write failure."""
        if self.audit_trail:
            try:
                self.audit_trail.record_event(
                    event_type=level,
                    gate_name="ReleaseGovernanceEngine",
                    reason=f"{event_name}: {details.get('reason', '')}",
                    metadata=details
                )
            except Exception as e:
                if self.fail_closed_audit:
                    raise RuntimeError(f"Audit log failure on mandatory event '{event_name}': {str(e)}") from e

    def evaluate_release_readiness(
        self,
        manifest: ReleaseManifest,
        evidence_records: List[VerificationEvidenceRecord],
        artifact_bytes_provider: Optional[Callable[[str], Optional[bytes]]] = None
    ) -> Tuple[bool, str, List[str]]:
        """
        Evaluates whether a release manifest has all required verification evidence satisfied.

        Security Validations:
        1. Evidence must be bound to this exact manifest digest.
        2. Evidence status must be PASS.
        3. If artifact bytes are provided or retrievable, verify SHA-256(bytes) == ev.artifact_digest.
        4. If evaluator signature is present, verify it against PrincipalVerifier.
        5. Fails closed on missing required evidence types.

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
                    f"Evidence '{ev.evidence_id}' has non-passing status '{ev.status.value}'"
                )
                continue

            # Check 3: Validate artifact bytes if provider is supplied
            if artifact_bytes_provider:
                art_bytes = artifact_bytes_provider(ev.evidence_id)
                if art_bytes is not None:
                    computed_art_digest = hashlib.sha256(art_bytes).hexdigest()
                    if computed_art_digest.lower() != ev.artifact_digest.lower():
                        rejected_reasons.append(
                            f"Evidence '{ev.evidence_id}' artifact byte digest mismatch: computed '{computed_art_digest[:12]}...', declared '{ev.artifact_digest[:12]}...'"
                        )
                        continue

            # Check 4: Validate evaluator signature if signature or evaluator_issuer is present
            if ev.signature or ev.evaluator_issuer:
                if not ev.signature:
                    rejected_reasons.append(f"Evidence '{ev.evidence_id}' declares evaluator_issuer but has no signature")
                    continue
                if not self.principal_verifier:
                    rejected_reasons.append(f"Evidence '{ev.evidence_id}' has evaluator signature but engine has no PrincipalVerifier")
                    continue
                if not ev.evaluator_issuer:
                    rejected_reasons.append(f"Evidence '{ev.evidence_id}' has signature but missing evaluator_issuer")
                    continue

                trusted_pubkeys = getattr(self.principal_verifier, "_trusted_public_keys", {})
                trusted_pubkey = trusted_pubkeys.get(ev.evaluator_issuer)
                if not trusted_pubkey:
                    rejected_reasons.append(f"Evidence '{ev.evidence_id}' untrusted evaluator issuer '{ev.evaluator_issuer}'")
                    continue

                try:
                    sig_bytes = bytes.fromhex(ev.signature) if len(ev.signature) == 128 else base64.b64decode(ev.signature)
                except Exception:
                    rejected_reasons.append(f"Evidence '{ev.evidence_id}' malformed signature encoding")
                    continue

                payload = ev.compute_signature_payload()
                if not verify_ed25519_signature(sig_bytes, payload, trusted_pubkey):
                    rejected_reasons.append(f"Evidence '{ev.evidence_id}' cryptographic evaluator signature verification failed")
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
        verified_evidence_records: Optional[List[VerificationEvidenceRecord]] = None,
        current_time: Optional[float] = None
    ) -> Tuple[bool, str]:
        """
        Verifies that a ReleaseApprovalRecord authoritatively authorizes the given ReleaseManifest.

        Strictly enforces:
        1. Exact manifest digest matching.
        2. Authoritative revocation check in ReleaseApprovalRevocationRegistry.
        3. Expiration state.
        4. Approver principal authorization.
        5. Policy version binding between approval and manifest.
        6. Approval evidence digest correspondence against verified evidence records.
        7. Asymmetric Ed25519 signature verification via PrincipalVerifier.
        8. Mandatory fail-closed audit event recording.
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

        # Check 2: Authoritative Revocation Registry check
        if self.revocation_registry.is_revoked(approval.approval_id):
            rev_rec = self.revocation_registry.get_revocation_record(approval.approval_id)
            reason = f"Release approval rejected: Approval '{approval.approval_id}' has been authoritatively revoked ({rev_rec.reason if rev_rec else 'No reason provided'})"
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
            return False, reason

        # Check 5: Authorized approver principal allowlist
        if self.allowed_approver_principals is not None:
            if approval.approver_id not in self.allowed_approver_principals:
                reason = f"Release approval rejected: Approver '{approval.approver_id}' is not in allowed approvers allowlist"
                self._log_event(AuditLogLevel.HALT, "UNAUTHORIZED_APPROVER", {
                    "reason": reason,
                    "approver_id": approval.approver_id
                })
                return False, reason

        # Check 6: Evidence correspondence
        if verified_evidence_records is not None:
            available_digests = {ev.compute_evidence_digest().lower() for ev in verified_evidence_records}
            approval_digests = {d.lower() for d in approval.required_evidence_digests}
            missing_in_records = approval_digests - available_digests
            if missing_in_records:
                reason = f"Release approval rejected: Approval references evidence digests not present in verified evidence records: {sorted(list(missing_in_records))}"
                self._log_event(AuditLogLevel.HALT, "APPROVAL_EVIDENCE_UNRESOLVED", {
                    "reason": reason,
                    "missing_evidence_digests": sorted(list(missing_in_records))
                })
                return False, reason

        # Check 7: Asymmetric Ed25519 cryptographic signature verification
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

        try:
            sig_bytes = bytes.fromhex(approval.signature) if len(approval.signature) == 128 else base64.b64decode(approval.signature)
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

    def revoke_release_approval(
        self,
        approval_id: str,
        revoked_by_principal: str,
        reason: str = ""
    ):
        """Authoritatively revokes an approval ID in the revocation registry."""
        rec = self.revocation_registry.revoke_approval(
            approval_id=approval_id,
            revoked_by_principal=revoked_by_principal,
            reason=reason
        )
        self._log_event(AuditLogLevel.HALT, "RELEASE_APPROVAL_REVOKED", {
            "reason": reason,
            "approval_id": approval_id,
            "revoked_by": revoked_by_principal
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
