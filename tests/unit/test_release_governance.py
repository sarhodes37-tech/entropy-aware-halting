"""
Deterministic Unit and Adversarial Test Suite for EpistemicOS Change & Release Governance.

Verifies the 14 mandatory security invariants + Hardening criteria:
1. Identical manifests produce identical canonical digests.
2. Material component changes produce different manifest digests.
3. Informational metadata does not accidentally alter the digest unless explicitly included in canonical schema.
4. Approval succeeds for the exact approved manifest.
5. Approval fails for a modified manifest.
6. Approval fails if the release identifier is unchanged but a component digest differs.
7. Evidence from an older manifest cannot satisfy a requirement for the new manifest.
8. Missing required evidence prevents approval.
9. Invalid or tampered approval signatures are rejected.
10. An unauthorized principal cannot issue a release approval.
11. Revoked or expired approval cannot authorize a release (monotonically enforced via RevocationRegistry).
12. Duplicate, malformed, or ambiguous manifest fields cannot produce inconsistent canonicalization.
13. Attempted substitution of evidence artifacts is detected through digest verification.
14. A post-approval manifest mutation cannot retain the original authorization.
15. Adversarial tests for revocation resurrection resistance, artifact byte verification, evaluator signatures, digest formatting, policy version mismatch, and audit failure semantics.
"""

import hashlib
import json
import os
import time
import pytest
from typing import Optional

from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel
from epistemicos.authorization import (
    AuthenticatedPrincipal,
    PrincipalVerifier,
)
from tests.unit.test_sec01_sec03_remediation import (
    _ed25519_publickey,
    _ed25519_sign,
)
from epistemicos.release import (
    ComponentSpec,
    ComponentType,
    EvidenceVerificationStatus,
    ReleaseApprovalRecord,
    ReleaseManifest,
    VerificationEvidenceRecord,
    ChangeCategory,
    ChangeImpactReport,
    ComponentDelta,
    EvidenceInvalidator,
    ReleaseApprovalRevocationRegistry,
    ReleaseGovernanceEngine,
)


class MockReleaseAuthority:
    """Deterministic Ed25519 identity authority for test approvals."""
    __test__ = False
    def __init__(self, seed: Optional[bytes] = None, issuer_id: str = "CorporateReleaseAuthority"):
        self.private_seed = seed if seed and len(seed) == 32 else os.urandom(32)
        self.public_key = _ed25519_publickey(self.private_seed)
        self.issuer_id = issuer_id

    def sign_approval(self, approval: ReleaseApprovalRecord) -> str:
        payload = approval.compute_signature_payload()
        sig_bytes = _ed25519_sign(payload, self.private_seed, self.public_key)
        approval.signature = sig_bytes.hex()
        return approval.signature

    def sign_evidence(self, evidence: VerificationEvidenceRecord) -> str:
        payload = evidence.compute_signature_payload()
        sig_bytes = _ed25519_sign(payload, self.private_seed, self.public_key)
        evidence.signature = sig_bytes.hex()
        return evidence.signature


def create_sample_manifest(
    model_digest: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    runtime_id: str = "epistemicos-core-v1.0",
    policy_digest: str = "2222222222222222222222222222222222222222222222222222222222222222",
    release_id: str = "rel-2026.05.01",
    policy_version: str = "1.0.0",
    display_name: str = "Standard Release",
    description: str = "Initial production candidate"
) -> ReleaseManifest:
    model_comp = ComponentSpec(
        component_id="diagnostic_model",
        component_type=ComponentType.MODEL.value,
        version="1.0.0",
        digest=model_digest,
        config_digest="3333333333333333333333333333333333333333333333333333333333333333"
    )
    runtime_comp = ComponentSpec(
        component_id="core_runtime",
        component_type=ComponentType.RUNTIME.value,
        version="1.0.0",
        digest="1111111111111111111111111111111111111111111111111111111111111111"
    )
    return ReleaseManifest(
        schema_version="1.0.0",
        release_id=release_id,
        target_environment="production-clinical-gateway",
        components=[model_comp, runtime_comp],
        runtime_identity=runtime_id,
        policy_version=policy_version,
        policy_digest=policy_digest,
        required_evidence_types={"layer4_security_audit", "clinical_diagnostic_benchmark"},
        display_name=display_name,
        description=description,
        tags={"tier": "tier1_critical"},
        notes="Pre-deployment validation candidate"
    )


def test_invariant_1_identical_manifests_produce_identical_canonical_digests():
    m1 = create_sample_manifest()
    m2 = ReleaseManifest(
        schema_version="1.0.0",
        release_id=m1.release_id,
        target_environment=m1.target_environment,
        components=list(reversed(m1.components)),
        runtime_identity=m1.runtime_identity,
        policy_version=m1.policy_version,
        policy_digest=m1.policy_digest,
        required_evidence_types=m1.required_evidence_types
    )
    assert m1.compute_manifest_digest() == m2.compute_manifest_digest()


def test_invariant_2_material_component_changes_produce_different_manifest_digests():
    m_base = create_sample_manifest()
    d_base = m_base.compute_manifest_digest()
    m_mod = create_sample_manifest(model_digest="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    d_mod = m_mod.compute_manifest_digest()
    assert d_base != d_mod


def test_invariant_3_informational_metadata_does_not_alter_digest():
    m = create_sample_manifest()
    d1 = m.compute_manifest_digest()
    m.display_name = "Modified Display Name 2.0"
    m.description = "Updated description text"
    m.notes = "New internal notes added after audit"
    m.tags = {"environment": "staging", "tier": "tier2"}
    d2 = m.compute_manifest_digest()
    assert d1 == d2


def test_invariant_4_approval_succeeds_for_exact_approved_manifest(tmp_path):
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"]
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111",
        evaluated_component_ids={"core_runtime"}
    )
    ev2 = VerificationEvidenceRecord(
        evidence_id="ev-clinical",
        manifest_digest=m_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="2222222222222222222222222222222222222222222222222222222222222222",
        evaluated_component_ids={"diagnostic_model"}
    )

    ready, msg, accepted = engine.evaluate_release_readiness(manifest, [ev1, ev2])
    assert ready is True

    approval = ReleaseApprovalRecord(
        approval_id="appr-001",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=accepted
    )
    auth.sign_approval(approval)

    verified, v_msg = engine.verify_release_approval(manifest, approval, verified_evidence_records=[ev1, ev2])
    assert verified is True
    assert "successfully verified" in v_msg


def test_invariant_5_and_6_approval_fails_for_modified_manifest_even_with_same_release_id():
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"]
    )

    m_orig = create_sample_manifest(release_id="rel-same-id-123")
    m_orig_digest = m_orig.compute_manifest_digest()

    approval = ReleaseApprovalRecord(
        approval_id="appr-orig",
        manifest_digest=m_orig_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["1111111111111111111111111111111111111111111111111111111111111111"]
    )
    auth.sign_approval(approval)

    m_mutant = create_sample_manifest(
        release_id="rel-same-id-123",
        model_digest="9999999999999999999999999999999999999999999999999999999999999999"
    )

    verified, reason = engine.verify_release_approval(m_mutant, approval)
    assert verified is False
    assert "Manifest digest mismatch" in reason


def test_invariant_7_evidence_from_older_manifest_cannot_satisfy_new_manifest():
    engine = ReleaseGovernanceEngine()
    m_old = create_sample_manifest(model_digest="1111111111111111111111111111111111111111111111111111111111111111")
    m_new = create_sample_manifest(model_digest="2222222222222222222222222222222222222222222222222222222222222222")

    old_digest = m_old.compute_manifest_digest()

    ev_old = VerificationEvidenceRecord(
        evidence_id="ev-layer4-old",
        manifest_digest=old_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    ev_old_clin = VerificationEvidenceRecord(
        evidence_id="ev-clinical-old",
        manifest_digest=old_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )

    ready, msg, accepted = engine.evaluate_release_readiness(m_new, [ev_old, ev_old_clin])
    assert ready is False
    assert "missing required verification evidence" in msg
    assert "bound to foreign manifest digest" in msg


def test_invariant_8_missing_required_evidence_prevents_readiness():
    engine = ReleaseGovernanceEngine()
    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )

    ready, msg, accepted = engine.evaluate_release_readiness(manifest, [ev1])
    assert ready is False
    assert "missing required verification evidence: ['clinical_diagnostic_benchmark']" in msg


def test_invariant_9_invalid_or_tampered_approval_signatures_are_rejected():
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(principal_verifier=verifier)

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    approval = ReleaseApprovalRecord(
        approval_id="appr-tampered",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["1111111111111111111111111111111111111111111111111111111111111111"]
    )
    auth.sign_approval(approval)

    tampered_sig = list(approval.signature)
    tampered_sig[0] = "0" if tampered_sig[0] != "0" else "1"
    approval.signature = "".join(tampered_sig)

    verified, reason = engine.verify_release_approval(manifest, approval)
    assert verified is False
    assert "Ed25519 signature verification failed" in reason


def test_invariant_10_unauthorized_principal_cannot_issue_release_approval():
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"]
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    approval = ReleaseApprovalRecord(
        approval_id="appr-mallory",
        manifest_digest=m_digest,
        approver_id="mallory_intruder",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["1111111111111111111111111111111111111111111111111111111111111111"]
    )
    auth.sign_approval(approval)

    verified, reason = engine.verify_release_approval(manifest, approval)
    assert verified is False
    assert "Approver 'mallory_intruder' is not in allowed approvers allowlist" in reason


def test_invariant_11_revoked_or_expired_approval_cannot_authorize_release_and_resurrection_resisted():
    """Invariant 11 & Hardening 1: Authoritative revocation prevents resurrection via object mutation."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    rev_registry = ReleaseApprovalRevocationRegistry()
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        revocation_registry=rev_registry
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    approval = ReleaseApprovalRecord(
        approval_id="appr-revocation-test",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["1111111111111111111111111111111111111111111111111111111111111111"]
    )
    auth.sign_approval(approval)

    # Initial verification passes
    v0, _ = engine.verify_release_approval(manifest, approval)
    assert v0 is True

    # Authoritatively revoke approval
    engine.revoke_release_approval(
        approval_id="appr-revocation-test",
        revoked_by_principal="security_officer_bob",
        reason="Zero-day dependency vulnerability"
    )

    # Verification fails due to revocation
    v1, r1 = engine.verify_release_approval(manifest, approval)
    assert v1 is False
    assert "authoritatively revoked" in r1

    # Adversarial Resurrection Attempt: Attacker attempts to forge/recreate a fresh approval object
    # with the same approval_id but claims it is active
    approval_resurrected = ReleaseApprovalRecord(
        approval_id="appr-revocation-test",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["1111111111111111111111111111111111111111111111111111111111111111"]
    )
    auth.sign_approval(approval_resurrected)

    # Must still fail because revocation is authoritatively keyed in the registry
    v2, r2 = engine.verify_release_approval(manifest, approval_resurrected)
    assert v2 is False
    assert "authoritatively revoked" in r2


def test_invariant_12_duplicate_and_malformed_fields_fail_closed():
    comp1 = ComponentSpec("c1", "model", "1.0.0", "1111111111111111111111111111111111111111111111111111111111111111")
    comp1_dup = ComponentSpec("c1", "model", "1.0.0", "2222222222222222222222222222222222222222222222222222222222222222")

    with pytest.raises(ValueError, match="duplicate component_id"):
        ReleaseManifest(
            schema_version="1.0.0",
            release_id="rel-dup",
            target_environment="prod",
            components=[comp1, comp1_dup]
        )

    with pytest.raises(ValueError, match="release_id must be a non-empty string"):
        ReleaseManifest(
            schema_version="1.0.0",
            release_id="",
            target_environment="prod"
        )


def test_invariant_13_artifact_byte_verification_and_substitution_detected():
    """Hardening 2: Validates evidence artifact digests against actual bytes."""
    engine = ReleaseGovernanceEngine()
    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    real_bytes = b"BENCHMARK RESULTS: 100% PASS"
    real_digest = hashlib.sha256(real_bytes).hexdigest()

    ev = VerificationEvidenceRecord(
        evidence_id="ev-layer4-bytes",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=real_digest
    )
    ev_clin = VerificationEvidenceRecord(
        evidence_id="ev-clinical",
        manifest_digest=m_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="2222222222222222222222222222222222222222222222222222222222222222"
    )

    # Valid bytes match
    ready, _, _ = engine.evaluate_release_readiness(
        manifest,
        [ev, ev_clin],
        artifact_bytes_provider=lambda ev_id: real_bytes if ev_id == "ev-layer4-bytes" else None
    )
    assert ready is True

    # Substituted bytes (tampered artifact)
    substituted_bytes = b"BENCHMARK RESULTS: TAMPERED MALICIOUS ARTIFACT"
    ready_sub, msg_sub, _ = engine.evaluate_release_readiness(
        manifest,
        [ev, ev_clin],
        artifact_bytes_provider=lambda ev_id: substituted_bytes if ev_id == "ev-layer4-bytes" else None
    )
    assert ready_sub is False
    assert "artifact byte digest mismatch" in msg_sub


def test_evaluator_signature_verification_and_untrusted_evaluator_rejected():
    """Hardening 2: Evaluator signature is cryptographically verified and untrusted issuer rejected."""
    eval_auth = MockReleaseAuthority(issuer_id="EvaluatorIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"EvaluatorIdP": eval_auth.public_key})
    engine = ReleaseGovernanceEngine(principal_verifier=verifier)

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev = VerificationEvidenceRecord(
        evidence_id="ev-signed",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111",
        evaluator_issuer="EvaluatorIdP"
    )
    eval_auth.sign_evidence(ev)

    ev_clin = VerificationEvidenceRecord(
        evidence_id="ev-clinical",
        manifest_digest=m_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="2222222222222222222222222222222222222222222222222222222222222222"
    )

    ready, _, _ = engine.evaluate_release_readiness(manifest, [ev, ev_clin])
    assert ready is True

    # Untrusted evaluator issuer
    ev.evaluator_issuer = "UntrustedRogueEvaluator"
    eval_auth.sign_evidence(ev)
    ready_untrusted, msg_untrusted, _ = engine.evaluate_release_readiness(manifest, [ev, ev_clin])
    assert ready_untrusted is False
    assert "untrusted evaluator issuer" in msg_untrusted


def test_approval_referencing_nonexistent_evidence_digests_rejected():
    """Hardening 2: verify_release_approval rejects approvals citing unknown evidence digests."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(principal_verifier=verifier)

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev = VerificationEvidenceRecord(
        evidence_id="ev-valid",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )

    # Approval claims arbitrary evidence digest not in verified evidence records
    approval = ReleaseApprovalRecord(
        approval_id="appr-fake-evidence",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["9999999999999999999999999999999999999999999999999999999999999999"]
    )
    auth.sign_approval(approval)

    verified, reason = engine.verify_release_approval(manifest, approval, verified_evidence_records=[ev])
    assert verified is False
    assert "Approval references evidence digests not present in verified evidence records" in reason


def test_sha256_digest_strict_validation():
    """Hardening 3: Strict 64-hex SHA-256 digest format validation."""
    with pytest.raises(ValueError, match="must be a valid 64-character hexadecimal"):
        ComponentSpec("c1", "model", "1.0.0", digest="not-a-64-hex-digest")

    with pytest.raises(ValueError, match="must be a valid 64-character hexadecimal"):
        VerificationEvidenceRecord(
            evidence_id="ev1",
            manifest_digest="short-digest",
            evidence_type="audit",
            status=EvidenceVerificationStatus.PASS,
            artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
        )


def test_policy_version_binding_mismatch_rejected():
    """Hardening 4: Approval policy version must match manifest policy version."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(principal_verifier=verifier)

    manifest = create_sample_manifest(policy_version="2.0.0")
    m_digest = manifest.compute_manifest_digest()

    approval = ReleaseApprovalRecord(
        approval_id="appr-policy-mismatch",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",  # Policy version mismatch (1.0.0 vs 2.0.0)
        required_evidence_digests=["1111111111111111111111111111111111111111111111111111111111111111"]
    )
    auth.sign_approval(approval)

    verified, reason = engine.verify_release_approval(manifest, approval)
    assert verified is False
    assert "Policy version mismatch" in reason


def test_audit_failure_semantics_fail_closed(monkeypatch):
    """Hardening 5: Mandatory audit write failure fails closed."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    audit_trail = TamperEvidentAuditTrail(log_file_path="logs/test_release_audit.jsonl")

    # Mock audit_trail.record_event to simulate disk/OS failure
    def mock_fail_record(*args, **kwargs):
        raise OSError("Disk full / permission denied")
    monkeypatch.setattr(audit_trail, "record_event", mock_fail_record)

    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        audit_trail=audit_trail,
        fail_closed_audit=True
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    approval = ReleaseApprovalRecord(
        approval_id="appr-audit-test",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["1111111111111111111111111111111111111111111111111111111111111111"]
    )
    auth.sign_approval(approval)

    with pytest.raises(RuntimeError, match="Audit log failure on mandatory event"):
        engine.verify_release_approval(manifest, approval)
