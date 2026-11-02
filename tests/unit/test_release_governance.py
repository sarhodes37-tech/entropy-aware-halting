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
16. Adversarial tests for missing artifact provider, provider returning None, evaluator signature field coverage mutation, and evidence omission at approval boundary.
17. Required evidence completeness at approval verification boundary (approval omitting one required type rejected; unreferenced records cannot satisfy requirements).
18. Evaluator authentication policy (missing signature/issuer rejected under default policy; unsigned evidence only accepted under explicit reduced-assurance mode).
19. Fail-closed auditing when audit_trail is unconfigured.
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
        allowed_approver_principals=["reviewer_alice"],
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
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

    verified, v_msg = engine.verify_release_approval(manifest, approval, evidence_records=[ev1, ev2])
    assert verified is True
    assert "successfully verified" in v_msg


def test_invariant_5_and_6_approval_fails_for_modified_manifest_even_with_same_release_id():
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"],
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )

    m_orig = create_sample_manifest(release_id="rel-same-id-123")
    m_orig_digest = m_orig.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_orig_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )

    approval = ReleaseApprovalRecord(
        approval_id="appr-orig",
        manifest_digest=m_orig_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval)

    m_mutant = create_sample_manifest(
        release_id="rel-same-id-123",
        model_digest="9999999999999999999999999999999999999999999999999999999999999999"
    )

    verified, reason = engine.verify_release_approval(m_mutant, approval, evidence_records=[ev1])
    assert verified is False
    assert "Manifest digest mismatch" in reason


def test_invariant_7_evidence_from_older_manifest_cannot_satisfy_new_manifest():
    engine = ReleaseGovernanceEngine(require_artifact_bytes_verification=False, require_evaluator_signatures=False)
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
    engine = ReleaseGovernanceEngine(require_artifact_bytes_verification=False, require_evaluator_signatures=False)
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
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )

    manifest = create_sample_manifest(display_name="Manifest For Single Evidence")
    manifest.required_evidence_types = {"layer4_security_audit"}
    m_digest = manifest.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )

    approval = ReleaseApprovalRecord(
        approval_id="appr-tampered",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval)

    tampered_sig = list(approval.signature)
    tampered_sig[0] = "0" if tampered_sig[0] != "0" else "1"
    approval.signature = "".join(tampered_sig)

    verified, reason = engine.verify_release_approval(manifest, approval, evidence_records=[ev1])
    assert verified is False
    assert "Ed25519 signature verification failed" in reason


def test_invariant_10_unauthorized_principal_cannot_issue_release_approval():
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"],
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )

    approval = ReleaseApprovalRecord(
        approval_id="appr-mallory",
        manifest_digest=m_digest,
        approver_id="mallory_intruder",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval)

    verified, reason = engine.verify_release_approval(manifest, approval, evidence_records=[ev1])
    assert verified is False
    assert "Approver 'mallory_intruder' is not in allowed approvers allowlist" in reason


def test_invariant_11_revoked_or_expired_approval_cannot_authorize_release_and_resurrection_resisted():
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    rev_registry = ReleaseApprovalRevocationRegistry()
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        revocation_registry=rev_registry,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )

    manifest = create_sample_manifest()
    manifest.required_evidence_types = {"layer4_security_audit"}
    m_digest = manifest.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )

    approval = ReleaseApprovalRecord(
        approval_id="appr-revocation-test",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval)

    v0, _ = engine.verify_release_approval(manifest, approval, evidence_records=[ev1])
    assert v0 is True

    engine.revoke_release_approval(
        approval_id="appr-revocation-test",
        revoked_by_principal="security_officer_bob",
        reason="Zero-day dependency vulnerability"
    )

    v1, r1 = engine.verify_release_approval(manifest, approval, evidence_records=[ev1])
    assert v1 is False
    assert "authoritatively revoked" in r1

    approval_resurrected = ReleaseApprovalRecord(
        approval_id="appr-revocation-test",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval_resurrected)

    v2, r2 = engine.verify_release_approval(manifest, approval_resurrected, evidence_records=[ev1])
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
    engine = ReleaseGovernanceEngine(require_artifact_bytes_verification=True, require_evaluator_signatures=False)
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

    clin_bytes = b"CLINICAL BENCHMARK PASS"
    clin_digest = hashlib.sha256(clin_bytes).hexdigest()
    ev_clin.artifact_digest = clin_digest

    provider = lambda ev_id: real_bytes if ev_id == "ev-layer4-bytes" else clin_bytes

    ready, _, _ = engine.evaluate_release_readiness(manifest, [ev, ev_clin], artifact_bytes_provider=provider)
    assert ready is True

    substituted_bytes = b"BENCHMARK RESULTS: TAMPERED MALICIOUS ARTIFACT"
    sub_provider = lambda ev_id: substituted_bytes if ev_id == "ev-layer4-bytes" else clin_bytes
    ready_sub, msg_sub, _ = engine.evaluate_release_readiness(manifest, [ev, ev_clin], artifact_bytes_provider=sub_provider)
    assert ready_sub is False
    assert "artifact byte digest mismatch" in msg_sub


def test_missing_or_none_artifact_provider_fails_closed():
    """Finding 1: Missing artifact provider or provider returning None cannot establish authenticity."""
    engine = ReleaseGovernanceEngine(require_artifact_bytes_verification=True, require_evaluator_signatures=False)
    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )

    ready1, msg1, _ = engine.evaluate_release_readiness(manifest, [ev])
    assert ready1 is False
    assert "no artifact_bytes_provider supplied" in msg1

    ready2, msg2, _ = engine.evaluate_release_readiness(manifest, [ev], artifact_bytes_provider=lambda id: None)
    assert ready2 is False
    assert "artifact retrieval returned None" in msg2


def test_approval_verification_missing_evidence_records_fails_closed():
    """Finding 2: Missing evidence records at approval boundary strictly fails closed."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    approval = ReleaseApprovalRecord(
        approval_id="appr-no-evidence",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["1111111111111111111111111111111111111111111111111111111111111111"]
    )
    auth.sign_approval(approval)

    verified, reason = engine.verify_release_approval(manifest, approval, evidence_records=[])
    assert verified is False
    assert "Mandatory evidence records missing at approval boundary" in reason


def test_approval_verification_non_passing_evidence_fails_closed():
    """Finding 2: Evidence with FAIL, PARTIAL, or INCONCLUSIVE status fails approval verification."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev_partial = VerificationEvidenceRecord(
        evidence_id="ev-partial",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PARTIAL,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )

    approval = ReleaseApprovalRecord(
        approval_id="appr-partial-evidence",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev_partial.compute_evidence_digest()]
    )
    auth.sign_approval(approval)

    verified, reason = engine.verify_release_approval(manifest, approval, evidence_records=[ev_partial])
    assert verified is False
    assert "has non-passing status 'PARTIAL'" in reason


def test_required_evidence_completeness_at_approval_boundary():
    """Follow-up P0 Finding 1: Approval omitting one required evidence category is strictly rejected."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )

    manifest = create_sample_manifest()
    # Requires: {"layer4_security_audit", "clinical_diagnostic_benchmark"}
    m_digest = manifest.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )
    ev2 = VerificationEvidenceRecord(
        evidence_id="ev-clinical",
        manifest_digest=m_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="2222222222222222222222222222222222222222222222222222222222222222"
    )

    # 1. Approval only references ev1 digest (omits clinical_diagnostic_benchmark)
    approval_incomplete = ReleaseApprovalRecord(
        approval_id="appr-incomplete",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval_incomplete)

    # Both records supplied to function, but approval signed only 1 -> must fail closed
    verified_inc, reason_inc = engine.verify_release_approval(
        manifest,
        approval_incomplete,
        evidence_records=[ev1, ev2]
    )
    assert verified_inc is False
    assert "Approval omits required evidence category" in reason_inc
    assert "clinical_diagnostic_benchmark" in reason_inc

    # 2. Complete approval references both digests -> must succeed
    approval_complete = ReleaseApprovalRecord(
        approval_id="appr-complete",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest(), ev2.compute_evidence_digest()]
    )
    auth.sign_approval(approval_complete)

    verified_comp, reason_comp = engine.verify_release_approval(
        manifest,
        approval_complete,
        evidence_records=[ev1, ev2]
    )
    assert verified_comp is True
    assert "successfully verified" in reason_comp


def test_evaluator_authentication_policy_enforcement():
    """Follow-up P0 Finding 2: Evaluator signature is mandatory under default policy."""
    eval_auth = MockReleaseAuthority(issuer_id="EvaluatorIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"EvaluatorIdP": eval_auth.public_key})

    # Default engine: require_evaluator_signatures=True
    engine_default = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_evaluator_signatures=True,
        require_artifact_bytes_verification=False
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    # 1. Neither signature nor issuer
    ev_unsigned = VerificationEvidenceRecord(
        evidence_id="ev-unsigned",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )
    res1 = engine_default.verify_single_evidence(m_digest, ev_unsigned)
    assert res1.status.value == "REJECTED"
    assert "evaluator signature and issuer are mandatory under default policy" in res1.reason

    # 2. Issuer but no signature
    ev_issuer_only = VerificationEvidenceRecord(
        evidence_id="ev-issuer-only",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111",
        evaluator_issuer="EvaluatorIdP"
    )
    res2 = engine_default.verify_single_evidence(m_digest, ev_issuer_only)
    assert res2.status.value == "REJECTED"
    assert "missing evaluator signature" in res2.reason

    # 3. Signature but no issuer
    ev_sig_only = VerificationEvidenceRecord(
        evidence_id="ev-sig-only",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111",
        signature="aa" * 64
    )
    res3 = engine_default.verify_single_evidence(m_digest, ev_sig_only)
    assert res3.status.value == "REJECTED"
    assert "missing evaluator_issuer" in res3.reason

    # 4. Untrusted evaluator issuer
    ev_untrusted = VerificationEvidenceRecord(
        evidence_id="ev-untrusted",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111",
        evaluator_issuer="RogueEvaluator"
    )
    eval_auth.sign_evidence(ev_untrusted)
    res4 = engine_default.verify_single_evidence(m_digest, ev_untrusted)
    assert res4.status.value == "REJECTED"
    assert "untrusted evaluator issuer" in res4.reason

    # 5. Invalid signature
    ev_invalid_sig = VerificationEvidenceRecord(
        evidence_id="ev-invalid-sig",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111",
        evaluator_issuer="EvaluatorIdP",
        signature="00" * 64
    )
    res5 = engine_default.verify_single_evidence(m_digest, ev_invalid_sig)
    assert res5.status.value == "REJECTED"
    assert "cryptographic evaluator signature verification failed" in res5.reason

    # 6. Valid signature from trusted issuer
    ev_valid = VerificationEvidenceRecord(
        evidence_id="ev-valid",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111",
        evaluator_issuer="EvaluatorIdP"
    )
    eval_auth.sign_evidence(ev_valid)
    res6 = engine_default.verify_single_evidence(m_digest, ev_valid)
    assert res6.status.value == "VERIFIED"

    # 7. Explicitly configured reduced-assurance mode allows unsigned evidence
    engine_reduced = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_evaluator_signatures=False,
        require_artifact_bytes_verification=False
    )
    res_red = engine_reduced.verify_single_evidence(m_digest, ev_unsigned)
    assert res_red.status.value == "VERIFIED"
    assert res_red.assurance_level.value == "REDUCED_ASSURANCE"


def test_audit_configuration_gap_fail_closed_when_unconfigured():
    """Follow-up P1 Finding 4: fail_closed_audit=True raises RuntimeError if audit_trail is unconfigured."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})

    # Engine configured with fail_closed_audit=True but audit_trail=None
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        audit_trail=None,
        fail_closed_audit=True,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )
    ev2 = VerificationEvidenceRecord(
        evidence_id="ev-clinical",
        manifest_digest=m_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="2222222222222222222222222222222222222222222222222222222222222222"
    )

    approval = ReleaseApprovalRecord(
        approval_id="appr-no-audit-trail",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest(), ev2.compute_evidence_digest()]
    )
    auth.sign_approval(approval)

    # Must raise RuntimeError because audit write is mandatory but audit trail is unconfigured
    with pytest.raises(RuntimeError, match="fail_closed_audit=True but no audit_trail configured"):
        engine.verify_release_approval(manifest, approval, evidence_records=[ev1, ev2])


def test_evaluator_signature_mutation_of_component_ids_and_metadata_detected():
    eval_auth = MockReleaseAuthority(issuer_id="EvaluatorIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"EvaluatorIdP": eval_auth.public_key})
    engine = ReleaseGovernanceEngine(principal_verifier=verifier, require_artifact_bytes_verification=False)

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev = VerificationEvidenceRecord(
        evidence_id="ev-scope-test",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111",
        evaluated_component_ids={"core_runtime"},
        evaluator_issuer="EvaluatorIdP",
        metadata={"coverage_pct": 100}
    )
    eval_auth.sign_evidence(ev)

    res_valid = engine.verify_single_evidence(m_digest, ev)
    assert res_valid.status.value == "VERIFIED"

    # Adversarial Mutation 1: Expand evaluated_component_ids without changing signature
    ev.evaluated_component_ids.add("diagnostic_model")
    res_mut1 = engine.verify_single_evidence(m_digest, ev)
    assert res_mut1.status.value == "REJECTED"
    assert "evaluator signature verification failed" in res_mut1.reason

    # Restore components and mutate metadata
    ev.evaluated_component_ids = {"core_runtime"}
    ev.metadata["coverage_pct"] = 50
    res_mut2 = engine.verify_single_evidence(m_digest, ev)
    assert res_mut2.status.value == "REJECTED"
    assert "evaluator signature verification failed" in res_mut2.reason


def test_sha256_digest_strict_validation():
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
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )

    manifest = create_sample_manifest(policy_version="2.0.0")
    m_digest = manifest.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )

    approval = ReleaseApprovalRecord(
        approval_id="appr-policy-mismatch",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",  # Policy version mismatch (1.0.0 vs 2.0.0)
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval)

    verified, reason = engine.verify_release_approval(manifest, approval, evidence_records=[ev1])
    assert verified is False
    assert "Policy version mismatch" in reason


def test_audit_failure_semantics_fail_closed(monkeypatch):
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    audit_trail = TamperEvidentAuditTrail(log_file_path="logs/test_release_audit.jsonl")

    def mock_fail_record(*args, **kwargs):
        raise OSError("Disk full / permission denied")
    monkeypatch.setattr(audit_trail, "record_event", mock_fail_record)

    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        audit_trail=audit_trail,
        fail_closed_audit=True,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )

    approval = ReleaseApprovalRecord(
        approval_id="appr-audit-test",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval)

    with pytest.raises(RuntimeError, match="Audit log failure on mandatory event"):
        engine.verify_release_approval(manifest, approval, evidence_records=[ev1])


def test_evidence_invalidation_and_change_impact_classification():
    m_old = create_sample_manifest(
        model_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )
    m_new = create_sample_manifest(
        model_digest="2222222222222222222222222222222222222222222222222222222222222222"
    )

    old_digest = m_old.compute_manifest_digest()
    new_digest = m_new.compute_manifest_digest()

    ev_model = VerificationEvidenceRecord(
        evidence_id="ev-model-old",
        manifest_digest=old_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        evaluated_component_ids={"diagnostic_model"}
    )
    ev_runtime = VerificationEvidenceRecord(
        evidence_id="ev-runtime-old",
        manifest_digest=old_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        evaluated_component_ids={"core_runtime"}
    )

    report = EvidenceInvalidator.analyze_change(m_old, m_new, [ev_model, ev_runtime])

    assert report.is_identical is False
    assert "diagnostic_model" in report.affected_component_ids
    assert "core_runtime" not in report.affected_component_ids
    assert len(report.invalidated_evidence) == 2
    assert report.can_authorize_without_rerun is False
    assert any("touches changed component(s)" in r for r in report.invalidation_reasons)
