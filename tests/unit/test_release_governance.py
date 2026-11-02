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
20. Assurance Level propagation through public APIs (FULL_AUTHENTICATED vs REDUCED_ASSURANCE, mixed evidence assurance calculation).
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
    AssuranceLevel,
    ComponentSpec,
    ComponentType,
    EvidenceValidationResultStatus,
    EvidenceVerificationStatus,
    ReleaseApprovalRecord,
    ReleaseApprovalVerificationResult,
    ReleaseGovernanceEngine,
    ReleaseManifest,
    ReleaseReadinessEvaluation,
    VerificationEvidenceRecord,
    ChangeCategory,
    ChangeImpactReport,
    ComponentDelta,
    EvidenceInvalidator,
    ReleaseApprovalRevocationRegistry,
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

    ready_eval = engine.evaluate_release_readiness(manifest, [ev1, ev2])
    assert ready_eval.is_ready is True
    assert ready_eval.effective_assurance_level == AssuranceLevel.REDUCED_ASSURANCE

    approval = ReleaseApprovalRecord(
        approval_id="appr-001",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=ready_eval.accepted_evidence_digests
    )
    auth.sign_approval(approval)

    res = engine.verify_release_approval(manifest, approval, evidence_records=[ev1, ev2])
    assert res.is_verified is True
    assert "successfully verified" in res.reason
    assert res.effective_assurance_level == AssuranceLevel.REDUCED_ASSURANCE


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

    res = engine.verify_release_approval(m_mutant, approval, evidence_records=[ev1])
    assert res.is_verified is False
    assert "Manifest digest mismatch" in res.reason


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

    ready_eval = engine.evaluate_release_readiness(m_new, [ev_old, ev_old_clin])
    assert ready_eval.is_ready is False
    assert "missing required verification evidence" in ready_eval.reason
    assert "bound to foreign manifest digest" in ready_eval.reason


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

    ready_eval = engine.evaluate_release_readiness(manifest, [ev1])
    assert ready_eval.is_ready is False
    assert "missing required verification evidence: ['clinical_diagnostic_benchmark']" in ready_eval.reason


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

    res = engine.verify_release_approval(manifest, approval, evidence_records=[ev1])
    assert res.is_verified is False
    assert "Ed25519 signature verification failed" in res.reason


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

    res = engine.verify_release_approval(manifest, approval, evidence_records=[ev1])
    assert res.is_verified is False
    assert "Approver 'mallory_intruder' is not in allowed approvers allowlist" in res.reason


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

    res0 = engine.verify_release_approval(manifest, approval, evidence_records=[ev1])
    assert res0.is_verified is True

    engine.revoke_release_approval(
        approval_id="appr-revocation-test",
        revoked_by_principal="security_officer_bob",
        reason="Zero-day dependency vulnerability"
    )

    res1 = engine.verify_release_approval(manifest, approval, evidence_records=[ev1])
    assert res1.is_verified is False
    assert "authoritatively revoked" in res1.reason

    approval_resurrected = ReleaseApprovalRecord(
        approval_id="appr-revocation-test",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval_resurrected)

    res2 = engine.verify_release_approval(manifest, approval_resurrected, evidence_records=[ev1])
    assert res2.is_verified is False
    assert "authoritatively revoked" in res2.reason


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

    ready_eval = engine.evaluate_release_readiness(manifest, [ev, ev_clin], artifact_bytes_provider=provider)
    assert ready_eval.is_ready is True

    substituted_bytes = b"BENCHMARK RESULTS: TAMPERED MALICIOUS ARTIFACT"
    sub_provider = lambda ev_id: substituted_bytes if ev_id == "ev-layer4-bytes" else clin_bytes
    ready_sub = engine.evaluate_release_readiness(manifest, [ev, ev_clin], artifact_bytes_provider=sub_provider)
    assert ready_sub.is_ready is False
    assert "artifact byte digest mismatch" in ready_sub.reason


def test_missing_or_none_artifact_provider_fails_closed():
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

    ready1 = engine.evaluate_release_readiness(manifest, [ev])
    assert ready1.is_ready is False
    assert "no artifact_bytes_provider supplied" in ready1.reason

    ready2 = engine.evaluate_release_readiness(manifest, [ev], artifact_bytes_provider=lambda id: None)
    assert ready2.is_ready is False
    assert "artifact retrieval returned None" in ready2.reason


def test_approval_verification_missing_evidence_records_fails_closed():
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

    res = engine.verify_release_approval(manifest, approval, evidence_records=[])
    assert res.is_verified is False
    assert "Mandatory evidence records missing at approval boundary" in res.reason


def test_approval_verification_non_passing_evidence_fails_closed():
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

    res = engine.verify_release_approval(manifest, approval, evidence_records=[ev_partial])
    assert res.is_verified is False
    assert "has non-passing status 'PARTIAL'" in res.reason


def test_required_evidence_completeness_at_approval_boundary():
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

    approval_incomplete = ReleaseApprovalRecord(
        approval_id="appr-incomplete",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval_incomplete)

    res_inc = engine.verify_release_approval(
        manifest,
        approval_incomplete,
        evidence_records=[ev1, ev2]
    )
    assert res_inc.is_verified is False
    assert "Approval omits required evidence category" in res_inc.reason
    assert "clinical_diagnostic_benchmark" in res_inc.reason

    approval_complete = ReleaseApprovalRecord(
        approval_id="appr-complete",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest(), ev2.compute_evidence_digest()]
    )
    auth.sign_approval(approval_complete)

    res_comp = engine.verify_release_approval(
        manifest,
        approval_complete,
        evidence_records=[ev1, ev2]
    )
    assert res_comp.is_verified is True
    assert "successfully verified" in res_comp.reason


def test_evaluator_authentication_policy_enforcement():
    eval_auth = MockReleaseAuthority(issuer_id="EvaluatorIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"EvaluatorIdP": eval_auth.public_key})

    engine_default = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_evaluator_signatures=True,
        require_artifact_bytes_verification=False
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

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

    engine_reduced = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_evaluator_signatures=False,
        require_artifact_bytes_verification=False
    )
    res_red = engine_reduced.verify_single_evidence(m_digest, ev_unsigned)
    assert res_red.status.value == "VERIFIED"
    assert res_red.assurance_level.value == "REDUCED_ASSURANCE"


def test_assurance_level_propagation_full_vs_reduced():
    """Final P0 & P1 Finding: AssuranceLevel propagation through public readiness and approval APIs."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    eval_auth = MockReleaseAuthority(issuer_id="EvaluatorIdP")
    verifier = PrincipalVerifier(trusted_public_keys={
        "TrustedCorpIdP": auth.public_key,
        "EvaluatorIdP": eval_auth.public_key
    })

    # Test Case 1: Default configuration with fully verified artifact bytes & evaluator signatures
    engine_full = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"],
        require_artifact_bytes_verification=True,
        require_evaluator_signatures=True,
        fail_closed_audit=False
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    art1_bytes = b"SECURITY AUDIT 100% PASS"
    art2_bytes = b"CLINICAL DIAGNOSTIC PASS"
    art1_digest = hashlib.sha256(art1_bytes).hexdigest()
    art2_digest = hashlib.sha256(art2_bytes).hexdigest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4-full",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art1_digest,
        evaluator_issuer="EvaluatorIdP"
    )
    eval_auth.sign_evidence(ev1)

    ev2 = VerificationEvidenceRecord(
        evidence_id="ev-clinical-full",
        manifest_digest=m_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art2_digest,
        evaluator_issuer="EvaluatorIdP"
    )
    eval_auth.sign_evidence(ev2)

    bytes_map = {"ev-layer4-full": art1_bytes, "ev-clinical-full": art2_bytes}
    provider = lambda eid: bytes_map.get(eid)

    # Readiness exposes FULL_AUTHENTICATED
    readiness = engine_full.evaluate_release_readiness(manifest, [ev1, ev2], artifact_bytes_provider=provider)
    assert readiness.is_ready is True
    assert readiness.effective_assurance_level == AssuranceLevel.FULL_AUTHENTICATED

    approval = ReleaseApprovalRecord(
        approval_id="appr-full",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=readiness.accepted_evidence_digests
    )
    auth.sign_approval(approval)

    # Approval exposes FULL_AUTHENTICATED
    appr_res = engine_full.verify_release_approval(manifest, approval, evidence_records=[ev1, ev2], artifact_bytes_provider=provider)
    assert appr_res.is_verified is True
    assert appr_res.effective_assurance_level == AssuranceLevel.FULL_AUTHENTICATED

    # Test Case 2: Explicit reduced-assurance configuration (e.g. require_evaluator_signatures=False)
    engine_reduced = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"],
        require_artifact_bytes_verification=True,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )

    # Use unsigned evidence
    ev_unsigned1 = VerificationEvidenceRecord(
        evidence_id="ev-layer4-unsigned",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art1_digest
    )
    ev_unsigned2 = VerificationEvidenceRecord(
        evidence_id="ev-clinical-unsigned",
        manifest_digest=m_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art2_digest
    )
    bytes_map_unsigned = {"ev-layer4-unsigned": art1_bytes, "ev-clinical-unsigned": art2_bytes}
    prov_unsigned = lambda eid: bytes_map_unsigned.get(eid)

    readiness_red = engine_reduced.evaluate_release_readiness(manifest, [ev_unsigned1, ev_unsigned2], artifact_bytes_provider=prov_unsigned)
    assert readiness_red.is_ready is True
    assert readiness_red.effective_assurance_level == AssuranceLevel.REDUCED_ASSURANCE

    approval_red = ReleaseApprovalRecord(
        approval_id="appr-reduced",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=readiness_red.accepted_evidence_digests
    )
    auth.sign_approval(approval_red)

    appr_res_red = engine_reduced.verify_release_approval(manifest, approval_red, evidence_records=[ev_unsigned1, ev_unsigned2], artifact_bytes_provider=prov_unsigned)
    assert appr_res_red.is_verified is True
    assert appr_res_red.effective_assurance_level == AssuranceLevel.REDUCED_ASSURANCE

    # Test Case 3: Mixed assurance (one signed, one unsigned) -> overall must be REDUCED_ASSURANCE
    bytes_map_mixed = {"ev-layer4-full": art1_bytes, "ev-clinical-unsigned": art2_bytes}
    prov_mixed = lambda eid: bytes_map_mixed.get(eid)
    readiness_mixed = engine_reduced.evaluate_release_readiness(manifest, [ev1, ev_unsigned2], artifact_bytes_provider=prov_mixed)
    assert readiness_mixed.is_ready is True
    assert readiness_mixed.effective_assurance_level == AssuranceLevel.REDUCED_ASSURANCE


def test_audit_configuration_gap_fail_closed_when_unconfigured():
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})

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

    ev.evaluated_component_ids.add("diagnostic_model")
    res_mut1 = engine.verify_single_evidence(m_digest, ev)
    assert res_mut1.status.value == "REJECTED"
    assert "evaluator signature verification failed" in res_mut1.reason

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
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval)

    res = engine.verify_release_approval(manifest, approval, evidence_records=[ev1])
    assert res.is_verified is False
    assert "Policy version mismatch" in res.reason


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
