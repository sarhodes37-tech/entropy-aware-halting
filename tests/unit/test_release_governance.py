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

    approval_mixed = ReleaseApprovalRecord(
        approval_id="appr-mixed",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=readiness_mixed.accepted_evidence_digests
    )
    auth.sign_approval(approval_mixed)

    appr_res_mixed = engine_reduced.verify_release_approval(manifest, approval_mixed, evidence_records=[ev1, ev_unsigned2], artifact_bytes_provider=prov_mixed)
    assert appr_res_mixed.is_verified is True
    assert appr_res_mixed.effective_assurance_level == AssuranceLevel.REDUCED_ASSURANCE

    # Test Case 4: Disabling artifact-byte verification while retaining evaluator signatures produces REDUCED_ASSURANCE in approval result
    engine_no_art = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"],
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=True,
        fail_closed_audit=False
    )
    readiness_no_art = engine_no_art.evaluate_release_readiness(manifest, [ev1, ev2])
    assert readiness_no_art.is_ready is True
    assert readiness_no_art.effective_assurance_level == AssuranceLevel.REDUCED_ASSURANCE

    approval_no_art = ReleaseApprovalRecord(
        approval_id="appr-no-art",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=readiness_no_art.accepted_evidence_digests
    )
    auth.sign_approval(approval_no_art)

    appr_res_no_art = engine_no_art.verify_release_approval(manifest, approval_no_art, evidence_records=[ev1, ev2])
    assert appr_res_no_art.is_verified is True
    assert appr_res_no_art.effective_assurance_level == AssuranceLevel.REDUCED_ASSURANCE

    # Test Case 5: Disabling evaluator-signature verification while retaining artifact-byte verification produces REDUCED_ASSURANCE in approval result
    engine_no_sig = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"],
        require_artifact_bytes_verification=True,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )
    readiness_no_sig = engine_no_sig.evaluate_release_readiness(manifest, [ev_unsigned1, ev_unsigned2], artifact_bytes_provider=prov_unsigned)
    assert readiness_no_sig.is_ready is True
    assert readiness_no_sig.effective_assurance_level == AssuranceLevel.REDUCED_ASSURANCE

    approval_no_sig = ReleaseApprovalRecord(
        approval_id="appr-no-sig",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=readiness_no_sig.accepted_evidence_digests
    )
    auth.sign_approval(approval_no_sig)

    appr_res_no_sig = engine_no_sig.verify_release_approval(manifest, approval_no_sig, evidence_records=[ev_unsigned1, ev_unsigned2], artifact_bytes_provider=prov_unsigned)
    assert appr_res_no_sig.is_verified is True
    assert appr_res_no_sig.effective_assurance_level == AssuranceLevel.REDUCED_ASSURANCE


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


def test_revocation_registry_input_validation_fail_closed():
    reg = ReleaseApprovalRevocationRegistry()

    # Query methods fail closed: raise ValueError on invalid, None, or non-string inputs
    for invalid_id in [None, "", "   ", 12345, object(), [], {}]:
        with pytest.raises(ValueError, match="approval_id must be a non-empty string"):
            reg.is_revoked(invalid_id)
        with pytest.raises(ValueError, match="approval_id must be a non-empty string"):
            reg.get_revocation_record(invalid_id)

    # Valid unknown IDs return False / None as expected
    assert reg.is_revoked("valid-unrevoked-id") is False
    assert reg.get_revocation_record("valid-unrevoked-id") is None

    # Invalid arguments to revoke_approval raise clear ValueError and do not mutate state
    for bad_id in [None, "", "   ", 12345, object()]:
        with pytest.raises(ValueError, match="approval_id must be a non-empty string"):
            reg.revoke_approval(bad_id, "admin_bob", reason="Compromised key")

    for bad_principal in [None, "", "   ", 12345, object()]:
        with pytest.raises(ValueError, match="revoked_by_principal must be a non-empty string"):
            reg.revoke_approval("appr-valid", bad_principal, reason="Compromised key")

    for bad_reason in [None, "", "   ", 12345, object()]:
        with pytest.raises(ValueError, match="(reason must be a non-empty string|RevocationRecord: reason must be a non-empty string)"):
            reg.revoke_approval("appr-valid", "admin_bob", reason=bad_reason)

    # Confirm registry state was not mutated by any failed attempt
    assert reg.is_revoked("appr-valid") is False
    assert reg.get_revocation_record("appr-valid") is None

    # Normal revocation works
    rec = reg.revoke_approval("appr-100", "admin_bob", reason="Compromised key")
    assert rec.approval_id == "appr-100"
    assert rec.revoked_by_principal == "admin_bob"
    assert rec.reason == "Compromised key"
    assert reg.is_revoked("appr-100") is True
    assert reg.is_revoked("  appr-100  ") is True
    assert reg.get_revocation_record("appr-100") is not None


def test_caller_verify_release_approval_fails_closed_on_invalid_approval_id():
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
        approval_id="appr-001",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev1.compute_evidence_digest()]
    )
    auth.sign_approval(approval)

    # Tamper with approval object in memory so approval_id is empty/whitespace
    object.__setattr__(approval, "approval_id", "   ")
    with pytest.raises(ValueError, match="approval_id must be a non-empty string"):
        engine.verify_release_approval(manifest, approval, evidence_records=[ev1])


def test_wrapper_revoke_release_approval_validation_and_audit():
    audit_trail = TamperEvidentAuditTrail(log_file_path="logs/test_wrapper_revoke_audit.jsonl")
    rev_registry = ReleaseApprovalRevocationRegistry()
    engine = ReleaseGovernanceEngine(
        audit_trail=audit_trail,
        revocation_registry=rev_registry,
        fail_closed_audit=False
    )

    # 1. Calling without explicit reason raises TypeError due to mandatory signature
    with pytest.raises(TypeError):
        engine.revoke_release_approval("appr-wrapped", "security_lead")  # type: ignore

    # 2. Invalid or non-string inputs raise ValueError and do not mutate registry or emit audit events
    for bad_id in [None, "", "   ", 12345, object()]:
        with pytest.raises(ValueError, match="approval_id must be a non-empty string"):
            engine.revoke_release_approval(bad_id, "security_lead", reason="Revocation reason")

    for bad_principal in [None, "", "   ", 12345, object()]:
        with pytest.raises(ValueError, match="revoked_by_principal must be a non-empty string"):
            engine.revoke_release_approval("appr-wrapped", bad_principal, reason="Revocation reason")

    for bad_reason in [None, "", "   ", 12345, object()]:
        with pytest.raises(ValueError, match="reason must be a non-empty string"):
            engine.revoke_release_approval("appr-wrapped", "security_lead", reason=bad_reason)

    assert rev_registry.is_revoked("appr-wrapped") is False
    assert rev_registry.get_revocation_record("appr-wrapped") is None

    # 3. Valid revocation through wrapper succeeds, mutates registry, and is recorded
    rec = engine.revoke_release_approval(
        approval_id="appr-wrapped",
        revoked_by_principal="security_lead",
        reason="Discovered critical CVE in dependencies"
    )
    assert rec.approval_id == "appr-wrapped"
    assert rec.revoked_by_principal == "security_lead"
    assert rec.reason == "Discovered critical CVE in dependencies"
    assert rev_registry.is_revoked("appr-wrapped") is True
    assert rev_registry.get_revocation_record("appr-wrapped") == rec


# Direct RevocationRecord validation failure tests
def test_direct_revocation_record_validation():
    from epistemicos.release.revocation import RevocationRecord
    for bad_id in [None, "", "   ", 12345, object()]:
        with pytest.raises(ValueError, match="RevocationRecord: approval_id must be a non-empty string"):
            RevocationRecord(approval_id=bad_id, revoked_by_principal="admin", reason="compromised")

    for bad_p in [None, "", "   ", 12345, object()]:
        with pytest.raises(ValueError, match="RevocationRecord: revoked_by_principal must be a non-empty string"):
            RevocationRecord(approval_id="appr-1", revoked_by_principal=bad_p, reason="compromised")

    for bad_r in [None, "", "   ", 12345, object()]:
        with pytest.raises(ValueError, match="RevocationRecord: reason must be a non-empty string"):
            RevocationRecord(approval_id="appr-1", revoked_by_principal="admin", reason=bad_r)

    # Validate revocation_timestamp type ambiguity and bounds
    for bad_type_ts in [True, False, "123456789", None, [12345], {"ts": 123}]:
        with pytest.raises(TypeError, match="RevocationRecord: revocation_timestamp must be a numeric timestamp"):
            RevocationRecord(approval_id="appr-1", revoked_by_principal="admin", reason="compromised", revocation_timestamp=bad_type_ts)

    for non_finite_ts in [float("nan"), float("inf"), float("-inf")]:
        with pytest.raises(ValueError, match="RevocationRecord: revocation_timestamp must be a finite number"):
            RevocationRecord(approval_id="appr-1", revoked_by_principal="admin", reason="compromised", revocation_timestamp=non_finite_ts)

    # 64-bit integer overflow
    with pytest.raises(ValueError, match="RevocationRecord: revocation_timestamp integer overflows 64-bit limits"):
        RevocationRecord(approval_id="appr-1", revoked_by_principal="admin", reason="compromised", revocation_timestamp=1 << 65)

    # Float magnitude overflow
    with pytest.raises(ValueError, match="RevocationRecord: revocation_timestamp float overflows magnitude limits"):
        RevocationRecord(approval_id="appr-1", revoked_by_principal="admin", reason="compromised", revocation_timestamp=1e300)

    # Valid int and float timestamps
    rec_int = RevocationRecord(approval_id="appr-1", revoked_by_principal="admin", reason="compromised", revocation_timestamp=1600000000)
    assert rec_int.revocation_timestamp == 1600000000
    rec_flt = RevocationRecord(approval_id="appr-1", revoked_by_principal="admin", reason="compromised", revocation_timestamp=1600000000.123456)
    assert rec_flt.revocation_timestamp == 1600000000.123456


# ==============================================================================
# Models Coverage Expansion: ComponentSpec, ReleaseManifest,
# VerificationEvidenceRecord, ReleaseApprovalRecord
# ==============================================================================

def test_component_spec_validation_and_canonicalization():
    valid_digest = "1" * 64
    valid_cfg_digest = "2" * 64

    # Empty, whitespace, invalid types for component_id
    for bad_id in [None, "", "   ", 123, object(), [], {}]:
        with pytest.raises(ValueError, match="ComponentSpec: component_id must be a non-empty string"):
            ComponentSpec(component_id=bad_id, component_type="model", version="1.0.0", digest=valid_digest)

    # Empty, whitespace, invalid types for component_type
    for bad_type in [None, "", "   ", 123, object(), [], {}]:
        with pytest.raises(ValueError, match="ComponentSpec: component_type must be a non-empty string"):
            ComponentSpec(component_id="c1", component_type=bad_type, version="1.0.0", digest=valid_digest)

    # Empty, whitespace, invalid types for version
    for bad_ver in [None, "", "   ", 123, object(), [], {}]:
        with pytest.raises(ValueError, match="ComponentSpec: version must be a non-empty string"):
            ComponentSpec(component_id="c1", component_type="model", version=bad_ver, digest=valid_digest)

    # Invalid artifact digest
    for bad_dig in [None, "", "short", "z" * 64, 123]:
        with pytest.raises(ValueError, match="ComponentSpec.digest must be a valid 64-character hexadecimal"):
            ComponentSpec(component_id="c1", component_type="model", version="1.0.0", digest=bad_dig)

    # Invalid optional config_digest (when truthy/non-None)
    for bad_cfg in ["short", "g" * 64, 123]:
        with pytest.raises(ValueError, match="ComponentSpec.config_digest must be a valid 64-character hexadecimal"):
            ComponentSpec(component_id="c1", component_type="model", version="1.0.0", digest=valid_digest, config_digest=bad_cfg)

    # Trimming and lowercase normalization
    spec = ComponentSpec(
        component_id="  c1  ",
        component_type="  model  ",
        version="  1.0.0  ",
        digest=valid_digest.upper(),
        config_digest=valid_cfg_digest.upper()
    )
    canon = spec.to_canonical_dict()
    assert canon["component_id"] == "c1"
    assert canon["component_type"] == "model"
    assert canon["version"] == "1.0.0"
    assert canon["digest"] == valid_digest.lower()
    assert canon["config_digest"] == valid_cfg_digest.lower()

    # compute_spec_digest stability
    d1 = spec.compute_spec_digest()
    spec_clean = ComponentSpec(
        component_id="c1",
        component_type="model",
        version="1.0.0",
        digest=valid_digest.lower(),
        config_digest=valid_cfg_digest.lower()
    )
    assert d1 == spec_clean.compute_spec_digest()
    assert len(d1) == 64


def test_release_manifest_validation_and_lookup():
    valid_digest = "1" * 64

    # Invalid schema_version
    for bad in [None, "", "   ", 123]:
        with pytest.raises(ValueError, match="ReleaseManifest: schema_version must be a non-empty string"):
            ReleaseManifest(schema_version=bad, release_id="rel-1", target_environment="prod")

    # Invalid release_id
    for bad in [None, "", "   ", 123]:
        with pytest.raises(ValueError, match="ReleaseManifest: release_id must be a non-empty string"):
            ReleaseManifest(schema_version="1.0", release_id=bad, target_environment="prod")

    # Invalid target_environment
    for bad in [None, "", "   ", 123]:
        with pytest.raises(ValueError, match="ReleaseManifest: target_environment must be a non-empty string"):
            ReleaseManifest(schema_version="1.0", release_id="rel-1", target_environment=bad)

    # Non-ComponentSpec entry in components
    with pytest.raises(TypeError, match="ReleaseManifest: components must contain ComponentSpec instances, got dict"):
        ReleaseManifest(
            schema_version="1.0",
            release_id="rel-1",
            target_environment="prod",
            components=[{"component_id": "c1"}]  # type: ignore
        )

    # get_component success and failure
    c1 = ComponentSpec("c1", "model", "1.0", valid_digest)
    c2 = ComponentSpec("c2", "runtime", "1.0", "2" * 64)
    manifest = ReleaseManifest(
        schema_version="1.0",
        release_id="rel-1",
        target_environment="prod",
        components=[c1, c2],
        policy_digest="3" * 64
    )
    assert manifest.get_component("c1") == c1
    assert manifest.get_component("c2") == c2
    assert manifest.get_component("nonexistent") is None


def test_verification_evidence_record_validation_and_payload_sensitivity():
    m_digest = "a" * 64
    art_digest = "b" * 64

    # Invalid evidence_id
    for bad in [None, "", "   ", 123]:
        with pytest.raises(ValueError, match="VerificationEvidenceRecord: evidence_id must be a non-empty string"):
            VerificationEvidenceRecord(
                evidence_id=bad,
                manifest_digest=m_digest,
                evidence_type="audit",
                status=EvidenceVerificationStatus.PASS,
                artifact_digest=art_digest
            )

    # Invalid evidence_type
    for bad in [None, "", "   ", 123]:
        with pytest.raises(ValueError, match="VerificationEvidenceRecord: evidence_type must be a non-empty string"):
            VerificationEvidenceRecord(
                evidence_id="ev1",
                manifest_digest=m_digest,
                evidence_type=bad,
                status=EvidenceVerificationStatus.PASS,
                artifact_digest=art_digest
            )

    # String status conversion and invalid status
    ev_str_pass = VerificationEvidenceRecord(
        evidence_id="ev1",
        manifest_digest=m_digest,
        evidence_type="audit",
        status="PASS",  # string converted to enum
        artifact_digest=art_digest
    )
    assert ev_str_pass.status == EvidenceVerificationStatus.PASS

    with pytest.raises(ValueError):
        VerificationEvidenceRecord(
            evidence_id="ev1",
            manifest_digest=m_digest,
            evidence_type="audit",
            status="UNKNOWN_STATUS",  # type: ignore
            artifact_digest=art_digest
        )

    # is_valid_for_manifest behavior
    assert ev_str_pass.is_valid_for_manifest(m_digest) is True
    assert ev_str_pass.is_valid_for_manifest(m_digest.upper()) is True
    assert ev_str_pass.is_valid_for_manifest("c" * 64) is False

    ev_str_fail = VerificationEvidenceRecord(
        evidence_id="ev2",
        manifest_digest=m_digest,
        evidence_type="audit",
        status=EvidenceVerificationStatus.FAIL,
        artifact_digest=art_digest
    )
    assert ev_str_fail.is_valid_for_manifest(m_digest) is False

    # Signature payload sensitivity: changing metadata, component IDs, issuer, timestamp, status, or artifact digest
    base_ev = VerificationEvidenceRecord(
        evidence_id="ev-base",
        manifest_digest=m_digest,
        evidence_type="audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluated_component_ids={"c1"},
        evaluator_id="eval-1",
        evaluator_issuer="IdP-1",
        evaluated_at_utc="2026-05-01T00:00:00Z",
        metadata={"key": "val1"}
    )
    base_payload = base_ev.compute_signature_payload()

    # Component IDs change
    ev_mod1 = VerificationEvidenceRecord(
        evidence_id="ev-base",
        manifest_digest=m_digest,
        evidence_type="audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluated_component_ids={"c1", "c2"},
        evaluator_id="eval-1",
        evaluator_issuer="IdP-1",
        evaluated_at_utc="2026-05-01T00:00:00Z",
        metadata={"key": "val1"}
    )
    assert ev_mod1.compute_signature_payload() != base_payload

    # Metadata change
    ev_mod2 = VerificationEvidenceRecord(
        evidence_id="ev-base",
        manifest_digest=m_digest,
        evidence_type="audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluated_component_ids={"c1"},
        evaluator_id="eval-1",
        evaluator_issuer="IdP-1",
        evaluated_at_utc="2026-05-01T00:00:00Z",
        metadata={"key": "val2"}
    )
    assert ev_mod2.compute_signature_payload() != base_payload

    # Evaluator issuer change
    ev_mod3 = VerificationEvidenceRecord(
        evidence_id="ev-base",
        manifest_digest=m_digest,
        evidence_type="audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluated_component_ids={"c1"},
        evaluator_id="eval-1",
        evaluator_issuer="IdP-2",
        evaluated_at_utc="2026-05-01T00:00:00Z",
        metadata={"key": "val1"}
    )
    assert ev_mod3.compute_signature_payload() != base_payload

    # Evaluated at timestamp change
    ev_mod4 = VerificationEvidenceRecord(
        evidence_id="ev-base",
        manifest_digest=m_digest,
        evidence_type="audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluated_component_ids={"c1"},
        evaluator_id="eval-1",
        evaluator_issuer="IdP-1",
        evaluated_at_utc="2026-05-02T00:00:00Z",
        metadata={"key": "val1"}
    )
    assert ev_mod4.compute_signature_payload() != base_payload

    # Status change
    ev_mod5 = VerificationEvidenceRecord(
        evidence_id="ev-base",
        manifest_digest=m_digest,
        evidence_type="audit",
        status=EvidenceVerificationStatus.PARTIAL,
        artifact_digest=art_digest,
        evaluated_component_ids={"c1"},
        evaluator_id="eval-1",
        evaluator_issuer="IdP-1",
        evaluated_at_utc="2026-05-01T00:00:00Z",
        metadata={"key": "val1"}
    )
    assert ev_mod5.compute_signature_payload() != base_payload

    # Artifact digest change
    ev_mod6 = VerificationEvidenceRecord(
        evidence_id="ev-base",
        manifest_digest=m_digest,
        evidence_type="audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="f" * 64,
        evaluated_component_ids={"c1"},
        evaluator_id="eval-1",
        evaluator_issuer="IdP-1",
        evaluated_at_utc="2026-05-01T00:00:00Z",
        metadata={"key": "val1"}
    )
    assert ev_mod6.compute_signature_payload() != base_payload


def test_release_approval_record_validation_and_expiration():
    m_digest = "a" * 64
    ev_digest1 = "1" * 64
    ev_digest2 = "2" * 64

    # Validation of fields
    for bad in [None, "", "   ", 123]:
        with pytest.raises(ValueError, match="ReleaseApprovalRecord: approval_id must be a non-empty string"):
            ReleaseApprovalRecord(
                approval_id=bad,
                manifest_digest=m_digest,
                approver_id="alice",
                approver_issuer="IdP",
                policy_version="1.0",
                required_evidence_digests=[ev_digest1]
            )

        with pytest.raises(ValueError, match="ReleaseApprovalRecord: approver_id must be a non-empty string"):
            ReleaseApprovalRecord(
                approval_id="appr-1",
                manifest_digest=m_digest,
                approver_id=bad,
                approver_issuer="IdP",
                policy_version="1.0",
                required_evidence_digests=[ev_digest1]
            )

        with pytest.raises(ValueError, match="ReleaseApprovalRecord: approver_issuer must be a non-empty string"):
            ReleaseApprovalRecord(
                approval_id="appr-1",
                manifest_digest=m_digest,
                approver_id="alice",
                approver_issuer=bad,
                policy_version="1.0",
                required_evidence_digests=[ev_digest1]
            )

        with pytest.raises(ValueError, match="ReleaseApprovalRecord: policy_version must be a non-empty string"):
            ReleaseApprovalRecord(
                approval_id="appr-1",
                manifest_digest=m_digest,
                approver_id="alice",
                approver_issuer="IdP",
                policy_version=bad,
                required_evidence_digests=[ev_digest1]
            )

    # Evidence digest ordering in payload
    appr_order1 = ReleaseApprovalRecord(
        approval_id="appr-1",
        manifest_digest=m_digest,
        approver_id="alice",
        approver_issuer="IdP",
        policy_version="1.0",
        required_evidence_digests=[ev_digest1, ev_digest2],
        timestamp=1000.0,
        expires_at=2000.0
    )
    appr_order2 = ReleaseApprovalRecord(
        approval_id="appr-1",
        manifest_digest=m_digest,
        approver_id="alice",
        approver_issuer="IdP",
        policy_version="1.0",
        required_evidence_digests=[ev_digest2, ev_digest1],
        timestamp=1000.0,
        expires_at=2000.0
    )
    assert appr_order1.compute_signature_payload() == appr_order2.compute_signature_payload()

    # is_expired behavior: no expiry, before expiry, at/after expiry
    appr_no_exp = ReleaseApprovalRecord(
        approval_id="appr-no-exp",
        manifest_digest=m_digest,
        approver_id="alice",
        approver_issuer="IdP",
        policy_version="1.0",
        required_evidence_digests=[ev_digest1],
        expires_at=None
    )
    assert appr_no_exp.is_expired() is False
    assert appr_no_exp.is_expired(current_time=999999999.0) is False

    appr_with_exp = ReleaseApprovalRecord(
        approval_id="appr-exp",
        manifest_digest=m_digest,
        approver_id="alice",
        approver_issuer="IdP",
        policy_version="1.0",
        required_evidence_digests=[ev_digest1],
        expires_at=1500.0
    )
    assert appr_with_exp.is_expired(current_time=1499.9) is False
    assert appr_with_exp.is_expired(current_time=1500.0) is True  # exact boundary
    assert appr_with_exp.is_expired(current_time=1500.1) is True

    # to_dict serialization
    d = appr_with_exp.to_dict()
    assert isinstance(d, dict)
    assert d["approval_id"] == "appr-exp"
    assert d["expires_at"] == 1500.0


def test_release_approval_record_expires_at_numeric_validation():
    """Validates that expires_at strictly enforces numeric finite boundaries and prevents overflow."""
    m_digest = "a" * 64
    ev_digest = "b" * 64

    # Non-numeric types and booleans rejected
    for bad_exp in [True, False, "1500.0", [1500.0], {"exp": 1500.0}]:
        with pytest.raises(TypeError, match="expires_at must be a numeric timestamp"):
            ReleaseApprovalRecord(
                approval_id="appr-bad-type",
                manifest_digest=m_digest,
                approver_id="alice",
                approver_issuer="IdP",
                policy_version="1.0",
                required_evidence_digests=[ev_digest],
                expires_at=bad_exp
            )

    # Non-finite floats rejected
    for bad_float in [float("nan"), float("inf"), float("-inf")]:
        with pytest.raises(ValueError, match="expires_at must be a finite number"):
            ReleaseApprovalRecord(
                approval_id="appr-bad-float",
                manifest_digest=m_digest,
                approver_id="alice",
                approver_issuer="IdP",
                policy_version="1.0",
                required_evidence_digests=[ev_digest],
                expires_at=bad_float
            )

    # Floats exceeding magnitude bound rejected (both positive and negative)
    for bad_mag in [1e25, -1e25, 1e100, -1e100]:
        with pytest.raises(ValueError, match="expires_at float overflows magnitude limits"):
            ReleaseApprovalRecord(
                approval_id="appr-bad-mag",
                manifest_digest=m_digest,
                approver_id="alice",
                approver_issuer="IdP",
                policy_version="1.0",
                required_evidence_digests=[ev_digest],
                expires_at=bad_mag
            )

    # Oversized integer rejected to prevent float conversion OverflowError
    with pytest.raises(ValueError, match="expires_at integer overflows 64-bit limits"):
        ReleaseApprovalRecord(
            approval_id="appr-overflow",
            manifest_digest=m_digest,
            approver_id="alice",
            approver_issuer="IdP",
            policy_version="1.0",
            required_evidence_digests=[ev_digest],
            expires_at=10**1000
        )

    # Valid integer and float within 64-bit bounds pass and compute signature payload cleanly
    for valid_exp in [1500, 1500.5, (1 << 63) - 1]:
        appr_valid = ReleaseApprovalRecord(
            approval_id="appr-valid-num",
            manifest_digest=m_digest,
            approver_id="alice",
            approver_issuer="IdP",
            policy_version="1.0",
            required_evidence_digests=[ev_digest],
            expires_at=valid_exp
        )
        payload = appr_valid.compute_signature_payload()
        assert isinstance(payload, bytes)
        assert b"expires_at" in payload


def test_release_approval_record_timestamp_numeric_validation():
    """Validates that timestamp strictly enforces numeric type, boolean rejection, finiteness, and magnitude."""
    m_digest = "a" * 64
    ev_digest = "b" * 64

    # Non-numeric types and booleans rejected
    for bad_ts in [True, False, "1000.0", [1000.0], {"ts": 1000.0}]:
        with pytest.raises(TypeError, match="timestamp must be a numeric timestamp"):
            ReleaseApprovalRecord(
                approval_id="appr-bad-ts-type",
                manifest_digest=m_digest,
                approver_id="alice",
                approver_issuer="IdP",
                policy_version="1.0",
                required_evidence_digests=[ev_digest],
                timestamp=bad_ts
            )

    # Non-finite floats rejected
    for bad_float in [float("nan"), float("inf"), float("-inf")]:
        with pytest.raises(ValueError, match="timestamp must be a finite number"):
            ReleaseApprovalRecord(
                approval_id="appr-bad-ts-float",
                manifest_digest=m_digest,
                approver_id="alice",
                approver_issuer="IdP",
                policy_version="1.0",
                required_evidence_digests=[ev_digest],
                timestamp=bad_float
            )

    # Floats exceeding magnitude bound rejected (both positive and negative)
    for bad_mag in [1e25, -1e25, 1e100, -1e100]:
        with pytest.raises(ValueError, match="timestamp float overflows magnitude limits"):
            ReleaseApprovalRecord(
                approval_id="appr-bad-ts-mag",
                manifest_digest=m_digest,
                approver_id="alice",
                approver_issuer="IdP",
                policy_version="1.0",
                required_evidence_digests=[ev_digest],
                timestamp=bad_mag
            )

    # Oversized integer rejected to prevent float conversion OverflowError
    with pytest.raises(ValueError, match="timestamp integer overflows 64-bit limits"):
        ReleaseApprovalRecord(
            approval_id="appr-ts-overflow",
            manifest_digest=m_digest,
            approver_id="alice",
            approver_issuer="IdP",
            policy_version="1.0",
            required_evidence_digests=[ev_digest],
            timestamp=10**1000
        )

    # Valid integer and float timestamp pass and compute signature payload cleanly
    for valid_ts in [1000, 1000.5, (1 << 63) - 1]:
        appr_valid = ReleaseApprovalRecord(
            approval_id="appr-valid-ts",
            manifest_digest=m_digest,
            approver_id="alice",
            approver_issuer="IdP",
            policy_version="1.0",
            required_evidence_digests=[ev_digest],
            timestamp=valid_ts
        )
        payload = appr_valid.compute_signature_payload()
        assert isinstance(payload, bytes)
        assert b"timestamp" in payload

    # Revalidation upon post-construction mutation in compute_signature_payload
    appr_mutate = ReleaseApprovalRecord(
        approval_id="appr-mutate",
        manifest_digest=m_digest,
        approver_id="alice",
        approver_issuer="IdP",
        policy_version="1.0",
        required_evidence_digests=[ev_digest],
        timestamp=1000.0,
        expires_at=2000.0
    )
    appr_mutate.timestamp = 10**1000
    with pytest.raises(ValueError, match="timestamp integer overflows 64-bit limits"):
        appr_mutate.compute_signature_payload()

    appr_mutate.timestamp = 1000.0
    appr_mutate.expires_at = 1e25
    with pytest.raises(ValueError, match="expires_at float overflows magnitude limits"):
        appr_mutate.compute_signature_payload()


def test_release_approval_record_is_expired_invalid_clock_fail_closed():
    """Validates that is_expired fails closed when given invalid or overflowing current_time."""
    m_digest = "a" * 64
    ev_digest = "b" * 64

    appr = ReleaseApprovalRecord(
        approval_id="appr-clock-test",
        manifest_digest=m_digest,
        approver_id="alice",
        approver_issuer="IdP",
        policy_version="1.0",
        required_evidence_digests=[ev_digest],
        expires_at=2000.0
    )

    # Valid times behave normally
    assert appr.is_expired(current_time=1999.0) is False
    assert appr.is_expired(current_time=2000.0) is True

    # Invalid clock types fail closed (treated as expired)
    assert appr.is_expired(current_time=True) is True
    assert appr.is_expired(current_time=False) is True
    assert appr.is_expired(current_time="1000.0") is True
    assert appr.is_expired(current_time=[1000.0]) is True

    # Non-finite clock floats fail closed
    assert appr.is_expired(current_time=float("nan")) is True
    assert appr.is_expired(current_time=float("inf")) is True
    assert appr.is_expired(current_time=float("-inf")) is True

    # Oversized integer clock fail closed
    assert appr.is_expired(current_time=10**1000) is True

    # Mutated expires_at fail-closed checks (NaN, inf, -inf, oversized int, non-numeric, out-of-range float)
    appr_mut_exp = ReleaseApprovalRecord(
        approval_id="appr-mut-exp",
        manifest_digest=m_digest,
        approver_id="alice",
        approver_issuer="IdP",
        policy_version="1.0",
        required_evidence_digests=[ev_digest],
        expires_at=2000.0
    )
    # Valid baseline
    assert appr_mut_exp.is_expired(current_time=1500.0) is False

    # NaN mutation fails closed
    appr_mut_exp.expires_at = float("nan")
    assert appr_mut_exp.is_expired(current_time=1500.0) is True

    # Infinity / -Infinity mutations fail closed
    appr_mut_exp.expires_at = float("inf")
    assert appr_mut_exp.is_expired(current_time=1500.0) is True
    appr_mut_exp.expires_at = float("-inf")
    assert appr_mut_exp.is_expired(current_time=1500.0) is True

    # Oversized integer mutation fails closed
    appr_mut_exp.expires_at = 10**1000
    assert appr_mut_exp.is_expired(current_time=1500.0) is True

    # Non-numeric and boolean mutations fail closed
    appr_mut_exp.expires_at = "not-a-number"
    assert appr_mut_exp.is_expired(current_time=1500.0) is True
    appr_mut_exp.expires_at = True
    assert appr_mut_exp.is_expired(current_time=1500.0) is True
    appr_mut_exp.expires_at = [1500.0]
    assert appr_mut_exp.is_expired(current_time=1500.0) is True

    # Float exceeding magnitude bounds fails closed
    appr_mut_exp.expires_at = 1e25
    assert appr_mut_exp.is_expired(current_time=1500.0) is True
    appr_mut_exp.expires_at = -1e25
    assert appr_mut_exp.is_expired(current_time=1500.0) is True


# ==============================================================================
# Invalidation Coverage Expansion: EvidenceInvalidator
# ==============================================================================

def test_evidence_invalidator_comprehensive():
    # 1. Identical manifests: test can_authorize_without_rerun (True and False)
    m_base = create_sample_manifest()
    m_digest = m_base.compute_manifest_digest()

    ev_pass1 = VerificationEvidenceRecord(
        evidence_id="ev-pass1",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1" * 64
    )
    ev_pass2 = VerificationEvidenceRecord(
        evidence_id="ev-pass2",
        manifest_digest=m_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="2" * 64
    )
    # Both required evidence types provided -> can_authorize_without_rerun = True
    report_identical_complete = EvidenceInvalidator.analyze_change(m_base, m_base, [ev_pass1, ev_pass2])
    assert report_identical_complete.is_identical is True
    assert report_identical_complete.can_authorize_without_rerun is True
    assert len(report_identical_complete.missing_evidence_types) == 0
    assert len(report_identical_complete.retained_evidence) == 2
    assert len(report_identical_complete.invalidated_evidence) == 0

    # Missing one required type -> can_authorize_without_rerun = False
    report_identical_partial = EvidenceInvalidator.analyze_change(m_base, m_base, [ev_pass1])
    assert report_identical_partial.is_identical is True
    assert report_identical_partial.can_authorize_without_rerun is False
    assert report_identical_partial.missing_evidence_types == {"clinical_diagnostic_benchmark"}
    assert len(report_identical_partial.retained_evidence) == 1

    # 2. Manifest deltas: policy change, runtime identity change, added component, removed component
    # Also modified component across all types: model, runtime, dependency, infrastructure, config_change
    c_model = ComponentSpec("c_model", "model", "1.0.0", "1" * 64)
    c_runtime = ComponentSpec("c_runtime", "runtime", "1.0.0", "2" * 64)
    c_dep = ComponentSpec("c_dep", "dependency", "1.0.0", "3" * 64)
    c_infra = ComponentSpec("c_infra", "infrastructure", "1.0.0", "4" * 64)
    c_other = ComponentSpec("c_other", "dataset", "1.0.0", "5" * 64, config_digest="a" * 64)
    c_removed = ComponentSpec("c_removed", "tool", "1.0.0", "6" * 64)

    m_old = ReleaseManifest(
        schema_version="1.0.0",
        release_id="rel-old",
        target_environment="prod",
        components=[c_model, c_runtime, c_dep, c_infra, c_other, c_removed],
        runtime_identity="runtime-v1",
        policy_version="1.0.0",
        policy_digest="7" * 64,
        required_evidence_types={"layer4_security_audit", "clinical_diagnostic_benchmark"}
    )

    c_model_new = ComponentSpec("c_model", "model", "1.0.1", "1" * 64)
    c_runtime_new = ComponentSpec("c_runtime", "runtime", "1.0.0", "8" * 64)
    c_dep_new = ComponentSpec("c_dep", "dependency", "1.0.0", "9" * 64)
    c_infra_new = ComponentSpec("c_infra", "infrastructure", "1.0.0", "0" * 64)
    c_other_new = ComponentSpec("c_other", "dataset", "1.0.0", "5" * 64, config_digest="b" * 64)
    c_added = ComponentSpec("c_added", "tool", "1.0.0", "e" * 64)

    m_new = ReleaseManifest(
        schema_version="1.0.0",
        release_id="rel-new",
        target_environment="prod",
        components=[c_model_new, c_runtime_new, c_dep_new, c_infra_new, c_other_new, c_added],
        runtime_identity="runtime-v2",
        policy_version="2.0.0",
        policy_digest="f" * 64,
        required_evidence_types={"layer4_security_audit", "clinical_diagnostic_benchmark"}
    )

    new_digest = m_new.compute_manifest_digest()
    old_digest = m_old.compute_manifest_digest()

    ev_touches_affected = VerificationEvidenceRecord(
        evidence_id="ev-touches",
        manifest_digest=new_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1" * 64,
        evaluated_component_ids={"c_model"}
    )
    ev_bound_old = VerificationEvidenceRecord(
        evidence_id="ev-bound-old",
        manifest_digest=old_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="2" * 64,
        evaluated_component_ids=set()
    )
    ev_bound_new_pass = VerificationEvidenceRecord(
        evidence_id="ev-bound-new-pass",
        manifest_digest=new_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="3" * 64,
        evaluated_component_ids=set()
    )
    ev_bound_new_fail = VerificationEvidenceRecord(
        evidence_id="ev-bound-new-fail",
        manifest_digest=new_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.FAIL,
        artifact_digest="4" * 64,
        evaluated_component_ids=set()
    )
    ev_foreign = VerificationEvidenceRecord(
        evidence_id="ev-foreign",
        manifest_digest="9" * 64,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="5" * 64,
        evaluated_component_ids=set()
    )

    report = EvidenceInvalidator.analyze_change(
        m_old,
        m_new,
        [ev_touches_affected, ev_bound_old, ev_bound_new_pass, ev_bound_new_fail, ev_foreign]
    )

    assert report.is_identical is False
    delta_cats = {d.component_id: d.change_category for d in report.component_deltas}
    assert delta_cats["policy"] == ChangeCategory.POLICY_CHANGE
    assert delta_cats["runtime"] == ChangeCategory.RUNTIME_CHANGE
    assert delta_cats["c_removed"] == ChangeCategory.COMPONENT_REMOVED
    assert delta_cats["c_added"] == ChangeCategory.COMPONENT_ADDED
    assert delta_cats["c_model"] == ChangeCategory.MODEL_CHANGE
    assert delta_cats["c_runtime"] == ChangeCategory.RUNTIME_CHANGE
    assert delta_cats["c_dep"] == ChangeCategory.DEPENDENCY_CHANGE
    assert delta_cats["c_infra"] == ChangeCategory.INFRASTRUCTURE_CHANGE
    assert delta_cats["c_other"] == ChangeCategory.CONFIG_CHANGE

    assert report.affected_component_ids == {
        "policy", "runtime", "c_removed", "c_added", "c_model",
        "c_runtime", "c_dep", "c_infra", "c_other"
    }

    assert ev_bound_new_pass in report.retained_evidence
    assert ev_touches_affected in report.invalidated_evidence
    assert ev_bound_old in report.invalidated_evidence
    assert ev_bound_new_fail in report.invalidated_evidence
    assert ev_foreign in report.invalidated_evidence

    assert report.can_authorize_without_rerun is False
    assert "clinical_diagnostic_benchmark" in report.missing_evidence_types


# ==============================================================================
# Engine Coverage Expansion: verify_single_evidence, verify_release_approval,
# Audit Behavior, and analyze_change_impact
# ==============================================================================

def test_engine_verify_single_evidence_coverage():
    import base64
    auth = MockReleaseAuthority(issuer_id="EvaluatorIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"EvaluatorIdP": auth.public_key})
    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    art_bytes = b"TEST ART BYTES"
    art_digest = hashlib.sha256(art_bytes).hexdigest()

    # 1. require_artifact_bytes_verification=False with optional provider
    engine_no_art_req = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False
    )
    ev = VerificationEvidenceRecord(
        evidence_id="ev-1",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest
    )

    # Optional provider returning matching bytes
    res_match = engine_no_art_req.verify_single_evidence(
        m_digest, ev, artifact_bytes_provider=lambda eid: art_bytes
    )
    assert res_match.status == EvidenceValidationResultStatus.VERIFIED
    assert res_match.artifact_bytes_verified is True

    # Optional provider returning mismatched bytes
    res_mismatch = engine_no_art_req.verify_single_evidence(
        m_digest, ev, artifact_bytes_provider=lambda eid: b"WRONG BYTES"
    )
    assert res_mismatch.status == EvidenceValidationResultStatus.REJECTED
    assert "artifact byte digest mismatch" in res_mismatch.reason

    # Optional provider returning None
    res_none = engine_no_art_req.verify_single_evidence(
        m_digest, ev, artifact_bytes_provider=lambda eid: None
    )
    assert res_none.status == EvidenceValidationResultStatus.VERIFIED
    assert res_none.artifact_bytes_verified is False

    # 2. Evaluator signatures under mandatory policy:
    # - Missing PrincipalVerifier on engine
    engine_no_verifier = ReleaseGovernanceEngine(
        principal_verifier=None,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=True
    )
    ev_signed = VerificationEvidenceRecord(
        evidence_id="ev-signed",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluator_issuer="EvaluatorIdP"
    )
    auth.sign_evidence(ev_signed)
    res_no_ver = engine_no_verifier.verify_single_evidence(m_digest, ev_signed)
    assert res_no_ver.status == EvidenceValidationResultStatus.REJECTED
    assert "engine has no PrincipalVerifier" in res_no_ver.reason

    # - Malformed signature encoding (e.g. 128 non-hex chars)
    engine_with_ver = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=True
    )
    ev_malformed_sig = VerificationEvidenceRecord(
        evidence_id="ev-mal",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluator_issuer="EvaluatorIdP",
        signature="Z" * 128
    )
    res_mal = engine_with_ver.verify_single_evidence(m_digest, ev_malformed_sig)
    assert res_mal.status == EvidenceValidationResultStatus.REJECTED
    assert "malformed signature encoding" in res_mal.reason

    # - Valid signature in Base64 encoding
    ev_b64 = VerificationEvidenceRecord(
        evidence_id="ev-b64",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluator_issuer="EvaluatorIdP"
    )
    payload = ev_b64.compute_signature_payload()
    sig_raw = _ed25519_sign(payload, auth.private_seed, auth.public_key)
    ev_b64.signature = base64.b64encode(sig_raw).decode("utf-8")
    res_b64 = engine_with_ver.verify_single_evidence(m_digest, ev_b64)
    assert res_b64.status == EvidenceValidationResultStatus.VERIFIED
    assert res_b64.evaluator_signature_verified is True

    # 3. Evaluator signatures under optional policy (require_evaluator_signatures=False)
    # - Declares evaluator_issuer but no signature
    engine_opt_sig = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False
    )
    ev_opt_issuer_no_sig = VerificationEvidenceRecord(
        evidence_id="ev-opt-1",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluator_issuer="EvaluatorIdP",
        signature=None
    )
    res_opt1 = engine_opt_sig.verify_single_evidence(m_digest, ev_opt_issuer_no_sig)
    assert res_opt1.status == EvidenceValidationResultStatus.REJECTED
    assert "declares evaluator_issuer but has no signature" in res_opt1.reason

    # - Has signature but engine has no PrincipalVerifier
    engine_opt_no_ver = ReleaseGovernanceEngine(
        principal_verifier=None,
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False
    )
    ev_opt_has_sig = VerificationEvidenceRecord(
        evidence_id="ev-opt-2",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluator_issuer="EvaluatorIdP",
        signature="a" * 128
    )
    res_opt2 = engine_opt_no_ver.verify_single_evidence(m_digest, ev_opt_has_sig)
    assert res_opt2.status == EvidenceValidationResultStatus.REJECTED
    assert "engine has no PrincipalVerifier" in res_opt2.reason

    # - Has signature but missing evaluator_issuer
    ev_opt_no_iss = VerificationEvidenceRecord(
        evidence_id="ev-opt-3",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluator_issuer=None,
        signature="a" * 128
    )
    res_opt3 = engine_opt_sig.verify_single_evidence(m_digest, ev_opt_no_iss)
    assert res_opt3.status == EvidenceValidationResultStatus.REJECTED
    assert "missing evaluator_issuer" in res_opt3.reason

    # - Untrusted evaluator issuer
    ev_opt_untrusted = VerificationEvidenceRecord(
        evidence_id="ev-opt-4",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluator_issuer="UntrustedIdP",
        signature="a" * 128
    )
    res_opt4 = engine_opt_sig.verify_single_evidence(m_digest, ev_opt_untrusted)
    assert res_opt4.status == EvidenceValidationResultStatus.REJECTED
    assert "untrusted evaluator issuer 'UntrustedIdP'" in res_opt4.reason

    # - Malformed signature encoding under optional policy
    ev_opt_mal = VerificationEvidenceRecord(
        evidence_id="ev-opt-5",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluator_issuer="EvaluatorIdP",
        signature="Z" * 128
    )
    res_opt5 = engine_opt_sig.verify_single_evidence(m_digest, ev_opt_mal)
    assert res_opt5.status == EvidenceValidationResultStatus.REJECTED
    assert "malformed signature encoding" in res_opt5.reason

    # - Cryptographic signature verification failed under optional policy
    ev_opt_bad_crypto = VerificationEvidenceRecord(
        evidence_id="ev-opt-6",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest=art_digest,
        evaluator_issuer="EvaluatorIdP",
        signature="0" * 128
    )
    res_opt6 = engine_opt_sig.verify_single_evidence(m_digest, ev_opt_bad_crypto)
    assert res_opt6.status == EvidenceValidationResultStatus.REJECTED
    assert "cryptographic evaluator signature verification failed" in res_opt6.reason

    # - Valid signature in optional policy verifies successfully
    auth.sign_evidence(ev_opt_bad_crypto)  # produces valid signature
    res_opt_ok = engine_opt_sig.verify_single_evidence(m_digest, ev_opt_bad_crypto)
    assert res_opt_ok.status == EvidenceValidationResultStatus.VERIFIED
    assert res_opt_ok.evaluator_signature_verified is True


def test_engine_verify_release_approval_rejection_boundaries():
    import base64
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev1 = VerificationEvidenceRecord(
        evidence_id="ev-1",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="1" * 64
    )
    ev2 = VerificationEvidenceRecord(
        evidence_id="ev-2",
        manifest_digest=m_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="2" * 64
    )
    ev_digests = [ev1.compute_evidence_digest(), ev2.compute_evidence_digest()]

    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"],
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )

    # 1. Approval expired check
    appr_expired = ReleaseApprovalRecord(
        approval_id="appr-exp",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=ev_digests,
        expires_at=1000.0
    )
    auth.sign_approval(appr_expired)
    res_exp = engine.verify_release_approval(
        manifest, appr_expired, [ev1, ev2], current_time=1000.0
    )
    assert res_exp.is_verified is False
    assert "has expired" in res_exp.reason

    # 2. Approval references an unresolved evidence digest
    appr_unresolved = ReleaseApprovalRecord(
        approval_id="appr-unres",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=[ev_digests[0], "f" * 64]
    )
    auth.sign_approval(appr_unresolved)
    res_unres = engine.verify_release_approval(manifest, appr_unresolved, [ev1, ev2])
    assert res_unres.is_verified is False
    assert "Approval references evidence digests not present in verified records" in res_unres.reason

    # 3. Missing or invalid signature (None or non-string)
    appr_no_sig = ReleaseApprovalRecord(
        approval_id="appr-no-sig",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=ev_digests,
        signature=None
    )
    res_no_sig = engine.verify_release_approval(manifest, appr_no_sig, [ev1, ev2])
    assert res_no_sig.is_verified is False
    assert "Missing or invalid signature" in res_no_sig.reason

    appr_non_str_sig = ReleaseApprovalRecord(
        approval_id="appr-non-str-sig",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=ev_digests,
        signature=12345  # type: ignore
    )
    res_non_str = engine.verify_release_approval(manifest, appr_non_str_sig, [ev1, ev2])
    assert res_non_str.is_verified is False
    assert "Missing or invalid signature" in res_non_str.reason

    # 4. Engine has no configured PrincipalVerifier
    engine_no_ver = ReleaseGovernanceEngine(
        principal_verifier=None,
        allowed_approver_principals=["reviewer_alice"],
        require_artifact_bytes_verification=False,
        require_evaluator_signatures=False,
        fail_closed_audit=False
    )
    appr_valid_sig = ReleaseApprovalRecord(
        approval_id="appr-ok",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=ev_digests
    )
    auth.sign_approval(appr_valid_sig)
    res_no_eng_ver = engine_no_ver.verify_release_approval(manifest, appr_valid_sig, [ev1, ev2])
    assert res_no_eng_ver.is_verified is False
    assert "ReleaseGovernanceEngine has no configured PrincipalVerifier to verify signature" in res_no_eng_ver.reason

    # 5. Untrusted approver issuer
    appr_untrusted_iss = ReleaseApprovalRecord(
        approval_id="appr-untrusted-iss",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="RogueIdP",
        policy_version="1.0.0",
        required_evidence_digests=ev_digests
    )
    auth.sign_approval(appr_untrusted_iss)
    res_untrusted = engine.verify_release_approval(manifest, appr_untrusted_iss, [ev1, ev2])
    assert res_untrusted.is_verified is False
    assert "Untrusted identity issuer 'RogueIdP'" in res_untrusted.reason

    # 6. Malformed signature encoding (e.g. 128 non-hex chars)
    appr_malformed = ReleaseApprovalRecord(
        approval_id="appr-malformed",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=ev_digests,
        signature="Z" * 128
    )
    res_malformed = engine.verify_release_approval(manifest, appr_malformed, [ev1, ev2])
    assert res_malformed.is_verified is False
    assert "Malformed signature encoding" in res_malformed.reason

    # 7. Signature length invalid (!= 64 bytes)
    # Valid base64 encoding of 32 bytes (instead of 64 bytes)
    appr_bad_len = ReleaseApprovalRecord(
        approval_id="appr-bad-len",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=ev_digests,
        signature=base64.b64encode(b"A" * 32).decode("utf-8")
    )
    res_bad_len = engine.verify_release_approval(manifest, appr_bad_len, [ev1, ev2])
    assert res_bad_len.is_verified is False
    assert "Signature length invalid (32 bytes, expected 64)" in res_bad_len.reason

    # 8. Valid signature in Base64 encoding succeeds
    payload = appr_valid_sig.compute_signature_payload()
    sig_raw = _ed25519_sign(payload, auth.private_seed, auth.public_key)
    appr_valid_sig.signature = base64.b64encode(sig_raw).decode("utf-8")
    res_b64_ok = engine.verify_release_approval(manifest, appr_valid_sig, [ev1, ev2])
    assert res_b64_ok.is_verified is True
    assert "successfully verified" in res_b64_ok.reason


def test_engine_audit_behavior_and_change_impact_wrapper():
    # 1. Non-fail-closed audit with no configured audit_trail
    engine_no_trail = ReleaseGovernanceEngine(
        audit_trail=None,
        fail_closed_audit=False
    )
    # Should not raise any error when logging
    engine_no_trail._log_event(AuditLogLevel.INFO, "TEST_EVENT", {"reason": "test"})

    # 2. Non-fail-closed audit with audit_trail that raises an exception -> swallowed
    class FaultyAuditTrail:
        def record_event(self, *args, **kwargs):
            raise OSError("Simulated disk error")

    engine_faulty = ReleaseGovernanceEngine(
        audit_trail=FaultyAuditTrail(),  # type: ignore
        fail_closed_audit=False
    )
    # Swallowed without raising
    engine_faulty._log_event(AuditLogLevel.INFO, "TEST_EVENT", {"reason": "test"})

    # 3. analyze_change_impact wrapper delegation
    m1 = create_sample_manifest()
    m2 = create_sample_manifest(model_digest="9" * 64)
    report = engine_no_trail.analyze_change_impact(m1, m2, available_evidence=[])
    assert isinstance(report, ChangeImpactReport)
    assert report.is_identical is False
    assert "diagnostic_model" in report.affected_component_ids
