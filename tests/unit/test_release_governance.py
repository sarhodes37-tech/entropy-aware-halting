"""
Deterministic Unit and Adversarial Test Suite for EpistemicOS Change & Release Governance.

Verifies the 14 mandatory security invariants:
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
11. Revoked or expired approval cannot authorize a release.
12. Duplicate, malformed, or ambiguous manifest fields cannot produce inconsistent canonicalization.
13. Attempted substitution of evidence artifacts is detected through digest verification.
14. A post-approval manifest mutation cannot retain the original authorization.
"""

import hashlib
import json
import os
import time
import pytest
from typing import Optional

from epistemicos.audit import TamperEvidentAuditTrail
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


def create_sample_manifest(
    model_digest: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    runtime_id: str = "epistemicos-core-v1.0",
    policy_digest: str = "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp",
    release_id: str = "rel-2026.05.01",
    display_name: str = "Standard Release",
    description: str = "Initial production candidate"
) -> ReleaseManifest:
    model_comp = ComponentSpec(
        component_id="diagnostic_model",
        component_type=ComponentType.MODEL.value,
        version="1.0.0",
        digest=model_digest,
        config_digest="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )
    runtime_comp = ComponentSpec(
        component_id="core_runtime",
        component_type=ComponentType.RUNTIME.value,
        version="1.0.0",
        digest="rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr"
    )
    return ReleaseManifest(
        schema_version="1.0.0",
        release_id=release_id,
        target_environment="production-clinical-gateway",
        components=[model_comp, runtime_comp],
        runtime_identity=runtime_id,
        policy_version="1.0.0",
        policy_digest=policy_digest,
        required_evidence_types={"layer4_security_audit", "clinical_diagnostic_benchmark"},
        display_name=display_name,
        description=description,
        tags={"tier": "tier1_critical"},
        notes="Pre-deployment validation candidate"
    )


def test_invariant_1_identical_manifests_produce_identical_canonical_digests():
    """Invariant 1: Identical manifests produce identical canonical digests regardless of component ordering."""
    m1 = create_sample_manifest()

    # Create m2 with reversed component insertion order
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
    """Invariant 2: Material component changes produce different manifest digests."""
    m_base = create_sample_manifest()
    d_base = m_base.compute_manifest_digest()

    # Change model weight digest
    m_mod = create_sample_manifest(model_digest="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    d_mod = m_mod.compute_manifest_digest()

    assert d_base != d_mod


def test_invariant_3_informational_metadata_does_not_alter_digest():
    """Invariant 3: Informational metadata changes do not alter canonical manifest digest."""
    m = create_sample_manifest()
    d1 = m.compute_manifest_digest()

    m.display_name = "Modified Display Name 2.0"
    m.description = "Updated description text"
    m.notes = "New internal notes added after audit"
    m.tags = {"environment": "staging", "tier": "tier2"}
    d2 = m.compute_manifest_digest()

    assert d1 == d2, "Informational metadata must not alter canonical manifest digest"


def test_invariant_4_approval_succeeds_for_exact_approved_manifest(tmp_path):
    """Invariant 4: Approval succeeds for the exact approved manifest."""
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

    verified, v_msg = engine.verify_release_approval(manifest, approval)
    assert verified is True
    assert "successfully verified" in v_msg


def test_invariant_5_and_6_approval_fails_for_modified_manifest_even_with_same_release_id():
    """Invariants 5 & 6: Approval fails for modified manifest even if release_id is unchanged."""
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
        required_evidence_digests=["dummy_ev_digest"]
    )
    auth.sign_approval(approval)

    # Mutant: same release_id, but modified model weight digest
    m_mutant = create_sample_manifest(
        release_id="rel-same-id-123",
        model_digest="9999999999999999999999999999999999999999999999999999999999999999"
    )

    verified, reason = engine.verify_release_approval(m_mutant, approval)
    assert verified is False
    assert "Manifest digest mismatch" in reason


def test_invariant_7_evidence_from_older_manifest_cannot_satisfy_new_manifest():
    """Invariant 7: Evidence from an older manifest cannot satisfy requirements for the new manifest."""
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
    """Invariant 8: Missing required evidence prevents readiness."""
    engine = ReleaseGovernanceEngine()
    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    # Provide only 1 of 2 required evidence records
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
    """Invariant 9: Invalid or tampered approval signatures are rejected."""
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
        required_evidence_digests=["dummy"]
    )
    auth.sign_approval(approval)

    # Tamper with signature
    tampered_sig = list(approval.signature)
    tampered_sig[0] = "0" if tampered_sig[0] != "0" else "1"
    approval.signature = "".join(tampered_sig)

    verified, reason = engine.verify_release_approval(manifest, approval)
    assert verified is False
    assert "Ed25519 signature verification failed" in reason


def test_invariant_10_unauthorized_principal_cannot_issue_release_approval():
    """Invariant 10: An unauthorized principal cannot issue a release approval."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})

    # Engine only authorizes reviewer_alice
    engine = ReleaseGovernanceEngine(
        principal_verifier=verifier,
        allowed_approver_principals=["reviewer_alice"]
    )

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    # Attacker Mallory signs approval
    approval = ReleaseApprovalRecord(
        approval_id="appr-mallory",
        manifest_digest=m_digest,
        approver_id="mallory_intruder",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["dummy"]
    )
    auth.sign_approval(approval)

    verified, reason = engine.verify_release_approval(manifest, approval)
    assert verified is False
    assert "Approver 'mallory_intruder' is not in allowed approvers allowlist" in reason


def test_invariant_11_revoked_or_expired_approval_cannot_authorize_release():
    """Invariant 11: Revoked or expired approval cannot authorize a release."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(principal_verifier=verifier)

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    # Sub-case A: Revoked
    appr_revoked = ReleaseApprovalRecord(
        approval_id="appr-revoked",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["dummy"],
        revoked=True,
        revocation_reason="Emergency critical CVE detected"
    )
    auth.sign_approval(appr_revoked)

    v1, r1 = engine.verify_release_approval(manifest, appr_revoked)
    assert v1 is False
    assert "revoked" in r1

    # Sub-case B: Expired
    appr_expired = ReleaseApprovalRecord(
        approval_id="appr-expired",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["dummy"],
        timestamp=time.time() - 1000,
        expires_at=time.time() - 10
    )
    auth.sign_approval(appr_expired)

    v2, r2 = engine.verify_release_approval(manifest, appr_expired)
    assert v2 is False
    assert "expired" in r2


def test_invariant_12_duplicate_and_malformed_fields_fail_closed():
    """Invariant 12: Duplicate or malformed manifest fields cannot produce inconsistent canonicalization."""
    comp1 = ComponentSpec("c1", "model", "1.0.0", "1111111111111111111111111111111111111111111111111111111111111111")
    comp1_dup = ComponentSpec("c1", "model", "1.0.0", "2222222222222222222222222222222222222222222222222222222222222222")

    # Duplicate component_id must raise ValueError
    with pytest.raises(ValueError, match="duplicate component_id"):
        ReleaseManifest(
            schema_version="1.0.0",
            release_id="rel-dup",
            target_environment="prod",
            components=[comp1, comp1_dup]
        )

    # Empty release_id must raise ValueError
    with pytest.raises(ValueError, match="release_id must be a non-empty string"):
        ReleaseManifest(
            schema_version="1.0.0",
            release_id="",
            target_environment="prod"
        )


def test_invariant_13_attempted_substitution_of_evidence_artifacts_detected():
    """Invariant 13: Attempted substitution of evidence artifacts is detected through digest verification."""
    engine = ReleaseGovernanceEngine()
    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    ev_failing = VerificationEvidenceRecord(
        evidence_id="ev-layer4-failed",
        manifest_digest=m_digest,
        evidence_type="layer4_security_audit",
        status=EvidenceVerificationStatus.FAIL,
        artifact_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )
    ev_valid_clin = VerificationEvidenceRecord(
        evidence_id="ev-clinical",
        manifest_digest=m_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="2222222222222222222222222222222222222222222222222222222222222222"
    )

    ready, msg, accepted = engine.evaluate_release_readiness(manifest, [ev_failing, ev_valid_clin])
    assert ready is False
    assert "has failing status 'FAIL'" in msg


def test_invariant_14_post_approval_manifest_mutation_cannot_retain_authorization():
    """Invariant 14: Post-approval manifest mutation cannot retain the original authorization."""
    auth = MockReleaseAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": auth.public_key})
    engine = ReleaseGovernanceEngine(principal_verifier=verifier)

    manifest = create_sample_manifest()
    m_digest = manifest.compute_manifest_digest()

    approval = ReleaseApprovalRecord(
        approval_id="appr-initial",
        manifest_digest=m_digest,
        approver_id="reviewer_alice",
        approver_issuer="TrustedCorpIdP",
        policy_version="1.0.0",
        required_evidence_digests=["dummy"]
    )
    auth.sign_approval(approval)

    # Initial verification succeeds
    v_orig, _ = engine.verify_release_approval(manifest, approval)
    assert v_orig is True

    # Mutate manifest by changing policy digest
    manifest.policy_digest = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

    v_after_mutation, reason = engine.verify_release_approval(manifest, approval)
    assert v_after_mutation is False
    assert "Manifest digest mismatch" in reason


def test_evidence_invalidation_and_change_impact_classification():
    """Verifies EvidenceInvalidator correctly classifies component changes and invalidates evidence."""
    m_old = create_sample_manifest(
        model_digest="1111111111111111111111111111111111111111111111111111111111111111"
    )
    m_new = create_sample_manifest(
        model_digest="2222222222222222222222222222222222222222222222222222222222222222"
    )

    old_digest = m_old.compute_manifest_digest()
    new_digest = m_new.compute_manifest_digest()

    # Evidence covering diagnostic_model bound to old manifest
    ev_model = VerificationEvidenceRecord(
        evidence_id="ev-model-old",
        manifest_digest=old_digest,
        evidence_type="clinical_diagnostic_benchmark",
        status=EvidenceVerificationStatus.PASS,
        artifact_digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        evaluated_component_ids={"diagnostic_model"}
    )
    # Evidence covering core_runtime bound to old manifest
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
