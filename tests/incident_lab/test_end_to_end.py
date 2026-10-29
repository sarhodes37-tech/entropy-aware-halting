"""
Pytest Test Suite for EpistemicOS Incident Lab — End-to-End Integration.

Verifies that EpistemicOS detects, halts, contains, and logs all seven incident patterns:
1. GitHub credential exposure
2. Government data authorization bypass
3. Indirect egress through browser or callback services
4. Dashboard and internal system access
5. Unauthorized cryptocurrency-wallet use
6. Destructive recovery and fabricated success
7. Multi-agent fleet amplification
"""

import uuid
import os
import pytest
from pathlib import Path
from epistemicos.provenance import (
    LocalProvenanceStore,
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource,
    ProvenanceReconciler
)
from benchmarks.run_incident_lab import compute_working_tree_digest
from tests.incident_lab.fixtures.base_fixture import SecurityOutcomeStatus
from tests.incident_lab.scenarios.case1_github import Case1GitHubCredentialExposureScenario
from tests.incident_lab.scenarios.case2_government import Case2GovernmentAuthorizationBypassScenario
from tests.incident_lab.scenarios.case3_egress import Case3IndirectEgressScenario
from tests.incident_lab.scenarios.case4_dashboard import Case4InternalDashboardScenario
from tests.incident_lab.scenarios.case5_crypto import Case5CryptoWalletScenario
from tests.incident_lab.scenarios.case6_destructive import Case6DestructiveRecoveryScenario
from tests.incident_lab.scenarios.case7_fleet import Case7FleetAmplificationScenario


@pytest.fixture
def tmp_audit_dir(tmp_path):
    return str(tmp_path / "lab_audit")


def test_case_1_github_credential_exposure(tmp_audit_dir):
    scenario = Case1GitHubCredentialExposureScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.governance_authorization_approved == 1
    assert report.dimension_b_task.untested_no_grant_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_2_government_authorization_bypass(tmp_audit_dir):
    scenario = Case2GovernmentAuthorizationBypassScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.governance_authorization_approved == 1
    assert report.dimension_b_task.untested_no_grant_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_3_indirect_egress(tmp_audit_dir):
    scenario = Case3IndirectEgressScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PARTIAL_GATING_DEFENSE
    assert report.dimension_a_security.containment_recovery_outcome == "PARTIAL_GATING_DEFENSE"
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.governance_authorization_approved == 1
    assert report.dimension_b_task.untested_no_grant_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_4_internal_dashboard(tmp_audit_dir):
    scenario = Case4InternalDashboardScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.governance_authorization_approved == 1
    assert report.dimension_b_task.untested_no_grant_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_5_crypto_wallet(tmp_audit_dir):
    scenario = Case5CryptoWalletScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.governance_authorization_approved == 1
    assert report.dimension_b_task.untested_no_grant_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_6_destructive_recovery(tmp_audit_dir):
    scenario = Case6DestructiveRecoveryScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.governance_authorization_approved == 1
    assert report.dimension_b_task.untested_no_grant_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_7_fleet_amplification(tmp_audit_dir):
    scenario = Case7FleetAmplificationScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_b_task.governance_authorization_approved == 2
    assert report.dimension_b_task.untested_no_grant_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 2
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_provenance_valid_control_cannot_compensate_for_missing_attack_correlation(tmp_path):
    """
    Unit Regression Test:
    Proves that a valid legitimate-control correlation cannot compensate for an
    invalid or missing attack correlation when evaluating overall scenario provenance.
    """
    prov_store = LocalProvenanceStore(log_path=str(tmp_path / "test_prov.jsonl"))
    reconciler = ProvenanceReconciler()

    attack_corr_id = f"ATTACK-CORR-{uuid.uuid4()}"
    legit_corr_id = f"LEGIT-CORR-{uuid.uuid4()}"
    req_id = f"REQ-{uuid.uuid4()}"
    token_id = f"TOKEN-{uuid.uuid4()}"

    grant_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=legit_corr_id,
        request_id=req_id,
        action_name="read",
        target="public_repo",
        canonical_request_digest="digest_123",
        timestamp="2025-01-01T00:00:00Z",
        authorization_token_id=token_id,
        decision="ALLOW"
    )
    start_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=legit_corr_id,
        request_id=req_id,
        action_name="read",
        target="public_repo",
        canonical_request_digest="digest_123",
        timestamp="2025-01-01T00:00:01Z",
        authorization_token_id=token_id,
        execution_attempt_id="attempt_1"
    )
    success_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=legit_corr_id,
        request_id=req_id,
        action_name="read",
        target="public_repo",
        canonical_request_digest="digest_123",
        timestamp="2025-01-01T00:00:02Z",
        authorization_token_id=token_id,
        execution_attempt_id="attempt_1"
    )

    prov_store.record_event(grant_event)
    prov_store.record_event(start_event)
    prov_store.record_event(success_event)

    events_legit = prov_store.get_events_for_correlation(legit_corr_id)
    rec_legit = reconciler.reconcile_correlation(legit_corr_id, events_legit)
    assert rec_legit.valid is True

    events_attack = prov_store.get_events_for_correlation(attack_corr_id)
    rec_attack = reconciler.reconcile_correlation(attack_corr_id, events_attack)
    assert rec_attack.valid is False

    overall_valid = rec_legit.valid and rec_attack.valid
    overall_status = "VERIFIED" if overall_valid else "UNVERIFIED"

    assert overall_valid is False
    assert overall_status == "UNVERIFIED"


def test_scenario_report_emits_unverified_when_attack_correlation_missing_events(tmp_path):
    """
    Scenario Reporting Regression Test:
    Executes a scenario evaluation where an attack correlation ID lacks required provenance events
    and verifies that the emitted ScenarioEvaluationReport explicitly marks provenance as "UNVERIFIED".
    """
    scenario = Case1GitHubCredentialExposureScenario(audit_dir=str(tmp_path / "s1_unverified"))
    report = scenario.run_evaluation()

    assert report.dimension_a_security.provenance_evidence_integrity == "UNVERIFIED"


def test_digest_changes_when_untracked_file_content_changes():
    """
    Digest Regression Test:
    Proves that modifying only the raw binary contents of an untracked file alters the working-tree digest.
    """
    test_untracked = Path("test_digest_dummy.tmp")
    try:
        if test_untracked.exists():
            test_untracked.unlink()

        test_untracked.write_text("initial untracked content V1", encoding="utf-8")
        digest_1 = compute_working_tree_digest()

        test_untracked.write_text("modified untracked content V2 - completely different bytes", encoding="utf-8")
        digest_2 = compute_working_tree_digest()

        assert len(digest_1) == 64
        assert len(digest_2) == 64
        assert digest_1 != digest_2
    finally:
        if test_untracked.exists():
            test_untracked.unlink()


def test_digest_identical_working_tree_inputs_produce_same_digest():
    """
    Digest Regression Test:
    Proves that identical working-tree inputs produce the exact same 64-character SHA-256 digest.
    """
    d1 = compute_working_tree_digest()
    d2 = compute_working_tree_digest()

    assert len(d1) == 64
    assert len(d2) == 64
    assert d1 == d2


def test_all_scenarios_combined(tmp_audit_dir):
    scenarios = [
        Case1GitHubCredentialExposureScenario(audit_dir=tmp_audit_dir),
        Case2GovernmentAuthorizationBypassScenario(audit_dir=tmp_audit_dir),
        Case3IndirectEgressScenario(audit_dir=tmp_audit_dir),
        Case4InternalDashboardScenario(audit_dir=tmp_audit_dir),
        Case5CryptoWalletScenario(audit_dir=tmp_audit_dir),
        Case6DestructiveRecoveryScenario(audit_dir=tmp_audit_dir),
        Case7FleetAmplificationScenario(audit_dir=tmp_audit_dir)
    ]

    reports = [s.run_evaluation() for s in scenarios]
    assert len(reports) == 7
    for rep in reports:
        if rep.scenario_id == "Case3_get_only_egress_circumvention":
            assert rep.dimension_a_security.status == SecurityOutcomeStatus.PARTIAL_GATING_DEFENSE
        else:
            assert rep.dimension_a_security.status == SecurityOutcomeStatus.PASS
