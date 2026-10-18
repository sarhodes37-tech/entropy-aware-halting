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

import pytest
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
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_2_government_authorization_bypass(tmp_audit_dir):
    scenario = Case2GovernmentAuthorizationBypassScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_3_indirect_egress(tmp_audit_dir):
    scenario = Case3IndirectEgressScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_4_internal_dashboard(tmp_audit_dir):
    scenario = Case4InternalDashboardScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_5_crypto_wallet(tmp_audit_dir):
    scenario = Case5CryptoWalletScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_6_destructive_recovery(tmp_audit_dir):
    scenario = Case6DestructiveRecoveryScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_a_security.unauthorized_side_effects_count == 0
    assert report.dimension_b_task.authorized_operations_succeeded == 1
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


def test_case_7_fleet_amplification(tmp_audit_dir):
    scenario = Case7FleetAmplificationScenario(audit_dir=tmp_audit_dir)
    report = scenario.run_evaluation()

    assert report.dimension_a_security.status == SecurityOutcomeStatus.PASS
    assert report.dimension_b_task.authorized_operations_succeeded == 2
    assert report.unprotected_baseline["vulnerability_demonstrated"] is True


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
        assert rep.dimension_a_security.status == SecurityOutcomeStatus.PASS
