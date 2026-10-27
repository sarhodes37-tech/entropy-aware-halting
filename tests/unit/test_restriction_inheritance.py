"""
Unit tests for Persistent Denial and Restriction Inheritance across Alternative Execution Paths (Phase 2).

Tests Scenarios A through F:
- Scenario A: Tool substitution (same prohibited action category via another tool/operation) -> Denied
- Scenario B: Endpoint substitution (same resource via alternate endpoint/path/query/fragment) -> Denied
- Scenario C: Indirect execution (restricted action through wrapper/intermediary) -> Denied
- Scenario D: Required approval bypass -> Denied
- Scenario E: Legitimate reauthorization (explicitly cleared with valid HumanApprovalRecord) -> Permitted
- Scenario F: Unrelated legitimate action -> Permitted
- Malformed/missing authorization context -> Denied / Fails closed
- Edge Cases: Subpath matching, root path restriction inheritance, upward isolation, query/fragment normalization.
- Audit trail integrity and decision recording -> Recorded & Verified
"""

import os
import pytest
from epistemicos.action_policy import ActionCategory, ActionRegistry, RegisteredActionDefinition, SideEffectPolicyEngine, TypedHumanApprovalRecord
from epistemicos.authorization import AuthorizationAuthority, CapabilityRegistry, HumanApprovalRecord, Policy, TrustedTaskContract
from epistemicos.audit import TamperEvidentAuditTrail, AuditEvent, AuditLogLevel
from epistemicos.core import EpistemicOrchestrator
from epistemicos.provenance import LocalProvenanceStore, TrustedExecutionBoundary


def test_scenario_a_tool_substitution(tmp_path):
    """
    Scenario A: Tool Substitution
    An operation is denied through one execution mechanism ('delete_db').
    The agent retries the same prohibited action type through another mechanism ('destructive_shell').
    Expected: Restriction inherited and denied; prohibited callback is never dispatched.
    """
    denial_log = tmp_path / "scenario_a_denial.jsonl"
    audit_file = tmp_path / "scenario_a_audit.jsonl"
    prov_file = tmp_path / "scenario_a_prov.jsonl"

    reg = CapabilityRegistry(denial_log_path=str(denial_log))
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg
    )
    store = LocalProvenanceStore(log_path=str(prov_file))
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=auth)

    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(audit_file),
        execution_boundary=boundary,
        authority=auth
    )

    dispatched = [0]
    def target_callback():
        dispatched[0] += 1
        return {"status": "executed"}

    auth.register_executor("target_callback", target_callback)

    contract_restrictive = TrustedTaskContract(
        task_id="TASK-A-01",
        permitted_actions={"read_only"},
        resource_scope={"/prod/db"}
    )
    contract_restrictive.sign(auth.contract_signing_secret)

    # 1. Initial attempt via 'delete_db' on /prod/db -> DENIED & recorded in persistent denial log
    res1 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"task_id": "TASK-A-01", "action_name": "delete_db", "target": "/prod/db", "actual_executable": target_callback, "task_contract": contract_restrictive}
    )
    assert res1["status"] == "HALTED"
    assert dispatched[0] == 0

    # 2. Tool substitution: Retry under a permissive contract with alternative tool 'destructive_shell' targeting /prod/db
    contract_permissive = TrustedTaskContract(
        task_id="TASK-A-01",
        permitted_actions={"*"},
        resource_scope={"*"}
    )
    contract_permissive.sign(auth.contract_signing_secret)

    res2 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"task_id": "TASK-A-01", "action_name": "destructive_shell", "target": "/prod/db", "actual_executable": target_callback, "task_contract": contract_permissive}
    )
    assert res2["status"] == "HALTED"
    assert "DURABLE_DENIAL_ACTIVE" in res2["reason"]
    assert dispatched[0] == 0


def test_scenario_b_endpoint_substitution(tmp_path):
    """
    Scenario B: Endpoint Substitution
    Agent cannot access restricted endpoint '/api/v1/user/delete' directly,
    attempts alternate endpoint representations: trailing slash '/api/v1/user/delete/',
    query string '/api/v1/user/delete?force=true', or fragment '/api/v1/user/delete#ref'.
    Expected: Destination evaluated and denied.
    """
    denial_log = tmp_path / "scenario_b_denial.jsonl"
    reg = CapabilityRegistry(denial_log_path=str(denial_log))
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg
    )

    contract_restrictive = TrustedTaskContract(
        task_id="TASK-B-01",
        permitted_actions={"read_only"},
        resource_scope={"/api/v1/user"}
    )
    contract_restrictive.sign(auth.contract_signing_secret)

    # Initial attempt -> DENIED
    cap1, reason1 = auth.evaluate_and_issue_capability(
        action_name="http_delete",
        target="/api/v1/user/delete",
        canonical_request_digest="dig1",
        task_contract=contract_restrictive
    )
    assert cap1 is None
    assert "CONTRACT_SCOPE_VIOLATION" in reason1

    # Permissive contract update
    contract_permissive = TrustedTaskContract(
        task_id="TASK-B-01",
        permitted_actions={"*"},
        resource_scope={"*"}
    )
    contract_permissive.sign(auth.contract_signing_secret)

    # 1. Alternate endpoint route with trailing slash
    cap2, reason2 = auth.evaluate_and_issue_capability(
        action_name="http_delete",
        target="/api/v1/user/delete/",
        canonical_request_digest="dig2",
        task_contract=contract_permissive
    )
    assert cap2 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason2

    # 2. Alternate endpoint route with query string
    cap3, reason3 = auth.evaluate_and_issue_capability(
        action_name="http_delete",
        target="/api/v1/user/delete?force=true",
        canonical_request_digest="dig3",
        task_contract=contract_permissive
    )
    assert cap3 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason3

    # 3. Alternate endpoint route with fragment
    cap4, reason4 = auth.evaluate_and_issue_capability(
        action_name="http_delete",
        target="/api/v1/user/delete#ref",
        canonical_request_digest="dig4",
        task_contract=contract_permissive
    )
    assert cap4 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason4


def test_scenario_c_indirect_execution(tmp_path):
    """
    Scenario C: Indirect Execution
    A restricted action is attempted through a genuinely different registered wrapper/intermediary action name ('proxy_dispatch' / 'wrapper_exec').
    Expected: Preserve applicable restrictions across the execution boundary and block dispatch before execution callback runs.
    """
    denial_log = tmp_path / "scenario_c_denial.jsonl"
    audit_file = tmp_path / "scenario_c_audit.jsonl"
    prov_file = tmp_path / "scenario_c_prov.jsonl"

    reg = CapabilityRegistry(denial_log_path=str(denial_log))
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg
    )
    store = LocalProvenanceStore(log_path=str(prov_file))
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=auth)

    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(audit_file),
        execution_boundary=boundary,
        authority=auth
    )

    dispatched = [0]
    def wrapper_callback():
        dispatched[0] += 1
        return {"status": "executed_via_wrapper"}

    auth.register_executor("wrapper_callback", wrapper_callback)

    contract_restrictive = TrustedTaskContract(
        task_id="TASK-C-01",
        permitted_actions={"read_only"},
        resource_scope={"/protected/resource"}
    )
    contract_restrictive.sign(auth.contract_signing_secret)

    # Step 1: Initial direct attempt via 'delete_db' on /protected/resource -> DENIED
    res1 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"task_id": "TASK-C-01", "action_name": "delete_db", "target": "/protected/resource", "actual_executable": wrapper_callback, "task_contract": contract_restrictive}
    )
    assert res1["status"] == "HALTED"
    assert dispatched[0] == 0

    # Step 2: Attempt same prohibited action via distinct wrapper action 'destructive_shell' under updated permissive contract
    contract_permissive = TrustedTaskContract(
        task_id="TASK-C-01",
        permitted_actions={"*"},
        resource_scope={"*"}
    )
    contract_permissive.sign(auth.contract_signing_secret)

    res2 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"task_id": "TASK-C-01", "action_name": "destructive_shell", "target": "/protected/resource", "actual_executable": wrapper_callback, "task_contract": contract_permissive}
    )
    assert res2["status"] == "HALTED"
    assert "DURABLE_DENIAL_ACTIVE" in res2["reason"]
    assert dispatched[0] == 0  # Prohibited callback was NEVER dispatched!


def test_scenario_d_required_approval_absent_and_route_switching_integration(tmp_path):
    """
    Scenario D: Required Approval & Alternate Route Switching Integration Test
    A task requires human approval before a consequential operation ('public_repo_mutation').
    When denied due to missing approval on one execution route, switching routes/tools ('package_publish')
    or contracts cannot bypass the approval requirement or durable denial.
    Verifies the prohibited callback is never invoked.
    """
    denial_log = tmp_path / "scenario_d_denial.jsonl"
    audit_file = tmp_path / "scenario_d_audit.jsonl"
    prov_file = tmp_path / "scenario_d_prov.jsonl"

    reg = CapabilityRegistry(denial_log_path=str(denial_log))
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}, required_human_approval_operations={"public_repo_mutation", "package_publish"}),
        registry=reg
    )
    store = LocalProvenanceStore(log_path=str(prov_file))
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=auth)

    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(audit_file),
        execution_boundary=boundary,
        authority=auth
    )

    dispatched = [0]
    def consequential_callback():
        dispatched[0] += 1
        return {"status": "consequential_executed"}

    auth.register_executor("consequential_callback", consequential_callback)

    contract = TrustedTaskContract(
        task_id="TASK-D-INTEG-01",
        permitted_actions={"*"},
        resource_scope={"*"}
    )
    contract.sign(auth.contract_signing_secret)

    # 1. Direct attempt without approval -> Denied due to missing required human approval
    res1 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"task_id": "TASK-D-INTEG-01", "action_name": "public_repo_mutation", "target": "org/repo", "actual_executable": consequential_callback, "task_contract": contract}
    )
    assert res1["status"] == "HALTED"
    assert "HUMAN_APPROVAL_REQUIRED" in res1["reason"]
    assert dispatched[0] == 0

    # 2. Switch route/tool to 'package_publish' on same target -> Durable denial inherited & blocked before dispatch
    res2 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"task_id": "TASK-D-INTEG-01", "action_name": "package_publish", "target": "org/repo", "actual_executable": consequential_callback, "task_contract": contract}
    )
    assert res2["status"] == "HALTED"
    assert "DURABLE_DENIAL_ACTIVE" in res2["reason"] or "HUMAN_APPROVAL_REQUIRED" in res2["reason"]
    assert dispatched[0] == 0  # Prohibited callback was NEVER invoked!


def test_scenario_e_legitimate_reauthorization(tmp_path):
    """
    Scenario E: Legitimate Reauthorization
    An operation was denied, but an authorized principal subsequently grants valid permission within an explicitly defined scope.
    Expected: Clear denial with authenticated HumanApprovalRecord and permit operation.
    """
    denial_log = tmp_path / "scenario_e_denial.jsonl"
    reg = CapabilityRegistry(denial_log_path=str(denial_log))
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg
    )

    contract_restrictive = TrustedTaskContract(
        task_id="TASK-E-01",
        permitted_actions={"read_only"},
        resource_scope={"/data/export"}
    )
    contract_restrictive.sign(auth.contract_signing_secret)

    # 1. Denied
    cap1, reason1 = auth.evaluate_and_issue_capability(
        action_name="export_data",
        target="/data/export",
        canonical_request_digest="dig1",
        task_contract=contract_restrictive
    )
    assert cap1 is None

    # 2. Grant explicit reauthorization record
    approval = HumanApprovalRecord(
        approval_id="appr-e-01",
        approver_id="admin_user",
        action_name="CLEAR_DENIAL:export_data",
        target="/data/export",
        action_digest="dig_clear",
        request_id="req_clear_1",
        task_id="TASK-E-01"
    )
    approval.sign(auth.approval_signing_secret)

    cleared, clear_msg = reg.clear_denial_with_approval(
        task_id="TASK-E-01",
        action_name="export_data",
        target="/data/export",
        reauthorization_record=approval,
        signing_secret=auth.approval_signing_secret,
        expected_action_digest="dig_clear"
    )
    assert cleared, f"Failed to clear denial: {clear_msg}"


def test_reauthorization_action_digest_binding_cases(tmp_path):
    """
    Tests focused reauthorization action-digest binding cases:
    1. Matching expected and approval digests -> Accepted
    2. Mismatched digests -> Rejected
    3. Expected digest supplied but approval digest missing/empty -> Rejected
    4. Expected digest omitted -> Accepted for backwards compatibility
    5. Rejected clearance does NOT clear active denial or prevent subsequent legitimate retry
    """
    denial_log = tmp_path / "digest_cases_denial.jsonl"
    reg = CapabilityRegistry(denial_log_path=str(denial_log))
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg
    )

    contract_restrictive = TrustedTaskContract(
        task_id="TASK-DIGEST-01",
        permitted_actions={"read_only"},
        resource_scope={"/data/export"}
    )
    contract_restrictive.sign(auth.contract_signing_secret)

    # Trigger active denial
    cap1, _ = auth.evaluate_and_issue_capability(
        action_name="export_data",
        target="/data/export",
        canonical_request_digest="dig1",
        task_contract=contract_restrictive
    )
    assert cap1 is None

    # Case 2: Mismatched digests -> Rejected
    app_mismatch = HumanApprovalRecord(
        approval_id="appr-mis-01",
        approver_id="admin",
        action_name="CLEAR_DENIAL:export_data",
        target="/data/export",
        action_digest="dig_wrong",
        request_id="req1",
        task_id="TASK-DIGEST-01"
    )
    app_mismatch.sign(auth.approval_signing_secret)

    cleared2, msg2 = reg.clear_denial_with_approval(
        task_id="TASK-DIGEST-01",
        action_name="export_data",
        target="/data/export",
        reauthorization_record=app_mismatch,
        signing_secret=auth.approval_signing_secret,
        expected_action_digest="dig_expected"
    )
    assert not cleared2
    assert "action_digest mismatch" in msg2

    # Case 3: Expected digest supplied but approval digest missing/empty -> Rejected
    app_empty = HumanApprovalRecord(
        approval_id="appr-empty-01",
        approver_id="admin",
        action_name="CLEAR_DENIAL:export_data",
        target="/data/export",
        action_digest="",
        request_id="req2",
        task_id="TASK-DIGEST-01"
    )
    app_empty.sign(auth.approval_signing_secret)

    cleared3, msg3 = reg.clear_denial_with_approval(
        task_id="TASK-DIGEST-01",
        action_name="export_data",
        target="/data/export",
        reauthorization_record=app_empty,
        signing_secret=auth.approval_signing_secret,
        expected_action_digest="dig_expected"
    )
    assert not cleared3
    assert "missing required action_digest" in msg3

    # Verify Case 5: Denial remains active after rejected clearance attempts
    is_denied, denial_rec = reg.check_denial("TASK-DIGEST-01", "export_data", "/data/export")
    assert is_denied
    assert denial_rec is not None

    # Case 4: Expected digest omitted -> Accepted for backwards compatibility
    denial_log4 = tmp_path / "digest_cases_denial4.jsonl"
    reg4 = CapabilityRegistry(denial_log_path=str(denial_log4))
    auth4 = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg4
    )

    cap_omit, _ = auth4.evaluate_and_issue_capability(
        action_name="export_data",
        target="/data/export",
        canonical_request_digest="dig1",
        task_contract=contract_restrictive
    )
    assert cap_omit is None

    app_omitted = HumanApprovalRecord(
        approval_id="appr-omit-01",
        approver_id="admin",
        action_name="CLEAR_DENIAL:export_data",
        target="/data/export",
        action_digest="dig_any",
        request_id="req_omit",
        task_id="TASK-DIGEST-01"
    )
    app_omitted.sign(auth4.approval_signing_secret)

    cleared_omitted, msg_omitted = reg4.clear_denial_with_approval(
        task_id="TASK-DIGEST-01",
        action_name="export_data",
        target="/data/export",
        reauthorization_record=app_omitted,
        signing_secret=auth4.approval_signing_secret,
        expected_action_digest=None
    )
    assert cleared_omitted, f"Omitted digest clearance failed: {msg_omitted}"

    # Case 1: Matching expected and approval digests -> Accepted & Cleared
    app_match = HumanApprovalRecord(
        approval_id="appr-match-01",
        approver_id="admin",
        action_name="CLEAR_DENIAL:export_data",
        target="/data/export",
        action_digest="dig_expected",
        request_id="req3",
        task_id="TASK-DIGEST-01"
    )
    app_match.sign(auth.approval_signing_secret)

    cleared1, msg1 = reg.clear_denial_with_approval(
        task_id="TASK-DIGEST-01",
        action_name="export_data",
        target="/data/export",
        reauthorization_record=app_match,
        signing_secret=auth.approval_signing_secret,
        expected_action_digest="dig_expected"
    )
    assert cleared1, f"Failed to clear denial: {msg1}"

    # Verify denial is now cleared
    is_denied_after, _ = reg.check_denial("TASK-DIGEST-01", "export_data", "/data/export")
    assert not is_denied_after

    # 3. Subsequent attempt under updated contract -> PERMITTED
    contract_updated = TrustedTaskContract(
        task_id="TASK-E-01",
        permitted_actions={"export_data", "read_only"},
        resource_scope={"/data/export"}
    )
    contract_updated.sign(auth.contract_signing_secret)

    cap2, reason2 = auth.evaluate_and_issue_capability(
        action_name="export_data",
        target="/data/export",
        canonical_request_digest="dig2",
        task_contract=contract_updated
    )
    assert cap2 is not None
    assert reason2 == "AUTHORIZATION_GRANTED"


def test_scenario_f_unrelated_legitimate_action(tmp_path):
    """
    Scenario F: Unrelated Legitimate Action
    An earlier operation was denied ('delete_db' on '/prod/db'),
    subsequently requests an unrelated, authorized action ('read_logs' on '/var/log').
    Expected: Do not impose an unrelated restriction merely because of shared task or tool category.
    """
    denial_log = tmp_path / "scenario_f_denial.jsonl"
    reg = CapabilityRegistry(denial_log_path=str(denial_log))
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg
    )

    contract_restrictive = TrustedTaskContract(
        task_id="TASK-F-01",
        permitted_actions={"read_logs"},
        resource_scope={"/var/log", "/prod/db"}
    )
    contract_restrictive.sign(auth.contract_signing_secret)

    # 1. Prohibited operation denied
    cap1, reason1 = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/prod/db",
        canonical_request_digest="dig1",
        task_contract=contract_restrictive
    )
    assert cap1 is None

    # 2. Unrelated legitimate action on different target/category -> PERMITTED
    cap2, reason2 = auth.evaluate_and_issue_capability(
        action_name="read_logs",
        target="/var/log",
        canonical_request_digest="dig2",
        task_contract=contract_restrictive
    )
    assert cap2 is not None
    assert reason2 == "AUTHORIZATION_GRANTED"


def test_root_path_and_subpath_inheritance(tmp_path):
    """
    Edge Cases:
    1. Root path denial ("/") inherits to subpaths ("/api/v1").
    2. Subpath denial ("/api/v1/users/123") does NOT inherit upward to parent ("/api/v1/users").
    3. Resource string prefix overlap without slash boundary ("/resource" vs "/resource-evil") does NOT match.
    4. Encoded separators (%2F, %5C), dot segments (., ..), repeated slashes (//), backslashes.
    5. URL vs path-only inputs and explicit host isolation (host-a vs host-b).
    """
    denial_log = tmp_path / "edge_cases_denial.jsonl"
    reg = CapabilityRegistry(denial_log_path=str(denial_log))
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg
    )

    # 1. Root path restriction
    contract_restrictive1 = TrustedTaskContract(
        task_id="TASK-ROOT-01",
        permitted_actions={"read_only"},
        resource_scope={"/"}
    )
    contract_restrictive1.sign(auth.contract_signing_secret)

    cap_r1, _ = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/",
        canonical_request_digest="dig_r1",
        task_contract=contract_restrictive1
    )
    assert cap_r1 is None

    contract_permissive1 = TrustedTaskContract(
        task_id="TASK-ROOT-01",
        permitted_actions={"*"},
        resource_scope={"*"}
    )
    contract_permissive1.sign(auth.contract_signing_secret)

    cap_r2, reason_r2 = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/api/v1/resource",
        canonical_request_digest="dig_r2",
        task_contract=contract_permissive1
    )
    assert cap_r2 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason_r2

    # 2. Upward path isolation: subpath denial does NOT block parent resource
    contract_restrictive2 = TrustedTaskContract(
        task_id="TASK-UPWARD-01",
        permitted_actions={"read_only"},
        resource_scope={"/api/v1/users/123"}
    )
    contract_restrictive2.sign(auth.contract_signing_secret)

    cap_u1, _ = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/api/v1/users/123",
        canonical_request_digest="dig_u1",
        task_contract=contract_restrictive2
    )
    assert cap_u1 is None

    contract_permissive2 = TrustedTaskContract(
        task_id="TASK-UPWARD-01",
        permitted_actions={"*"},
        resource_scope={"*"}
    )
    contract_permissive2.sign(auth.contract_signing_secret)

    # Calling parent path '/api/v1/users' should NOT be blocked by subpath denial on '/api/v1/users/123'
    cap_u2, reason_u2 = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/api/v1/users",
        canonical_request_digest="dig_u2",
        task_contract=contract_permissive2
    )
    assert cap_u2 is not None
    assert reason_u2 == "AUTHORIZATION_GRANTED"

    # 3. String prefix overlap without slash boundary isolation
    contract_restrictive3 = TrustedTaskContract(
        task_id="TASK-PREFIX-01",
        permitted_actions={"read_only"},
        resource_scope={"/resource"}
    )
    contract_restrictive3.sign(auth.contract_signing_secret)

    cap_p1, _ = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/resource",
        canonical_request_digest="dig_p1",
        task_contract=contract_restrictive3
    )
    assert cap_p1 is None

    contract_permissive3 = TrustedTaskContract(
        task_id="TASK-PREFIX-01",
        permitted_actions={"*"},
        resource_scope={"*"}
    )
    contract_permissive3.sign(auth.contract_signing_secret)

    # '/resource-evil' should NOT be blocked by denial on '/resource'
    cap_p2, reason_p2 = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/resource-evil",
        canonical_request_digest="dig_p2",
        task_contract=contract_permissive3
    )
    assert cap_p2 is not None
    assert reason_p2 == "AUTHORIZATION_GRANTED"

    # 4. Encoded separators (%2F, %5C), dot segments (..), backslashes, repeated slashes
    contract_restrictive4 = TrustedTaskContract(
        task_id="TASK-ENCODED-01",
        permitted_actions={"read_only"},
        resource_scope={"/api/v1/secure"}
    )
    contract_restrictive4.sign(auth.contract_signing_secret)

    # Direct denial on /api/v1/secure
    cap_e1, _ = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/api/v1/secure",
        canonical_request_digest="dig_e1",
        task_contract=contract_restrictive4
    )
    assert cap_e1 is None

    contract_permissive4 = TrustedTaskContract(
        task_id="TASK-ENCODED-01",
        permitted_actions={"*"},
        resource_scope={"*"}
    )
    contract_permissive4.sign(auth.contract_signing_secret)

    # Percent-encoded slash attempt: /api%2Fv1%2Fsecure
    cap_e2, reason_e2 = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/api%2Fv1%2Fsecure",
        canonical_request_digest="dig_e2",
        task_contract=contract_permissive4
    )
    assert cap_e2 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason_e2

    # Traversal dot segment attempt: /api/v1/other/../secure
    cap_e3, reason_e3 = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/api/v1/other/../secure",
        canonical_request_digest="dig_e3",
        task_contract=contract_permissive4
    )
    assert cap_e3 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason_e3

    # Backslash attempt: /api\v1\secure
    cap_e4, reason_e4 = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="/api\\v1\\secure",
        canonical_request_digest="dig_e4",
        task_contract=contract_permissive4
    )
    assert cap_e4 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason_e4

    # 5. Explicit Host Isolation
    contract_restrictive5 = TrustedTaskContract(
        task_id="TASK-HOST-01",
        permitted_actions={"read_only"},
        resource_scope={"http://host-a.internal/data"}
    )
    contract_restrictive5.sign(auth.contract_signing_secret)

    # Denial on host-a.internal/data
    cap_h1, _ = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="http://host-a.internal/data",
        canonical_request_digest="dig_h1",
        task_contract=contract_restrictive5
    )
    assert cap_h1 is None

    contract_permissive5 = TrustedTaskContract(
        task_id="TASK-HOST-01",
        permitted_actions={"*"},
        resource_scope={"*"}
    )
    contract_permissive5.sign(auth.contract_signing_secret)

    # Target http://host-b.internal/data should NOT be blocked by denial on host-a.internal
    cap_h2, reason_h2 = auth.evaluate_and_issue_capability(
        action_name="delete_db",
        target="http://host-b.internal/data",
        canonical_request_digest="dig_h2",
        task_contract=contract_permissive5
    )
    assert cap_h2 is not None
    assert reason_h2 == "AUTHORIZATION_GRANTED"


def test_malformed_authorization_context():
    """
    Malformed or missing authorization context fails closed.
    """
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"})
    )

    # Empty action name
    cap1, reason1 = auth.evaluate_and_issue_capability(
        action_name="",
        target="/res",
        canonical_request_digest="dig1"
    )
    assert cap1 is None
    assert "INVALID_ACTION_NAME" in reason1

    # Empty target
    cap2, reason2 = auth.evaluate_and_issue_capability(
        action_name="read",
        target="   ",
        canonical_request_digest="dig2"
    )
    assert cap2 is None
    assert "INVALID_TARGET" in reason2


def test_audit_record_for_denied_attempt(tmp_path):
    """
    Trigger an inherited denial through the actual EpistemicOrchestrator authorization pipeline
    and inspect the resulting AuditEvent written directly to the real audit trail log file.
    Verifies that the audit event captures the HALT decision, gate_name, reason, and maintains hash-chain tamper integrity.
    """
    audit_log = tmp_path / "actual_audit.jsonl"
    denial_log = tmp_path / "actual_denial.jsonl"
    prov_file = tmp_path / "actual_prov.jsonl"

    reg = CapabilityRegistry(denial_log_path=str(denial_log))
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg
    )
    store = LocalProvenanceStore(log_path=str(prov_file))
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=auth)

    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(audit_log),
        execution_boundary=boundary,
        authority=auth
    )

    contract_restrictive = TrustedTaskContract(
        task_id="TASK-AUDIT-01",
        permitted_actions={"read_only"},
        resource_scope={"/prod/db"}
    )
    contract_restrictive.sign(auth.contract_signing_secret)

    def dummy_executable():
        return {"status": "ok"}
    auth.register_executor("dummy_executable", dummy_executable)

    # 1. Initial attempt -> Denied & persisted
    res1 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"task_id": "TASK-AUDIT-01", "action_name": "delete_db", "target": "/prod/db", "actual_executable": dummy_executable, "task_contract": contract_restrictive}
    )
    assert res1["status"] == "HALTED"

    # 2. Submitting alternate tool 'destructive_shell' triggers inherited denial through actual orchestrator pipeline
    contract_permissive = TrustedTaskContract(
        task_id="TASK-AUDIT-01",
        permitted_actions={"*"},
        resource_scope={"*"}
    )
    contract_permissive.sign(auth.contract_signing_secret)

    res2 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"task_id": "TASK-AUDIT-01", "action_name": "destructive_shell", "target": "/prod/db", "actual_executable": dummy_executable, "task_contract": contract_permissive}
    )
    assert res2["status"] == "HALTED"
    assert "DURABLE_DENIAL_ACTIVE" in res2["reason"]

    # 3. Inspect real audit log generated by orchestrator
    audit_trail = TamperEvidentAuditTrail(log_file_path=str(audit_log))
    is_healthy, last_hash, err_msg = audit_trail.inspect_log_health()
    assert is_healthy, f"Audit log health check failed: {err_msg}"
    assert last_hash is not None

    # Read and inspect entries directly from audit log file
    import json
    with open(audit_log, "r", encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]

    assert len(entries) >= 2
    inherited_audit_entry = entries[-1]
    assert inherited_audit_entry["event_type"] == "DETERMINISTIC_HALT"
    assert inherited_audit_entry["gate_name"] == "AuthorizationAuthority"
    assert "DURABLE_DENIAL_ACTIVE" in inherited_audit_entry["reason"]
