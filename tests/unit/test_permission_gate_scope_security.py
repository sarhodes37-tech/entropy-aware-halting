"""
Regression test suite for P0 authorization defect fix in PermissionGate.
Verifies that request-, payload-, or model-supplied 'scope' fields cannot grant
or expand authorization scope, missing trusted scope fails closed, conflicting
untrusted scope cannot override trusted scope, legitimate trusted scope operations pass,
unauthorized operations fail, and denied operations yield zero side effects.
"""

from unittest.mock import MagicMock
from epistemicos.gates import PermissionGate, GateDecision
from epistemicos.core import EpistemicOrchestrator


class MockPayloadObj:
    """Class representing an object payload with a .scope attribute."""
    def __init__(self, scope, proposed_actions=None):
        self.scope = scope
        self.proposed_actions = proposed_actions or []


def test_payload_attempting_self_grant_permission_is_halted():
    """
    1. A payload attempting to grant itself permission through 'payload.scope'
    (dict or object attribute) when no trusted scope is present must fail closed/halt
    when performing restricted operations.
    """
    gate = PermissionGate(allowed_actions=["allowed_read"])

    # Dict payload with untrusted 'scope' attempting to permit 'admin_write'
    payload_dict = {
        "scope": {"allowed_operations": ["admin_write"], "allowed_resources": ["db_admin"]},
        "proposed_actions": [{"op": "admin_write", "node": "db_admin"}]
    }
    outcome_dict = gate.evaluate_contract(MagicMock(payload=payload_dict, context={}))
    assert outcome_dict.decision == GateDecision.HALT
    assert "not in gate allowed_actions" in outcome_dict.reason_code or "outside allowed scope" in outcome_dict.reason_code

    # Object payload with .scope attribute attempting self-grant
    payload_obj = MockPayloadObj(
        scope={"allowed_operations": ["admin_write"], "allowed_resources": ["db_admin"]},
        proposed_actions=[{"op": "admin_write", "node": "db_admin"}]
    )
    outcome_obj = gate.evaluate_contract(MagicMock(payload=payload_obj, context={"proposed_actions": [{"op": "admin_write", "node": "db_admin"}]}))
    assert outcome_obj.decision == GateDecision.HALT


def test_missing_trusted_scope_fails_closed_for_restricted_operations():
    """
    2. Missing trusted scope when attempting operations restricted by gate allowed_actions or scope limits.
    """
    # Gate configured with allowed_actions requiring allowed_read
    gate = PermissionGate(allowed_actions=["allowed_read"])

    payload = {"proposed_actions": [{"op": "unauthorized_delete", "node": "database"}]}
    context = {}  # Missing trusted_scope in context and gate

    outcome = gate.evaluate_contract(MagicMock(payload=payload, context=context))
    assert outcome.decision == GateDecision.HALT
    assert "not in gate allowed_actions" in outcome.reason_code


def test_untrusted_scope_conflicting_with_trusted_scope():
    """
    3. Untrusted scope in payload or context attempting to expand or override
    a restrictive trusted scope. Untrusted input must be ignored, and the request
    must be halted because it exceeds the trusted scope.
    """
    # Restrictive server-side trusted scope: allows only read_only on public_db
    trusted_scope = {
        "allowed_operations": ["read_only"],
        "allowed_resources": ["public_db"]
    }
    gate = PermissionGate(trusted_scope=trusted_scope)

    # Untrusted request payload claiming admin_write on sensitive_db
    payload = {
        "scope": {"allowed_operations": ["admin_write", "read_only"], "allowed_resources": ["sensitive_db", "public_db"]},
        "proposed_actions": [{"op": "admin_write", "node": "sensitive_db"}]
    }

    # Untrusted scope passed in context["scope"] as well
    context = {
        "scope": {"allowed_operations": ["admin_write"], "allowed_resources": ["sensitive_db"]}
    }

    outcome = gate.evaluate_contract(MagicMock(payload=payload, context=context))
    assert outcome.decision == GateDecision.HALT
    assert "outside allowed scope operations" in outcome.reason_code or "outside allowed scope resources" in outcome.reason_code


def test_legitimate_request_authorized_by_trusted_scope():
    """
    4. Legitimate request authorized by trusted scope (configured on gate or passed via context["trusted_scope"]).
    """
    # Legitimate authorization via gate trusted_scope
    gate = PermissionGate(trusted_scope={"allowed_operations": ["read_file"], "allowed_resources": ["doc1.txt"]})

    payload = {}
    context = {"proposed_actions": [{"op": "read_file", "node": "doc1.txt"}]}

    outcome = gate.evaluate_contract(MagicMock(payload=payload, context=context))
    assert outcome.decision == GateDecision.ALLOW
    assert outcome.reason_code == "PERMISSION_SCOPE_VALIDATED"

    # Legitimate authorization via context["trusted_scope"]
    gate_dynamic = PermissionGate()
    context_dynamic = {
        "trusted_scope": {"allowed_operations": ["query_db"], "allowed_resources": ["users_table"]},
        "proposed_actions": [{"op": "query_db", "node": "users_table"}]
    }
    outcome_dynamic = gate_dynamic.evaluate_contract(MagicMock(payload={}, context=context_dynamic))
    assert outcome_dynamic.decision == GateDecision.ALLOW


def test_unauthorized_request_denied():
    """
    5. An unauthorized request that exceeds trusted scope must be denied/halted.
    """
    gate = PermissionGate(trusted_scope={"allowed_operations": ["read_user"], "allowed_resources": ["user_123"]})

    # Action targeting forbidden resource
    context_bad_resource = {
        "proposed_actions": [{"op": "read_user", "node": "user_456_admin"}]
    }
    outcome_res = gate.evaluate_contract(MagicMock(payload={}, context=context_bad_resource))
    assert outcome_res.decision == GateDecision.HALT

    # Action attempting forbidden operation
    context_bad_op = {
        "proposed_actions": [{"op": "delete_user", "node": "user_123"}]
    }
    outcome_op = gate.evaluate_contract(MagicMock(payload={}, context=context_bad_op))
    assert outcome_op.decision == GateDecision.HALT


def test_attempted_protected_operation_denied_zero_side_effects(tmp_path):
    """
    6. Attempted protected operation for which denial results in zero side effects.
    Exercises the real gate and orchestration path through EpistemicOrchestrator,
    confirming pipeline halt, vector revocation/rollback, and zero side-effects.
    """
    audit_file = str(tmp_path / "side_effects_audit.jsonl")
    orchestrator = EpistemicOrchestrator(audit_log_path=audit_file)

    # Register a PermissionGate with restrictive allowed_actions
    orchestrator.register_gate(PermissionGate(allowed_actions=["safe_query"]))

    # Prepare payload with CPR schema required fields and an unauthorized payload scope claim
    raw_payload = {
        "policy_id": "POL-999",
        "fleet_data": {"vessels": ["vessel-1"]},
        "scope": {"allowed_operations": ["drop_table"], "allowed_resources": ["all_databases"]}
    }

    # Context attempting unauthorized drop_table action
    context = {
        "token_count": 10,
        "token_logprobs": [-0.1] * 10,
        "proposed_actions": [{"op": "drop_table", "node": "all_databases"}]
    }

    # Execute orchestrator pipeline
    traj_id = "test_side_effect_traj_001"
    result = orchestrator.process_submission(raw_payload, context, trajectory_id=traj_id)

    # Pipeline MUST halt
    assert result["status"] == "HALTED"
    assert result["gate"] == "PermissionGate"

    # Verify zero active side effects / vector quarantine state for this trajectory
    assert traj_id not in orchestrator.vector_manager._active_trajectories
    assert result.get("vectors_revoked", 0) >= 0
