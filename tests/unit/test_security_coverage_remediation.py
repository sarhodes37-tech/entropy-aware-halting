"""
Targeted Security-Critical Coverage Remediation Test Suite.
Addresses uncovered lines across:
- epistemicos/audit.py (139, 149, 166, 182, 259-260, 275, 285)
- epistemicos/compliance.py (120-121, 141-142, 145, 150-151, 154)
- epistemicos/containment.py (221, 228-231, 243, 249, 346, 349)
- epistemicos/core.py (33, 55-56, 120, 126, 167, 200-203)
- epistemicos/gates.py (82, 86, 140-141, 194, 207, 231, 342-343, 439, 447-448, 453-454, 531, 533)
- epistemicos/models.py (65-66, 80, 141-143, 338)
- epistemicos/provenance.py (25-26, 95-98, 105, 108, 167-168, 190, 221, 227)
- epistemicos/scheduler.py (99, 130-136, 142, 145, 152, 157)
"""

import os
import json
import importlib
import pytest
from unittest.mock import MagicMock, patch

# 1. AUDIT.PY REMEDIATION
from epistemicos.audit import TamperEvidentAuditTrail, AuditEvent, AuditLogLevel

def test_audit_blank_lines_skipping_and_nonexistent(tmp_path):
    log_file = tmp_path / "audit_blank.jsonl"
    audit = TamperEvidentAuditTrail(str(log_file))
    e1 = audit.record_event(AuditEvent(AuditLogLevel.INFO, "g1", "r1", "m1", "s1"))

    with open(log_file, "r") as f:
        c = f.read()
    with open(log_file, "w") as f:
        f.write("\n\n" + c + "\n\n  \n")

    healthy, last_h, err = audit.inspect_log_health()
    assert healthy is True
    assert last_h == e1["entry_hash"]

    valid, count, msg = audit.verify_chain_integrity()
    assert valid is True
    assert count == 1

    # Nonexistent file return (Line 275)
    missing_audit = TamperEvidentAuditTrail(str(tmp_path / "missing.jsonl"))
    m_valid, m_count, m_msg = missing_audit.verify_chain_integrity()
    assert m_valid is True
    assert m_count == 0

def test_audit_duplicate_event_id_and_hash_mismatch(tmp_path):
    log_file = tmp_path / "audit_dup.jsonl"
    audit = TamperEvidentAuditTrail(str(log_file))
    e1 = audit.record_event(AuditEvent(AuditLogLevel.INFO, "g1", "r1", "m1", "s1"))
    e2 = audit.record_event(AuditEvent(AuditLogLevel.INFO, "g2", "r2", "m2", "s2"))

    with open(log_file, "r") as f:
        lines = f.readlines()

    # Duplicate event_id (Line 149)
    lines.append(lines[1])
    with open(log_file, "w") as f:
        f.writelines(lines)

    healthy, _, msg = audit.inspect_log_health()
    assert healthy is False
    assert "Duplicate event_id" in msg

    # Hash mismatch (Line 166)
    with open(log_file, "r") as f:
        data = json.loads(f.readline().strip())
    data["entry_hash"] = "0" * 64
    with open(log_file, "w") as f:
        f.write(json.dumps(data) + "\n")

    healthy2, _, msg2 = audit.inspect_log_health()
    assert healthy2 is False
    assert "Tampered entry" in msg2

def test_audit_get_last_hash_cached_and_fsync_oserror(tmp_path):
    log_file = tmp_path / "audit_cache.jsonl"
    audit = TamperEvidentAuditTrail(str(log_file))
    e1 = audit.record_event(AuditEvent(AuditLogLevel.INFO, "g1", "r1", "m1", "s1"))

    # Line 182: Cached last_hash return
    audit.last_hash = "cached_123"
    assert audit._get_last_hash(force_reload=False) == "cached_123"

    # Lines 259-260: fsync OSError
    with patch("os.fsync", side_effect=OSError("Not supported")):
        rec = audit.record_event(AuditEvent(AuditLogLevel.INFO, "g2", "r2", "m2", "s2"))
        assert rec["event_id"] is not None


# 2. COMPLIANCE.PY REMEDIATION
from epistemicos.compliance import TransactionalComplianceBroker

def test_compliance_commonpath_and_toctou_edge_cases(tmp_path):
    broker = TransactionalComplianceBroker()
    tx_id = "tx_comp_edge"
    test_file = tmp_path / "comp_file.log"
    test_file.write_text("tx_comp_edge data")

    # Lines 120-121: initial loop commonpath ValueError
    orig_commonpath = os.path.commonpath
    calls = [0]
    def mock_cp(paths):
        calls[0] += 1
        if calls[0] == 1:
            raise ValueError("Drive mismatch")
        return orig_commonpath(paths)

    with patch("os.path.commonpath", side_effect=mock_cp):
        del_st, _ = broker.execute_right_to_be_forgotten(tx_id, file_path=str(test_file))
        assert del_st is False

    # Lines 141-142, 145: re-verification commonpath ValueError
    calls[0] = 0
    def mock_cp_recheck(paths):
        calls[0] += 1
        if calls[0] > 2:
            raise ValueError("Drive mismatch re-verification")
        return orig_commonpath(paths)

    with patch("os.path.commonpath", side_effect=mock_cp_recheck):
        with pytest.raises(ValueError, match="Path traversal detected"):
            broker.execute_right_to_be_forgotten(tx_id, file_path=str(test_file))

    # Lines 150-151: TOCTOU FileNotFoundError
    with patch("os.stat", side_effect=FileNotFoundError("Deleted")):
        with pytest.raises(ValueError, match="was deleted during validation"):
            broker.execute_right_to_be_forgotten(tx_id, file_path=str(test_file))

    # Line 154: TOCTOU stat mismatch
    mock_stat = MagicMock(st_ino=999, st_dev=888)
    with patch("os.stat", return_value=mock_stat):
        with pytest.raises(ValueError, match="changed during validation"):
            broker.execute_right_to_be_forgotten(tx_id, file_path=str(test_file))


# 3. CONTAINMENT.PY REMEDIATION
from epistemicos.containment import ContainmentGuard

def test_containment_extract_hostname_and_scalar_traversal():
    guard = ContainmentGuard()

    # Line 221: Empty URL
    assert guard._extract_hostname_secure("") == ""

    # Lines 228-231: Schemeless / Protocol-relative URLs
    assert guard._extract_hostname_secure("//example.com/path") == "example.com"
    assert guard._extract_hostname_secure("example.com/path") == "example.com"

    # Line 243: Empty hostname
    assert guard._extract_hostname_secure("http:///path") == ""

    # Line 249: Hostname containing whitespace
    mock_parsed = MagicMock()
    mock_parsed.hostname = "ex ample.com"
    with patch("epistemicos.containment.urlsplit", return_value=mock_parsed):
        assert guard._extract_hostname_secure("http://ex ample.com/path") == ""

    # Lines 346, 349: Circular & primitive scalar type skipping
    d = {"a": 1, "b": 2.5, "c": True, "d": None}
    d["self"] = d
    strings, urls = guard._extract_all_strings_and_urls(d)
    assert len(strings) > 0


# 4. CORE.PY REMEDIATION
from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import Gate

def test_core_uninitialized_gates_custom_scheduler_and_uuid(tmp_path):
    orchestrator = EpistemicOrchestrator()

    # Line 33: Uninitialized self.gates in register_gate
    orchestrator.gates = None
    orchestrator.register_gate(MagicMock())
    assert len(orchestrator.gates) == 1

    # Lines 55-56, 120: Custom scheduler init & reset
    mock_base = MagicMock()
    mock_custom = MagicMock()
    orch_sched = EpistemicOrchestrator(scheduler=mock_base)
    orch_sched.scheduler = mock_custom
    orch_sched.reset_schedulers()
    mock_base.reset.assert_called_once()
    mock_custom.reset.assert_called_once()

    # Line 126: Omitted trajectory_id UUID generation
    res = orchestrator.process_step([0.7, 0.3], 1.0, {"step": 1}, trajectory_id=None)
    assert res is not None

    # Line 167: SENSITIVE_FIELDS fallback
    import epistemicos.core
    with patch.object(epistemicos.core.CanonicalProblemRepresentation, "SENSITIVE_FIELDS", "not_a_set", create=True):
        res_sub = orchestrator.process_submission({"fleet_data": {}}, {"token_count": 1, "token_logprobs": [-0.1]})
        assert res_sub["status"] == "HALTED"

    # Lines 200-203: Fail-closed gate evaluation exception
    class FaultyGate(Gate):
        def evaluate(self, payload, context):
            raise RuntimeError("Database connection lost")

    orch_faulty = EpistemicOrchestrator()
    orch_faulty.register_gate(FaultyGate())
    res_fault = orch_faulty.process_submission({"policy_id": "P1", "fleet_data": {}}, {"token_count": 1, "token_logprobs": [-0.1]})
    assert res_fault["status"] == "HALTED"
    assert "Database connection lost" in res_fault["reason"]


# 5. GATES.PY REMEDIATION
from epistemicos.gates import GateOutcome, GateDecision, GateResult, GateAction, ControlPlaneGate, GateInput, GateConfig, PermissionGate

def test_gates_outcome_status_result_legacy_and_control_plane():
    # Lines 82, 86: GateOutcome status and reason properties
    out = GateOutcome(decision=GateDecision.HALT, reason_code="REASON_X", gate_name="G1")
    assert out.status == "HALTED"
    assert out.reason == "REASON_X"

    # Lines 140-141: GateResult legacy constructor with non-GateAction 'action'
    res_leg = GateResult(action="NOT_ENUM", status="HALTED", gate_name="G1")
    assert res_leg.action == GateAction.HALT

    # Lines 194, 207, 231: Abstract methods & evaluate_safe non-critical error
    class TestControlGate(ControlPlaneGate):
        def evaluate(self, payload, context): return GateResult(action=GateAction.ALLOW)
        def evaluate_contract(self, gi):
            if gi.payload.get("err"): raise RuntimeError("Non-critical error")
            return GateOutcome(decision=GateDecision.ALLOW, gate_name="G1")

    cg = TestControlGate(config=GateConfig(is_critical=False))
    assert Gate.evaluate(cg, {}, {}) is None
    assert ControlPlaneGate.evaluate_contract(cg, GateInput(payload={}, context={})) is None
    out_safe = cg.evaluate_safe(GateInput(payload={"err": True}, context={}))
    assert out_safe.decision == GateDecision.INDETERMINATE

def test_permission_gate_model_validate_dict_traversal_and_trusted_scope():
    # Lines 342-343: model_validate fallback
    class ModelVal:
        @classmethod
        def model_validate(cls, obj):
            if isinstance(obj, str): raise ValueError("Validation fail")
            return cls()

    pg = PermissionGate(contract_model=ModelVal)
    res_val = pg.evaluate({"llm_output": "bad_str"}, {})
    assert res_val.passed is False

    # Lines 439, 447-448, 453-454: SensitiveData search recursion
    class CustomObj:
        def __init__(self, k): self.k = k

    c_list = []
    c_list.append(c_list)
    custom_obj = CustomObj(123)

    payload = {123: "val", "obj": custom_obj, "cycle": c_list}
    assert pg.evaluate(payload, {})["passed"] is True

    # Lines 531, 533: trusted_scope model_dump and __dict__
    class ScopeDump:
        def model_dump(self): return {"allowed_operations": ["op1"], "allowed_resources": ["r1"]}

    class ScopeDict:
        def __init__(self): self.allowed_operations = ["op2"]; self.allowed_resources = ["r2"]

    pg_dump = PermissionGate(contract_model=ModelVal, trusted_scope=ScopeDump())
    assert pg_dump.evaluate({"scope": {}}, {"proposed_actions": [{"op": "op1", "node": "r1"}]}).passed is True

    pg_dict = PermissionGate(contract_model=ModelVal, trusted_scope=ScopeDict())
    assert pg_dict.evaluate({"scope": {}}, {"proposed_actions": [{"op": "op2", "node": "r2"}]}).passed is True


# 6. MODELS.PY REMEDIATION
from epistemicos.models import _estimate_payload_size, PermissionScope, TokenSurprisalSensor

def test_models_estimate_payload_non_scalar_key_and_quarantine():
    # Lines 65-66, 80: Primitive scalar sizing & non-scalar key
    scalar_list = [10, 20.5, True, "str"]
    assert _estimate_payload_size(scalar_list) > 0

    non_scalar_key_dict = {(1, 2): "value"}
    assert _estimate_payload_size(non_scalar_key_dict) > 0

    # Line 338: Non-matching subnet quarantine
    scope = PermissionScope(origin_subnet="192.168.1.1", quarantine_subnets=["10.240."])
    assert scope.is_quarantined_channel() is False

def test_models_token_surprisal_sensor_non_finite():
    sensor = TokenSurprisalSensor()

    class CustomFloat:
        def __init__(self, v): self.v = v
        def __float__(self): return float(self.v)

    # Lines 141-143: non-finite logprobs in compute_z_scores
    with pytest.raises(ValueError, match="Malformed or non-finite logprob"):
        sensor.compute_z_scores([CustomFloat(-0.1), CustomFloat(float("nan"))])


# 7. PROVENANCE.PY REMEDIATION
from epistemicos.provenance import ProvenanceEvent, ProvenanceEventType, ProvenanceSource, ProvenanceStore, LocalProvenanceStore

def test_provenance_digest_abstract_and_store_fallbacks(tmp_path):
    evt = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="e_dig",
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="c1", request_id="r1", action_name="A", target="T",
        canonical_request_digest="dig", timestamp="ts"
    )

    # Lines 95-98: compute_event_digest
    assert len(evt.compute_event_digest()) == 64

    # Lines 105, 108: ProvenanceStore abstract methods
    class DummyStore(ProvenanceStore): pass
    ds = DummyStore()
    with pytest.raises(NotImplementedError): ds.record_event(evt)
    with pytest.raises(NotImplementedError): ds.get_events_for_correlation("c1")

    # Lines 25-26: fcntl ImportError fallback
    test_file = str(tmp_path / "prov_no_fcntl.jsonl")
    with patch.dict("sys.modules", {"fcntl": None}):
        import epistemicos.provenance
        importlib.reload(epistemicos.provenance)
        no_fcntl_store = epistemicos.provenance.LocalProvenanceStore(log_path=test_file)
        rec = no_fcntl_store.record_event(evt)
        assert rec["event_id"] == "e_dig"
    import epistemicos.provenance
    importlib.reload(epistemicos.provenance)

    # Lines 167-168: fsync OSError suppression
    log_file = tmp_path / "prov_fsync.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))
    with patch("os.fsync", side_effect=OSError("Not supported")):
        store.record_event(evt)

    # Lines 190, 227: blank lines skipping
    evt_blank = ProvenanceEvent("1.0.0", "e_b", ProvenanceEventType.ACTION_PROPOSED.value, ProvenanceSource.AGENT_ADAPTER.value, "c_blank", "r1", "A", "T", "dig", "ts")
    store.record_event(evt_blank)
    with open(log_file, "r") as f: c = f.read()
    with open(log_file, "w") as f: f.write("\n\n" + c + "\n\n  \n")
    assert len(store.get_events_for_correlation("c_blank")) == 1

    # Line 221: missing log_path return
    missing_store = LocalProvenanceStore(log_path=str(tmp_path / "missing.jsonl"))
    assert missing_store.get_events_for_correlation("c1") == []


# 8. SCHEDULER.PY REMEDIATION
from epistemicos.scheduler import EntropyAwareScheduler

def test_scheduler_2d_rejection_no_torch_and_tensor_validations():
    class Mock2DSeq:
        @property
        def ndim(self): return 2

    scheduler = EntropyAwareScheduler()

    # Line 99: 2D array rejection
    with pytest.raises(ValueError, match="1D distribution sequence"):
        scheduler.entropy(Mock2DSeq())

    # Lines 130-136: Pure Python entropy calculation without torch
    with patch.dict("sys.modules", {"torch": None}):
        assert abs(scheduler.entropy([0.5, 0.5, 0.0]) - 1.0) < 1e-5

    # Torch validations (Lines 142, 145, 152, 157)
    torch = pytest.importorskip("torch")

    # Line 142: Non-1D tensor
    with pytest.raises(ValueError, match="1D distribution sequence"):
        scheduler.entropy(torch.tensor([[0.5, 0.5], [0.5, 0.5]]))

    # Line 145: NaN / Inf tensor
    with pytest.raises(ValueError, match="cannot contain NaN or non-finite"):
        scheduler.entropy(torch.tensor([0.5, float("nan")]))

    # Line 152: Non-positive sum
    with pytest.raises(ValueError, match="must sum to a positive finite value"):
        scheduler.entropy(torch.tensor([0.0, 0.0]))

    # Line 157: Zero positive elements fallback
    t_valid = torch.tensor([0.5, 0.5])
    with patch.object(torch.Tensor, "__getitem__", return_value=torch.tensor([])):
        assert scheduler.entropy(t_valid) == 0.0
