"""
Adversarial Regression Test Suite for GAP-WID-01: Tool-Output Credential Isolation.

Verifies:
1. Credential values in nested dictionaries and lists are redacted.
2. Sensitive dictionary keys such as "secret", "api_key", "password", "token" are redacted.
3. Recognized credential patterns embedded in ordinary strings are redacted.
4. Credentials returned by tools through SUCCESS, UNVERIFIED_SUCCESS, and
   EXECUTION_OUTCOME_UNKNOWN are sanitized.
5. Audit-recording failure preserves sanitization on the returned EXECUTION_OUTCOME_UNKNOWN object.
6. Sanitization of returned objects does not mutate the executor's internal/original object.
7. Ordinary non-sensitive application outputs remain functional and unchanged.
8. Documented limitations: A secret-bearing result that regex patterns do not recognize
   (without sensitive key names) is documented, while sensitive keys protect opaque strings.
9. Attempts to bypass output sanitization through TrustedToolWrapper or EpistemicOrchestrator fail.
10. Existing tool consumers and execution boundary invariants continue to hold.
"""

import copy
import uuid

from epistemicos.authorization import AuthorizationAuthority, Policy
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    ExecutionContext,
    LocalProvenanceStore,
    ProvenanceEventType,
)
from epistemicos.tools import TrustedToolRegistry
from epistemicos.core import EpistemicOrchestrator


def _make_open_policy():
    return Policy(
        policy_id="test_open_policy",
        allowed_operations={"*"},
        allowed_resources={"*"},
        allowed_principals={"*"}
    )


def test_gap_wid_01_nested_dictionaries_and_lists(tmp_path):
    """Scenario 1: Credential values inside deep nested dictionaries and lists are sanitized."""
    raw_secret = "sk-ant-api03-abcdefghijklmnop1234567890"

    def leaking_executor():
        return {
            "metadata": {
                "accounts": [
                    {"id": 1, "connection_info": {"raw_key": raw_secret}},
                    {"id": 2, "tokens": ["Bearer some_jwt_token_value_abc123"]}
                ]
            }
        }

    store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))
    auth = AuthorizationAuthority(default_policy=_make_open_policy())
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=auth)

    payload = {"op": "test"}
    digest = boundary.compute_canonical_digest(payload)
    cap, _ = auth.evaluate_and_issue_capability(
        action_name="test",
        target="/res",
        canonical_request_digest=digest,
        executor_id=leaking_executor
    )

    ctx = ExecutionContext(
        correlation_id=cap.correlation_id,
        request_id=cap.request_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    outcome = boundary.execute_protected_action(
        action_name="test",
        target="/res",
        request_payload=payload,
        executor_func=leaking_executor,
        context=ctx
    )

    assert outcome["status"] == "SUCCESS"
    res = outcome["result"]
    assert raw_secret not in str(res)
    assert res["metadata"]["accounts"][0]["connection_info"]["raw_key"] == "sk-[REDACTED]"
    assert "some_jwt_token" not in str(res)
    assert res["metadata"]["accounts"][1]["tokens"] == "[REDACTED]"


def test_gap_wid_01_sensitive_dictionary_keys():
    """Scenario 2: Sensitive keys like secret, api_key, password, token are redacted."""
    def sensitive_keys_executor():
        return {
            "api_key": "custom_opaque_secret_value_12345",
            "password": "SuperSecretPassword!",
            "token": "opaque_session_token_xyz",
            "client_secret": "999888777",
            "safe_token_id": "ID-12345",  # SAFE_KEY_SUFFIXES preserves _id
            "system_status": "ONLINE"
        }

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="cred_tool",
        action_name="query_creds",
        executor_func=sensitive_keys_executor,
        default_target="/credentials"
    )

    res = tool()
    assert res["status"] == "SUCCESS"
    data = res["result"]
    assert data["api_key"] == "[REDACTED]"
    assert data["password"] == "[REDACTED]"
    assert data["token"] == "[REDACTED]"
    assert data["client_secret"] == "[REDACTED]"
    # Legitimate non-sensitive suffix preserved
    assert data["safe_token_id"] == "ID-12345"
    assert data["system_status"] == "ONLINE"


def test_gap_wid_01_recognized_credential_patterns_in_strings():
    """Scenario 3: Recognized credential patterns embedded in ordinary strings are redacted."""
    raw_gh_token = "ghp_111111111111111111111111111111111111"
    raw_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

    def pattern_executor():
        return {
            "message": f"Fetched repository with token {raw_gh_token} and auth header {raw_bearer}"
        }

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="pattern_tool",
        action_name="fetch_repo",
        executor_func=pattern_executor,
        default_target="/repo"
    )

    res = tool()
    msg = res["result"]["message"]
    assert raw_gh_token not in msg
    assert "sk-[REDACTED]" in msg or "[REDACTED]" in msg
    assert "Bearer [REDACTED]" in msg


def test_gap_wid_01_all_three_execution_statuses(tmp_path):
    """
    Scenario 4: Credentials returned through SUCCESS, UNVERIFIED_SUCCESS, and
    EXECUTION_OUTCOME_UNKNOWN are sanitized.
    """
    store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))

    # 1. SUCCESS path
    def success_tool():
        return {"password": "admin_password_1"}

    auth = AuthorizationAuthority(default_policy=_make_open_policy())
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=auth)

    cap_s, _ = auth.evaluate_and_issue_capability("op", "/t", "d1", executor_id=success_tool)
    ctx_s = ExecutionContext(
        correlation_id=cap_s.correlation_id, request_id=cap_s.request_id,
        authorization_token_id=cap_s.token_id, authorized_digest="d1", authorization_granted=True
    )
    boundary.compute_canonical_digest = lambda x: "d1"

    out_s = boundary.execute_protected_action(
        "op", "/t", {}, executor_func=success_tool, context=ctx_s
    )
    assert out_s["status"] == "SUCCESS"
    assert out_s["result"]["password"] == "[REDACTED]"

    # 2. UNVERIFIED_SUCCESS path (missing required evidence)
    def unverified_tool():
        return {"status": "ok", "api_key": "secret_key_123"}

    cap_u, _ = auth.evaluate_and_issue_capability("op", "/t", "d2", executor_id=unverified_tool)
    ctx_u = ExecutionContext(
        correlation_id=cap_u.correlation_id, request_id=cap_u.request_id,
        authorization_token_id=cap_u.token_id, authorized_digest="d2", authorization_granted=True,
        required_success_evidence={"missing_signature"}
    )
    boundary.compute_canonical_digest = lambda x: "d2"

    out_u = boundary.execute_protected_action(
        "op", "/t", {}, executor_func=unverified_tool, context=ctx_u
    )
    assert out_u["status"] == "UNVERIFIED_SUCCESS"
    assert out_u["result"]["api_key"] == "[REDACTED]"

    # 3. EXECUTION_OUTCOME_UNKNOWN path (terminal audit recording failure)
    def unknown_tool():
        return {"secret_token": "sk-ant-api03-abcdefghijklmnop1234567890"}

    cap_k, _ = auth.evaluate_and_issue_capability("op", "/t", "d3", executor_id=unknown_tool)
    ctx_k = ExecutionContext(
        correlation_id=cap_k.correlation_id, request_id=cap_k.request_id,
        authorization_token_id=cap_k.token_id, authorized_digest="d3", authorization_granted=True
    )
    boundary.compute_canonical_digest = lambda x: "d3"

    # Make store.record_event fail specifically for EXECUTION_SUCCEEDED
    orig_record = store.record_event

    def failing_record(event):
        if event.event_type == ProvenanceEventType.EXECUTION_SUCCEEDED.value:
            raise IOError("Simulated disk error during terminal provenance write")
        return orig_record(event)

    store.record_event = failing_record

    out_k = boundary.execute_protected_action(
        "op", "/t", {}, executor_func=unknown_tool, context=ctx_k
    )
    assert out_k["status"] == "EXECUTION_OUTCOME_UNKNOWN"
    assert out_k["audit_recording_failed"] is True
    assert out_k["result"]["secret_token"] == "[REDACTED]"


def test_gap_wid_01_original_object_not_mutated():
    """Scenario 6: Sanitization creates a safe structure without mutating original object."""
    original_state = {
        "password": "raw_db_password_never_mutate_me",
        "nested": {"token": "sk-ant-api03-abcdefghijklmnop1234567890"}
    }
    copy_baseline = copy.deepcopy(original_state)

    def stateful_executor():
        return original_state

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="state_tool",
        action_name="get_state",
        executor_func=stateful_executor,
        default_target="/state"
    )

    res = tool()
    assert res["status"] == "SUCCESS"
    # The returned result is redacted
    assert res["result"]["password"] == "[REDACTED]"
    assert res["result"]["nested"] == "[REDACTED]" or (
        res["result"]["nested"]["token"] == "[REDACTED]"
    )

    # The internal/original state object in the executor remains intact
    assert original_state == copy_baseline
    assert original_state["password"] == "raw_db_password_never_mutate_me"


def test_gap_wid_01_ordinary_non_sensitive_output_unaffected():
    """Scenario 7: Ordinary non-sensitive tool outputs remain fully functional and uncorrupted."""
    normal_output = {
        "user_count": 42,
        "active_nodes": ["node-1", "node-2"],
        "status": "HEALTHY",
        "configuration": {
            "retries": 3,
            "timeout_ms": 5000,
            "log_level": "INFO"
        }
    }

    def normal_executor():
        return normal_output

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="normal_tool",
        action_name="get_status",
        executor_func=normal_executor,
        default_target="/system/status"
    )

    res = tool()
    assert res["status"] == "SUCCESS"
    assert res["result"] == normal_output


def test_gap_wid_01_unrecognized_secret_documentation_and_limitation():
    """
    Scenario 8: Establish behavior on secrets not recognized by regex patterns.
    If key name is sensitive (e.g. 'client_secret'), it is ALWAYS redacted.
    If both key and value are completely arbitrary/unstructured (e.g. key='data', val='opaque_key'),
    the regex does not match. Demonstrates why key-based + pattern-based isolation is vital.
    """
    unstructured_secret = "opaque_arbitrary_string_without_delimiters_or_known_prefix"

    # 1. Under sensitive key: protected
    def cred_tool():
        return {"secret": unstructured_secret}

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    t1 = reg.register_tool(
        tool_id="t1", action_name="a1", executor_func=cred_tool, default_target="/t1"
    )
    res1 = t1()
    assert res1["result"]["secret"] == "[REDACTED]"

    # 2. Under non-sensitive key without trigger: documented limitation of regex sanitization
    def generic_tool():
        return {"data": unstructured_secret}

    t2 = reg.register_tool(
        tool_id="t2", action_name="a2", executor_func=generic_tool, default_target="/t2"
    )
    res2 = t2()
    # Documents that regex sanitizers cannot detect arbitrary strings without key context
    assert res2["result"]["data"] == unstructured_secret


def test_gap_wid_01_orchestrator_pipeline_propagation_sanitized(tmp_path):
    """Scenario 9: Verifies that EpistemicOrchestrator propagates sanitized outcomes to clients."""
    raw_api_key = "sk-ant-api03-abcdefghijklmnop1234567890"

    def leaking_tool():
        return {"api_key": raw_api_key, "data": "analysis"}

    boundary = TrustedExecutionBoundary()
    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(tmp_path / "orchestrator_audit.jsonl"),
        execution_boundary=boundary
    )

    open_policy = Policy(
        policy_id="pol_leak",
        allowed_operations={"leak_op"},
        allowed_resources={"/creds"}
    )
    orchestrator.authority.default_policy = open_policy
    orchestrator.authority.register_executor("leaking_tool", leaking_tool)

    payload = {
        "policy_id": "pol_leak",
        "proposed_actions": [{"op": "leak_op", "endpoint": "/creds"}]
    }
    context = {
        "token_count": 5,
        "token_logprobs": [-0.01] * 5,
        "actual_executable": leaking_tool,
        "correlation_id": f"corr-{uuid.uuid4()}",
        "trusted_scope": {
            "allowed_operations": ["leak_op"],
            "allowed_resources": ["/creds"]
        }
    }

    submission_res = orchestrator.process_submission(payload, context)
    assert submission_res["status"] == "ALLOWED"
    outcome = submission_res["execution_outcome"]
    assert outcome["status"] == "SUCCESS"
    assert outcome["result"]["api_key"] == "[REDACTED]"
    assert raw_api_key not in str(submission_res)


def test_gap_wid_01_caller_cannot_opt_out_of_sanitization():
    """Scenario 10: Untrusted caller supplying bypass kwargs cannot disable sanitization."""
    def sensitive_tool():
        return {"password": "admin_db_secret"}

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="bypass_test_tool",
        action_name="query_db",
        executor_func=sensitive_tool,
        default_target="/db"
    )

    # Caller attempts to supply unmask=True or raw_output=True in context
    res = tool(context={"unmask": True, "raw_output": True, "skip_sanitization": True})
    assert res["status"] == "SUCCESS"
    assert res["result"]["password"] == "[REDACTED]"


def test_gap_wid_01_custom_objects_dataclasses_and_mappings():
    """Scenario 11: Non-primitive results (dataclasses, Mappings, custom objects) are sanitized."""
    from dataclasses import dataclass
    from collections.abc import Mapping

    @dataclass
    class ServiceCredentials:
        service: str
        api_key: str
        token: str

    class CustomHeaderMapping(Mapping):
        def __init__(self, data):
            self._data = data

        def __getitem__(self, k):
            return self._data[k]

        def __iter__(self):
            return iter(self._data)

        def __len__(self):
            return len(self._data)

    class CustomResultObject:
        def __init__(self):
            self.status = "SUCCESS"
            self.password = "secret_password"
            self.client_id = "CID-001"

    def complex_tool():
        return {
            "service_data": ServiceCredentials(
                "auth_svc", "sk-ant-api03-12345678901234567890", "opaque_tok"
            ),
            "headers_map": CustomHeaderMapping(
                {"Authorization": "Bearer token123", "X-Custom": "val"}
            ),
            "custom_inst": CustomResultObject()
        }

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="complex_tool",
        action_name="get_complex",
        executor_func=complex_tool,
        default_target="/complex"
    )

    res = tool()
    assert res["status"] == "SUCCESS"
    r = res["result"]
    assert r["service_data"]["api_key"] == "[REDACTED]"
    assert r["service_data"]["token"] == "[REDACTED]"
    assert r["headers_map"]["Authorization"] == "[REDACTED]"
    assert r["headers_map"]["X-Custom"] == "val"
    assert r["custom_inst"]["password"] == "[REDACTED]"
    assert r["custom_inst"]["client_id"] == "CID-001"


def test_gap_wid_01_slotted_objects_with_credentials():
    """Scenario 12: Objects using __slots__ carrying credentials are appropriately redacted."""
    class SlottedParent:
        __slots__ = ("parent_secret", "normal_id")

    class SlottedChild(SlottedParent):
        __slots__ = ("api_key", "public_info")

    def slotted_tool():
        inst = SlottedChild()
        inst.parent_secret = "master_password_abc"
        inst.normal_id = "SVC-99"
        inst.api_key = "sk-ant-api03-abcdefghijklmnop1234567890"
        inst.public_info = {"version": "2.1"}
        return inst

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="slotted_tool",
        action_name="get_slotted",
        executor_func=slotted_tool,
        default_target="/slotted"
    )

    res = tool()
    assert res["status"] == "SUCCESS"
    r = res["result"]
    assert r["parent_secret"] == "[REDACTED]"
    assert r["api_key"] == "[REDACTED]"
    assert r["normal_id"] == "SVC-99"
    assert r["public_info"]["version"] == "2.1"


def test_gap_wid_01_cyclic_references_handled_deterministically():
    """Scenario 13: Self-referencing structures do not trigger uncontrolled recursion or crash."""
    # 1. Cyclic dict
    def cyclic_dict_tool():
        d = {"status": "ok", "api_key": "sk-ant-api03-abcdefghijklmnop1234567890"}
        d["self_ref"] = d
        return d

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    t1 = reg.register_tool(
        tool_id="t_cyc_d", action_name="cyc_d", executor_func=cyclic_dict_tool, default_target="/t"
    )
    res1 = t1()
    assert res1["status"] == "SUCCESS"
    assert res1["result"]["api_key"] == "[REDACTED]"
    assert res1["result"]["self_ref"] == "[CIRCULAR_REFERENCE]"

    # 2. Cyclic list
    def cyclic_list_tool():
        lst = ["safe", "Bearer secret_bearer_token"]
        lst.append(lst)
        return lst

    t2 = reg.register_tool(
        tool_id="t_cyc_l", action_name="cyc_l", executor_func=cyclic_list_tool, default_target="/t"
    )
    res2 = t2()
    assert res2["status"] == "SUCCESS"
    assert "Bearer [REDACTED]" in res2["result"][1]
    assert res2["result"][2] == "[CIRCULAR_REFERENCE]"


def test_gap_wid_01_self_returning_serialization_hooks():
    """Scenario 14: Model serialization hooks returning self do not trigger unbounded recursion."""
    class CyclicModelHook:
        def __init__(self):
            self.password = "secret_pass"

        def model_dump(self):
            return self

    def model_hook_tool():
        return CyclicModelHook()

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="t_hook", action_name="hook", executor_func=model_hook_tool, default_target="/t"
    )
    res = tool()
    assert res["status"] == "SUCCESS"
    assert res["result"]["password"] == "[REDACTED]"


def test_gap_wid_01_unsupported_object_with_no_dict_or_slots_redacted():
    """Scenario 15: Objects without __dict__ or __slots__ fail closed rather than passing."""
    import sqlite3

    def sqlite_row_tool():
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute('select "sk-ant-secret-12345" as secret, "admin" as user')
        return cur.fetchone()

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="row_tool",
        action_name="get_row",
        executor_func=sqlite_row_tool,
        default_target="/db"
    )
    res = tool()
    assert res["status"] == "SUCCESS"
    # Fails closed to [UNSUPPORTED_OBJECT] rather than leaking the raw sqlite3.Row object
    assert res["result"] == "[UNSUPPORTED_OBJECT]"


def test_gap_wid_01_untrusted_serialization_hooks_not_blindly_invoked():
    """Scenario 16: Arbitrary serialization hooks with side-effects or errors are not invoked."""
    hook_invoked = False

    class EvilHookObject:
        def __init__(self):
            self.normal_attr = "ok"

        def to_dict(self):
            nonlocal hook_invoked
            hook_invoked = True
            raise RuntimeError("Untrusted serialization side effect or bomb!")

    def evil_hook_tool():
        return EvilHookObject()

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="evil_tool",
        action_name="get_evil",
        executor_func=evil_hook_tool,
        default_target="/obj"
    )
    res = tool()
    assert res["status"] == "SUCCESS"
    # Sanitization relied on safe __dict__ inspection without invoking arbitrary to_dict()
    assert hook_invoked is False
    assert res["result"] == {"normal_attr": "ok"}


def test_gap_wid_01_cyclic_custom_objects_and_cyclic_dataclasses():
    """Scenario 17: Cyclic __dict__ objects and cyclic dataclasses are handled deterministically."""
    from dataclasses import dataclass

    # 1. Cyclic object with __dict__
    class CyclicCustom:
        def __init__(self):
            self.token = "sk-ant-api03-abcdefghijklmnop1234567890"
            self.ref = self

    def cyclic_custom_tool():
        return CyclicCustom()

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    t1 = reg.register_tool(
        tool_id="t_custom",
        action_name="custom",
        executor_func=cyclic_custom_tool,
        default_target="/t"
    )
    res1 = t1()
    assert res1["status"] == "SUCCESS"
    assert res1["result"]["token"] == "[REDACTED]"
    assert res1["result"]["ref"] == "[CIRCULAR_REFERENCE]"

    # 2. Cyclic dataclass
    @dataclass
    class Node:
        secret: str
        next_node: "Node" = None

    def cyclic_dc_tool():
        n = Node("super_secret_dc")
        n.next_node = n
        return n

    t2 = reg.register_tool(
        tool_id="t_dc", action_name="dc", executor_func=cyclic_dc_tool, default_target="/t"
    )
    res2 = t2()
    assert res2["status"] == "SUCCESS"
    assert res2["result"]["secret"] == "[REDACTED]"
    assert res2["result"]["next_node"] == "[CIRCULAR_REFERENCE]"

    # 3. Cyclic slotted object
    class SlottedCyclicNode:
        __slots__ = ("api_key", "cycle_ref")

    def cyclic_slot_tool():
        sn = SlottedCyclicNode()
        sn.api_key = "sk-ant-api03-abcdefghijklmnop1234567890"
        sn.cycle_ref = sn
        return sn

    t3 = reg.register_tool(
        tool_id="t_slot_cyc",
        action_name="slot_cyc",
        executor_func=cyclic_slot_tool,
        default_target="/t"
    )
    res3 = t3()
    assert res3["status"] == "SUCCESS"
    assert res3["result"]["api_key"] == "[REDACTED]"
    assert res3["result"]["cycle_ref"] == "[CIRCULAR_REFERENCE]"


def test_gap_wid_01_sanitization_failure_preserves_execution_status():
    """Scenario 18: If sanitization throws, safe failure representation is returned."""
    from unittest.mock import patch
    from epistemicos.audit import _sanitize_sensitive_data as real_sanitize

    def exploding_sanitize_tool():
        return {"status": "ok", "secret": "leaked_secret"}

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="exploding_tool",
        action_name="explode_action",
        executor_func=exploding_sanitize_tool,
        default_target="/explode"
    )

    def explode_on_tool_result(obj, *args, **kwargs):
        if isinstance(obj, dict) and obj.get("secret") == "leaked_secret":
            raise TypeError("Simulated traversal fault on tool result")
        return real_sanitize(obj, *args, **kwargs)

    with patch(
        "epistemicos.provenance._sanitize_sensitive_data",
        side_effect=explode_on_tool_result
    ):
        res = tool()

    assert res["status"] == "SUCCESS"
    # Never leaks the raw dict {"status": "ok", "secret": "leaked_secret"}
    assert res["result"] == "[SANITIZATION_FAILED: TypeError]"


def test_gap_wid_01_credential_bearing_and_unsupported_dictionary_keys():
    """Scenario 19: Credentials in keys are sanitized and uninspected key objects fail closed."""
    class EvilKeyObject:
        def __str__(self):
            raise RuntimeError("Dangerous side-effect in __str__")

    def dict_key_tool():
        return {
            "sk-ant-api03-abcdefghijklmnop1234567890": "credential_key_value",
            "header_with_Bearer token_123": "bearer_key_value",
            EvilKeyObject(): "evil_key_value",
            "normal_safe_key": "normal_data",
            42: "integer_key"
        }

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="key_tool",
        action_name="get_keys",
        executor_func=dict_key_tool,
        default_target="/keys"
    )
    res = tool()
    assert res["status"] == "SUCCESS"
    r = res["result"]
    assert "sk-ant-api03-abcdefghijklmnop1234567890" not in r
    assert "sk-[REDACTED]" in r
    assert r["sk-[REDACTED]"] == "credential_key_value"
    assert "header_with_Bearer [REDACTED]" in r
    # Because key contains 'bearer' (a sensitive key pattern), its associated value is also redacted
    assert r["header_with_Bearer [REDACTED]"] == "[REDACTED]"
    assert "[UNSUPPORTED_KEY]" in r
    assert r["[UNSUPPORTED_KEY]"] == "evil_key_value"
    assert r["normal_safe_key"] == "normal_data"
    assert r["42"] == "integer_key"


def test_gap_wid_01_dataclass_with_evil_deepcopy_never_invoked():
    """Scenario 20: Dataclass sanitization inspects fields directly without __deepcopy__."""
    deepcopy_called = False

    class EvilDeepCopyObject:
        def __init__(self):
            self.val = "evil_sub"

        def __deepcopy__(self, memo):
            nonlocal deepcopy_called
            deepcopy_called = True
            raise RuntimeError("Untrusted __deepcopy__ executed!")

    from dataclasses import dataclass

    @dataclass
    class DeepCopyTestDC:
        service: str
        token: str
        sub_obj: EvilDeepCopyObject

    def dc_tool():
        return DeepCopyTestDC(
            "auth_service",
            "sk-ant-api03-abcdefghijklmnop1234567890",
            EvilDeepCopyObject()
        )

    reg = TrustedToolRegistry()
    reg.authority.default_policy = _make_open_policy()
    tool = reg.register_tool(
        tool_id="dc_tool", action_name="get_dc", executor_func=dc_tool, default_target="/dc"
    )
    res = tool()
    assert res["status"] == "SUCCESS"
    r = res["result"]
    assert deepcopy_called is False
    assert r["service"] == "auth_service"
    assert r["token"] == "[REDACTED]"
    assert r["sub_obj"] == {"val": "evil_sub"}
