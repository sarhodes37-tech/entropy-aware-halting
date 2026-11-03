"""
Comprehensive Unit Tests for epistemicos/tools.py Coverage Closeout.

Focuses on edge cases, constructor validation, signature/target binding,
read-only vs mutating target extraction, conflicting/missing targets,
custom extractor failures, principal authentication, policy enforcement,
executor argument binding, provenance recording, execution-boundary failures,
and capability cleanup.
"""

import inspect
import time
import unittest.mock as mock
import pytest

from epistemicos.tools import TrustedToolRegistry, TrustedToolWrapper
from epistemicos.authorization import (
    AuthorizationAuthority,
    Policy,
    AuthenticatedPrincipal,
    CapabilityRegistry,
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
)
from epistemicos.core import EpistemicOrchestrator


@pytest.fixture
def test_setup(tmp_path):
    prov_path = tmp_path / "provenance.jsonl"
    denial_path = tmp_path / "denial.jsonl"

    store = LocalProvenanceStore(log_path=str(prov_path))
    cap_registry = CapabilityRegistry(denial_log_path=str(denial_path))
    authority = AuthorizationAuthority(registry=cap_registry)
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=authority)
    registry = TrustedToolRegistry(authority=authority, execution_boundary=boundary)

    return {
        "registry": registry,
        "authority": authority,
        "boundary": boundary,
        "store": store,
        "cap_registry": cap_registry,
    }


# ============================================================================
# 1. Constructor Validation & Signature Binding
# ============================================================================

def test_wrapper_init_invalid_arguments():
    """Lines 50, 53, 56: Validate tool_id, action_name, and callable executor_func."""
    def dummy():
        return None

    # Invalid tool_id
    with pytest.raises(ValueError, match="tool_id must be a non-empty string"):
        TrustedToolWrapper("", "read_file", dummy, None)
    with pytest.raises(ValueError, match="tool_id must be a non-empty string"):
        TrustedToolWrapper("   ", "read_file", dummy, None)
    with pytest.raises(ValueError, match="tool_id must be a non-empty string"):
        TrustedToolWrapper(None, "read_file", dummy, None)

    # Invalid action_name
    with pytest.raises(ValueError, match="action_name must be a non-empty string"):
        TrustedToolWrapper("tool1", "", dummy, None)
    with pytest.raises(ValueError, match="action_name must be a non-empty string"):
        TrustedToolWrapper("tool1", "   ", dummy, None)
    with pytest.raises(ValueError, match="action_name must be a non-empty string"):
        TrustedToolWrapper("tool1", None, dummy, None)

    # Non-callable executor_func
    with pytest.raises(ValueError, match="executor_func must be a callable object"):
        TrustedToolWrapper("tool1", "read_file", "not_callable", None)


def test_wrapper_init_uninspectable_signature_handling():
    """
    Lines 81-84, 108: Mutating operations require inspectable signature,
    whereas read-only operations fall back to _executor_sig = None.
    If target_param is provided on read-only with uninspectable signature, raise ValueError.
    """
    def dummy():
        return None

    with mock.patch("inspect.signature", side_effect=TypeError("built-in function")):
        # Mutating operation fails initialization (lines 81-84)
        msg_mut = "Executor signature must be inspectable for mutating operation"
        with pytest.raises(ValueError, match=msg_mut):
            TrustedToolWrapper("tool1", "write_file", dummy, None)

        # Read-only operation with uninspectable signature succeeds when no target_param (line 84)
        wrapper_ro = TrustedToolWrapper(
            "tool_ro", "read_file", dummy, None, default_target="resource:default"
        )
        assert wrapper_ro._executor_sig is None

        # Read-only operation with uninspectable signature fails if target_param provided (line 108)
        msg_tp = "Executor signature must be inspectable to bind target_param"
        with pytest.raises(ValueError, match=msg_tp):
            TrustedToolWrapper("tool_ro_target", "read_file", dummy, None, target_param="path")


def test_wrapper_init_mutating_target_param_deduction():
    """
    Line 92: Automatic deduction of target_param = 'target' when 'target' is in signature.
    """
    def mut_func(target, data=""):
        return f"{target}:{data}"

    wrapper = TrustedToolWrapper("mut_tool", "write_file", mut_func, None)
    assert wrapper.target_param == "target"
    assert not wrapper.is_read_only


def test_wrapper_init_mutating_no_target_param_no_target_arg_raises():
    """
    Lines 97-99, 101-103: Mutating operation with multi-arg signature lacking 'target'
    and without explicit target_param or default_target raises ValueError.
    """
    def mut_func_custom(dest_path, data):
        return None

    msg = "requires explicit 'target_param' bound to executor signature"
    with pytest.raises(ValueError, match=msg):
        TrustedToolWrapper("mut_custom", "write_file", mut_func_custom, None)

    # Line 101: if _executor_sig evaluated to None on mutating without target_param
    with mock.patch("inspect.signature", return_value=None):
        with pytest.raises(ValueError, match=msg):
            TrustedToolWrapper("mut_no_sig", "write_file", mut_func_custom, None)


def test_wrapper_init_target_param_not_in_signature():
    """
    Lines 111-114: target_param specified does not exist in executor signature.
    """
    def dummy_func(arg1):
        return arg1

    with pytest.raises(ValueError, match="does not exist in executor signature parameters"):
        TrustedToolWrapper("tool1", "read_file", dummy_func, None, target_param="nonexistent_arg")


def test_wrapper_init_without_registry_or_authority():
    """
    Line 117 branch: Wrapper initialization when registry or registry.authority is None.
    """
    def dummy():
        return None

    w1 = TrustedToolWrapper("w1", "read_file", dummy, None, default_target="target1")
    assert w1.registry is None

    class MockRegNoAuth:
        authority = None

    w2 = TrustedToolWrapper("w2", "read_file", dummy, MockRegNoAuth(), default_target="target2")
    assert w2.registry.authority is None


# ============================================================================
# 2. Target Extraction: Read-Only Operations
# ============================================================================

def test_extract_target_read_only_bound_target_param(test_setup):
    """
    Lines 154-166: Read-only target extraction via bound signature target_param,
    fallback when bind_partial fails but target_param exists in kwargs,
    and branch when _executor_sig is None.
    """
    registry = test_setup["registry"]

    def read_node(node_id=""):
        return node_id

    wrapper = registry.register_tool(
        tool_id="node_reader",
        action_name="read_file",
        executor_func=read_node,
        target_param="node_id",
        default_target="default_node",
    )

    # 1. Target extracted from positional argument bound to target_param
    target_pos = wrapper._extract_actual_target(("cluster_node_1",), {})
    assert target_pos == "cluster_node_1"

    # 2. Target extracted from kwarg bound to target_param
    target_kw = wrapper._extract_actual_target((), {"node_id": "cluster_node_2"})
    assert target_kw == "cluster_node_2"

    # 3. bind_partial fails, but filtered_kwargs contains target_param (lines 161-166)
    target_fallback = wrapper._extract_actual_target(
        ("extra1", "extra2"), {"node_id": "cluster_node_3"}
    )
    assert target_fallback == "cluster_node_3"

    # 4. _executor_sig is None, target_param extracted from filtered_kwargs (branch 154->163)
    wrapper._executor_sig = None
    assert wrapper._extract_actual_target((), {"node_id": "cluster_node_4"}) == "cluster_node_4"

    # 5. target_param in bound.arguments is empty/whitespace, falls through to default_target
    wrapper_ws = registry.register_tool(
        tool_id="node_ws",
        action_name="read_file",
        executor_func=read_node,
        target_param="node_id",
        default_target="fallback_node",
    )
    assert wrapper_ws._extract_actual_target(("   ",), {}) == "fallback_node"

    # 6. _executor_sig is None and target_param in filtered_kwargs is whitespace (branch 165->168)
    wrapper_ws._executor_sig = None
    assert wrapper_ws._extract_actual_target((), {"node_id": "   "}) == "fallback_node"

    # 7. target_param not in bound.arguments (branch 157->163)
    def multi_arg_reader(a=None, b=None):
        return a

    wrapper_multi = registry.register_tool(
        tool_id="node_multi",
        action_name="read_file",
        executor_func=multi_arg_reader,
        target_param="b",
        default_target="fallback_multi",
    )
    assert wrapper_multi._extract_actual_target(("val_a",), {}) == "val_a"


def test_extract_target_read_only_keyword_target(test_setup):
    """
    Lines 169-171: Read-only target extraction via explicit 'target' kwarg
    when target_param is not configured, and branch 170->174 when target is whitespace.
    """
    registry = test_setup["registry"]

    def simple_read():
        return "data"

    wrapper = registry.register_tool(
        tool_id="simple_read",
        action_name="read_file",
        executor_func=simple_read,
        default_target="fallback_target",
    )

    # Valid target in kwargs
    extracted = wrapper._extract_actual_target((), {"target": "resource/config.yaml"})
    assert extracted == "resource/config.yaml"

    # Whitespace target in kwargs falls through (branch 170->174)
    extracted_ws = wrapper._extract_actual_target((), {"target": "   "})
    assert extracted_ws == "fallback_target"


def test_extract_target_read_only_standard_resource_keys(test_setup):
    """
    Lines 173-190: Read-only target extraction via standard resource argument names
    ('path', 'file', 'filepath', 'node', 'endpoint', 'url', 'resource', 'filename', 'destination').
    Also covers branches 178->175 (whitespace in kwarg), 181->192 (no executor sig),
    187->184 (whitespace in bound arg), and lines 189-190 (bind exception).
    """
    registry = test_setup["registry"]

    def dummy_read(**kwargs):
        return kwargs

    wrapper = registry.register_tool(
        tool_id="kwarg_reader",
        action_name="read_file",
        executor_func=dummy_read,
    )
    resource_names = (
        "path", "file", "filepath", "node", "endpoint",
        "url", "resource", "filename", "destination"
    )
    for key in resource_names:
        res = wrapper._extract_actual_target((), {key: f"/app/{key}.dat"})
        assert res == f"/app/{key}.dat"

    # Branch 178->175: Whitespace in first resource kwarg continues loop to next resource kwarg
    res_loop = wrapper._extract_actual_target((), {"path": "   ", "file": "/app/valid.txt"})
    assert res_loop == "/app/valid.txt"

    # In signature bound parameters (positional or kwarg) (lines 181-190)
    def signature_resource_reader(endpoint, resource=""):
        return endpoint

    wrapper_sig = registry.register_tool(
        tool_id="sig_reader",
        action_name="read_file",
        executor_func=signature_resource_reader,
    )
    res_pos = wrapper_sig._extract_actual_target(("https://api.internal/v1",), {})
    assert res_pos == "https://api.internal/v1"

    # Branch 187->184: Whitespace in bound resource argument continues to next bound resource key
    def dual_resource_reader(endpoint="", resource=""):
        return endpoint

    wrapper_dual = registry.register_tool(
        tool_id="dual_reader",
        action_name="read_file",
        executor_func=dual_resource_reader,
    )
    res_bound_ws = wrapper_dual._extract_actual_target(("   ", "/app/resource.json"), {})
    assert res_bound_ws == "/app/resource.json"

    # Lines 189-190: Signature bound partial raises exception in resource_keys check
    orig_sig = wrapper_sig._executor_sig

    class FailBindSig:
        parameters = orig_sig.parameters

        def bind_partial(self, *args, **kwargs):
            raise TypeError("fail")

    wrapper_sig._executor_sig = FailBindSig()
    try:
        # Falls through bind exception to positional args check (line 192)
        res_kw = wrapper_sig._extract_actual_target(("fallback_positional",), {})
        assert res_kw == "fallback_positional"
    finally:
        wrapper_sig._executor_sig = orig_sig

    # Branch 181->192: self._executor_sig is None skips signature check to positional args
    wrapper_nosig = registry.register_tool(
        tool_id="sig_none_reader",
        action_name="read_file",
        executor_func=signature_resource_reader,
    )
    wrapper_nosig._executor_sig = None
    res_nosig = wrapper_nosig._extract_actual_target(("pos_target",), {})
    assert res_nosig == "pos_target"


def test_extract_target_read_only_default_target_and_failure(test_setup):
    """
    Lines 195-198: Read-only default target fallback and PermissionError
    when target cannot be determined.
    """
    registry = test_setup["registry"]

    def empty_reader():
        return "empty"

    # Default target
    wrapper_def = registry.register_tool(
        tool_id="default_reader",
        action_name="read_file",
        executor_func=empty_reader,
        default_target="default/resource",
    )
    assert wrapper_def._extract_actual_target((), {}) == "default/resource"

    # Failure when no target can be determined
    wrapper_none = registry.register_tool(
        tool_id="no_target_reader",
        action_name="read_file",
        executor_func=empty_reader,
    )
    with pytest.raises(PermissionError, match="Unable to determine resource target for read-only"):
        wrapper_none._extract_actual_target((), {})


# ============================================================================
# 3. Target Extraction: Mutating Operations & Edge Cases
# ============================================================================

def test_extract_target_mutating_whitespace_in_target_param(test_setup):
    """
    Line 142: Non-canonical target value with leading/trailing whitespace
    for parameter target_param when 'target' kwarg is also present.
    """
    registry = test_setup["registry"]

    def mut_func(dest, target=None):
        return dest

    wrapper = registry.register_tool(
        tool_id="ws_mut",
        action_name="write_file",
        executor_func=mut_func,
        target_param="dest",
    )

    with pytest.raises(PermissionError, match="contains leading or trailing whitespace"):
        wrapper._extract_actual_target((), {"target": "/allowed", "dest": "  /allowed  "})


def test_extract_target_mutating_matching_explicit_target_kwarg(test_setup):
    """
    Branches 139->152, 146->152: When explicit 'target' and target_param match canonical values.
    """
    registry = test_setup["registry"]

    def mut_func(dest, target=None):
        return dest

    wrapper = registry.register_tool(
        tool_id="match_mut",
        action_name="write_file",
        executor_func=mut_func,
        target_param="dest",
    )

    # Both target and dest match "/allowed"
    target = wrapper._extract_actual_target((), {"target": "/allowed", "dest": "/allowed"})
    assert target == "/allowed"

    # target in kwargs, but dest not in kwargs (bound positionally) and they match
    target_pos = wrapper._extract_actual_target(("/allowed",), {"target": "/allowed"})
    assert target_pos == "/allowed"


def test_extract_target_mutating_uninspectable_signature_at_extraction(test_setup):
    """
    Line 202: Mutating operation fails closed if executor signature is None.
    """
    registry = test_setup["registry"]

    def mut_func(target):
        return target

    wrapper = registry.register_tool(
        tool_id="mut_no_sig",
        action_name="write_file",
        executor_func=mut_func,
    )
    wrapper._executor_sig = None

    with pytest.raises(PermissionError, match="requires an inspectable executor signature"):
        wrapper._extract_actual_target(("/allowed",), {})


def test_extract_target_parameterless_mutating_tool_rejects_dynamic_arguments(test_setup):
    """
    Lines 206-210: Parameterless mutating tool with explicit default_target
    rejects dynamic positional or keyword arguments.
    """
    registry = test_setup["registry"]

    def zero_arg_task():
        return "cleared"

    wrapper = registry.register_tool(
        tool_id="task_tool",
        action_name="write_file",
        executor_func=zero_arg_task,
    )
    assert wrapper.default_target == "resource:write_file"

    # No args -> succeeds with default_target
    assert wrapper._extract_actual_target((), {}) == "resource:write_file"

    # Dynamic args -> rejected
    with pytest.raises(PermissionError, match="cannot accept dynamic arguments"):
        wrapper._extract_actual_target(("dynamic_arg",), {})

    with pytest.raises(PermissionError, match="cannot accept dynamic arguments"):
        wrapper._extract_actual_target((), {"dynamic_kwarg": 123})


def test_extract_target_mutating_missing_target_param_attr(test_setup):
    """
    Line 213: Mutating operation with target_param unset at extraction time.
    """
    registry = test_setup["registry"]

    def mut_func(target):
        return target

    wrapper = registry.register_tool(
        tool_id="mut_unset_tp",
        action_name="write_file",
        executor_func=mut_func,
    )
    wrapper.target_param = None

    with pytest.raises(PermissionError, match="requires explicit 'target_param'"):
        wrapper._extract_actual_target(("/target",), {})


def test_extract_target_mutating_conflicting_target_in_kwargs_vs_signature(test_setup):
    """
    Lines 219-230: Target parameter in kwargs/positional conflicting with 'target' kwarg.
    Also tests branch 223->233 (dest not in bound_trial) and line 230 exception pass in trial bind.
    """
    registry = test_setup["registry"]

    def mut_func(dest, **kwargs):
        return dest

    wrapper = registry.register_tool(
        tool_id="mut_conflict_trial",
        action_name="write_file",
        executor_func=mut_func,
        target_param="dest",
    )

    # Conflicting trial value detected (lines 225-228)
    with pytest.raises(PermissionError, match="Conflicting target values detected"):
        wrapper._extract_actual_target(("dest_val",), {"target": "different_target"})

    # Branch 223->233: 'target' passed in kwargs but 'dest' not passed
    msg_bind = "Signature binding error for mutating operation|Missing required target parameter"
    with pytest.raises(PermissionError, match=msg_bind):
        wrapper._extract_actual_target((), {"target": "different_target"})

    # Line 230: TypeError during trial bind swallowed by pass, then caught by bound_args
    real_sig = inspect.signature(mut_func)

    class TrialFailSig:
        parameters = real_sig.parameters

        def __init__(self):
            self.calls = 0

        def bind_partial(self, *args, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise TypeError("trial bind error")
            return real_sig.bind_partial(*args, **kwargs)

    wrapper._executor_sig = TrialFailSig()
    # Line 264 defense-in-depth executed when trial bind fails but actual bind succeeds
    with pytest.raises(PermissionError, match="Conflicting target values detected"):
        wrapper._extract_actual_target(("dest_val",), {"target": "different_target"})


def test_extract_target_mutating_invalid_target_parameter_types(test_setup):
    """
    Line 247: Target parameter is non-string or whitespace-only.
    """
    registry = test_setup["registry"]

    def mut_func(dest):
        return dest

    wrapper = registry.register_tool(
        tool_id="mut_invalid_type",
        action_name="write_file",
        executor_func=mut_func,
        target_param="dest",
    )

    with pytest.raises(PermissionError, match="must be a non-empty string"):
        wrapper._extract_actual_target((12345,), {})

    with pytest.raises(PermissionError, match="must be a non-empty string"):
        wrapper._extract_actual_target(("",), {})

    with pytest.raises(PermissionError, match="must be a non-empty string"):
        wrapper._extract_actual_target(("   ",), {})


def test_extract_target_custom_extractor_failures_and_success(test_setup):
    """
    Lines 273-274, 277, 280-285: Custom target_extractor exception, empty target,
    mismatch, and matching success path.
    """
    registry = test_setup["registry"]

    def mut_func(dest):
        return dest

    # 1. Extractor raises exception (lines 273-274)
    def failing_extractor(*args, **kwargs):
        raise RuntimeError("database unreachable for target resolution")

    wrapper_fail = registry.register_tool(
        tool_id="ext_fail",
        action_name="write_file",
        executor_func=mut_func,
        target_param="dest",
        target_extractor=failing_extractor,
    )
    with pytest.raises(PermissionError, match="Custom target extractor failed"):
        wrapper_fail._extract_actual_target(("/dest/path",), {})

    # 2. Extractor returns empty or non-string (line 277)
    def empty_extractor(*args, **kwargs):
        return ""

    wrapper_empty = registry.register_tool(
        tool_id="ext_empty",
        action_name="write_file",
        executor_func=mut_func,
        target_param="dest",
        target_extractor=empty_extractor,
    )
    msg_empty = "Custom target extractor returned empty or invalid target"
    with pytest.raises(PermissionError, match=msg_empty):
        wrapper_empty._extract_actual_target(("/dest/path",), {})

    # 3. Extractor returns valid matching target (lines 280->285)
    def matching_extractor(*args, **kwargs):
        return "/dest/path"

    wrapper_match = registry.register_tool(
        tool_id="ext_match",
        action_name="write_file",
        executor_func=mut_func,
        target_param="dest",
        target_extractor=matching_extractor,
    )
    assert wrapper_match._extract_actual_target(("/dest/path",), {}) == "/dest/path"


# ============================================================================
# 4. Invocation Entry Point (__call__) & Authorization Boundary
# ============================================================================

def test_wrapper_call_unbound_wrapper_raises():
    """
    Line 302: Unbound tool wrapper missing TrustedToolRegistry reference.
    """
    def dummy():
        return "data"

    wrapper = TrustedToolWrapper(
        tool_id="unbound",
        action_name="read_file",
        executor_func=dummy,
        registry=None,
        default_target="res",
    )
    msg = "Unbound tool wrapper missing TrustedToolRegistry reference"
    with pytest.raises(PermissionError, match=msg):
        wrapper()


def test_wrapper_call_authenticated_principal_validation(test_setup):
    """
    Lines 334, 336: authenticated_principal must be AuthenticatedPrincipal instance,
    and authority must have principal_provider configured.
    """
    registry = test_setup["registry"]
    authority = test_setup["authority"]

    def read_func(target):
        return target

    wrapper = registry.register_tool(
        tool_id="princ_tool",
        action_name="read_file",
        executor_func=read_func,
        target_param="target",
    )

    # Non-AuthenticatedPrincipal object in context or kwargs (line 334)
    with pytest.raises(PermissionError, match="must be an instance of AuthenticatedPrincipal"):
        wrapper("res", context={"authenticated_principal": {"principal_id": "alice"}})

    # Valid AuthenticatedPrincipal instance, but authority has no principal_provider (line 336)
    dummy_princ = AuthenticatedPrincipal(
        principal_id="alice",
        issuer_id="corp",
        timestamp=time.time(),
        signature="00" * 64,
    )
    # authority.principal_provider is None by default in AuthorizationAuthority
    assert getattr(authority, "principal_provider", None) is None
    with pytest.raises(PermissionError, match="Authority has no configured PrincipalProvider"):
        wrapper("res", context={"authenticated_principal": dummy_princ})


def test_wrapper_call_policy_requiring_authenticated_principal(test_setup):
    """
    Line 349: Tool policy requires authenticated principal (allowed_principals != {'*'}),
    but none provided.
    """
    registry = test_setup["registry"]

    def read_func(target):
        return target

    restricted_policy = Policy(
        policy_id="admin_only",
        allowed_operations={"read_file"},
        allowed_resources={"*"},
        allowed_principals={"admin_principal"},
    )

    wrapper = registry.register_tool(
        tool_id="admin_tool",
        action_name="read_file",
        executor_func=read_func,
        target_param="target",
        policy=restricted_policy,
    )

    msg = "Policy requires authenticated principal but none provided"
    with pytest.raises(PermissionError, match=msg):
        wrapper("res")


def test_wrapper_call_injects_target_parameter_when_in_signature(test_setup):
    """
    Line 369: 'target' in sig_params and 'target' not in call_kwargs: injects target.
    """
    registry = test_setup["registry"]
    authority = test_setup["authority"]

    captured = {}

    def executor_with_target(target, other="val"):
        captured["target"] = target
        captured["other"] = other
        return "success"

    authority.default_policy = Policy(
        policy_id="test_pol",
        allowed_operations={"read_file"},
        allowed_resources={"*"},
    )

    wrapper = registry.register_tool(
        tool_id="target_param_tool",
        action_name="read_file",
        executor_func=executor_with_target,
        default_target="injected_resource",
    )

    # Calling without kwargs['target'] ensures line 369 assigns call_kwargs['target'] = exec_target
    res = wrapper()
    assert res["status"] == "SUCCESS"
    assert captured["target"] == "injected_resource"


def test_wrapper_call_mutating_target_param_missing_or_mismatched_at_exec(test_setup):
    """
    Lines 382, 387: In mutating operation, target_param missing or mismatched in bound_for_exec.
    """
    registry = test_setup["registry"]
    authority = test_setup["authority"]

    def mut_func(dest):
        return dest

    authority.default_policy = Policy(
        policy_id="p_mut",
        allowed_operations={"write_file"},
        allowed_resources={"*"},
    )

    wrapper = registry.register_tool(
        tool_id="mut_bound_check",
        action_name="write_file",
        executor_func=mut_func,
        target_param="dest",
    )

    real_sig = inspect.signature(mut_func)

    class ProxySig:
        def __init__(self, override_fn):
            self.parameters = real_sig.parameters
            self._override_fn = override_fn

        def bind_partial(self, *args, **kwargs):
            return self._override_fn(*args, **kwargs)

    # In __call__, line 362 calls inspect.signature(self._executor_func)
    # Simulate target_param missing in bound arguments (line 382)
    fake_bound_missing = inspect.BoundArguments(real_sig, {})
    sig_missing = ProxySig(lambda *args, **kwargs: fake_bound_missing)
    with mock.patch("inspect.signature", return_value=sig_missing):
        with pytest.raises(PermissionError, match="missing from bound executor arguments"):
            wrapper(dest="/app/data.txt")

    # Simulate target_param value mismatch (line 387)
    fake_bound_mismatch = inspect.BoundArguments(real_sig, {"dest": "/app/spoofed.txt"})
    sig_mismatch = ProxySig(lambda *args, **kwargs: fake_bound_mismatch)
    with mock.patch("inspect.signature", return_value=sig_mismatch):
        msg_diff = "differs from executor target parameter"
        with pytest.raises(PermissionError, match=msg_diff):
            wrapper(dest="/app/data.txt")


def test_wrapper_call_read_only_target_param_mismatch_and_bind_error(test_setup):
    """
    Lines 393-405: Read-only operation target_param mismatch check
    and signature binding error handling for mutating vs read-only operations.
    Also covers branches 394->408 (matching bound target) and 402->408 (read-only ignores bind err).
    """
    registry = test_setup["registry"]
    authority = test_setup["authority"]

    def ro_func(dest):
        return dest

    authority.default_policy = Policy(
        policy_id="p_ro",
        allowed_operations={"read_file"},
        allowed_resources={"*"},
    )

    wrapper_ro = registry.register_tool(
        tool_id="ro_bound_check",
        action_name="read_file",
        executor_func=ro_func,
        target_param="dest",
    )

    real_ro_sig = inspect.signature(ro_func)
    fake_bound_ro = inspect.BoundArguments(real_ro_sig, {"dest": "/app/spoofed.txt"})

    class ProxyROSig:
        parameters = real_ro_sig.parameters

        def bind_partial(self, *args, **kwargs):
            return fake_bound_ro

    # Read-only target match (branch 394->408)
    res_match = wrapper_ro(dest="/app/data.txt")
    assert res_match["status"] == "SUCCESS"

    # Read-only target mismatch (lines 393-397)
    with mock.patch("inspect.signature", return_value=ProxyROSig()):
        msg_diff = "differs from executor target parameter"
        with pytest.raises(PermissionError, match=msg_diff):
            wrapper_ro(dest="/app/data.txt")

    # Branch 402->408: Signature binding error in read-only operation does NOT raise PermissionError
    class ProxyROBindFail:
        parameters = real_ro_sig.parameters

        def bind_partial(self, *args, **kwargs):
            raise TypeError("read-only bind failure")

    with mock.patch("inspect.signature", return_value=ProxyROBindFail()):
        res_ro = wrapper_ro(dest="/app/data.txt")
        assert res_ro["status"] == "SUCCESS"

    # Mutating operation signature binding error (line 403)
    def mut_func(dest):
        return dest

    wrapper_mut = registry.register_tool(
        tool_id="mut_bind_err",
        action_name="write_file",
        executor_func=mut_func,
        target_param="dest",
    )
    real_mut_sig = inspect.signature(mut_func)

    class ProxyMutErrorSig:
        parameters = real_mut_sig.parameters

        def bind_partial(self, *args, **kwargs):
            raise TypeError("invalid signature binding")

    with mock.patch("inspect.signature", return_value=ProxyMutErrorSig()):
        with pytest.raises(PermissionError, match="Signature binding failure for mutating"):
            wrapper_mut(dest="/app/data.txt")


def test_wrapper_call_capability_cleanup_in_executor_registry(test_setup):
    """
    Lines 455-460: finally block cleanup of capability token in executor_registry.
    """
    registry = test_setup["registry"]
    authority = test_setup["authority"]

    def simple_read():
        return "cleaned"

    authority.default_policy = Policy(
        policy_id="p_cleanup",
        allowed_operations={"read_file"},
        allowed_resources={"*"},
    )

    wrapper = registry.register_tool(
        tool_id="cleanup_tool",
        action_name="read_file",
        executor_func=simple_read,
        default_target="res",
    )

    pop_calls = []
    real_pop = authority.executor_registry._pop_internal

    def tracked_pop(token_id, default=None):
        pop_calls.append(token_id)
        return real_pop(token_id, default)

    with mock.patch.object(authority.executor_registry, "_pop_internal", side_effect=tracked_pop):
        res = wrapper()
        assert res["status"] == "SUCCESS"
        assert len(pop_calls) == 1


# ============================================================================
# 5. Tool Registry Lifecycle Methods
# ============================================================================

def test_tool_registry_with_orchestrator():
    """
    Lines 492-494: Initializing TrustedToolRegistry with an EpistemicOrchestrator instance.
    """
    orchestrator = EpistemicOrchestrator()
    tool_registry = TrustedToolRegistry(orchestrator=orchestrator)

    assert tool_registry.orchestrator is orchestrator
    assert tool_registry.execution_boundary is orchestrator.execution_boundary
    assert tool_registry.authority is orchestrator.authority


def test_tool_registry_list_tools(test_setup):
    """
    Line 537: list_tools returns dictionary mapping tool_id to description.
    """
    registry = test_setup["registry"]

    def fn1():
        return 1

    def fn2():
        return 2

    registry.register_tool(
        tool_id="tool_alpha",
        action_name="read_file",
        executor_func=fn1,
        description="Reads alpha stream",
        default_target="alpha",
    )
    registry.register_tool(
        tool_id="tool_beta",
        action_name="read_file",
        executor_func=fn2,
        description="Reads beta stream",
        default_target="beta",
    )

    tool_dict = registry.list_tools()
    assert tool_dict == {
        "tool_alpha": "Reads alpha stream",
        "tool_beta": "Reads beta stream",
    }
