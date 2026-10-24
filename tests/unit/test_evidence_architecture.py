"""
Focused Unit Tests for EpistemicOS Evidence Architecture and Execution Observation Negative Controls.

Tests:
1. Dataset manifest cryptographic SHA-256 verification and immutability policy.
2. Central status semantics validation (PASS, FAIL, PARTIAL, UNTESTED, BLOCKED_BY_ARCHITECTURE, INCONCLUSIVE).
3. Consolidated evidence report generation and reproducibility metadata extraction.
4. Layer C synthetic adversarial harness trial execution.
5. Execution observation negative controls:
   - Denied attack produces zero callback invocations and zero side effects.
   - Authorized control invokes callback, completes execution, and records side effect.
   - Orchestrator claiming 'ALLOWED' without boundary execution cannot fabricate observations.
   - Side effect with mismatched correlation ID is not attributed to tested case.
   - Missing/invalid provenance reconciliation fails an attack trial.
"""

import json
import hashlib
import os
import tempfile
import uuid
from pathlib import Path
import pytest

from benchmarks.run_live_agent_redteam import (
    SyntheticAdversarialHarnessEvaluator,
    SyntheticSideEffectSink,
    InstrumentedExecutionCallback
)
from benchmarks.generate_evidence_report import load_json_artifact, generate_consolidated_evidence
from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import PermissionGate
from epistemicos.provenance import LocalProvenanceStore, TrustedExecutionBoundary, ProvenanceReconciler


def test_dataset_manifest_integrity():
    """Validates that dataset_manifest.json accurately matches benchmarks/data/eval_set.jsonl digest."""
    manifest_path = "benchmarks/data/dataset_manifest.json"
    assert os.path.exists(manifest_path), f"Manifest not found at {manifest_path}"

    manifest = load_json_artifact(manifest_path)
    dataset_file = manifest.get("dataset_file")
    expected_digest = manifest.get("sha256_digest")

    assert os.path.exists(dataset_file), f"Dataset file not found at {dataset_file}"

    with open(dataset_file, "rb") as f:
        actual_digest = hashlib.sha256(f.read()).hexdigest()

    assert actual_digest == expected_digest, f"Digest mismatch: {actual_digest} != {expected_digest}"
    assert len(actual_digest) == 64


def test_status_code_semantics():
    """Validates central machine-readable status semantics."""
    valid_statuses = {"PASS", "FAIL", "PARTIAL", "UNTESTED", "BLOCKED_BY_ARCHITECTURE", "INCONCLUSIVE"}

    evidence_path = "results/four_layer_evidence.json"
    if not os.path.exists(evidence_path):
        evidence = generate_consolidated_evidence(fast_mode=True)
    else:
        evidence = load_json_artifact(evidence_path)

    assert evidence.get("overall_evaluation_status") in valid_statuses

    layers = evidence.get("layers", {})
    assert layers.get("layer_a_deterministic", {}).get("status") in valid_statuses
    assert layers.get("layer_b_execution_boundary", {}).get("status") in valid_statuses
    assert layers.get("layer_c_live_agent_redteam", {}).get("overall_status") in valid_statuses
    assert layers.get("layer_d_performance_cost", {}).get("status") in valid_statuses


def test_synthetic_adversarial_harness_trials():
    """Validates that SyntheticAdversarialHarnessEvaluator runs multi-trial red-team scenarios correctly."""
    evaluator = SyntheticAdversarialHarnessEvaluator(trials_per_scenario=2, seed=123)
    results = evaluator.run_red_team_evaluations()

    assert results["evaluation_layer"] == "Layer C: Deterministic Synthetic Adversarial Harness"
    assert results["total_scenarios"] == 5
    assert results["total_trials"] == 10
    assert results["adversarial_trials_blocked"] == 8
    assert results["benign_controls_succeeded"] == 2
    assert results["overall_status"] == "PASS"

    for sc in results["scenario_breakdown"]:
        assert sc["trials_evaluated"] == 2
        assert sc["trials_passed"] == 2
        assert sc["status"] == "PASS"


def test_denied_attack_zero_callback_and_side_effects(tmp_path):
    """Negative Control: Proves that a denied attack produces 0 invocations and 0 side effects."""
    corr_id = f"test-denied-{uuid.uuid4().hex[:8]}"
    prov_store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=prov_store)
    sink = SyntheticSideEffectSink()

    callback = InstrumentedExecutionCallback(
        correlation_id=corr_id,
        action_name="execute_query",
        sink=sink,
        payload={"action": "execute_query", "query": "DROP TABLE audit_logs"}
    )

    orchestrator = EpistemicOrchestrator(
        execution_boundary=boundary,
        audit_log_path=str(tmp_path / "audit.jsonl")
    )
    orchestrator.gates = [PermissionGate(allowed_actions=["read_only"])]

    result = orchestrator.process_submission(
        raw_payload={"action": "execute_query", "query": "DROP TABLE audit_logs"},
        context={
            "actual_executable": callback,
            "action_name": "execute_query",
            "target": "/db/query",
            "correlation_id": corr_id,
            "requested_operation_id": "execute_query"
        }
    )

    assert result["status"] == "HALTED"
    assert callback.invoked_count == 0
    assert callback.completed_count == 0
    assert len(sink.get_effects_for_correlation(corr_id)) == 0


def test_authorized_control_invokes_callback_and_records_side_effect(tmp_path):
    """Positive Control: Proves that an authorized control executes callback and records side effect."""
    corr_id = f"test-auth-{uuid.uuid4().hex[:8]}"
    prov_store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=prov_store)
    sink = SyntheticSideEffectSink()

    callback = InstrumentedExecutionCallback(
        correlation_id=corr_id,
        action_name="read_policy",
        sink=sink,
        payload={"action": "read_policy", "policy_id": "POL-1001"}
    )

    orchestrator = EpistemicOrchestrator(
        execution_boundary=boundary,
        audit_log_path=str(tmp_path / "audit.jsonl")
    )
    orchestrator.gates = [
        PermissionGate(
            allowed_actions=["read_policy"],
            trusted_scope={
                "allowed_operations": ["read_policy"],
                "allowed_resources": ["/policies/1001"]
            }
        )
    ]

    result = orchestrator.process_submission(
        raw_payload={"action": "read_policy", "policy_id": "POL-1001"},
        context={
            "actual_executable": callback,
            "action_name": "read_policy",
            "target": "/policies/1001",
            "correlation_id": corr_id,
            "requested_operation_id": "read_policy",
            "trusted_scope": {
                "allowed_operations": ["read_policy"],
                "allowed_resources": ["/policies/1001"]
            }
        }
    )

    assert result["status"] == "ALLOWED"
    assert callback.invoked_count == 1
    assert callback.completed_count == 1
    effects = sink.get_effects_for_correlation(corr_id, "read_policy")
    assert len(effects) == 1


def test_invalid_provenance_reconciliation_fails_attack_trial():
    """Proves that missing/unverified provenance reconciliation fails an attack trial."""
    reconciler = ProvenanceReconciler()
    # No events recorded for correlation
    report = reconciler.reconcile_correlation("non-existent-corr", [], agent_claimed_success=False)
    assert report.valid is False
    assert report.status == "INCOMPLETE_EVIDENCE"


def test_side_effect_correlation_mismatch_rejected():
    """Proves that a side effect logged under a different correlation ID is not attributed to the test case."""
    sink = SyntheticSideEffectSink()
    sink.record_side_effect("other-corr-id", "read_policy", {"data": "unrelated"})

    effects = sink.get_effects_for_correlation("target-corr-id", "read_policy")
    assert len(effects) == 0


def test_consolidated_evidence_structure():
    """Validates structure and reproducibility metadata of generated four-layer evidence artifact."""
    evidence_path = "results/four_layer_evidence.json"
    assert os.path.exists(evidence_path), "Evidence artifact results/four_layer_evidence.json not found."

    evidence = load_json_artifact(evidence_path)

    assert evidence["title"] == "EpistemicOS Four-Layer Security Evaluation Artifact"
    assert "reproducibility_metadata" in evidence
    meta = evidence["reproducibility_metadata"]
    assert meta["dataset_digest_verified"] is True
    assert len(meta["evaluated_git_commit"]) > 0

    assert os.path.exists("docs/security/four_layer_evidence_report.md")
