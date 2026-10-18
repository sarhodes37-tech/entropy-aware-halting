"""
Focused Unit Tests for EpistemicOS Evidence Architecture and Evidence Integrity.

Tests:
1. Dataset manifest cryptographic SHA-256 verification and immutability policy.
2. Central status semantics validation (PASS, FAIL, PARTIAL, UNTESTED, BLOCKED_BY_ARCHITECTURE, INCONCLUSIVE).
3. Consolidated evidence report generation and reproducibility metadata extraction.
4. Layer C synthetic adversarial harness trial execution.
"""

import json
import hashlib
import os
import tempfile
from pathlib import Path
import pytest

from benchmarks.run_live_agent_redteam import SyntheticAdversarialHarnessEvaluator
from benchmarks.generate_evidence_report import load_json_artifact, generate_consolidated_evidence


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
    assert results["total_scenarios"] == 4
    assert results["total_trials"] == 8
    assert results["overall_status"] == "PASS"

    for sc in results["scenario_breakdown"]:
        assert sc["trials_evaluated"] == 2
        assert sc["trials_blocked"] == 2
        assert sc["status"] == "PASS"


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
