"""
Negative Unit Tests for Evidence Validator (`benchmarks/validate_evidence.py`).

Tests rejection of synthetic invalid artifacts:
1. Missing required evaluation layers.
2. Unverified or missing dataset SHA-256 digest.
3. Observed unauthorized side effects or breaches in Layer B.
4. Metric recall or FPR regressions in Layer D.
5. Inconsistent overall status 'PASS' when required layers report PARTIAL or FAIL.
"""

import copy
import json
import pytest
from benchmarks.validate_evidence import validate_evidence_artifact


@pytest.fixture
def valid_evidence_data():
    return {
        "title": "EpistemicOS Four-Layer Security Evaluation Artifact",
        "version": "1.0.0",
        "reproducibility_metadata": {
            "evaluated_git_commit": "abcdef1234567890",
            "working_tree_status": "CLEAN",
            "dataset_version": "1.0.0-frozen",
            "dataset_sha256_digest": "f4e31381a922c1143769ccb887c4841e4a14fedec6eef6569d40eed2956ce873",
            "dataset_digest_verified": True
        },
        "overall_evaluation_status": "PASS",
        "layers": {
            "layer_a_deterministic": {
                "evaluation_layer": "Layer A: Deterministic Regression",
                "status": "PASS"
            },
            "layer_b_execution_boundary": {
                "evaluation_layer": "Layer B: Actual Execution-Boundary Integration",
                "status": "PASS",
                "breaches_observed": 0
            },
            "layer_c_live_agent_redteam": {
                "evaluation_layer": "Layer C: Deterministic Synthetic Adversarial Harness",
                "overall_status": "PASS"
            },
            "layer_d_performance_cost": {
                "evaluation_layer": "Layer D: Performance & Cost Benchmarks",
                "status": "PASS",
                "combined_gating_recall_pct": 100.0,
                "combined_gating_fpr_pct": 0.0
            }
        }
    }


def test_valid_artifact_passes(valid_evidence_data, tmp_path):
    artifact_file = tmp_path / "valid_evidence.json"
    artifact_file.write_text(json.dumps(valid_evidence_data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file))
    assert is_valid is True
    assert len(errors) == 0


def test_missing_layer_rejected(valid_evidence_data, tmp_path):
    data = copy.deepcopy(valid_evidence_data)
    del data["layers"]["layer_c_live_agent_redteam"]

    artifact_file = tmp_path / "missing_layer.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file))
    assert is_valid is False
    assert any("Missing required evaluation layers" in err for err in errors)


def test_unverified_dataset_digest_rejected(valid_evidence_data, tmp_path):
    data = copy.deepcopy(valid_evidence_data)
    data["reproducibility_metadata"]["dataset_digest_verified"] = False

    artifact_file = tmp_path / "unverified_digest.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file))
    assert is_valid is False
    assert any("Dataset SHA-256 digest verification failed" in err for err in errors)


def test_layer_b_breach_rejected(valid_evidence_data, tmp_path):
    data = copy.deepcopy(valid_evidence_data)
    data["layers"]["layer_b_execution_boundary"]["breaches_observed"] = 1
    data["layers"]["layer_b_execution_boundary"]["status"] = "FAIL"
    data["overall_evaluation_status"] = "FAIL"

    artifact_file = tmp_path / "breach_observed.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file))
    assert is_valid is False
    assert any("observed 1 security breaches" in err for err in errors)


def test_metric_regression_rejected(valid_evidence_data, tmp_path):
    data = copy.deepcopy(valid_evidence_data)
    data["layers"]["layer_d_performance_cost"]["combined_gating_recall_pct"] = 85.0

    artifact_file = tmp_path / "recall_regression.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file))
    assert is_valid is False
    assert any("Combined Gating security recall dropped" in err for err in errors)


def test_inconsistent_overall_pass_rejected(valid_evidence_data, tmp_path):
    data = copy.deepcopy(valid_evidence_data)
    data["layers"]["layer_b_execution_boundary"]["status"] = "PARTIAL"
    data["overall_evaluation_status"] = "PASS"

    artifact_file = tmp_path / "inconsistent_status.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file))
    assert is_valid is False
    assert any("Overall status 'PASS' inconsistent with imperfect layers" in err for err in errors)
