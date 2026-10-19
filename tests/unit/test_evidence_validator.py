"""
Negative Unit Tests for Evidence Validator (`benchmarks/validate_evidence.py`).

Tests rejection of synthetic invalid artifacts:
1. Missing required evaluation layers.
2. Unverified, missing, or forged dataset SHA-256 digest.
3. Coordinated modification of dataset, manifest, and validator constant in PR branch.
4. Base branch resolution exclusion of HEAD and local untrusted files.
5. Fail closed when no trusted base ref is available and allow_local_constant_fallback is False.
6. Explicit opt-in --allow-local-constant-fallback behavior.
7. Observed unauthorized side effects or breaches in Layer B.
8. Missing mandatory Layer B scenarios causing non-PASS.
9. Metric recall or FPR regressions in Layer D.
10. Inconsistent denominators or recomputed metric mismatches in Layer D.
11. Inconsistent overall status 'PASS' when required layers report PARTIAL or FAIL.
12. Overall status 'PARTIAL' blocked under --require-full-pass flag.
13. Fabricated summary metrics in Layer D with missing/mismatched run records rejected by validator.
14. Missing summary metrics, unknown classification codes, zero denominators, and dataset digest mismatch in run records.
"""

import copy
import json
import os
import hashlib
import pytest
from benchmarks.validate_evidence import (
    validate_evidence_artifact,
    get_base_branch_manifest_digest,
    FROZEN_BASELINE_DATASET_DIGEST
)


@pytest.fixture
def valid_evidence_data():
    records_path = "results/per_case_results.json"
    records_digest = ""
    run_id = "run-l4-20260330000000-f4e31381"
    if os.path.exists(records_path):
        with open(records_path, "rb") as f:
            records_digest = hashlib.sha256(f.read()).hexdigest()
            try:
                rec_data = json.loads(f.read().decode("utf-8"))
                if rec_data and isinstance(rec_data, list) and len(rec_data) > 0:
                    run_id = rec_data[0].get("run_id", run_id)
            except Exception:
                pass

    return {
        "title": "EpistemicOS Four-Layer Security Evaluation Artifact",
        "version": "1.0.0",
        "reproducibility_metadata": {
            "evaluated_git_commit": "abcdef1234567890",
            "working_tree_status": "CLEAN",
            "dataset_version": "1.0.0-frozen",
            "dataset_sha256_digest": FROZEN_BASELINE_DATASET_DIGEST,
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
                "breaches_observed": 0,
                "scenario_summary": [
                    {"case_id": f"Case{i}_test_scenario", "name": f"Case {i}", "security_outcome": "PASS", "provenance_verified": "VERIFIED"}
                    for i in range(1, 8)
                ]
            },
            "layer_c_live_agent_redteam": {
                "evaluation_layer": "Layer C: Deterministic Synthetic Adversarial Harness",
                "overall_status": "PASS"
            },
            "layer_d_performance_cost": {
                "evaluation_layer": "Layer D: Performance & Cost Benchmarks",
                "status": "PASS",
                "run_id": run_id,
                "dataset_sha256_digest": FROZEN_BASELINE_DATASET_DIGEST,
                "run_records_sha256_digest": records_digest,
                "sample_count": 100,
                "combined_gating_accuracy_pct": 100.0,
                "combined_gating_recall_pct": 100.0,
                "combined_gating_fpr_pct": 0.0
            }
        }
    }


def test_valid_artifact_passes(valid_evidence_data, tmp_path):
    artifact_file = tmp_path / "valid_evidence.json"
    artifact_file.write_text(json.dumps(valid_evidence_data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is True
    assert len(errors) == 0


def test_missing_summary_metric_rejected(valid_evidence_data, tmp_path):
    """Proves that missing recall_pct or accuracy_pct in Layer D summary is rejected."""
    data = copy.deepcopy(valid_evidence_data)
    del data["layers"]["layer_d_performance_cost"]["combined_gating_recall_pct"]

    artifact_file = tmp_path / "missing_metric.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Summary metric 'combined_gating_recall_pct' is None or omitted" in err for err in errors)


def test_unknown_classification_code_in_run_records_rejected(valid_evidence_data, tmp_path, monkeypatch):
    """Proves that run records with unknown classification codes (e.g., 'UNKNOWN') are rejected."""
    data = copy.deepcopy(valid_evidence_data)

    fake_records = [{"baseline": "Combined Gating", "classification": "INVALID_CODE", "run_id": data["layers"]["layer_d_performance_cost"]["run_id"], "dataset_sha256_digest": FROZEN_BASELINE_DATASET_DIGEST}] * 100
    fake_records_bytes = (json.dumps(fake_records, indent=2) + "\n").encode("utf-8")
    fake_digest = hashlib.sha256(fake_records_bytes).hexdigest()
    data["layers"]["layer_d_performance_cost"]["run_records_sha256_digest"] = fake_digest

    fake_records_file = tmp_path / "per_case_results.json"
    fake_records_file.write_bytes(fake_records_bytes)

    artifact_file = tmp_path / "unknown_class.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    real_exists = os.path.exists
    monkeypatch.setattr(os.path, "exists", lambda p: True if p in ("results/per_case_records.json", "results/per_case_results.json", str(artifact_file)) else real_exists(p))

    original_open = open
    def mock_open(file, *args, **kwargs):
        if str(file) in ("results/per_case_records.json", "results/per_case_results.json"):
            return original_open(fake_records_file, *args, **kwargs)
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", mock_open)

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Invalid classification codes detected" in err for err in errors)


def test_zero_denominator_in_run_records_rejected(valid_evidence_data, tmp_path, monkeypatch):
    """Proves that zero denominators (e.g. 0 adversarial cases) in run records are rejected."""
    data = copy.deepcopy(valid_evidence_data)

    # 100 TC cases -> 0 adversarial cases (tr + fc = 0)
    fake_records = [{"baseline": "Combined Gating", "classification": "TC", "run_id": data["layers"]["layer_d_performance_cost"]["run_id"], "dataset_sha256_digest": FROZEN_BASELINE_DATASET_DIGEST}] * 100
    fake_records_bytes = (json.dumps(fake_records, indent=2) + "\n").encode("utf-8")
    fake_digest = hashlib.sha256(fake_records_bytes).hexdigest()
    data["layers"]["layer_d_performance_cost"]["run_records_sha256_digest"] = fake_digest

    fake_records_file = tmp_path / "per_case_results.json"
    fake_records_file.write_bytes(fake_records_bytes)

    artifact_file = tmp_path / "zero_denom.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    real_exists = os.path.exists
    monkeypatch.setattr(os.path, "exists", lambda p: True if p in ("results/per_case_records.json", "results/per_case_results.json", str(artifact_file)) else real_exists(p))

    original_open = open
    def mock_open(file, *args, **kwargs):
        if str(file) in ("results/per_case_records.json", "results/per_case_results.json"):
            return original_open(fake_records_file, *args, **kwargs)
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", mock_open)

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Adversarial case count (tr + fc) is 0" in err for err in errors)


def test_transplanted_run_records_different_dataset_digest_rejected(valid_evidence_data, tmp_path, monkeypatch):
    """Proves that run records bound to a different dataset digest are rejected."""
    data = copy.deepcopy(valid_evidence_data)

    different_digest = "9999999999999999999999999999999999999999999999999999999999999999"
    fake_records = [{"baseline": "Combined Gating", "classification": "TC", "run_id": data["layers"]["layer_d_performance_cost"]["run_id"], "dataset_sha256_digest": different_digest}] * 50 + \
                   [{"baseline": "Combined Gating", "classification": "TR", "run_id": data["layers"]["layer_d_performance_cost"]["run_id"], "dataset_sha256_digest": different_digest}] * 50
    fake_records_bytes = (json.dumps(fake_records, indent=2) + "\n").encode("utf-8")
    fake_digest = hashlib.sha256(fake_records_bytes).hexdigest()
    data["layers"]["layer_d_performance_cost"]["run_records_sha256_digest"] = fake_digest

    fake_records_file = tmp_path / "per_case_results.json"
    fake_records_file.write_bytes(fake_records_bytes)

    artifact_file = tmp_path / "transplanted.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    real_exists = os.path.exists
    monkeypatch.setattr(os.path, "exists", lambda p: True if p in ("results/per_case_records.json", "results/per_case_results.json", str(artifact_file)) else real_exists(p))

    original_open = open
    def mock_open(file, *args, **kwargs):
        if str(file) in ("results/per_case_records.json", "results/per_case_results.json"):
            return original_open(fake_records_file, *args, **kwargs)
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", mock_open)

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Dataset Binding Failure" in err for err in errors)


def test_fabricated_summary_metrics_rejected_by_validator(valid_evidence_data, tmp_path, monkeypatch):
    """Proves that a Layer D artifact claiming 100% recall but backed by flawed run records is rejected."""
    data = copy.deepcopy(valid_evidence_data)
    data["layers"]["layer_d_performance_cost"]["combined_gating_recall_pct"] = 100.0

    # Inject fake run records with a false commit (FC) -> recomputed recall = 0%
    fake_records = [{"baseline": "Combined Gating", "classification": "FC", "run_id": data["layers"]["layer_d_performance_cost"]["run_id"], "dataset_sha256_digest": FROZEN_BASELINE_DATASET_DIGEST}] * 100
    fake_records_bytes = (json.dumps(fake_records, indent=2) + "\n").encode("utf-8")
    fake_digest = hashlib.sha256(fake_records_bytes).hexdigest()
    data["layers"]["layer_d_performance_cost"]["run_records_sha256_digest"] = fake_digest

    fake_records_file = tmp_path / "per_case_results.json"
    fake_records_file.write_bytes(fake_records_bytes)

    artifact_file = tmp_path / "fabricated_summary.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    real_exists = os.path.exists
    monkeypatch.setattr(os.path, "exists", lambda p: True if p in ("results/per_case_records.json", "results/per_case_results.json", str(artifact_file)) else real_exists(p))

    original_open = open
    def mock_open(file, *args, **kwargs):
        if str(file) in ("results/per_case_records.json", "results/per_case_results.json"):
            return original_open(fake_records_file, *args, **kwargs)
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", mock_open)

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Metric Forgery Detected" in err or "recall dropped" in err for err in errors)


def test_missing_layer_b_mandatory_scenarios_rejected(valid_evidence_data, tmp_path):
    """Proves that missing mandatory Layer B scenarios cannot produce PASS."""
    data = copy.deepcopy(valid_evidence_data)
    # Exclude case7
    data["layers"]["layer_b_execution_boundary"]["scenario_summary"] = [
        {"case_id": f"Case{i}_test", "name": f"Case {i}", "security_outcome": "PASS", "provenance_verified": "VERIFIED"}
        for i in range(1, 7)
    ]
    data["layers"]["layer_b_execution_boundary"]["status"] = "PASS"

    artifact_file = tmp_path / "missing_layer_b_cases.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Missing mandatory cases" in err for err in errors)


def test_incomplete_layer_d_sample_count_rejected(valid_evidence_data, tmp_path):
    """Proves that Layer D with sample_count < 100 cannot produce PASS."""
    data = copy.deepcopy(valid_evidence_data)
    data["layers"]["layer_d_performance_cost"]["sample_count"] = 50
    data["layers"]["layer_d_performance_cost"]["status"] = "PASS"

    artifact_file = tmp_path / "incomplete_sample.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("incomplete sample count N=50" in err for err in errors)


def test_non_pass_layer_forces_overall_non_pass(valid_evidence_data, tmp_path):
    """Proves that any mandatory non-PASS layer makes overall result non-PASS."""
    data = copy.deepcopy(valid_evidence_data)
    data["layers"]["layer_a_deterministic"]["status"] = "FAIL"
    data["overall_evaluation_status"] = "PASS"

    artifact_file = tmp_path / "non_pass_layer.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Overall status 'PASS' cannot coexist with imperfect required layers" in err for err in errors)


def test_missing_layer_rejected(valid_evidence_data, tmp_path):
    data = copy.deepcopy(valid_evidence_data)
    del data["layers"]["layer_c_live_agent_redteam"]

    artifact_file = tmp_path / "missing_layer.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Missing required evaluation layers" in err for err in errors)


def test_forged_dataset_digest_rejected(valid_evidence_data, tmp_path):
    data = copy.deepcopy(valid_evidence_data)
    data["reproducibility_metadata"]["dataset_sha256_digest"] = "1111111111111111111111111111111111111111111111111111111111111111"

    artifact_file = tmp_path / "forged_digest.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Report Metadata Tampering/Forged Claim Detected" in err for err in errors)


def test_simultaneous_unreviewed_manifest_and_dataset_edit_rejected(valid_evidence_data, tmp_path):
    """Proves that changing dataset and manifest together fails code-level baseline check."""
    new_hash = "2222222222222222222222222222222222222222222222222222222222222222"
    data = copy.deepcopy(valid_evidence_data)
    data["reproducibility_metadata"]["dataset_sha256_digest"] = new_hash

    fake_dataset = tmp_path / "fake_eval.jsonl"
    fake_dataset.write_text("MODIFIED DATASET CONTENT", encoding="utf-8")

    fake_manifest = tmp_path / "fake_manifest.json"
    fake_manifest.write_text(json.dumps({
        "sha256_digest": new_hash,
        "dataset_file": str(fake_dataset)
    }), encoding="utf-8")

    artifact_file = tmp_path / "simultaneous_edit.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file), manifest_path=str(fake_manifest), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Manifest Baseline Violation" in err or "Dataset Tampering" in err for err in errors)


def test_coordinated_modification_of_dataset_manifest_and_validator_rejected(valid_evidence_data, tmp_path):
    """
    Proves that even if an unmerged PR modifies dataset, manifest, and local validator constant together,
    validation against the trusted base-branch expected baseline still catches and rejects the modification.
    """
    tampered_digest = "3333333333333333333333333333333333333333333333333333333333333333"
    data = copy.deepcopy(valid_evidence_data)
    data["reproducibility_metadata"]["dataset_sha256_digest"] = tampered_digest

    fake_dataset = tmp_path / "tampered_eval.jsonl"
    fake_dataset.write_text("TAMPERED EVAL SET", encoding="utf-8")

    fake_manifest = tmp_path / "tampered_manifest.json"
    fake_manifest.write_text(json.dumps({
        "sha256_digest": tampered_digest,
        "dataset_file": str(fake_dataset)
    }), encoding="utf-8")

    artifact_file = tmp_path / "coordinated_tampering.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    # Pass the trusted base-branch baseline explicitly
    is_valid, errors = validate_evidence_artifact(
        str(artifact_file),
        manifest_path=str(fake_manifest),
        expected_baseline_digest=FROZEN_BASELINE_DATASET_DIGEST
    )
    assert is_valid is False
    assert any("Manifest Baseline Violation" in err for err in errors)


def test_no_trusted_base_ref_fails_closed(valid_evidence_data, tmp_path, monkeypatch):
    """Proves that when no trusted base ref can be resolved, validate_evidence_artifact fails closed."""
    monkeypatch.setattr("benchmarks.validate_evidence.get_base_branch_manifest_digest", lambda *a, **k: (False, "", None))

    artifact_file = tmp_path / "no_base_ref.json"
    artifact_file.write_text(json.dumps(valid_evidence_data), encoding="utf-8")

    # Without allow_local_constant_fallback, MUST fail closed
    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=False)
    assert is_valid is False
    assert any("Baseline Resolution Error" in err for err in errors)

    # With opt-in allow_local_constant_fallback, passes
    is_valid_optin, errors_optin = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid_optin is True


def test_get_base_branch_manifest_digest_excludes_untrusted_refs():
    """Confirms get_base_branch_manifest_digest resolves strictly from base refs, not local non-manifest paths."""
    ok, digest, ref = get_base_branch_manifest_digest(
        manifest_rel_path="non_existent_file.json",
        eval_set_rel_path="non_existent_eval.jsonl"
    )
    assert ok is False
    assert digest == ""
    assert ref is None


def test_layer_b_breach_rejected(valid_evidence_data, tmp_path):
    data = copy.deepcopy(valid_evidence_data)
    data["layers"]["layer_b_execution_boundary"]["breaches_observed"] = 1
    data["layers"]["layer_b_execution_boundary"]["status"] = "FAIL"
    data["overall_evaluation_status"] = "FAIL"

    artifact_file = tmp_path / "breach_observed.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("CRITICAL SECURITY FAILURE" in err for err in errors)


def test_metric_regression_rejected(valid_evidence_data, tmp_path):
    data = copy.deepcopy(valid_evidence_data)
    data["layers"]["layer_d_performance_cost"]["combined_gating_recall_pct"] = 85.0

    artifact_file = tmp_path / "recall_regression.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    is_valid, errors = validate_evidence_artifact(str(artifact_file), allow_local_constant_fallback=True)
    assert is_valid is False
    assert any("Combined Gating security recall dropped" in err for err in errors)


def test_partial_status_rejected_under_require_full_pass(valid_evidence_data, tmp_path):
    data = copy.deepcopy(valid_evidence_data)
    data["layers"]["layer_b_execution_boundary"]["status"] = "PARTIAL"
    data["overall_evaluation_status"] = "PARTIAL"

    artifact_file = tmp_path / "partial_evidence.json"
    artifact_file.write_text(json.dumps(data), encoding="utf-8")

    # Should pass without require_full_pass
    is_valid_pr, errors_pr = validate_evidence_artifact(str(artifact_file), require_full_pass=False, allow_local_constant_fallback=True)
    assert is_valid_pr is True

    # Should fail with require_full_pass
    is_valid_release, errors_release = validate_evidence_artifact(str(artifact_file), require_full_pass=True, allow_local_constant_fallback=True)
    assert is_valid_release is False
    assert any("Release Workflow Policy Failure" in err for err in errors_release)
