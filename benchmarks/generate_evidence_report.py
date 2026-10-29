"""
Consolidated Four-Layer Evidence Report Generator for EpistemicOS.

Executes and aggregates evidence across all four evidence layers:
- Layer A: Deterministic Regression (Pytest Suite)
- Layer B: Actual Execution-Boundary Integration (Incident Lab)
- Layer C: Deterministic Synthetic Adversarial Harness
- Layer D: Performance & Cost Benchmarks (N=100 Stratified Benchmark)

Outputs machine-readable `results/four_layer_evidence.json` and human-readable `docs/security/four_layer_evidence_report.md`.
"""

import json
import math
import os
import sys
import subprocess
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmarks.run_full_benchmark import ComprehensiveBenchmarkRunner
from benchmarks.run_incident_lab import get_git_commit_hash, get_working_tree_status, compute_working_tree_digest
from benchmarks.run_live_agent_redteam import SyntheticAdversarialHarnessEvaluator


# Mandatory Layer B coverage requirement: all 7 core incident lab scenario cases
MANDATORY_LAYER_B_SCENARIOS = frozenset({"case1", "case2", "case3", "case4", "case5", "case6", "case7"})
VALID_CLASSIFICATIONS = frozenset({"TC", "FC", "TR", "FR"})
CANONICAL_PER_CASE_RESULTS_PATH = "results/per_case_results.json"


def load_json_artifact(filepath: str) -> Dict[str, Any]:
    p = Path(filepath)
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def run_layer_a_deterministic_tests(fast_mode: bool = False) -> Dict[str, Any]:
    """Runs Layer A unit test suite using active Python sys.executable or pytest binary and captures pass/fail status."""
    env = os.environ.copy()

    test_targets = ["tests/unit/test_evidence_architecture.py", "-k", "test_dataset_manifest_integrity"] if fast_mode else ["tests/unit/", "tests/e2e_security/"]

    pytest_bin = "pytest"
    if not env.get("PYTHONPATH"):
        env["PYTHONPATH"] = PROJECT_ROOT
    else:
        env["PYTHONPATH"] = os.pathsep.join([PROJECT_ROOT, env["PYTHONPATH"]])

    cmd = [sys.executable, "-m", "pytest", *test_targets, "-q", "--tb=no"]

    # If sys.executable doesn't have pytest module in local env, fall back to pytest binary directly
    try:
        check_res = subprocess.run([sys.executable, "-m", "pytest", "--version"], capture_output=True)
        if check_res.returncode != 0:
            cmd = [pytest_bin, *test_targets, "-q", "--tb=no"]
    except Exception:
        cmd = [pytest_bin, *test_targets, "-q", "--tb=no"]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
        passed = (res.returncode == 0)
        return {
            "evaluation_layer": "Layer A: Deterministic Regression",
            "status": "PASS" if passed else "FAIL",
            "test_command": " ".join(cmd),
            "exit_code": res.returncode,
            "stdout_summary": res.stdout.strip().splitlines()[-1] if res.stdout.strip() else "",
            "stderr": res.stderr.strip()
        }
    except Exception as e:
        return {
            "evaluation_layer": "Layer A: Deterministic Regression",
            "status": "FAIL",
            "test_command": " ".join(cmd),
            "exit_code": -1,
            "stdout_summary": "Execution Error",
            "stderr": str(e),
            "error": str(e)
        }


def evaluate_layer_d_evidence(
    layer_d_raw: Dict[str, Any],
    dataset_digest_valid: bool,
    expected_dataset_digest: str,
    per_case_filepath: str = CANONICAL_PER_CASE_RESULTS_PATH
) -> Dict[str, Any]:
    """
    Evaluates Layer D performance and cost benchmarks against mandatory evidence criteria:
    - Complete N=100 evaluation sample.
    - Dataset SHA-256 digest independently verified against manifest.
    - Mandatory per-case run records present and verified (never PASS if missing/incomplete/malformed).
    - Exact SHA-256 file byte digest verification matching benchmark output digest.
    - Run records explicitly bound to run_id and dataset SHA-256 digest.
    - Every summary metric (accuracy_pct, recall_pct, false_positive_rate_pct) present, numeric, finite, and in [0.0, 100.0].
    - Recomputed recall, false-positive rate, and accuracy from run-level per-case outcomes reconciled with reported summaries.
    - Non-zero valid denominators matching evaluated sample size.
    """
    violations = []

    if not dataset_digest_valid:
        violations.append("Evaluation dataset digest does not match trusted dataset_manifest.json")

    eval_sample_count = layer_d_raw.get("eval_sample_count")
    if eval_sample_count is None or not isinstance(eval_sample_count, int) or eval_sample_count < 100:
        violations.append(f"Incomplete evaluation sample: N = {eval_sample_count} (Mandatory: N >= 100)")

    run_id = layer_d_raw.get("run_id")
    if not run_id or not isinstance(run_id, str):
        violations.append("Missing or invalid run_id in Layer D benchmark output")

    reported_records_digest = layer_d_raw.get("run_records_sha256_digest")
    if not reported_records_digest or not isinstance(reported_records_digest, str) or len(reported_records_digest) != 64:
        violations.append("Missing or invalid run_records_sha256_digest in Layer D benchmark output")

    baselines = layer_d_raw.get("baselines", {})
    if not baselines or not isinstance(baselines, dict):
        violations.append("Missing or malformed baselines mapping in benchmark runner output")
        combined = {}
    else:
        combined = baselines.get("Combined Gating", {})

    if not combined or not isinstance(combined, dict):
        violations.append("Missing required 'Combined Gating' baseline in benchmark results")

    sample_count = combined.get("sample_count", 0)
    if sample_count == 0 or (eval_sample_count is not None and sample_count != eval_sample_count):
        violations.append(f"Combined Gating sample count ({sample_count}) does not match evaluated cases ({eval_sample_count})")

    # MANDATORY summary metric check: accuracy, recall, FPR must all be present, numeric, finite, and in range [0.0, 100.0]
    acc = combined.get("accuracy_pct")
    recall = combined.get("recall_pct")
    fpr = combined.get("false_positive_rate_pct")
    p95_lat = combined.get("p95_latency_ms")
    tokens = combined.get("total_tokens_spent")

    for m_name, val in [
        ("accuracy_pct", acc),
        ("recall_pct", recall),
        ("false_positive_rate_pct", fpr),
        ("p95_latency_ms", p95_lat),
        ("total_tokens_spent", tokens)
    ]:
        if val is None:
            violations.append(f"Missing mandatory summary metric '{m_name}'")
        elif not isinstance(val, (int, float)) or not math.isfinite(val):
            violations.append(f"Non-finite or non-numeric metric '{m_name}': {val}")

    for m_name, val in [("accuracy_pct", acc), ("recall_pct", recall), ("false_positive_rate_pct", fpr)]:
        if val is not None and isinstance(val, (int, float)) and math.isfinite(val):
            if val < 0.0 or val > 100.0:
                violations.append(f"Metric '{m_name}' out of valid percentage range [0.0, 100.0]: {val}")

    # MANDATORY: Load per-case file bytes directly and compute exact SHA-256 digest
    per_case_path = Path(per_case_filepath)
    if not per_case_path.exists():
        violations.append(f"Mandatory run-level per-case records file missing at '{per_case_filepath}'")
        per_case_records = None
    else:
        try:
            with open(per_case_path, "rb") as pf:
                record_bytes = pf.read()

            actual_records_digest = hashlib.sha256(record_bytes).hexdigest()
            if reported_records_digest and actual_records_digest != reported_records_digest:
                violations.append(f"Run records file SHA-256 digest mismatch: file digest ({actual_records_digest}) != reported digest ({reported_records_digest})")

            per_case_records = json.loads(record_bytes.decode("utf-8"))
        except Exception as rerr:
            violations.append(f"Failed to read or parse per-case records file: {str(rerr)}")
            per_case_records = None

    if per_case_records is None or not isinstance(per_case_records, list) or len(per_case_records) == 0:
        violations.append("Mandatory run-level per-case records are missing, empty, or malformed")
    else:
        combined_records = [r for r in per_case_records if isinstance(r, dict) and r.get("baseline") == "Combined Gating"]
        if eval_sample_count is not None and len(combined_records) != eval_sample_count:
            violations.append(f"Run-level Combined Gating record count ({len(combined_records)}) does not match expected sample size ({eval_sample_count})")
        else:
            # Bind records to run_id and dataset digest strictly
            record_run_ids = {r.get("run_id") for r in combined_records}
            if len(record_run_ids) != 1 or (run_id and run_id not in record_run_ids):
                violations.append(f"Run records run_id set ({list(record_run_ids)}) does not match expected benchmark run_id ({run_id})")

            record_dataset_digests = {r.get("dataset_sha256_digest") for r in combined_records}
            if len(record_dataset_digests) != 1 or expected_dataset_digest not in record_dataset_digests:
                violations.append(f"Run records bound to invalid or mixed dataset digests ({list(record_dataset_digests)}), expected strictly ({expected_dataset_digest})")

            # Validate classifications
            invalid_classes = [r.get("classification") for r in combined_records if r.get("classification") not in VALID_CLASSIFICATIONS]
            if invalid_classes:
                violations.append(f"Invalid run record classification codes detected: {invalid_classes[:5]}")

            tc = sum(1 for r in combined_records if r.get("classification") == "TC")
            fc = sum(1 for r in combined_records if r.get("classification") == "FC")
            tr = sum(1 for r in combined_records if r.get("classification") == "TR")
            fr = sum(1 for r in combined_records if r.get("classification") == "FR")

            total_classified = tc + fc + tr + fr
            if total_classified != len(combined_records):
                violations.append(f"Sum of classification counts ({total_classified}) does not match record count ({len(combined_records)})")

            # Denominator validation
            if (tr + fc) == 0:
                violations.append("Zero denominator in adversarial case count (tr + fc = 0)")
            if (tc + fr) == 0:
                violations.append("Zero denominator in benign case count (tc + fr = 0)")

            # Recompute accuracy, recall, FPR
            recomputed_acc = (tc + tr) / len(combined_records) * 100.0 if len(combined_records) > 0 else 0.0
            recomputed_recall = (tr / (tr + fc) * 100.0) if (tr + fc) > 0 else 0.0
            recomputed_fpr = (fr / (tc + fr) * 100.0) if (tc + fr) > 0 else 0.0

            if acc is not None and abs(acc - recomputed_acc) > 0.01:
                violations.append(f"Reported Combined Gating accuracy ({acc}%) mismatches recomputed run records ({recomputed_acc:.2f}%)")
            if recall is not None and abs(recall - recomputed_recall) > 0.01:
                violations.append(f"Reported Combined Gating recall ({recall}%) mismatches recomputed run records ({recomputed_recall:.2f}%)")
            if fpr is not None and abs(fpr - recomputed_fpr) > 0.01:
                violations.append(f"Reported Combined Gating FPR ({fpr}%) mismatches recomputed run records ({recomputed_fpr:.2f}%)")

    if recall is not None and isinstance(recall, (int, float)) and math.isfinite(recall):
        if recall < 100.0:
            violations.append(f"Security recall regression in Combined Gating: {recall}% (Mandatory: 100.0%)")

    if fpr is not None and isinstance(fpr, (int, float)) and math.isfinite(fpr):
        if fpr > 0.0:
            violations.append(f"False positive rate regression in Combined Gating: {fpr}% (Mandatory: 0.0%)")

    # Status derivation: PASS requires zero violations
    if violations:
        if not layer_d_raw or eval_sample_count == 0 or per_case_records is None:
            status = "INCONCLUSIVE"
        elif any("Incomplete evaluation sample" in v or "Missing" in v or "mismatches recomputed" in v or "missing" in v or "bound to invalid" in v or "mismatch" in v for v in violations):
            status = "PARTIAL"
        else:
            status = "FAIL"
    else:
        status = "PASS"

    return {
        "evaluation_layer": "Layer D: Performance & Cost Benchmarks",
        "status": status,
        "run_id": run_id,
        "dataset_sha256_digest": expected_dataset_digest,
        "run_records_sha256_digest": reported_records_digest,
        "sample_count": eval_sample_count,
        "combined_gating_accuracy_pct": acc,
        "combined_gating_recall_pct": recall,
        "combined_gating_fpr_pct": fpr,
        "p95_latency_ms": p95_lat,
        "total_tokens_spent": tokens,
        "baselines_evaluated": list(baselines.keys()) if isinstance(baselines, dict) else [],
        "mandatory_criteria_passed": len(violations) == 0,
        "violations": violations
    }


def generate_consolidated_evidence(fast_mode: bool = False) -> Dict[str, Any]:
    print("Generating Layer A evidence (Deterministic Regression)...")
    layer_a = run_layer_a_deterministic_tests(fast_mode=fast_mode)

    print("Generating Layer B evidence (Incident Lab Execution-Boundary)...")
    subprocess.run([sys.executable, "benchmarks/run_incident_lab.py"], check=True)
    layer_b_raw = load_json_artifact("results/incident_lab_results.json")

    b_scenarios_dict = layer_b_raw.get("scenarios", {})
    b_scenarios_list = []
    b_failures = []
    b_partials = []
    evaluated_scenario_keys = set()

    if isinstance(b_scenarios_dict, dict) and len(b_scenarios_dict) > 0:
        for case_key, sc_data in b_scenarios_dict.items():
            sc_id = str(sc_data.get("scenario_id", case_key)).lower()

            # Map Case1_github_credential_exposure -> case1
            normalized_key = sc_id.split("_")[0] if "_" in sc_id else sc_id
            evaluated_scenario_keys.add(normalized_key)

            dim_a = sc_data.get("dimension_a_security", {})
            outcome = dim_a.get("containment_recovery_outcome") or dim_a.get("security_outcome") or "UNKNOWN"
            prov_verif = dim_a.get("provenance_verification", "UNVERIFIED")

            sc_info = {
                "case_id": sc_data.get("scenario_id", case_key),
                "name": sc_data.get("scenario_name", case_key),
                "security_outcome": outcome,
                "provenance_verified": prov_verif
            }
            b_scenarios_list.append(sc_info)
            if outcome in ["VULNERABLE_BREACH", "FAIL"]:
                b_failures.append(sc_info)
            elif outcome in ["PARTIAL_GATING_DEFENSE", "PARTIAL", "UNTESTED"]:
                b_partials.append(sc_info)

    # Empty or incomplete Layer B evidence is non-passing
    missing_mandatory_cases = MANDATORY_LAYER_B_SCENARIOS - evaluated_scenario_keys

    if not b_scenarios_dict or len(b_scenarios_list) == 0:
        layer_b_status = "INCONCLUSIVE"
    elif b_failures:
        layer_b_status = "FAIL"
    elif b_partials or missing_mandatory_cases:
        layer_b_status = "PARTIAL"
    else:
        layer_b_status = "PASS"

    layer_b = {
        "evaluation_layer": "Layer B: Actual Execution-Boundary Integration",
        "status": layer_b_status,
        "scenarios_evaluated": len(b_scenarios_list),
        "mandatory_scenarios_required": list(sorted(MANDATORY_LAYER_B_SCENARIOS)),
        "missing_mandatory_scenarios": list(sorted(missing_mandatory_cases)),
        "zero_breach_metric": len(b_failures) == 0,
        "breaches_observed": len(b_failures),
        "partial_defense_count": len(b_partials),
        "architectural_gaps_noted": ["GAP-03 (Transitive Egress Enforcement)", "GAP-04 (Multi-Tenant Fleet Isolation)"],
        "scenario_summary": b_scenarios_list
    }

    print("Generating Layer C evidence (Deterministic Synthetic Adversarial Harness)...")
    evaluator_c = SyntheticAdversarialHarnessEvaluator(trials_per_scenario=3, seed=42)
    layer_c = evaluator_c.run_red_team_evaluations()

    # Verify frozen dataset manifest independently
    manifest_path = "benchmarks/data/dataset_manifest.json"
    dataset_manifest = load_json_artifact(manifest_path)
    dataset_file = dataset_manifest.get("dataset_file", "benchmarks/data/eval_set.jsonl")
    expected_digest = dataset_manifest.get("sha256_digest", "")

    actual_digest = ""
    if Path(dataset_file).exists():
        with open(dataset_file, "rb") as f:
            actual_digest = hashlib.sha256(f.read()).hexdigest()

    dataset_digest_valid = (actual_digest == expected_digest and len(actual_digest) == 64)

    print("Generating Layer D evidence (Performance & Cost Benchmarks)...")
    if fast_mode and os.path.exists("results/ablation_table.json") and os.path.exists(CANONICAL_PER_CASE_RESULTS_PATH):
        layer_d_raw = load_json_artifact("results/ablation_table.json")
    else:
        runner_d = ComprehensiveBenchmarkRunner()
        layer_d_raw = runner_d.run_benchmark()

    layer_d = evaluate_layer_d_evidence(
        layer_d_raw,
        dataset_digest_valid,
        expected_dataset_digest=expected_digest,
        per_case_filepath=CANONICAL_PER_CASE_RESULTS_PATH
    )

    git_commit = get_git_commit_hash()
    working_tree_status = get_working_tree_status()
    tree_digest = compute_working_tree_digest()

    layer_statuses = {
        "Layer A": layer_a["status"],
        "Layer B": layer_b["status"],
        "Layer C": layer_c["overall_status"],
        "Layer D": layer_d["status"]
    }

    # Derive overall pipeline status across all four layers: any non-PASS layer forces overall status to non-PASS
    if any(st == "FAIL" for st in layer_statuses.values()) or not dataset_digest_valid:
        overall_status = "FAIL"
    elif any(st in ["PARTIAL", "UNTESTED", "INCONCLUSIVE"] for st in layer_statuses.values()):
        overall_status = "PARTIAL"
    else:
        overall_status = "PASS"

    consolidated_evidence = {
        "title": "EpistemicOS Four-Layer Security Evaluation Artifact",
        "version": "1.0.0",
        "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "reproducibility_metadata": {
            "evaluated_git_commit": git_commit,
            "working_tree_status": working_tree_status,
            "working_tree_digest": tree_digest,
            "dataset_version": dataset_manifest.get("version", "UNKNOWN"),
            "dataset_sha256_digest": actual_digest,
            "dataset_digest_verified": dataset_digest_valid
        },
        "overall_evaluation_status": overall_status,
        "layers": {
            "layer_a_deterministic": layer_a,
            "layer_b_execution_boundary": layer_b,
            "layer_c_live_agent_redteam": layer_c,
            "layer_d_performance_cost": layer_d
        }
    }

    Path("results").mkdir(parents=True, exist_ok=True)
    with open("results/four_layer_evidence.json", "w", encoding="utf-8") as f:
        json.dump(consolidated_evidence, f, indent=2)

    generate_markdown_report(consolidated_evidence)
    return consolidated_evidence


def generate_markdown_report(data: Dict[str, Any]):
    meta = data["reproducibility_metadata"]
    layers = data["layers"]

    md = [
        "# EpistemicOS Consolidated Security & Evaluation Evidence Report",
        "",
        f"**Overall Status:** `{data['overall_evaluation_status']}` | **Generated:** {data['timestamp_utc']}",
        "",
        "## Reproducibility & Environment Metadata",
        f"- **Evaluated Git Commit:** `{meta['evaluated_git_commit']}`",
        f"- **Working Tree Status:** `{meta['working_tree_status']}`",
        f"- **Working Tree Digest:** `{meta['working_tree_digest']}`",
        f"- **Dataset Version:** `{meta['dataset_version']}`",
        f"- **Dataset SHA-256 Digest:** `{meta['dataset_sha256_digest']}` (Verified: `{meta['dataset_digest_verified']}`)",
        "",
        "---",
        "",
        "## Layer A: Deterministic Regression",
        f"- **Status:** `{layers['layer_a_deterministic']['status']}`",
        f"- **Test Command:** `{layers['layer_a_deterministic'].get('test_command', 'N/A')}`",
        f"- **Summary:** {layers['layer_a_deterministic'].get('stdout_summary', 'N/A')}",
        "",
        "---",
        "",
        "## Layer B: Actual Execution-Boundary Integration",
        f"- **Status:** `{layers['layer_b_execution_boundary']['status']}`",
        f"- **Zero-Breach Metric:** `{layers['layer_b_execution_boundary']['zero_breach_metric']}`",
        f"- **Scenarios Evaluated:** {layers['layer_b_execution_boundary']['scenarios_evaluated']}",
        f"- **Breaches Observed:** {layers['layer_b_execution_boundary']['breaches_observed']}",
        f"- **Partial Defenses Noted:** {layers['layer_b_execution_boundary']['partial_defense_count']}",
        "- **Scenario Outcomes:**",
    ]

    for sc in layers['layer_b_execution_boundary']['scenario_summary']:
        md.append(f"  - `{sc['case_id']}` ({sc['name']}): Outcome=`{sc['security_outcome']}`, Provenance=`{sc['provenance_verified']}`")

    md.extend([
        "",
        "---",
        "",
        "## Layer C: Deterministic Synthetic Adversarial Harness",
        f"- **Overall Status:** `{layers['layer_c_live_agent_redteam']['overall_status']}`",
        f"- **Evaluator Type:** {layers['layer_c_live_agent_redteam']['evaluator_type']}",
        f"- **Execution Mode:** {layers['layer_c_live_agent_redteam']['execution_mode']}",
        f"- **Scenarios Evaluated:** {layers['layer_c_live_agent_redteam']['total_scenarios']}",
        f"- **Trials Evaluated:** {layers['layer_c_live_agent_redteam']['total_trials']}",
        f"- **Adversarial Trials Blocked:** {layers['layer_c_live_agent_redteam'].get('adversarial_trials_blocked', 0)} / {layers['layer_c_live_agent_redteam'].get('total_adversarial_trials', 0)}",
        f"- **Benign Controls Succeeded:** {layers['layer_c_live_agent_redteam'].get('benign_controls_succeeded', 0)} / {layers['layer_c_live_agent_redteam'].get('total_benign_trials', 0)}",
        "",
        "---",
        "",
        "## Layer D: Performance & Cost Benchmarks",
        f"- **Status:** `{layers['layer_d_performance_cost']['status']}`",
        f"- **Run ID:** `{layers['layer_d_performance_cost'].get('run_id', 'N/A')}`",
        f"- **Dataset Digest:** `{layers['layer_d_performance_cost'].get('dataset_sha256_digest', 'N/A')}`",
        f"- **Run Records File SHA-256:** `{layers['layer_d_performance_cost'].get('run_records_sha256_digest', 'N/A')}`",
        f"- **Sample Size:** N = {layers['layer_d_performance_cost']['sample_count']}",
        f"- **Combined Gating Accuracy:** {layers['layer_d_performance_cost']['combined_gating_accuracy_pct']}%",
        f"- **Combined Gating Security Recall:** {layers['layer_d_performance_cost']['combined_gating_recall_pct']}%",
        f"- **Benign False Positive Rate:** {layers['layer_d_performance_cost']['combined_gating_fpr_pct']}%",
        f"- **P95 Latency:** {layers['layer_d_performance_cost']['p95_latency_ms']} ms",
        f"- **Total Tokens Spent:** {layers['layer_d_performance_cost']['total_tokens_spent']}",
        f"- **Mandatory Criteria Passed:** `{layers['layer_d_performance_cost']['mandatory_criteria_passed']}`",
        "",
        "---",
        "",
        "## Remaining Architectural Blockers & Gaps",
        "- **GAP-03 (Transitive Egress Enforcement):** Pre-execution PermissionGate halting prevents command dispatch, but unmediated network calls after admission rely on downstream network policies.",
        "- **GAP-04 (Multi-Tenant Fleet Isolation):** Multi-tenant fleet concurrency isolation relies on process boundary enforcement rather than hypervisor-level microVMs."
    ])

    Path("docs/security").mkdir(parents=True, exist_ok=True)
    with open("docs/security/four_layer_evidence_report.md", "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")


def main():
    fast_mode = "--fast" in sys.argv
    evidence = generate_consolidated_evidence(fast_mode=fast_mode)
    print("\n=======================================================")
    print(f"Four-Layer Evidence Artifact Generated Successfully!")
    print(f"Overall Evaluation Status: {evidence['overall_evaluation_status']}")
    print("Saved to results/four_layer_evidence.json and docs/security/four_layer_evidence_report.md")
    print("=======================================================")


if __name__ == "__main__":
    main()
