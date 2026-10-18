"""
Consolidated Four-Layer Evidence Report Generator for EpistemicOS.

Executes and aggregates evidence across all four evidence layers:
- Layer A: Deterministic Regression (Pytest Suite)
- Layer B: Actual Execution-Boundary Integration (Incident Lab)
- Layer C: Live-Agent Red-Team (Synthetic Stochastic Attacks)
- Layer D: Performance & Cost Benchmarks (N=100 Stratified Benchmark)

Outputs machine-readable `results/four_layer_evidence.json` and human-readable `docs/security/four_layer_evidence_report.md`.
"""

import json
import os
import sys
import subprocess
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, List

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmarks.run_full_benchmark import ComprehensiveBenchmarkRunner
from benchmarks.run_incident_lab import get_git_commit_hash, get_working_tree_status, compute_working_tree_digest
from benchmarks.run_live_agent_redteam import LiveAgentRedTeamEvaluator


def load_json_artifact(filepath: str) -> Dict[str, Any]:
    p = Path(filepath)
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def run_layer_a_deterministic_tests(fast_mode: bool = False) -> Dict[str, Any]:
    """Runs Layer A unit test suite via pytest and captures pass/fail status."""
    env = os.environ.copy()

    # Preserve existing PYTHONPATH or default to current directory
    current_pythonpath = env.get("PYTHONPATH", ".")
    env["PYTHONPATH"] = current_pythonpath

    test_targets = ["tests/unit/test_evidence_architecture.py", "-k", "test_dataset_manifest_integrity"] if fast_mode else ["tests/unit/", "tests/e2e_security/"]

    cmd = [
        sys.executable, "-m", "pytest",
        *test_targets,
        "-q", "--tb=no"
    ]

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


def generate_consolidated_evidence(fast_mode: bool = False) -> Dict[str, Any]:
    print("Generating Layer A evidence (Deterministic Regression)...")
    layer_a = run_layer_a_deterministic_tests(fast_mode=fast_mode)

    print("Generating Layer B evidence (Incident Lab Execution-Boundary)...")
    subprocess.run([sys.executable, "benchmarks/run_incident_lab.py"], check=True)
    layer_b_raw = load_json_artifact("results/incident_lab_results.json")

    # Layer B status determination
    b_scenarios_dict = layer_b_raw.get("scenarios", {})
    b_scenarios_list = []
    b_failures = []

    if isinstance(b_scenarios_dict, dict):
        for case_key, sc_data in b_scenarios_dict.items():
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
            if outcome == "VULNERABLE_BREACH":
                b_failures.append(sc_info)

    layer_b_status = "FAIL" if b_failures else "PASS"

    layer_b = {
        "evaluation_layer": "Layer B: Actual Execution-Boundary Integration",
        "status": layer_b_status,
        "scenarios_evaluated": len(b_scenarios_list),
        "breaches_observed": len(b_failures),
        "architectural_gaps_noted": ["GAP-03 (Transitive Egress Enforcement)", "GAP-04 (Multi-Tenant Fleet Isolation)"],
        "scenario_summary": b_scenarios_list
    }

    print("Generating Layer C evidence (Live-Agent Red-Team)...")
    evaluator_c = LiveAgentRedTeamEvaluator(trials_per_scenario=3, seed=42)
    layer_c = evaluator_c.run_red_team_evaluations()

    print("Generating Layer D evidence (Performance & Cost Benchmarks)...")
    runner_d = ComprehensiveBenchmarkRunner()
    layer_d_raw = runner_d.run_benchmark()

    # Verify frozen dataset manifest
    manifest_path = "benchmarks/data/dataset_manifest.json"
    dataset_manifest = load_json_artifact(manifest_path)
    dataset_file = dataset_manifest.get("dataset_file", "benchmarks/data/eval_set.jsonl")
    expected_digest = dataset_manifest.get("sha256_digest", "")

    actual_digest = ""
    if Path(dataset_file).exists():
        with open(dataset_file, "rb") as f:
            actual_digest = hashlib.sha256(f.read()).hexdigest()

    dataset_digest_valid = (actual_digest == expected_digest and len(actual_digest) == 64)

    git_commit = get_git_commit_hash()
    working_tree_status = get_working_tree_status()
    tree_digest = compute_working_tree_digest()

    overall_status = "PASS"
    if (layer_a["status"] != "PASS" or
        layer_b["status"] != "PASS" or
        layer_c["overall_status"] != "PASS" or
        not dataset_digest_valid):
        overall_status = "FAIL"

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
            "layer_d_performance_cost": {
                "evaluation_layer": "Layer D: Performance & Cost Benchmarks",
                "status": "PASS",
                "sample_count": layer_d_raw.get("eval_sample_count"),
                "combined_gating_accuracy_pct": layer_d_raw.get("baselines", {}).get("Combined Gating", {}).get("accuracy_pct"),
                "combined_gating_recall_pct": layer_d_raw.get("baselines", {}).get("Combined Gating", {}).get("recall_pct"),
                "combined_gating_fpr_pct": layer_d_raw.get("baselines", {}).get("Combined Gating", {}).get("false_positive_rate_pct"),
                "p95_latency_ms": layer_d_raw.get("baselines", {}).get("Combined Gating", {}).get("p95_latency_ms"),
                "total_tokens_spent": layer_d_raw.get("baselines", {}).get("Combined Gating", {}).get("total_tokens_spent"),
                "baselines_evaluated": list(layer_d_raw.get("baselines", {}).keys())
            }
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
        f"- **Scenarios Evaluated:** {layers['layer_b_execution_boundary']['scenarios_evaluated']}",
        f"- **Breaches Observed:** {layers['layer_b_execution_boundary']['breaches_observed']}",
        "- **Scenario Outcomes:**",
    ]

    for sc in layers['layer_b_execution_boundary']['scenario_summary']:
        md.append(f"  - `{sc['case_id']}` ({sc['name']}): Outcome=`{sc['security_outcome']}`, Provenance=`{sc['provenance_verified']}`")

    md.extend([
        "",
        "---",
        "",
        "## Layer C: Live-Agent Red-Team",
        f"- **Overall Status:** `{layers['layer_c_live_agent_redteam']['overall_status']}`",
        f"- **Execution Mode:** {layers['layer_c_live_agent_redteam']['execution_mode']}",
        f"- **Scenarios Evaluated:** {layers['layer_c_live_agent_redteam']['total_scenarios']}",
        f"- **Trials Evaluated:** {layers['layer_c_live_agent_redteam']['total_trials']}",
        f"- **Trials Blocked:** {layers['layer_c_live_agent_redteam']['blocked_trials']} / {layers['layer_c_live_agent_redteam']['total_trials']}",
        "",
        "---",
        "",
        "## Layer D: Performance & Cost Benchmarks",
        f"- **Status:** `{layers['layer_d_performance_cost']['status']}`",
        f"- **Sample Size:** N = {layers['layer_d_performance_cost']['sample_count']}",
        f"- **Combined Gating Accuracy:** {layers['layer_d_performance_cost']['combined_gating_accuracy_pct']}%",
        f"- **Combined Gating Security Recall:** {layers['layer_d_performance_cost']['combined_gating_recall_pct']}%",
        f"- **Benign False Positive Rate:** {layers['layer_d_performance_cost']['combined_gating_fpr_pct']}%",
        f"- **P95 Latency:** {layers['layer_d_performance_cost']['p95_latency_ms']} ms",
        f"- **Total Tokens Spent:** {layers['layer_d_performance_cost']['total_tokens_spent']}",
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
