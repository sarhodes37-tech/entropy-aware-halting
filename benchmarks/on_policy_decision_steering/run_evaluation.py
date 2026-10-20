"""CLI entrypoint for running Phase 1B On-Policy Decision Steering evaluations.

Supports two distinct execution modes:
1. Offline Validation (--offline-validation):
   - Dry-run execution using local fixtures / mock response generators.
   - Makes zero network API calls.
   - Verifies schemas, metrics, dataset integrity, and artifact handling.

2. Explicit Model Evaluation (--model-eval):
   - Opt-in, network-backed evaluation requiring explicit user configuration and credentials.
   - Records run provenance (run ID, command, commit SHA, model config, dataset SHA-256 digest).
   - Writes run records and summary metrics to benchmarks/on_policy_decision_steering/results/<run_id>/.
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from benchmarks.on_policy_decision_steering.adapter import ModelRankingAdapter
from benchmarks.on_policy_decision_steering.dataset import (
    generate_manifest,
    load_scenarios,
    verify_dataset_manifest,
)
from benchmarks.on_policy_decision_steering.metrics import (
    compute_benign_demotion_rate,
    compute_invalid_trial_breakdown,
    compute_invalid_trial_rate,
    compute_mcnemar_test,
    compute_pairing_coverage,
    compute_rank_position_shift,
    compute_resource_usage_summary,
    compute_top_k_entry_rate,
    compute_top_k_exit_rate,
    compute_unsupported_claim_influence,
    compute_wilson_score_interval,
)
from benchmarks.on_policy_decision_steering.mock_retrieval import MockRetrievalTool
from benchmarks.on_policy_decision_steering.models import (
    Condition,
    EvaluationRunArtifact,
    RetrievalResult,
    TrialResult,
)
from benchmarks.on_policy_decision_steering.runner import SteeringRunner


DEFAULT_DATASET_PATH = "benchmarks/on_policy_decision_steering/fixtures/smoke_dataset.json"


def get_git_commit_sha() -> str:
    """Retrieve current working tree commit SHA or 'unknown'."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        )
        return res.stdout.strip()
    except Exception:
        return "unknown_commit"


def get_target_candidate_id(scenario_id: str, scenarios: List[Any]) -> str:
    """Find designated target candidate ID for a scenario."""
    for sc in scenarios:
        if sc.scenario_id == scenario_id:
            for c in sc.candidates:
                if c.is_target_option:
                    return c.candidate_id
            return sc.candidates[0].candidate_id
    return ""


def run_evaluation_suite(
    scenarios_path: str,
    partition: str,
    adapter: ModelRankingAdapter,
    run_id: str,
    command_str: str,
    scenario_count: Optional[int] = None,
    conditions_filter: Optional[List[Condition]] = None,
) -> EvaluationRunArtifact:
    """Execute complete paired evaluation suite and compute summary metrics."""
    manifest = generate_manifest(scenarios_path)
    scenarios = load_scenarios(scenarios_path, partition=partition)

    # Deterministic scenario selection if scenario_count specified
    if scenario_count is not None and scenario_count > 0:
        scenarios = scenarios[:scenario_count]

    # Setup retrieval tool from scenario metadata fixtures
    fixture_map: Dict[str, List[RetrievalResult]] = {}
    for sc in scenarios:
        if "fixture_passages" in sc.metadata:
            for fix in sc.metadata["fixture_passages"]:
                q = fix["query"]
                if q not in fixture_map:
                    fixture_map[q] = []
                fixture_map[q].append(RetrievalResult.from_dict(fix))

    retrieval_tool = MockRetrievalTool(fixture_map)
    runner = SteeringRunner(agent=adapter, retrieval_tool=retrieval_tool)

    # Execute paired suite across specified conditions or Conditions A–F
    scheduled_conditions = conditions_filter if conditions_filter else list(Condition)
    trial_results = runner.run_paired_suite(scenarios=scenarios, conditions=scheduled_conditions)

    # Metrics computation
    trials_ctrl = [t for t in trial_results if t.condition == Condition.A_BASELINE]
    trials_treat_b = [t for t in trial_results if t.condition == Condition.B_CLAIM_ONLY]
    trials_treat_d = [t for t in trial_results if t.condition == Condition.D_RETRIEVAL_MEDIATED]
    trials_treat_e = [t for t in trial_results if t.condition == Condition.E_SOURCE_ASSESSMENT]
    trials_treat_f = [t for t in trial_results if t.condition == Condition.F_EXPERIMENTAL_GATE]

    target_func = lambda sid: get_target_candidate_id(sid, scenarios)

    entry_d = compute_top_k_entry_rate(trials_ctrl, trials_treat_d, k=1, target_candidate_id_func=target_func)
    exit_d = compute_top_k_exit_rate(trials_ctrl, trials_treat_d, k=1, target_candidate_id_func=target_func)
    exit_b_vs_d = compute_top_k_exit_rate(trials_treat_b, trials_treat_d, k=1, target_candidate_id_func=target_func)
    exit_f = compute_top_k_exit_rate(trials_treat_d, trials_treat_f, k=1, target_candidate_id_func=target_func)

    # Wilson Score CIs
    ci_exit_d = compute_wilson_score_interval(exit_d.numerator, exit_d.denominator) if exit_d.denominator > 0 else None
    ci_exit_b_vs_d = compute_wilson_score_interval(exit_b_vs_d.numerator, exit_b_vs_d.denominator) if exit_b_vs_d.denominator > 0 else None
    ci_exit_f = compute_wilson_score_interval(exit_f.numerator, exit_f.denominator) if exit_f.denominator > 0 else None

    # McNemar tests
    mcnemar_b_d = compute_mcnemar_test(trials_treat_b, trials_treat_d, k=1, target_candidate_id_func=target_func)
    mcnemar_a_d = compute_mcnemar_test(trials_ctrl, trials_treat_d, k=1, target_candidate_id_func=target_func)
    mcnemar_d_f = compute_mcnemar_test(trials_treat_d, trials_treat_f, k=1, target_candidate_id_func=target_func)

    shift_d = compute_rank_position_shift(trials_ctrl, trials_treat_d, target_func)
    shift_f = compute_rank_position_shift(trials_ctrl, trials_treat_f, target_func)

    # Benign demotion rate
    benign_sids = {sc.scenario_id for sc in scenarios if sc.attack_variant == "benign_control"}
    ctrl_benign = [t for t in trials_ctrl if t.scenario_id in benign_sids]
    treat_f_benign = [t for t in trials_treat_f if t.scenario_id in benign_sids]
    benign_demotion = compute_benign_demotion_rate(ctrl_benign, treat_f_benign, k=1, target_candidate_id_func=target_func)

    invalid_rate = compute_invalid_trial_rate(trial_results)
    invalid_breakdown = compute_invalid_trial_breakdown(trial_results)
    resource_summary = compute_resource_usage_summary(trial_results)
    coverage = compute_pairing_coverage(
        scenarios,
        trial_results,
        expected_conditions=[c.value for c in scheduled_conditions],
    )
    unsupported_claim = compute_unsupported_claim_influence()

    summary_metrics = {
        "top_k_entry_rate_cond_d": entry_d.to_dict(),
        "top_k_exit_rate_cond_d": exit_d.to_dict(),
        "top_k_exit_rate_cond_d_wilson_ci": ci_exit_d,
        "top_k_exit_rate_cond_b_vs_d": exit_b_vs_d.to_dict(),
        "top_k_exit_rate_cond_b_vs_d_wilson_ci": ci_exit_b_vs_d,
        "top_k_exit_rate_cond_f": exit_f.to_dict(),
        "top_k_exit_rate_cond_f_wilson_ci": ci_exit_f,
        "mcnemar_cond_b_vs_d": mcnemar_b_d,
        "mcnemar_baseline_vs_cond_d": mcnemar_a_d,
        "mcnemar_cond_d_vs_cond_f": mcnemar_d_f,
        "rank_shift_cond_d": shift_d,
        "rank_shift_cond_f": shift_f,
        "benign_demotion_rate_cond_f": benign_demotion.to_dict(),
        "invalid_trial_rate": invalid_rate.to_dict(),
        "invalid_trial_breakdown": invalid_breakdown,
        "pairing_coverage": coverage,
        "resource_usage": resource_summary,
        "unsupported_claim_influence": unsupported_claim.to_dict(),
    }

    is_complete = invalid_rate.numerator == 0
    incomplete_reason = None if is_complete else f"{invalid_rate.numerator} trials were invalid or failed."

    model_cfg = {
        "provider": adapter.provider,
        "model_name": adapter.model_name,
        "temperature": adapter.temperature,
        "seed": adapter.seed,
        "dry_run": adapter.dry_run,
        "reasoning_effort": getattr(adapter, "reasoning_effort", None),
        "selected_scenario_ids": [sc.scenario_id for sc in scenarios],
        "scheduled_conditions": [c.value for c in scheduled_conditions],
    }
    if adapter.budget_guard:
        model_cfg["budget_guard"] = {
            "max_budget_dollars": adapter.budget_guard.max_budget_dollars,
            "total_spent_dollars": adapter.budget_guard.total_spent_dollars,
            "remaining_budget_dollars": adapter.budget_guard.remaining_budget_dollars,
        }

    artifact = EvaluationRunArtifact(
        run_id=run_id,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        commit_sha=get_git_commit_sha(),
        command=command_str,
        dataset_manifest=manifest,
        partition=partition,
        model_config=model_cfg,
        trial_results=trial_results,
        summary_metrics=summary_metrics,
        is_complete=is_complete,
        incomplete_reason=incomplete_reason,
    )

    return artifact


def main():
    parser = argparse.ArgumentParser(description="Phase 1B On-Policy Decision Steering Evaluation Runner")
    parser.add_argument("--offline-validation", action="store_true", help="Run offline dry-run test without network API calls")
    parser.add_argument("--model-eval", action="store_true", help="Run network-backed evaluation with explicit model provider")
    parser.add_argument("--provider", type=str, default="openai", choices=["openai", "anthropic"], help="Model API provider")
    parser.add_argument("--model-name", type=str, default="gpt-4o-mini", help="Target model identifier")
    parser.add_argument("--api-key-env-var", type=str, default="OPENAI_API_KEY", help="Environment variable name for API key")
    parser.add_argument("--dataset-path", type=str, default=DEFAULT_DATASET_PATH, help="Path to scenario dataset JSON file")
    parser.add_argument("--partition", type=str, default="dev", choices=["dev", "held_out"], help="Dataset partition to evaluate")
    parser.add_argument("--temperature", type=float, default=0.0, help="Generation sampling temperature")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for model generation")
    parser.add_argument("--scenario-count", type=int, default=None, help="Number of scenarios to select deterministically")
    parser.add_argument("--conditions", type=str, default=None, help="Comma-separated list of conditions to schedule")
    parser.add_argument("--reasoning-effort", type=str, default=None, choices=["low", "medium", "high"], help="Reasoning effort level")
    parser.add_argument("--max-budget", type=float, default=2.00, help="Hard run budget limit in dollars")
    parser.add_argument("--output-dir", type=str, default=None, help="Directory to save run results artifact")

    args = parser.parse_args()

    if not args.offline_validation and not args.model_eval:
        print("Error: Must specify either --offline-validation or --model-eval.")
        sys.exit(1)

    # Parse and validate requested conditions filter for pilot
    conditions_filter = None
    ALLOWED_PILOT_CONDITIONS = {"B_CLAIM_ONLY", "D_RETRIEVAL_MEDIATED", "E_SOURCE_ASSESSMENT", "F_EXPERIMENTAL_GATE"}
    if args.conditions:
        raw_conds = [c.strip() for c in args.conditions.split(",") if c.strip()]
        conditions_filter = []
        valid_cond_map = {c.value: c for c in Condition}
        for rc in raw_conds:
            if rc not in valid_cond_map:
                print(f"Error: Invalid condition '{rc}'. Valid choices: {list(valid_cond_map.keys())}")
                sys.exit(1)
            if rc not in ALLOWED_PILOT_CONDITIONS:
                print(f"Error: Condition '{rc}' is not permitted for pilot run. Permitted pilot conditions: {sorted(list(ALLOWED_PILOT_CONDITIONS))}")
                sys.exit(1)
            conditions_filter.append(valid_cond_map[rc])

    command_str = " ".join(sys.argv)
    run_id = f"run_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

    from benchmarks.on_policy_decision_steering.adapter import BudgetGuard

    budget_guard = BudgetGuard(max_budget_dollars=args.max_budget)

    if args.offline_validation:
        print(f"Executing Phase 1B Offline Validation (Dry-Run Mode) - Run ID: {run_id}")
        adapter = ModelRankingAdapter(
            provider="mock",
            model_name=args.model_name if args.model_name != "gpt-4o-mini" else "offline-mock-ranker",
            reasoning_effort=args.reasoning_effort,
            dry_run=True,
            budget_guard=budget_guard,
        )
    else:
        print(f"Executing Phase 1B Model Evaluation - Provider: {args.provider}, Model: {args.model_name}, Run ID: {run_id}")
        adapter = ModelRankingAdapter(
            provider=args.provider,
            model_name=args.model_name,
            api_key_env_var=args.api_key_env_var,
            temperature=args.temperature,
            seed=args.seed,
            reasoning_effort=args.reasoning_effort,
            dry_run=False,
            budget_guard=budget_guard,
        )

    artifact = run_evaluation_suite(
        scenarios_path=args.dataset_path,
        partition=args.partition,
        adapter=adapter,
        run_id=run_id,
        command_str=command_str,
        scenario_count=args.scenario_count,
        conditions_filter=conditions_filter,
    )

    out_dir = Path(args.output_dir) if args.output_dir else Path(f"benchmarks/on_policy_decision_steering/results/{run_id}")
    out_dir.mkdir(parents=True, exist_ok=True)
    artifact_file = out_dir / "run_artifact.json"

    with open(artifact_file, "w", encoding="utf-8") as f:
        json.dump(artifact.to_dict(), f, indent=2)

    print(f"\nEvaluation Run Completed.")
    print(f"Is Complete: {artifact.is_complete}")
    print(f"Run Artifact Saved To: {artifact_file}")
    print("\nSummary Metrics Overview:")
    print(json.dumps(artifact.summary_metrics, indent=2))


if __name__ == "__main__":
    main()
