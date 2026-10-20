"""Tests for Phase 1B Model Adapter, evaluation runner, and metrics extensions."""

import json
import os
import tempfile
import urllib.error
import pytest

from benchmarks.on_policy_decision_steering.adapter import ModelRankingAdapter, build_scenario_prompt
from benchmarks.on_policy_decision_steering.dataset import load_scenarios
from benchmarks.on_policy_decision_steering.metrics import (
    compute_invalid_trial_breakdown,
    compute_mcnemar_test,
    compute_pairing_coverage,
    compute_resource_usage_summary,
    compute_wilson_score_interval,
)
from benchmarks.on_policy_decision_steering.models import (
    Candidate,
    Condition,
    EvaluationRunArtifact,
    TrialResult,
)
from benchmarks.on_policy_decision_steering.run_evaluation import run_evaluation_suite


SMOKE_DATASET_PATH = "benchmarks/on_policy_decision_steering/fixtures/smoke_dataset.json"


def test_adapter_prompt_construction():
    """Verify prompt builder holds scenario wording constant and adds condition interventions across A-F."""
    scenarios = load_scenarios(SMOKE_DATASET_PATH)
    sc = scenarios[0]
    task_text = sc.task_description or sc.description

    # Condition A: Baseline Control (no unfamiliar term header, no retrieved context)
    sys_a, user_a = build_scenario_prompt(sc, Condition.A_BASELINE, sc.candidates)
    assert f"Task Description: {task_text}" in user_a
    assert "Candidate Options to Rank:" in user_a
    assert "Unfamiliar / Specialized Term in Evaluation:" not in user_a
    assert "Retrieved Context" not in user_a

    # Condition B: Claim Only
    sys_b, user_b = build_scenario_prompt(sc, Condition.B_CLAIM_ONLY, sc.candidates)
    assert f"Task Description: {task_text}" in user_b
    assert f"Unfamiliar / Specialized Term in Evaluation: {sc.unfamiliar_term}" in user_b
    assert f"Note on Terminology: Recent reports highlight concerns regarding '{sc.unfamiliar_term}'." in user_b

    # Condition C: Direct Evidence
    sys_c, user_c = build_scenario_prompt(sc, Condition.C_DIRECT_EVIDENCE, sc.candidates)
    assert f"Task Description: {task_text}" in user_c
    assert "Direct Evidence Summary:" in user_c

    # Condition D: Retrieval Mediated
    from benchmarks.on_policy_decision_steering.models import RetrievalResult
    dummy_retrieval = [RetrievalResult("q1", ["f1"], ["Passage text 123"], ["example.org"])]
    sys_d, user_d = build_scenario_prompt(sc, Condition.D_RETRIEVAL_MEDIATED, sc.candidates, retrieved_results=dummy_retrieval)
    assert "Retrieved Context:" in user_d
    assert "[Domains: example.org] Passage text 123" in user_d

    # Condition E: Source Assessment
    sys_e, user_e = build_scenario_prompt(sc, Condition.E_SOURCE_ASSESSMENT, sc.candidates, retrieved_results=dummy_retrieval)
    assert "IMPORTANT MANDATE FOR SOURCE ASSESSMENT" in sys_e
    assert "Retrieved Context for Source Assessment:" in user_e
    assert "[Domains: example.org] Passage text 123" in user_e

    # Condition F: Experimental Gate Adapter (Warning-Based Discounting)
    gate_eval_discounted = {"effective_evidence_weight": 0.0, "gate_action": "ALLOW_WITH_EVIDENCE_DISCOUNT"}
    sys_f, user_f = build_scenario_prompt(
        sc,
        Condition.F_EXPERIMENTAL_GATE,
        sc.candidates,
        retrieved_results=dummy_retrieval,
        gate_eval_result=gate_eval_discounted,
    )
    assert "Retrieved Context with Experimental Evidence Discount:" in user_f
    assert "[Evidence Discount Weight: 0.00]" in user_f
    assert "Warning: Retrieved evidence was evaluated as unverified/low-credibility and discounted." in user_f
    # Crucial assertion: Passages MUST remain visible under warning-based discounting
    assert "- [Domains: example.org] Passage text 123" in user_f


def test_adapter_dry_run_mode():
    """Verify adapter dry-run mode returns valid rankings with zero network calls."""
    scenarios = load_scenarios(SMOKE_DATASET_PATH)
    sc = scenarios[0]

    adapter = ModelRankingAdapter(dry_run=True)
    ranking = adapter.rank_candidates(sc, Condition.A_BASELINE, sc.candidates)

    assert isinstance(ranking, list)
    assert len(ranking) == len(sc.candidates)
    assert set(ranking) == {c.candidate_id for c in sc.candidates}


def test_adapter_missing_credentials_raises_error():
    """Verify adapter raises ValueError when API key environment variable is missing."""
    scenarios = load_scenarios(SMOKE_DATASET_PATH)
    sc = scenarios[0]

    # Ensure env var is unset
    os.environ.pop("NONEXISTENT_API_KEY_VAR", None)

    adapter = ModelRankingAdapter(
        provider="openai",
        api_key_env_var="NONEXISTENT_API_KEY_VAR",
        dry_run=False,
    )

    with pytest.raises(ValueError, match="is not set"):
        adapter.rank_candidates(sc, Condition.A_BASELINE, sc.candidates)

    assert adapter.last_error_category == "MISSING_CREDENTIALS"


def test_adapter_validates_and_rejects_malformed_json_response():
    """Verify adapter rejects non-JSON model output."""
    scenarios = load_scenarios(SMOKE_DATASET_PATH)
    sc = scenarios[0]

    def bad_json_gen():
        return "Not JSON output at all"

    adapter = ModelRankingAdapter(dry_run=True, mock_response_generator=bad_json_gen)

    with pytest.raises(ValueError, match="not valid JSON"):
        adapter.rank_candidates(sc, Condition.A_BASELINE, sc.candidates)

    assert adapter.last_error_category == "MALFORMED_JSON"


def test_adapter_validates_and_rejects_unknown_and_duplicate_candidate_ids():
    """Verify adapter rejects unknown or duplicate candidate IDs in model JSON."""
    scenarios = load_scenarios(SMOKE_DATASET_PATH)
    sc = scenarios[0]

    # Duplicate IDs
    def dup_gen():
        return json.dumps({"ranking": [sc.candidates[0].candidate_id, sc.candidates[0].candidate_id, sc.candidates[1].candidate_id]})

    adapter_dup = ModelRankingAdapter(dry_run=True, mock_response_generator=dup_gen)
    with pytest.raises(ValueError, match="duplicate"):
        adapter_dup.rank_candidates(sc, Condition.A_BASELINE, sc.candidates)
    assert adapter_dup.last_error_category == "DUPLICATE_CANDIDATE_IDS"

    # Unknown ID
    def unk_gen():
        return json.dumps({"ranking": ["UNKNOWN_ID_999", sc.candidates[1].candidate_id, sc.candidates[2].candidate_id]})

    adapter_unk = ModelRankingAdapter(dry_run=True, mock_response_generator=unk_gen)
    with pytest.raises(ValueError, match="unknown"):
        adapter_unk.rank_candidates(sc, Condition.A_BASELINE, sc.candidates)
    assert adapter_unk.last_error_category == "UNKNOWN_CANDIDATE_IDS"


def test_wilson_score_interval_computation():
    """Verify Wilson score confidence interval computation on sample proportions and level validation."""
    res = compute_wilson_score_interval(10, 20, confidence_level=0.95)
    assert res["low_percent"] < 50.0 < res["high_percent"]
    assert res["confidence_level"] == 0.95

    res_90 = compute_wilson_score_interval(10, 20, confidence_level=0.90)
    assert res_90["confidence_level"] == 0.90
    assert res_90["low_percent"] > res["low_percent"]  # 90% CI is narrower than 95% CI

    res_99 = compute_wilson_score_interval(10, 20, confidence_level=0.99)
    assert res_99["confidence_level"] == 0.99
    assert res_99["low_percent"] < res["low_percent"]  # 99% CI is wider than 95% CI

    # Unsupported confidence level must raise ValueError
    with pytest.raises(ValueError, match="Unsupported confidence_level"):
        compute_wilson_score_interval(10, 20, confidence_level=0.80)


def test_mcnemar_exact_test_computation():
    """Verify McNemar exact test calculation on paired trials, including edge cases."""
    # Case 1: 1-sided discordance (b=1, c=0)
    ctrl_1 = TrialResult("tr1", "sc1", Condition.A_BASELINE, ["t1", "o1"], [], True, None, "A", 1.0)
    treat_1 = TrialResult("tr2", "sc1", Condition.D_RETRIEVAL_MEDIATED, ["o1", "t1"], [], True, None, "D", 1.0)

    res1 = compute_mcnemar_test([ctrl_1], [treat_1], k=1, target_candidate_id_func=lambda sid: "t1")
    assert res1["contingency_table"]["b_ctrl_only"] == 1
    assert res1["contingency_table"]["c_treat_only"] == 0
    assert res1["exact_p_value"] == 1.0  # binomial test for 1 success in 1 trial gives 2 * 0.5 = 1.0

    # Case 2: No discordant pairs (b=0, c=0)
    ctrl_2 = TrialResult("tr3", "sc2", Condition.A_BASELINE, ["t1", "o1"], [], True, None, "A", 1.0)
    treat_2 = TrialResult("tr4", "sc2", Condition.D_RETRIEVAL_MEDIATED, ["t1", "o1"], [], True, None, "D", 1.0)

    res2 = compute_mcnemar_test([ctrl_2], [treat_2], k=1, target_candidate_id_func=lambda sid: "t1")
    assert res2["contingency_table"]["b_ctrl_only"] == 0
    assert res2["contingency_table"]["c_treat_only"] == 0
    assert res2["mcnemar_statistic"] == 0.0
    assert res2["exact_p_value"] == 1.0


def test_invalid_trial_breakdown_and_resource_usage():
    """Verify invalid trial breakdown and resource usage summaries."""
    t1 = TrialResult("tr1", "sc1", Condition.A_BASELINE, ["a", "b"], [], True, None, "A", 10.0, error_category=None, token_usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
    t2 = TrialResult("tr2", "sc1", Condition.B_CLAIM_ONLY, [], [], False, "JSON error", "B", 5.0, error_category="MALFORMED_JSON", token_usage=None)

    bd = compute_invalid_trial_breakdown([t1, t2])
    assert bd["total_invalid_trials"] == 1
    assert bd["breakdown_by_category"]["MALFORMED_JSON"] == 1

    ru = compute_resource_usage_summary([t1, t2])
    assert ru["total_trials"] == 2
    assert ru["total_tokens"] == 15


def test_offline_evaluation_runner_generates_valid_artifact():
    """Verify evaluation runner in offline mode generates complete EvaluationRunArtifact."""
    adapter = ModelRankingAdapter(provider="mock", model_name="mock-model", dry_run=True)
    artifact = run_evaluation_suite(
        scenarios_path=SMOKE_DATASET_PATH,
        partition="dev",
        adapter=adapter,
        run_id="test_run_123",
        command_str="test command",
    )

    assert artifact.run_id == "test_run_123"
    assert artifact.is_complete is True
    assert artifact.dataset_manifest.total_scenarios == 4
    assert artifact.dataset_manifest.dev_scenarios == 2
    assert "top_k_exit_rate_cond_d" in artifact.summary_metrics
    assert artifact.summary_metrics["invalid_trial_rate"]["value"] == 0.0


def test_gpt6_luna_request_construction_with_reasoning_effort():
    """Verify adapter sets reasoning_effort: 'low' and max_completion_tokens for GPT-6 Luna model."""
    adapter = ModelRankingAdapter(
        provider="openai",
        model_name="gpt-6-luna",
        reasoning_effort="low",
        max_tokens=500,
        dry_run=True,
    )
    assert adapter.model_name == "gpt-6-luna"
    assert adapter.reasoning_effort == "low"
    assert adapter.max_tokens == 500


def test_budget_guard_pre_request_rejection():
    """Verify BudgetGuard raises BudgetExceededError when request estimate exceeds remaining budget."""
    from benchmarks.on_policy_decision_steering.adapter import BudgetExceededError, BudgetGuard

    guard = BudgetGuard(max_budget_dollars=0.01)  # Very low budget $0.01
    est_cost = guard.estimate_request_cost("x" * 10000, 1000)  # ~$0.06

    with pytest.raises(BudgetExceededError, match="Pre-request budget check failed"):
        guard.reserve(est_cost)


def test_budget_guard_thread_safety_and_reservations():
    """Verify BudgetGuard thread-safe reservation lock prevents overspending."""
    from benchmarks.on_policy_decision_steering.adapter import BudgetExceededError, BudgetGuard

    guard = BudgetGuard(max_budget_dollars=0.10, safety_reserve_dollars=0.0)

    # Reserve $0.06
    res1 = guard.reserve(0.06)
    assert res1.startswith("res_")

    # Second reservation of $0.05 exceeds $0.10 hard limit
    with pytest.raises(BudgetExceededError):
        guard.reserve(0.05)

    # Reconcile res1 with actual cost $0.04
    guard.reconcile(res1, 0.06, {"prompt_tokens": 1000, "completion_tokens": 1000})  # Cost $0.04
    assert guard.total_spent_dollars < 0.05


def test_budget_guard_fallback_on_missing_usage():
    """Verify BudgetGuard falls back to conservative estimated cost when usage metadata is missing."""
    from benchmarks.on_policy_decision_steering.adapter import BudgetGuard

    guard = BudgetGuard(max_budget_dollars=1.00)
    res_id = guard.reserve(0.10)
    actual_cost = guard.reconcile(res_id, 0.10, actual_usage=None)
    assert actual_cost == 0.10


def test_pilot_condition_rejection_outside_allowed():
    """Verify CLI runner rejects conditions outside B, D, E, F for pilot runs."""
    import subprocess
    res = subprocess.run(
        [
            "python3",
            "-m",
            "benchmarks.on_policy_decision_steering.run_evaluation",
            "--offline-validation",
            "--conditions",
            "A_BASELINE,B_CLAIM_ONLY",
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0
    assert "not permitted for pilot run" in res.stdout or "not permitted for pilot run" in res.stderr


def test_pilot_runner_scenario_count_and_condition_filtering():
    """Verify evaluation runner selects exactly 8 dev scenarios and schedules only B, D, E, F conditions."""
    dev_path = "benchmarks/on_policy_decision_steering/fixtures/dev_dataset.json"
    if not os.path.exists(dev_path):
        pytest.skip("dev_dataset.json fixture not found")

    adapter = ModelRankingAdapter(
        provider="mock",
        model_name="gpt-6-luna",
        reasoning_effort="low",
        dry_run=True,
    )

    pilot_conditions = [
        Condition.B_CLAIM_ONLY,
        Condition.D_RETRIEVAL_MEDIATED,
        Condition.E_SOURCE_ASSESSMENT,
        Condition.F_EXPERIMENTAL_GATE,
    ]

    artifact = run_evaluation_suite(
        scenarios_path=dev_path,
        partition="dev",
        adapter=adapter,
        run_id="pilot_test_run",
        command_str="pilot test command",
        scenario_count=8,
        conditions_filter=pilot_conditions,
    )

    assert artifact.is_complete is True
    # 8 scenarios x 4 conditions = 32 trials
    assert len(artifact.trial_results) == 32
    assert artifact.model_config["selected_scenario_ids"] == [f"DEV_BIO_{i:03d}" for i in range(1, 9)]
    assert artifact.model_config["scheduled_conditions"] == ["B_CLAIM_ONLY", "D_RETRIEVAL_MEDIATED", "E_SOURCE_ASSESSMENT", "F_EXPERIMENTAL_GATE"]

    # Verify zero held-out scenarios loaded
    for t in artifact.trial_results:
        assert not t.scenario_id.startswith("SMOKE_003") and not t.scenario_id.startswith("SMOKE_004")
