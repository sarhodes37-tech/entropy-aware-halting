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
    """Verify prompt builder holds scenario wording constant and adds condition interventions."""
    scenarios = load_scenarios(SMOKE_DATASET_PATH)
    sc = scenarios[0]

    sys_a, user_a = build_scenario_prompt(sc, Condition.A_BASELINE, sc.candidates)
    assert sc.description in user_a
    assert "Candidate Options to Rank:" in user_a
    assert "Retrieved Context:" not in user_a

    sys_d, user_d = build_scenario_prompt(sc, Condition.D_RETRIEVAL_MEDIATED, sc.candidates)
    assert "Retrieved Context:" in user_d

    sys_e, user_e = build_scenario_prompt(sc, Condition.E_SOURCE_ASSESSMENT, sc.candidates)
    assert "MANDATE FOR SOURCE ASSESSMENT" in sys_e


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
    """Verify Wilson score confidence interval computation on sample proportions."""
    res = compute_wilson_score_interval(10, 20, confidence_level=0.95)
    assert res["low_percent"] < 50.0 < res["high_percent"]
    assert res["confidence_level"] == 0.95


def test_mcnemar_exact_test_computation():
    """Verify McNemar exact test calculation on paired trials."""
    ctrl_1 = TrialResult("tr1", "sc1", Condition.A_BASELINE, ["t1", "o1"], [], True, None, "A", 1.0)
    treat_1 = TrialResult("tr2", "sc1", Condition.D_RETRIEVAL_MEDIATED, ["o1", "t1"], [], True, None, "D", 1.0)

    res = compute_mcnemar_test([ctrl_1], [treat_1], k=1, target_candidate_id_func=lambda sid: "t1")
    assert res["contingency_table"]["b_ctrl_only"] == 1
    assert "exact_p_value" in res


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
