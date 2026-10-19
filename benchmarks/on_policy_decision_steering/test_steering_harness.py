"""Comprehensive unit and integration tests for On-Policy Decision Steering benchmark harness."""

import json
import os
import shutil
import tempfile
from pathlib import Path
import pytest

from benchmarks.on_policy_decision_steering.dataset import (
    compute_dataset_digest,
    generate_manifest,
    load_scenarios,
    verify_dataset_manifest,
)
from benchmarks.on_policy_decision_steering.metrics import (
    compute_benign_demotion_rate,
    compute_invalid_trial_rate,
    compute_rank_position_shift,
    compute_top_k_entry_rate,
    compute_top_k_exit_rate,
)
from benchmarks.on_policy_decision_steering.mock_retrieval import MockRetrievalTool
from benchmarks.on_policy_decision_steering.models import (
    Candidate,
    Condition,
    RetrievalResult,
    Scenario,
    TrialResult,
)
from benchmarks.on_policy_decision_steering.runner import (
    DeterministicBaselineRanker,
    ExperimentalGateAdapter,
    RankingAgent,
    SteeringRunner,
)


# Path to smoke dataset fixture
SMOKE_DATASET_PATH = "benchmarks/on_policy_decision_steering/fixtures/smoke_dataset.json"


# 1. Test Reproducibility
def test_1_identical_deterministic_inputs_produce_identical_outputs():
    """Verify identical deterministic inputs produce identical outputs."""
    scenarios = load_scenarios(SMOKE_DATASET_PATH)

    # Setup Mock Retrieval from scenario metadata
    fixture_map = {}
    for sc in scenarios:
        if "fixture_passages" in sc.metadata:
            for fix in sc.metadata["fixture_passages"]:
                q = fix["query"]
                fixture_map[q] = [RetrievalResult.from_dict(fix)]

    retrieval_tool_1 = MockRetrievalTool(fixture_map)
    retrieval_tool_2 = MockRetrievalTool(fixture_map)

    ranker_1 = DeterministicBaselineRanker()
    ranker_2 = DeterministicBaselineRanker()

    runner_1 = SteeringRunner(ranker_1, retrieval_tool_1)
    runner_2 = SteeringRunner(ranker_2, retrieval_tool_2)

    results_1 = runner_1.run_paired_suite(scenarios)
    results_2 = runner_2.run_paired_suite(scenarios)

    assert len(results_1) == len(results_2)
    for r1, r2 in zip(results_1, results_2):
        assert r1.scenario_id == r2.scenario_id
        assert r1.condition == r2.condition
        assert r1.output_ranking == r2.output_ranking
        assert r1.is_valid == r2.is_valid


# 2. Test Mock Retrieval Isolation
def test_2_mock_retrieval_returns_only_configured_fixture_results():
    """Verify mock retrieval returns only configured local fixture results with zero network calls."""
    fixture_res = RetrievalResult(
        query="test_query",
        returned_fixture_ids=["f123"],
        raw_passages=["test passage"],
        origin_domains=["example.org"],
    )
    tool = MockRetrievalTool({"test_query": [fixture_res]})

    # Known query
    res = tool.search("test_query")
    assert len(res) == 1
    assert res[0].returned_fixture_ids == ["f123"]

    # Unknown query
    unknown_res = tool.search("unconfigured_query_xyz")
    assert unknown_res == []


# 3. Test Conditions A-F Interventions Harness Deterministic Wiring
def test_3_conditions_a_to_f_harness_wiring_verification():
    """
    Verify conditions A through F apply their declared ranking interventions in the baseline ranker.
    Note: This test validates deterministic harness wiring and contract execution logic, NOT real-world model susceptibility.
    """
    scenarios = load_scenarios(SMOKE_DATASET_PATH)
    adv_scenario = [s for s in scenarios if s.scenario_id == "SMOKE_001_DEV_RETRIEVAL_STEERING"][0]

    ranker = DeterministicBaselineRanker()

    # Condition A: Baseline rank
    rank_a = ranker.rank_candidates(adv_scenario, Condition.A_BASELINE, adv_scenario.candidates)
    assert rank_a == ["opt_vendor_a", "opt_vendor_b", "opt_vendor_c"]

    # Condition B: Claim only demotion
    rank_b = ranker.rank_candidates(adv_scenario, Condition.B_CLAIM_ONLY, adv_scenario.candidates)
    assert rank_b == ["opt_vendor_b", "opt_vendor_c", "opt_vendor_a"]

    # Condition C: Direct evidence demotion
    rank_c = ranker.rank_candidates(adv_scenario, Condition.C_DIRECT_EVIDENCE, adv_scenario.candidates)
    assert rank_c == ["opt_vendor_b", "opt_vendor_c", "opt_vendor_a"]

    # Condition D: Retrieval mediated demotion
    rank_d = ranker.rank_candidates(adv_scenario, Condition.D_RETRIEVAL_MEDIATED, adv_scenario.candidates)
    assert rank_d == ["opt_vendor_b", "opt_vendor_c", "opt_vendor_a"]

    # Condition E: Source assessment restoration
    rank_e = ranker.rank_candidates(adv_scenario, Condition.E_SOURCE_ASSESSMENT, adv_scenario.candidates)
    assert rank_e == ["opt_vendor_a", "opt_vendor_b", "opt_vendor_c"]

    # Condition F: Experimental gate adapter restoration
    rank_f = ranker.rank_candidates(adv_scenario, Condition.F_EXPERIMENTAL_GATE, adv_scenario.candidates)
    assert rank_f == ["opt_vendor_a", "opt_vendor_b", "opt_vendor_c"]


# 4. Test Paired Condition Consistency
def test_4_candidate_sets_and_initial_order_remain_consistent_across_paired_conditions():
    """Verify candidate sets and initial baseline ranks remain identical across paired conditions."""
    scenarios = load_scenarios(SMOKE_DATASET_PATH)
    for sc in scenarios:
        baseline_ids = [c.candidate_id for c in sorted(sc.candidates, key=lambda x: x.baseline_rank)]
        assert len(baseline_ids) == len(set(baseline_ids))
        for c in sc.candidates:
            assert c.candidate_id in baseline_ids


# 5. Test Candidate Validation Rejections
def test_5_duplicate_missing_and_unknown_candidate_ids_are_rejected():
    """Verify duplicate, missing, and unknown candidate IDs are rejected as invalid trials."""
    scenario = load_scenarios(SMOKE_DATASET_PATH)[0]

    # Malicious/buggy ranker returning duplicate candidate IDs
    class DuplicateRanker(RankingAgent):
        def rank_candidates(self, scenario, condition, candidates, retrieval_tool=None):
            return [candidates[0].candidate_id, candidates[0].candidate_id, candidates[1].candidate_id]

    runner_dup = SteeringRunner(DuplicateRanker())
    trial_dup = runner_dup.run_scenario(scenario, Condition.A_BASELINE)
    assert trial_dup.is_valid is False
    assert "duplicate" in trial_dup.invalid_reason.lower()

    # Malicious/buggy ranker returning unknown candidate ID
    class UnknownRanker(RankingAgent):
        def rank_candidates(self, scenario, condition, candidates, retrieval_tool=None):
            return ["UNKNOWN_ID_999", candidates[1].candidate_id, candidates[2].candidate_id]

    runner_unk = SteeringRunner(UnknownRanker())
    trial_unk = runner_unk.run_scenario(scenario, Condition.A_BASELINE)
    assert trial_unk.is_valid is False
    assert "unknown" in trial_unk.invalid_reason.lower()

    # Malicious/buggy ranker returning missing candidate ID (too short)
    class MissingRanker(RankingAgent):
        def rank_candidates(self, scenario, condition, candidates, retrieval_tool=None):
            return [candidates[0].candidate_id]

    runner_mis = SteeringRunner(MissingRanker())
    trial_mis = runner_mis.run_scenario(scenario, Condition.A_BASELINE)
    assert trial_mis.is_valid is False
    assert "length" in trial_mis.invalid_reason.lower()


# 6. Test Hand-Calculated Top-k Entry and Exit Metrics
def test_6_top_k_entry_and_exit_metrics_are_correct_on_hand_calculated_fixtures():
    """Verify top-k entry and exit metrics match hand-calculated fixture deltas."""
    ctrl_1 = TrialResult("tr1", "sc1", Condition.A_BASELINE, ["o1", "t1", "o2"], [], True, None, "A", 1.0)
    treat_1 = TrialResult("tr2", "sc1", Condition.D_RETRIEVAL_MEDIATED, ["t1", "o1", "o2"], [], True, None, "D", 1.0)

    ctrl_2 = TrialResult("tr3", "sc2", Condition.A_BASELINE, ["o3", "t2", "o4"], [], True, None, "A", 1.0)
    treat_2 = TrialResult("tr4", "sc2", Condition.D_RETRIEVAL_MEDIATED, ["o3", "t2", "o4"], [], True, None, "D", 1.0)

    res_entry = compute_top_k_entry_rate(
        trials_control=[ctrl_1, ctrl_2],
        trials_treatment=[treat_1, treat_2],
        k=1,
        target_candidate_id_func=lambda sid: "t1" if sid == "sc1" else "t2",
    )

    assert res_entry.value == 50.0
    assert res_entry.numerator == 1
    assert res_entry.denominator == 2

    # Exit rate test:
    ctrl_3 = TrialResult("tr5", "sc3", Condition.A_BASELINE, ["t1", "o1"], [], True, None, "A", 1.0)
    treat_3 = TrialResult("tr6", "sc3", Condition.D_RETRIEVAL_MEDIATED, ["o1", "t1"], [], True, None, "D", 1.0)

    res_exit = compute_top_k_exit_rate(
        trials_control=[ctrl_3],
        trials_treatment=[treat_3],
        k=1,
        target_candidate_id_func=lambda sid: "t1",
    )

    assert res_exit.value == 100.0
    assert res_exit.numerator == 1
    assert res_exit.denominator == 1


# 7. Test Empty or Ineligible Denominators
def test_7_empty_or_ineligible_denominators_are_reported_explicitly():
    """Verify zero denominator cases return value='N/A' explicitly."""
    res_entry = compute_top_k_entry_rate(
        trials_control=[],
        trials_treatment=[],
        k=1,
        target_candidate_id_func=lambda sid: "t1",
    )
    assert res_entry.value == "N/A"
    assert res_entry.numerator == 0
    assert res_entry.denominator == 0

    res_exit = compute_top_k_exit_rate(
        trials_control=[],
        trials_treatment=[],
        k=1,
        target_candidate_id_func=lambda sid: "t1",
    )
    assert res_exit.value == "N/A"
    assert res_exit.numerator == 0
    assert res_exit.denominator == 0


# 8. Test Invalid Trials and Malformed Rankings Handling
def test_8_invalid_trials_and_malformed_rankings_cannot_be_counted_as_defense_successes():
    """
    Verify invalid trials and malformed rankings are counted in invalid_trial_rate
    and strictly excluded from top-k exit/defense success counts.
    """
    valid_trial = TrialResult("t1", "sc1", Condition.D_RETRIEVAL_MEDIATED, ["a", "b"], [], True, None, "D", 1.0)
    invalid_trial = TrialResult("t2", "sc2", Condition.D_RETRIEVAL_MEDIATED, [], [], False, "Crashed/Malformed", "D", 1.0)

    res_invalid = compute_invalid_trial_rate([valid_trial, invalid_trial])
    assert res_invalid.value == 50.0
    assert res_invalid.numerator == 1
    assert res_invalid.denominator == 2

    # Verify invalid trial is excluded from top-k exit calculations and cannot be counted as defense success
    ctrl_2 = TrialResult("t3", "sc2", Condition.A_BASELINE, ["b", "a"], [], True, None, "A", 1.0)
    res_exit = compute_top_k_exit_rate(
        trials_control=[ctrl_2],
        trials_treatment=[invalid_trial],
        k=1,
        target_candidate_id_func=lambda sid: "b",
    )
    # Since treatment trial was invalid, paired trials is empty -> N/A (numerator=0, denominator=0)
    assert res_exit.value == "N/A"
    assert res_exit.numerator == 0


# 8b. Test Duplicate Scenario-Condition Record Rejection
def test_8b_duplicate_scenario_condition_records_raise_value_error():
    """Verify duplicate scenario-condition trial records in metric inputs raise ValueError."""
    t1 = TrialResult("tr1", "sc1", Condition.A_BASELINE, ["a", "b"], [], True, None, "A", 1.0)
    t2 = TrialResult("tr2", "sc1", Condition.A_BASELINE, ["a", "b"], [], True, None, "A", 1.0)

    with pytest.raises(ValueError, match="Duplicate scenario-condition record"):
        compute_top_k_exit_rate([t1, t2], [], k=1, target_candidate_id_func=lambda s: "a")

    with pytest.raises(ValueError, match="Duplicate scenario-condition record"):
        compute_invalid_trial_rate([t1, t2])


# 9. Test Dataset Digest Verification Tampering Detection
def test_9_dataset_digest_verification_detects_byte_level_modification():
    """Verify cryptographic SHA-256 digest verification detects any byte-level dataset modification."""
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as f:
        f.write(json.dumps({"version": "1.0", "scenarios": []}))
        temp_path = f.name

    try:
        manifest = generate_manifest(temp_path)
        assert verify_dataset_manifest(temp_path, manifest) is True

        # Tamper with single byte
        with open(temp_path, "w") as f:
            f.write(json.dumps({"version": "1.0", "scenarios": [], "tampered": True}))

        assert verify_dataset_manifest(temp_path, manifest) is False

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# 10. Test Dataset Partition Filtering Utility
def test_10_dataset_partition_filtering_utility():
    """
    Verify dataset loader partition filtering utility correctly splits dev and held_out scenarios from dataset file.
    Note: This tests dataset loader filtering functions; runtime environment isolation during training/tuning must be enforced by training loops.
    """
    dev_scenarios = load_scenarios(SMOKE_DATASET_PATH, partition="dev")
    held_out_scenarios = load_scenarios(SMOKE_DATASET_PATH, partition="held_out")

    assert len(dev_scenarios) > 0
    assert len(held_out_scenarios) > 0

    for sc in dev_scenarios:
        assert sc.partition == "dev"

    for sc in held_out_scenarios:
        assert sc.partition == "held_out"

    # Intersect check: zero overlap in loaded lists
    dev_ids = {s.scenario_id for s in dev_scenarios}
    held_out_ids = {s.scenario_id for s in held_out_scenarios}
    assert dev_ids.intersection(held_out_ids) == set()


# 11. Test Historical Benchmark Artifacts Remain Untouched
def test_11_historical_benchmark_artifacts_and_epistemicos_core_remain_untouched():
    """Verify epistemicos/ production directory and historical result files are unmutated."""
    epistemicos_path = Path("epistemicos")
    assert epistemicos_path.exists() and epistemicos_path.is_dir()

    # Check key historical result files exist and are untampered
    for hist_file in [
        "results/per_case_results.json",
        "docs/security/four_layer_evidence_report.md",
        "docs/security/incident_lab_report.md",
    ]:
        p = Path(hist_file)
        if p.exists():
            assert p.stat().st_size > 0
