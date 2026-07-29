import pytest
from scheduler import EntropyAwareScheduler

def test_scheduler_init_valid():
    # Test valid initialization (default and custom)
    scheduler = EntropyAwareScheduler()
    assert scheduler.V == 100
    assert scheduler.divergence_threshold == 0.15

    scheduler2 = EntropyAwareScheduler(
        value_of_information=50,
        divergence_threshold=0.2,
        negative_yield_window=3,
        entropy_delta_threshold=0.01,
        stagnation_window=5,
        confidence_threshold=0.05,
        utility_epsilon=0.1,
        minimum_steps_before_convergence=5
    )
    assert scheduler2.V == 50
    assert scheduler2.negative_yield_window == 3

def test_scheduler_init_invalid_type():
    with pytest.raises(TypeError, match="value_of_information must be a number"):
        EntropyAwareScheduler(value_of_information="100")

    with pytest.raises(TypeError, match="negative_yield_window must be an integer"):
        EntropyAwareScheduler(negative_yield_window=2.5)

def test_scheduler_init_invalid_value():
    with pytest.raises(ValueError, match="value_of_information must be positive"):
        EntropyAwareScheduler(value_of_information=0)

    with pytest.raises(ValueError, match="value_of_information must be positive"):
        EntropyAwareScheduler(value_of_information=-10)

    with pytest.raises(ValueError, match="divergence_threshold must be non-negative"):
        EntropyAwareScheduler(divergence_threshold=-0.1)

    with pytest.raises(ValueError, match="negative_yield_window must be positive"):
        EntropyAwareScheduler(negative_yield_window=0)

def test_scheduler_entropy():
    import torch
    scheduler = EntropyAwareScheduler()

    # Test with python list
    entropy_list = scheduler.entropy([0.5, 0.5])
    assert pytest.approx(entropy_list, 0.0001) == 1.0

    # Test with torch tensor
    entropy_tensor = scheduler.entropy(torch.tensor([0.5, 0.5]))
    assert pytest.approx(entropy_tensor, 0.0001) == 1.0

    # Test deterministic distribution (should be close to 0)
    entropy_deterministic = scheduler.entropy([1.0, 0.0])
    # The calculated entropy might have a small value due to the 1e-9 epsilon
    assert pytest.approx(entropy_deterministic, abs=1e-5) == 0.0

    # Test uniform distribution across 4 elements
    entropy_uniform_4 = scheduler.entropy([0.25, 0.25, 0.25, 0.25])
    assert pytest.approx(entropy_uniform_4, abs=1e-4) == 2.0

import torch

scheduler = EntropyAwareScheduler()
scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state=None)
scheduler.step(torch.tensor([0.9, 0.1]), cost=0, state=None)

def test_entropy_negative_probabilities():
    scheduler = EntropyAwareScheduler()
    with pytest.raises(ValueError, match="Probabilities cannot contain negative values"):
        scheduler.entropy(torch.tensor([-0.5, 1.5]))

def test_scheduler_init_invalid_type_extended():
    with pytest.raises(TypeError, match="entropy_delta_threshold must be a number"):
        EntropyAwareScheduler(entropy_delta_threshold="0.005")

    with pytest.raises(TypeError, match="stagnation_window must be an integer"):
        EntropyAwareScheduler(stagnation_window=3.5)

    with pytest.raises(TypeError, match="confidence_threshold must be a number"):
        EntropyAwareScheduler(confidence_threshold="0.01")

    with pytest.raises(TypeError, match="utility_epsilon must be a number"):
        EntropyAwareScheduler(utility_epsilon="0.5")

    with pytest.raises(TypeError, match="minimum_steps_before_convergence must be an integer"):
        EntropyAwareScheduler(minimum_steps_before_convergence=3.5)

def test_scheduler_init_invalid_value_extended():
    with pytest.raises(ValueError, match="entropy_delta_threshold must be non-negative"):
        EntropyAwareScheduler(entropy_delta_threshold=-0.005)

    with pytest.raises(ValueError, match="stagnation_window must be positive"):
        EntropyAwareScheduler(stagnation_window=0)

    with pytest.raises(ValueError, match="stagnation_window must be positive"):
        EntropyAwareScheduler(stagnation_window=-3)

    with pytest.raises(ValueError, match="confidence_threshold must be non-negative"):
        EntropyAwareScheduler(confidence_threshold=-0.01)

    with pytest.raises(ValueError, match="utility_epsilon must be non-negative"):
        EntropyAwareScheduler(utility_epsilon=-0.5)

    with pytest.raises(ValueError, match="minimum_steps_before_convergence must be non-negative"):
        EntropyAwareScheduler(minimum_steps_before_convergence=-3)

def test_scheduler_init_invalid_divergence_threshold():
    with pytest.raises(TypeError, match="divergence_threshold must be a number"):
        EntropyAwareScheduler(divergence_threshold="0.15")

def test_scheduler_step_eta_calculation():
    scheduler = EntropyAwareScheduler()
    # Step 1: Initial step, eta should be 0 because step_index=0
    # Let's set a high initial entropy (e.g., [0.5, 0.5] -> 1.0)
    scheduler.step(torch.tensor([0.5, 0.5]), cost=10, state="s1")

    # Step 2: Next step, make H drop and cost > 0 to calculate eta
    # [1.0, 0.0] -> 0.0, delta_h = 1.0 - 0.0 = 1.0. cost = 5.
    # eta = (delta_h / initial_entropy) * V / cost
    # eta = (1.0 / 1.0) * 100 / 5 = 20.0
    scheduler.step(torch.tensor([1.0, 0.0]), cost=5, state="s2")
    assert pytest.approx(scheduler.history[-1].eta, abs=1e-5) == 20.0

def test_scheduler_step_negative_yield():
    scheduler = EntropyAwareScheduler(negative_yield_window=2, divergence_threshold=0.15)
    # H increases from a baseline, causing negative delta_h
    # initial H is approx 0.0 for [1.0, 0.0]
    scheduler.step(torch.tensor([1.0, 0.0]), cost=0, state="s1")
    # second step, H goes up significantly, say to 1.0 -> delta_h = approx -1.0
    res1 = scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state="s2")
    assert res1.directive == "CONTINUE" # window is 2, need 2 consecutive negative yields
    # third step, H goes up again? We can't really go above 1.0 with 2 dims.
    # Let's use 4 dims.
    # Step 1: [1.0, 0.0, 0.0, 0.0] H ~ 0
    # Step 2: [0.5, 0.5, 0.0, 0.0] H ~ 1 (delta_h ~ -1)
    # Step 3: [0.25, 0.25, 0.25, 0.25] H ~ 2 (delta_h ~ -1)
    scheduler2 = EntropyAwareScheduler(negative_yield_window=2, divergence_threshold=0.15)
    scheduler2.step(torch.tensor([1.0, 0.0, 0.0, 0.0]), cost=1, state="s1")
    scheduler2.step(torch.tensor([0.5, 0.5, 0.0, 0.0]), cost=1, state="s2")
    res = scheduler2.step(torch.tensor([0.25, 0.25, 0.25, 0.25]), cost=1, state="s3")
    assert res.directive == "NEGATIVE_YIELD"
    assert res.halt is True

def test_scheduler_step_optimal_convergence():
    scheduler = EntropyAwareScheduler(minimum_steps_before_convergence=2, confidence_threshold=0.1, utility_epsilon=0.5)
    # To hit OPTIMAL_CONVERGENCE:
    # 1. step_index >= minimum_steps_before_convergence
    # 2. H < confidence_threshold
    # 3. utility_gain < utility_epsilon

    # Step 0: establish high entropy (to set initial_entropy and initial utility)
    scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state="s1") # H ~ 1.0, utility ~ 0
    # Step 1: establish low entropy to cause high utility jump
    scheduler.step(torch.tensor([1.0, 0.0]), cost=0, state="s2") # H ~ 0.0, utility ~ 100, gain ~ 100
    # Step 2: utility gain must be < utility_epsilon. If we keep H ~ 0 and cost ~ 0, utility stays same, gain ~ 0.
    res = scheduler.step(torch.tensor([1.0, 0.0]), cost=0, state="s3") # H ~ 0, utility ~ 100, gain ~ 0
    assert res.directive == "OPTIMAL_CONVERGENCE"
    assert res.halt is True

def test_scheduler_step_irreducible_uncertainty():
    scheduler = EntropyAwareScheduler(stagnation_window=2, entropy_delta_threshold=0.01)
    # To hit IRREDUCIBLE_UNCERTAINTY:
    # 1. len(self.history) >= stagnation_window
    # 2. all(abs(delta_h) < entropy_delta_threshold) for the last `stagnation_window` steps

    # Step 0:
    scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state="s1")
    # Step 1: delta_h ~ 0
    res1 = scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state="s2")
    # Step 2: delta_h ~ 0
    res2 = scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state="s3")

    assert res2.directive == "IRREDUCIBLE_UNCERTAINTY"
    assert res2.halt is True

def test_scheduler_entropy_math_exact():
    scheduler = EntropyAwareScheduler()
    import torch

    # 0.5, 0.5 -> entropy should be approx 1.0 (with 1e-9 it will be slightly different, but within 1e-5)
    ent_2 = scheduler.entropy(torch.tensor([0.5, 0.5]))
    assert abs(ent_2 - 1.0) < 1e-5

    # 1.0, 0.0 -> entropy should be approx 0.0
    ent_1_0 = scheduler.entropy(torch.tensor([1.0, 0.0]))
    assert abs(ent_1_0 - 0.0) < 1e-5

    # 0.25, 0.25, 0.25, 0.25 -> entropy should be 2.0
    ent_4 = scheduler.entropy(torch.tensor([0.25, 0.25, 0.25, 0.25]))
    assert abs(ent_4 - 2.0) < 1e-5

def test_scheduler_entropy_math_exact_list():
    scheduler = EntropyAwareScheduler()
    # verify it converts raw lists internally without issue
    ent_list = scheduler.entropy([0.5, 0.5])
    assert abs(ent_list - 1.0) < 1e-5
