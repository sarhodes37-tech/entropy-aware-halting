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
import torch
from scheduler import EntropyAwareScheduler

def test_scheduler_step_initial():
    scheduler = EntropyAwareScheduler(value_of_information=100)
    # Uniform distribution (highest entropy for 2 classes)
    probs = torch.tensor([0.5, 0.5])
    result = scheduler.step(probs, cost=10, state="state1")

    assert scheduler.initial_entropy is not None
    assert len(scheduler.history) == 1
    assert scheduler.total_cost == 10

    assert not result.halt
    assert result.directive == "CONTINUE"
    assert result.best_state == "state1"
    assert result.best_step == 0
    assert result.current_utility == result.peak_utility

def test_scheduler_step_negative_yield():
    scheduler = EntropyAwareScheduler(
        value_of_information=100,
        divergence_threshold=0.15,
        negative_yield_window=2
    )

    # Step 0: Entropy ~0.08
    probs0 = torch.tensor([0.99, 0.01])
    scheduler.step(probs0, cost=10, state="state0")

    # Step 1: entropy ~0.72, delta_h ~ -0.64
    probs1 = torch.tensor([0.8, 0.2])
    scheduler.step(probs1, cost=10, state="state1")

    # Step 2: entropy = 1.0, delta_h ~ -0.28
    probs2 = torch.tensor([0.5, 0.5])
    result = scheduler.step(probs2, cost=10, state="state2")

    assert result.halt
    assert result.directive == "NEGATIVE_YIELD"
    # The best step is likely 0
    assert result.best_step == 0
    assert result.utility_loss_avoided > 0

def test_scheduler_step_optimal_convergence():
    scheduler = EntropyAwareScheduler(
        value_of_information=100,
        minimum_steps_before_convergence=2,
        confidence_threshold=0.05, # relaxed for testing
        utility_epsilon=2.0 # Ensure utility gain is below epsilon
    )

    # Need to simulate enough steps and reach low entropy
    # Step 0: utility = V * (1.0 - 1.0) - 1 = -1
    scheduler.step(torch.tensor([0.5, 0.5]), cost=1, state="state0")
    # Step 1: H = ~0.01. utility = 100 * (1.0 - 0.01) - 2 = 97
    scheduler.step(torch.tensor([0.999, 0.001]), cost=1, state="state1")

    # High confidence (low entropy)
    # Step 2: H = ~0.01. utility = 100 * (1.0 - 0.01) - 3 = 96
    # Utility gain will be negative (< epsilon)
    probs_converged = torch.tensor([0.999, 0.001])
    result = scheduler.step(probs_converged, cost=1, state="state2")

    assert result.halt
    assert result.directive == "OPTIMAL_CONVERGENCE"

def test_scheduler_step_irreducible_uncertainty():
    scheduler = EntropyAwareScheduler(
        value_of_information=100,
        stagnation_window=3,
        entropy_delta_threshold=0.005,
        minimum_steps_before_convergence=10 # ensure it doesn't converge
    )

    probs = torch.tensor([0.6, 0.4])
    scheduler.step(probs, cost=1, state="state0")

    # Keep entropy same/very similar for 3 steps
    scheduler.step(probs, cost=1, state="state1")
    scheduler.step(probs, cost=1, state="state2")
    result = scheduler.step(probs, cost=1, state="state3")

    assert result.halt
    assert result.directive == "IRREDUCIBLE_UNCERTAINTY"

def test_scheduler_step_list_input():
    scheduler = EntropyAwareScheduler()
    # It should accept list instead of tensor
    result = scheduler.step([0.5, 0.5], cost=1, state="list_state")
    assert not result.halt
    assert result.best_state == "list_state"
