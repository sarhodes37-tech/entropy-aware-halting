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
