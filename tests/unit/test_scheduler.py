"""
Unit test suite for EntropyAwareScheduler initialization, mathematical 
entropy metrics, and execution state directives (NEGATIVE_YIELD, 
OPTIMAL_CONVERGENCE, IRREDUCIBLE_UNCERTAINTY).
"""

import pytest
import torch
from scheduler import EntropyAwareScheduler


# =====================================================================
# INITIALIZATION & PARAMETER VALIDATION
# =====================================================================

def test_scheduler_init_valid():
    """Validates default and custom initialization configurations."""
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
    """Validates type checking on primary parameters."""
    with pytest.raises(TypeError, match="value_of_information must be a number"):
        EntropyAwareScheduler(value_of_information="100")

    with pytest.raises(TypeError, match="negative_yield_window must be an integer"):
        EntropyAwareScheduler(negative_yield_window=2.5)


def test_scheduler_init_invalid_type_extended():
    """Validates type checking on secondary parameters."""
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

    with pytest.raises(TypeError, match="divergence_threshold must be a number"):
        EntropyAwareScheduler(divergence_threshold="0.15")


def test_scheduler_init_invalid_value():
    """Validates boundary value enforcement for primary parameters."""
    with pytest.raises(ValueError, match="value_of_information must be positive"):
        EntropyAwareScheduler(value_of_information=0)

    with pytest.raises(ValueError, match="value_of_information must be positive"):
        EntropyAwareScheduler(value_of_information=-10)

    with pytest.raises(ValueError, match="divergence_threshold must be non-negative"):
        EntropyAwareScheduler(divergence_threshold=-0.1)

    with pytest.raises(ValueError, match="negative_yield_window must be positive"):
        EntropyAwareScheduler(negative_yield_window=0)


def test_scheduler_init_invalid_value_extended():
    """Validates boundary value enforcement for secondary parameters."""
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


# =====================================================================
# ENTROPY CALCULATION & MATHEMATICAL PRECISION
# =====================================================================

def test_scheduler_entropy():
    """Validates entropy metrics across Python lists, PyTorch tensors, and known distributions."""
    scheduler = EntropyAwareScheduler()

    # Test with python list (uniform 2-element -> 1.0 bit)
    entropy_list = scheduler.entropy([0.5, 0.5])
    assert pytest.approx(entropy_list, 0.0001) == 1.0

    # Test with torch tensor
    entropy_tensor = scheduler.entropy(torch.tensor([0.5, 0.5]))
    assert pytest.approx(entropy_tensor, 0.0001) == 1.0

    # Test deterministic distribution (should be close to 0)
    entropy_deterministic = scheduler.entropy([1.0, 0.0])
    assert pytest.approx(entropy_deterministic, abs=1e-5) == 0.0

    # Test uniform distribution across 4 elements (2.0 bits)
    entropy_uniform_4 = scheduler.entropy([0.25, 0.25, 0.25, 0.25])
    assert pytest.approx(entropy_uniform_4, abs=1e-4) == 2.0


def test_entropy_negative_probabilities():
    """Ensures negative probability entries raise ValueError."""
    scheduler = EntropyAwareScheduler()
    with pytest.raises(ValueError, match="Probabilities cannot contain negative values"):
        scheduler.entropy(torch.tensor([-0.5, 1.5]))


def test_scheduler_entropy_math_exact():
    """Precision numerical tests for entropy metric implementation."""
    scheduler = EntropyAwareScheduler()

    ent_2 = scheduler.entropy(torch.tensor([0.5, 0.5]))
    assert abs(ent_2 - 1.0) < 1e-5

    ent_1_0 = scheduler.entropy(torch.tensor([1.0, 0.0]))
    assert abs(ent_1_0 - 0.0) < 1e-5

    ent_4 = scheduler.entropy(torch.tensor([0.25, 0.25, 0.25, 0.25]))
    assert abs(ent_4 - 2.0) < 1e-5


def test_scheduler_entropy_math_exact_list():
    """Validates implicit list conversion during entropy calculation."""
    scheduler = EntropyAwareScheduler()
    ent_list = scheduler.entropy([0.5, 0.5])
    assert abs(ent_list - 1.0) < 1e-5


# =====================================================================
# STEP EXECUTION & STATE DIRECTIVES
# =====================================================================

def test_scheduler_step_eta_calculation():
    """Validates marginal yield calculation (eta = (delta_h / initial_h) * V / cost)."""
    scheduler = EntropyAwareScheduler()
    scheduler.step(torch.tensor([0.5, 0.5]), cost=10, state="s1")
    scheduler.step(torch.tensor([1.0, 0.0]), cost=5, state="s2")
    assert pytest.approx(scheduler.history[-1].eta, abs=1e-5) == 20.0


def test_scheduler_step_negative_yield():
    """Validates NEGATIVE_YIELD directive trigger when entropy continuously increases."""
    scheduler = EntropyAwareScheduler(negative_yield_window=2, divergence_threshold=0.15)

    scheduler.step(torch.tensor([1.0, 0.0, 0.0, 0.0]), cost=1, state="s1")
    res1 = scheduler.step(torch.tensor([0.5, 0.5, 0.0, 0.0]), cost=1, state="s2")
    assert res1.directive == "CONTINUE"

    res2 = scheduler.step(torch.tensor([0.25, 0.25, 0.25, 0.25]), cost=1, state="s3")
    assert res2.directive == "NEGATIVE_YIELD"
    assert res2.halt is True


def test_scheduler_step_optimal_convergence():
    """Validates OPTIMAL_CONVERGENCE directive when confidence threshold is reached."""
    scheduler = EntropyAwareScheduler(
        minimum_steps_before_convergence=2, 
        confidence_threshold=0.1, 
        utility_epsilon=0.5
    )

    scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state="s1")
    scheduler.step(torch.tensor([1.0, 0.0]), cost=0, state="s2")

    res = scheduler.step(torch.tensor([1.0, 0.0]), cost=0, state="s3")
    assert res.directive == "OPTIMAL_CONVERGENCE"
    assert res.halt is True


def test_scheduler_step_irreducible_uncertainty():
    """Validates IRREDUCIBLE_UNCERTAINTY directive across stagnation windows."""
    scheduler = EntropyAwareScheduler(stagnation_window=2, entropy_delta_threshold=0.01)

    scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state="s1")
    res1 = scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state="s2")
    assert res1.directive == "CONTINUE"

    res2 = scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state="s3")
    assert res2.directive == "IRREDUCIBLE_UNCERTAINTY"
    assert res2.halt is True
