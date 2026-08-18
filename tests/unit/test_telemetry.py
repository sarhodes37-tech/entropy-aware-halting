"""
Unit tests for epistemicos.telemetry.
Validates hardware profiling fallbacks, CUDA telemetry, and risk metrics.
"""

import sys
import importlib
import pytest
from unittest.mock import patch, MagicMock

import epistemicos.telemetry
from epistemicos.telemetry import (
    ResourceProfiler,
    calculate_rolling_entropy,
    calculate_trigram_repetition,
    calculate_ast_persistence,
    calculate_structural_risk_index
)

def test_telemetry_no_torch_fallback():
    """Validates zero-dependency fallback when PyTorch is not installed."""
    # Force torch to be missing from the environment
    with patch.dict('sys.modules', {'torch': None}):
        importlib.reload(epistemicos.telemetry)
        assert epistemicos.telemetry.HAS_TORCH is False

    # Restore normal state for downstream tests
    importlib.reload(epistemicos.telemetry)


@patch("epistemicos.telemetry.HAS_TORCH", True)
@patch("epistemicos.telemetry.torch",create=True)
def test_resource_profiler_cuda_active(mock_torch):
    """Validates VRAM and fragmentation math when CUDA profiling is active."""
    mock_torch.cuda.is_available.return_value = True
    
    # Setup VRAM mocks (500MB alloc, 1000MB reserved, 750MB peak)
    mock_torch.cuda.memory_allocated.return_value = 1024 ** 2 * 500
    mock_torch.cuda.memory_reserved.return_value = 1024 ** 2 * 1000
    mock_torch.cuda.max_memory_allocated.return_value = 1024 ** 2 * 750
    
    # Setup Timing mocks
    mock_event = MagicMock()
    mock_event.elapsed_time.return_value = 42.5
    mock_torch.cuda.Event.return_value = mock_event

    profiler = epistemicos.telemetry.ResourceProfiler(device="cuda", token_count=10)
    
    with profiler:
        pass  # Trigger __enter__ and __exit__

    telemetry = profiler.get_telemetry()

    assert telemetry.cuda_time_ms == 42.5
    assert telemetry.vram_allocated_mb == 500.0
    assert telemetry.vram_reserved_mb == 1000.0
    assert telemetry.vram_peak_mb == 750.0
    assert telemetry.fragmentation_index == 0.5  # (1000-500)/1000
    assert telemetry.tokens_processed == 10
    assert telemetry.ms_per_token == 4.25


def test_trigram_repetition_short_text():
    """Validates evasion of index errors on short text sequences."""
    # Text under 3 tokens should safely return 0.0
    assert calculate_trigram_repetition("too short") == 0.0


def test_ast_persistence_break():
    """Validates that AST streak counting correctly halts on first invalid step."""
    # Reading backwards: True (1), True (2), False (Break)
    history = [True, False, True, True]
    assert calculate_ast_persistence(history) == 2


def test_calculate_structural_risk_index():
    """Validates standard SRI calculation logic."""
    # sri = max(0.0, dH_pos) * omega * float(dA)
    # sri = 0.5 * 2.0 * 3.0 = 3.0
    assert calculate_structural_risk_index(dH_pos=0.5, omega=2.0, dA=3) == 3.0


def test_calculate_rolling_entropy():
    """Validates the calculation of smoothed rolling mean entropy."""
    # Empty history
    assert calculate_rolling_entropy([]) == 0.0

    # History smaller than window size (default 5)
    assert calculate_rolling_entropy([1.0, 2.0, 3.0]) == 2.0

    # History equal to window size (default 5)
    assert calculate_rolling_entropy([1.0, 2.0, 3.0, 4.0, 5.0]) == 3.0

    # History larger than window size (default 5)
    assert calculate_rolling_entropy([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]) == 5.0

    # Custom window size
    assert calculate_rolling_entropy([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0], window_size=3) == 6.0

def test_calculate_rolling_entropy_edge_cases():
    """Validates edge case behavior for window size in calculating smoothed rolling mean entropy."""
    # Explicitly testing the empty history edge case again as requested by the rationale
    assert calculate_rolling_entropy([]) == 0.0

    # Window size 0 evaluates as an empty slice which sum to 0.0 and len to 0. But in Python [-0:] is [0:], i.e. full list
    assert calculate_rolling_entropy([1.0], window_size=0) == 1.0

    # Negative window size behaves strangely with slices
    assert calculate_rolling_entropy([1.0, 2.0], window_size=-1) == 2.0

    # Large floats
    assert calculate_rolling_entropy([1.123456, 2.123456], window_size=2) == 1.6235
