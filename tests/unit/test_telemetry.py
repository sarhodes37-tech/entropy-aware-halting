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
    TelemetryBuffer,
    calculate_entropy_differential,
    calculate_rolling_entropy,
    calculate_trigram_repetition,
    calculate_ast_persistence,
    calculate_structural_risk_index,
    ASTAnalyzer
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


def test_trigram_repetition_with_repeats():
    """Validates trigram repetition ratio calculation when trigrams repeat."""
    text = "the cat sat on the mat the cat sat"
    # tokens = ['the', 'cat', 'sat', 'on', 'the', 'mat', 'the', 'cat', 'sat']
    # 7 trigrams: ('the','cat','sat'), ('cat','sat','on'), ('sat','on','the'), ('on','the','mat'), ('the','mat','the'), ('mat','the','cat'), ('the','cat','sat')
    # ('the','cat','sat') appears twice -> 1 repeated / 7 = 0.1429
    assert calculate_trigram_repetition(text) == 0.1429


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


def test_calculate_entropy_differential():
    """Validates that entropy differential computes surges and ignores drops."""
    # When previous entropy is None
    assert calculate_entropy_differential(current_entropy=5.0, prev_entropy=None) == 0.0

    # Surge (current > previous)
    assert calculate_entropy_differential(current_entropy=6.5, prev_entropy=5.0) == 1.5

    # Drop (current < previous)
    assert calculate_entropy_differential(current_entropy=4.0, prev_entropy=5.0) == 0.0

    # No change (current == previous)
    assert calculate_entropy_differential(current_entropy=5.0, prev_entropy=5.0) == 0.0


def test_calculate_rolling_entropy_empty_list():
    """Validates rolling entropy calculation on an empty list."""
    assert calculate_rolling_entropy([]) == 0.0


def test_calculate_rolling_entropy_small_list():
    """Validates rolling entropy calculation on a small list."""
    assert calculate_rolling_entropy([1.0, 2.0, 3.0]) == 2.0


def test_calculate_rolling_entropy_exact_window():
    """Validates rolling entropy calculation when list matches window size."""
    assert calculate_rolling_entropy([1.0, 2.0, 3.0, 4.0, 5.0]) == 3.0


def test_calculate_rolling_entropy_large_list():
    """Validates rolling entropy calculation on a large list."""
    assert calculate_rolling_entropy([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]) == 5.0


def test_calculate_rolling_entropy_custom_window():
    """Validates rolling entropy calculation with a custom window size."""
    assert calculate_rolling_entropy([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0], window_size=3) == 6.0

def test_ast_analyzer_get_node_weight():
    """Validates empirical risk weight mapping for AST nodes."""
    analyzer = ASTAnalyzer()

    # Exact match from DEFAULT_OMEGA_MAP
    assert analyzer.get_node_weight("Assign") == 1.0
    assert analyzer.get_node_weight("Call") == 6.17

    # Fallback to clean key (e.g., ast.Return -> Return)
    assert analyzer.get_node_weight("foo.bar.Return") == 1.52

    # Missing key defaults to 1.0
    assert analyzer.get_node_weight("UnknownNodeType") == 1.0

def test_ast_analyzer_passes_static_ast():
    """Validates if code string parses into a valid, non-empty AST tree."""
    analyzer = ASTAnalyzer()

    # Valid code
    assert analyzer.passes_static_ast("x = 1") is True
    # Empty string
    assert analyzer.passes_static_ast("") is False
    # Invalid syntax
    assert analyzer.passes_static_ast("if True") is False

def test_ast_analyzer_count_ast_nodes():
    """Validates counting total AST nodes in the code snippet."""
    analyzer = ASTAnalyzer()

    # Simple assignment
    assert analyzer.count_ast_nodes("x = 1") == 5
    # Empty string
    assert analyzer.count_ast_nodes("") == 1
    # Invalid syntax
    assert analyzer.count_ast_nodes("if True") == 0

def test_ast_analyzer_compute_aggregate_ast_risk():
    """Validates total summed Omega weight across all AST nodes in snippet."""
    analyzer = ASTAnalyzer()

    # Assign node has weight 1.0, and 4 default nodes have weight 1.0 -> total 5.0
    assert analyzer.compute_aggregate_ast_risk("x = 1") == 5.0

def test_ast_analyzer_compute_aggregate_ast_risk_invalid_syntax():
    """Validates compute_aggregate_ast_risk returns default 0.0 on invalid syntax."""
    analyzer = ASTAnalyzer()

    # Invalid syntax triggers SyntaxError and returns default 0.0 risk
    assert analyzer.compute_aggregate_ast_risk("if True") == 0.0

def test_ast_analyzer_get_node_weight_custom():
    """Validates get_node_weight behavior with custom omega map."""
    analyzer = ASTAnalyzer(omega_map={"CustomNode": 2.5, "ast.CustomNode2": 3.0})

    # Custom weights
    assert analyzer.get_node_weight("CustomNode") == 2.5
    assert analyzer.get_node_weight("ast.CustomNode2") == 3.0
    assert analyzer.get_node_weight("foo.bar.CustomNode") == 2.5 # clean_key check
    assert analyzer.get_node_weight("foo.bar.CustomNode2") == 1.0

    # Missing weights fallback to 1.0
    assert analyzer.get_node_weight("Assign") == 1.0


# ==========================================
# TELEMETRY BUFFER UNIT TESTS
# ==========================================

def test_telemetry_buffer_init_and_len():
    """Validates default TelemetryBuffer initialization and __len__."""
    tb = TelemetryBuffer()
    assert tb._sink is None
    assert tb.max_size == 1000
    assert len(tb) == 0


def test_telemetry_buffer_add_event():
    """Validates adding events to TelemetryBuffer."""
    tb = TelemetryBuffer()
    tb.add_event({"event_type": "metric", "value": 42})
    assert len(tb) == 1
    tb.add_event({"event_type": "metric", "value": 43})
    assert len(tb) == 2


def test_telemetry_buffer_flush_events_empty():
    """Validates flushing an empty TelemetryBuffer."""
    mock_sink = MagicMock()
    tb = TelemetryBuffer(sink=mock_sink)

    count = tb.flush_events()

    assert count == 0
    assert len(tb) == 0
    mock_sink.send_batch.assert_not_called()


def test_telemetry_buffer_flush_events_with_sink():
    """Validates flushing buffered events to a mocked sink."""
    mock_sink = MagicMock()
    tb = TelemetryBuffer(sink=mock_sink)

    events = [{"id": 1}, {"id": 2}, {"id": 3}]
    for e in events:
        tb.add_event(e)

    assert len(tb) == 3

    count = tb.flush_events()

    assert count == 3
    assert len(tb) == 0
    mock_sink.send_batch.assert_called_once_with([{"id": 1}, {"id": 2}, {"id": 3}])


def test_telemetry_buffer_auto_flush_on_max_size():
    """Validates auto-flushing when buffer reaches max_size."""
    mock_sink = MagicMock()
    tb = TelemetryBuffer(sink=mock_sink, max_size=3)

    tb.add_event({"id": 1})
    tb.add_event({"id": 2})
    mock_sink.send_batch.assert_not_called()
    assert len(tb) == 2

    tb.add_event({"id": 3})  # Reaches max_size=3 -> auto-flushes!

    mock_sink.send_batch.assert_called_once_with([{"id": 1}, {"id": 2}, {"id": 3}])
    assert len(tb) == 0


def test_telemetry_buffer_flush_without_sink():
    """Validates flush_events safely clears buffer when sink is None."""
    tb = TelemetryBuffer(sink=None)
    tb.add_event("event_1")
    tb.add_event("event_2")

    count = tb.flush_events()

    assert count == 2
    assert len(tb) == 0


def test_telemetry_buffer_flush_with_invalid_sink():
    """Validates flush_events safely handles sink objects missing send_batch."""
    tb = TelemetryBuffer(sink=object())
    tb.add_event("event_1")

    count = tb.flush_events()

    assert count == 1
    assert len(tb) == 0


def test_telemetry_buffer_consecutive_flushes():
    """Validates that consecutive flush_events calls handle empty state properly."""
    mock_sink = MagicMock()
    tb = TelemetryBuffer(sink=mock_sink)
    tb.add_event("e1")

    first_count = tb.flush_events()
    assert first_count == 1
    mock_sink.send_batch.assert_called_once_with(["e1"])

    mock_sink.reset_mock()
    second_count = tb.flush_events()
    assert second_count == 0
    mock_sink.send_batch.assert_not_called()


def test_telemetry_buffer_clear():
    """Validates clearing the buffer without flushing to sink."""
    mock_sink = MagicMock()
    tb = TelemetryBuffer(sink=mock_sink)
    tb.add_event("e1")
    tb.add_event("e2")
    assert len(tb) == 2

    tb.clear()

    assert len(tb) == 0
    mock_sink.send_batch.assert_not_called()
