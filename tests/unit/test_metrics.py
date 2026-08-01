"""
Unit test suite for epistemicos.metrics module.
Validates AST analysis, positive entropy differentials, trigram repetition ratios,
AST persistence streaks, and Structural Risk Index calculations.
"""

import pytest
from epistemicos.metrics import (
    ASTAnalyzer,
    calculate_entropy_differential,
    calculate_rolling_entropy,
    calculate_trigram_repetition,
    calculate_ast_persistence,
    calculate_structural_risk_index,
)


def test_ast_analyzer_valid_and_invalid():
    analyzer = ASTAnalyzer()

    valid_code = "def add(a, b):\n    return a + b"
    invalid_code = "def add(a, b"

    assert analyzer.passes_static_ast(valid_code) is True
    assert analyzer.passes_static_ast(invalid_code) is False

    assert analyzer.count_ast_nodes(valid_code) > 0
    assert analyzer.count_ast_nodes(invalid_code) == 0


def test_ast_node_weights_and_aggregate_risk():
    analyzer = ASTAnalyzer()

    assert analyzer.get_node_weight("Call") == 6.17
    assert analyzer.get_node_weight("ast.Call") == 6.17
    assert analyzer.get_node_weight("UnknownNode") == 1.0

    code = "x = 10\nreturn x"
    risk = analyzer.compute_aggregate_ast_risk(code)
    assert risk > 0.0


def test_entropy_differential_positive_lock():
    # Surge in entropy
    assert calculate_entropy_differential(3.5, 1.5) == 2.0

    # Drop in entropy should lock at 0.0
    assert calculate_entropy_differential(1.0, 2.5) == 0.0

    # First token step
    assert calculate_entropy_differential(2.0, None) == 0.0


def test_trigram_repetition():
    repetitive_text = "foo bar baz foo bar baz foo bar baz"
    unique_text = "the quick brown fox jumps over the lazy dog"

    assert calculate_trigram_repetition(repetitive_text) > 0.5
    assert calculate_trigram_repetition(unique_text) == 0.0


def test_ast_persistence_streak():
    history = [True, False, True, True, True]
    assert calculate_ast_persistence(history) == 3

    history_failed = [True, True, False]
    assert calculate_ast_persistence(history_failed) == 0


def test_structural_risk_index():
    # dH_pos = 1.5, omega = 6.17, dA = 4 -> 1.5 * 6.17 * 4 = 37.02
    sri = calculate_structural_risk_index(dH_pos=1.5, omega=6.17, dA=4)
    assert sri == 37.02
