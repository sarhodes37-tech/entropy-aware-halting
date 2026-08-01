"""
EpistemicOS Metrics Telemetry Engine.
Provides AST syntax analysis, token entropy differentials, trigram repetition metrics,
and Structural Risk Index (SRI) calculations.
"""

import ast
from collections import Counter
from typing import Dict, List, Optional
import numpy as np


class ASTAnalyzer:
    """Handles Abstract Syntax Tree parsing, node counting, and weight mapping."""

    # Empirically derived Omega weights from mutation sweeps
    DEFAULT_OMEGA_MAP = {
        "Assign": 1.0,
        "Return": 1.52,
        "For": 3.53,
        "Compare": 4.83,
        "Call": 6.17,
        "ast.Assign": 1.0,
        "ast.Return": 1.52,
        "ast.For": 3.53,
        "ast.Compare": 4.83,
        "ast.Call": 6.17,
    }

    def __init__(self, omega_map: Optional[Dict[str, float]] = None):
        self.omega_map = omega_map or self.DEFAULT_OMEGA_MAP

    @staticmethod
    def passes_static_ast(code_str: str) -> bool:
        """Checks if a string parses into a valid, non-empty AST tree."""
        try:
            tree = ast.parse(code_str)
            return len(tree.body) > 0
        except SyntaxError:
            return False

    @staticmethod
    def count_ast_nodes(code_str: str) -> int:
        """Counts total AST nodes in the code snippet."""
        try:
            tree = ast.parse(code_str)
            return sum(1 for _ in ast.walk(tree))
        except SyntaxError:
            return 0

    def get_node_weight(self, node_type_str: str) -> float:
        """Retrieves empirical risk weight (Omega) for a given AST node type."""
        clean_key = node_type_str.split(".")[-1]
        return self.omega_map.get(node_type_str, self.omega_map.get(clean_key, 1.0))

    def compute_aggregate_ast_risk(self, code_str: str) -> float:
        """Computes total summed Omega weight across all AST nodes in snippet."""
        try:
            tree = ast.parse(code_str)
            total_weight = 0.0
            for node in ast.walk(tree):
                node_type = type(node).__name__
                total_weight += self.get_node_weight(node_type)
            return round(total_weight, 4)
        except SyntaxError:
            return 0.0


def calculate_entropy_differential(current_entropy: float, prev_entropy: Optional[float]) -> float:
    """
    Computes positive entropy differential (dH = max(0, H_t - H_{t-1})).
    Ignores negative drops to focus exclusively on uncertainty surges.
    """
    if prev_entropy is None:
        return 0.0
    return max(0.0, current_entropy - prev_entropy)


def calculate_rolling_entropy(entropy_history: List[float], window_size: int = 5) -> float:
    """Calculates smoothed rolling mean entropy over recent token history."""
    if not entropy_history:
        return 0.0
    window = entropy_history[-window_size:]
    return round(float(np.mean(window)), 4)


def calculate_trigram_repetition(text: str) -> float:
    """
    Computes trigram repetition ratio to detect repetitive generation loops or degradation.
    """
    tokens = text.split()
    if len(tokens) < 3:
        return 0.0
    trigrams = [tuple(tokens[i : i + 3]) for i in range(len(tokens) - 2)]
    counts = Counter(trigrams)
    repeated = sum(c - 1 for c in counts.values() if c > 1)
    return round(repeated / len(trigrams), 4)


def calculate_ast_persistence(ast_valid_history: List[bool]) -> int:
    """
    Counts consecutive AST-valid steps leading up to the current token index.
    """
    streak = 0
    for is_valid in reversed(ast_valid_history):
        if is_valid:
            streak += 1
        else:
            break
    return streak


def calculate_structural_risk_index(dH_pos: float, omega: float, dA: int) -> float:
    """
    Calculates instantaneous Structural Risk Index (SRI = max(0, dH) * Omega * dA).
    Couples entropy velocity with structural expansion velocity.
    """
    sri = max(0.0, dH_pos) * omega * float(dA)
    return round(sri, 4)
