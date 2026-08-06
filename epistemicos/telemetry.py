"""
EpistemicOS Unified Telemetry & Observability Layer.

Consolidates hardware profiling (VRAM, CUDA latency) with structural risk 
metrics (AST analysis, entropy velocity, trigram repetition) to provide 
a single source of truth for system monitoring.
"""

import ast
import time
import logging
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger("EpistemicOS.Telemetry")

# Defensive lazy-loading to maintain zero-dependency core
try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

# ==========================================
# HARDWARE PROFILING & VRAM TELEMETRY
# ==========================================

@dataclass
class HardwareTelemetry:
    wall_clock_ms: float
    cuda_time_ms: float
    vram_allocated_mb: float
    vram_reserved_mb: float
    vram_peak_mb: float
    fragmentation_index: float  # (Reserved - Allocated) / Reserved
    tokens_processed: int
    ms_per_token: float


class ResourceProfiler:
    """
    Context manager for high-precision hardware profiling.
    Safely degrades to standard time.perf_counter() if running on CPU
    or if PyTorch is not installed in the current environment.
    """

    def __init__(self, device: str = "cuda", token_count: int = 0):
        self.device = device
        self.token_count = max(1, token_count)

        # Failsafe hardware detection
        self.use_cuda = HAS_TORCH and "cuda" in self.device and torch.cuda.is_available()

        if self.use_cuda:
            self.start_event = torch.cuda.Event(enable_timing=True)
            self.end_event = torch.cuda.Event(enable_timing=True)
            
    def __enter__(self):
        self.start_wall = time.perf_counter()

        if self.use_cuda:
            torch.cuda.reset_peak_memory_stats()
            self.start_event.record()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.use_cuda:
            self.end_event.record()
            torch.cuda.synchronize() # Wait for GPU to finish execution
            self.cuda_time_ms = self.start_event.elapsed_time(self.end_event)
        else:
            self.cuda_time_ms = 0.0

        self.end_wall = time.perf_counter()
        self.wall_clock_ms = (self.end_wall - self.start_wall) * 1000.0

    def get_telemetry(self) -> HardwareTelemetry:
        """Calculates and returns memory and latency telemetry."""
        alloc_mb = 0.0
        res_mb = 0.0
        peak_mb = 0.0
        frag_index = 0.0

        if self.use_cuda:
            alloc_mb = torch.cuda.memory_allocated() / (1024 ** 2)
            res_mb = torch.cuda.memory_reserved() / (1024 ** 2)
            peak_mb = torch.cuda.max_memory_allocated() / (1024 ** 2)

            # High fragmentation (> 0.3) indicates KV-cache is physically scattered 
            # and highly vulnerable to OOM during dynamic rollbacks
            if res_mb > 0:
                frag_index = (res_mb - alloc_mb) / res_mb

        # Safely extract timings with fallbacks in case the pipeline halts before __exit__
        safe_wall_clock = getattr(self, "wall_clock_ms", 0.0)
        safe_cuda_time = getattr(self, "cuda_time_ms", 0.0)

        # Default to wall clock if CUDA timing isn't available
        effective_time = safe_cuda_time if self.use_cuda else safe_wall_clock

        return HardwareTelemetry(
            wall_clock_ms=round(safe_wall_clock, 2),
            cuda_time_ms=round(safe_cuda_time, 2),
            vram_allocated_mb=round(alloc_mb, 2),
            vram_reserved_mb=round(res_mb, 2),
            vram_peak_mb=round(peak_mb, 2),
            fragmentation_index=round(frag_index, 4),
            tokens_processed=self.token_count,
            ms_per_token=round(effective_time / self.token_count, 2)
        )


# ==========================================
# STRUCTURAL RISK & AST ANALYSIS
# ==========================================

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


# ==========================================
# ENTROPY VELOCITY & DEGRADATION METRICS
# ==========================================

def calculate_entropy_differential(current_entropy: float, prev_entropy: Optional[float]) -> float:
    """
    Computes positive entropy differential (dH = max(0, H_t - H_{t-1})).
    Ignores negative drops to focus exclusively on uncertainty surges.
    """
    if prev_entropy is None:
        return 0.0
    return max(0.0, current_entropy - prev_entropy)


def calculate_rolling_entropy(entropy_history: List[float], window_size: int = 5) -> float:
    """Calculates smoothed rolling mean entropy over recent token history using standard library math."""
    if not entropy_history:
        return 0.0
    window = entropy_history[-window_size:]
    return round(sum(window) / len(window), 4)


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
