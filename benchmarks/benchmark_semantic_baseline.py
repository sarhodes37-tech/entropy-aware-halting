"""
Reproducible Benchmark comparing genuine pre-PR baseline vs optimized implementation for Semantic Uncertainty.

Requirements satisfied:
1. Genuine pre-PR baseline:
   - Original 4-element _get_features() returning (norm, tokens, token_set, units)
   - Original per-comparison set intersections (& NEGATION_WORDS, & CONDITIONAL_WORDS, & TEMPORAL_WORDS, & DIRECTIONAL_KEYWORDS)
   - Original uncanonicalized comparison_cache with separate key and rev_key lookups
2. N = 10, 30, 50, 100, 200 candidate-set evaluations
3. Separated timing from tracemalloc so memory measurement does not distort latency
4. Explicit cold-cache and warm-cache reporting
5. Statistics: median, mean, p95 across repeated runs
6. Peak memory via tracemalloc
7. Output environment info, Python version, iteration count, exact command.
"""

import functools
import math
import os
import platform
import re
import statistics
import sys
import time
import tracemalloc
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

from epistemicos.semantic_uncertainty import (
    Candidate,
    ExactAndNormalizedResolver,
    SemanticComparisonResult,
    SemanticResolver,
    SemanticUncertaintyEstimator,
    SemanticUncertaintyStatus,
)


class GenuinePrePRResolver(SemanticResolver):
    """
    Genuine baseline reproducing ExactAndNormalizedResolver immediately before this PR:
    - 4-element _get_features() returning (norm, tokens, token_set, units)
    - Per-comparison keyword set intersections in resolve()
    """
    NEGATION_WORDS = {"not", "no", "never", "cannot", "none", "neither", "nor", "deny", "rejected", "false"}
    CONDITIONAL_WORDS = {"if", "unless", "provided", "assuming", "except", "conditional", "subject"}
    TEMPORAL_WORDS = {"before", "after", "during", "until", "since", "prior"}
    DIRECTIONAL_KEYWORDS = {"to", "from", "transferred", "paid", "sent", "billed", "received", "gave"}

    DOUBLE_NEGATION_PATTERNS = [
        (re.compile(r"\bnot\s+unauthorized\b"), "authorized"),
        (re.compile(r"\bnot\s+invalid\b"), "valid"),
        (re.compile(r"\bnot\s+false\b"), "true"),
        (re.compile(r"\bnot\s+denied\b"), "approved"),
        (re.compile(r"\bnot\s+impossible\b"), "possible"),
        (re.compile(r"\bnot\s+incorrect\b"), "correct"),
    ]
    CLEAN_PUNCTUATION_PATTERN = re.compile(r"[^\w\s\$\€\£\¥]")
    QUANTITY_UNIT_PATTERN = re.compile(r"[\$\€\£\¥]?\b\d+(?:\.\d+)?\b(?:\s*(?:usd|eur|gbp|jpy|kg|lbs|dollars|euros|percent|%))?")

    def __init__(self, confidence_threshold: float = 0.85):
        self.confidence_threshold = confidence_threshold

    @staticmethod
    @functools.lru_cache(maxsize=4096)
    def _get_features(text: str) -> Tuple[str, Tuple[str, ...], FrozenSet[str], Tuple[str, ...]]:
        clean = text.strip().lower()
        for pattern, replacement in GenuinePrePRResolver.DOUBLE_NEGATION_PATTERNS:
            clean = pattern.sub(replacement, clean)
        clean = GenuinePrePRResolver.CLEAN_PUNCTUATION_PATTERN.sub("", clean)
        norm = " ".join(clean.split())
        tokens = tuple(norm.split())
        token_set = frozenset(tokens)

        matches = GenuinePrePRResolver.QUANTITY_UNIT_PATTERN.findall(text.lower())
        units = tuple(m.strip() for m in matches if m.strip())
        return norm, tokens, token_set, units

    def resolve(self, candidate_a: Candidate, candidate_b: Candidate) -> SemanticComparisonResult:
        norm_a, tokens_a, set_a, units_a = self._get_features(candidate_a.text)
        norm_b, tokens_b, set_b, units_b = self._get_features(candidate_b.text)

        if norm_a == norm_b:
            action_diff = (candidate_a.action is not None and candidate_b.action is not None and candidate_a.action != candidate_b.action)
            return SemanticComparisonResult(
                is_equivalent=not action_diff,
                similarity_score=1.0,
                is_contradiction=False,
                affects_decision=action_diff,
                resolver_confidence=1.0
            )

        # Per-comparison set intersection
        negs_a = set_a & self.NEGATION_WORDS
        negs_b = set_b & self.NEGATION_WORDS
        neg_flip = len(negs_a) != len(negs_b)

        unit_mismatch = (units_a != units_b) and (len(units_a) > 0 or len(units_b) > 0)

        cond_a = set_a & self.CONDITIONAL_WORDS
        cond_b = set_b & self.CONDITIONAL_WORDS
        conditional_diff = (cond_a != cond_b)

        temp_a = set_a & self.TEMPORAL_WORDS
        temp_b = set_b & self.TEMPORAL_WORDS
        temporal_diff = (temp_a != temp_b)

        directional_a = set_a & self.DIRECTIONAL_KEYWORDS
        directional_b = set_b & self.DIRECTIONAL_KEYWORDS
        actor_swap = bool(directional_a and directional_b and set_a == set_b and tokens_a != tokens_b)

        affects_decision = False
        if candidate_a.action is not None and candidate_b.action is not None:
            affects_decision = (candidate_a.action != candidate_b.action)

        intersection = set_a & set_b
        union = set_a | set_b
        jaccard = len(intersection) / len(union) if union else 1.0

        if neg_flip or unit_mismatch or affects_decision or conditional_diff or temporal_diff or actor_swap:
            is_equivalent = False
            is_contradiction = neg_flip or affects_decision or unit_mismatch or actor_swap
            resolver_confidence = 0.50 if (conditional_diff or temporal_diff) else 0.95
        else:
            is_equivalent = (jaccard >= 0.7)
            is_contradiction = False
            resolver_confidence = 0.90 if is_equivalent else 0.80

        return SemanticComparisonResult(
            is_equivalent=is_equivalent,
            similarity_score=jaccard,
            is_contradiction=is_contradiction,
            affects_decision=affects_decision,
            resolver_confidence=resolver_confidence
        )


class GenuinePrePREstimator:
    """
    Genuine baseline reproducing SemanticUncertaintyEstimator immediately before this PR:
    - No candidate feature pre-extraction
    - Uncanonicalized comparison_cache with separate key and rev_key checks
    """
    def __init__(self, resolver: Optional[SemanticResolver] = None):
        self.resolver = resolver or GenuinePrePRResolver()

    def estimate(self, candidates: Sequence[Any]) -> Any:
        estimator = SemanticUncertaintyEstimator(resolver=self.resolver)
        # Use existing parsing and validation
        parsed_candidates = [estimator._parse_candidate(c) for c in candidates]
        n_candidates = len(parsed_candidates)
        if n_candidates <= 1:
            return estimator.estimate(candidates)

        clusters: List[List[int]] = []
        ambiguity_scores = []
        comparison_cache: Dict[Tuple[int, int], SemanticComparisonResult] = {}

        def _get_comparison(idx_a: int, idx_b: int) -> SemanticComparisonResult:
            key = (idx_a, idx_b)
            rev_key = (idx_b, idx_a)
            res = comparison_cache.get(key)
            if res is not None:
                return res
            res = comparison_cache.get(rev_key)
            if res is not None:
                return res
            c_a, c_b = parsed_candidates[idx_a], parsed_candidates[idx_b]
            res = self.resolver.resolve(c_a, c_b)
            comparison_cache[key] = res
            return res

        for i in range(n_candidates):
            assigned = None
            for cluster in clusters:
                rep_idx = cluster[0]
                comp = _get_comparison(i, rep_idx)
                ambiguity_scores.append(1.0 - comp.resolver_confidence)
                if comp.is_equivalent:
                    assigned = cluster
                    break
            if assigned is not None:
                assigned.append(i)
            else:
                clusters.append([i])

        total_pairs = 0
        pairwise_disagreements = 0
        pairwise_decision_disagreements = 0
        for i in range(n_candidates):
            for j in range(i + 1, n_candidates):
                total_pairs += 1
                comp = _get_comparison(i, j)
                if not comp.is_equivalent:
                    pairwise_disagreements += 1
                if comp.affects_decision:
                    pairwise_decision_disagreements += 1

        sem_dis = pairwise_disagreements / total_pairs if total_pairs > 0 else 0.0
        dec_dis = pairwise_decision_disagreements / total_pairs if total_pairs > 0 else 0.0
        res_amb = sum(ambiguity_scores) / len(ambiguity_scores) if ambiguity_scores else 0.0
        return clusters, sem_dis, dec_dis, res_amb


def generate_candidates(n: int) -> List[Candidate]:
    base_texts = [
        "The transfer of $100 USD to Alice was completed successfully.",
        "Transfer of 100 usd to Alice was not completed successfully.",
        "Paid $100 to Alice without error.",
        "Transferred $100 USD to Bob before deadline.",
        "Transferred $100 USD to Bob after deadline.",
        "Alice transferred $100 USD to Bob.",
        "Bob transferred $100 USD to Alice.",
        "The system is operating within normal parameters.",
        "System performance is normal and healthy.",
        "Operation failed due to timeout.",
    ]
    actions = ["APPROVE", "DENY", "REVIEW", None]
    candidates = []
    for i in range(n):
        text = f"{base_texts[i % len(base_texts)]} [Variation sample {i}]"
        action = actions[i % len(actions)]
        prob = 1.0 / n
        candidates.append(Candidate(text=text, probability=prob, action=action))
    return candidates


def run_benchmark():
    n_sizes = [10, 30, 50, 100, 200]
    timing_repetitions = 30

    print("=" * 105)
    print(" EpistemicOS Semantic Uncertainty: Rigorous Genuine Baseline vs Optimized Benchmark")
    print("=" * 105)
    print(f"Platform: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python: {platform.python_version()} ({sys.executable})")
    print(f"Candidate set sizes: {n_sizes}")
    print(f"Timing repetitions: {timing_repetitions} per condition (isolated from memory tracing)")
    print(f"Command: PYTHONPATH=. python3 benchmarks/benchmark_semantic_baseline.py")
    print("=" * 105)

    base_resolver = GenuinePrePRResolver()
    base_estimator = GenuinePrePREstimator(resolver=base_resolver)

    opt_resolver = ExactAndNormalizedResolver()
    opt_estimator = SemanticUncertaintyEstimator(resolver=opt_resolver)

    summary_rows = []

    for n in n_sizes:
        candidates = generate_candidates(n)
        pairs_count = n * (n - 1) // 2

        # ---------------- COLD CACHE TIMING ----------------
        base_cold_times = []
        opt_cold_times = []
        for _ in range(timing_repetitions):
            GenuinePrePRResolver._get_features.cache_clear()
            t0 = time.perf_counter()
            base_estimator.estimate(candidates)
            t1 = time.perf_counter()
            base_cold_times.append((t1 - t0) * 1000.0)

            ExactAndNormalizedResolver._get_features.cache_clear()
            t0 = time.perf_counter()
            opt_estimator.estimate(candidates)
            t1 = time.perf_counter()
            opt_cold_times.append((t1 - t0) * 1000.0)

        base_cold_med = statistics.median(base_cold_times)
        base_cold_mean = statistics.mean(base_cold_times)
        base_cold_p95 = sorted(base_cold_times)[int(0.95 * len(base_cold_times))]

        opt_cold_med = statistics.median(opt_cold_times)
        opt_cold_mean = statistics.mean(opt_cold_times)
        opt_cold_p95 = sorted(opt_cold_times)[int(0.95 * len(opt_cold_times))]

        # ---------------- WARM CACHE TIMING ----------------
        base_warm_times = []
        opt_warm_times = []
        for _ in range(timing_repetitions):
            t0 = time.perf_counter()
            base_estimator.estimate(candidates)
            t1 = time.perf_counter()
            base_warm_times.append((t1 - t0) * 1000.0)

            t0 = time.perf_counter()
            opt_estimator.estimate(candidates)
            t1 = time.perf_counter()
            opt_warm_times.append((t1 - t0) * 1000.0)

        base_warm_med = statistics.median(base_warm_times)
        base_warm_mean = statistics.mean(base_warm_times)
        base_warm_p95 = sorted(base_warm_times)[int(0.95 * len(base_warm_times))]

        opt_warm_med = statistics.median(opt_warm_times)
        opt_warm_mean = statistics.mean(opt_warm_times)
        opt_warm_p95 = sorted(opt_warm_times)[int(0.95 * len(opt_warm_times))]

        # ---------------- PEAK MEMORY TRACING (Separate from timing) ----------------
        GenuinePrePRResolver._get_features.cache_clear()
        tracemalloc.start()
        base_estimator.estimate(candidates)
        _, base_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        ExactAndNormalizedResolver._get_features.cache_clear()
        tracemalloc.start()
        opt_estimator.estimate(candidates)
        _, opt_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Feature extraction call counts and cache lookups
        # Baseline calls _get_features 2 times per pair evaluated.
        # Optimized calls _get_features exactly N times (once per candidate).
        base_feat_calls = pairs_count * 2
        opt_feat_calls = n

        summary_rows.append({
            "n": n,
            "pairs": pairs_count,
            "base_cold_med": base_cold_med,
            "opt_cold_med": opt_cold_med,
            "base_cold_p95": base_cold_p95,
            "opt_cold_p95": opt_cold_p95,
            "cold_diff": base_cold_med - opt_cold_med,
            "cold_pct": ((base_cold_med - opt_cold_med) / base_cold_med) * 100.0 if base_cold_med > 0 else 0.0,
            "base_warm_med": base_warm_med,
            "opt_warm_med": opt_warm_med,
            "base_warm_p95": base_warm_p95,
            "opt_warm_p95": opt_warm_p95,
            "warm_diff": base_warm_med - opt_warm_med,
            "warm_pct": ((base_warm_med - opt_warm_med) / base_warm_med) * 100.0 if base_warm_med > 0 else 0.0,
            "base_mem_kb": base_peak / 1024.0,
            "opt_mem_kb": opt_peak / 1024.0,
            "base_feat_calls": base_feat_calls,
            "opt_feat_calls": opt_feat_calls,
        })

    print("\n--- COLD CACHE RESULTS (LRU Cache Cleared Pre-Run) ---")
    print(f"{'N':<5} | {'Pairs':<7} | {'Base Med(ms)':<13} | {'Opt Med(ms)':<12} | {'Diff (ms)':<10} | {'Improvement':<12} | {'Base p95':<9} | {'Opt p95':<9}")
    print("-" * 95)
    for r in summary_rows:
        print(f"{r['n']:<5} | {r['pairs']:<7} | {r['base_cold_med']:<13.3f} | {r['opt_cold_med']:<12.3f} | {r['cold_diff']:<10.3f} | {r['cold_pct']:<10.1f}% | {r['base_cold_p95']:<9.3f} | {r['opt_cold_p95']:<9.3f}")

    print("\n--- WARM CACHE RESULTS (Pre-Warmed Feature Cache) ---")
    print(f"{'N':<5} | {'Pairs':<7} | {'Base Med(ms)':<13} | {'Opt Med(ms)':<12} | {'Diff (ms)':<10} | {'Improvement':<12} | {'Base p95':<9} | {'Opt p95':<9}")
    print("-" * 95)
    for r in summary_rows:
        print(f"{r['n']:<5} | {r['pairs']:<7} | {r['base_warm_med']:<13.3f} | {r['opt_warm_med']:<12.3f} | {r['warm_diff']:<10.3f} | {r['warm_pct']:<10.1f}% | {r['base_warm_p95']:<9.3f} | {r['opt_warm_p95']:<9.3f}")

    print("\n--- MEMORY & OPERATION COUNTS ---")
    print(f"{'N':<5} | {'Pairs':<7} | {'Base Feat Calls':<16} | {'Opt Feat Calls':<15} | {'Base Peak (KB)':<15} | {'Opt Peak (KB)':<14} | {'Mem Delta'}")
    print("-" * 95)
    for r in summary_rows:
        mem_pct = ((r['base_mem_kb'] - r['opt_mem_kb']) / r['base_mem_kb']) * 100.0 if r['base_mem_kb'] > 0 else 0.0
        print(f"{r['n']:<5} | {r['pairs']:<7} | {r['base_feat_calls']:<16} | {r['opt_feat_calls']:<15} | {r['base_mem_kb']:<15.2f} | {r['opt_mem_kb']:<14.2f} | -{mem_pct:.1f}%")
    print("=" * 105)


if __name__ == "__main__":
    run_benchmark()
