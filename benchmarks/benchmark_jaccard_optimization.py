"""
Microbenchmark: Jaccard Similarity Optimization (Union-Free vs Explicit Union).

Evaluates the performance impact of eliminating intermediate set union allocations:
    Original:
        intersection = set_a & set_b
        union = set_a | set_b
        jaccard = len(intersection) / len(union) if union else 1.0

    Optimized:
        inter_len = len(set_a & set_b)
        union_len = len(set_a) + len(set_b) - inter_len
        jaccard = inter_len / union_len if union_len else 1.0

Measures:
1. Isolated Jaccard computation across representative token sets.
2. End-to-end pairwise _resolve_with_features comparisons across candidates.
"""

import random
import statistics
import time
from typing import List, Set, Tuple

from epistemicos.semantic_uncertainty import (
    Candidate,
    ExactAndNormalizedResolver,
    SemanticComparisonResult,
)


def baseline_jaccard(set_a: Set[str], set_b: Set[str]) -> float:
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union) if union else 1.0


def optimized_jaccard(set_a: Set[str], set_b: Set[str]) -> float:
    inter_len = len(set_a & set_b)
    union_len = len(set_a) + len(set_b) - inter_len
    return inter_len / union_len if union_len else 1.0


def resolve_with_features_baseline(
    candidate_a: Candidate,
    candidate_b: Candidate,
    feat_a: Tuple,
    feat_b: Tuple
) -> SemanticComparisonResult:
    norm_a, tokens_a, set_a, units_a, negs_a, cond_a, temp_a, directional_a = feat_a
    norm_b, tokens_b, set_b, units_b, negs_b, cond_b, temp_b, directional_b = feat_b

    if norm_a == norm_b:
        action_diff = (candidate_a.action is not None and candidate_b.action is not None and candidate_a.action != candidate_b.action)
        return SemanticComparisonResult(
            is_equivalent=not action_diff,
            similarity_score=1.0,
            is_contradiction=False,
            affects_decision=action_diff,
            resolver_confidence=1.0
        )

    neg_flip = len(negs_a) != len(negs_b)
    unit_mismatch = (units_a != units_b) and (len(units_a) > 0 or len(units_b) > 0)
    conditional_diff = (cond_a != cond_b)
    temporal_diff = (temp_a != temp_b)
    actor_swap = bool(directional_a and directional_b and set_a == set_b and tokens_a != tokens_b)

    affects_decision = False
    if candidate_a.action is not None and candidate_b.action is not None:
        affects_decision = (candidate_a.action != candidate_b.action)

    # Baseline: explicit union set allocation
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


def run_benchmarks():
    print("=" * 70)
    print("⚡ BOLT BENCHMARK: Jaccard Similarity Optimization")
    print("=" * 70)

    # 1. Isolated Jaccard Kernel Microbenchmark
    vocab = [f"tok_{i}" for i in range(300)]
    random.seed(42)
    pairs: List[Tuple[Set[str], Set[str]]] = []
    for _ in range(1000):
        s_a = set(random.sample(vocab, random.randint(5, 30)))
        s_b = set(random.sample(vocab, random.randint(5, 30)))
        pairs.append((s_a, s_b))

    # Warmup
    for s_a, s_b in pairs:
        assert baseline_jaccard(s_a, s_b) == optimized_jaccard(s_a, s_b)

    n_trials = 30
    n_loops = 500

    base_times = []
    opt_times = []

    for _ in range(n_trials):
        # Baseline
        t0 = time.perf_counter()
        for _ in range(n_loops):
            for s_a, s_b in pairs:
                baseline_jaccard(s_a, s_b)
        t_base = time.perf_counter() - t0
        base_times.append(t_base)

        # Optimized
        t0 = time.perf_counter()
        for _ in range(n_loops):
            for s_a, s_b in pairs:
                optimized_jaccard(s_a, s_b)
        t_opt = time.perf_counter() - t0
        opt_times.append(t_opt)

    base_med = statistics.median(base_times)
    opt_med = statistics.median(opt_times)
    speedup = base_med / opt_med
    reduction = (1.0 - (opt_med / base_med)) * 100

    per_op_base_us = (base_med / (n_loops * len(pairs))) * 1e6
    per_op_opt_us = (opt_med / (n_loops * len(pairs))) * 1e6

    print("\n--- Part 1: Isolated Jaccard Kernel (1,000 token-set pairs, 500 loops x 30 trials) ---")
    print(f"  Baseline (median):  {base_med:.4f}s ({per_op_base_us:.3f} µs per op)")
    print(f"  Optimized (median): {opt_med:.4f}s ({per_op_opt_us:.3f} µs per op)")
    print(f"  Speedup:            {speedup:.2f}x ({reduction:.1f}% latency reduction)")

    # 2. End-to-end Candidate Pairwise Comparison Microbenchmark
    resolver = ExactAndNormalizedResolver()
    candidates = []
    for i in range(50):
        text = " ".join(random.sample(vocab, random.randint(5, 20)))
        candidates.append(Candidate(text=text))

    feats = [resolver._get_features(c.text) for c in candidates]
    cand_pairs = [(i, j) for i in range(len(candidates)) for j in range(i + 1, len(candidates))]

    # Verify identical output
    for i, j in cand_pairs:
        r_base = resolve_with_features_baseline(candidates[i], candidates[j], feats[i], feats[j])
        r_opt = resolver._resolve_with_features(candidates[i], candidates[j], feats[i], feats[j])
        assert r_base == r_opt

    base_res_times = []
    opt_res_times = []
    res_loops = 200

    for _ in range(n_trials):
        t0 = time.perf_counter()
        for _ in range(res_loops):
            for i, j in cand_pairs:
                resolve_with_features_baseline(candidates[i], candidates[j], feats[i], feats[j])
        t_base = time.perf_counter() - t0
        base_res_times.append(t_base)

        t0 = time.perf_counter()
        for _ in range(res_loops):
            for i, j in cand_pairs:
                resolver._resolve_with_features(candidates[i], candidates[j], feats[i], feats[j])
        t_opt = time.perf_counter() - t0
        opt_res_times.append(t_opt)

    base_res_med = statistics.median(base_res_times)
    opt_res_med = statistics.median(opt_res_times)
    res_speedup = base_res_med / opt_res_med
    res_reduction = (1.0 - (opt_res_med / base_res_med)) * 100

    per_comp_base_us = (base_res_med / (res_loops * len(cand_pairs))) * 1e6
    per_comp_opt_us = (opt_res_med / (res_loops * len(cand_pairs))) * 1e6

    print(f"\n--- Part 2: _resolve_with_features() ({len(cand_pairs)} candidate pairs, 200 loops x 30 trials) ---")
    print(f"  Baseline (median):  {base_res_med:.4f}s ({per_comp_base_us:.3f} µs per comparison)")
    print(f"  Optimized (median): {opt_res_med:.4f}s ({per_comp_opt_us:.3f} µs per comparison)")
    print(f"  Speedup:            {res_speedup:.2f}x ({res_reduction:.1f}% latency reduction)")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    run_benchmarks()
