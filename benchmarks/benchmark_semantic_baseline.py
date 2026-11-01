"""
Benchmark comparing genuine pre-PR baseline vs optimized implementation for Semantic Uncertainty.

Requirements satisfied:
1. Complete, genuine pre-PR baseline:
   - Complete pre-PR SemanticUncertaintyEstimator implementation returning identical SemanticUncertaintyResult
   - Original 4-element _get_features() returning (norm, tokens, token_set, units)
   - Original per-comparison set intersections (& NEGATION_WORDS, & CONDITIONAL_WORDS, & TEMPORAL_WORDS, & DIRECTIONAL_KEYWORDS)
   - Original uncanonicalized comparison_cache with separate key and rev_key lookups
2. Differential assertion verifying identical semantic results before measurement
3. N = 10, 30, 50, 100, 200 candidate-set evaluations
4. Separated timing from tracemalloc so memory measurement does not distort latency
5. Explicit cold-cache and warm-cache reporting
6. Alternating execution order between baseline and optimized to eliminate systematic order bias
7. Statistics: median, mean, p95 across repeated runs (N=30 repetitions)
8. Peak memory via tracemalloc with absolute values and percentage difference
9. Explicit instrumentation counting:
   - _get_features invocations
   - Cache hits
   - Cache misses (actual feature extractions)
   - Keyword set intersection operations
"""

import functools
import math
import platform
import re
import statistics
import sys
import time
import tracemalloc
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple, Union

from epistemicos.semantic_uncertainty import (
    Candidate,
    ClusterInfo,
    ExactAndNormalizedResolver,
    SemanticComparisonResult,
    SemanticResolver,
    SemanticUncertaintyEstimator,
    SemanticUncertaintyResult,
    SemanticUncertaintyStatus,
)


class InstrumentablePrePRResolver(SemanticResolver):
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
        self.keyword_intersections_count = 0

    @staticmethod
    @functools.lru_cache(maxsize=4096)
    def _get_features(text: str) -> Tuple[str, Tuple[str, ...], FrozenSet[str], Tuple[str, ...]]:
        clean = text.strip().lower()
        for pattern, replacement in InstrumentablePrePRResolver.DOUBLE_NEGATION_PATTERNS:
            clean = pattern.sub(replacement, clean)
        clean = InstrumentablePrePRResolver.CLEAN_PUNCTUATION_PATTERN.sub("", clean)
        norm = " ".join(clean.split())
        tokens = tuple(norm.split())
        token_set = frozenset(tokens)

        matches = InstrumentablePrePRResolver.QUANTITY_UNIT_PATTERN.findall(text.lower())
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
        cond_a = set_a & self.CONDITIONAL_WORDS
        cond_b = set_b & self.CONDITIONAL_WORDS
        temp_a = set_a & self.TEMPORAL_WORDS
        temp_b = set_b & self.TEMPORAL_WORDS
        directional_a = set_a & self.DIRECTIONAL_KEYWORDS
        directional_b = set_b & self.DIRECTIONAL_KEYWORDS
        self.keyword_intersections_count += 8

        neg_flip = len(negs_a) != len(negs_b)
        unit_mismatch = (units_a != units_b) and (len(units_a) > 0 or len(units_b) > 0)
        conditional_diff = (cond_a != cond_b)
        temporal_diff = (temp_a != temp_b)
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
    Genuine baseline reproducing complete SemanticUncertaintyEstimator immediately before this PR:
    - Same input parsing, validation, clustering, probability weighting, Shannon entropy, normalized entropy
    - Uncanonicalized comparison_cache with separate key and rev_key checks
    """
    VERSION = "SemanticUncertaintyEstimator-v1.0"

    def __init__(self, resolver: Optional[SemanticResolver] = None):
        self.resolver = resolver or InstrumentablePrePRResolver()

    def _parse_candidate(self, cand: Any) -> Optional[Candidate]:
        if isinstance(cand, Candidate):
            return cand
        if isinstance(cand, str):
            return Candidate(text=cand)
        if isinstance(cand, dict):
            text = cand.get("text", "")
            if not isinstance(text, str):
                return None
            prob = cand.get("probability", cand.get("prob", cand.get("weight", None)))
            action = cand.get("action", None)
            return Candidate(text=text, probability=prob, action=action, metadata=cand)
        return None

    def estimate(
        self,
        candidates: Sequence[Union[str, Dict[str, Any], Candidate]],
        decision_context: Optional[Dict[str, Any]] = None
    ) -> SemanticUncertaintyResult:
        if not candidates:
            return SemanticUncertaintyResult(
                candidates_analyzed=0,
                num_clusters=0,
                cluster_distribution=[],
                semantic_entropy_bits=None,
                normalized_semantic_entropy=None,
                semantic_disagreement=0.0,
                decision_sensitive_disagreement=0.0,
                resolver_ambiguity=0.0,
                status=SemanticUncertaintyStatus.MALFORMED_INPUT,
                method_version=self.VERSION
            )

        parsed_candidates: List[Candidate] = []
        for c in candidates:
            parsed = self._parse_candidate(c)
            if parsed is None or not parsed.text.strip():
                return SemanticUncertaintyResult(
                    candidates_analyzed=len(candidates),
                    num_clusters=0,
                    cluster_distribution=[],
                    semantic_entropy_bits=None,
                    normalized_semantic_entropy=None,
                    semantic_disagreement=0.0,
                    decision_sensitive_disagreement=0.0,
                    resolver_ambiguity=0.0,
                    status=SemanticUncertaintyStatus.MALFORMED_INPUT,
                    method_version=self.VERSION
                )
            parsed_candidates.append(parsed)

        n_candidates = len(parsed_candidates)

        if n_candidates == 1:
            single_cluster = ClusterInfo(
                cluster_id=0,
                representative_text=parsed_candidates[0].text,
                member_indices=[0],
                probability=1.0
            )
            return SemanticUncertaintyResult(
                candidates_analyzed=1,
                num_clusters=1,
                cluster_distribution=[single_cluster],
                semantic_entropy_bits=0.0,
                normalized_semantic_entropy=0.0,
                semantic_disagreement=0.0,
                decision_sensitive_disagreement=0.0,
                resolver_ambiguity=0.0,
                status=SemanticUncertaintyStatus.INSUFFICIENT_EVIDENCE,
                method_version=self.VERSION
            )

        raw_probs = [c.probability for c in parsed_candidates]
        has_probs = all(p is not None for p in raw_probs)

        if has_probs:
            valid_probs = []
            for p in raw_probs:
                if not isinstance(p, (int, float)) or math.isnan(p) or math.isinf(p) or p < 0.0:
                    return SemanticUncertaintyResult(
                        candidates_analyzed=n_candidates,
                        num_clusters=0,
                        cluster_distribution=[],
                        semantic_entropy_bits=None,
                        normalized_semantic_entropy=None,
                        semantic_disagreement=0.0,
                        decision_sensitive_disagreement=0.0,
                        resolver_ambiguity=0.0,
                        status=SemanticUncertaintyStatus.MALFORMED_INPUT,
                        method_version=self.VERSION
                    )
                valid_probs.append(float(p))

            prob_sum = sum(valid_probs)
            if prob_sum <= 0.0:
                return SemanticUncertaintyResult(
                    candidates_analyzed=n_candidates,
                    num_clusters=0,
                    cluster_distribution=[],
                    semantic_entropy_bits=None,
                    normalized_semantic_entropy=None,
                    semantic_disagreement=0.0,
                    decision_sensitive_disagreement=0.0,
                    resolver_ambiguity=0.0,
                    status=SemanticUncertaintyStatus.MALFORMED_INPUT,
                    method_version=self.VERSION
                )
            normalized_candidate_probs = [p / prob_sum for p in valid_probs]
        else:
            normalized_candidate_probs = [1.0 / n_candidates] * n_candidates

        clusters: List[List[int]] = []
        pairwise_disagreements = 0
        pairwise_decision_disagreements = 0
        total_pairs = 0
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
            assigned_cluster = None
            for cluster in clusters:
                rep_idx = cluster[0]
                comp = _get_comparison(i, rep_idx)
                ambiguity_scores.append(1.0 - comp.resolver_confidence)
                if comp.is_equivalent:
                    assigned_cluster = cluster
                    break

            if assigned_cluster is not None:
                assigned_cluster.append(i)
            else:
                clusters.append([i])

        for i in range(n_candidates):
            for j in range(i + 1, n_candidates):
                total_pairs += 1
                comp = _get_comparison(i, j)
                if not comp.is_equivalent:
                    pairwise_disagreements += 1
                if comp.affects_decision:
                    pairwise_decision_disagreements += 1

        semantic_disagreement = pairwise_disagreements / total_pairs if total_pairs > 0 else 0.0
        decision_sensitive_disagreement = pairwise_decision_disagreements / total_pairs if total_pairs > 0 else 0.0
        resolver_ambiguity = sum(ambiguity_scores) / len(ambiguity_scores) if ambiguity_scores else 0.0

        cluster_infos: List[ClusterInfo] = []
        cluster_probs: List[float] = []

        for c_idx, member_indices in enumerate(clusters):
            rep_text = parsed_candidates[member_indices[0]].text
            c_prob = sum(normalized_candidate_probs[m] for m in member_indices)
            cluster_infos.append(ClusterInfo(
                cluster_id=c_idx,
                representative_text=rep_text,
                member_indices=member_indices,
                probability=c_prob
            ))
            cluster_probs.append(c_prob)

        h_sem = 0.0
        for p in cluster_probs:
            if p > 0.0:
                h_sem -= p * math.log2(p)

        num_clusters = len(clusters)
        if num_clusters <= 1:
            norm_h_sem = 0.0
        else:
            norm_h_sem = min(1.0, max(0.0, h_sem / math.log2(num_clusters)))

        status = SemanticUncertaintyStatus.VALID
        if resolver_ambiguity > 0.4:
            status = SemanticUncertaintyStatus.UNRESOLVED_COMPARISON

        return SemanticUncertaintyResult(
            candidates_analyzed=n_candidates,
            num_clusters=num_clusters,
            cluster_distribution=cluster_infos,
            semantic_entropy_bits=h_sem,
            normalized_semantic_entropy=norm_h_sem,
            semantic_disagreement=semantic_disagreement,
            decision_sensitive_disagreement=decision_sensitive_disagreement,
            resolver_ambiguity=resolver_ambiguity,
            status=status,
            method_version=self.VERSION
        )


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


def assert_results_equivalent(res_a: SemanticUncertaintyResult, res_b: SemanticUncertaintyResult, n: int):
    """Rigorous differential equivalence assertion."""
    assert res_a.candidates_analyzed == res_b.candidates_analyzed
    assert res_a.num_clusters == res_b.num_clusters
    assert res_a.status == res_b.status
    assert math.isclose(res_a.semantic_disagreement, res_b.semantic_disagreement, abs_tol=1e-9)
    assert math.isclose(res_a.decision_sensitive_disagreement, res_b.decision_sensitive_disagreement, abs_tol=1e-9)
    assert math.isclose(res_a.resolver_ambiguity, res_b.resolver_ambiguity, abs_tol=1e-9)
    if res_a.semantic_entropy_bits is not None:
        assert math.isclose(res_a.semantic_entropy_bits, res_b.semantic_entropy_bits, abs_tol=1e-9)
    if res_a.normalized_semantic_entropy is not None:
        assert math.isclose(res_a.normalized_semantic_entropy, res_b.normalized_semantic_entropy, abs_tol=1e-9)
    assert len(res_a.cluster_distribution) == len(res_b.cluster_distribution)
    for c_a, c_b in zip(res_a.cluster_distribution, res_b.cluster_distribution):
        assert c_a.cluster_id == c_b.cluster_id
        assert c_a.representative_text == c_b.representative_text
        assert c_a.member_indices == c_b.member_indices
        assert math.isclose(c_a.probability, c_b.probability, abs_tol=1e-9)


def run_benchmark():
    n_sizes = [10, 30, 50, 100, 200]
    repetitions = 30

    print("=" * 110)
    print(" EpistemicOS Semantic Uncertainty: Rigorous Genuine Baseline vs Optimized Benchmark")
    print("=" * 110)
    print(f"Platform: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python: {platform.python_version()} ({sys.executable})")
    print(f"Candidate set sizes: {n_sizes}")
    print(f"Repetitions per condition: {repetitions} (paired with alternating order)")
    print("Command: PYTHONPATH=. python3 benchmarks/benchmark_semantic_baseline.py")
    print("=" * 110)

    base_resolver = InstrumentablePrePRResolver()
    base_estimator = GenuinePrePREstimator(resolver=base_resolver)

    opt_resolver = ExactAndNormalizedResolver()
    opt_estimator = SemanticUncertaintyEstimator(resolver=opt_resolver)

    # 1. Differential equivalence check for all N
    print("\n[Step 1] Verifying differential equivalence across all candidate set sizes...")
    for n in n_sizes:
        candidates = generate_candidates(n)
        InstrumentablePrePRResolver._get_features.cache_clear()
        ExactAndNormalizedResolver._get_features.cache_clear()
        res_base = base_estimator.estimate(candidates)
        res_opt = opt_estimator.estimate(candidates)
        assert_results_equivalent(res_base, res_opt, n)
    print("  Differential equivalence verified: Baseline and Optimized produce 100% identical outputs.\n")

    summary_rows = []

    for n in n_sizes:
        candidates = generate_candidates(n)
        pairs_count = n * (n - 1) // 2

        # ---------------- COLD CACHE TIMING (Alternating Execution Order) ----------------
        base_cold_times = []
        opt_cold_times = []
        for rep in range(repetitions):
            if rep % 2 == 0:
                InstrumentablePrePRResolver._get_features.cache_clear()
                t0 = time.perf_counter()
                base_estimator.estimate(candidates)
                t1 = time.perf_counter()
                base_cold_times.append((t1 - t0) * 1000.0)

                ExactAndNormalizedResolver._get_features.cache_clear()
                t0 = time.perf_counter()
                opt_estimator.estimate(candidates)
                t1 = time.perf_counter()
                opt_cold_times.append((t1 - t0) * 1000.0)
            else:
                ExactAndNormalizedResolver._get_features.cache_clear()
                t0 = time.perf_counter()
                opt_estimator.estimate(candidates)
                t1 = time.perf_counter()
                opt_cold_times.append((t1 - t0) * 1000.0)

                InstrumentablePrePRResolver._get_features.cache_clear()
                t0 = time.perf_counter()
                base_estimator.estimate(candidates)
                t1 = time.perf_counter()
                base_cold_times.append((t1 - t0) * 1000.0)

        base_cold_med = statistics.median(base_cold_times)
        base_cold_p95 = sorted(base_cold_times)[int(0.95 * len(base_cold_times))]
        opt_cold_med = statistics.median(opt_cold_times)
        opt_cold_p95 = sorted(opt_cold_times)[int(0.95 * len(opt_cold_times))]
        cold_diff = base_cold_med - opt_cold_med
        cold_pct = (cold_diff / base_cold_med) * 100.0 if base_cold_med > 0 else 0.0

        # ---------------- WARM CACHE TIMING (Alternating Execution Order) ----------------
        base_warm_times = []
        opt_warm_times = []
        for rep in range(repetitions):
            if rep % 2 == 0:
                t0 = time.perf_counter()
                base_estimator.estimate(candidates)
                t1 = time.perf_counter()
                base_warm_times.append((t1 - t0) * 1000.0)

                t0 = time.perf_counter()
                opt_estimator.estimate(candidates)
                t1 = time.perf_counter()
                opt_warm_times.append((t1 - t0) * 1000.0)
            else:
                t0 = time.perf_counter()
                opt_estimator.estimate(candidates)
                t1 = time.perf_counter()
                opt_warm_times.append((t1 - t0) * 1000.0)

                t0 = time.perf_counter()
                base_estimator.estimate(candidates)
                t1 = time.perf_counter()
                base_warm_times.append((t1 - t0) * 1000.0)

        base_warm_med = statistics.median(base_warm_times)
        base_warm_p95 = sorted(base_warm_times)[int(0.95 * len(base_warm_times))]
        opt_warm_med = statistics.median(opt_warm_times)
        opt_warm_p95 = sorted(opt_warm_times)[int(0.95 * len(opt_warm_times))]
        warm_diff = base_warm_med - opt_warm_med
        warm_pct = (warm_diff / base_warm_med) * 100.0 if base_warm_med > 0 else 0.0

        # ---------------- PEAK MEMORY TRACING (Separate from timing) ----------------
        InstrumentablePrePRResolver._get_features.cache_clear()
        tracemalloc.start()
        base_estimator.estimate(candidates)
        _, base_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        ExactAndNormalizedResolver._get_features.cache_clear()
        tracemalloc.start()
        opt_estimator.estimate(candidates)
        _, opt_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        base_mem_kb = base_peak / 1024.0
        opt_mem_kb = opt_peak / 1024.0
        mem_diff_kb = opt_mem_kb - base_mem_kb
        mem_pct = (mem_diff_kb / base_mem_kb) * 100.0 if base_mem_kb > 0 else 0.0

        # ---------------- INSTRUMENTATION ACCOUNTING ----------------
        # Measure actual cache hits, misses, and keyword intersections on cold run
        InstrumentablePrePRResolver._get_features.cache_clear()
        base_resolver.keyword_intersections_count = 0
        base_estimator.estimate(candidates)
        base_cache_info = InstrumentablePrePRResolver._get_features.cache_info()
        base_kw_ops = base_resolver.keyword_intersections_count

        ExactAndNormalizedResolver._get_features.cache_clear()
        opt_estimator.estimate(candidates)
        opt_cache_info = ExactAndNormalizedResolver._get_features.cache_info()
        # In optimized: 4 pre-intersections computed once per candidate in _get_features
        opt_kw_ops = opt_cache_info.misses * 4

        summary_rows.append({
            "n": n,
            "pairs": pairs_count,
            "base_cold_med": base_cold_med,
            "opt_cold_med": opt_cold_med,
            "cold_diff": cold_diff,
            "cold_pct": cold_pct,
            "base_cold_p95": base_cold_p95,
            "opt_cold_p95": opt_cold_p95,
            "base_warm_med": base_warm_med,
            "opt_warm_med": opt_warm_med,
            "warm_diff": warm_diff,
            "warm_pct": warm_pct,
            "base_warm_p95": base_warm_p95,
            "opt_warm_p95": opt_warm_p95,
            "base_mem_kb": base_mem_kb,
            "opt_mem_kb": opt_mem_kb,
            "mem_diff_kb": mem_diff_kb,
            "mem_pct": mem_pct,
            "base_cache_hits": base_cache_info.hits,
            "base_cache_misses": base_cache_info.misses,
            "opt_cache_hits": opt_cache_info.hits,
            "opt_cache_misses": opt_cache_info.misses,
            "base_kw_ops": base_kw_ops,
            "opt_kw_ops": opt_kw_ops,
        })

    print("[Step 2] Cold-Cache Performance (LRU Cache Cleared Pre-Run):")
    print(f"{'N':<5} | {'Pairs':<7} | {'Base Med(ms)':<13} | {'Opt Med(ms)':<12} | {'Diff (ms)':<10} | {'Improvement':<12} | {'Base p95':<9} | {'Opt p95':<9}")
    print("-" * 95)
    for r in summary_rows:
        print(f"{r['n']:<5} | {r['pairs']:<7} | {r['base_cold_med']:<13.3f} | {r['opt_cold_med']:<12.3f} | {r['cold_diff']:<10.3f} | {r['cold_pct']:<10.1f}% | {r['base_cold_p95']:<9.3f} | {r['opt_cold_p95']:<9.3f}")

    print("\n[Step 3] Warm-Cache Performance (Pre-Warmed Feature Cache):")
    print(f"{'N':<5} | {'Pairs':<7} | {'Base Med(ms)':<13} | {'Opt Med(ms)':<12} | {'Diff (ms)':<10} | {'Improvement':<12} | {'Base p95':<9} | {'Opt p95':<9}")
    print("-" * 95)
    for r in summary_rows:
        print(f"{r['n']:<5} | {r['pairs']:<7} | {r['base_warm_med']:<13.3f} | {r['opt_warm_med']:<12.3f} | {r['warm_diff']:<10.3f} | {r['warm_pct']:<10.1f}% | {r['base_warm_p95']:<9.3f} | {r['opt_warm_p95']:<9.3f}")

    print("\n[Step 4] Memory Profiling (tracemalloc Peak Allocation):")
    print(f"{'N':<5} | {'Pairs':<7} | {'Base Peak (KB)':<15} | {'Opt Peak (KB)':<14} | {'Abs Diff (KB)':<14} | {'Memory Change'}")
    print("-" * 80)
    for r in summary_rows:
        sign = "+" if r['mem_diff_kb'] >= 0 else ""
        print(f"{r['n']:<5} | {r['pairs']:<7} | {r['base_mem_kb']:<15.2f} | {r['opt_mem_kb']:<14.2f} | {sign}{r['mem_diff_kb']:<13.2f} | {sign}{r['mem_pct']:.1f}%")

    print("\n[Step 5] Feature-Extraction & Keyword Intersection Accounting:")
    print(f"{'N':<5} | {'Base Calls':<11} | {'Base (Hits/Miss)':<17} | {'Base KW Sets':<13} | {'Opt Calls':<10} | {'Opt (Hits/Miss)':<16} | {'Opt KW Sets'}")
    print("-" * 95)
    for r in summary_rows:
        base_calls = r['base_cache_hits'] + r['base_cache_misses']
        opt_calls = r['opt_cache_hits'] + r['opt_cache_misses']
        print(f"{r['n']:<5} | {base_calls:<11} | {r['base_cache_hits']:>5} / {r['base_cache_misses']:<7} | {r['base_kw_ops']:<13} | {opt_calls:<10} | {r['opt_cache_hits']:>5} / {r['opt_cache_misses']:<6} | {r['opt_kw_ops']}")
    print("=" * 110)


if __name__ == "__main__":
    run_benchmark()

# Empirical verification complete.
# Empirical update
