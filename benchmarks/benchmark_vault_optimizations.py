"""
Reproducible Benchmark Harness for LocalMappingVault Optimizations.

Compares reference unoptimized implementation vs. optimized implementation
in the same Python process across:
1. Rehydration workloads:
   - Zero placeholders in text (best-case / common-case for uncontained LLM outputs)
   - Few placeholders in text (realistic workload: 2 placeholders)
   - Varied vault mapping sizes (N = 5, 25, 100 registered placeholders)
   - Varied text lengths (short: ~50 chars, medium: ~300 chars, long: ~2000 chars)
2. Case-Insensitive pseudonym lookup workloads:
   - Hit lookups (matching existing pseudonym with case variation across mapping sizes N = 10, 50, 200)
   - Miss lookups (creating brand-new pseudonyms into clean sessions across mapping sizes N = 10, 50, 200)

Reports:
- Interleaved runs with warm-up
- Summary statistics: Mean, Median, StdDev (µs/op)
- Relative Speedup (Ref / Opt)
"""

import os
import random
import secrets
import statistics
import sys
import threading
import time
from typing import List, Dict, Any, Optional, Set

# Ensure project root is on sys.path so epistemicos package is importable when invoked directly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from epistemicos.shower_curtain.detector import (  # noqa: E402
    SensitivityCategory,
    DetectionResult,
)
from epistemicos.shower_curtain.vault import (  # noqa: E402
    LocalMappingVault,
    _get_placeholder_pattern,
)


class ReferenceLocalMappingVault:
    """
    Self-contained reference implementation of pre-optimization LocalMappingVault.
    - Uses linear scan for case-insensitive lookup.
    - Does not perform literal substring pre-check in rehydrate().
    Kept completely self-contained to avoid importing from test suites.
    """

    def __init__(self, master_key: Optional[bytes] = None):
        self.master_key = master_key or secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._forward_vault: Dict[str, Dict[str, str]] = {}
        self._reverse_vault: Dict[str, Dict[str, str]] = {}
        self._category_counters: Dict[str, Dict[str, int]] = {}

    def _generate_placeholder(
        self, session_id: str, category: SensitivityCategory
    ) -> str:
        if session_id not in self._category_counters:
            self._category_counters[session_id] = {}

        cat_key = category.value
        count = self._category_counters[session_id].get(cat_key, 0) + 1
        self._category_counters[session_id][cat_key] = count

        if category == SensitivityCategory.EMAIL:
            return f"EMAIL_{count}@sanitized.local"
        elif category == SensitivityCategory.NAME:
            return f"PERSON_{count}"
        elif category == SensitivityCategory.PHONE:
            return f"PHONE_NUMBER_{count}"
        elif category == SensitivityCategory.ADDRESS:
            return f"LOCATION_{count}"
        elif category == SensitivityCategory.CUSTOM_ENTITY:
            return f"ENTITY_{count}"
        elif category == SensitivityCategory.FILE_PATH:
            return f"FILE_PATH_{count}"
        elif category == SensitivityCategory.IP_ADDRESS:
            return f"IP_ADDRESS_{count}"
        else:
            return f"PLACEHOLDER_{cat_key}_{count}"

    def get_or_create_pseudonym(
        self, session_id: str, detection: DetectionResult
    ) -> str:
        if detection.category in (
            SensitivityCategory.CREDENTIAL,
            SensitivityCategory.FINANCIAL,
            SensitivityCategory.GOV_ID,
        ):
            raise ValueError(
                f"Category {detection.category.value} cannot be stored in reversible pseudonym vault."
            )

        with self._lock:
            if session_id not in self._forward_vault:
                self._forward_vault[session_id] = {}
                self._reverse_vault[session_id] = {}

            raw_val = detection.value
            for existing_raw, placeholder in self._forward_vault[session_id].items():
                if existing_raw.lower() == raw_val.lower():
                    return placeholder

            placeholder = self._generate_placeholder(session_id, detection.category)
            self._forward_vault[session_id][raw_val] = placeholder
            self._reverse_vault[session_id][placeholder] = raw_val
            return placeholder

    def rehydrate(
        self,
        session_id: str,
        text: str,
        allowed_placeholders: Optional[Set[str]] = None,
    ) -> str:
        with self._lock:
            if not text or session_id not in self._reverse_vault:
                return text
            reverse_map = dict(self._reverse_vault[session_id])

        if not reverse_map:
            return text

        rehydrated = text
        sorted_placeholders = sorted(reverse_map.keys(), key=len, reverse=True)

        for placeholder in sorted_placeholders:
            if (
                allowed_placeholders is not None
                and placeholder not in allowed_placeholders
            ):
                continue

            raw_value = reverse_map[placeholder]
            pattern = _get_placeholder_pattern(placeholder)
            rehydrated = pattern.sub(lambda _: raw_value, rehydrated)

        return rehydrated

    def clear_session(self, session_id: str) -> None:
        with self._lock:
            self._forward_vault.pop(session_id, None)
            self._reverse_vault.pop(session_id, None)
            self._category_counters.pop(session_id, None)


def run_benchmark_trials(
    fn_ref,
    fn_opt,
    rounds: int = 7,
    warmup: int = 2,
    iterations_per_round: int = 1000,
) -> Dict[str, Any]:
    """Runs interleaved warm-up and measured rounds for reference vs optimized."""
    for _ in range(warmup):
        fn_ref(iterations_per_round // 5)
        fn_opt(iterations_per_round // 5)

    ref_times: List[float] = []
    opt_times: List[float] = []

    for _ in range(rounds):
        if random.random() < 0.5:
            t0 = time.perf_counter()
            fn_ref(iterations_per_round)
            ref_times.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            fn_opt(iterations_per_round)
            opt_times.append(time.perf_counter() - t0)
        else:
            t0 = time.perf_counter()
            fn_opt(iterations_per_round)
            opt_times.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            fn_ref(iterations_per_round)
            ref_times.append(time.perf_counter() - t0)

    ref_us = [(t / iterations_per_round) * 1e6 for t in ref_times]
    opt_us = [(t / iterations_per_round) * 1e6 for t in opt_times]

    ref_mean = statistics.mean(ref_us)
    ref_med = statistics.median(ref_us)
    ref_sd = statistics.stdev(ref_us) if len(ref_us) > 1 else 0.0

    opt_mean = statistics.mean(opt_us)
    opt_med = statistics.median(opt_us)
    opt_sd = statistics.stdev(opt_us) if len(opt_us) > 1 else 0.0

    speedup = ref_med / opt_med if opt_med > 0 else float("inf")

    return {
        "ref_raw_us": [round(x, 2) for x in ref_us],
        "opt_raw_us": [round(x, 2) for x in opt_us],
        "ref_mean_us": ref_mean,
        "ref_med_us": ref_med,
        "ref_sd_us": ref_sd,
        "opt_mean_us": opt_mean,
        "opt_med_us": opt_med,
        "opt_sd_us": opt_sd,
        "speedup_median": speedup,
        "latency_delta_pct": (
            ((opt_med - ref_med) / ref_med) * 100.0 if ref_med > 0 else 0.0
        ),
    }


def format_row(condition: str, stats: Dict[str, Any]) -> str:
    """Formats benchmark summary metrics including Mean, Median, and StdDev."""
    ref_str = f"{stats['ref_med_us']:.2f} µs (μ={stats['ref_mean_us']:.2f}±{stats['ref_sd_us']:.2f})"
    opt_str = f"{stats['opt_med_us']:.2f} µs (μ={stats['opt_mean_us']:.2f}±{stats['opt_sd_us']:.2f})"
    return f"{condition:<38} | {ref_str:<26} | {opt_str:<26} | {stats['speedup_median']:>7.2f}x"


def main():
    print("=" * 105)
    print("EpistemicOS LocalMappingVault Microbenchmark Harness")
    print(f"Python: {sys.version.split()[0]} on {sys.platform}")
    print("=" * 105)

    header = f"{'Condition':<38} | {'Reference (Median, Mean±SD)':<26} | {'Optimized (Median, Mean±SD)':<26} | {'Speedup':<8}"

    # -------------------------------------------------------------
    # Workload 1: Rehydration Performance across Mapping Sizes
    # -------------------------------------------------------------
    print("\n[PART 1: Rehydration Fast-Path Performance]")
    print(header)
    print("-" * 105)

    mapping_sizes = [5, 25, 100]
    for n_placeholders in mapping_sizes:
        ref_vault = ReferenceLocalMappingVault()
        opt_vault = LocalMappingVault()
        sid = f"bench_sess_{n_placeholders}"

        for i in range(1, n_placeholders + 1):
            d = DetectionResult(
                category=SensitivityCategory.NAME,
                value=f"OriginalUser_{i}",
                span=(0, 10),
                confidence=1.0,
                detector_type="p",
            )
            ref_vault.get_or_create_pseudonym(sid, d)
            opt_vault.get_or_create_pseudonym(sid, d)

        # Case A: Zero placeholders in text
        text_zero = "The system analyzed the request and found no sensitive information to rehydrate."
        res_zero = run_benchmark_trials(
            lambda iters: [ref_vault.rehydrate(sid, text_zero) for _ in range(iters)],
            lambda iters: [opt_vault.rehydrate(sid, text_zero) for _ in range(iters)],
            iterations_per_round=1000,
        )
        print(format_row(f"N={n_placeholders} (0 placeholders in text)", res_zero))

        # Case B: 2 placeholders in text
        text_two = (
            "Notification sent from PERSON_2 to PERSON_4 regarding project updates."
        )
        res_two = run_benchmark_trials(
            lambda iters: [ref_vault.rehydrate(sid, text_two) for _ in range(iters)],
            lambda iters: [opt_vault.rehydrate(sid, text_two) for _ in range(iters)],
            iterations_per_round=1000,
        )
        print(format_row(f"N={n_placeholders} (2 placeholders in text)", res_two))

    # -------------------------------------------------------------
    # Workload 2: Rehydration Performance across Text Lengths
    # -------------------------------------------------------------
    print("\n[PART 2: Rehydration across Text Lengths (N=25 placeholders in vault)]")
    print(header)
    print("-" * 105)

    sid_len = "bench_len_25"
    ref_vault = ReferenceLocalMappingVault()
    opt_vault = LocalMappingVault()
    for i in range(1, 26):
        d = DetectionResult(
            category=SensitivityCategory.NAME,
            value=f"OriginalUser_{i}",
            span=(0, 10),
            confidence=1.0,
            detector_type="p",
        )
        ref_vault.get_or_create_pseudonym(sid_len, d)
        opt_vault.get_or_create_pseudonym(sid_len, d)

    texts = {
        "Short (~50 chars, 1 placeholder)": (
            "Status update for PERSON_5: Completed successfully."
        ),
        "Medium (~300 chars, 2 placeholders)": (
            "Status report: PERSON_3 submitted the security assessment to PERSON_12 for validation. "
            "All perimeter firewall configurations have been inspected and confirmed compliant with the "
            "baseline security policies established in the architecture documentation."
        ),
        "Long (~2000 chars, 3 placeholders)": (
            (
                "This is a detailed operational telemetry log entry. Everything is stable. "
                * 20
            )
            + "PERSON_1 signed off on the operational envelope. "
            + (
                "Continuing telemetry observation across all connected nodes and endpoints. "
                * 15
            )
            + "PERSON_7 confirmed the migration with PERSON_22."
        ),
    }

    for label, text in texts.items():
        res = run_benchmark_trials(
            lambda iters, t=text: [
                ref_vault.rehydrate(sid_len, t) for _ in range(iters)
            ],
            lambda iters, t=text: [
                opt_vault.rehydrate(sid_len, t) for _ in range(iters)
            ],
            iterations_per_round=1000,
        )
        print(format_row(label, res))

    # -------------------------------------------------------------
    # Workload 3: Case-Insensitive Pseudonym Lookup Performance
    # -------------------------------------------------------------
    print("\n[PART 3: Case-Insensitive Pseudonym Lookup (Hit Workloads)]")
    print(header)
    print("-" * 105)

    for n_items in [10, 50, 200]:
        ref_vault = ReferenceLocalMappingVault()
        opt_vault = LocalMappingVault()
        sid_lookup = f"sess_lookup_{n_items}"

        for i in range(1, n_items + 1):
            d = DetectionResult(
                category=SensitivityCategory.NAME,
                value=f"Employee_{i}",
                span=(0, 10),
                confidence=1.0,
                detector_type="p",
            )
            ref_vault.get_or_create_pseudonym(sid_lookup, d)
            opt_vault.get_or_create_pseudonym(sid_lookup, d)

        # Lookup existing item with case variation (near end of dict to exercise linear search)
        target_name = f"employee_{n_items - 2}"
        d_hit = DetectionResult(
            category=SensitivityCategory.NAME,
            value=target_name,
            span=(0, len(target_name)),
            confidence=1.0,
            detector_type="p",
        )
        res_lookup = run_benchmark_trials(
            lambda iters, d=d_hit: [
                ref_vault.get_or_create_pseudonym(sid_lookup, d) for _ in range(iters)
            ],
            lambda iters, d=d_hit: [
                opt_vault.get_or_create_pseudonym(sid_lookup, d) for _ in range(iters)
            ],
            iterations_per_round=5000,
        )
        print(format_row(f"N={n_items} (Case-variant hit lookup)", res_lookup))

    # -------------------------------------------------------------
    # Workload 4: Miss Lookup Performance (Cold Creation)
    # -------------------------------------------------------------
    print("\n[PART 4: Case-Insensitive Pseudonym Lookup (Miss / New Creation)]")
    print(header)
    print("-" * 105)

    for n_items in [10, 50, 200]:

        def bench_ref_miss(iters: int):
            v = ReferenceLocalMappingVault()
            s = "sess_miss"
            for k in range(n_items):
                v.get_or_create_pseudonym(
                    s,
                    DetectionResult(
                        category=SensitivityCategory.NAME,
                        value=f"Init_{k}",
                        span=(0, 6),
                        confidence=1.0,
                        detector_type="p",
                    ),
                )
            for m in range(iters):
                v.get_or_create_pseudonym(
                    s,
                    DetectionResult(
                        category=SensitivityCategory.NAME,
                        value=f"BrandNewItem_{m}",
                        span=(0, 15),
                        confidence=1.0,
                        detector_type="p",
                    ),
                )

        def bench_opt_miss(iters: int):
            v = LocalMappingVault()
            s = "sess_miss"
            for k in range(n_items):
                v.get_or_create_pseudonym(
                    s,
                    DetectionResult(
                        category=SensitivityCategory.NAME,
                        value=f"Init_{k}",
                        span=(0, 6),
                        confidence=1.0,
                        detector_type="p",
                    ),
                )
            for m in range(iters):
                v.get_or_create_pseudonym(
                    s,
                    DetectionResult(
                        category=SensitivityCategory.NAME,
                        value=f"BrandNewItem_{m}",
                        span=(0, 15),
                        confidence=1.0,
                        detector_type="p",
                    ),
                )

        res_miss = run_benchmark_trials(
            bench_ref_miss,
            bench_opt_miss,
            rounds=7,
            warmup=2,
            iterations_per_round=500,
        )
        print(format_row(f"N={n_items} (Miss lookup / creation)", res_miss))

    print("=" * 105)
    print(
        "Microbenchmark complete. Measurements are isolated to LocalMappingVault operations."
    )
    print("=" * 105)


if __name__ == "__main__":
    main()
