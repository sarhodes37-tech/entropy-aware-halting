"""
Empirical Performance Benchmark for LocalProvenanceStore Correlation Filtering.

Methodology:
- Constructs a reproducible isolated JSONL log fixture with fixed record count (N=1,000).
- Writes entries with valid incremental hash chaining directly to the fixture file.
- Tests a documented distribution of queries: 80% matching existing correlation IDs
  (with varying frequencies) and 20% non-matching negative controls.
- Runs warm-up iterations to eliminate Python interpreter / file cache cold-start bias.
- Alternates baseline (unfiltered) and optimized execution order across repetitions.
- Measures both implementations against the exact same file and query set.
- Strictly asserts complete output equivalence between implementations before recording timings.
- Measures and reports sample count, total record count, mean, median, and p95 latencies.
"""

import os
import json
import random
import statistics
import tempfile
import time
from pathlib import Path
from typing import List

from epistemicos.provenance import (
    LocalProvenanceStore,
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource,
)


def _unfiltered_scan(log_path: Path, correlation_id: str) -> List[ProvenanceEvent]:
    """Reference baseline: parses every JSON line without literal token pre-filtering."""
    events = []
    if not log_path.exists():
        return events
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                if data.get("correlation_id") == correlation_id:
                    filtered_data = {
                        k: v for k, v in data.items()
                        if k in ProvenanceEvent.__dataclass_fields__
                    }
                    events.append(ProvenanceEvent(**filtered_data))
            except Exception:
                continue
    return events


def generate_benchmark_fixture(
    log_path: str,
    num_records: int = 1000,
    seed: int = 42
) -> List[str]:
    """
    Populates an isolated provenance log file with reproducible records.
    Generates valid chained JSONL records in a single batch to avoid O(N^2)
    per-write health-check overhead during benchmark setup.
    """
    rng = random.Random(seed)
    store = LocalProvenanceStore(log_path=log_path)

    # 100 distinct correlation IDs (avg 10 events each)
    num_distinct_corrs = 100
    corr_pool = [f"corr-bench-{i:04d}" for i in range(num_distinct_corrs)]

    prev_hash = store.genesis_hash
    with open(log_path, "w", encoding="utf-8") as f:
        for idx in range(num_records):
            cid = rng.choice(corr_pool)
            ev = ProvenanceEvent(
                schema_version="1.0.0",
                event_id=f"evt-{idx:06d}",
                event_type=ProvenanceEventType.ACTION_PROPOSED.value,
                provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
                correlation_id=cid,
                request_id=f"req-{idx:06d}",
                action_name="benchmark_op",
                target="/api/v1/resource",
                canonical_request_digest="b3f81e8c49e29a1b0284e3d7491d91a92a3",
                timestamp="2026-11-04T12:00:00Z",
                sequence_number=idx + 1,
                prev_hash=prev_hash,
                outcome={"step": idx, "tag": "bench"}
            )
            event_dict = ev.to_dict()
            entry_hash = store._compute_chain_hash(prev_hash, event_dict)
            event_dict["entry_hash"] = entry_hash
            prev_hash = entry_hash
            f.write(json.dumps(event_dict) + "\n")

    return corr_pool


def main():
    seed = 42
    num_records = 1000
    rng = random.Random(seed)

    with tempfile.TemporaryDirectory() as tmp_dir:
        fixture_path = os.path.join(tmp_dir, "bench_provenance.jsonl")
        print(f"Generating reproducible benchmark fixture ({num_records} records)...")
        corr_pool = generate_benchmark_fixture(fixture_path, num_records=num_records, seed=seed)
        store = LocalProvenanceStore(log_path=fixture_path)

        # Generate query distribution: 80% matching, 20% non-matching (50 total queries)
        num_queries = 50
        num_matching = int(num_queries * 0.8)
        num_negative = num_queries - num_matching

        matching_queries = [rng.choice(corr_pool) for _ in range(num_matching)]
        negative_queries = [f"nonexistent-query-{i}" for i in range(num_negative)]
        query_set = matching_queries + negative_queries
        rng.shuffle(query_set)

        # 1. Warm-up phase (3 queries each)
        for warm_q in query_set[:3]:
            _unfiltered_scan(store.log_path, warm_q)
            store.get_events_for_correlation(warm_q)

        # 2. Strict Equivalence Verification before timing
        for q in query_set:
            ref_out = _unfiltered_scan(store.log_path, q)
            opt_out = store.get_events_for_correlation(q)
            assert ref_out == opt_out, f"Equivalence failure for query {q!r}"

        # 3. Timed Trials with alternating execution order across repetitions
        unfiltered_latencies: List[float] = []
        optimized_latencies: List[float] = []

        for idx, q in enumerate(query_set):
            if idx % 2 == 0:
                # Baseline first
                t0 = time.perf_counter()
                _unfiltered_scan(store.log_path, q)
                t1 = time.perf_counter()
                unfiltered_latencies.append((t1 - t0) * 1000.0)

                t2 = time.perf_counter()
                store.get_events_for_correlation(q)
                t3 = time.perf_counter()
                optimized_latencies.append((t3 - t2) * 1000.0)
            else:
                # Optimized first
                t2 = time.perf_counter()
                store.get_events_for_correlation(q)
                t3 = time.perf_counter()
                optimized_latencies.append((t3 - t2) * 1000.0)

                t0 = time.perf_counter()
                _unfiltered_scan(store.log_path, q)
                t1 = time.perf_counter()
                unfiltered_latencies.append((t1 - t0) * 1000.0)

        # Compute summary statistics
        unfiltered_latencies.sort()
        optimized_latencies.sort()

        unf_mean = statistics.mean(unfiltered_latencies)
        unf_med = statistics.median(unfiltered_latencies)
        unf_p95 = unfiltered_latencies[int(len(unfiltered_latencies) * 0.95)]

        opt_mean = statistics.mean(optimized_latencies)
        opt_med = statistics.median(optimized_latencies)
        opt_p95 = optimized_latencies[int(len(optimized_latencies) * 0.95)]

        speedup_mean = unf_mean / opt_mean if opt_mean > 0 else 0.0
        speedup_med = unf_med / opt_med if opt_med > 0 else 0.0
        speedup_p95 = unf_p95 / opt_p95 if opt_p95 > 0 else 0.0

        print("\n" + "=" * 64)
        print("⚡ BOLT: LocalProvenanceStore Correlation Filtering Benchmark")
        print("=" * 64)
        print(f"Fixture records:        {num_records} JSONL entries")
        print(f"Query distribution:     {num_queries} queries (80% matching, 20% non-matching)")
        print("Output equivalence:     VERIFIED (100% exact match across all queries)")
        print("-" * 64)
        print(
            f"Unfiltered (Baseline):  mean={unf_mean:.2f}ms, med={unf_med:.2f}ms, "
            f"p95={unf_p95:.2f}ms"
        )
        print(
            f"Optimized (Pre-filter): mean={opt_mean:.2f}ms, med={opt_med:.2f}ms, "
            f"p95={opt_p95:.2f}ms"
        )
        print("-" * 64)
        print(
            f"⚡ Speedup:             {speedup_mean:.2f}x (mean), {speedup_med:.2f}x (med), "
            f"{speedup_p95:.2f}x (p95)"
        )
        print("=" * 64 + "\n")


if __name__ == "__main__":
    main()
