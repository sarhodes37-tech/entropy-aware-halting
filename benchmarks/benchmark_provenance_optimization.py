"""
Empirical Performance Benchmark for LocalProvenanceStore Correlation Filtering.

Compares query execution time between unguided line-by-line JSON parsing
and literal substring pre-filtered scanning over realistic provenance log files.
"""

import time
import json
import statistics
from pathlib import Path
from epistemicos.provenance import LocalProvenanceStore, ProvenanceEvent


def _unfiltered_scan(log_path: Path, correlation_id: str):
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


def main():
    store = LocalProvenanceStore()
    if not store.log_path.exists():
        print(f"Log path {store.log_path} does not exist.")
        return

    # Extract sample correlation IDs
    corr_ids = []
    with open(store.log_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                d = json.loads(line)
                cid = d.get("correlation_id")
                if cid and cid != "[REDACTED]":
                    corr_ids.append(cid)
            except Exception:
                pass

    total_lines = len(corr_ids)
    print(f"Log file: {store.log_path} ({total_lines} entries)")

    # Sample last 50 correlation IDs
    sample_corrs = corr_ids[-50:] if len(corr_ids) >= 50 else corr_ids

    # 1. Benchmark Unfiltered Scan
    unfiltered_times = []
    for cid in sample_corrs:
        t0 = time.perf_counter()
        _unfiltered_scan(store.log_path, cid)
        t1 = time.perf_counter()
        unfiltered_times.append((t1 - t0) * 1000.0)

    # 2. Benchmark Optimized Substring Pre-filter
    optimized_times = []
    for cid in sample_corrs:
        t0 = time.perf_counter()
        store.get_events_for_correlation(cid)
        t1 = time.perf_counter()
        optimized_times.append((t1 - t0) * 1000.0)

    unfiltered_mean = statistics.mean(unfiltered_times)
    unfiltered_median = statistics.median(unfiltered_times)
    optimized_mean = statistics.mean(optimized_times)
    optimized_median = statistics.median(optimized_times)

    speedup_mean = unfiltered_mean / optimized_mean if optimized_mean > 0 else 0.0
    speedup_median = unfiltered_median / optimized_median if optimized_median > 0 else 0.0

    print("==========================================================")
    print("⚡ BOLT: LocalProvenanceStore Correlation Filtering Benchmark")
    print("==========================================================")
    print(f"Samples evaluated: {len(sample_corrs)}")
    print(f"Unfiltered Scan:   mean={unfiltered_mean:.2f}ms, median={unfiltered_median:.2f}ms")
    print(f"Optimized Filter:  mean={optimized_mean:.2f}ms, median={optimized_median:.2f}ms")
    print(f"Speedup:           {speedup_mean:.2f}x (mean), {speedup_median:.2f}x (median)")
    print("==========================================================")


if __name__ == "__main__":
    main()
