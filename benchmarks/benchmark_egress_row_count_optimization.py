"""
Microbenchmark: PermissionScope.validate_egress & _estimate_payload_size Optimization
Measures the performance impact of early-exit DFS row-count and payload byte validation
compared to exhaustive full-tree baseline scanning.
"""

import timeit
from typing import Any
from epistemicos.models import PermissionScope, _estimate_payload_size


def baseline_validate_egress(max_payload_bytes: int, max_row_count: int, response_payload: Any) -> bool:
    """Baseline implementation executing exhaustive size estimation and record counting."""
    if _estimate_payload_size(response_payload) > max_payload_bytes:
        return False

    def count_max_records(data: Any) -> int:
        max_records = 0
        stack = [data]
        while stack:
            current = stack.pop()
            if isinstance(current, list):
                if len(current) > max_records:
                    max_records = len(current)
                stack.extend(current)
            elif isinstance(current, dict):
                if len(current) > max_records:
                    max_records = len(current)
                stack.extend(current.values())
        return max_records

    return count_max_records(response_payload) <= max_row_count


def run_benchmarks():
    print("=" * 75)
    print("⚡ BOLT BENCHMARK: PermissionScope.validate_egress Short-Circuit Optimization")
    print("=" * 75)

    # Scenario 1: Payload exceeding max_payload_bytes (500 items with long strings, limit 4KB)
    payload_huge_bytes = [{"data": "x" * 1000} for _ in range(500)]
    scope_huge_bytes = PermissionScope(max_payload_bytes=4096, max_row_count=1000)

    # Scenario 2: Top-level collection exceeding max_row_count (500 items, small records, limit 50)
    payload_top_rows = [{"id": i} for i in range(500)]
    scope_top_rows = PermissionScope(max_payload_bytes=10000000, max_row_count=50)

    # Scenario 3: Deeply nested collection exceeding max_row_count (200 items in sub-list, limit 50)
    payload_nested_rows = {"status": "ok", "response": {"data": [{"id": i} for i in range(200)]}}
    scope_nested_rows = PermissionScope(max_payload_bytes=10000000, max_row_count=50)

    # Scenario 4: Valid collection within limit (20 items, limit 50, size within 4KB)
    payload_valid = {"status": "ok", "items": [{"id": i} for i in range(20)]}
    scope_valid = PermissionScope(max_payload_bytes=10000000, max_row_count=50)

    scenarios = [
        ("Scenario 1: Payload Byte Limit Violation (500 items, limit 4KB)", payload_huge_bytes, scope_huge_bytes, 4096, 1000, 2000),
        ("Scenario 2: Top-Level Row Count Violation (500 items, limit 50)", payload_top_rows, scope_top_rows, 10000000, 50, 20000),
        ("Scenario 3: Nested Row Count Violation (200 items, limit 50)", payload_nested_rows, scope_nested_rows, 10000000, 50, 20000),
        ("Scenario 4: Valid Payload Within Limits (20 items, limit 50)", payload_valid, scope_valid, 10000000, 50, 20000),
    ]

    for name, payload, scope, max_b, max_r, trials in scenarios:
        t_base = timeit.timeit(lambda: baseline_validate_egress(max_b, max_r, payload), number=trials)
        t_opt = timeit.timeit(lambda: scope.validate_egress(payload), number=trials)

        base_us = (t_base / trials) * 1e6
        opt_us = (t_opt / trials) * 1e6
        speedup = t_base / t_opt
        reduction = ((t_base - t_opt) / t_base) * 100

        print(f"\n{name} ({trials} trials):")
        print(f"  Baseline (Exhaustive): {base_us:8.2f} µs/op ({t_base:.4f}s total)")
        print(f"  Optimized (Early-Exit): {opt_us:8.2f} µs/op ({t_opt:.4f}s total)")
        print(f"  Speedup:               {speedup:8.2f}x ({reduction:.1f}% latency reduction)")


if __name__ == "__main__":
    run_benchmarks()
