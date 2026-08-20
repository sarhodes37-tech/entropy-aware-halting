import time
from typing import Any

def build_deep_payload(depth):
    if depth == 0:
        return ["leaf"]
    return {"level": depth, "child": build_deep_payload(depth - 1)}

def build_wide_payload(width):
    return {f"key_{i}": "val" for i in range(width)}

def count_max_records_baseline(data: Any) -> int:
    if isinstance(data, list): return max(len(data), max((count_max_records_baseline(item) for item in data), default=0))
    elif isinstance(data, dict): return max(len(data.keys()), max((count_max_records_baseline(val) for val in data.values()), default=0))
    return 0

def count_max_records_iterative(data: Any) -> int:
    max_count = 0
    stack = [data]

    while stack:
        current = stack.pop()
        if isinstance(current, list):
            if len(current) > max_count:
                max_count = len(current)
            stack.extend(current)
        elif isinstance(current, dict):
            if len(current) > max_count:
                max_count = len(current)
            stack.extend(current.values())

    return max_count

def run_benchmark():
    import sys
    sys.setrecursionlimit(20000)

    # Let's use smaller depth for baseline to prevent recursion error, but enough to show speedup
    payloads = {
        "deep_500": build_deep_payload(500),
        "deep_2000": build_deep_payload(2000),
        "wide_100000": build_wide_payload(100000),
        "nested_large": [build_wide_payload(10) for _ in range(50000)]
    }

    for name, payload in payloads.items():
        print(f"--- Benchmarking {name} ---")

        try:
            start = time.time()
            res_base = count_max_records_baseline(payload)
            t_base = time.time() - start
            print(f"Baseline: valid={res_base}, time={t_base:.6f}s")
        except Exception as e:
            t_base = float('inf')
            print(f"Baseline failed: {e}")

        start = time.time()
        res_iter = count_max_records_iterative(payload)
        t_iter = time.time() - start

        print(f"Iterative: valid={res_iter}, time={t_iter:.6f}s")

        if t_base != float('inf'):
            print(f"Speedup: {t_base / t_iter:.2f}x\n" if t_iter > 0 else "Speedup: INF\n")

if __name__ == "__main__":
    run_benchmark()
