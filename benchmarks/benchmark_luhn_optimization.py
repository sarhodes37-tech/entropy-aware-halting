"""
Benchmark suite for Luhn checksum algorithm optimization.
Evaluates reference vs optimized _luhn_check across paired alternating trials.
"""

import platform
import statistics
import time
from epistemicos.shower_curtain.detector import _luhn_check


def reference_luhn(card_number: str) -> bool:
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


CARDS = [
    "4532015112830366",
    "4532-0151-1283-0366",
    "4532 0151 1283 0366",
    "4532015112830367",
    "4000000000006",
    "4000000000000000006",
    "12345678901234",
    "9876543210987654",
]


def run_benchmark(trials: int = 20, calls_per_trial: int = 50000):
    total_calls = trials * calls_per_trial
    print("=" * 76)
    print("⚡ Luhn Checksum Validation Benchmark (Paired Alternating Trials)")
    print(f"Python: {platform.python_version()} on {platform.platform()}")
    print(f"Trials: {trials} | Calls/trial: {calls_per_trial} | Total calls: {total_calls}")
    print("=" * 76)

    # Verification pass
    for card in CARDS:
        assert reference_luhn(card) == _luhn_check(card)

    base_trial_ns = []
    opt_trial_ns = []

    for trial in range(trials):
        if trial % 2 == 0:
            t0 = time.perf_counter_ns()
            for i in range(calls_per_trial):
                reference_luhn(CARDS[i % len(CARDS)])
            t1 = time.perf_counter_ns()
            base_trial_ns.append(t1 - t0)

            t0 = time.perf_counter_ns()
            for i in range(calls_per_trial):
                _luhn_check(CARDS[i % len(CARDS)])
            t1 = time.perf_counter_ns()
            opt_trial_ns.append(t1 - t0)
        else:
            t0 = time.perf_counter_ns()
            for i in range(calls_per_trial):
                _luhn_check(CARDS[i % len(CARDS)])
            t1 = time.perf_counter_ns()
            opt_trial_ns.append(t1 - t0)

            t0 = time.perf_counter_ns()
            for i in range(calls_per_trial):
                reference_luhn(CARDS[i % len(CARDS)])
            t1 = time.perf_counter_ns()
            base_trial_ns.append(t1 - t0)

    med_base_ns = statistics.median(base_trial_ns)
    med_opt_ns = statistics.median(opt_trial_ns)

    per_call_base_ns = med_base_ns / calls_per_trial
    per_call_opt_ns = med_opt_ns / calls_per_trial

    speedup = med_base_ns / med_opt_ns
    reduction = (1.0 - (med_opt_ns / med_base_ns)) * 100.0

    base_us = per_call_base_ns / 1000.0
    opt_us = per_call_opt_ns / 1000.0
    print(f"Reference Luhn median: {per_call_base_ns:.1f} ns/call ({base_us:.4f} µs/call)")
    print(f"Optimized Luhn median: {per_call_opt_ns:.1f} ns/call ({opt_us:.4f} µs/call)")
    print(f"Speedup:               {speedup:.2f}x ({reduction:.1f}% latency reduction)")
    print("=" * 76)


if __name__ == "__main__":
    run_benchmark()
