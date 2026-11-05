"""
Empirical Benchmark for EntropyAwareScheduler Stagnation Window Optimization.

Measures:
1. Isolated predicate microbenchmark: latency of evaluating stagnation convergence
   in isolation across trajectory sizes N=10, 50, 100, 200, 500.
2. Complete end-to-end scheduler execution: latency of full EntropyAwareScheduler.step()
   across representative trajectory lengths.

Methodology:
- Alternating paired trials to mitigate CPU throttling / scheduler bias.
- Explicit distinction between isolated predicate microbenchmark results and complete
  step() pipeline throughput.
- Auxiliary memory allocation transitions from unbounded O(N) to bounded O(W) where
  W = stagnation_window.
"""

import timeit
from epistemicos.scheduler import EntropyAwareScheduler


def eval_original(s: EntropyAwareScheduler) -> str:
    """Pre-optimization reference implementation for convergence check."""
    real_deltas = [x.delta_h for x in s.history[1:]]
    if len(real_deltas) >= s.stagnation_window:
        if all(abs(d) < s.entropy_delta_threshold for d in real_deltas[-s.stagnation_window:]):
            return "IRREDUCIBLE_UNCERTAINTY"
    return "CONTINUE"


def eval_optimized(s: EntropyAwareScheduler) -> str:
    """Optimized implementation in epistemicos.scheduler."""
    if len(s.history) > s.stagnation_window:
        win = s.history[-s.stagnation_window:]
        if all(abs(x.delta_h) < s.entropy_delta_threshold for x in win):
            return "IRREDUCIBLE_UNCERTAINTY"
    return "CONTINUE"


def run_benchmark():
    trajectory_sizes = [10, 50, 100, 200, 500]
    rounds = 30
    number_per_round = 10000

    print("=" * 85)
    print("⚡ BOLT BENCHMARK: EntropyAwareScheduler Stagnation Window Check")
    print("=" * 85)
    print("\n--- Part 1: Isolated Convergence Predicate Microbenchmark ---")

    for n in trajectory_sizes:
        sched = EntropyAwareScheduler(stagnation_window=3, entropy_delta_threshold=0.005)
        for i in range(n):
            sched.step([0.5, 0.5], cost=1, state=f"s{i}")

        # Behavioral equivalence check under test distribution
        assert eval_original(sched) == eval_optimized(sched) == "IRREDUCIBLE_UNCERTAINTY", (
            f"Equivalence mismatch at N={n}"
        )

        orig_times = []
        opt_times = []

        for trial in range(rounds):
            if trial % 2 == 0:
                t_orig = timeit.timeit(lambda: eval_original(sched), number=number_per_round)
                t_opt = timeit.timeit(lambda: eval_optimized(sched), number=number_per_round)
            else:
                t_opt = timeit.timeit(lambda: eval_optimized(sched), number=number_per_round)
                t_orig = timeit.timeit(lambda: eval_original(sched), number=number_per_round)
            orig_times.append(t_orig)
            opt_times.append(t_opt)

        orig_mean_us = (sum(orig_times) / len(orig_times)) * 1_000_000 / number_per_round
        opt_mean_us = (sum(opt_times) / len(opt_times)) * 1_000_000 / number_per_round
        speedup = orig_mean_us / opt_mean_us
        reduction = (1.0 - (opt_mean_us / orig_mean_us)) * 100

        print(
            f"Trajectory N={n:<4} (W=3) | Legacy: {orig_mean_us:6.3f} µs | "
            f"Optimized: {opt_mean_us:6.3f} µs | "
            f"Predicate Speedup: {speedup:5.2f}x | Latency Reduction: {reduction:5.1f}%"
        )

    print("\n--- Part 2: Complete End-to-End Scheduler step() Measurement ---")
    step_samples = 5000
    for n in [50, 200]:
        sched = EntropyAwareScheduler(stagnation_window=3, entropy_delta_threshold=0.005)
        for i in range(n):
            sched.step([0.5, 0.5], cost=1, state=f"s{i}")

        t_full = timeit.timeit(
            lambda: sched.step([0.5, 0.5], cost=1, state="benchmark_state"),
            number=step_samples
        )
        step_mean_us = (t_full * 1_000_000) / step_samples
        print(
            f"Trajectory N={n:<4} (W=3) | Full step() latency: {step_mean_us:6.3f} µs/call "
            f"(includes probability validation, Shannon entropy, utility calculation, convergence)"
        )

    print("=" * 85)


if __name__ == "__main__":
    run_benchmark()
