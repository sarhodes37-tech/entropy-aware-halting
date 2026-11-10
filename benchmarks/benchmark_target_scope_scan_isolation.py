#!/usr/bin/env python3
"""
⚡ BOLT: Isolated Benchmark for Target Scope Character Scanning.

Directly benchmarks and compares the original Python generator any() character scans
against the precompiled C-level character-class regular expression scans.
Bypasses all LRU caching and memoization so that only the raw character scanning
and normalization logic is measured.

Workload classes evaluated:
1. Valid Short URLs & Paths (< 50 chars)
2. Valid Medium & Long URLs (> 512 chars)
3. Malformed Rejected Inputs (early unencoded whitespace / C0 rejection)
4. Malformed Decoded Authority (C0 / DEL rejection after URL parse)
5. Malformed Decoded Path (C0 control char rejection after percent-unquoting)
"""

import os
import platform
import re
import statistics
import subprocess
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote, urlparse

MAX_TARGET_INPUT_LEN = 4096

# Regex patterns under test
_TARGET_UNENCODED_CTRL_REGEX = re.compile(r"[\s\x00\x0b\x0c]")
_TARGET_AUTHORITY_CTRL_REGEX = re.compile(r"[\s\x00-\x1f\x7f]")
_TARGET_DECODED_CTRL_REGEX = re.compile(r"[\x00\r\n\t\x0b\x0c]")


def normalize_generator_impl(raw_target: str) -> str:
    """Original implementation using Python generator expressions with any()."""
    if not isinstance(raw_target, str) or not raw_target:
        raise ValueError(
            f"Target resource must be a non-empty string, got {type(raw_target).__name__}: {raw_target!r}"
        )

    if len(raw_target) > MAX_TARGET_INPUT_LEN:
        raise ValueError(
            f"Target resource exceeds maximum input length of {MAX_TARGET_INPUT_LEN} characters: length={len(raw_target)}"
        )

    str_raw = raw_target
    # Reject unencoded control characters and whitespace anomalies that cause parser differential or scope collision
    if any(c.isspace() or c in ("\x00", "\x0b", "\x0c") for c in str_raw):
        raise ValueError(f"Malformed target resource contains unencoded whitespace or control characters: {raw_target!r}")
    str_target = str_raw
    if "://" in str_target:
        parsed = urlparse(str_target)
        raw_netloc = parsed.netloc or ""
        unquoted_netloc = unquote(raw_netloc)
        # Reject decoded whitespace and C0 control characters in authority
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in unquoted_netloc):
            raise ValueError(f"Malformed target resource contains decoded whitespace or control characters in authority: {raw_target!r}")
        netloc = unquoted_netloc.lower()
        raw_path = parsed.path or "/"
    else:
        netloc = ""
        raw_path = str_target if str_target.startswith("/") else "/" + str_target
        if "?" in raw_path or "#" in raw_path:
            parsed = urlparse("http://localhost" + raw_path)
            raw_path = parsed.path or "/"
    clean_path = unquote(raw_path).replace("\\", "/")
    # Reject decoded NUL and control characters (CR, LF, TAB, vertical tab, form feed, NUL) after percent-decoding
    if any(c in clean_path for c in ("\x00", "\r", "\n", "\t", "\x0b", "\x0c")):
        raise ValueError(f"Malformed target resource contains decoded control characters or NUL: {raw_target!r}")
    norm_path = os.path.normpath(clean_path)
    if norm_path in (".", "", "/"):
        norm_path = "/"
    else:
        norm_path = norm_path.rstrip("/")
    return f"target:{netloc}:{norm_path}"


def normalize_regex_impl(raw_target: str) -> str:
    """Optimized implementation using precompiled character-class regexes."""
    if not isinstance(raw_target, str) or not raw_target:
        raise ValueError(
            f"Target resource must be a non-empty string, got {type(raw_target).__name__}: {raw_target!r}"
        )

    if len(raw_target) > MAX_TARGET_INPUT_LEN:
        raise ValueError(
            f"Target resource exceeds maximum input length of {MAX_TARGET_INPUT_LEN} characters: length={len(raw_target)}"
        )

    str_raw = raw_target
    # Reject unencoded control characters and whitespace anomalies that cause parser differential or scope collision
    if _TARGET_UNENCODED_CTRL_REGEX.search(str_raw):
        raise ValueError(f"Malformed target resource contains unencoded whitespace or control characters: {raw_target!r}")
    str_target = str_raw
    if "://" in str_target:
        parsed = urlparse(str_target)
        raw_netloc = parsed.netloc or ""
        unquoted_netloc = unquote(raw_netloc)
        # Reject decoded whitespace and C0 control characters in authority
        if _TARGET_AUTHORITY_CTRL_REGEX.search(unquoted_netloc):
            raise ValueError(f"Malformed target resource contains decoded whitespace or control characters in authority: {raw_target!r}")
        netloc = unquoted_netloc.lower()
        raw_path = parsed.path or "/"
    else:
        netloc = ""
        raw_path = str_target if str_target.startswith("/") else "/" + str_target
        if "?" in raw_path or "#" in raw_path:
            parsed = urlparse("http://localhost" + raw_path)
            raw_path = parsed.path or "/"
    clean_path = unquote(raw_path).replace("\\", "/")
    # Reject decoded NUL and control characters (CR, LF, TAB, vertical tab, form feed, NUL) after percent-decoding
    if _TARGET_DECODED_CTRL_REGEX.search(clean_path):
        raise ValueError(f"Malformed target resource contains decoded control characters or NUL: {raw_target!r}")
    norm_path = os.path.normpath(clean_path)
    if norm_path in (".", "", "/"):
        norm_path = "/"
    else:
        norm_path = norm_path.rstrip("/")
    return f"target:{netloc}:{norm_path}"


def get_git_commit_sha() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        base_sha = res.stdout.strip()
        status_res = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True
        )
        if status_res.stdout.strip():
            return f"{base_sha} (working-tree dirty)"
        return base_sha
    except Exception:
        return "UNKNOWN_SHA"


def compute_percentiles(data: List[float]) -> Tuple[float, float, float, float]:
    """Returns (mean, median, p95, std_dev)."""
    sorted_data = sorted(data)
    n = len(sorted_data)
    mean_val = statistics.mean(sorted_data)
    median_val = statistics.median(sorted_data)
    p95_idx = int(0.95 * (n - 1))
    p95_val = sorted_data[p95_idx]
    std_val = statistics.stdev(sorted_data) if n > 1 else 0.0
    return mean_val, median_val, p95_val, std_val


def benchmark_class(
    name: str,
    inputs: List[str],
    expect_exception: bool,
    iterations_per_trial: int = 500,
    trial_count: int = 25
) -> Dict[str, Any]:
    total_ops_per_trial = len(inputs) * iterations_per_trial
    gen_times = []
    reg_times = []

    for trial in range(trial_count):
        # Alternate execution order to avoid bias
        if trial % 2 == 0:
            # Generator trial
            t0 = time.perf_counter()
            for _ in range(iterations_per_trial):
                for inp in inputs:
                    if expect_exception:
                        try:
                            normalize_generator_impl(inp)
                        except ValueError:
                            pass
                    else:
                        normalize_generator_impl(inp)
            t_gen = time.perf_counter() - t0

            # Regex trial
            t0 = time.perf_counter()
            for _ in range(iterations_per_trial):
                for inp in inputs:
                    if expect_exception:
                        try:
                            normalize_regex_impl(inp)
                        except ValueError:
                            pass
                    else:
                        normalize_regex_impl(inp)
            t_reg = time.perf_counter() - t0
        else:
            # Regex trial first
            t0 = time.perf_counter()
            for _ in range(iterations_per_trial):
                for inp in inputs:
                    if expect_exception:
                        try:
                            normalize_regex_impl(inp)
                        except ValueError:
                            pass
                    else:
                        normalize_regex_impl(inp)
            t_reg = time.perf_counter() - t0

            # Generator trial second
            t0 = time.perf_counter()
            for _ in range(iterations_per_trial):
                for inp in inputs:
                    if expect_exception:
                        try:
                            normalize_generator_impl(inp)
                        except ValueError:
                            pass
                    else:
                        normalize_generator_impl(inp)
            t_gen = time.perf_counter() - t0

        gen_times.append(t_gen)
        reg_times.append(t_reg)

    g_mean, g_med, g_p95, g_std = compute_percentiles(gen_times)
    r_mean, r_med, r_p95, r_std = compute_percentiles(reg_times)

    speedup_median = g_med / r_med if r_med > 0 else 1.0
    speedup_mean = g_mean / r_mean if r_mean > 0 else 1.0

    g_us_med = (g_med / total_ops_per_trial) * 1e6
    g_us_p95 = (g_p95 / total_ops_per_trial) * 1e6
    r_us_med = (r_med / total_ops_per_trial) * 1e6
    r_us_p95 = (r_p95 / total_ops_per_trial) * 1e6

    reduction_pct = ((g_med - r_med) / g_med) * 100.0 if g_med > 0 else 0.0

    return {
        "class_name": name,
        "sample_count": len(inputs),
        "total_evaluations_per_trial": total_ops_per_trial,
        "trials": trial_count,
        "generator": {
            "median_sec": g_med,
            "p95_sec": g_p95,
            "us_per_op_median": g_us_med,
            "us_per_op_p95": g_us_p95,
        },
        "regex": {
            "median_sec": r_med,
            "p95_sec": r_p95,
            "us_per_op_median": r_us_med,
            "us_per_op_p95": r_us_p95,
        },
        "speedup_median": round(speedup_median, 2),
        "speedup_mean": round(speedup_mean, 2),
        "latency_reduction_pct": round(reduction_pct, 1),
    }


def main():
    print("=" * 78)
    print("⚡ BOLT: Isolated Direct Benchmark (Generator any() vs Compiled Regex)")
    print("=" * 78)

    env = {
        "commit_sha": get_git_commit_sha(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count() or 1,
    }
    print(f"Commit:  {env['commit_sha']}")
    print(f"Python:  {env['python_version']} on {env['platform']} (CPUs: {env['cpu_count']})")
    print("-" * 78)

    # 1. Valid Short URLs & Paths (< 50 chars)
    short_valid = [
        "/api/v1/auth",
        "/db/accounts/balance",
        "https://example.com/status",
        "/services/payment",
        "http://api.local:8080/v1",
        "/users/123/profile",
        "/files/report.pdf",
        "/metrics/summary",
    ]

    # 2. Valid Medium & Long Targets (> 512 chars)
    long_valid = [
        "/" + ("segment/" * 70) + f"target_{i}" for i in range(8)
    ]

    # 3. Malformed Rejected Inputs (Unencoded Whitespace & C0)
    unencoded_rejected = [
        "/bad path/with/spaces",
        "/bad\tpath/tab",
        "/bad\npath/newline",
        "/bad\x00path/nul",
        "/bad\x0bpath/vtab",
        "/bad\x0cpath/formfeed",
        "https://example.com/bad target",
        "https://example.com/bad\x00nul",
    ]

    # 4. Malformed Decoded Authority (C0 / DEL in authority)
    authority_rejected = [
        "http://exa%20mple.com/path",
        "http://example.com%00:8080/path",
        "http://example%0A.com/path",
        "http://example%0D.com/path",
        "http://example%7F.com/path",
        "https://api%1F.corp.internal/v1",
        "http://bad%08host/v1",
        "http://test%01host/v1",
    ]

    # 5. Malformed Decoded Path (C0 control chars in path after percent unquoting)
    path_decoded_rejected = [
        "/api/v1/%00/records",
        "/api/v1/%0A/records",
        "/api/v1/%0D/records",
        "/api/v1/%09/records",
        "/api/v1/%0B/records",
        "/api/v1/%0C/records",
        "https://example.com/data/%00/leak",
        "https://example.com/data/%0D%0A/leak",
    ]

    workloads = [
        ("1. Valid Short URLs/Paths (<50 chars)", short_valid, False, 2000),
        ("2. Valid Long Targets (>512 chars)", long_valid, False, 300),
        ("3. Malformed: Unencoded Whitespace/C0", unencoded_rejected, True, 2000),
        ("4. Malformed: Decoded Authority C0/DEL", authority_rejected, True, 2000),
        ("5. Malformed: Decoded Path C0", path_decoded_rejected, True, 2000),
    ]

    for title, inputs, expect_exc, iters in workloads:
        res = benchmark_class(title, inputs, expect_exc, iterations_per_trial=iters, trial_count=20)
        print(f"\n📊 {res['class_name']}:")
        print(f"  Samples: {res['sample_count']} | Ops/trial: {res['total_evaluations_per_trial']} | Trials: {res['trials']}")
        print(f"  Generator: median={res['generator']['us_per_op_median']:.3f} µs/op, p95={res['generator']['us_per_op_p95']:.3f} µs/op")
        print(f"  Regex:     median={res['regex']['us_per_op_median']:.3f} µs/op, p95={res['regex']['us_per_op_p95']:.3f} µs/op")
        print(f"  ⚡ Speedup: {res['speedup_median']:.2f}x (median), {res['speedup_mean']:.2f}x (mean) | Latency reduction: {res['latency_reduction_pct']}%")

    print("\n" + "=" * 78)


if __name__ == "__main__":
    main()
