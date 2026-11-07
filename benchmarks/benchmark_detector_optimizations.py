"""
Reproducible Benchmark: SensitiveDataDetector Fast-Path Short-Circuiting.

Methodology:
- Isolated baseline implementation representing pre-PR detect() behavior
  (unconditional regex execution across all 14 patterns).
- Alternating execution order across identical clean and sensitive workloads.
- Rigorous output equivalence verification asserting detection categories,
  values, spans, confidence, detector_types, treatments, and metadata.
- Median, mean, p95 latency reporting over stable measurement repetitions.
- Separate benchmark comparing _shannon_entropy implementations.

Invocation:
    python benchmarks/benchmark_detector_optimizations.py
"""

import sys
import time
import math
import platform
import statistics
import os
from collections import Counter
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from epistemicos.shower_curtain.detector import (  # noqa: E402
    SensitiveDataDetector,
    DetectionResult,
    SensitivityCategory,
    COMMON_FIRST_NAMES_REGEX,
    _luhn_check,
    _shannon_entropy
)


class BaselineUncachedSensitiveDataDetector(SensitiveDataDetector):
    """
    Isolated baseline reproducing pre-PR SensitiveDataDetector.detect().
    Executes all 14 regex patterns unconditionally without fast-path guards.
    """

    def detect(self, text: str) -> List[DetectionResult]:
        if not text or not isinstance(text, str):
            return []

        results: List[DetectionResult] = []
        spans_covered = []

        def _is_overlapping(s):
            import bisect
            a, b = s
            idx = bisect.bisect_left(spans_covered, a, key=lambda x: x[0])
            if idx > 0 and spans_covered[idx - 1][1] > a:
                return True
            if idx < len(spans_covered) and spans_covered[idx][0] < b:
                return True
            return False

        def _add_result(res: DetectionResult):
            import bisect
            if not _is_overlapping(res.span):
                results.append(res)
                idx = bisect.bisect_left(
                    spans_covered, res.span[0], key=lambda x: x[0]
                )
                spans_covered.insert(idx, res.span)

        # 1. Private keys (multiline)
        for m in self.private_key_regex.finditer(text):
            _add_result(DetectionResult(
                category=SensitivityCategory.CREDENTIAL,
                value=m.group(0),
                span=(m.start(), m.end()),
                confidence=1.0,
                detector_type="pattern",
                suggested_treatment="REDACT",
                metadata={"subtype": "private_key"}
            ))

        # 2. Known API key patterns
        for m in self.api_key_regex.finditer(text):
            _add_result(DetectionResult(
                category=SensitivityCategory.CREDENTIAL,
                value=m.group(0),
                span=(m.start(), m.end()),
                confidence=1.0,
                detector_type="pattern",
                suggested_treatment="REDACT",
                metadata={"subtype": "api_key"}
            ))

        # 3. Bearer tokens
        for m in self.bearer_regex.finditer(text):
            _add_result(DetectionResult(
                category=SensitivityCategory.CREDENTIAL,
                value=m.group(0),
                span=(m.start(), m.end()),
                confidence=1.0,
                detector_type="pattern",
                suggested_treatment="REDACT",
                metadata={"subtype": "bearer_token"}
            ))

        # 4. Email addresses
        for m in self.email_regex.finditer(text):
            _add_result(DetectionResult(
                category=SensitivityCategory.EMAIL,
                value=m.group(0),
                span=(m.start(), m.end()),
                confidence=0.98,
                detector_type="pattern",
                suggested_treatment="PSEUDONYMIZE"
            ))

        # 5. SSN
        for m in self.ssn_regex.finditer(text):
            _add_result(DetectionResult(
                category=SensitivityCategory.GOV_ID,
                value=m.group(0),
                span=(m.start(), m.end()),
                confidence=0.95,
                detector_type="pattern",
                suggested_treatment="REDACT",
                metadata={"subtype": "ssn"}
            ))

        # 6. Credit Card (with Luhn check)
        for m in self.credit_card_regex.finditer(text):
            raw = m.group(0)
            if _luhn_check(raw):
                _add_result(DetectionResult(
                    category=SensitivityCategory.FINANCIAL,
                    value=raw,
                    span=(m.start(), m.end()),
                    confidence=0.99,
                    detector_type="checksum",
                    suggested_treatment="REDACT",
                    metadata={"subtype": "credit_card"}
                ))

        # 7. IBAN
        for m in self.iban_regex.finditer(text):
            _add_result(DetectionResult(
                category=SensitivityCategory.FINANCIAL,
                value=m.group(0),
                span=(m.start(), m.end()),
                confidence=0.90,
                detector_type="pattern",
                suggested_treatment="REDACT",
                metadata={"subtype": "iban"}
            ))

        # 8. Phone Numbers
        for m in self.phone_regex.finditer(text):
            val = m.group(0).strip()
            digits_only = [c for c in val if c.isdigit()]
            if 7 <= len(digits_only) <= 15:
                _add_result(DetectionResult(
                    category=SensitivityCategory.PHONE,
                    value=val,
                    span=(m.start(), m.end()),
                    confidence=0.85,
                    detector_type="pattern",
                    suggested_treatment="REDACT"
                ))

        # 9. Name with title or Common First Names
        for m in self.name_title_regex.finditer(text):
            _add_result(DetectionResult(
                category=SensitivityCategory.NAME,
                value=m.group(0),
                span=(m.start(), m.end()),
                confidence=0.92,
                detector_type="pattern",
                suggested_treatment="PSEUDONYMIZE"
            ))

        for m in COMMON_FIRST_NAMES_REGEX.finditer(text):
            _add_result(DetectionResult(
                category=SensitivityCategory.NAME,
                value=m.group(0),
                span=(m.start(), m.end()),
                confidence=0.90,
                detector_type="dictionary",
                suggested_treatment="PSEUDONYMIZE"
            ))

        # 10. File paths
        for m in self.file_path_regex.finditer(text):
            _add_result(DetectionResult(
                category=SensitivityCategory.FILE_PATH,
                value=m.group(0),
                span=(m.start(), m.end()),
                confidence=0.88,
                detector_type="pattern",
                suggested_treatment="GENERALIZE"
            ))

        # 11. IP addresses
        for m in self.ip_regex.finditer(text):
            _add_result(DetectionResult(
                category=SensitivityCategory.IP_ADDRESS,
                value=m.group(0),
                span=(m.start(), m.end()),
                confidence=0.90,
                detector_type="pattern",
                suggested_treatment="GENERALIZE"
            ))

        # 12. Custom Entities Dictionary (Unconditional regex execution baseline)
        for item in self.custom_entities_compiled:
            entity, pattern = item[0], item[1]
            for m in pattern.finditer(text):
                _add_result(DetectionResult(
                    category=SensitivityCategory.CUSTOM_ENTITY,
                    value=m.group(0),
                    span=(m.start(), m.end()),
                    confidence=1.0,
                    detector_type="dictionary",
                    suggested_treatment="PSEUDONYMIZE",
                    metadata={"entity_name": entity}
                ))

        # 13. Custom Regex Patterns
        for name, pat_compiled in self.custom_compiled.items():
            for m in pat_compiled.finditer(text):
                _add_result(DetectionResult(
                    category=SensitivityCategory.CUSTOM_ENTITY,
                    value=m.group(0),
                    span=(m.start(), m.end()),
                    confidence=0.90,
                    detector_type="custom_pattern",
                    suggested_treatment="REDACT",
                    metadata={"rule": name}
                ))

        # 14. Entropy-based secret detection for high-entropy tokens
        for m in self.entropy_regex.finditer(text):
            word = m.group(0)
            ent = _shannon_entropy(word)
            if ent >= self.entropy_threshold:
                span = (m.start(), m.end())
                if not _is_overlapping(span):
                    _add_result(DetectionResult(
                        category=SensitivityCategory.CREDENTIAL,
                        value=word,
                        span=span,
                        confidence=round(min(1.0, ent / 6.0), 2),
                        detector_type="entropy",
                        suggested_treatment="REDACT",
                        metadata={"shannon_entropy": round(ent, 2)}
                    ))

        results.sort(key=lambda r: r.span[0])
        return results


def _baseline_shannon_entropy(s: str) -> float:
    """Original Shannon entropy calculation using collections.Counter."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


CLEAN_TEXTS = [
    "The user requested documentation for deploying services across regions.",
    "Please summarize the findings from the quarterly logistics analysis.",
    "The quick brown fox jumps over the lazy dog in the green meadow.",
    "Can you help me design a software architecture for stream processing?",
    "Explain difference between Bayesian and frequentist inference.",
    "Calculate gradient descent update rule for a linear model.",
    "Write a function that calculates the nth Fibonacci number.",
    "What are the best practices for structuring microservices?"
]

SENSITIVE_TEXTS = [
    "Please contact alice@example.com or bob.miller@corp.internal for access.",
    "Server reachable at 192.168.1.15 and backup host 10.0.4.2.",
    "Config loaded from /etc/nginx/sites-available/default on unix host.",
    "Windows path C:\\Users\\Admin\\AppData\\Local\\Temp\\log.",
    "Customer card is 4532015112830366 expiring next year.",
    "Representative Dr. John Watson reached at +1 555-0199.",
    "Auth header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
    "Primary API token sk-ant-api03-abcdef123456789012345678."
]


def assert_equivalence(
    detector_base: SensitiveDataDetector,
    detector_opt: SensitiveDataDetector,
    workload: List[str]
):
    """
    Strictly asserts output equivalence across both implementations:
    categories, values, spans, confidence, detector_types, treatments,
    and metadata dictionaries.
    """
    for idx, text in enumerate(workload):
        res_base = detector_base.detect(text)
        res_opt = detector_opt.detect(text)
        assert len(res_base) == len(res_opt), (
            f"Item {idx} result length mismatch: "
            f"base={len(res_base)}, opt={len(res_opt)}"
        )
        for d_base, d_opt in zip(res_base, res_opt):
            assert d_base.category == d_opt.category, "Category mismatch"
            assert d_base.value == d_opt.value, "Value mismatch"
            assert d_base.span == d_opt.span, "Span mismatch"
            assert d_base.confidence == d_opt.confidence, "Confidence mismatch"
            assert d_base.detector_type == d_opt.detector_type, (
                "Detector type mismatch"
            )
            assert d_base.suggested_treatment == d_opt.suggested_treatment, (
                "Treatment mismatch"
            )
            assert d_base.metadata == d_opt.metadata, "Metadata mismatch"


def compute_p95(values: List[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = int(round(0.95 * (len(s) - 1)))
    return s[min(idx, len(s) - 1)]


def benchmark_workload(
    name: str,
    workload: List[str],
    detector_base: SensitiveDataDetector,
    detector_opt: SensitiveDataDetector,
    num_runs: int = 20,
    calls_per_run: int = 1000
):
    assert_equivalence(detector_base, detector_opt, workload)

    base_times = []
    opt_times = []

    # Paired alternating execution
    for rep in range(num_runs):
        if rep % 2 == 0:
            t0 = time.perf_counter()
            for i in range(calls_per_run):
                detector_base.detect(workload[i % len(workload)])
            t1 = time.perf_counter()
            base_times.append(t1 - t0)

            t0 = time.perf_counter()
            for i in range(calls_per_run):
                detector_opt.detect(workload[i % len(workload)])
            t1 = time.perf_counter()
            opt_times.append(t1 - t0)
        else:
            t0 = time.perf_counter()
            for i in range(calls_per_run):
                detector_opt.detect(workload[i % len(workload)])
            t1 = time.perf_counter()
            opt_times.append(t1 - t0)

            t0 = time.perf_counter()
            for i in range(calls_per_run):
                detector_base.detect(workload[i % len(workload)])
            t1 = time.perf_counter()
            base_times.append(t1 - t0)

    med_base = statistics.median(base_times)
    p95_base = compute_p95(base_times)
    ms_base_med = (med_base / calls_per_run) * 1000.0
    ms_base_p95 = (p95_base / calls_per_run) * 1000.0

    med_opt = statistics.median(opt_times)
    p95_opt = compute_p95(opt_times)
    ms_opt_med = (med_opt / calls_per_run) * 1000.0
    ms_opt_p95 = (p95_opt / calls_per_run) * 1000.0

    speedup = med_base / med_opt
    reduction = (1.0 - (med_opt / med_base)) * 100.0

    print(f"\n{name} ({num_runs} paired alternating repetitions):")
    print(
        f"  Baseline:  median={ms_base_med:.4f} ms/eval | "
        f"p95={ms_base_p95:.4f} ms/eval"
    )
    print(
        f"  Optimized: median={ms_opt_med:.4f} ms/eval | "
        f"p95={ms_opt_p95:.4f} ms/eval"
    )
    print(f"  Speedup:   {speedup:.2f}x ({reduction:.1f}% latency reduction)")


def run_benchmark():
    env_info = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "x86_64",
        "cpu_count": os.cpu_count() or 1,
    }

    detector_base = BaselineUncachedSensitiveDataDetector()
    detector_opt = SensitiveDataDetector()

    print("=" * 76)
    print("⚡ SensitiveDataDetector Fast-Path Short-Circuiting Benchmark")
    print(f"Python: {env_info['python_version']} on {env_info['platform']}")
    print(f"CPUs:   {env_info['cpu_count']} ({env_info['processor']})")
    print("Method: Paired alternating trials, strict equivalence assertions")
    print("=" * 76)

    benchmark_workload(
        "1. Clean Text Workload (No Trigger Characters)",
        CLEAN_TEXTS,
        detector_base,
        detector_opt,
        num_runs=20,
        calls_per_run=1000
    )

    benchmark_workload(
        "2. Mixed Sensitive Text Workload",
        SENSITIVE_TEXTS,
        detector_base,
        detector_opt,
        num_runs=20,
        calls_per_run=1000
    )

    # 3. Custom Entities Workload (8 configured entities)
    custom_entities_list = [
        "ProjectFalcon", "Acme Corp", "TopSecret", "OmegaKey",
        "SuperServer", "DatabaseProd", "UserZero", "SpecialAlpha"
    ]
    det_custom_base = BaselineUncachedSensitiveDataDetector(custom_entities=custom_entities_list)
    det_custom_opt = SensitiveDataDetector(custom_entities=custom_entities_list)

    benchmark_workload(
        "3. Custom Entities Workload (Clean text, 8 configured entities)",
        CLEAN_TEXTS,
        det_custom_base,
        det_custom_opt,
        num_runs=20,
        calls_per_run=1000
    )

    # 4. Shannon Entropy isolated comparison
    print("\n4. Shannon Entropy Isolated Evaluation (100k calls, 20 reps):")
    test_word = "aB39kLpQ0zWsX7vB1mZ9wK2yTx4rNv6q"
    base_ent_times = []
    curr_ent_times = []
    for rep in range(20):
        t0 = time.perf_counter()
        for _ in range(5000):
            _baseline_shannon_entropy(test_word)
        t1 = time.perf_counter()
        base_ent_times.append(t1 - t0)

        t0 = time.perf_counter()
        for _ in range(5000):
            _shannon_entropy(test_word)
        t1 = time.perf_counter()
        curr_ent_times.append(t1 - t0)

    med_base_ent = statistics.median(base_ent_times)
    med_curr_ent = statistics.median(curr_ent_times)
    print(
        f"  Original Counter implementation: median={med_base_ent*1000:.2f}ms"
    )
    print(
        f"  Current production impl:         median={med_curr_ent*1000:.2f}ms"
    )
    diff = ((med_base_ent - med_curr_ent) / med_base_ent) * 100.0
    print(f"  Delta: {diff:+.1f}% (retained Counter to avoid unneeded drift)")
    print("=" * 76)


if __name__ == "__main__":
    run_benchmark()
