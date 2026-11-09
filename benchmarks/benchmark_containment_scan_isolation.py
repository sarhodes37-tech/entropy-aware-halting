"""
Empirical Benchmark Harness for Containment Character Scan Isolation & Full Parser Comparison.

Directly compares the original generator expressions against the new compiled regexes:
  1. Isolated predicate performance across short, typical, long, valid, and rejected inputs.
  2. Complete uncached parse_url_authority_structure() calls with identical input sets.
  3. Complete uncached parse_ip_numeric() calls with identical input sets.

Methodology:
  - Bypasses normalization caches by calling parse_url_authority_structure directly.
  - Alternating execution order per trial to reduce ordering bias.
  - Reports sample counts, median (p50), p95, Python runtime, and hardware architecture.
"""

import os
import platform
import re
import statistics
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Tuple
from urllib.parse import unquote, urlsplit

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from epistemicos.containment import (  # noqa: E402
    _NETLOC_CTRL_REGEX,
    _HOST_WS_REGEX,
    _IP_INVALID_REGEX,
    parse_url_authority_structure,
    parse_ip_numeric,
    MAX_URL_INPUT_LEN,
    MAX_IPV4_NUMERIC_STR_LEN,
    MAX_IPV4_PART_STR_LEN,
    MAX_DNS_HOSTNAME_LEN,
    MAX_DNS_LABEL_LEN,
)

# Reference generator-based implementation of parse_url_authority_structure


def parse_url_authority_structure_generator(
    target_url_or_host: str, default_protocol: str = "https", default_port: int = 443
) -> Dict[str, object]:
    import ipaddress
    if not isinstance(target_url_or_host, str):
        return {"scheme": default_protocol.lower(), "port": default_port, "normalized_host": "", "valid": False}
    if len(target_url_or_host) > MAX_URL_INPUT_LEN:
        return {"scheme": default_protocol.lower(), "port": default_port, "normalized_host": "", "valid": False}
    if target_url_or_host != target_url_or_host.strip():
        return {"scheme": default_protocol.lower(), "port": default_port, "normalized_host": "", "valid": False}
    raw = target_url_or_host.replace('\\', '/')
    if not raw:
        return {"scheme": default_protocol.lower(), "port": default_port, "normalized_host": "", "valid": False}
    if any(c in target_url_or_host for c in ('\r', '\n', '\t', '\x00', '\x0b', '\x0c')):
        return {"scheme": default_protocol.lower(), "port": default_port, "normalized_host": "", "valid": False}
    if "://" in raw:
        url_to_split = raw
    elif raw.startswith("//"):
        url_to_split = f"{default_protocol.lower()}:{raw}"
    else:
        url_to_split = f"{default_protocol.lower()}://{raw}"
    try:
        parsed = urlsplit(url_to_split)
    except Exception:
        return {"scheme": default_protocol.lower(), "port": default_port, "normalized_host": "", "valid": False}
    scheme = (parsed.scheme or default_protocol).lower()
    eff_default_port = default_port
    if scheme == "http" and default_port == 443:
        eff_default_port = 80
    elif scheme == "https" and default_port == 80:
        eff_default_port = 443
    netloc = parsed.netloc
    if not isinstance(netloc, str):
        if hasattr(parsed, "hostname") and isinstance(parsed.hostname, str):
            netloc = parsed.hostname
        else:
            netloc = str(netloc) if netloc else ""
    if not netloc:
        return {"scheme": scheme, "port": eff_default_port, "normalized_host": "", "valid": False}
    if "#" in netloc or "%23" in netloc.lower():
        return {"scheme": scheme, "port": eff_default_port, "normalized_host": "", "valid": False}
    unquoted_netloc = unquote(netloc)
    if "#" in unquoted_netloc:
        return {"scheme": scheme, "port": eff_default_port, "normalized_host": "", "valid": False}
    # Original generator expression:
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in unquoted_netloc):
        return {"scheme": scheme, "port": eff_default_port, "normalized_host": "", "valid": False}
    if "@" in unquoted_netloc:
        host_port = unquoted_netloc.rsplit("@", 1)[1]
    else:
        host_port = unquoted_netloc
    port = eff_default_port
    if host_port.startswith("["):
        if "]" not in host_port:
            return {"scheme": scheme, "port": eff_default_port, "normalized_host": "", "valid": False}
        end_idx = host_port.find("]")
        host_part = host_port[:end_idx + 1]
        after_bracket = host_port[end_idx + 1:]
        if after_bracket.startswith(":") and after_bracket[1:].isdigit():
            port = int(after_bracket[1:])
    elif ":" in host_port:
        h_str, p_str = host_port.rsplit(":", 1)
        if p_str.isdigit():
            port = int(p_str)
            host_part = h_str
        else:
            host_part = host_port
    else:
        host_part = host_port
    if host_part != host_part.strip():
        return {"scheme": scheme, "port": port, "normalized_host": "", "valid": False}
    host_clean = host_part.lower()
    if host_clean.endswith(".") and len(host_clean) > 1:
        host_clean = host_clean[:-1]
    # Original generator expression:
    if not host_clean or any(c.isspace() for c in host_clean):
        return {"scheme": scheme, "port": port, "normalized_host": "", "valid": False}
    norm_host = ""
    if host_clean.startswith("[") and host_clean.endswith("]"):
        inner = host_clean[1:-1]
        try:
            ip = ipaddress.ip_address(inner)
            if getattr(ip, "ipv4_mapped", None):
                norm_host = str(ip.ipv4_mapped)
            else:
                norm_host = str(ip)
        except ValueError:
            pass
    else:
        try:
            ip = ipaddress.ip_address(host_clean)
            if getattr(ip, "ipv4_mapped", None):
                norm_host = str(ip.ipv4_mapped)
            else:
                norm_host = str(ip)
        except ValueError:
            alt_ip = parse_ip_numeric_generator(host_clean)
            if alt_ip:
                norm_host = str(alt_ip)
            else:
                if len(host_clean) > MAX_DNS_HOSTNAME_LEN:
                    return {"scheme": scheme, "port": port, "normalized_host": "", "valid": False}
                raw_labels = host_clean.split(".")
                if any(len(label) > MAX_DNS_LABEL_LEN or len(label) == 0 for label in raw_labels):
                    return {"scheme": scheme, "port": port, "normalized_host": "", "valid": False}
                try:
                    idna_host = host_clean.encode('idna').decode('ascii')
                except (UnicodeError, ValueError):
                    return {"scheme": scheme, "port": port, "normalized_host": "", "valid": False}
                if len(idna_host) > MAX_DNS_HOSTNAME_LEN:
                    return {"scheme": scheme, "port": port, "normalized_host": "", "valid": False}
                encoded_labels = idna_host.split(".")
                if any(len(label) > MAX_DNS_LABEL_LEN or len(label) == 0 for label in encoded_labels):
                    return {"scheme": scheme, "port": port, "normalized_host": "", "valid": False}
                if re.match(r'^[a-z0-9\-\.]+$', idna_host):
                    norm_host = idna_host
    return {"scheme": scheme, "port": port, "normalized_host": norm_host, "valid": bool(norm_host)}


# Reference generator-based implementation of parse_ip_numeric
def parse_ip_numeric_generator(host_str: str):
    import ipaddress
    import socket
    if not isinstance(host_str, str):
        return None
    # Original generator expression:
    if any(c.isspace() or c in ('+', '-', '\x00') for c in host_str):
        return None
    clean = host_str
    if not clean:
        return None
    if len(clean) > MAX_IPV4_NUMERIC_STR_LEN:
        return None
    clean_no_dot = clean[:-1] if (clean.endswith('.') and len(clean) > 1 and not clean.startswith('.')) else clean
    if len(clean_no_dot) > MAX_IPV4_NUMERIC_STR_LEN:
        return None
    parts = clean_no_dot.split(".")
    if len(parts) > 4:
        return None
    if len(parts) > 1:
        for p in parts:
            if len(p) > MAX_IPV4_PART_STR_LEN:
                return None
    try:
        raw = socket.inet_aton(clean_no_dot)
        return ipaddress.IPv4Address(raw)
    except Exception:
        pass
    if re.match(r'^(0x[0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$', clean_no_dot):
        try:
            if clean_no_dot.startswith(('0x', '0X')):
                val = int(clean_no_dot, 16)
            elif clean_no_dot.startswith('0') and len(clean_no_dot) > 1:
                val = int(clean_no_dot, 8)
            else:
                val = int(clean_no_dot, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    if 1 <= len(parts) <= 4:
        num_parts = []
        for p in parts:
            p_strip = p.strip()
            if not p_strip:
                return None
            try:
                if p_strip.startswith("0x") or p_strip.startswith("0X"):
                    v = int(p_strip, 16)
                elif p_strip.startswith("0") and len(p_strip) > 1 and p_strip.isdigit():
                    v = int(p_strip, 8)
                elif p_strip.isdigit():
                    v = int(p_strip, 10)
                else:
                    return None
                if 0 <= v <= 255:
                    num_parts.append(v)
                else:
                    return None
            except Exception:
                return None
        if len(num_parts) == 4:
            return ipaddress.IPv4Address(bytes(num_parts))
    return None


def compute_stats(times: List[float]) -> Dict[str, float]:
    sorted_times = sorted(times)
    n = len(sorted_times)
    median_val = statistics.median(sorted_times)
    p95_idx = int(0.95 * n)
    p95_val = sorted_times[min(p95_idx, n - 1)]
    return {
        "median_us": round(median_val * 1e6, 2),
        "p95_us": round(p95_val * 1e6, 2),
        "mean_us": round(statistics.mean(sorted_times) * 1e6, 2),
    }


def run_paired_trial(
    fn_a: Callable[[], object],
    fn_b: Callable[[], object],
    trials: int = 100,
    inner_loops: int = 200,
) -> Tuple[Dict[str, float], Dict[str, float]]:
    times_a: List[float] = []
    times_b: List[float] = []

    for i in range(trials):
        if i % 2 == 0:
            t0 = time.perf_counter()
            for _ in range(inner_loops):
                fn_a()
            times_a.append((time.perf_counter() - t0) / inner_loops)

            t0 = time.perf_counter()
            for _ in range(inner_loops):
                fn_b()
            times_b.append((time.perf_counter() - t0) / inner_loops)
        else:
            t0 = time.perf_counter()
            for _ in range(inner_loops):
                fn_b()
            times_b.append((time.perf_counter() - t0) / inner_loops)

            t0 = time.perf_counter()
            for _ in range(inner_loops):
                fn_a()
            times_a.append((time.perf_counter() - t0) / inner_loops)

    return compute_stats(times_a), compute_stats(times_b)


def main():
    print("=" * 80)
    print(" Containment Character Scan Isolation & Full Parser Empirical Benchmark")
    print("=" * 80)
    print(f"Platform       : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python Runtime : {sys.version.split()[0]}")
    print(f"CPU Cores      : {os.cpu_count()}")
    print("-" * 80)

    # Workloads for isolated predicate testing
    isolated_workloads = {
        "netloc_short_valid": ("api.github.com", False),
        "netloc_typical_valid": ("internal-service.cluster.local:8443", False),
        "netloc_long_valid": ("very-long-subdomain-name-with-many-labels.and-complex-routing-paths.example.org:443", False),
        "netloc_c0_rejected": ("cluster.local\x1f:80", True),
        "netloc_ws_rejected": ("internal service.cluster.local:8080", True),
        "host_clean_valid": ("api-v2.internal-service.local", False),
        "host_clean_rejected": ("api-v2.internal service.local", True),
        "ip_short_valid": ("10.0.0.1", False),
        "ip_typical_valid": ("192.168.1.100", False),
        "ip_octal_valid": ("0177.0.0.1", False),
        "ip_hex_valid": ("0x7f000001", False),
        "ip_whitespace_rejected": ("192.168. 1.1", True),
        "ip_sign_rejected": ("+192.168.1.1", True),
    }

    print("\n--- 1. Isolated Character Predicate Benchmarks (100 trials, 500 inner loops) ---")
    for name, (inp, _) in isolated_workloads.items():
        if name.startswith("netloc"):
            fn_gen = lambda s=inp: any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in s)
            fn_reg = lambda s=inp: bool(_NETLOC_CTRL_REGEX.search(s))
        elif name.startswith("host"):
            fn_gen = lambda s=inp: any(c.isspace() for c in s)
            fn_reg = lambda s=inp: bool(_HOST_WS_REGEX.search(s))
        else:
            fn_gen = lambda s=inp: any(c.isspace() or c in ("+", "-", "\x00") for c in s)
            fn_reg = lambda s=inp: bool(_IP_INVALID_REGEX.search(s))

        stats_gen, stats_reg = run_paired_trial(fn_gen, fn_reg, trials=100, inner_loops=500)
        speedup = stats_gen["median_us"] / stats_reg["median_us"] if stats_reg["median_us"] > 0 else 0
        reduction = (1 - (stats_reg["median_us"] / stats_gen["median_us"])) * 100
        print(f"  [{name:<24}] Gen p50: {stats_gen['median_us']:>6.2f} µs | Regex p50: {stats_reg['median_us']:>6.2f} µs | Speedup: {speedup:>5.2f}x ({reduction:>5.1f}% reduction)")

    # Full parser URL workloads (uncached)
    url_workloads = {
        "url_short_valid": "https://api.github.com/v1",
        "url_typical_valid": "https://internal-service.cluster.local:8443/api/v2/metrics",
        "url_long_valid": "https://very-long-subdomain-name-with-many-labels.and-complex-routing-paths.example.org:443/deeply/nested/resource/endpoint/v3/data/records/12345/details",
        "url_ip_authority": "http://192.168.1.100:8080/debug/pprof",
        "url_schemeless": "example.com:8080/path",
        "url_ws_rejected": "http://ex ample.com/path",
        "url_c0_rejected": "http://example.com\x01/path",
    }

    print("\n--- 2. Complete Uncached parse_url_authority_structure() (100 trials, 200 inner loops) ---")
    for name, url in url_workloads.items():
        fn_gen = lambda u=url: parse_url_authority_structure_generator(u)
        fn_reg = lambda u=url: parse_url_authority_structure(u)

        stats_gen, stats_reg = run_paired_trial(fn_gen, fn_reg, trials=100, inner_loops=200)
        speedup = stats_gen["median_us"] / stats_reg["median_us"] if stats_reg["median_us"] > 0 else 0
        reduction = (1 - (stats_reg["median_us"] / stats_gen["median_us"])) * 100
        print(f"  [{name:<24}] Gen p50: {stats_gen['median_us']:>6.2f} µs | Regex p50: {stats_reg['median_us']:>6.2f} µs | Speedup: {speedup:>5.2f}x ({reduction:>5.1f}% reduction)")

    # Full parser IP workloads (uncached)
    ip_workloads = {
        "ip_standard_v4": "192.168.1.1",
        "ip_loopback": "127.0.0.1",
        "ip_octal_dotted": "0177.0.0.1",
        "ip_hex_dword": "0x7f000001",
        "ip_decimal_dword": "2130706433",
        "ip_non_numeric": "not.an.ip.address",
        "ip_invalid_char_rejected": "+192.168.1.1",
    }

    print("\n--- 3. Complete Uncached parse_ip_numeric() (100 trials, 200 inner loops) ---")
    for name, ip_str in ip_workloads.items():
        fn_gen = lambda s=ip_str: parse_ip_numeric_generator(s)
        fn_reg = lambda s=ip_str: parse_ip_numeric(s)

        stats_gen, stats_reg = run_paired_trial(fn_gen, fn_reg, trials=100, inner_loops=200)
        speedup = stats_gen["median_us"] / stats_reg["median_us"] if stats_reg["median_us"] > 0 else 0
        reduction = (1 - (stats_reg["median_us"] / stats_gen["median_us"])) * 100
        print(f"  [{name:<24}] Gen p50: {stats_gen['median_us']:>6.2f} µs | Regex p50: {stats_reg['median_us']:>6.2f} µs | Speedup: {speedup:>5.2f}x ({reduction:>5.1f}% reduction)")

    print("\n✓ Dedicated benchmark suite completed successfully.")


if __name__ == "__main__":
    main()
