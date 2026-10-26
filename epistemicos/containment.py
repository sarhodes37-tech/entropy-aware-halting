"""
EpistemicOS V1 - ContainmentGuard & Controlled Egress Transport Subsystem
------------------------------------------------------------------------
Provides active ingress, egress, action classification, and tool-execution guardrails to prevent:
1. Prompt Injections & Jailbreaks (Ingress)
2. Unauthorized Network Egress & Unsafe Tool Parameters (Egress Policy & Normalization)
3. Controlled Egress Transport Broker at transport establishment time with IP pinning and re-validation
4. Action Classification & Externally Consequential Side Effect Controls
5. Agent Containment Escape / Goal Mutation (Agentic Integrity)
"""

import ipaddress
import re
import socket
import contextlib
import contextvars
import time
import uuid
import hashlib
from urllib.parse import urlsplit, unquote
from functools import lru_cache
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from epistemicos.gates import ControlPlaneGate, GateConfig, GateInput, GateOutcome, GateDecision, GateAction, GateResult

import errno
import threading

_boundary_lock = threading.Lock()
_active_boundary_count = 0
_orig_socket_connect = socket.socket.connect
_orig_socket_connect_ex = socket.socket.connect_ex

_active_broker_context = contextvars.ContextVar("active_broker_context", default=None)
_enforce_safe_dns = contextvars.ContextVar("enforce_safe_dns", default=False)
_original_getaddrinfo = socket.getaddrinfo

def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """
    Optional process-wide compatibility wrapper for legacy code.
    Note: Transport-boundary egress enforcement is performed directly by ControlledEgressTransport / EgressTransportBroker.
    """
    results = _original_getaddrinfo(host, port, family, type, proto, flags)
    if _enforce_safe_dns.get():
        active_ctx = _active_broker_context.get()
        allow_loop = active_ctx["broker"].policy.allow_loopback if (active_ctx and active_ctx.get("broker") and active_ctx["broker"].policy) else False
        allow_priv = active_ctx["broker"].policy.allow_private if (active_ctx and active_ctx.get("broker") and active_ctx["broker"].policy) else False

        for res in results:
            ip_str = res[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if getattr(ip, "ipv4_mapped", None):
                    ip = ip.ipv4_mapped

                is_restricted = False
                if ip.is_loopback and not allow_loop:
                    is_restricted = True
                elif ip.is_private and not allow_priv:
                    is_restricted = True
                elif ip.is_link_local or ip.is_reserved or ip.is_unspecified:
                    is_restricted = True

                if is_restricted:
                    raise socket.error(f"Egress blocked: DNS resolution for '{host}' returned restricted IP '{ip_str}'.")
            except ValueError:
                pass
    return results

socket.getaddrinfo = _patched_getaddrinfo


class ContainmentViolationType(Enum):
    NONE = "none"
    PROMPT_INJECTION_DETECTED = "prompt_injection_detected"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    UNAUTHORIZED_EGRESS_ATTEMPT = "unauthorized_egress_attempt"
    FORBIDDEN_COMMAND_EXECUTION = "forbidden_command_execution"
    GOAL_MUTATION_REWARD_CHEATING = "goal_mutation_reward_cheating"
    EXFILTRATION_PATTERN_MATCH = "exfiltration_pattern_match"
    UNAUTHORIZED_SIDE_EFFECT = "unauthorized_side_effect"


@dataclass
class ContainmentReceipt:
    passed: bool
    violation_type: ContainmentViolationType = ContainmentViolationType.NONE
    reason: Optional[str] = None
    sanitized_payload: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ActionCategory(Enum):
    READ_ONLY_LOCAL = "READ_ONLY_LOCAL"
    NETWORK_READ = "NETWORK_READ"
    EXTERNAL_RECONNAISSANCE = "EXTERNAL_RECONNAISSANCE"
    ACCOUNT_CREATION = "ACCOUNT_CREATION"
    MESSAGING_CONTACT = "MESSAGING_CONTACT"
    PUBLIC_REPOSITORY_MUTATION = "PUBLIC_REPOSITORY_MUTATION"
    PACKAGE_PUBLISHING = "PACKAGE_PUBLISHING"
    CREDENTIAL_USAGE = "CREDENTIAL_USAGE"
    DESTRUCTIVE_COMMAND = "DESTRUCTIVE_COMMAND"
    STATE_MUTATION = "STATE_MUTATION"


def parse_url_authority_structure(target_url_or_host: str, default_protocol: str = "https", default_port: int = 443) -> Dict[str, Any]:
    """
    Unified authority and destination parser using urllib.parse.urlsplit.
    Extracts canonical scheme, normalized host, explicit/default port, and authority sanity status.
    Rejects authority strings containing userinfo with `#` or `%23` fragment tricks.
    """
    if not isinstance(target_url_or_host, str):
        return {"scheme": default_protocol.lower(), "port": default_port, "normalized_host": "", "valid": False}

    raw = target_url_or_host.strip().replace('\\', '/')
    if not raw:
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
    if not netloc:
        return {"scheme": scheme, "port": eff_default_port, "normalized_host": "", "valid": False}

    if "#" in netloc or "%23" in netloc.lower():
        return {"scheme": scheme, "port": eff_default_port, "normalized_host": "", "valid": False}

    unquoted_netloc = unquote(netloc)
    if "#" in unquoted_netloc:
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

    host_clean = host_part.strip().lower()
    if host_clean.endswith(".") and len(host_clean) > 1:
        host_clean = host_clean[:-1]

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
            alt_ip = parse_ip_numeric(host_clean)
            if alt_ip:
                norm_host = str(alt_ip)
            else:
                try:
                    idna_host = host_clean.encode('idna').decode('ascii')
                except Exception:
                    idna_host = host_clean
                if re.match(r'^[a-z0-9\-\.]+$', idna_host):
                    norm_host = idna_host

    return {
        "scheme": scheme,
        "port": port,
        "normalized_host": norm_host,
        "valid": bool(norm_host)
    }


def extract_url_components(target: str, default_protocol: str = "https", default_port: int = 443) -> Tuple[str, int]:
    """
    Extracts (protocol, port) from a target URL or host string using unified parse_url_authority_structure.
    """
    res = parse_url_authority_structure(target, default_protocol=default_protocol, default_port=default_port)
    return res["scheme"], res["port"]


@dataclass
class EgressPolicy:
    """
    Explicit, default-deny network egress policy binding allowed destinations,
    protocols, ports, and action categories.
    """
    allowed_destinations: Set[str] = field(default_factory=set)  # Exact hostnames or normalized IP strings
    allowed_wildcards: Set[str] = field(default_factory=set)     # Fully-qualified wildcard patterns, e.g. "*.api.github.com"
    allowed_protocols: Set[str] = field(default_factory=lambda: {"http", "https"})
    allowed_ports: Set[int] = field(default_factory=lambda: {80, 443})
    allowed_categories: Set[ActionCategory] = field(default_factory=lambda: {ActionCategory.READ_ONLY_LOCAL, ActionCategory.NETWORK_READ})
    allow_loopback: bool = False
    allow_private: bool = False

    def is_destination_allowed(self, hostname: str, protocol: str = "https", port: int = 443, category: Optional[ActionCategory] = None) -> Tuple[bool, str]:
        if category is not None and category not in self.allowed_categories:
            return False, f"Egress blocked: Action category '{category.value}' is not authorized by egress policy."

        if not self.allowed_destinations and not self.allowed_wildcards:
            return False, "Egress blocked: Absent or empty approved-egress policy."

        norm_host = normalize_destination_host(hostname)
        if not norm_host:
            return False, f"Egress blocked: Destination host '{hostname}' could not be normalized."

        eff_protocol, eff_port = extract_url_components(hostname, default_protocol=protocol, default_port=port)
        if eff_protocol.lower() not in self.allowed_protocols:
            return False, f"Egress blocked: Protocol '{eff_protocol}' is not authorized."

        if eff_port not in self.allowed_ports:
            return False, f"Egress blocked: Port '{eff_port}' is not authorized."

        if norm_host in self.allowed_destinations:
            return True, "Allowed by explicit destination match."

        for wildcard in self.allowed_wildcards:
            if wildcard.startswith("*."):
                suffix = wildcard[1:]  # e.g., ".api.github.com"
                if norm_host.endswith(suffix) and norm_host != suffix[1:]:
                    return True, f"Allowed by wildcard match '{wildcard}'."

        return False, f"Egress blocked: Destination host '{norm_host}' is not in approved egress policy."


def parse_ip_numeric(host_str: str) -> Optional[ipaddress.IPv4Address]:
    """
    Attempts to parse alternate numeric address encodings for IPv4
    (decimal integer, hex, octal, dotted octal, 1/2/3/4-part dword).
    """
    if not isinstance(host_str, str):
        return None
    clean = host_str.strip()
    if not clean:
        return None

    clean_no_dot = clean[:-1] if (clean.endswith('.') and len(clean) > 1 and not clean.startswith('.')) else clean

    # First try socket.inet_aton for standard C-library IPv4 representations
    try:
        raw = socket.inet_aton(clean_no_dot)
        return ipaddress.IPv4Address(raw)
    except Exception:
        pass

    # Single integer/hex/octal without 0o
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

    # Dotted representations with non-standard base encodings (e.g., 0177.0.0.1)
    parts = clean_no_dot.split(".")
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


def normalize_destination_host(target_url_or_host: str) -> str:
    """
    Strictly normalizes a target host/URL string into a canonical host representation using unified parse_url_authority_structure.
    Returns empty string if invalid or malformed authority.
    """
    res = parse_url_authority_structure(target_url_or_host)
    return res["normalized_host"]


class ContainmentGuard(ControlPlaneGate):
    """Active LLM Context & Tool Execution Guardrail Engine."""

    # Default Restricted Networks / Protocols
    DEFAULT_BLOCKED_HOSTS = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",  # AWS Metadata IP
        "metadata.google.internal",
    }

    # Default Forbidden Shell/System Operations for Code Agents
    DEFAULT_FORBIDDEN_COMMANDS = [
        r"\brm\b",
        r"rm\s+-rf",
        r"chmod\s+777",
        r"wget\s+",
        r"curl\s+",
        r"nc\s+-e",
        r"bash\s+-i",
        r"bash\s+-c",
        r"sh\s+-c",
        r"sudo\s+",
        r"python\s+-c\s+'import\s+socket",
        r"subprocess\.Popen",
        r"os\.system",
    ]

    DEFAULT_FORBIDDEN_COMMANDS_COMPILED = re.compile(
        "|".join(DEFAULT_FORBIDDEN_COMMANDS), re.IGNORECASE
    )

    # Pre-compile Injection Patterns
    INJECTION_PATTERNS_COMPILED = re.compile(
        "|".join([
            r"ignore\s+all\s+previous\s+instructions",
            r"disregard\s+the\s+above",
            r"you\s+are\s+now\s+in\s+DAN\s+mode",
            r"system\s*:\s*override",
            r"<\|im_start\|>\s*system",
            r"\]\s*;\s*DROP\s+TABLE",
        ]),
        re.IGNORECASE,
    )

    # Pre-compile System Delimiter Regex
    SYSTEM_DELIMITERS_REGEX = re.compile(r"<\|im_start\|>|<\|im_end\|>")

    # Pre-compile Goal Mutation Cheat Keywords
    CHEAT_KEYWORDS_COMPILED = re.compile(
        "|".join([
            r"assert\s+True",
            r"return\s+True\s+#\s*skip\s*test",
            r"sys\.exit\(0\)",
            r"unittest\.skip",
            r"pytest\.mark\.skip",
        ]),
        re.IGNORECASE,
    )

    def __init__(
        self,
        allowed_egress_domains: Optional[List[str]] = None,
        egress_policy: Optional[EgressPolicy] = None,
        blocked_hosts: Optional[Set[str]] = None,
        custom_forbidden_commands: Optional[List[str]] = None,
        strict_mode: bool = True,
        config: Optional[GateConfig] = None
    ):
        super().__init__(config=config or GateConfig(version="1.0.0", is_critical=True))
        self.allowed_domains = set(allowed_egress_domains or [])
        self.egress_policy = egress_policy
        if self.egress_policy is None:
            # Default unconfigured ContainmentGuard to an explicit EgressPolicy (deny-all unless configured)
            self.egress_policy = EgressPolicy(allowed_destinations=set(self.allowed_domains))

        self.blocked_hosts = blocked_hosts or self.DEFAULT_BLOCKED_HOSTS
        self.forbidden_commands_compiled = self.DEFAULT_FORBIDDEN_COMMANDS_COMPILED

        if custom_forbidden_commands:
            self.forbidden_commands_compiled = re.compile(
                self.DEFAULT_FORBIDDEN_COMMANDS_COMPILED.pattern + "|" + "|".join(custom_forbidden_commands),
                re.IGNORECASE
            )

        self.strict_mode = strict_mode

    def evaluate_contract(self, gate_input: GateInput) -> GateOutcome:
        t0 = time.perf_counter()
        payload = gate_input.payload
        context = gate_input.context

        all_inputs = [payload, context]
        extracted_strings, extracted_urls = self._extract_all_strings_and_urls(all_inputs)

        original_goal = context.get("original_goal") or (payload.get("original_goal") if isinstance(payload, dict) else getattr(payload, "original_goal", None))
        for str_val in extracted_strings:
            cmd_receipt = self.inspect_tool_command(str_val)
            if not cmd_receipt.passed:
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code=cmd_receipt.reason or "Forbidden command execution detected by ContainmentGuard",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"status": "HALTED", "confidence": 0.0, "vectors_revoked": 1},
                    latency_ms=(time.perf_counter() - t0) * 1000
                )

            if original_goal:
                goal_receipt = self.inspect_goal_integrity(original_goal, str_val)
                if not goal_receipt.passed:
                    return GateOutcome(
                        decision=GateDecision.HALT,
                        reason_code=goal_receipt.reason or "Goal integrity violation detected by ContainmentGuard",
                        gate_name=self.gate_name,
                        gate_version=self.config.version,
                        evidence={"status": "HALTED", "confidence": 0.0, "vectors_revoked": 1},
                        latency_ms=(time.perf_counter() - t0) * 1000
                    )

        for url_val in extracted_urls:
            egress_receipt = self.inspect_network_egress(url_val)
            if not egress_receipt.passed:
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code=egress_receipt.reason or "Unauthorized network egress attempt detected by ContainmentGuard",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"status": "HALTED", "confidence": 0.0, "vectors_revoked": 1},
                    latency_ms=(time.perf_counter() - t0) * 1000
                )

        return GateOutcome(
            decision=GateDecision.ALLOW,
            reason_code="CONTAINMENT_GUARDRAILS_PASSED",
            gate_name=self.gate_name,
            gate_version=self.config.version,
            evidence={"status": "ALLOWED"},
            latency_ms=(time.perf_counter() - t0) * 1000
        )

    def _is_restricted_target(self, hostname: str) -> bool:
        """Parses and checks if a hostname or IP resolves to private, loopback, or cloud metadata ranges."""
        if not hostname:
            return True

        norm_host = normalize_destination_host(hostname)
        if not norm_host:
            return True

        # Try parsing as IP address directly (including IPv4 mapped)
        try:
            ip = ipaddress.ip_address(norm_host)
            if getattr(ip, "ipv4_mapped", None):
                ip = ip.ipv4_mapped
            return (
                ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_unspecified
            )
        except ValueError:
            pass

        # Perform DNS resolution and verify ALL returned answers
        try:
            addr_info = socket.getaddrinfo(norm_host, None)
            if not addr_info:
                return True

            seen = set()
            for res in addr_info:
                ip_str = res[4][0]
                if ip_str in seen:
                    continue
                seen.add(ip_str)

                resolved_ip = ipaddress.ip_address(ip_str)
                if getattr(resolved_ip, "ipv4_mapped", None):
                    resolved_ip = resolved_ip.ipv4_mapped

                if (
                    resolved_ip.is_loopback
                    or resolved_ip.is_private
                    or resolved_ip.is_link_local
                    or resolved_ip.is_reserved
                    or resolved_ip.is_unspecified
                ):
                    return True
        except socket.gaierror:
            return True

        return False

    # =========================================================================
    # 1. INGRESS FILTERING (Prompt & Context Inspection)
    # =========================================================================

    def inspect_ingress_prompt(self, prompt_text: str) -> ContainmentReceipt:
        """Inspects user/planner input for prompt injection or system override attempts."""
        cleaned_prompt = prompt_text.strip()

        if match := self.INJECTION_PATTERNS_COMPILED.search(cleaned_prompt):
            return ContainmentReceipt(
                passed=False,
                violation_type=ContainmentViolationType.PROMPT_INJECTION_DETECTED,
                reason=f"Detected restricted prompt manipulation pattern: '{match.group(0)}'",
            )

        sanitized = self.SYSTEM_DELIMITERS_REGEX.sub("", cleaned_prompt)

        return ContainmentReceipt(
            passed=True,
            violation_type=ContainmentViolationType.NONE,
            sanitized_payload=sanitized,
        )

    # =========================================================================
    # 2. EGRESS & TOOL PARAMETER FILTERING
    # =========================================================================

    def _extract_hostname_secure(self, url: str) -> str:
        """Extracts the hostname securely using normalize_destination_host."""
        return normalize_destination_host(url)

    def inspect_network_egress(self, target_url: str) -> ContainmentReceipt:
        """Inspects outbound network attempts from agentic tools to prevent exfiltration or internal SSRF."""
        try:
            hostname = self._extract_hostname_secure(target_url)

            if not hostname:
                return ContainmentReceipt(
                    passed=False,
                    violation_type=ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT,
                    reason="Egress blocked: Missing or invalid target hostname.",
                )

            if hostname in self.blocked_hosts or self._is_restricted_target(hostname):
                return ContainmentReceipt(
                    passed=False,
                    violation_type=ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT,
                    reason=f"Egress blocked: Attempted access to internal/isolated host '{hostname}'.",
                )

            # Check explicit egress_policy if present
            if self.egress_policy is not None:
                allowed, msg = self.egress_policy.is_destination_allowed(hostname)
                if not allowed:
                    return ContainmentReceipt(
                        passed=False,
                        violation_type=ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT,
                        reason=msg,
                    )

            elif self.allowed_domains and hostname not in self.allowed_domains:
                return ContainmentReceipt(
                    passed=False,
                    violation_type=ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT,
                    reason=f"Egress blocked: Host '{hostname}' is not in allowed domain whitelist.",
                )

            return ContainmentReceipt(passed=True)

        except Exception as e:
            return ContainmentReceipt(
                passed=False,
                violation_type=ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT,
                reason=f"Malformed URL provided for egress: {str(e)}",
            )

    def inspect_tool_command(self, code_or_command: str) -> ContainmentReceipt:
        """Inspects generated code or shell execution commands for OS-level escape attempts."""
        if match := self.forbidden_commands_compiled.search(code_or_command):
            return ContainmentReceipt(
                passed=False,
                violation_type=ContainmentViolationType.FORBIDDEN_COMMAND_EXECUTION,
                reason=f"Command execution blocked: Contains restricted OS-level directive matching '{match.group(0)}'.",
            )

        return ContainmentReceipt(passed=True)

    @contextlib.contextmanager
    def _safe_dns_resolution(self):
        """Context manager to enforce DNS rebinding protection thread-safely."""
        token = _enforce_safe_dns.set(True)
        try:
            yield
        finally:
            _enforce_safe_dns.reset(token)

    # =========================================================================
    # 3. AGENTIC INTEGRITY & GOAL MUTATION FILTERING
    # =========================================================================

    def inspect_goal_integrity(
        self, original_goal: str, proposed_action: str
    ) -> ContainmentReceipt:
        """Detects whether an agent is attempting to alter its primary objective or cheat on evaluation tests."""
        if match := self.CHEAT_KEYWORDS_COMPILED.search(proposed_action):
            return ContainmentReceipt(
                passed=False,
                violation_type=ContainmentViolationType.GOAL_MUTATION_REWARD_CHEATING,
                reason=f"Reward-cheating attempt detected: Proposed action overrides test verification via '{match.group(0)}'.",
            )

        return ContainmentReceipt(passed=True)

    # =========================================================================
    # WRAPPER PIPELINE EXECUTER
    # =========================================================================

    @staticmethod
    def _is_candidate_destination(curr: str, key_context: str = "") -> bool:
        """Determines if a string argument represents a candidate network destination URL, host, host:port, or IP."""
        if not curr or not isinstance(curr, str):
            return False
        s = curr.strip()
        if not s:
            return False

        norm = normalize_destination_host(s)
        if not norm:
            return False

        if "://" in s or s.startswith("//") or s.startswith(("http://", "https://", "ftp://")):
            return True

        if "/" in s or ":" in s:
            return True

        try:
            ipaddress.ip_address(norm)
            return True
        except ValueError:
            pass

        if parse_ip_numeric(s) is not None:
            return True

        if re.search(r"\.[a-zA-Z]{2,}$", norm):
            if not norm.endswith((".py", ".txt", ".json", ".md", ".sh", ".csv", ".log", ".yaml", ".yml", ".html", ".css", ".js", ".png", ".jpg", ".pdf")):
                return True

        return False

    def _extract_all_strings_and_urls(self, arg: Any) -> Tuple[List[str], List[str]]:
        """Recursively extracts string representations and network URLs from arbitrary nested arguments."""
        strings = []
        urls = []
        stack = [(arg, "")]
        seen = set()

        while stack:
            curr, parent_key = stack.pop()
            curr_id = id(curr)
            if curr_id in seen:
                continue

            if type(curr) in (int, float, bool, type(None)):
                continue

            seen.add(curr_id)

            if isinstance(curr, str):
                strings.append(curr)
                if self._is_candidate_destination(curr, parent_key):
                    urls.append(curr)
            elif isinstance(curr, dict):
                for k, v in curr.items():
                    key_str = str(k) if isinstance(k, (str, int)) else ""
                    stack.append((v, key_str))
                    if isinstance(k, str):
                        stack.append((k, ""))
            elif isinstance(curr, (list, tuple, set, frozenset)):
                if isinstance(curr, (set, frozenset)):
                    scalar_items = sorted([str(x) for x in curr if type(x) in (str, int, float, bool)])
                else:
                    scalar_items = [str(x) for x in curr if type(x) in (str, int, float, bool)]
                if scalar_items and len(scalar_items) > 1:
                    strings.append(" ".join(scalar_items))
                for item in curr:
                    stack.append((item, parent_key))

        return strings, urls

    def wrap_tool_execution(
        self,
        tool_name: str,
        tool_func: Callable[..., Any],
        args: Optional[Tuple[Any, ...]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        original_goal: Optional[str] = None,
    ) -> Tuple[bool, Any, ContainmentReceipt]:
        """Wraps any tool call with active ingress, egress, and command containment checks across normalized positional and keyword arguments."""
        tool_args = args or ()
        tool_kwargs = kwargs or {}

        all_arg_values = list(tool_args) + list(tool_kwargs.values())
        extracted_strings, extracted_urls = self._extract_all_strings_and_urls(all_arg_values)

        for str_val in extracted_strings:
            cmd_receipt = self.inspect_tool_command(str_val)
            if not cmd_receipt.passed:
                return False, None, cmd_receipt

            if original_goal:
                goal_receipt = self.inspect_goal_integrity(original_goal, str_val)
                if not goal_receipt.passed:
                    return False, None, goal_receipt

        for url_val in extracted_urls:
            egress_receipt = self.inspect_network_egress(url_val)
            if not egress_receipt.passed:
                return False, None, egress_receipt

        try:
            broker = EgressTransportBroker(policy=self.egress_policy)
            with broker.enforce_socket_boundary():
                result = tool_func(*tool_args, **tool_kwargs)
            return True, result, ContainmentReceipt(passed=True)
        except Exception as e:
            err_msg = str(e)
            return (
                False,
                None,
                ContainmentReceipt(
                    passed=False,
                    violation_type=ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT if "Egress blocked" in err_msg else ContainmentViolationType.NONE,
                    reason=f"Tool transport error: {err_msg}",
                ),
            )


# =========================================================================
# CONTROLLED EGRESS TRANSPORT & RESOLVER ABSTRACTION
# =========================================================================

@dataclass
class EgressConnectionRecord:
    connection_id: str
    target_url: str
    normalized_host: str
    resolved_ip: Optional[str]
    allowed: bool
    reason: str
    timestamp: str


class EgressTransportBroker:
    """
    Registered transport abstraction enforcing egress policy at connection establishment time.
    Revalidates DNS resolution, performs IP pinning, checks redirects, and records egress events.
    """

    def __init__(
        self,
        policy: Optional[EgressPolicy] = None,
        resolver_func: Optional[Callable[[str], List[str]]] = None,
        provenance_store: Optional[Any] = None,
        require_infrastructure_enforcement: bool = False,
        infrastructure_enforced: bool = False
    ):
        self.policy = policy or EgressPolicy()
        self.resolver_func = resolver_func or self._default_resolver
        self.provenance_store = provenance_store
        self.require_infrastructure_enforcement = require_infrastructure_enforcement
        self.infrastructure_enforced = infrastructure_enforced
        self.connection_history: List[EgressConnectionRecord] = []

        if self.require_infrastructure_enforcement and not self.infrastructure_enforced:
            raise RuntimeError(
                "EgressTransportBroker initialization failed: Mandatory infrastructure-level network enforcement is missing."
            )

    def _default_resolver(self, hostname: str) -> List[str]:
        try:
            ip = ipaddress.ip_address(hostname)
            if getattr(ip, "ipv4_mapped", None):
                return [str(ip.ipv4_mapped)]
            return [str(ip)]
        except ValueError:
            pass

        try:
            results = socket.getaddrinfo(hostname, None)
            ips = []
            for res in results:
                ip_str = res[4][0]
                if ip_str not in ips:
                    ips.append(ip_str)
            return ips
        except Exception as e:
            raise socket.gaierror(f"DNS resolution failed for '{hostname}': {str(e)}")

    def _record_egress_event(
        self,
        correlation_id: str,
        request_id: str,
        action_name: str,
        target_url: str,
        normalized_host: str,
        resolved_ip: Optional[str],
        allowed: bool,
        reason: str
    ) -> None:
        rec = EgressConnectionRecord(
            connection_id=str(uuid.uuid4()),
            target_url=target_url,
            normalized_host=normalized_host,
            resolved_ip=resolved_ip,
            allowed=allowed,
            reason=reason,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        )
        self.connection_history.append(rec)

        if not allowed and self.provenance_store is not None:
            from epistemicos.provenance import ProvenanceEvent, ProvenanceEventType, ProvenanceSource
            event = ProvenanceEvent(
                schema_version="1.0.0",
                event_id=str(uuid.uuid4()),
                event_type=ProvenanceEventType.EGRESS_BLOCKED.value,
                provenance_source=ProvenanceSource.EGRESS_GATE.value,
                correlation_id=correlation_id,
                request_id=request_id,
                action_name=action_name,
                target=target_url,
                canonical_request_digest=hashlib.sha256(target_url.encode("utf-8")).hexdigest(),
                timestamp=rec.timestamp,
                outcome={"status": "EGRESS_BLOCKED", "reason": reason, "normalized_host": normalized_host, "resolved_ip": resolved_ip}
            )
            try:
                self.provenance_store.record_event(event)
            except Exception:
                pass

    def establish_connection(
        self,
        target_url: str,
        action_name: str = "network_request",
        correlation_id: str = "DEFAULT-CORR",
        request_id: str = "DEFAULT-REQ",
        category: Optional[ActionCategory] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Validates egress policy at connection time:
        1. Normalizes destination host
        2. Resolves DNS strictly via registered resolver
        3. Revalidates all resolved IPs against restricted IP ranges
        4. Validates normalized host against egress policy
        5. Returns (allowed, reason, pinned_ip)
        """
        norm_host = normalize_destination_host(target_url)
        if not norm_host:
            reason = "Egress blocked: Missing or invalid target destination."
            self._record_egress_event(correlation_id, request_id, action_name, target_url, "", None, False, reason)
            return False, reason, None

        # Resolve DNS via trusted resolver
        try:
            resolved_ips = self.resolver_func(norm_host)
        except Exception as resolver_err:
            reason = f"Egress blocked: Resolver error: {str(resolver_err)}"
            self._record_egress_event(correlation_id, request_id, action_name, target_url, norm_host, None, False, reason)
            return False, reason, None

        if not resolved_ips:
            reason = f"Egress blocked: Resolver returned zero IP addresses for host '{norm_host}'."
            self._record_egress_event(correlation_id, request_id, action_name, target_url, norm_host, None, False, reason)
            return False, reason, None

        # Check ALL returned IPs for restricted/private ranges
        restricted_found = []
        valid_ips = []
        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if getattr(ip_obj, "ipv4_mapped", None):
                    ip_obj = ip_obj.ipv4_mapped

                is_restricted = False
                if ip_obj.is_loopback:
                    if not (self.policy and self.policy.allow_loopback):
                        is_restricted = True
                elif ip_obj.is_private:
                    if not (self.policy and self.policy.allow_private):
                        is_restricted = True
                elif ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_unspecified:
                    is_restricted = True

                if is_restricted:
                    restricted_found.append(ip_str)
                else:
                    valid_ips.append(ip_str)
            except ValueError:
                restricted_found.append(ip_str)

        if restricted_found:
            reason = f"Egress blocked: DNS resolution for '{norm_host}' returned restricted IP(s) '{restricted_found}'."
            self._record_egress_event(correlation_id, request_id, action_name, target_url, norm_host, restricted_found[0], False, reason)
            return False, reason, None

        # Check policy
        allowed, pol_reason = self.policy.is_destination_allowed(target_url, category=category)
        if not allowed:
            self._record_egress_event(correlation_id, request_id, action_name, target_url, norm_host, valid_ips[0], False, pol_reason)
            return False, pol_reason, None

        # Pin first valid IP for connection
        pinned_ip = valid_ips[0]
        self._record_egress_event(correlation_id, request_id, action_name, target_url, norm_host, pinned_ip, True, pol_reason)
        return True, pol_reason, pinned_ip

    def revalidate_redirect(
        self,
        original_url: str,
        redirect_url: str,
        action_name: str = "network_redirect",
        correlation_id: str = "DEFAULT-CORR",
        request_id: str = "DEFAULT-REQ",
        category: Optional[ActionCategory] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """Re-validates a redirect target URL strictly before the redirected request is made."""
        return self.establish_connection(
            target_url=redirect_url,
            action_name=f"{action_name}_redirect",
            correlation_id=correlation_id,
            request_id=request_id,
            category=category
        )

    def wrap_callable(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Wraps a callable to copy the current contextvars context so child calls inherit active broker context."""
        ctx = contextvars.copy_context()
        def wrapper(*args, **kwargs):
            return ctx.run(func, *args, **kwargs)
        return wrapper

    def spawn_thread(self, target: Callable[..., Any], args: Tuple[Any, ...] = (), kwargs: Optional[Dict[str, Any]] = None) -> threading.Thread:
        """Spawns a thread carrying the current contextvars context so active egress policy is preserved in child thread."""
        wrapped = self.wrap_callable(lambda: target(*args, **(kwargs or {})))
        t = threading.Thread(target=wrapped)
        return t

    @contextlib.contextmanager
    def enforce_socket_boundary(
        self,
        correlation_id: str = "DEFAULT-CORR",
        request_id: str = "DEFAULT-REQ",
        action_name: str = "socket_connect",
        category: Optional[ActionCategory] = None
    ):
        """
        Thread-safe context manager patching socket.socket.connect and connect_ex
        during protected execution. Uses contextvars for active broker/policy context
        propagation so overlapping and concurrent contexts across threads and nested calls
        dispatch to their own correct policy and emit provenance events with their own correlation/request IDs.
        """
        global _active_boundary_count, _orig_socket_connect, _orig_socket_connect_ex

        def _is_inet_family(sock_self) -> bool:
            family = getattr(sock_self, "family", socket.AF_INET)
            return family in (socket.AF_INET, getattr(socket, "AF_INET6", socket.AF_INET))

        def _patched_connect_internal(sock_self, address, is_connect_ex=False):
            if not _is_inet_family(sock_self):
                if is_connect_ex:
                    return _orig_socket_connect_ex(sock_self, address)
                return _orig_socket_connect(sock_self, address)

            active_ctx = _active_broker_context.get()
            if not active_ctx:
                err_msg = "Egress blocked: Uncontexted thread socket connection attempt inside active protected boundary."
                if is_connect_ex:
                    return errno.EACCES
                raise socket.error(err_msg)

            dispatch_broker = active_ctx["broker"]
            dispatch_corr = active_ctx.get("correlation_id", correlation_id)
            dispatch_req = active_ctx.get("request_id", request_id)
            dispatch_act = active_ctx.get("action_name", action_name)
            dispatch_cat = active_ctx.get("category", category)

            if isinstance(address, (tuple, list)) and len(address) >= 2:
                target_host, target_port = str(address[0]), int(address[1])
                allowed, reason, pinned_ip = dispatch_broker.establish_connection(
                    target_url=f"{target_host}:{target_port}",
                    action_name=dispatch_act,
                    correlation_id=dispatch_corr,
                    request_id=dispatch_req,
                    category=dispatch_cat
                )
                if not allowed:
                    err_msg = f"Egress blocked: Socket connection to '{target_host}:{target_port}' denied by policy ({reason})."
                    if is_connect_ex:
                        return errno.EACCES
                    raise socket.error(err_msg)
                if pinned_ip and not target_host.startswith("["):
                    new_addr = (pinned_ip, target_port) + tuple(address[2:])
                    if is_connect_ex:
                        return _orig_socket_connect_ex(sock_self, new_addr)
                    return _orig_socket_connect(sock_self, new_addr)

            if is_connect_ex:
                return _orig_socket_connect_ex(sock_self, address)
            return _orig_socket_connect(sock_self, address)

        def _patched_connect(sock_self, address):
            return _patched_connect_internal(sock_self, address, is_connect_ex=False)

        def _patched_connect_ex(sock_self, address):
            return _patched_connect_internal(sock_self, address, is_connect_ex=True)

        ctx_info = {
            "broker": self,
            "correlation_id": correlation_id,
            "request_id": request_id,
            "action_name": action_name,
            "category": category,
            "thread_id": threading.get_ident()
        }
        ctx_token = _active_broker_context.set(ctx_info)

        with _boundary_lock:
            global _active_boundary_count
            if _active_boundary_count == 0:
                _orig_socket_connect = socket.socket.connect
                _orig_socket_connect_ex = socket.socket.connect_ex
                socket.socket.connect = _patched_connect
                socket.socket.connect_ex = _patched_connect_ex
            _active_boundary_count += 1

        token = _enforce_safe_dns.set(True)
        try:
            yield
        finally:
            _enforce_safe_dns.reset(token)
            _active_broker_context.reset(ctx_token)
            with _boundary_lock:
                _active_boundary_count -= 1
                if _active_boundary_count <= 0:
                    _active_boundary_count = 0
                    socket.socket.connect = _orig_socket_connect
                    socket.socket.connect_ex = _orig_socket_connect_ex


import http.client
import ssl


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP Connection connecting directly to pinned_ip while sending Host: norm_host."""
    def __init__(self, norm_host: str, pinned_ip: Optional[str] = None, port: Optional[int] = None, timeout: float = 10.0):
        super().__init__(norm_host, port=port or 80, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self):
        connect_target = self.pinned_ip if self.pinned_ip else self.host
        self.sock = self._create_connection(
            (connect_target, self.port),
            self.timeout,
            self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS Connection connecting directly to pinned_ip with SNI and cert verification for norm_host."""
    def __init__(
        self,
        norm_host: str,
        pinned_ip: Optional[str] = None,
        port: Optional[int] = None,
        timeout: float = 10.0,
        context: Optional[ssl.SSLContext] = None
    ):
        super().__init__(norm_host, port=port or 443, timeout=timeout, context=context)
        self.pinned_ip = pinned_ip

    def connect(self):
        connect_target = self.pinned_ip if self.pinned_ip else self.host
        self.sock = self._create_connection(
            (connect_target, self.port),
            self.timeout,
            self.source_address
        )
        if self._tunnel_host:
            self._tunnel()
        ctx = getattr(self, "_context", None) or getattr(self, "context", None)
        if ctx is None:
            ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)


class ControlledEgressTransport:
    """
    Authoritative transport-level client wrapper enforcing EgressTransportBroker policy,
    DNS re-validation, connection-time IP pinning, and redirect re-validation.
    """

    def __init__(
        self,
        broker: Optional[EgressTransportBroker] = None,
        policy: Optional[EgressPolicy] = None,
        timeout: float = 10.0
    ):
        if broker is not None:
            self.broker = broker
        else:
            self.broker = EgressTransportBroker(policy=policy or EgressPolicy())
        self.timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Union[bytes, str]] = None,
        timeout: Optional[float] = None,
        correlation_id: str = "DEFAULT-CORR",
        request_id: str = "DEFAULT-REQ",
        category: Optional[ActionCategory] = None,
        max_redirects: int = 5,
        redirect_handler: Optional[Callable[[str], Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Executes an outbound HTTP request through transport-boundary policy enforcement.
        Validates initial destination, performs real HTTP network I/O bound to the pinned IP,
        and re-validates every redirect hop before opening subsequent connections.
        """
        from urllib.parse import urlsplit, urljoin

        eff_timeout = timeout if timeout is not None else self.timeout
        if eff_timeout is not None and eff_timeout <= 0:
            raise ValueError(f"Timeout must be a positive number, got {eff_timeout}")

        current_url = url
        current_method = method.upper()
        current_headers = dict(headers or {})
        redirect_count = 0

        while True:
            allowed, reason, pinned_ip = self.broker.establish_connection(
                target_url=current_url,
                action_name=f"http_{current_method.lower()}",
                correlation_id=correlation_id,
                request_id=request_id,
                category=category
            )
            if not allowed:
                raise PermissionError(f"Egress transport blocked request to '{current_url}': {reason}")

            if redirect_handler:
                res = redirect_handler(current_url)
            else:
                parsed = urlsplit(current_url)
                scheme = parsed.scheme.lower() or "http"
                norm_host = normalize_destination_host(current_url)
                eff_protocol, eff_port = extract_url_components(current_url, default_protocol=scheme)
                path_and_query = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

                req_headers = dict(current_headers)
                if "Host" not in req_headers and "host" not in req_headers:
                    req_headers["Host"] = norm_host

                try:
                    if scheme == "https":
                        ssl_ctx = ssl.create_default_context()
                        conn = PinnedHTTPSConnection(
                            norm_host=norm_host,
                            pinned_ip=pinned_ip,
                            port=eff_port,
                            timeout=eff_timeout,
                            context=ssl_ctx
                        )
                    else:
                        conn = PinnedHTTPConnection(
                            norm_host=norm_host,
                            pinned_ip=pinned_ip,
                            port=eff_port,
                            timeout=eff_timeout
                        )
                    encoded_body = body.encode("utf-8") if isinstance(body, str) else body
                    conn.request(current_method, path_and_query, body=encoded_body, headers=req_headers)
                    resp = conn.getresponse()
                    resp_data = resp.read()
                    resp_headers = {k: v for k, v in resp.getheaders()}
                    conn.close()

                    res = {
                        "status": resp.status,
                        "reason": resp.reason,
                        "url": current_url,
                        "pinned_ip": pinned_ip,
                        "headers": resp_headers,
                        "body": resp_data
                    }
                except Exception as net_err:
                    raise socket.error(f"Egress transport network I/O error to '{current_url}': {str(net_err)}") from net_err

            loc = res.get("headers", {}).get("Location") or res.get("headers", {}).get("location")
            if res.get("status") in (301, 302, 303, 307, 308) and loc:
                redirect_count += 1
                if redirect_count > max_redirects:
                    raise PermissionError(f"Egress transport blocked: Exceeded maximum redirect limit of {max_redirects}")

                next_url = urljoin(current_url, loc)
                redir_allowed, redir_reason, redir_ip = self.broker.revalidate_redirect(
                    original_url=current_url,
                    redirect_url=next_url,
                    correlation_id=correlation_id,
                    request_id=request_id,
                    category=category
                )
                if not redir_allowed:
                    raise PermissionError(f"Egress transport blocked redirect to '{next_url}': {redir_reason}")

                current_url = next_url
                if res.get("status") in (301, 302, 303):
                    current_method = "GET"
                    body = None
                continue

            return res

    def urlopen(
        self,
        url: str,
        data: Optional[bytes] = None,
        timeout: Optional[float] = None,
        correlation_id: str = "DEFAULT-CORR",
        request_id: str = "DEFAULT-REQ",
        category: Optional[ActionCategory] = None
    ) -> Dict[str, Any]:
        method = "POST" if data is not None else "GET"
        return self.request(
            method=method,
            url=url,
            body=data,
            timeout=timeout,
            correlation_id=correlation_id,
            request_id=request_id,
            category=category
        )
