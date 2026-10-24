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


_enforce_safe_dns = contextvars.ContextVar("enforce_safe_dns", default=False)
_original_getaddrinfo = socket.getaddrinfo

def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """
    Optional process-wide compatibility wrapper for legacy code.
    Note: Transport-boundary egress enforcement is performed directly by ControlledEgressTransport / EgressTransportBroker.
    """
    results = _original_getaddrinfo(host, port, family, type, proto, flags)
    if _enforce_safe_dns.get():
        for res in results:
            ip_str = res[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if getattr(ip, "ipv4_mapped", None):
                    ip = ip.ipv4_mapped
                if (
                    ip.is_loopback
                    or ip.is_private
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_unspecified
                ):
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

        if protocol.lower() not in self.allowed_protocols:
            return False, f"Egress blocked: Protocol '{protocol}' is not authorized."

        if port not in self.allowed_ports:
            return False, f"Egress blocked: Port '{port}' is not authorized."

        norm_host = normalize_destination_host(hostname)
        if not norm_host:
            return False, f"Egress blocked: Destination host '{hostname}' could not be normalized."

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
    (decimal integer, hex, octal, dotted octal).
    """
    clean = host_str.strip()
    if not clean:
        return None

    # Handle single integer or hex or octal value
    if re.match(r'^(0x[0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$', clean):
        try:
            val = int(clean, 0) if (clean.startswith("0x") or (clean.startswith("0") and len(clean) > 1)) else int(clean)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass

    # Handle dotted representations with non-standard base encodings (e.g., 0177.0.0.1)
    parts = clean.split(".")
    if len(parts) == 4:
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
    Strictly normalizes a target host/URL string into a canonical host representation.
    Handles userinfo, userinfo with `#` or `%23` bypass tricks, IPv6 brackets,
    percent-encoded delimiters, alternate numeric IP encodings, trailing dots,
    and converts scheme-rest to lower case.
    Returns empty string if invalid or malformed authority.
    """
    if not isinstance(target_url_or_host, str):
        return ""

    raw = target_url_or_host.strip()
    if not raw:
        return ""

    # Replace backslashes with forward slashes before parsing
    norm = raw.replace('\\', '/')

    # Handle scheme or schemeless URL structure
    if "://" in norm:
        scheme_rest = norm.split("://", 1)[1]
    elif norm.startswith("//"):
        scheme_rest = norm[2:]
    else:
        scheme_rest = norm

    # Extract authority part before path or query
    authority_part = scheme_rest.split("/", 1)[0].split("?", 1)[0]
    if not authority_part:
        return ""

    # Reject URLs containing '#' or '%23' in authority part before path or query
    if "#" in authority_part or "%23" in authority_part.lower():
        return ""

    # Unquote percent-encoded characters in authority part
    unquoted_auth = unquote(authority_part)
    if "#" in unquoted_auth:
        return ""

    # Handle userinfo (e.g. user:pass@hostname)
    if "@" in unquoted_auth:
        host_port = unquoted_auth.rsplit("@", 1)[1]
    else:
        host_port = unquoted_auth

    # Strip port if present
    if host_port.startswith("["):
        # Bracketed IPv6
        if "]" not in host_port:
            return ""
        host_part = host_port.split("]", 1)[0] + "]"
    else:
        host_part = host_port.split(":", 1)[0]

    host_clean = host_part.strip().lower()

    # Strip trailing dot if present (DNS FQDN dot)
    if host_clean.endswith(".") and len(host_clean) > 1:
        host_clean = host_clean[:-1]

    if not host_clean:
        return ""

    # Reject whitespace
    if any(c.isspace() for c in host_clean):
        return ""

    # IPv6 bracketed handling
    if host_clean.startswith("[") and host_clean.endswith("]"):
        inner = host_clean[1:-1]
        try:
            ip = ipaddress.ip_address(inner)
            if getattr(ip, "ipv4_mapped", None):
                return str(ip.ipv4_mapped)
            return str(ip)
        except ValueError:
            return ""

    # Check for direct IPv4 / IPv6 or alternate numeric IP encodings
    try:
        ip = ipaddress.ip_address(host_clean)
        return str(ip)
    except ValueError:
        alt_ip = parse_ip_numeric(host_clean)
        if alt_ip:
            return str(alt_ip)

    # Validate standard domain name character set
    if not re.match(r'^[a-z0-9\-\.]+$', host_clean):
        return ""

    return host_clean


class ContainmentGuard:
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
    ):
        self.allowed_domains = set(allowed_egress_domains or [])
        self.egress_policy = egress_policy
        if self.egress_policy is None and allowed_egress_domains is not None:
            self.egress_policy = EgressPolicy(allowed_destinations=set(allowed_egress_domains))

        self.blocked_hosts = blocked_hosts or self.DEFAULT_BLOCKED_HOSTS
        self.forbidden_commands_compiled = self.DEFAULT_FORBIDDEN_COMMANDS_COMPILED

        if custom_forbidden_commands:
            self.forbidden_commands_compiled = re.compile(
                self.DEFAULT_FORBIDDEN_COMMANDS_COMPILED.pattern + "|" + "|".join(custom_forbidden_commands),
                re.IGNORECASE
            )

        self.strict_mode = strict_mode

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

    def _extract_all_strings_and_urls(self, arg: Any) -> Tuple[List[str], List[str]]:
        """Recursively extracts string representations and network URLs from arbitrary nested arguments."""
        strings = []
        urls = []
        stack = [arg]
        seen = set()

        while stack:
            curr = stack.pop()
            curr_id = id(curr)
            if curr_id in seen:
                continue

            if type(curr) in (int, float, bool, type(None)):
                continue

            seen.add(curr_id)

            if isinstance(curr, str):
                strings.append(curr)
                if "://" in curr or curr.startswith(("http://", "https://", "ftp://")):
                    urls.append(curr)
            elif isinstance(curr, dict):
                for k, v in curr.items():
                    stack.append(v)
                    if isinstance(k, str):
                        stack.append(k)
            elif isinstance(curr, (list, tuple, set, frozenset)):
                if isinstance(curr, (set, frozenset)):
                    scalar_items = sorted([str(x) for x in curr if type(x) in (str, int, float, bool)])
                else:
                    scalar_items = [str(x) for x in curr if type(x) in (str, int, float, bool)]
                if scalar_items and len(scalar_items) > 1:
                    strings.append(" ".join(scalar_items))
                for item in curr:
                    stack.append(item)

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
            with self._safe_dns_resolution():
                result = tool_func(*tool_args, **tool_kwargs)
            return True, result, ContainmentReceipt(passed=True)
        except Exception as e:
            return (
                False,
                None,
                ContainmentReceipt(
                    passed=False,
                    violation_type=ContainmentViolationType.NONE,
                    reason=f"Tool transport error: {str(e)}",
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

                if (
                    ip_obj.is_loopback
                    or ip_obj.is_private
                    or ip_obj.is_link_local
                    or ip_obj.is_reserved
                    or ip_obj.is_unspecified
                ):
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
        allowed, pol_reason = self.policy.is_destination_allowed(norm_host, category=category)
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
