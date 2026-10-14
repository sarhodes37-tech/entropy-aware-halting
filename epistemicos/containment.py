"""
EpistemicOS V1 - ContainmentGuard Module
----------------------------------------
Provides active ingress, egress, and tool-execution guardrails to prevent:
1. Prompt Injections & Jailbreaks (Ingress)
2. Unauthorized Network Egress & Unsafe Tool Parameters (Egress)
3. Agent Containment Escape / Goal Mutation (Agentic Integrity)
"""

import ipaddress
import re
import socket
import contextlib
import contextvars
from urllib.parse import urlsplit, unquote
from functools import lru_cache
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


_enforce_safe_dns = contextvars.ContextVar("enforce_safe_dns", default=False)
_original_getaddrinfo = socket.getaddrinfo

def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    results = _original_getaddrinfo(host, port, family, type, proto, flags)
    if _enforce_safe_dns.get():
        for res in results:
            ip_str = res[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
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


@dataclass
class ContainmentReceipt:
    passed: bool
    violation_type: ContainmentViolationType = ContainmentViolationType.NONE
    reason: Optional[str] = None
    sanitized_payload: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)



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
        blocked_hosts: Optional[Set[str]] = None,
        custom_forbidden_commands: Optional[List[str]] = None,
        strict_mode: bool = True,
    ):
        self.allowed_domains = set(allowed_egress_domains or [])
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

        try:
            ip = ipaddress.ip_address(hostname)
            return (
                ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_unspecified
            )
        except ValueError:
            pass

        try:
            addr_info = socket.getaddrinfo(hostname, None)
            seen = set()
            for res in addr_info:
                ip_str = res[4][0]
                if ip_str in seen:
                    continue
                seen.add(ip_str)

                resolved_ip = ipaddress.ip_address(ip_str)
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
        """Extracts the hostname securely using urllib.parse to prevent SSRF bypasses via URL parsing inconsistencies."""
        if not isinstance(url, str):
            return ""
        try:
            url = url.strip()
            if not url:
                return ""

            url_norm = url.replace('\\', '/')

            # Reject URLs containing '#' or '%23' in the authority portion before path or query
            if "://" in url_norm:
                scheme_rest = url_norm.split("://", 1)[1]
            elif url_norm.startswith("//"):
                scheme_rest = url_norm[2:]
            else:
                scheme_rest = url_norm

            authority_part = scheme_rest.split("/", 1)[0].split("?", 1)[0]
            if "#" in authority_part or "%23" in authority_part.lower():
                return ""

            parsed = urlsplit(url_norm)

            # urllib.parse.urlsplit parsed.hostname extracts hostname, strips userinfo and port,
            # strips brackets from IPv6, and handles lowercase.
            hostname = parsed.hostname
            if not hostname:
                return ""

            hostname = hostname.lower().strip()

            # Reject whitespace inside hostname
            if any(c.isspace() for c in hostname):
                return ""

            # Validate character set (alphanumeric, hyphens, dots, and colons for unbracketed IPv6)
            if not re.match(r'^[a-zA-Z0-9\-\.\:]+$', hostname):
                return ""

            return hostname
        except Exception:
            return ""

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

            if self.allowed_domains and hostname not in self.allowed_domains:
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
