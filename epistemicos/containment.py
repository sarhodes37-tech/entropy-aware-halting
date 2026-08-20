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
import string
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


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
        r"rm\s+-rf",
        r"chmod\s+777",
        r"wget\s+",
        r"curl\s+",
        r"nc\s+-e",
        r"bash\s+-i",
        r"python\s+-c\s+'import\s+socket",
        r"subprocess\.Popen",  # Fixed typo (was subprocesses?)
        r"os\.system",
    ]

    DEFAULT_FORBIDDEN_COMMANDS_COMPILED = [
        re.compile("|".join(DEFAULT_FORBIDDEN_COMMANDS), re.IGNORECASE)
    ]

    # Pre-compile Injection Patterns (Fix for Ingress Prompt Inspection Loop)
    INJECTION_PATTERNS_COMPILED = re.compile("|".join([
        r"ignore\s+all\s+previous\s+instructions",
        r"disregard\s+the\s+above",
        r"you\s+are\s+now\s+in\s+DAN\s+mode",  # Fixed \n+ to \s+
        r"system\s*:\s*override",
        r"<\|im_start\|>\s*system",
        r"\]\s*;\s*DROP\s+TABLE",
    ]), re.IGNORECASE)


    # Pre-compile System Delimiter Regex (Fix for String Substitution)
    SYSTEM_DELIMITERS_REGEX = re.compile(r"<\|im_start\|>|<\|im_end\|>")

    # Pre-compile Goal Mutation Cheat Keywords (Fix for Goal Integrity Validation)
    CHEAT_KEYWORDS_COMPILED = re.compile("|".join([
        r"assert\s+True",
        r"return\s+True\s+#\s*skip\s*test",
        r"sys\.exit\(0\)",
        r"unittest\.skip",
        r"pytest\.mark\.skip",
    ]), re.IGNORECASE)

    def __init__(
        self,
        allowed_egress_domains: Optional[List[str]] = None,
        blocked_hosts: Optional[Set[str]] = None,
        custom_forbidden_commands: Optional[List[str]] = None,
        strict_mode: bool = True,
    ):
        self.allowed_domains = set(allowed_egress_domains or [])
        self.blocked_hosts = blocked_hosts or self.DEFAULT_BLOCKED_HOSTS
        
        self.forbidden_commands_compiled = list(self.DEFAULT_FORBIDDEN_COMMANDS_COMPILED)
        if custom_forbidden_commands:
            self.forbidden_commands_compiled.append(
                re.compile("|".join(custom_forbidden_commands), re.IGNORECASE)
            )
        
        self.strict_mode = strict_mode

    def _is_restricted_target(self, hostname: str) -> bool:
        """Parses and checks if a hostname or IP resolves to private, loopback, or cloud metadata ranges."""
        if not hostname:
            return True

        # 1. Direct IP parsing (handles hex, octal, integer, and standard IPv4/IPv6 literals)
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
            pass  # Hostname is a domain name, proceed to DNS resolution

        # 2. Resolve DNS hostnames to verify underlying IP destinations
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for res in addr_info:
                resolved_ip = ipaddress.ip_address(res[4][0])
                if (
                    resolved_ip.is_loopback
                    or resolved_ip.is_private
                    or resolved_ip.is_link_local
                    or resolved_ip.is_reserved
                    or resolved_ip.is_unspecified
                ):
                    return True
        except socket.gaierror:
            # Block hostnames that fail DNS resolution as a safety measure
            return True

        return False

    # =========================================================================
    # 1. INGRESS FILTERING (Prompt & Context Inspection)
    # =========================================================================

    def inspect_ingress_prompt(self, prompt_text: str) -> ContainmentReceipt:
        """Inspects user/planner input for prompt injection or system override attempts."""
        cleaned_prompt = prompt_text.strip()

        # Check against compiled injection/jailbreak patterns
        if match := self.INJECTION_PATTERNS_COMPILED.search(cleaned_prompt):
            return ContainmentReceipt(
                passed=False,
                violation_type=ContainmentViolationType.PROMPT_INJECTION_DETECTED,
                reason=f"Detected restricted prompt manipulation pattern: '{match.group(0)}'",
            )

        # Sanitize raw system delimiters if injected into user prompt
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
        """Extracts the hostname securely to prevent SSRF bypasses via URL parsing inconsistencies."""
        try:
            # 1. Strip whitespace and normalize backslashes
            url = url.strip()
            url_norm = url.replace('\\', '/')

            # 2. Parse URL
            parsed = urllib.parse.urlsplit(url_norm)

            # 3. Unquote the netloc to prevent URL-encoding bypasses (e.g. %40 for @)
            decoded_netloc = urllib.parse.unquote(parsed.netloc)

            # 4. Remove any whitespace characters injected into the netloc (requests strips these)
            for ws in string.whitespace:
                decoded_netloc = decoded_netloc.replace(ws, '')

            # 5. Extract host port part by splitting at last @
            if '@' in decoded_netloc:
                host_port = decoded_netloc.rsplit('@', 1)[-1]
            else:
                host_port = decoded_netloc

            # 6. Remove port if present, safely handling IPv6
            # An IPv6 address is enclosed in brackets, e.g., [::1] or [::1]:80
            if host_port.startswith('['):
                end_bracket = host_port.find(']')
                if end_bracket != -1:
                    hostname = host_port[1:end_bracket]
                else:
                    hostname = host_port
            else:
                if ':' in host_port:
                    hostname = host_port.rsplit(':', 1)[0]
                else:
                    hostname = host_port

            return hostname.lower()
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

            # 1. Block Local/Metadata SSRF Targets via static list & robust IP/DNS resolution
            if hostname in self.blocked_hosts or self._is_restricted_target(hostname):
                return ContainmentReceipt(
                    passed=False,
                    violation_type=ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT,
                    reason=f"Egress blocked: Attempted access to internal/isolated host '{hostname}'.",
                )

            # 2. Enforce Allowed Domains Whitelist (if configured)
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
        for pattern in self.forbidden_commands_compiled:
            if match := pattern.search(code_or_command):
                return ContainmentReceipt(
                    passed=False,
                    violation_type=ContainmentViolationType.FORBIDDEN_COMMAND_EXECUTION,
                    reason=f"Command execution blocked: Contains restricted OS-level directive matching '{match.group(0)}'.",
                )

        return ContainmentReceipt(passed=True)

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

    def wrap_tool_execution(
        self,
        tool_name: str,
        tool_func: Callable[..., Any],
        kwargs: Dict[str, Any],
        original_goal: Optional[str] = None,
    ) -> Tuple[bool, Any, ContainmentReceipt]:
        """Wraps any tool call with active ingress, egress, and command containment checks."""

        # 1. Parameter Inspection
        command_str = str(kwargs.get("command", "")) or str(kwargs.get("script", ""))
        if command_str:
            cmd_receipt = self.inspect_tool_command(command_str)
            if not cmd_receipt.passed:
                return False, None, cmd_receipt

            if original_goal:
                goal_receipt = self.inspect_goal_integrity(original_goal, command_str)
                if not goal_receipt.passed:
                    return False, None, goal_receipt

        url_str = str(kwargs.get("url", "")) or str(kwargs.get("endpoint", ""))
        if url_str:
            egress_receipt = self.inspect_network_egress(url_str)
            if not egress_receipt.passed:
                return False, None, egress_receipt

        # 2. Safe Tool Execution
        try:
            result = tool_func(**kwargs)
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
