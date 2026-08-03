"""
EpistemicOS V1 - ContainmentGuard Module
----------------------------------------
Provides active ingress, egress, and tool-execution guardrails to prevent:
1. Prompt Injections & Jailbreaks (Ingress)
2. Unauthorized Network Egress & Unsafe Tool Parameters (Egress)
3. Agent Containment Escape / Goal Mutation (Agentic Integrity)
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


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
    DEFAULT_FORBIDDEN_COMMANDS = {
        r"rm\s+-rf",
        r"chmod\s+777",
        r"wget\s+",
        r"curl\s+",
        r"nc\s+-e",
        r"bash\s+-i",
        r"python\s+-c\s+'import\s+socket",
        r"subprocesses?\.Popen",
        r"os\.system",
    }

    # Common Jailbreak and System Override Patterns
    INJECTION_PATTERNS = [
        r"ignore\s+all\s+previous\s+instructions",
        r"disregard\s+the\s+above",
        r"you\s+are\n+now\s+in\s+DAN\s+mode",
        r"system\s*:\s*override",
        r"<\|im_start\|>\s*system",
        r"\]\s*;\s*DROP\s+TABLE",
    ]

    def __init__(
        self,
        allowed_egress_domains: Optional[List[str]] = None,
        blocked_hosts: Optional[Set[str]] = None,
        custom_forbidden_commands: Optional[List[str]] = None,
        strict_mode: bool = True,
    ):
        self.allowed_domains = set(allowed_egress_domains or [])
        self.blocked_hosts = blocked_hosts or self.DEFAULT_BLOCKED_HOSTS
        self.forbidden_commands = set(self.DEFAULT_FORBIDDEN_COMMANDS)
        if custom_forbidden_commands:
            self.forbidden_commands.update(custom_forbidden_commands)
        self.strict_mode = strict_mode

    # =========================================================================
    # 1. INGRESS FILTERING (Prompt & Context Inspection)
    # =========================================================================

    def inspect_ingress_prompt(self, prompt_text: str) -> ContainmentReceipt:
        """Inspects user/planner input for prompt injection or system override attempts."""
        cleaned_prompt = prompt_text.strip()

        # Check against injection/jailbreak patterns
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, cleaned_prompt, re.IGNORECASE):
                return ContainmentReceipt(
                    passed=False,
                    violation_type=ContainmentViolationType.PROMPT_INJECTION_DETECTED,
                    reason=f"Detected restricted prompt manipulation pattern: '{pattern}'",
                )

        # Sanitize raw system delimiters if injected into user prompt
        sanitized = re.sub(
            r"<\|im_start\|>|<\|im_end\|>", "", cleaned_prompt
        )

        return ContainmentReceipt(
            passed=True,
            violation_type=ContainmentViolationType.NONE,
            sanitized_payload=sanitized,
        )

    # =========================================================================
    # 2. EGRESS & TOOL PARAMETER FILTERING
    # =========================================================================

    def inspect_network_egress(self, target_url: str) -> ContainmentReceipt:
        """Inspects outbound network attempts from agentic tools to prevent exfiltration or internal SSRF."""
        try:
            parsed = urllib.parse.urlparse(target_url)
            hostname = parsed.hostname.lower() if parsed.hostname else ""

            # 1. Block Local/Metadata SSRF Targets
            if hostname in self.blocked_hosts or any(
                hostname.startswith(b) for b in ["127.", "10.", "172.16.", "192.168."]
            ):
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
        for pattern in self.forbidden_commands:
            if re.search(pattern, code_or_command, re.IGNORECASE):
                return ContainmentReceipt(
                    passed=False,
                    violation_type=ContainmentViolationType.FORBIDDEN_COMMAND_EXECUTION,
                    reason=f"Command execution blocked: Contains restricted OS-level directive matching '{pattern}'.",
                )

        return ContainmentReceipt(passed=True)

    # =========================================================================
    # 3. AGENTIC INTEGRITY & GOAL MUTATION FILTERING
    # =========================================================================

    def inspect_goal_integrity(
        self, original_goal: str, proposed_action: str
    ) -> ContainmentReceipt:
        """Detects whether an agent is attempting to alter its primary objective or cheat on evaluation tests."""
        # Detect attempts to edit test harnesses or evaluation scripts
        cheat_keywords = [
            r"assert\s+True",
            r"return\s+True\s+#\s*skip\s*test",
            r"sys\.exit\(0\)",
            r"unittest\.skip",
            r"pytest\.mark\.skip",
        ]

        for kw in cheat_keywords:
            if re.search(kw, proposed_action, re.IGNORECASE):
                return ContainmentReceipt(
                    passed=False,
                    violation_type=ContainmentViolationType.GOAL_MUTATION_REWARD_CHEATING,
                    reason=f"Reward-cheating attempt detected: Proposed action overrides test verification via '{kw}'.",
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
