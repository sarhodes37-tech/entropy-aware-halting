"""
Stage D: Context Minimization Broker for Shower Curtain.

Supplies only the user context necessary for the task, performing selective
retrieval, relevance/sensitivity classification, and provenance tracking.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class ContextChunk:
    chunk_id: str
    content: str
    source: str  # e.g., "conversation_history", "local_file", "memory"
    relevance_score: float  # 0.0 to 1.0
    sensitivity_score: float  # 0.0 to 1.0
    disclosed_remotely: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContextMinimizationBroker:
    """
    Broker supplying minimal necessary context for a given task,
    tracking provenance and distinguishing local vs remote context.
    """

    def __init__(
        self,
        max_context_tokens: int = 2048,
        min_relevance_threshold: float = 0.3,
        max_sensitivity_threshold: float = 0.8,
        max_history_messages: int = 10
    ):
        self.max_context_tokens = max_context_tokens
        self.min_relevance_threshold = min_relevance_threshold
        self.max_sensitivity_threshold = max_sensitivity_threshold
        self.max_history_messages = max_history_messages

    def filter_context_chunks(
        self,
        chunks: List[ContextChunk]
    ) -> List[ContextChunk]:
        """
        Selects minimal necessary chunks based on relevance, sensitivity, and token budgets.
        Strictly excludes chunks exceeding max_sensitivity_threshold regardless of relevance.
        First enforces hard eligibility checks, then ranks permitted chunks by relevance and utility.
        """
        if not chunks:
            return []

        # 1. Enforce hard eligibility checks: relevance must meet threshold and sensitivity must NOT exceed threshold
        permitted = []
        for c in chunks:
            if c.sensitivity_score > self.max_sensitivity_threshold:
                continue
            if c.relevance_score < self.min_relevance_threshold:
                continue
            permitted.append(c)

        # 2. Rank permitted chunks by relevance descending, then sensitivity ascending
        permitted.sort(key=lambda c: (c.relevance_score, -c.sensitivity_score), reverse=True)

        selected: List[ContextChunk] = []
        accumulated_chars = 0
        max_chars = self.max_context_tokens * 4  # Approx 4 chars per token

        for chunk in permitted:
            chunk_len = len(chunk.content)
            if accumulated_chars + chunk_len <= max_chars:
                chunk.disclosed_remotely = True
                selected.append(chunk)
                accumulated_chars += chunk_len

        return selected

    def trim_messages(
        self,
        messages: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Trims long conversation message histories while preserving
        developer/system context and recent user context.
        Note: Developer and system context remain subject to policy evaluation and sanitization.
        """
        if not messages or len(messages) <= self.max_history_messages:
            return messages

        # Separate system/developer messages from conversational history
        system_or_dev_msgs = [
            m for m in messages if m.get("role") in ("system", "developer")
        ]
        other_msgs = [
            m for m in messages if m.get("role") not in ("system", "developer")
        ]

        # Keep recent history up to max_history_messages
        recent_other = other_msgs[-self.max_history_messages:]

        return system_or_dev_msgs + recent_other
