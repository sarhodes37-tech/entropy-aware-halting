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
        max_history_messages: int = 10
    ):
        self.max_context_tokens = max_context_tokens
        self.min_relevance_threshold = min_relevance_threshold
        self.max_history_messages = max_history_messages

    def filter_context_chunks(
        self,
        chunks: List[ContextChunk]
    ) -> List[ContextChunk]:
        """
        Selects minimal necessary chunks based on relevance and token budgets.
        """
        if not chunks:
            return []

        # Filter out low-relevance chunks
        relevant = [c for c in chunks if c.relevance_score >= self.min_relevance_threshold]

        # Sort by relevance descending
        relevant.sort(key=lambda c: c.relevance_score, reverse=True)

        selected: List[ContextChunk] = []
        accumulated_chars = 0
        max_chars = self.max_context_tokens * 4  # Approx 4 chars per token

        for chunk in relevant:
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
        """
        if not messages or len(messages) <= self.max_history_messages:
            return messages

        # Separate system messages from conversational history
        system_msgs = [m for m in messages if m.get("role") == "system"]
        other_msgs = [m for m in messages if m.get("role") != "system"]

        # Keep recent history
        recent_other = other_msgs[-self.max_history_messages:]

        return system_msgs + recent_other
