"""Deterministic mock retrieval tool backed exclusively by local fixture data."""

from typing import Dict, List, Optional
from benchmarks.on_policy_decision_steering.models import RetrievalResult


class MockRetrievalTool:
    """Mock retrieval tool for benchmark trials, enforcing zero external network access."""

    def __init__(self, fixture_map: Optional[Dict[str, List[RetrievalResult]]] = None):
        """
        Initialize with a mapping from query string (or scenario ID/term) to RetrievalResults.
        """
        self._fixture_map: Dict[str, List[RetrievalResult]] = fixture_map or {}
        self._retrieval_history: List[RetrievalResult] = []

    def add_fixture(self, key: str, results: List[RetrievalResult]) -> None:
        """Add or update fixture mapping for a query or key."""
        self._fixture_map[key] = results

    def search(self, query: str) -> List[RetrievalResult]:
        """
        Execute deterministic search against local fixtures.
        Returns matching RetrievalResults or empty list if no fixture matches.
        Strictly offline - no network or external requests.
        """
        # Exact match or key lookup
        results = self._fixture_map.get(query, [])
        if not results:
            # Case-insensitive / whitespace trimmed fallback search
            normalized_query = query.strip().lower()
            for key, res_list in self._fixture_map.items():
                if key.strip().lower() == normalized_query:
                    results = res_list
                    break

        self._retrieval_history.extend(results)
        return results

    def get_history(self) -> List[RetrievalResult]:
        """Return history of all returned retrieval results in execution order."""
        return list(self._retrieval_history)

    def clear_history(self) -> None:
        """Clear retrieval history."""
        self._retrieval_history.clear()
