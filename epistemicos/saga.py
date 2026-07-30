from typing import Dict, Any, List

class ActionBuffer:
    def __init__(self):
        self._actions = []
        self._rollbacks = []

    def push_action(self, action: Dict[str, Any], rollback_patch: Dict[str, Any]):
        """
        Records a proposed system action alongside its JSON Patch compensating transaction.
        """
        self._actions.append(action)
        self._rollbacks.append(rollback_patch)

    def commit(self):
        """
        Commits the queued actions and clears the buffer.
        """
        self._actions.clear()
        self._rollbacks.clear()

    def rollback(self) -> List[Dict[str, Any]]:
        """
        Executes queued rollbacks in Last-In-First-Out (LIFO) order.
        Returns the list of executed rollbacks.
        """
        executed_rollbacks = []
        while self._rollbacks:
            rollback_patch = self._rollbacks.pop()
            executed_rollbacks.append(rollback_patch)
        self._actions.clear()
        return executed_rollbacks
