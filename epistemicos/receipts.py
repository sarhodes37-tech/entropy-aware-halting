from typing import Dict, Any, List
import time
import hashlib
import json

class ReceiptGenerator:
    def __init__(self):
        self._events = []
        self._rollbacks = []

    def log_event(self, event_type: str, details: Dict[str, Any]):
        """Records an immutable event in the transaction lifecycle."""
        event = {
            "timestamp": time.time(),
            "type": event_type,
            "details": details
        }
        self._events.append(event)

    def push_action(self, action: Dict[str, Any], rollback_patch: Dict[str, Any]):
        self.log_event("ActionProposed", {"action": action})
        self._rollbacks.append(rollback_patch)

    def mint_receipt(self, transaction_id: str, success: bool, confidence_matrix: Dict[str, float]) -> Dict[str, Any]:
        receipt = {
            "transaction_id": transaction_id,
            "status": "COMMITTED" if success else "ROLLED_BACK",
            "confidence_matrix": confidence_matrix,
            "event_log": self._events
        }
        receipt_string = json.dumps(receipt, sort_keys=True).encode()
        receipt["signature"] = hashlib.sha256(receipt_string).hexdigest()
        return receipt

    def rollback(self) -> List[Dict[str, Any]]:
        self.log_event("RollbackIssued", {"count": len(self._rollbacks)})
        executed_rollbacks = []
        while self._rollbacks:
            executed_rollbacks.append(self._rollbacks.pop())
        return executed_rollbacks
