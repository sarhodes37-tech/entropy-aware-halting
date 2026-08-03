"""
Validates GDPR/CCPA off-chain mutable store operations, immutable ledger 
anchoring, and compensating rollback mechanisms.
"""

import json
import hashlib
from typing import Dict, Tuple, Any, Optional, List
from threading import RLock
from datetime import datetime, timezone

class OffChainStoreAdapter:
    """Thread-safe mutable store interface for raw PII payload management."""
    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()

    def save(self, transaction_id: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._store[transaction_id] = payload

    def get(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._store.get(transaction_id)

    def delete_pii(self, transaction_id: str) -> bool:
        """Executes Right to be Forgotten (GDPR Art. 17) deletion of raw PII payload."""
        with self._lock:
            if transaction_id in self._store:
                del self._store[transaction_id]
                return True
            return False


class ImmutableLedgerAdapter:
    """Immutable append-only ledger interface for transaction receipt anchoring."""
    def __init__(self):
        self._blocks: List[Dict[str, Any]] = []
        self._lock = RLock()

    def commit_block(self, transaction_id: str, payload_hash: str, receipt: Dict[str, Any]) -> Dict[str, Any]:
        block = {
            "ledger_timestamp": datetime.now(timezone.utc).isoformat(),
            "transaction_id": transaction_id,
            "payload_hash": payload_hash,
            "receipt": receipt
        }
        with self._lock:
            self._blocks.append(block)
        return block

    def get_block(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for b in self._blocks:
                if b["transaction_id"] == transaction_id:
                    return b
            return None


class TransactionalComplianceBroker:
    """
    Coordinates atomic receipt logging across off-chain mutable stores 
    and immutable permissioned ledgers.
    """
    def __init__(self, offchain_store: Optional[OffChainStoreAdapter] = None, ledger: Optional[ImmutableLedgerAdapter] = None):
        self.offchain_store = offchain_store or OffChainStoreAdapter()
        self.ledger = ledger or ImmutableLedgerAdapter()

    @staticmethod
    def compute_canonical_hash(payload: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 hash over canonical (sorted-key) JSON bytes."""
        canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    def record_transaction(self, transaction_id: str, raw_payload: Dict[str, Any], receipt: Dict[str, Any]) -> Dict[str, Any]:
        """
        Atomically anchors transaction in ledger while persisting raw PII off-chain.
        """
        payload_hash = self.compute_canonical_hash(raw_payload)
        
        # 1. Save mutable payload off-chain
        self.offchain_store.save(transaction_id, raw_payload)
        
        # 2. Commit immutable receipt block to ledger
        try:
            block = self.ledger.commit_block(transaction_id, payload_hash, receipt)
            return block
        except Exception as e:
            # Compensating Rollback: Purge staged off-chain data if ledger commit fails
            self.offchain_store.delete_pii(transaction_id)
            raise RuntimeError(f"Ledger commitment failed. Off-chain rollback executed: {e}") from e

    def execute_right_to_be_forgotten(self, transaction_id: str) -> Tuple[bool, Optional[str]]:
        """
        Purges raw PII from off-chain store while preserving cryptographic proof on ledger.
        """
        deleted_from_store = self.offchain_store.delete_pii(transaction_id)
        ledger_block = self.ledger.get_block(transaction_id)
        anchored_hash = ledger_block["payload_hash"] if ledger_block else None
        return deleted_from_store, anchored_hash
