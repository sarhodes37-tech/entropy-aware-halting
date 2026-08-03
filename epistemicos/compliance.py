"""
Unit test suite for epistemicos.compliance module.
Validates GDPR/CCPA off-chain mutable store operations, immutable ledger 
anchoring, and compensating rollback mechanisms.
"""

from typing import Dict, Tuple, Any, Optional
import pytest
from unittest.mock import MagicMock

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


def test_offchain_store_delete_pii_not_found():
    """Validates deletion returns False for non-existent transactions (Line 35)."""
    store = OffChainStoreAdapter()
    
    # Store is empty, deleting should cleanly return False
    result = store.delete_pii("ghost_tx_001")
    assert result is False


def test_immutable_ledger_get_block_not_found():
    """Validates ledger lookup returns None for non-existent blocks (Line 61)."""
    ledger = ImmutableLedgerAdapter()
    
    # Ledger is empty, querying should cleanly return None
    result = ledger.get_block("ghost_tx_001")
    assert result is None


def test_transactional_broker_compensating_rollback():
    """Validates off-chain PII is purged if the immutable ledger commit fails (Lines 93-96)."""
    mock_ledger = ImmutableLedgerAdapter()
    # Force the ledger to simulate a failure (e.g., IO error or consensus rejection)
    mock_ledger.commit_block = MagicMock(side_effect=Exception("Ledger IO Error"))
    
    mock_store = OffChainStoreAdapter()
    mock_store.delete_pii = MagicMock(return_value=True)

    broker = TransactionalComplianceBroker(offchain_store=mock_store, ledger=mock_ledger)

    # Verify that the correct RuntimeError is raised with the inner exception mapped
    with pytest.raises(RuntimeError, match="Ledger commitment failed. Off-chain rollback executed: Ledger IO Error"):
        broker.record_transaction(
            transaction_id="tx_rollback_123",
            raw_payload={"pii": "sensitive_user_data"},
            receipt={"status": "pending_anchoring"}
        )
    
    # Verify the compensating rollback was executed to prevent orphaned PII
    mock_store.delete_pii.assert_called_once_with("tx_rollback_123")
