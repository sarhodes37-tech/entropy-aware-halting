"""
Unit test suite for epistemicos.compliance module.
Validates GDPR/CCPA off-chain mutable store operations, immutable ledger 
anchoring, and compensating rollback mechanisms.
"""

import pytest
from unittest.mock import MagicMock
from epistemicos.compliance import (
    OffChainStoreAdapter,
    ImmutableLedgerAdapter,
    TransactionalComplianceBroker
)

def test_offchain_store_delete_pii_not_found():
    """Validates deletion returns False for non-existent transactions."""
    store = OffChainStoreAdapter()
    
    # Store is empty, deleting should cleanly return False
    result = store.delete_pii("ghost_tx_001")
    assert result is False


def test_immutable_ledger_get_block_not_found():
    """Validates ledger lookup returns None for non-existent blocks."""
    ledger = ImmutableLedgerAdapter()
    
    # Ledger is empty, querying should cleanly return None
    result = ledger.get_block("ghost_tx_001")
    assert result is None


def test_transactional_broker_compensating_rollback():
    """Validates off-chain PII is purged if the immutable ledger commit fails."""
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
