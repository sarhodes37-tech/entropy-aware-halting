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


def test_execute_right_to_be_forgotten_exists_both():
    """Validates right to be forgotten when transaction exists off-chain and on ledger."""
    broker = TransactionalComplianceBroker()
    broker.record_transaction("tx_123", {"pii": "data"}, {"status": "ok"})

    deleted, anchored_hash = broker.execute_right_to_be_forgotten("tx_123")

    assert deleted is True
    assert anchored_hash is not None
    assert isinstance(anchored_hash, str)

    # Verify off-chain data is gone
    assert broker.offchain_store.get("tx_123") is None


def test_execute_right_to_be_forgotten_not_in_store():
    """Validates behavior when data is already missing off-chain but present on ledger."""
    broker = TransactionalComplianceBroker()
    # Populate ledger only
    payload_hash = broker.compute_canonical_hash({"pii": "data"})
    broker.ledger.commit_block("tx_456", payload_hash, {"status": "ok"})

    deleted, anchored_hash = broker.execute_right_to_be_forgotten("tx_456")

    assert deleted is False
    assert anchored_hash == payload_hash


def test_execute_right_to_be_forgotten_not_in_ledger():
    """Validates behavior when data is off-chain but not on ledger."""
    broker = TransactionalComplianceBroker()
    # Populate store only
    broker.offchain_store.save("tx_789", {"pii": "data"})

    deleted, anchored_hash = broker.execute_right_to_be_forgotten("tx_789")

    assert deleted is True
    assert anchored_hash is None


def test_execute_right_to_be_forgotten_not_found_anywhere():
    """Validates behavior when transaction exists nowhere."""
    broker = TransactionalComplianceBroker()

    deleted, anchored_hash = broker.execute_right_to_be_forgotten("tx_ghost")

    assert deleted is False
    assert anchored_hash is None


def test_execute_right_to_be_forgotten_empty_transaction_id():
    """Validates behavior when transaction id is empty."""
    broker = TransactionalComplianceBroker()

    deleted, anchored_hash = broker.execute_right_to_be_forgotten("")

    assert deleted is False
    assert anchored_hash is None
