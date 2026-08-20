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

def test_compute_canonical_hash_same_data_different_order():
    """Validates identical payloads with different key insertion orders produce the same hash."""
    payload_1 = {"a": 1, "b": 2, "c": 3}
    payload_2 = {"c": 3, "a": 1, "b": 2}

    hash_1 = TransactionalComplianceBroker.compute_canonical_hash(payload_1)
    hash_2 = TransactionalComplianceBroker.compute_canonical_hash(payload_2)

    assert hash_1 == hash_2


def test_compute_canonical_hash_different_data():
    """Validates different payloads produce different hashes."""
    payload_1 = {"a": 1, "b": 2}
    payload_2 = {"a": 1, "b": 3}

    hash_1 = TransactionalComplianceBroker.compute_canonical_hash(payload_1)
    hash_2 = TransactionalComplianceBroker.compute_canonical_hash(payload_2)

    assert hash_1 != hash_2


def test_compute_canonical_hash_nested_dicts():
    """Validates nested identical payloads with different key insertion orders produce the same hash."""
    payload_1 = {"a": 1, "b": {"c": 3, "d": 4}}
    payload_2 = {"b": {"d": 4, "c": 3}, "a": 1}

    hash_1 = TransactionalComplianceBroker.compute_canonical_hash(payload_1)
    hash_2 = TransactionalComplianceBroker.compute_canonical_hash(payload_2)

    assert hash_1 == hash_2


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


def test_execute_right_to_be_forgotten_file_redaction(tmp_path):
    """Validates that entity references (transaction_id) are replaced with [REDACTED] in the file."""
    broker = TransactionalComplianceBroker()
    tx_id = "tx_redact_123"
    broker.record_transaction(tx_id, {"pii": "sensitive"}, {"status": "ok"})

    # Create a temporary file with some mock data containing the tx_id
    test_file = tmp_path / "data.log"
    test_file.write_text(f"Event: login, user: {tx_id}\nEvent: logout, user: {tx_id}\nEvent: query, user: normal_user")

    deleted, anchored_hash = broker.execute_right_to_be_forgotten(tx_id, file_path=str(test_file))

    assert deleted is True
    assert anchored_hash is not None

    # Read the file back and check for redactions
    content = test_file.read_text()
    assert tx_id not in content
    assert "[REDACTED]" in content
    assert content == "Event: login, user: [REDACTED]\nEvent: logout, user: [REDACTED]\nEvent: query, user: normal_user"


def test_execute_right_to_be_forgotten_file_not_found():
    """Validates that a non-existent file is handled gracefully without error."""
    broker = TransactionalComplianceBroker()
    tx_id = "tx_missing_file"

    # Ensure it doesn't raise an exception when file doesn't exist
    deleted, anchored_hash = broker.execute_right_to_be_forgotten(tx_id, file_path="/tmp/non_existent_file_9999.log")

    assert deleted is False
    assert anchored_hash is None
