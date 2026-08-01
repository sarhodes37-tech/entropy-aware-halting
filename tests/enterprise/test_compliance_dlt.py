"""
Unit and compliance test suite for DLT Logger & Transactional Compliance Broker.
Validates off-chain PII deletion (GDPR/CCPA) and immutable hash verification.
"""

import pytest
from epistemicos.enterprise.compliance import (
    TransactionalComplianceBroker,
    OffChainStoreAdapter,
    ImmutableLedgerAdapter
)


@pytest.fixture
def compliance_broker():
    return TransactionalComplianceBroker(
        offchain_store=OffChainStoreAdapter(),
        ledger=ImmutableLedgerAdapter()
    )


def test_atomic_transaction_record_and_hash_verification(compliance_broker):
    """Validates off-chain storage, payload hashing, and ledger block commitment."""
    tx_id = "TX-2026-8819"
    payload = {"client_name": "Jane Doe", "ssn": "000-00-0000", "policy_limit": 1000000}
    receipt = {"status": "COMMITTED", "gate": "EntropyGate", "halt_directive": "NONE"}

    block = compliance_broker.record_transaction(tx_id, payload, receipt)

    # 1. Verify ledger hash matches independently computed hash
    expected_hash = compliance_broker.compute_canonical_hash(payload)
    assert block["payload_hash"] == expected_hash
    assert block["transaction_id"] == tx_id

    # 2. Verify off-chain store holds raw payload
    stored_payload = compliance_broker.offchain_store.get(tx_id)
    assert stored_payload == payload


def test_right_to_be_forgotten_gdpr_purge(compliance_broker):
    """
    Validates GDPR Article 17 compliance:
    Raw PII is completely deleted from off-chain DB, but ledger proof remains intact.
    """
    tx_id = "TX-2026-9901"
    payload = {"email": "user@example.com", "address": "123 Main St"}
    receipt = {"status": "HALTED", "gate": "EntropyGate"}

    # Anchor transaction
    block = compliance_broker.record_transaction(tx_id, payload, receipt)
    anchored_hash = block["payload_hash"]

    # Execute PII Purge
    deleted, preserved_hash = compliance_broker.execute_right_to_be_forgotten(tx_id)

    assert deleted is True
    assert preserved_hash == anchored_hash

    # Raw PII must be gone
    assert compliance_broker.offchain_store.get(tx_id) is None

    # Immutable ledger block must still exist
    ledger_block = compliance_broker.ledger.get_block(tx_id)
    assert ledger_block is not None
    assert ledger_block["payload_hash"] == anchored_hash

