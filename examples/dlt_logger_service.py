import json
import hashlib
import time
from typing import Dict, Any
from epistemicos.broker import kafka_mock

class OffChainDatabase:
    """Simulates a mutable database (e.g., PostgreSQL) for storing raw PII data."""
    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}

    def save(self, transaction_id: str, payload: Dict[str, Any]):
        self._store[transaction_id] = payload
        print(f"  [OffChain DB] Saved payload for {transaction_id}")

    def delete(self, transaction_id: str):
        if transaction_id in self._store:
            del self._store[transaction_id]
            print(f"  [OffChain DB] Deleted payload for {transaction_id} (Right to be Forgotten)")

class PermissionedLedger:
    """Simulates an immutable blockchain for storing transaction receipts and payload hashes."""
    def __init__(self):
        self._blocks: list = []

    def commit_block(self, transaction_id: str, payload_hash: str, receipt: Dict[str, Any]):
        block = {
            "ledger_timestamp": time.time(),
            "transaction_id": transaction_id,
            "payload_hash": payload_hash,
            "receipt": receipt
        }
        self._blocks.append(block)
        print(f"  [Immutable Ledger] Committed block for {transaction_id} (Hash: {payload_hash[:8]}...)")

class DLTLoggerService:
    def __init__(self):
        self.offchain_db = OffChainDatabase()
        self.ledger = PermissionedLedger()

    def process_queue(self):
        """Consumes from the receipts topic and routes data according to GDPR/CCPA standards."""
        print("DLT Logger Service: Starting queue processor...")
        while True:
            message = kafka_mock.consume("receipts_topic")
            if message is None:
                print("DLT Logger Service: Queue empty. Shutting down.")
                break

            raw_payload = message.get("raw_payload", {})
            receipt = message.get("receipt", {})
            transaction_id = receipt.get("transaction_id", "UNKNOWN")

            # 1. Save mutable raw data to PostgreSQL
            self.offchain_db.save(transaction_id, raw_payload)

            # 2. Hash the raw payload (ensuring deterministic sorting)
            payload_str = json.dumps(raw_payload, sort_keys=True).encode()
            payload_hash = hashlib.sha256(payload_str).hexdigest()

            # 3. Commit immutable receipt and hash to the Blockchain
            self.ledger.commit_block(transaction_id, payload_hash, receipt)

if __name__ == "__main__":
    service = DLTLoggerService()
    service.process_queue()