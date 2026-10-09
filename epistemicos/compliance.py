"""
Validates GDPR/CCPA off-chain mutable store operations, immutable ledger 
anchoring, and compensating rollback mechanisms.
"""

import json
import hashlib
import secrets
from typing import Dict, Tuple, Any, Optional
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

    def delete_pii(self, transaction_id: str, requestor_id: Optional[str] = None) -> bool:
        """Executes Right to be Forgotten (GDPR Art. 17) deletion of raw PII payload."""
        with self._lock:
            if transaction_id in self._store:
                if requestor_id is not None:
                    payload = self._store[transaction_id]
                    if payload.get("owner_id") != requestor_id:
                        raise PermissionError("Unauthorized to delete this PII data")
                del self._store[transaction_id]
                return True
            return False


class ImmutableLedgerAdapter:
    """Immutable append-only ledger interface for transaction receipt anchoring."""
    def __init__(self):
        self._blocks: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()

    def commit_block(self, transaction_id: str, payload_hash: str, receipt: Dict[str, Any], salt: Optional[str] = None) -> Dict[str, Any]:
        block = {
            "ledger_timestamp": datetime.now(timezone.utc).isoformat(),
            "transaction_id": transaction_id,
            "payload_hash": payload_hash,
            "receipt": receipt
        }
        if salt is not None:
            block["salt"] = salt
        with self._lock:
            self._blocks[transaction_id] = block
        return block

    def get_block(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._blocks.get(transaction_id)


class TransactionalComplianceBroker:
    """
    Coordinates atomic receipt logging across off-chain mutable stores 
    and immutable permissioned ledgers.
    """
    def __init__(self, offchain_store: Optional[OffChainStoreAdapter] = None, ledger: Optional[ImmutableLedgerAdapter] = None):
        self.offchain_store = offchain_store or OffChainStoreAdapter()
        self.ledger = ledger or ImmutableLedgerAdapter()

    @staticmethod
    def compute_canonical_hash(payload: Dict[str, Any], salt: bytes) -> str:
        """Computes deterministic salted SHA-256 hash over canonical (sorted-key) JSON bytes."""
        canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(salt + canonical_bytes).hexdigest()

    def record_transaction(self, transaction_id: str, raw_payload: Dict[str, Any], receipt: Dict[str, Any]) -> Dict[str, Any]:
        """
        Atomically anchors transaction in ledger while persisting raw PII off-chain.
        """
        salt = secrets.token_hex(16)
        payload_hash = self.compute_canonical_hash(raw_payload, salt.encode('utf-8'))
        
        # 1. Save mutable payload off-chain
        self.offchain_store.save(transaction_id, raw_payload)
        
        # 2. Commit immutable receipt block to ledger
        try:
            block = self.ledger.commit_block(transaction_id, payload_hash, receipt, salt=salt)
            return block
        except Exception as e:
            # Compensating Rollback: Purge staged off-chain data if ledger commit fails
            self.offchain_store.delete_pii(transaction_id)
            raise RuntimeError(f"Ledger commitment failed. Off-chain rollback executed: {e}") from e

    def execute_right_to_be_forgotten(self, transaction_id: str, file_path: Optional[str] = None, requestor_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Purges raw PII from off-chain store while preserving cryptographic proof on ledger.
        If file_path is provided, reads lines from the file, replaces entity references
        (transaction_id) with [REDACTED], and writes back to file.
        """
        deleted_from_store = self.offchain_store.delete_pii(transaction_id, requestor_id=requestor_id)
        ledger_block = self.ledger.get_block(transaction_id)
        anchored_hash = ledger_block["payload_hash"] if ledger_block else None

        if file_path:
            import os
            import tempfile
            target_path = os.path.realpath(os.path.abspath(file_path))
            allowed_dirs = [os.path.realpath(os.getcwd()), os.path.realpath(tempfile.gettempdir())]

            is_safe = False
            for allowed_dir in allowed_dirs:
                try:
                    if os.path.commonpath([allowed_dir, target_path]) == allowed_dir:
                        is_safe = True
                        break
                except ValueError:
                    continue

            if not is_safe:
                raise ValueError(f"Path traversal detected: '{file_path}' resolves outside allowed base directory.")

            try:
                fd = os.open(target_path, os.O_RDWR | os.O_NOFOLLOW)
            except OSError:
                pass
            else:
                try:
                    # Re-verify after opening to prevent TOCTOU on parent directories
                    current_target_path = os.path.realpath(os.path.abspath(file_path))

                    is_still_safe = False
                    for allowed_dir in allowed_dirs:
                        try:
                            if os.path.commonpath([allowed_dir, current_target_path]) == allowed_dir:
                                is_still_safe = True
                                break
                        except ValueError:
                            continue

                    if not is_still_safe:
                        raise ValueError(f"Path traversal detected: '{file_path}' resolves outside allowed base directory.")

                    fd_stat = os.fstat(fd)
                    try:
                        path_stat = os.stat(current_target_path)
                    except FileNotFoundError:
                        raise ValueError(f"TOCTOU detected: '{file_path}' was deleted during validation.")

                    if fd_stat.st_ino != path_stat.st_ino or fd_stat.st_dev != path_stat.st_dev:
                        raise ValueError(f"TOCTOU detected: '{file_path}' changed during validation.")

                    import shutil
                    with tempfile.TemporaryFile(mode="w+") as temp_f:
                        with open(fd, "r+", closefd=False) as f:
                            for line in f:
                                temp_f.write(line.replace(transaction_id, "[REDACTED]"))

                            f.seek(0)
                            f.truncate(0)
                            temp_f.seek(0)
                            shutil.copyfileobj(temp_f, f)
                finally:
                    os.close(fd)

        return deleted_from_store, anchored_hash
