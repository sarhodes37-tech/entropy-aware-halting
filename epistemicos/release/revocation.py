"""
Authoritative Revocation Registry for Release Approvals.

Ensures that an approval marked as revoked cannot be resurrected through
in-memory object mutation or serialization tampering.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set


@dataclass(frozen=True)
class RevocationRecord:
    approval_id: str
    revoked_by_principal: str
    reason: str
    revocation_timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        if not self.approval_id or not isinstance(self.approval_id, str) or not self.approval_id.strip():
            raise ValueError("RevocationRecord: approval_id must be a non-empty string")
        if not self.revoked_by_principal or not isinstance(self.revoked_by_principal, str) or not self.revoked_by_principal.strip():
            raise ValueError("RevocationRecord: revoked_by_principal must be a non-empty string")
        if not self.reason or not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("RevocationRecord: reason must be a non-empty string")


class ReleaseApprovalRevocationRegistry:
    """
    Authoritative, thread-safe registry tracking revoked approval IDs.

    Trust and Persistence Assumptions:
    - In-memory registry provides monotonic, irreversible revocation within the process lifetime.
    - Prevents resurrection attacks where a caller modifies approval.revoked = False on a previously revoked approval.
    - An approval registered as revoked cannot be un-revoked.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._revocations: Dict[str, RevocationRecord] = {}

    def revoke_approval(
        self,
        approval_id: str,
        revoked_by_principal: str,
        reason: str
    ) -> RevocationRecord:
        """Atomically records monotonic revocation of an approval ID."""
        if not approval_id or not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("approval_id must be a non-empty string")
        if not revoked_by_principal or not isinstance(revoked_by_principal, str) or not revoked_by_principal.strip():
            raise ValueError("revoked_by_principal must be a non-empty string")
        if not reason or not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be a non-empty string")

        rec = RevocationRecord(
            approval_id=approval_id.strip(),
            revoked_by_principal=revoked_by_principal.strip(),
            reason=reason.strip()
        )
        with self._lock:
            # Monotonic: once revoked, never removed
            self._revocations[rec.approval_id] = rec
            return rec

    def is_revoked(self, approval_id: str) -> bool:
        """Authoritatively checks whether an approval ID is revoked (fails closed on invalid input)."""
        if not approval_id or not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("approval_id must be a non-empty string")
        with self._lock:
            return approval_id.strip() in self._revocations

    def get_revocation_record(self, approval_id: str) -> Optional[RevocationRecord]:
        """Retrieves revocation record for an approval ID (fails closed on invalid input)."""
        if not approval_id or not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("approval_id must be a non-empty string")
        with self._lock:
            return self._revocations.get(approval_id.strip())
