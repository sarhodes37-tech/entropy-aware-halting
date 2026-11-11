"""
EpistemicOS Persistence Subsystem.
Foundational storage, indexing, and cryptographic primitives.
"""

from epistemicos.persistence.merkle import (
    leaf_hash,
    node_hash,
    merkle_tree_hash,
    generate_inclusion_proof,
    verify_inclusion_proof,
)
from epistemicos.persistence.schema import (
    initialize_database,
    open_database,
    get_schema_version,
    SCHEMA_VERSION,
    transaction,
)
from epistemicos.persistence.append import (
    append_event,
    verify_append_state,
    reconcile_active_segment,
    canonical_json_serialize,
    acquire_writer_lock,
    AppendResult,
    VerifiedAppendState,
    PersistenceAppendError,
    DuplicateEventError,
    InvalidPayloadError,
    SegmentNotActiveError,
    UnresolvedGapError,
    PhysicalRecordCorruptionError,
    ReconciliationError,
    FatalCommittedDataCorruptionError,
    IndeterminateCommitError,
    MissingLockConfigurationError,
)

__all__ = [
    "leaf_hash",
    "node_hash",
    "merkle_tree_hash",
    "generate_inclusion_proof",
    "verify_inclusion_proof",
    "initialize_database",
    "open_database",
    "get_schema_version",
    "SCHEMA_VERSION",
    "transaction",
    "append_event",
    "verify_append_state",
    "reconcile_active_segment",
    "canonical_json_serialize",
    "acquire_writer_lock",
    "AppendResult",
    "VerifiedAppendState",
    "PersistenceAppendError",
    "DuplicateEventError",
    "InvalidPayloadError",
    "SegmentNotActiveError",
    "UnresolvedGapError",
    "PhysicalRecordCorruptionError",
    "ReconciliationError",
    "FatalCommittedDataCorruptionError",
    "IndeterminateCommitError",
    "MissingLockConfigurationError",
]
