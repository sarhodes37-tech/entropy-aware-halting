"""
Context-Aware Egress Data Transfer Governance.

Governs legitimate data transfer tools and trusted cloud destinations by evaluating:
1. Initiating principal and credential/service identity.
2. Destination identity (service, tenant, account, workspace, endpoint) rather than hostname alone.
3. Data classification originating from trusted policy or verified metadata.
4. Requested and actual observed byte volume (including cumulative task/request limits).
5. Explicit capability authorization and scope binding.
6. Operation type and transfer direction.

Motivated by the Silent Ransom Group (SRG / Luna Moth) threat model, where legitimate tools
(Rclone, WinSCP) and trusted cloud providers (OneDrive, Google Drive) are abused for exfiltration.
"""

from __future__ import annotations

import enum
import hmac
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


class DataClassification(str, enum.Enum):
    """
    Sensitivity classification levels for data movement.
    Ordered by increasing sensitivity.
    """
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

    @property
    def level(self) -> int:
        order = {
            DataClassification.PUBLIC: 1,
            DataClassification.INTERNAL: 2,
            DataClassification.CONFIDENTIAL: 3,
            DataClassification.RESTRICTED: 4,
        }
        return order[self]

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, DataClassification):
            return NotImplemented
        return self.level >= other.level

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, DataClassification):
            return NotImplemented
        return self.level > other.level

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, DataClassification):
            return NotImplemented
        return self.level <= other.level

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, DataClassification):
            return NotImplemented
        return self.level < other.level


class TransferDirection(str, enum.Enum):
    """Direction of the data transfer."""
    UPLOAD = "UPLOAD"
    DOWNLOAD = "DOWNLOAD"
    SYNCHRONIZE = "SYNCHRONIZE"
    REPLICATE = "REPLICATE"
    BIDIRECTIONAL = "BIDIRECTIONAL"


class TransferOperation(str, enum.Enum):
    """Specific operational action performed during the transfer."""
    READ = "READ"
    WRITE = "WRITE"
    SYNC = "SYNC"
    DELETE = "DELETE"
    BACKUP = "BACKUP"
    EXPORT = "EXPORT"


@dataclass(frozen=True)
class DestinationIdentity:
    """
    Fine-grained destination identity representing the specific service, tenant,
    account, workspace, and normalized host/endpoint.

    A hostname allowlist must not override a destination-tenant restriction.
    """
    service: str
    host: str
    tenant_id: Optional[str] = None
    account_id: Optional[str] = None
    workspace_id: Optional[str] = None
    endpoint_path: Optional[str] = None

    def __post_init__(self):
        if not self.service or not isinstance(self.service, str) or not self.service.strip():
            raise ValueError("DestinationIdentity requires a non-empty service identifier.")
        if not self.host or not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("DestinationIdentity requires a non-empty destination host.")
        # Normalize fields
        object.__setattr__(self, "service", self.service.strip().lower())
        object.__setattr__(self, "host", self.host.strip().lower())
        if self.tenant_id is not None:
            if not isinstance(self.tenant_id, str) or not self.tenant_id.strip():
                raise ValueError("DestinationIdentity tenant_id must be non-empty or None.")
            object.__setattr__(self, "tenant_id", self.tenant_id.strip())
        if self.account_id is not None:
            if not isinstance(self.account_id, str) or not self.account_id.strip():
                raise ValueError("DestinationIdentity account_id must be non-empty or None.")
            object.__setattr__(self, "account_id", self.account_id.strip())
        if self.workspace_id is not None:
            if not isinstance(self.workspace_id, str) or not self.workspace_id.strip():
                raise ValueError("DestinationIdentity workspace_id must be non-empty or None.")
            object.__setattr__(self, "workspace_id", self.workspace_id.strip())
        if self.endpoint_path is not None:
            if not isinstance(self.endpoint_path, str):
                raise ValueError("DestinationIdentity endpoint_path must be a string or None.")
            object.__setattr__(self, "endpoint_path", self.endpoint_path.strip())


@dataclass
class DataTransferContext:
    """
    Typed, validated context representing a data transfer attempt.

    Important trust requirements:
    - Initiating principal must be an authenticated principal ID.
    - Classification must originate from trusted policy/context or verified metadata,
      not an unverified agent claim.
    - Distinguishes declared/requested volume from observed/streamed volume.
    - Missing, malformed, or untrusted security context fails closed.
    """
    initiating_principal: str
    destination: DestinationIdentity
    classification: DataClassification
    direction: TransferDirection
    operation: TransferOperation
    source_scope: Optional[str] = None
    service_identity: Optional[str] = None
    declared_bytes: Optional[int] = None
    observed_bytes: int = 0
    task_id: Optional[str] = None
    correlation_id: str = "DEFAULT-CORR"
    request_id: str = "DEFAULT-REQ"
    capability_token_id: Optional[str] = None
    _is_classification_trusted: bool = field(default=False, repr=False)
    action_name: Optional[str] = None
    target: Optional[str] = None
    canonical_request_digest: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    trusted_authority_assertion: Optional[Any] = field(default=None, repr=False)
    principal_verifier: Optional[Any] = field(default=None, repr=False)

    @property
    def is_classification_trusted(self) -> bool:
        if not self._is_classification_trusted:
            return False
        if not self.trusted_authority_assertion:
            return False
        return self._verify_context_assertion(self.principal_verifier)

    def _verify_context_assertion(self, verifier_override: Optional[Any] = None) -> bool:
        """
        Cryptographically verifies the bound authority assertion against the current context
        fields using Ed25519 asymmetric verification.
        Any post-construction mutation of security fields will cause this check to fail,
        and an unauthenticated caller cannot forge a valid Ed25519 signature.
        """
        assertion = self.trusted_authority_assertion
        if not assertion:
            return False

        from epistemicos.authorization import PrincipalVerifier, verify_ed25519_signature
        verifier = verifier_override or self.principal_verifier or PrincipalVerifier()
        if not verifier.has_trusted_issuers():
            return False

        if isinstance(assertion, dict):
            issuer = assertion.get("issuer")
            sig_hex = assertion.get("signature")
            asserted_principal = assertion.get("principal")
            asserted_dest = assertion.get("destination_host")
            asserted_tenant = assertion.get("tenant_id")
            asserted_account = assertion.get("account_id")
            asserted_workspace = assertion.get("workspace_id")
            asserted_endpoint = assertion.get("endpoint_path")
            asserted_class = assertion.get("classification")
            asserted_scope = assertion.get("source_scope")
            asserted_direction = assertion.get("direction")
            asserted_operation = assertion.get("operation")
            asserted_task = assertion.get("task_id")
            asserted_bytes = assertion.get("declared_bytes")
            timestamp = assertion.get("timestamp")
            expires_at = assertion.get("expires_at")

            dest_host = self.destination.host.strip().lower() if self.destination else ""
            if not asserted_dest or str(asserted_dest).strip().lower() != dest_host:
                return False

            if (
                not asserted_principal
                or str(asserted_principal).strip() != self.initiating_principal.strip()
            ):
                return False

            curr_tenant = (self.destination.tenant_id if self.destination else "") or ""
            if (asserted_tenant or "") != curr_tenant:
                return False

            curr_account = (self.destination.account_id if self.destination else "") or ""
            if (asserted_account or "") != curr_account:
                return False

            curr_ws = (self.destination.workspace_id if self.destination else "") or ""
            if (asserted_workspace or "") != curr_ws:
                return False

            curr_ep = (self.destination.endpoint_path if self.destination else "") or ""
            if (asserted_endpoint or "") != curr_ep:
                return False

            if (
                not asserted_class
                or str(asserted_class).upper() != self.classification.value.upper()
            ):
                return False

            if (asserted_scope or "") != (self.source_scope or ""):
                return False

            if (
                not asserted_direction
                or str(asserted_direction).upper() != self.direction.value.upper()
            ):
                return False

            if (
                not asserted_operation
                or str(asserted_operation).upper() != self.operation.value.upper()
            ):
                return False

            # Strict task_id binding: whenever the context specifies a task_id, the assertion
            # must explicitly bind that task_id. An assertion with a task_id cannot be replayed
            # under a different task_id.
            if self.task_id is not None and self.task_id.strip():
                if not asserted_task or str(asserted_task).strip() != self.task_id.strip():
                    return False
            elif asserted_task is not None and str(asserted_task).strip():
                return False

            # Strict volume constraint binding: whenever context has declared volume > 0, the
            # assertion must explicitly bind and authorize that volume. Context cannot exceed it.
            if self.declared_bytes is not None and self.declared_bytes > 0:
                if asserted_bytes is None or not isinstance(asserted_bytes, int):
                    return False
                if self.declared_bytes > asserted_bytes:
                    return False
            elif asserted_bytes is not None:
                ctx_bytes = self.declared_bytes if self.declared_bytes is not None else 0
                if not isinstance(asserted_bytes, int) or ctx_bytes > asserted_bytes:
                    return False

            now = time.time()
            if expires_at is None or not isinstance(expires_at, (int, float)) or now >= expires_at:
                return False

            trusted_pubkey = verifier._trusted_public_keys.get(issuer) if issuer else None
            if not issuer or not sig_hex or not trusted_pubkey:
                return False

            try:
                sig_bytes = bytes.fromhex(sig_hex)
                dest_str = asserted_dest.strip().lower()
                tenant_str = asserted_tenant or ""
                account_str = asserted_account or ""
                ws_str = asserted_workspace or ""
                ep_str = asserted_endpoint or ""
                scope_str = asserted_scope or ""
                task_str = asserted_task or ""
                bytes_str = str(asserted_bytes) if asserted_bytes is not None else ""
                ts_str = (
                    f"{timestamp:.6f}" if isinstance(timestamp, (int, float))
                    else str(timestamp or "")
                )
                exp_str = (
                    f"{expires_at:.6f}" if isinstance(expires_at, (int, float))
                    else str(expires_at or "")
                )
                payload_extended = (
                    f"{asserted_principal.strip()}:{issuer}:{dest_str}:"
                    f"{tenant_str}:{account_str}:{ws_str}:{ep_str}:"
                    f"{asserted_class.upper()}:{scope_str}:"
                    f"{asserted_direction.upper()}:{asserted_operation.upper()}:"
                    f"{task_str}:{bytes_str}:{ts_str}:{exp_str}"
                ).encode("utf-8")

                return bool(verify_ed25519_signature(sig_bytes, payload_extended, trusted_pubkey))
            except Exception:
                return False

        from epistemicos.authorization import AuthenticatedPrincipal
        if isinstance(assertion, AuthenticatedPrincipal):
            valid, reason, _ = verifier.verify_principal(assertion)
            return valid and assertion.principal_id == self.initiating_principal

        return False

    def __post_init__(self):
        if (
            not self.initiating_principal
            or not isinstance(self.initiating_principal, str)
            or not self.initiating_principal.strip()
        ):
            raise ValueError("DataTransferContext requires a non-empty initiating_principal.")
        self.initiating_principal = self.initiating_principal.strip()

        if not isinstance(self.destination, DestinationIdentity):
            raise TypeError(
                "DataTransferContext destination must be an instance of DestinationIdentity."
            )

        if not isinstance(self.classification, DataClassification):
            if isinstance(self.classification, str):
                try:
                    self.classification = DataClassification(self.classification)
                except ValueError:
                    raise ValueError(f"Invalid DataClassification: {self.classification}")
            else:
                raise TypeError(
                    "DataTransferContext classification must be a DataClassification enum."
                )

        if not isinstance(self.direction, TransferDirection):
            if isinstance(self.direction, str):
                try:
                    self.direction = TransferDirection(self.direction)
                except ValueError:
                    raise ValueError(f"Invalid TransferDirection: {self.direction}")
            else:
                raise TypeError("DataTransferContext direction must be a TransferDirection enum.")

        if not isinstance(self.operation, TransferOperation):
            if isinstance(self.operation, str):
                try:
                    self.operation = TransferOperation(self.operation)
                except ValueError:
                    raise ValueError(f"Invalid TransferOperation: {self.operation}")
            else:
                raise TypeError("DataTransferContext operation must be a TransferOperation enum.")

        if self.declared_bytes is not None:
            if not isinstance(self.declared_bytes, int) or self.declared_bytes < 0:
                raise ValueError("declared_bytes must be a non-negative integer or None.")

        if not isinstance(self.observed_bytes, int) or self.observed_bytes < 0:
            raise ValueError("observed_bytes must be a non-negative integer.")


class TrustedTransferContextBuilder:
    """
    Builder creating cryptographically/authoritatively verified DataTransferContext instances.
    Ensures principals, destination tenant identities, and classifications cannot be arbitrarily
    asserted by untrusted agents or model prompts.
    """

    @classmethod
    def create_trusted_context(
        cls,
        principal: str,
        destination: DestinationIdentity,
        classification: DataClassification,
        direction: TransferDirection,
        operation: TransferOperation,
        source_scope: Optional[str] = None,
        service_identity: Optional[str] = None,
        declared_bytes: Optional[int] = None,
        task_id: Optional[str] = None,
        correlation_id: str = "DEFAULT-CORR",
        request_id: str = "DEFAULT-REQ",
        capability_token_id: Optional[str] = None,
        action_name: Optional[str] = None,
        target: Optional[str] = None,
        canonical_request_digest: Optional[str] = None,
        trusted_authority_assertion: Optional[Any] = None,
        principal_verifier: Optional[Any] = None
    ) -> DataTransferContext:
        """
        Creates a DataTransferContext with is_classification_trusted=True only if
        an authenticated, cryptographically verified authority assertion is provided.
        Binds principal, issuer, destination host, tenant/account identity, classification,
        source scope, direction, operation, and expiration.
        Missing destination host, missing expiration, expired assertion, or mismatched fields
        strictly fail closed (is_classification_trusted=False).
        """
        is_trusted = False

        if trusted_authority_assertion is not None:
            if isinstance(trusted_authority_assertion, dict):
                from epistemicos.authorization import PrincipalVerifier, verify_ed25519_signature

                verifier = principal_verifier or PrincipalVerifier()
                if verifier.has_trusted_issuers():
                    issuer = trusted_authority_assertion.get("issuer")
                    sig_hex = trusted_authority_assertion.get("signature")
                    asserted_principal = trusted_authority_assertion.get("principal")
                    asserted_dest = trusted_authority_assertion.get("destination_host")
                    asserted_tenant = trusted_authority_assertion.get("tenant_id")
                    asserted_account = trusted_authority_assertion.get("account_id")
                    asserted_workspace = trusted_authority_assertion.get("workspace_id")
                    asserted_endpoint = trusted_authority_assertion.get("endpoint_path")
                    asserted_class = trusted_authority_assertion.get("classification")
                    asserted_scope = trusted_authority_assertion.get("source_scope")
                    asserted_direction = trusted_authority_assertion.get("direction")
                    asserted_operation = trusted_authority_assertion.get("operation")
                    asserted_task = trusted_authority_assertion.get("task_id")
                    asserted_bytes = trusted_authority_assertion.get("declared_bytes")
                    timestamp = trusted_authority_assertion.get("timestamp")
                    expires_at = trusted_authority_assertion.get("expires_at")

                    # Destination host binding is MANDATORY: generic or missing destination rejected
                    has_valid_dest = bool(
                        asserted_dest
                        and isinstance(asserted_dest, str)
                        and asserted_dest.strip().lower() == destination.host.strip().lower()
                    )

                    # Principal match
                    has_valid_principal = bool(
                        asserted_principal
                        and isinstance(asserted_principal, str)
                        and asserted_principal.strip() == principal.strip()
                    )

                    # Tenant match (where applicable)
                    has_valid_tenant = (
                        (asserted_tenant or "") == (destination.tenant_id or "")
                    )

                    # Account match (where applicable)
                    has_valid_account = (
                        (asserted_account or "") == (destination.account_id or "")
                    )

                    # Workspace and Endpoint match (where applicable)
                    has_valid_workspace = (
                        (asserted_workspace or "") == (destination.workspace_id or "")
                    )
                    has_valid_endpoint = (
                        (asserted_endpoint or "") == (destination.endpoint_path or "")
                    )

                    # Classification match
                    has_valid_class = bool(
                        asserted_class
                        and str(asserted_class).upper() == classification.value.upper()
                    )

                    # Source scope match
                    has_valid_scope = (
                        (asserted_scope or "") == (source_scope or "")
                    )

                    # Direction and operation match
                    has_valid_direction = bool(
                        asserted_direction
                        and str(asserted_direction).upper() == direction.value.upper()
                    )
                    has_valid_operation = bool(
                        asserted_operation
                        and str(asserted_operation).upper() == operation.value.upper()
                    )

                    # Strict Task ID binding: whenever task_id is present, assertion must bind it
                    if task_id is not None and task_id.strip():
                        has_valid_task = bool(
                            asserted_task and str(asserted_task).strip() == task_id.strip()
                        )
                    elif asserted_task is not None and str(asserted_task).strip():
                        has_valid_task = False
                    else:
                        has_valid_task = True

                    # Strict volume binding: whenever declared_bytes > 0, assertion must bind it
                    ctx_bytes = declared_bytes if declared_bytes is not None else 0
                    if ctx_bytes > 0:
                        has_valid_bytes = (
                            asserted_bytes is not None
                            and isinstance(asserted_bytes, int)
                            and ctx_bytes <= asserted_bytes
                        )
                    else:
                        has_valid_bytes = (
                            asserted_bytes is None
                            or (isinstance(asserted_bytes, int) and ctx_bytes <= asserted_bytes)
                        )

                    # Expiration is MANDATORY: missing expiration or expired fails closed
                    now = time.time()
                    has_valid_expiry = (
                        expires_at is not None
                        and isinstance(expires_at, (int, float))
                        and now < expires_at
                    )

                    trusted_pubkey = verifier._trusted_public_keys.get(issuer) if issuer else None

                    if (
                        issuer
                        and sig_hex
                        and trusted_pubkey
                        and has_valid_dest
                        and has_valid_principal
                        and has_valid_tenant
                        and has_valid_account
                        and has_valid_workspace
                        and has_valid_endpoint
                        and has_valid_class
                        and has_valid_scope
                        and has_valid_direction
                        and has_valid_operation
                        and has_valid_task
                        and has_valid_bytes
                        and has_valid_expiry
                    ):
                        try:
                            sig_bytes = bytes.fromhex(sig_hex)
                            dest_str = asserted_dest.strip().lower()
                            tenant_str = asserted_tenant or ""
                            account_str = asserted_account or ""
                            ws_str = asserted_workspace or ""
                            ep_str = asserted_endpoint or ""
                            scope_str = asserted_scope or ""
                            task_str = asserted_task or ""
                            bytes_str = str(asserted_bytes) if asserted_bytes is not None else ""
                            ts_str = (
                                f"{timestamp:.6f}" if isinstance(timestamp, (int, float))
                                else str(timestamp or "")
                            )
                            exp_str = (
                                f"{expires_at:.6f}" if isinstance(expires_at, (int, float))
                                else str(expires_at or "")
                            )
                            payload_extended = (
                                f"{asserted_principal.strip()}:{issuer}:{dest_str}:"
                                f"{tenant_str}:{account_str}:{ws_str}:{ep_str}:"
                                f"{asserted_class.upper()}:{scope_str}:"
                                f"{asserted_direction.upper()}:{asserted_operation.upper()}:"
                                f"{task_str}:{bytes_str}:{ts_str}:{exp_str}"
                            ).encode("utf-8")

                            if verify_ed25519_signature(
                                sig_bytes, payload_extended, trusted_pubkey
                            ):
                                is_trusted = True
                        except Exception:
                            is_trusted = False
            else:
                is_trusted = False

        return DataTransferContext(
            initiating_principal=principal,
            destination=destination,
            classification=classification,
            direction=direction,
            operation=operation,
            source_scope=source_scope,
            service_identity=service_identity,
            declared_bytes=declared_bytes,
            task_id=task_id,
            correlation_id=correlation_id,
            request_id=request_id,
            capability_token_id=capability_token_id,
            _is_classification_trusted=is_trusted,
            action_name=action_name,
            target=target,
            canonical_request_digest=canonical_request_digest,
            trusted_authority_assertion=trusted_authority_assertion if is_trusted else None,
            principal_verifier=principal_verifier if is_trusted else None
        )


@dataclass
class TransferDecision:
    """
    Authoritative outcome of transfer policy evaluation.
    """
    allowed: bool
    reason: str
    rule_id: Optional[str] = None
    requires_approval: bool = False
    max_permitted_bytes: Optional[int] = None
    reservation_id: Optional[str] = None
    reserved_bytes: int = 0
    matched_rule: Optional[Any] = None


@dataclass
class TransferRule:
    """
    Explicit context-aware transfer rule binding principal, destination service & tenant,
    host, classification ceilings, directions, operations, and volume constraints.
    """
    rule_id: str
    allowed_principals: Set[str] = field(default_factory=set)  # Principal IDs or '*'
    destination_service: Optional[str] = None                  # e.g. "onedrive", "google_drive"
    allowed_tenants: Set[str] = field(default_factory=set)     # Specific approved tenant IDs
    disallowed_tenants: Set[str] = field(default_factory=set)  # Explicitly prohibited tenants
    allowed_accounts: Set[str] = field(default_factory=set)    # Specific approved accounts
    allowed_hosts: Set[str] = field(default_factory=set)  # e.g. "graph.microsoft.com"
    allowed_wildcard_hosts: Set[str] = field(default_factory=set)
    max_classification: DataClassification = DataClassification.INTERNAL
    allowed_directions: Set[TransferDirection] = field(
        default_factory=lambda: {TransferDirection.UPLOAD, TransferDirection.DOWNLOAD}
    )
    allowed_operations: Set[TransferOperation] = field(
        default_factory=lambda: {TransferOperation.READ, TransferOperation.WRITE}
    )
    max_bytes_per_transfer: Optional[int] = None
    max_cumulative_bytes: Optional[int] = None
    require_capability: bool = False
    require_authenticated_principal: bool = True
    require_trusted_classification: bool = True
    source_scope_pattern: Optional[str] = None

    def __post_init__(self):
        if not self.rule_id:
            raise ValueError("TransferRule rule_id must be non-empty.")
        if self.destination_service:
            self.destination_service = self.destination_service.strip().lower()
        self.allowed_hosts = {h.strip().lower() for h in self.allowed_hosts}
        self.allowed_wildcard_hosts = {w.strip().lower() for w in self.allowed_wildcard_hosts}


class DataTransferPolicy:
    """
    Policy engine evaluating data transfer context against explicit rules,
    tenant authorization, classification limits, volume bounds, and capability binding.
    """

    def __init__(
        self,
        rules: Optional[List[TransferRule]] = None,
        default_max_cumulative_bytes: Optional[int] = None,
        protected_mode: bool = True,
        authorization_authority: Optional[Any] = None,
        principal_verifier: Optional[Any] = None
    ):
        self.rules: List[TransferRule] = list(rules or [])
        self.default_max_cumulative_bytes = default_max_cumulative_bytes
        self.protected_mode = protected_mode
        self.authorization_authority = authorization_authority
        self.principal_verifier = principal_verifier
        self._cumulative_bytes_tracker: Dict[str, int] = {}
        self._reserved_bytes_tracker: Dict[str, int] = {}
        self._active_reservations: Dict[str, Tuple[str, int]] = {}
        self._lock = threading.Lock()

    def add_rule(self, rule: TransferRule) -> None:
        self.rules.append(rule)

    def get_cumulative_bytes(self, tracker_key: str) -> int:
        with self._lock:
            return self._cumulative_bytes_tracker.get(tracker_key, 0)

    def get_allocated_bytes(self, tracker_key: str) -> int:
        with self._lock:
            committed = self._cumulative_bytes_tracker.get(tracker_key, 0)
            reserved = self._reserved_bytes_tracker.get(tracker_key, 0)
            return committed + reserved

    def get_in_flight_allocated_bytes(
        self, tracker_key: str, exclude_reservation_id: Optional[str] = None
    ) -> int:
        """
        Calculates the in-flight cumulative allocated bytes for a given scope, including all
        committed bytes and other active concurrent reservations, while excluding the current
        transfer's own reservation (if any) to prevent double counting.
        """
        with self._lock:
            committed = self._cumulative_bytes_tracker.get(tracker_key, 0)
            reserved = self._reserved_bytes_tracker.get(tracker_key, 0)
            if (
                exclude_reservation_id
                and exclude_reservation_id in self._active_reservations
            ):
                res_key, res_amt = self._active_reservations[exclude_reservation_id]
                if res_key == tracker_key:
                    reserved = max(0, reserved - res_amt)
            return committed + reserved

    def claim_in_flight_chunk(
        self,
        tracker_key: str,
        curr_transfer_total: int,
        reservation_id: Optional[str] = None,
        limit: Optional[int] = None
    ) -> bool:
        """
        Atomically checks and claims in-flight observed bytes for a streaming transfer under lock.
        Accounts for committed bytes, other concurrent active reservations, and the current
        transfer's total observed bytes across all hops. Dynamically expands or adjusts the
        active reservation under the policy lock so that any concurrent transfer immediately
        observes the newly claimed bytes, eliminating simultaneous streaming TOCTOU races.
        """
        if curr_transfer_total < 0:
            raise ValueError("curr_transfer_total must be non-negative.")
        with self._lock:
            committed = self._cumulative_bytes_tracker.get(tracker_key, 0)
            total_reserved = self._reserved_bytes_tracker.get(tracker_key, 0)

            # Compute reservations held by OTHER transfers
            current_res_amt = 0
            if reservation_id and reservation_id in self._active_reservations:
                res_key, current_res_amt = self._active_reservations[reservation_id]
                if res_key != tracker_key:
                    current_res_amt = 0

            other_reserved = max(0, total_reserved - current_res_amt)
            eff_limit = limit if limit is not None else self.default_max_cumulative_bytes

            if (
                eff_limit is not None
                and (committed + other_reserved + curr_transfer_total) > eff_limit
            ):
                return False

            # Atomically update this transfer's active reservation to hold observed volume
            if reservation_id and reservation_id in self._active_reservations:
                # Update reservation amount to max of initial declared bytes and observed bytes
                new_res_amt = max(current_res_amt, curr_transfer_total)
                self._active_reservations[reservation_id] = (tracker_key, new_res_amt)
                delta_res = new_res_amt - current_res_amt
                self._reserved_bytes_tracker[tracker_key] = total_reserved + delta_res
            return True

    def reserve_bytes(
        self,
        tracker_key: str,
        byte_count: int,
        reservation_id: str,
        limit: Optional[int] = None
    ) -> bool:
        """Atomically reserves capacity against the cumulative task limit."""
        if byte_count < 0:
            raise ValueError("byte_count must be non-negative.")
        with self._lock:
            if reservation_id in self._active_reservations:
                raise ValueError(f"Duplicate reservation ID '{reservation_id}' is not permitted.")
            committed = self._cumulative_bytes_tracker.get(tracker_key, 0)
            reserved = self._reserved_bytes_tracker.get(tracker_key, 0)
            eff_limit = limit if limit is not None else self.default_max_cumulative_bytes
            if eff_limit is not None and (committed + reserved + byte_count) > eff_limit:
                return False
            self._reserved_bytes_tracker[tracker_key] = reserved + byte_count
            self._active_reservations[reservation_id] = (tracker_key, byte_count)
            return True

    def commit_reservation(
        self, reservation_id: str, actual_bytes_observed: Optional[int] = None
    ) -> int:
        """Atomically commits a reservation with actual observed bytes."""
        with self._lock:
            if reservation_id not in self._active_reservations:
                return 0
            tracker_key, reserved_amount = self._active_reservations.pop(reservation_id)
            current_reserved = self._reserved_bytes_tracker.get(tracker_key, 0)
            self._reserved_bytes_tracker[tracker_key] = max(0, current_reserved - reserved_amount)

            bytes_to_commit = (
                actual_bytes_observed
                if actual_bytes_observed is not None
                else reserved_amount
            )
            current_committed = self._cumulative_bytes_tracker.get(tracker_key, 0)
            updated_committed = current_committed + bytes_to_commit
            self._cumulative_bytes_tracker[tracker_key] = updated_committed
            return updated_committed

    def refund_reservation(self, reservation_id: str) -> None:
        """Atomically refunds a reservation if a transfer fails, is rejected, or aborts."""
        with self._lock:
            if reservation_id not in self._active_reservations:
                return
            tracker_key, reserved_amount = self._active_reservations.pop(reservation_id)
            current_reserved = self._reserved_bytes_tracker.get(tracker_key, 0)
            self._reserved_bytes_tracker[tracker_key] = max(0, current_reserved - reserved_amount)

    def record_observed_bytes(
        self,
        tracker_key: str,
        byte_count: int,
        limit: Optional[int] = None
    ) -> int:
        if byte_count < 0:
            raise ValueError("byte_count must be non-negative.")
        with self._lock:
            current = self._cumulative_bytes_tracker.get(tracker_key, 0)
            reserved = self._reserved_bytes_tracker.get(tracker_key, 0)
            eff_limit = limit if limit is not None else self.default_max_cumulative_bytes
            if eff_limit is not None and (current + reserved + byte_count) > eff_limit:
                raise PermissionError(
                    f"Recording {byte_count} bytes exceeds cumulative limit of {eff_limit} bytes "
                    f"for scope '{tracker_key}'."
                )
            updated = current + byte_count
            self._cumulative_bytes_tracker[tracker_key] = updated
            return updated

    def reset_cumulative_bytes(self, tracker_key: Optional[str] = None) -> None:
        with self._lock:
            if tracker_key is not None:
                self._cumulative_bytes_tracker.pop(tracker_key, None)
                self._reserved_bytes_tracker.pop(tracker_key, None)
            else:
                self._cumulative_bytes_tracker.clear()
                self._reserved_bytes_tracker.clear()
                self._active_reservations.clear()

    def evaluate_and_reserve(
        self,
        context: DataTransferContext,
        capability: Optional[Any] = None,
        authority: Optional[Any] = None,
        reservation_id: Optional[str] = None
    ) -> TransferDecision:
        """
        Atomically evaluates transfer rules and reserves capacity against the matched
        rule's max_cumulative_bytes ceiling under lock, eliminating TOCTOU race conditions.
        """
        import uuid as _uuid
        res_id = reservation_id or str(_uuid.uuid4())
        eff_authority = authority or self.authorization_authority
        return self._evaluate_internal(
            context=context,
            capability=capability,
            authority=eff_authority,
            reserve=True,
            reservation_id=res_id
        )

    def evaluate_transfer(
        self,
        context: DataTransferContext,
        capability: Optional[Any] = None,
        authority: Optional[Any] = None,
        active_reservation_id: Optional[str] = None,
        allow_consumed_token: bool = False
    ) -> TransferDecision:
        """
        Evaluates DataTransferContext against registered rules without reserving.
        """
        eff_authority = authority or self.authorization_authority
        return self._evaluate_internal(
            context=context,
            capability=capability,
            authority=eff_authority,
            reserve=False,
            reservation_id=active_reservation_id,
            allow_consumed_token=allow_consumed_token
        )

    def _evaluate_internal(
        self,
        context: DataTransferContext,
        capability: Optional[Any] = None,
        authority: Optional[Any] = None,
        reserve: bool = False,
        reservation_id: Optional[str] = None,
        allow_consumed_token: bool = False
    ) -> TransferDecision:
        """Internal evaluation routine with atomic evaluation and reservation under lock."""
        if not isinstance(context, DataTransferContext):
            return TransferDecision(
                allowed=False,
                reason="Transfer blocked: Invalid or non-DataTransferContext provided."
            )

        # Fail closed on untrusted or unverified classification in protected mode
        if self.protected_mode:
            if not context._is_classification_trusted:
                return TransferDecision(
                    allowed=False,
                    reason=(
                        f"Transfer blocked: Classification '{context.classification.value}' "
                        "does not originate from a trusted authority or policy-controlled metadata."
                    )
                )

            # H1: Verify authority assertion strictly against the policy's configured trusted verifier.
            # A caller-supplied verifier on the context must never override the policy's trusted trust store.
            # Protected mode must fail closed when self.principal_verifier is absent or has no trusted issuers.
            # Fallback to context or evaluation-time authority verifier promotion is strictly prohibited.
            if self.principal_verifier is None or not getattr(self.principal_verifier, "has_trusted_issuers", lambda: False)():
                return TransferDecision(
                    allowed=False,
                    reason=(
                        f"Transfer blocked: Classification '{context.classification.value}' "
                        "cannot be verified; no trusted PrincipalVerifier configured on policy boundary."
                    )
                )

            effective_verifier = self.principal_verifier
            assertion = getattr(context, "trusted_authority_assertion", None)
            issuer = assertion.get("issuer") if isinstance(assertion, dict) else None
            trusted_keys = getattr(effective_verifier, "_trusted_public_keys", {})
            if issuer not in trusted_keys:
                return TransferDecision(
                    allowed=False,
                    reason=(
                        f"Transfer blocked: Classification '{context.classification.value}' "
                        f"assertion issuer '{issuer}' is not trusted by policy PrincipalVerifier."
                    )
                )
            if not context._verify_context_assertion(verifier_override=effective_verifier):
                return TransferDecision(
                    allowed=False,
                    reason=(
                        f"Transfer blocked: Classification '{context.classification.value}' "
                        "failed cryptographic authority assertion verification against policy trust store."
                    )
                )

        dest = context.destination
        principal = context.initiating_principal

        # Compute tracker key for cumulative task / principal limits
        tracker_key = context.task_id or f"{principal}:{dest.host}"

        # In strict enforcement, if observed_bytes exceeds declared_bytes (or is set),
        # volume_to_check must reflect the larger observed volume.
        volume_to_check = max(
            context.declared_bytes if context.declared_bytes is not None else 0,
            context.observed_bytes
        )

        matched_destination_host = False
        rejection_reasons: List[str] = []

        for rule in self.rules:
            # 1. Match destination host / service
            host_match = False
            if not rule.allowed_hosts and not rule.allowed_wildcard_hosts:
                # If no hosts specified, match any host if service matches
                if rule.destination_service and dest.service == rule.destination_service:
                    host_match = True
            else:
                if dest.host in rule.allowed_hosts:
                    host_match = True
                else:
                    for wc in rule.allowed_wildcard_hosts:
                        if wc.startswith("*."):
                            suffix = wc[1:]
                            if dest.host.endswith(suffix) and dest.host != suffix[1:]:
                                host_match = True
                                break

            if rule.destination_service and dest.service != rule.destination_service:
                host_match = False

            if not host_match:
                continue

            matched_destination_host = True

            # 2. Enforce Tenant / Account Identity (A hostname allowlist must not override tenant!)
            if rule.disallowed_tenants:
                if dest.tenant_id and dest.tenant_id in rule.disallowed_tenants:
                    rejection_reasons.append(
                        f"Destination tenant '{dest.tenant_id}' is explicitly disallowed "
                        f"by rule '{rule.rule_id}'."
                    )
                    continue

            if rule.allowed_tenants:
                if not dest.tenant_id:
                    rejection_reasons.append(
                        f"Rule '{rule.rule_id}' requires an authorized tenant identity, "
                        "but none was provided."
                    )
                    continue
                if dest.tenant_id not in rule.allowed_tenants:
                    rejection_reasons.append(
                        f"Destination tenant '{dest.tenant_id}' is not in approved tenants "
                        f"for rule '{rule.rule_id}'."
                    )
                    continue

            if rule.allowed_accounts:
                if not dest.account_id:
                    rejection_reasons.append(
                        f"Rule '{rule.rule_id}' requires an authorized account identity, "
                        "but none was provided."
                    )
                    continue
                if dest.account_id not in rule.allowed_accounts:
                    rejection_reasons.append(
                        f"Destination account '{dest.account_id}' is not in approved accounts "
                        f"for rule '{rule.rule_id}'."
                    )
                    continue

            # 3. Initiating Principal check
            if rule.allowed_principals and "*" not in rule.allowed_principals:
                if principal not in rule.allowed_principals:
                    rejection_reasons.append(
                        f"Principal '{principal}' is not authorized by rule '{rule.rule_id}'."
                    )
                    continue

            # 4. Data Classification ceiling check
            if context.classification > rule.max_classification:
                rejection_reasons.append(
                    f"Data classification '{context.classification.value}' exceeds rule "
                    f"'{rule.rule_id}' maximum classification '{rule.max_classification.value}'."
                )
                continue

            # 5. Operation & Direction check
            if context.direction not in rule.allowed_directions:
                rejection_reasons.append(
                    f"Direction '{context.direction.value}' is not permitted by rule "
                    f"'{rule.rule_id}'."
                )
                continue

            if context.operation not in rule.allowed_operations:
                rejection_reasons.append(
                    f"Operation '{context.operation.value}' is not permitted by rule "
                    f"'{rule.rule_id}'."
                )
                continue

            # 6. Volume Limits check
            if rule.max_bytes_per_transfer is not None and volume_to_check is not None:
                if volume_to_check > rule.max_bytes_per_transfer:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason=(
                            f"Transfer volume ({volume_to_check} bytes) exceeds rule "
                            f"'{rule.rule_id}' maximum limit of "
                            f"{rule.max_bytes_per_transfer} bytes."
                        ),
                        max_permitted_bytes=rule.max_bytes_per_transfer
                    )

            # 7. Capability & Scope Binding check
            if rule.require_capability:
                if not capability:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason=(
                            f"Rule '{rule.rule_id}' requires explicit capability authorization, "
                            "but none was provided."
                        ),
                        requires_approval=True
                    )

                if authority is None:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason=(
                            f"Rule '{rule.rule_id}' requires capability verification, but "
                            "AuthorizationAuthority is not configured."
                        ),
                        requires_approval=True
                    )

                cap_token = getattr(capability, "token_id", None)
                cap_sig = getattr(capability, "signature", None)
                if not cap_token or not cap_sig:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason="Capability missing valid token_id or cryptographic signature."
                    )

                # Independently derive expected authorization values from the transfer context
                if context.action_name:
                    expected_action = context.action_name
                elif dest.service:
                    expected_action = f"{dest.service}_{context.direction.value.lower()}"
                else:
                    expected_action = f"data_transfer:{context.operation.value.lower()}"

                if context.target:
                    expected_target = context.target
                elif dest.endpoint_path:
                    # Endpoint-level authorization: bind host and endpoint path into canonical target
                    norm_ep = dest.endpoint_path if dest.endpoint_path.startswith("/") else f"/{dest.endpoint_path}"
                    expected_target = f"{dest.host}{norm_ep}"
                elif dest.tenant_id:
                    expected_target = f"{dest.host}/{dest.tenant_id}"
                else:
                    expected_target = dest.host

                expected_digest = context.canonical_request_digest

                # Validate expected action independently against granted capability
                cap_action = getattr(capability, "action_name", "")
                if cap_action != expected_action:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason=(
                            f"Capability action mismatch: capability granted '{cap_action}', "
                            f"requested transfer operation requires '{expected_action}'."
                        )
                    )

                # Validate expected target independently against granted capability
                cap_target = getattr(capability, "target", "")
                expected_targets = {expected_target, dest.host}
                if dest.endpoint_path:
                    norm_ep = dest.endpoint_path if dest.endpoint_path.startswith("/") else f"/{dest.endpoint_path}"
                    expected_targets.add(f"{dest.host}{norm_ep}")
                if dest.tenant_id:
                    expected_targets.add(f"{dest.host}/{dest.tenant_id}")
                    expected_targets.add(dest.tenant_id)

                if cap_target != "*" and cap_target not in expected_targets:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason=(
                            f"Capability target mismatch: authorized target '{cap_target}' "
                            f"does not match requested target '{expected_target}'."
                        )
                    )

                # Validate request digest independently if expected_digest is specified
                cap_digest = getattr(capability, "canonical_request_digest", "")
                if expected_digest is not None and cap_digest != expected_digest:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason=(
                            f"Capability digest mismatch: capability bound to digest "
                            f"'{cap_digest}', requested transfer digest is '{expected_digest}'."
                        )
                    )

                # If AuthorizationAuthority is provided, perform independent verification
                if authority is not None:
                    if (
                        hasattr(authority, "registry")
                        and hasattr(authority.registry, "sign_capability")
                    ):
                        expected_sig = authority.registry.sign_capability(capability)
                        if not hmac.compare_digest(cap_sig, expected_sig):
                            return TransferDecision(
                                allowed=False,
                                rule_id=rule.rule_id,
                                reason="Capability verification failed: signature mismatch."
                            )

                    cap_executor = getattr(capability, "executor_id", "")
                    valid_cap, reason_cap, verified_cap = authority.verify_capability(
                        token_id=cap_token,
                        action_name=expected_action,
                        target=cap_target,
                        canonical_request_digest=expected_digest or cap_digest,
                        executor_id=cap_executor,
                        principal_id=principal,
                        task_id=context.task_id
                    )
                    if not valid_cap:
                        if allow_consumed_token and "ALREADY_CONSUMED" in reason_cap:
                            pass
                        else:
                            return TransferDecision(
                                allowed=False,
                                rule_id=rule.rule_id,
                                reason=f"Capability verification failed: {reason_cap}"
                            )

                # Validate capability principal binding against context
                cap_principal = getattr(capability, "principal_id", "")
                if cap_principal and cap_principal != principal:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason=(
                            f"Capability principal mismatch: bound to '{cap_principal}', "
                            f"initiated by '{principal}'."
                        )
                    )

                # Validate capability task ID against context
                cap_task_id = getattr(capability, "task_id", None)
                if context.task_id and cap_task_id and cap_task_id != context.task_id:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason=(
                            f"Capability task mismatch: capability task '{cap_task_id}', "
                            f"context task '{context.task_id}'."
                        )
                    )

            # 8. Indivisible Atomic Cumulative Volume Check & Reservation
            effective_max_cumulative = (
                rule.max_cumulative_bytes
                if rule.max_cumulative_bytes is not None
                else self.default_max_cumulative_bytes
            )
            with self._lock:
                if reserve and reservation_id and reservation_id in self._active_reservations:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason=f"Duplicate active reservation ID '{reservation_id}'."
                    )
                current_committed = self._cumulative_bytes_tracker.get(tracker_key, 0)
                current_reserved = self._reserved_bytes_tracker.get(tracker_key, 0)
                is_held = bool(reservation_id and reservation_id in self._active_reservations)
                if not reserve and is_held:
                    tot_vol = current_committed + current_reserved
                else:
                    tot_vol = current_committed + current_reserved + (volume_to_check or 0)

                if effective_max_cumulative is not None and tot_vol > effective_max_cumulative:
                    return TransferDecision(
                        allowed=False,
                        rule_id=rule.rule_id,
                        reason=(
                            f"Cumulative transfer volume ({tot_vol} bytes) exceeds "
                            f"maximum cumulative limit of {effective_max_cumulative} bytes "
                            f"for scope '{tracker_key}'."
                        ),
                        max_permitted_bytes=effective_max_cumulative
                    )

                if reserve and reservation_id:
                    self._reserved_bytes_tracker[tracker_key] = (
                        current_reserved + (volume_to_check or 0)
                    )
                    self._active_reservations[reservation_id] = (
                        tracker_key, volume_to_check or 0
                    )

            return TransferDecision(
                allowed=True,
                rule_id=rule.rule_id,
                reason=f"Transfer authorized under rule '{rule.rule_id}'.",
                max_permitted_bytes=rule.max_bytes_per_transfer,
                reservation_id=reservation_id if reserve else None,
                reserved_bytes=(volume_to_check or 0) if reserve else 0,
                matched_rule=rule
            )

        # No rule allowed the transfer
        if matched_destination_host:
            if rejection_reasons:
                reason = "Transfer denied: " + " ".join(rejection_reasons)
            else:
                reason = (
                    "Transfer denied: Destination host matched but transfer context "
                    "was not authorized."
                )
        else:
            reason = (
                f"Transfer denied: Destination host '{dest.host}' "
                "is not in approved transfer rules."
            )

        return TransferDecision(
            allowed=False,
            reason=reason
        )
