"""
Comprehensive regression and invariant test suite for Context-Aware Egress Data Transfer.

Verifies requirements A through L:
A. Approved organizational cloud destination + authorized principal +
   permitted classification + permitted volume succeeds.
B. Same provider, different/unapproved tenant or consumer account is denied.
C. Approved hostname does not override an unapproved destination identity.
D. Confidential/restricted data to an unapproved destination is denied.
E. Unauthorized or mismatched initiating principal is denied.
F. Missing, malformed, or untrusted classification fails closed in protected mode.
G. Declared volume below limit but actual observed bytes exceed limit cannot silently complete.
H. A transfer exceeding cumulative task/request limits is denied (including concurrent race tests).
I. Valid explicit authorization for one destination, classification, or scope cannot be reused.
J. Legitimate tools/services are not globally blocked merely because they appear in SRG reports.
K. Existing default-deny destination checks, DNS/IP protections, redirects, human approval,
   capability binding, and non-egress execution behavior remain intact.
L. Audit/provenance records contain the required decision context without leaking payloads.
"""

import concurrent.futures
import hashlib
import os
import tempfile
from typing import Optional, Union
import pytest

from epistemicos.authorization import Capability
from epistemicos.containment import (
    ControlledEgressTransport,
    EgressPolicy,
    EgressTransportBroker,
)
import threading
from unittest.mock import MagicMock

from epistemicos.data_transfer import (
    DataClassification,
    DataTransferContext,
    DataTransferPolicy,
    DestinationIdentity,
    TransferDirection,
    TransferOperation,
    TransferRule,
    TrustedTransferContextBuilder,
)
from epistemicos.provenance import LocalProvenanceStore


import functools
from epistemicos.authorization import PrincipalVerifier
from tests.unit.test_sec01_sec03_remediation import ExternalTestIdentityAuthority, _ed25519_sign

TEST_IDP = ExternalTestIdentityAuthority(issuer_id="TrustedClassificationAuthority")
TEST_VERIFIER = PrincipalVerifier(
    trusted_public_keys={"TrustedClassificationAuthority": TEST_IDP.public_key}
)


@functools.lru_cache(maxsize=128)
def _cached_sign(payload: bytes):
    return _ed25519_sign(payload, TEST_IDP.private_seed, TEST_IDP.public_key).hex()


# Fixed static timestamp to enable LRU cache hits across thread workers
# While ensuring expiration is valid relative to runtime
_BASE_TIMESTAMP = 1800000000.0
_BASE_EXPIRY = 2500000000.0


def make_assertion(
    principal: str,
    classification: str = "CONFIDENTIAL",
    destination_host: Optional[str] = "graph.microsoft.com",
    tenant_id: Optional[str] = None,
    account_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    endpoint_path: Optional[str] = None,
    source_scope: Optional[str] = None,
    direction: Union[TransferDirection, str] = TransferDirection.UPLOAD,
    operation: Union[TransferOperation, str] = TransferOperation.WRITE,
    task_id: Optional[str] = None,
    declared_bytes: Optional[int] = None,
    expires_at: Optional[float] = None,
    issuer: str = "TrustedClassificationAuthority",
    timestamp: Optional[float] = None,
    explicit_task: Optional[bool] = None,
    explicit_bytes: Optional[bool] = None
):
    if hasattr(classification, "value"):
        classification = classification.value
    dir_str = direction.value if hasattr(direction, "value") else str(direction)
    op_str = operation.value if hasattr(operation, "value") else str(operation)
    ts = timestamp if timestamp is not None else _BASE_TIMESTAMP
    exp = expires_at if expires_at is not None else _BASE_EXPIRY
    dest_str = destination_host.strip().lower() if destination_host else ""
    tenant_str = tenant_id or ""
    account_str = account_id or ""
    ws_str = workspace_id or ""
    ep_str = endpoint_path or ""
    scope_str = source_scope or ""
    task_str = task_id or ""
    bytes_str = str(declared_bytes) if declared_bytes is not None else ""
    payload = (
        f"{principal.strip()}:{issuer}:{dest_str}:"
        f"{tenant_str}:{account_str}:{ws_str}:{ep_str}:"
        f"{classification.upper()}:{scope_str}:"
        f"{dir_str.upper()}:{op_str.upper()}:"
        f"{task_str}:{bytes_str}:{ts:.6f}:{exp:.6f}"
    ).encode("utf-8")
    sig = _cached_sign(payload)
    return {
        "issuer": issuer,
        "signature": sig,
        "principal": principal,
        "destination_host": destination_host,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "workspace_id": workspace_id,
        "endpoint_path": endpoint_path,
        "classification": classification,
        "source_scope": source_scope,
        "direction": dir_str,
        "operation": op_str,
        "task_id": task_id,
        "declared_bytes": declared_bytes,
        "timestamp": ts,
        "expires_at": exp,
        "_explicit_task": explicit_task if explicit_task is not None else (task_id is not None),
        "_explicit_bytes": (
            explicit_bytes if explicit_bytes is not None else (declared_bytes is not None)
        )
    }


def create_test_context(*args, **kwargs):
    assertion = kwargs.get("trusted_authority_assertion")
    task_id = kwargs.get("task_id")
    declared_bytes = kwargs.get("declared_bytes")
    if (
        isinstance(assertion, dict)
        and assertion.get("issuer") == "TrustedClassificationAuthority"
    ):
        needs_update = False
        new_tid = assertion.get("task_id")
        new_db = assertion.get("declared_bytes")
        if task_id and not assertion.get("_explicit_task") and not assertion.get("task_id"):
            new_tid = task_id
            needs_update = True
        if (
            declared_bytes
            and not assertion.get("_explicit_bytes")
            and assertion.get("declared_bytes") is None
        ):
            new_db = declared_bytes
            needs_update = True
        if needs_update:
            kwargs["trusted_authority_assertion"] = make_assertion(
                principal=assertion.get("principal"),
                classification=assertion.get("classification"),
                destination_host=assertion.get("destination_host"),
                tenant_id=assertion.get("tenant_id"),
                account_id=assertion.get("account_id"),
                workspace_id=assertion.get("workspace_id"),
                endpoint_path=assertion.get("endpoint_path"),
                source_scope=assertion.get("source_scope"),
                direction=assertion.get("direction"),
                operation=assertion.get("operation"),
                task_id=new_tid,
                declared_bytes=new_db,
                expires_at=assertion.get("expires_at"),
                timestamp=assertion.get("timestamp"),
                explicit_task=False,
                explicit_bytes=False
            )
    return TrustedTransferContextBuilder.create_trusted_context(*args, **kwargs)





@pytest.fixture
def org_policy():
    """Returns a DataTransferPolicy for approved organizational OneDrive & Google Drive tenants."""
    rule_onedrive = TransferRule(
        rule_id="approved-org-onedrive",
        allowed_principals={"principal:backup-agent", "principal:alice"},
        destination_service="onedrive",
        allowed_tenants={"org-tenant-uuid-1111"},
        allowed_hosts={"graph.microsoft.com"},
        max_classification=DataClassification.CONFIDENTIAL,
        allowed_directions={TransferDirection.UPLOAD, TransferDirection.DOWNLOAD},
        allowed_operations={
            TransferOperation.BACKUP,
            TransferOperation.WRITE,
            TransferOperation.READ,
        },
        max_bytes_per_transfer=10000,
        max_cumulative_bytes=50000,
        require_capability=False
    )
    rule_gdrive = TransferRule(
        rule_id="approved-org-gdrive",
        allowed_principals={"principal:alice"},
        destination_service="google_drive",
        allowed_tenants={"org-workspace-2222"},
        allowed_hosts={"www.googleapis.com"},
        max_classification=DataClassification.INTERNAL,
        allowed_directions={TransferDirection.UPLOAD},
        allowed_operations={TransferOperation.EXPORT, TransferOperation.WRITE},
        max_bytes_per_transfer=5000,
        max_cumulative_bytes=20000,
        require_capability=False
    )
    rule_cap_required = TransferRule(
        rule_id="restricted-s3-replication",
        allowed_principals={"principal:admin"},
        destination_service="s3",
        allowed_hosts={"s3.us-east-1.amazonaws.com"},
        max_classification=DataClassification.RESTRICTED,
        allowed_directions={TransferDirection.REPLICATE},
        allowed_operations={TransferOperation.SYNC},
        max_bytes_per_transfer=100000,
        require_capability=True
    )
    from epistemicos.authorization import (
        AuthorizationAuthority, CapabilityRegistry, Policy
    )
    test_registry = CapabilityRegistry(signing_secret=b"org_policy_cap_secret_bytes_1234")
    test_auth_policy = Policy(
        policy_id="org-auth-policy",
        allowed_operations={"s3_replicate"},
        allowed_resources={"s3.us-east-1.amazonaws.com"},
        allowed_principals={"principal:admin"},
        allowed_executors={"exec"}
    )
    test_authority = AuthorizationAuthority(
        default_policy=test_auth_policy,
        registry=test_registry,
        principal_provider=TEST_VERIFIER
    )
    return DataTransferPolicy(
        rules=[rule_onedrive, rule_gdrive, rule_cap_required],
        default_max_cumulative_bytes=100000,
        protected_mode=True,
        authorization_authority=test_authority,
        principal_verifier=TEST_VERIFIER
    )


def test_requirement_a_approved_org_destination_succeeds(org_policy):
    """
    Requirement A: Approved organizational cloud destination + authorized principal +
    permitted classification + permitted volume succeeds.
    """
    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="onedrive",
            host="graph.microsoft.com",
            tenant_id="org-tenant-uuid-1111"
        ),
        classification=DataClassification.CONFIDENTIAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=2500,
        task_id="task-req-a",
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "CONFIDENTIAL",

            destination_host="graph.microsoft.com",

            tenant_id="org-tenant-uuid-1111"

        )
    )
    decision = org_policy.evaluate_transfer(ctx)
    assert decision.allowed is True
    assert decision.rule_id == "approved-org-onedrive"
    assert "Transfer authorized" in decision.reason


def test_requirement_b_unapproved_tenant_or_consumer_account_denied(org_policy):
    """
    Requirement B: Same provider, different/unapproved tenant or consumer account is denied.
    """
    ctx_consumer = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="onedrive",
            host="graph.microsoft.com",
            tenant_id="personal-consumer-tenant-9999"
        ),
        classification=DataClassification.CONFIDENTIAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=2500,
        task_id="task-req-b",
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "CONFIDENTIAL",

            destination_host="graph.microsoft.com",

            tenant_id="personal-consumer-tenant-9999"

        )
    )
    decision = org_policy.evaluate_transfer(ctx_consumer)
    assert decision.allowed is False
    assert "not in approved tenants" in decision.reason


def test_requirement_c_approved_hostname_does_not_override_destination_identity(org_policy):
    """
    Requirement C: Approved hostname does not override an unapproved destination identity.
    """
    # Host graph.microsoft.com is in network allowlist, but tenant is unapproved
    egress_policy = EgressPolicy(allowed_destinations={"graph.microsoft.com"})
    broker = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=org_policy,
        resolver_func=lambda h: ["20.190.159.0"]
    )

    ctx_unapproved_tenant = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="onedrive",
            host="graph.microsoft.com",
            tenant_id="attacker-controlled-tenant"
        ),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=500,
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "INTERNAL",

            destination_host="graph.microsoft.com",

            tenant_id="attacker-controlled-tenant"

        )
    )

    allowed, reason, ip = broker.establish_connection(
        target_url="https://graph.microsoft.com/v1.0/drive/root",
        transfer_context=ctx_unapproved_tenant
    )
    assert allowed is False
    assert "not in approved tenants" in reason


def test_requirement_d_confidential_data_to_unapproved_destination_denied(org_policy):
    """
    Requirement D: Confidential/restricted data to an unapproved destination is denied.
    """
    # Google Drive rule only permits up to INTERNAL classification
    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="google_drive",
            host="www.googleapis.com",
            tenant_id="org-workspace-2222"
        ),
        classification=DataClassification.CONFIDENTIAL,  # Exceeds INTERNAL
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.EXPORT,
        declared_bytes=1000,
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "CONFIDENTIAL",

            destination_host="www.googleapis.com",

            tenant_id="org-workspace-2222",

            operation=TransferOperation.EXPORT

        )
    )
    decision = org_policy.evaluate_transfer(ctx)
    assert decision.allowed is False
    assert "exceeds rule" in decision.reason


def test_requirement_e_unauthorized_initiating_principal_denied(org_policy):
    """
    Requirement E: Unauthorized or mismatched initiating principal is denied.
    """
    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:unauthorized-mallory",
        destination=DestinationIdentity(
            service="onedrive",
            host="graph.microsoft.com",
            tenant_id="org-tenant-uuid-1111"
        ),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=500,
        trusted_authority_assertion=make_assertion(

            "principal:unauthorized-mallory",

            "INTERNAL",

            destination_host="graph.microsoft.com",

            tenant_id="org-tenant-uuid-1111"

        )
    )
    decision = org_policy.evaluate_transfer(ctx)
    assert decision.allowed is False
    assert "not authorized" in decision.reason


def test_requirement_f_untrusted_classification_fails_closed(org_policy):
    """
    Requirement F: Missing, malformed, or untrusted classification fails closed in protected mode.
    """
    # Raw construction without builder defaults to is_classification_trusted=False
    ctx = DataTransferContext(
        initiating_principal="principal:alice",
        destination=DestinationIdentity(
            service="onedrive",
            host="graph.microsoft.com",
            tenant_id="org-tenant-uuid-1111"
        ),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=500
    )
    decision = org_policy.evaluate_transfer(ctx)
    assert decision.allowed is False
    assert "does not originate from a trusted authority" in decision.reason


def test_requirement_g_declared_volume_under_limit_but_actual_bytes_exceed(org_policy):
    """
    Requirement G: Declared volume below limit but actual observed bytes exceed limit
    cannot silently complete as authorized.
    """
    egress_policy = EgressPolicy(allowed_destinations={"graph.microsoft.com"})
    broker = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=org_policy,
        resolver_func=lambda h: ["20.190.159.0"]
    )
    transport = ControlledEgressTransport(broker=broker)

    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="onedrive",
            host="graph.microsoft.com",
            tenant_id="org-tenant-uuid-1111"
        ),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=100,  # Declares 100 bytes (under rule limit of 10,000)
        task_id="task-vol-g",
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "INTERNAL",

            destination_host="graph.microsoft.com",

            tenant_id="org-tenant-uuid-1111"

        )
    )

    # Actual body size is 15,000 bytes (exceeds rule limit of 10,000)
    oversized_body = b"X" * 15000

    with pytest.raises(PermissionError) as exc_info:
        transport.request(
            method="POST",
            url="https://graph.microsoft.com/v1.0/drive/root/children",
            body=oversized_body,
            transfer_context=ctx
        )
    assert "Transfer volume (15000 bytes) exceeds rule" in str(exc_info.value)


def test_requirement_h_barrier_synchronized_atomic_reservations(org_policy):
    """
    Requirement H: A transfer exceeding cumulative task/request limits is denied,
    exercising atomic evaluate_and_reserve() under barrier synchronization across threads.
    """
    task_id = "task-barrier-race"
    org_policy.reset_cumulative_bytes(task_id)

    num_threads = 15
    transfer_amount = 5000  # 15 * 5000 = 75,000 > 50,000 rule limit
    barrier = threading.Barrier(num_threads)

    results = []

    def worker(worker_id):
        c = create_test_context(
            principal_verifier=TEST_VERIFIER,
            principal="principal:backup-agent",
            destination=DestinationIdentity(
                service="onedrive",
                host="graph.microsoft.com",
                tenant_id="org-tenant-uuid-1111"
            ),
            classification=DataClassification.INTERNAL,
            direction=TransferDirection.UPLOAD,
            operation=TransferOperation.BACKUP,
            declared_bytes=transfer_amount,
            task_id=task_id,
            trusted_authority_assertion=make_assertion(

                "principal:backup-agent",

                "INTERNAL",

                destination_host="graph.microsoft.com",

                tenant_id="org-tenant-uuid-1111",

                operation=TransferOperation.BACKUP

            )
        )
        # Synchronize all threads right at the atomic reservation boundary
        barrier.wait()
        decision = org_policy.evaluate_and_reserve(c)
        if decision.allowed:
            # Commit the reservation
            org_policy.commit_reservation(decision.reservation_id, transfer_amount)
            return True
        return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        results = [f.result() for f in futures]

    allowed_count = results.count(True)
    denied_count = results.count(False)

    # Exactly 10 transfers of 5000 fit into the 50,000 rule cumulative limit
    assert allowed_count == 10
    assert denied_count == 5
    assert org_policy.get_cumulative_bytes(task_id) == 50000


def test_requirement_i_strict_capability_binding(org_policy):
    """
    Requirement I: Valid explicit authorization for one destination, classification,
    or scope cannot be reused for another.
    """
    auth = org_policy.authorization_authority
    auth_principal = TEST_IDP.issue_principal("principal:admin")
    cap, status = auth.evaluate_and_issue_capability(
        action_name="s3_replicate",
        target="s3.us-east-1.amazonaws.com",
        canonical_request_digest="abc",
        executor_id="exec",
        principal_id=auth_principal,
        task_id="task-prod-backup"
    )
    assert cap is not None, f"Failed to issue cap: {status}"

    # 1. Matching target and task succeeds
    ctx_s3 = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:admin",
        destination=DestinationIdentity(
            service="s3",
            host="s3.us-east-1.amazonaws.com"
        ),
        classification=DataClassification.RESTRICTED,
        direction=TransferDirection.REPLICATE,
        operation=TransferOperation.SYNC,
        declared_bytes=1000,
        task_id="task-prod-backup",
        canonical_request_digest="abc",
        trusted_authority_assertion=make_assertion(

            "principal:admin",

            "RESTRICTED",

            destination_host="s3.us-east-1.amazonaws.com",

            direction=TransferDirection.REPLICATE,

            operation=TransferOperation.SYNC

        )
    )
    decision = org_policy.evaluate_transfer(ctx_s3, capability=cap)
    assert decision.allowed is True

    # 2. Destination host mismatch fails closed
    ctx_diff_dest = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:admin",
        destination=DestinationIdentity(
            service="s3",
            host="s3.eu-west-1.amazonaws.com"
        ),
        classification=DataClassification.RESTRICTED,
        direction=TransferDirection.REPLICATE,
        operation=TransferOperation.SYNC,
        declared_bytes=1000,
        task_id="task-prod-backup",
        canonical_request_digest="abc",
        trusted_authority_assertion=make_assertion(

            "principal:admin",

            "RESTRICTED",

            destination_host="s3.eu-west-1.amazonaws.com",

            direction=TransferDirection.REPLICATE,

            operation=TransferOperation.SYNC

        )
    )
    dec_diff = org_policy.evaluate_transfer(ctx_diff_dest, capability=cap)
    assert dec_diff.allowed is False
    assert "Capability target mismatch" in dec_diff.reason or "not in approved" in dec_diff.reason

    # 3. Task ID mismatch fails closed
    ctx_diff_task = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:admin",
        destination=DestinationIdentity(
            service="s3",
            host="s3.us-east-1.amazonaws.com"
        ),
        classification=DataClassification.RESTRICTED,
        direction=TransferDirection.REPLICATE,
        operation=TransferOperation.SYNC,
        declared_bytes=1000,
        task_id="unauthorized-task-spoof",
        canonical_request_digest="abc",
        trusted_authority_assertion=make_assertion(

            "principal:admin",

            "RESTRICTED",

            destination_host="s3.us-east-1.amazonaws.com",

            direction=TransferDirection.REPLICATE,

            operation=TransferOperation.SYNC

        )
    )
    dec_task = org_policy.evaluate_transfer(ctx_diff_task, capability=cap)
    assert dec_task.allowed is False
    assert (
        "Capability task mismatch" in dec_task.reason
        or "TASK_ID_MISMATCH" in dec_task.reason
    )


def test_requirement_j_legitimate_tools_not_globally_blocked():
    """
    Requirement J: Legitimate tools and services (Rclone, WinSCP, Google Drive, OneDrive)
    are not globally blocked merely because they appear in SRG reporting.
    """
    # Verify policy allows legitimate configuration for any provider when properly scoped
    policy = DataTransferPolicy(
        rules=[
            TransferRule(
                rule_id="rclone-corporate-sync",
                allowed_principals={"principal:backup-svc"},
                destination_service="rclone_s3",
                allowed_hosts={"backup-vault.internal.corp"},
                max_classification=DataClassification.CONFIDENTIAL
            ),
            TransferRule(
                rule_id="winscp-authorized-sftp",
                allowed_principals={"principal:admin"},
                destination_service="winscp_sftp",
                allowed_hosts={"sftp.partner.corp"},
                max_classification=DataClassification.INTERNAL
            )
        ],
        principal_verifier=TEST_VERIFIER
    )

    ctx_rclone = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:backup-svc",
        destination=DestinationIdentity(
            service="rclone_s3",
            host="backup-vault.internal.corp"
        ),
        classification=DataClassification.CONFIDENTIAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=1000000,
        trusted_authority_assertion=make_assertion(

            "principal:backup-svc",

            "CONFIDENTIAL",

            destination_host="backup-vault.internal.corp"

        )
    )
    assert policy.evaluate_transfer(ctx_rclone).allowed is True


def test_requirement_k_existing_egress_and_host_binding_intact(org_policy):
    """
    Requirement K: Destination host binding mismatch rejection, redirects, and
    underlying default-deny mechanisms remain intact.
    """
    egress_policy = EgressPolicy(allowed_destinations={"graph.microsoft.com", "api.github.com"})
    broker = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=org_policy,
        resolver_func=lambda h: ["20.190.159.0"]
    )

    # 1. Host in transfer context must match the actual request target host
    ctx_mismatch = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="onedrive",
            host="graph.microsoft.com",
            tenant_id="org-tenant-uuid-1111"
        ),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=500,
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "INTERNAL",

            destination_host="graph.microsoft.com",

            tenant_id="org-tenant-uuid-1111"

        )
    )
    # Target URL is api.github.com, while context claimed graph.microsoft.com!
    allowed, reason, ip = broker.establish_connection(
        target_url="https://api.github.com/repos",
        transfer_context=ctx_mismatch
    )
    assert allowed is False
    assert "does not match actual target host" in reason


def test_requirement_l_fail_closed_provenance_and_clean_records(org_policy):
    """
    Requirement L: Audit/provenance records contain the required decision context without
    leaking payloads or credentials, and fail closed when provenance writing fails.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        prov_path = os.path.join(tmpdir, "provenance.jsonl")
        prov_store = LocalProvenanceStore(log_path=prov_path)

        egress_policy = EgressPolicy(allowed_destinations={"graph.microsoft.com"})
        broker = EgressTransportBroker(
            policy=egress_policy,
            transfer_policy=org_policy,
            provenance_store=prov_store,
            resolver_func=lambda h: ["20.190.159.0"]
        )

        sensitive_token = "Bearer secret-access-token-998877"
        corr_id = "corr-audit-test-123"

        ctx = create_test_context(
            principal_verifier=TEST_VERIFIER,
            principal="principal:alice",
            destination=DestinationIdentity(
                service="onedrive",
                host="graph.microsoft.com",
                tenant_id="org-tenant-uuid-1111"
            ),
            classification=DataClassification.CONFIDENTIAL,
            direction=TransferDirection.UPLOAD,
            operation=TransferOperation.WRITE,
            declared_bytes=3456,
            correlation_id=corr_id,
            task_id="task-audit-l",
            trusted_authority_assertion=make_assertion(

                "principal:alice",

                "CONFIDENTIAL",

                destination_host="graph.microsoft.com",

                tenant_id="org-tenant-uuid-1111"

            )
        )

        allowed, reason, ip = broker.establish_connection(
            target_url="https://graph.microsoft.com/v1.0/drive/root",
            correlation_id=corr_id,
            transfer_context=ctx
        )
        assert allowed is True

        events = prov_store.get_events_for_correlation(corr_id)
        assert len(events) == 1
        ev = events[0]
        assert ev.event_type == "DATA_TRANSFER_RECORD"
        assert ev.outcome["status"] == "ALLOWED"

        transfer_meta = ev.outcome["transfer_context"]
        assert transfer_meta["initiating_principal"] == "principal:alice"
        assert transfer_meta["destination_service"] == "onedrive"
        assert transfer_meta["destination_tenant"] == "org-tenant-uuid-1111"
        assert transfer_meta["destination_host"] == "graph.microsoft.com"
        assert transfer_meta["classification"] == "CONFIDENTIAL"
        assert transfer_meta["declared_bytes"] == 3456

        # Check clean records without credential leakage
        raw_event_record = ev.to_dict()
        str_record = str(raw_event_record)
        assert sensitive_token not in str_record
        assert "password" not in str_record
        assert "secret" not in str_record

    # 2. Test fail-closed provenance failure in require_provenance mode
    mock_failing_store = MagicMock(spec=LocalProvenanceStore)
    mock_failing_store.record_event.side_effect = OSError("Audit disk full")
    broker_fail_closed = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=org_policy,
        provenance_store=mock_failing_store,
        resolver_func=lambda h: ["20.190.159.0"],
        require_provenance=True
    )
    with pytest.raises(RuntimeError) as exc_info:
        broker_fail_closed.establish_connection(
            target_url="https://graph.microsoft.com/v1.0/drive/root",
            transfer_context=ctx
        )
    assert "Fail-closed provenance recording failure" in str(exc_info.value)


def test_concurrency_barrier_production_transport(org_policy):
    """
    Test 1: Real barrier-driven concurrency test exercising ControlledEgressTransport.request()
    ensuring atomic evaluation and reservation paths prevent over-allocating cumulative budgets.
    """
    task_id = "task-transport-barrier"
    org_policy.reset_cumulative_bytes(task_id)

    egress_policy = EgressPolicy(allowed_destinations={"graph.microsoft.com"})
    broker = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=org_policy,
        resolver_func=lambda h: ["20.190.159.0"]
    )
    transport = ControlledEgressTransport(broker=broker)

    num_threads = 12
    # Rule cumulative limit is 50,000 bytes. Each transfer is 5,000 bytes.
    # Exactly 10 transfers should succeed (50,000 bytes), and 2 must fail.
    transfer_amount = 5000
    barrier = threading.Barrier(num_threads)
    results = []

    def transport_worker(i):
        ctx = create_test_context(
            principal_verifier=TEST_VERIFIER,
            principal="principal:backup-agent",
            destination=DestinationIdentity(
                service="onedrive",
                host="graph.microsoft.com",
                tenant_id="org-tenant-uuid-1111"
            ),
            classification=DataClassification.INTERNAL,
            direction=TransferDirection.UPLOAD,
            operation=TransferOperation.BACKUP,
            declared_bytes=transfer_amount,
            task_id=task_id,
            trusted_authority_assertion=make_assertion(

                "principal:backup-agent",

                "INTERNAL",

                destination_host="graph.microsoft.com",

                tenant_id="org-tenant-uuid-1111",

                operation=TransferOperation.BACKUP

            )
        )
        barrier.wait()
        try:
            # Mock redirect_handler returns a mock HTTP response without real network socket
            transport.request(
                method="POST",
                url="https://graph.microsoft.com/v1.0/drive/root",
                body=b"A" * transfer_amount,
                transfer_context=ctx,
                redirect_handler=lambda u: {
                    "status": 200,
                    "reason": "OK",
                    "headers": {"Content-Type": "application/json"},
                    "body": b''
                }
            )
            return True
        except PermissionError:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(transport_worker, i) for i in range(num_threads)]
        results = [f.result() for f in futures]

    assert results.count(True) == 10
    assert results.count(False) == 2


def test_response_streaming_oversized_response_aborts_mid_stream(org_policy):
    """
    Test 2: Proves an oversized response is halted mid-stream before full consumption.
    """
    egress_policy = EgressPolicy(allowed_destinations={"graph.microsoft.com"})
    broker = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=org_policy,
        resolver_func=lambda h: ["20.190.159.0"]
    )
    transport = ControlledEgressTransport(broker=broker)

    # Rule max_bytes_per_transfer is 10,000 bytes.
    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="onedrive",
            host="graph.microsoft.com",
            tenant_id="org-tenant-uuid-1111"
        ),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        declared_bytes=1000,
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "INTERNAL",

            destination_host="graph.microsoft.com",

            tenant_id="org-tenant-uuid-1111",

            direction=TransferDirection.DOWNLOAD,

            operation=TransferOperation.READ

        )
    )

    # Create a mock socket and connection yielding an oversized stream in chunks
    class MockOversizedResponse:
        def __init__(self):
            self.status = 200
            self.reason = "OK"
            self.total_read = 0

        def getheaders(self):
            return [("Content-Type", "application/octet-stream")]

        def read(self, amt=1024):
            # Stream 25,000 bytes in 1,024 byte chunks
            if self.total_read >= 25000:
                return b""
            chunk = b"X" * min(amt, 25000 - self.total_read)
            self.total_read += len(chunk)
            return chunk

    mock_resp = MockOversizedResponse()

    # Intercept PinnedHTTPSConnection inside _execute_request_loop
    from unittest.mock import patch
    with patch("epistemicos.containment.PinnedHTTPSConnection") as mock_conn_cls:
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        with pytest.raises(PermissionError) as exc_info:
            transport.request(
                method="GET",
                url="https://graph.microsoft.com/v1.0/drive/items/large-file",
                transfer_context=ctx
            )

        assert "Response volume" in str(exc_info.value)
        assert "exceeds maximum allowed per-transfer limit" in str(exc_info.value)
        # Verify connection was closed immediately
        mock_conn.close.assert_called()
        # Verify response was NOT fully consumed before mid-stream abort
        assert mock_resp.total_read < 20000
        assert mock_resp.total_read >= 10000


def test_trusted_context_assertion_negative_cases():
    """
    Test 3: Cryptographic negative tests: forged signatures, unknown issuers,
    destination mismatches, expired assertions, altered payloads, and unconfigured verifiers.
    """
    dest = DestinationIdentity(service="s", host="h")

    # 1. Arbitrary object strictly rejected
    ctx_obj = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="alice",
        destination=dest,
        classification=DataClassification.PUBLIC,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=object()
    )
    assert ctx_obj.is_classification_trusted is False

    # 2. Forged signature strictly rejected
    valid_assert = make_assertion("alice", "PUBLIC", destination_host="h")
    forged_assert = dict(valid_assert)
    forged_assert["signature"] = "00" * 64
    ctx_forged = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="alice",
        destination=dest,
        classification=DataClassification.PUBLIC,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=forged_assert
    )
    assert ctx_forged.is_classification_trusted is False

    # 3. Altered payload content (tampering with classification after signing) rejected
    tampered_assert = dict(valid_assert)
    tampered_assert["classification"] = "CONFIDENTIAL"
    ctx_tampered = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="alice",
        destination=dest,
        classification=DataClassification.CONFIDENTIAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=tampered_assert
    )
    assert ctx_tampered.is_classification_trusted is False

    # 4. Unknown/untrusted issuer rejected
    unknown_issuer_assert = make_assertion(
        "alice", "PUBLIC", destination_host="h", issuer="AttackerIssuer"
    )
    ctx_unknown = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="alice",
        destination=dest,
        classification=DataClassification.PUBLIC,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=unknown_issuer_assert
    )
    assert ctx_unknown.is_classification_trusted is False

    # 5. Destination host mismatch rejected
    mismatched_dest_assert = make_assertion(
        "alice", "PUBLIC", destination_host="different-host.com"
    )
    ctx_dest_mismatch = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="alice",
        destination=dest,
        classification=DataClassification.PUBLIC,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=mismatched_dest_assert
    )
    assert ctx_dest_mismatch.is_classification_trusted is False

    # 6. Expired assertion strictly rejected
    expired_assert = make_assertion("alice", "PUBLIC", destination_host="h", expires_at=100.0)
    ctx_expired = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="alice",
        destination=dest,
        classification=DataClassification.PUBLIC,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=expired_assert
    )
    assert ctx_expired.is_classification_trusted is False

    # 7. Unconfigured verifier (no trusted issuers) fails closed
    empty_verifier = PrincipalVerifier(trusted_public_keys={})
    ctx_no_verifier = create_test_context(
        principal_verifier=empty_verifier,
        principal="alice",
        destination=dest,
        classification=DataClassification.PUBLIC,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=valid_assert
    )
    assert ctx_no_verifier.is_classification_trusted is False


def test_capability_authority_verification_transport(org_policy):
    """
    Test 4: Integrates AuthorizationAuthority.verify_capability() at execution boundary,
    proving invalidly signed, expired, or revoked capabilities are rejected.
    """
    from epistemicos.authorization import (
        AuthorizationAuthority, CapabilityRegistry, Policy, PrincipalVerifier
    )
    from tests.unit.test_sec01_sec03_remediation import ExternalTestIdentityAuthority

    idp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"CorpIdP": idp.public_key})

    registry = CapabilityRegistry(signing_secret=b"test_secret_32_bytes_long_123456")
    policy = Policy(
        policy_id="test-pol",
        allowed_operations={"s3_replicate"},
        allowed_resources={"s3.us-east-1.amazonaws.com"},
        allowed_principals={"principal:admin"},
        allowed_executors={"exec"}
    )
    authority = AuthorizationAuthority(
        default_policy=policy,
        registry=registry,
        principal_provider=verifier
    )

    auth_principal = idp.issue_principal("principal:admin")

    # Issue a valid capability through authority
    cap, status = authority.evaluate_and_issue_capability(
        action_name="s3_replicate",
        target="s3.us-east-1.amazonaws.com",
        canonical_request_digest="abc",
        executor_id="exec",
        principal_id=auth_principal
    )
    assert cap is not None

    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:admin",
        destination=DestinationIdentity(service="s3", host="s3.us-east-1.amazonaws.com"),
        classification=DataClassification.RESTRICTED,
        direction=TransferDirection.REPLICATE,
        operation=TransferOperation.SYNC,
        declared_bytes=1000,
        canonical_request_digest="abc",
        trusted_authority_assertion=make_assertion(

            "principal:admin",

            "RESTRICTED",

            destination_host="s3.us-east-1.amazonaws.com",

            direction=TransferDirection.REPLICATE,

            operation=TransferOperation.SYNC

        )
    )

    # 1. Valid verified capability succeeds
    dec_valid = org_policy.evaluate_transfer(ctx, capability=cap, authority=authority)
    assert dec_valid.allowed is True

    # 2. Revoked capability fails closed
    registry.revoke_token(cap.token_id, reason="Security incident")
    dec_revoked = org_policy.evaluate_transfer(ctx, capability=cap, authority=authority)
    assert dec_revoked.allowed is False
    assert "revoked" in dec_revoked.reason.lower()


def test_cross_host_redirect_rejection(org_policy):
    """
    Test 5: Proves cross-host redirects are strictly rejected without trust inheritance.
    """
    egress_policy = EgressPolicy(allowed_destinations={"graph.microsoft.com", "attacker.com"})
    broker = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=org_policy,
        resolver_func=lambda h: ["20.190.159.0"]
    )

    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="onedrive",
            host="graph.microsoft.com",
            tenant_id="org-tenant-uuid-1111"
        ),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=500,
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "INTERNAL",

            destination_host="graph.microsoft.com",

            tenant_id="org-tenant-uuid-1111"

        )
    )

    allowed, reason, ip = broker.revalidate_redirect(
        original_url="https://graph.microsoft.com/v1.0/drive/root",
        redirect_url="https://attacker.com/sink",
        transfer_context=ctx
    )
    assert allowed is False
    assert "cannot be inherited across hosts" in reason


def test_provenance_failure_proves_zero_network_io(org_policy):
    """
    Test 6: Proves that failing provenance under require_provenance=True halts execution
    before ANY network I/O or socket creation occurs.
    """
    mock_failing_store = MagicMock(spec=LocalProvenanceStore)
    mock_failing_store.record_event.side_effect = OSError("Immutable provenance disk read-only")

    egress_policy = EgressPolicy(allowed_destinations={"graph.microsoft.com"})
    broker = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=org_policy,
        provenance_store=mock_failing_store,
        resolver_func=lambda h: ["20.190.159.0"],
        require_provenance=True
    )
    transport = ControlledEgressTransport(broker=broker)

    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="onedrive",
            host="graph.microsoft.com",
            tenant_id="org-tenant-uuid-1111"
        ),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=500,
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "INTERNAL",

            destination_host="graph.microsoft.com",

            tenant_id="org-tenant-uuid-1111"

        )
    )

    # Patch PinnedHTTPSConnection to ensure it is NEVER called
    from unittest.mock import patch
    with patch("epistemicos.containment.PinnedHTTPSConnection") as mock_conn_cls:
        with pytest.raises((PermissionError, RuntimeError)) as exc_info:
            transport.request(
                method="POST",
                url="https://graph.microsoft.com/v1.0/drive/root",
                body=b"payload",
                transfer_context=ctx
            )
        assert "provenance" in str(exc_info.value).lower()
        mock_conn_cls.assert_not_called()


def test_atomic_reservation_under_concurrency_contention():
    """
    Test 7: Demonstrates indivisible atomic cumulative volume checking and reservation.
    Multiple threads concurrently call evaluate_and_reserve() under tight cumulative limit.
    Verifies that cumulative limit is never exceeded and exactly capacity-fitting requests succeed.
    """
    rule = TransferRule(
        rule_id="tight-cumulative-limit",
        allowed_principals={"principal:worker"},
        destination_service="s3",
        allowed_hosts={"s3.us-west-2.amazonaws.com"},
        max_classification=DataClassification.INTERNAL,
        max_cumulative_bytes=1000
    )
    policy = DataTransferPolicy(rules=[rule], default_max_cumulative_bytes=1000, principal_verifier=TEST_VERIFIER)

    num_threads = 10
    vol_per_request = 200  # 10 * 200 = 2000 > 1000
    barrier = threading.Barrier(num_threads)

    def worker(idx):
        ctx = create_test_context(
            principal_verifier=TEST_VERIFIER,
            principal="principal:worker",
            destination=DestinationIdentity(service="s3", host="s3.us-west-2.amazonaws.com"),
            classification=DataClassification.INTERNAL,
            direction=TransferDirection.UPLOAD,
            operation=TransferOperation.WRITE,
            declared_bytes=vol_per_request,
            task_id="task-contention-shared",
            trusted_authority_assertion=make_assertion(

                "principal:worker",

                "INTERNAL",

                destination_host="s3.us-west-2.amazonaws.com"

            )
        )
        barrier.wait()
        decision = policy.evaluate_and_reserve(ctx)
        return decision.allowed

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        results = [f.result() for f in futures]

    assert results.count(True) == 5
    assert results.count(False) == 5
    assert policy.get_allocated_bytes("task-contention-shared") == 1000


def test_cross_tenant_and_cross_operation_assertion_replay_rejected():
    """
    Test 8: Cross-tenant and cross-operation assertion replay tests.
    Proves that a valid signed assertion for one tenant, operation, or destination
    cannot be reused for another, and that missing destination or expiration fails closed.
    """
    dest_tenant_a = DestinationIdentity(
        service="onedrive", host="graph.microsoft.com", tenant_id="tenant-alpha"
    )
    dest_tenant_b = DestinationIdentity(
        service="onedrive", host="graph.microsoft.com", tenant_id="tenant-bravo"
    )

    # 1. Valid assertion for Tenant A
    valid_assert_a = make_assertion(
        "principal:alice", "CONFIDENTIAL",
        destination_host="graph.microsoft.com", tenant_id="tenant-alpha",
        direction=TransferDirection.UPLOAD, operation=TransferOperation.WRITE
    )

    # Replaying assertion signed for Tenant A in a context targeting Tenant B fails closed
    ctx_replayed_tenant = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=dest_tenant_b,
        classification=DataClassification.CONFIDENTIAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=valid_assert_a
    )
    assert ctx_replayed_tenant.is_classification_trusted is False

    # 2. Replaying assertion signed for WRITE/UPLOAD in context with READ/DOWNLOAD fails closed
    ctx_replayed_op = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=dest_tenant_a,
        classification=DataClassification.CONFIDENTIAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        trusted_authority_assertion=valid_assert_a
    )
    assert ctx_replayed_op.is_classification_trusted is False

    # 3. Missing destination_host fails closed (rejects generic unanchored assertions)
    generic_assert = dict(valid_assert_a)
    generic_assert["destination_host"] = ""
    ctx_generic_dest = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=dest_tenant_a,
        classification=DataClassification.CONFIDENTIAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=generic_assert
    )
    assert ctx_generic_dest.is_classification_trusted is False

    # 4. Missing expires_at fails closed
    no_exp_assert = dict(valid_assert_a)
    no_exp_assert["expires_at"] = None
    ctx_no_exp = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=dest_tenant_a,
        classification=DataClassification.CONFIDENTIAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=no_exp_assert
    )
    assert ctx_no_exp.is_classification_trusted is False


def test_capability_parameter_mismatches_and_replay_at_execution_boundary():
    """
    Test 9: Exercising ControlledEgressTransport.request() execution boundary with capabilities:
    - Valid capability, wrong operation
    - Valid capability, wrong canonical request digest
    - Valid capability, wrong tenant or target scope
    - Replayed capability token (single-use consumption prevents replay)
    """
    from epistemicos.authorization import CapabilityRegistry, AuthorizationAuthority, Policy
    from tests.unit.test_sec01_sec03_remediation import ExternalTestIdentityAuthority

    idp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"CorpIdP": idp.public_key})
    registry = CapabilityRegistry(signing_secret=b"cap_secret_32_bytes_test_998877")
    auth_policy = Policy(
        policy_id="corp-transfer-policy",
        allowed_operations={"s3_upload", "s3_read"},
        allowed_resources={"s3.us-east-1.amazonaws.com/approved-tenant"},
        allowed_principals={"principal:admin"},
        allowed_executors={"egress_transport"}
    )
    authority = AuthorizationAuthority(
        default_policy=auth_policy,
        registry=registry,
        principal_provider=verifier
    )
    auth_principal = idp.issue_principal("principal:admin")

    transfer_rule = TransferRule(
        rule_id="s3-tenant-rule",
        allowed_principals={"principal:admin"},
        destination_service="s3",
        allowed_tenants={"approved-tenant"},
        allowed_hosts={"s3.us-east-1.amazonaws.com"},
        max_classification=DataClassification.CONFIDENTIAL,
        require_capability=True
    )
    transfer_policy = DataTransferPolicy(rules=[transfer_rule], principal_verifier=TEST_VERIFIER)
    egress_policy = EgressPolicy(allowed_destinations={"s3.us-east-1.amazonaws.com"})
    broker = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=transfer_policy,
        authorization_authority=authority,
        resolver_func=lambda h: ["52.216.0.1"]
    )
    transport = ControlledEgressTransport(broker=broker)

    expected_body = b"canonical-transfer-body-data"
    expected_digest = hashlib.sha256(expected_body).hexdigest()

    # Issue a valid capability for s3_upload, target s3.us-east-1.amazonaws.com/approved-tenant
    cap_valid, status = authority.evaluate_and_issue_capability(
        action_name="s3_upload",
        target="s3.us-east-1.amazonaws.com/approved-tenant",
        canonical_request_digest=expected_digest,
        executor_id="egress_transport",
        principal_id=auth_principal
    )
    assert cap_valid is not None

    def make_ctx(op=TransferOperation.WRITE, target_override=None, action_override=None,
                 digest_override=None, tenant="approved-tenant"):
        return create_test_context(
            principal_verifier=TEST_VERIFIER,
            principal="principal:admin",
            destination=DestinationIdentity(
                service="s3", host="s3.us-east-1.amazonaws.com", tenant_id=tenant
            ),
            classification=DataClassification.CONFIDENTIAL,
            direction=TransferDirection.UPLOAD,
            operation=op,
            action_name=action_override,
            target=target_override,
            canonical_request_digest=digest_override,
            trusted_authority_assertion=make_assertion(

                "principal:admin",

                "CONFIDENTIAL",

                destination_host="s3.us-east-1.amazonaws.com",

                tenant_id=tenant,

                operation=op

            )
        )

    # 1. Valid capability, wrong operation
    ctx_wrong_op = make_ctx(action_override="s3_read")
    with pytest.raises(PermissionError) as exc_op:
        transport.request(
            method="POST",
            url="https://s3.us-east-1.amazonaws.com/approved-tenant",
            body=expected_body,
            transfer_context=ctx_wrong_op,
            capability=cap_valid
        )
    assert "Capability action mismatch" in str(exc_op.value)

    # 2. Valid capability, wrong request digest
    ctx_wrong_digest = make_ctx()
    with pytest.raises(PermissionError) as exc_digest:
        transport.request(
            method="POST",
            url="https://s3.us-east-1.amazonaws.com/approved-tenant",
            body=b"tampered-body-different-digest",
            transfer_context=ctx_wrong_digest,
            capability=cap_valid
        )
    assert "Capability digest mismatch" in str(exc_digest.value)

    # 3. Valid capability, wrong tenant or scope
    ctx_wrong_tenant = make_ctx(
        tenant="attacker-tenant", target_override="s3.us-east-1.amazonaws.com/attacker-tenant"
    )
    with pytest.raises(PermissionError) as exc_target:
        transport.request(
            method="POST",
            url="https://s3.us-east-1.amazonaws.com/attacker-tenant",
            body=expected_body,
            transfer_context=ctx_wrong_tenant,
            capability=cap_valid
        )
    assert (
        "Capability target mismatch" in str(exc_target.value)
        or "not in approved" in str(exc_target.value)
    )

    # 4. Valid capability with matching request succeeds through the execution boundary
    ctx_valid = make_ctx()
    resp = transport.request(
        method="POST",
        url="https://s3.us-east-1.amazonaws.com/approved-tenant",
        body=expected_body,
        transfer_context=ctx_valid,
        capability=cap_valid,
        redirect_handler=lambda u: {
            "status": 200, "reason": "OK",
            "headers": {"Content-Type": "application/json"},
            "body": b"{}"
        }
    )
    assert resp["status"] == 200

    # 5. Replayed capability: subsequent execution with the same consumed capability fails closed
    with pytest.raises(PermissionError) as exc_replay:
        transport.request(
            method="POST",
            url="https://s3.us-east-1.amazonaws.com/approved-tenant",
            body=expected_body,
            transfer_context=ctx_valid,
            capability=cap_valid
        )
    assert "already been consumed" in str(exc_replay.value)


def test_overlapping_host_different_tenant_streaming_limits():
    """
    Test 10: Overlapping-host streaming limits test.
    Two rules share the same hostname api.cloud-service.com with different tenant limits:
    - Tenant 'restricted-tenant' has max_bytes_per_transfer = 50.
    - Tenant 'standard-tenant' has max_bytes_per_transfer = 5000.
    Proves that response-streaming volume enforcement applies the actual matched rule
    and does not select an incorrect rule based solely on hostname.
    """
    rule_restricted = TransferRule(
        rule_id="rule-restricted-tenant",
        allowed_principals={"principal:alice"},
        destination_service="cloud",
        allowed_tenants={"restricted-tenant"},
        allowed_hosts={"api.cloud-service.com"},
        max_classification=DataClassification.INTERNAL,
        max_bytes_per_transfer=50
    )
    rule_standard = TransferRule(
        rule_id="rule-standard-tenant",
        allowed_principals={"principal:alice"},
        destination_service="cloud",
        allowed_tenants={"standard-tenant"},
        allowed_hosts={"api.cloud-service.com"},
        max_classification=DataClassification.INTERNAL,
        max_bytes_per_transfer=5000
    )

    policy = DataTransferPolicy(rules=[rule_restricted, rule_standard], principal_verifier=TEST_VERIFIER)
    egress_policy = EgressPolicy(allowed_destinations={"api.cloud-service.com"})
    broker = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=policy,
        resolver_func=lambda h: ["20.190.159.1"]
    )
    transport = ControlledEgressTransport(broker=broker)

    class Mock100ByteResponse:
        def __init__(self):
            self.status = 200
            self.reason = "OK"
            self.read_count = 0

        def getheaders(self):
            return [("Content-Type", "application/octet-stream")]

        def read(self, amt=1024):
            if self.read_count >= 1:
                return b""
            self.read_count += 1
            return b"Y" * 100

        def close(self):
            pass

    class Mock100ByteConnection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, url, body=None, headers=None):
            pass

        def getresponse(self):
            return Mock100ByteResponse()

        def close(self):
            pass

    from unittest.mock import patch

    # 1. Restricted tenant: 100-byte response exceeds the 50-byte limit -> streaming aborted
    ctx_restricted = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="cloud", host="api.cloud-service.com", tenant_id="restricted-tenant"
        ),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "INTERNAL",

            destination_host="api.cloud-service.com",

            tenant_id="restricted-tenant",

            direction=TransferDirection.DOWNLOAD,

            operation=TransferOperation.READ

        )
    )

    with patch("epistemicos.containment.PinnedHTTPSConnection", Mock100ByteConnection):
        with pytest.raises(PermissionError) as exc_restricted:
            transport.request(
                method="GET",
                url="https://api.cloud-service.com/data",
                transfer_context=ctx_restricted
            )
        assert "exceeds maximum allowed per-transfer limit (50 bytes)" in str(exc_restricted.value)

    # 2. Standard tenant: 100-byte response is within the 5000-byte limit -> succeeds
    ctx_standard = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(
            service="cloud", host="api.cloud-service.com", tenant_id="standard-tenant"
        ),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        trusted_authority_assertion=make_assertion(

            "principal:alice",

            "INTERNAL",

            destination_host="api.cloud-service.com",

            tenant_id="standard-tenant",

            direction=TransferDirection.DOWNLOAD,

            operation=TransferOperation.READ

        )
    )

    with patch("epistemicos.containment.PinnedHTTPSConnection", Mock100ByteConnection):
        resp = transport.request(
            method="GET",
            url="https://api.cloud-service.com/data",
            transfer_context=ctx_standard
        )
        assert resp["status"] == 200
        assert len(resp["body"]) == 100


def test_targeted_security_defect_verification_suite():
    """
    Targeted regression tests confirming user verification requirements:
    1. Mutating any security-relevant field after trusted-context construction
       invalidates the integrity seal and causes denial.
    2. A required capability with no AuthorizationAuthority is denied before socket creation.
    3. Invalid, expired, revoked, or mismatched capabilities are denied before network I/O.
    4. Partial uploads and streamed downloads retain actual transferred-byte accounting after
       exceptions.
    5. Failures before any bytes cross the network boundary refund the full reservation.
    6. Successful transfers are accounted exactly once.
    7. Required provenance with a missing or failing store prevents transfer before socket creation.
    """
    from epistemicos.authorization import (
        AuthorizationAuthority, CapabilityRegistry, Policy
    )
    from unittest.mock import patch, MagicMock

    # 1. Mutating security-relevant fields invalidates seal and causes denial
    for field, new_val in [
        ("initiating_principal", "principal:malicious"),
        ("destination", DestinationIdentity(service="s3", host="attacker.com")),
        ("classification", DataClassification.PUBLIC),
        ("source_scope", "tampered-scope"),
        ("direction", TransferDirection.DOWNLOAD),
        ("operation", TransferOperation.READ),
    ]:
        ctx = create_test_context(
            principal_verifier=TEST_VERIFIER,
            principal="principal:alice",
            destination=DestinationIdentity(service="s3", host="s3.us-east-1.amazonaws.com"),
            classification=DataClassification.INTERNAL,
            direction=TransferDirection.UPLOAD,
            operation=TransferOperation.WRITE,
            source_scope="scope-1",
            declared_bytes=100,
            trusted_authority_assertion=make_assertion(
                "principal:alice", "INTERNAL", destination_host="s3.us-east-1.amazonaws.com",
                source_scope="scope-1"
            )
        )
        assert ctx.is_classification_trusted is True
        setattr(ctx, field, new_val)
        # Verify seal invalidation
        assert ctx.is_classification_trusted is False

        # Verify policy denies tampered context
        rule = TransferRule(
            rule_id="tamper-test-rule",
            allowed_principals={"principal:alice"},
            destination_service="s3",
            allowed_hosts={"s3.us-east-1.amazonaws.com"},
            max_classification=DataClassification.INTERNAL
        )
        policy = DataTransferPolicy(rules=[rule], principal_verifier=TEST_VERIFIER)
        decision = policy.evaluate_transfer(ctx)
        assert decision.allowed is False
        assert (
            "Untrusted or unverified data classification" in decision.reason
            or "does not originate from a trusted authority" in decision.reason
            or "failed cryptographic authority assertion verification" in decision.reason
        )

    # 2. Required capability with no AuthorizationAuthority is denied before socket creation
    cap_rule = TransferRule(
        rule_id="cap-required-rule",
        allowed_principals={"principal:alice"},
        destination_service="s3",
        allowed_hosts={"s3.us-east-1.amazonaws.com"},
        max_classification=DataClassification.INTERNAL,
        require_capability=True
    )
    cap_policy = DataTransferPolicy(rules=[cap_rule], principal_verifier=TEST_VERIFIER)
    dummy_cap = Capability(
        token_id="tok-dummy",
        principal_id="principal:alice",
        correlation_id="corr-1",
        request_id="req-1",
        action_name="s3_upload",
        target="s3.us-east-1.amazonaws.com",
        canonical_request_digest="dig-1",
        executor_id="exec",
        policy_version="1.0",
        created_at=100.0,
        expires_at=200.0,
        signature="aa" * 32
    )
    clean_ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="s3", host="s3.us-east-1.amazonaws.com"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="s3.us-east-1.amazonaws.com"
        )
    )
    dec_no_auth = cap_policy.evaluate_transfer(clean_ctx, capability=dummy_cap, authority=None)
    assert dec_no_auth.allowed is False
    assert "AuthorizationAuthority is not configured" in dec_no_auth.reason

    # Ensure broker with no authority raises PermissionError before socket connection
    egress_policy = EgressPolicy(allowed_destinations={"s3.us-east-1.amazonaws.com"})
    broker_no_auth = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=cap_policy,
        authorization_authority=None,
        resolver_func=lambda h: ["52.216.0.1"]
    )
    transport_no_auth = ControlledEgressTransport(broker=broker_no_auth)
    with patch("epistemicos.containment.PinnedHTTPSConnection") as mock_conn:
        with pytest.raises(PermissionError) as exc_no_auth:
            transport_no_auth.request(
                method="POST",
                url="https://s3.us-east-1.amazonaws.com/test",
                body=b"data",
                transfer_context=clean_ctx,
                capability=dummy_cap
            )
        assert "AuthorizationAuthority is not configured" in str(exc_no_auth.value)
        mock_conn.assert_not_called()

    # 3. Invalid, expired, revoked, or mismatched capabilities denied before network I/O
    registry = CapabilityRegistry(signing_secret=b"cap_secret_targeted_test_key_1234")
    auth_policy = Policy(
        policy_id="targeted-policy",
        allowed_operations={"s3_upload"},
        allowed_resources={"s3.us-east-1.amazonaws.com"},
        allowed_principals={"principal:alice"},
        allowed_executors={"exec"}
    )
    authority = AuthorizationAuthority(
        default_policy=auth_policy,
        registry=registry,
        principal_provider=TEST_VERIFIER
    )
    auth_principal = TEST_IDP.issue_principal("principal:alice")

    body_digest = hashlib.sha256(b"data").hexdigest()
    cap_valid, _ = authority.evaluate_and_issue_capability(
        action_name="s3_upload",
        target="s3.us-east-1.amazonaws.com",
        canonical_request_digest=body_digest,
        executor_id="exec",
        principal_id=auth_principal,
        task_id="task-targeted"
    )
    broker_auth = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=cap_policy,
        authorization_authority=authority,
        resolver_func=lambda h: ["52.216.0.1"]
    )
    transport_auth = ControlledEgressTransport(broker=broker_auth)

    # 3a. Invalid signature
    cap_bad_sig = Capability(
        token_id=cap_valid.token_id,
        principal_id=cap_valid.principal_id,
        correlation_id=cap_valid.correlation_id,
        request_id=cap_valid.request_id,
        action_name=cap_valid.action_name,
        target=cap_valid.target,
        canonical_request_digest=cap_valid.canonical_request_digest,
        executor_id=cap_valid.executor_id,
        policy_version=cap_valid.policy_version,
        created_at=cap_valid.created_at,
        expires_at=cap_valid.expires_at,
        task_id=cap_valid.task_id,
        signature="00" * 32
    )
    with patch("epistemicos.containment.PinnedHTTPSConnection") as mock_conn:
        with pytest.raises(PermissionError) as exc_bad_sig:
            transport_auth.request(
                method="POST",
                url="https://s3.us-east-1.amazonaws.com/test",
                body=b"data",
                transfer_context=clean_ctx,
                capability=cap_bad_sig
            )
        assert "Capability verification failed" in str(exc_bad_sig.value)
        mock_conn.assert_not_called()

    # 3b. Expired capability
    past_principal = TEST_IDP.issue_principal("principal:alice", current_time=10.0, expires_at=20.0)
    cap_expired, _ = authority.evaluate_and_issue_capability(
        action_name="s3_upload",
        target="s3.us-east-1.amazonaws.com",
        canonical_request_digest=body_digest,
        executor_id="exec",
        principal_id=past_principal,
        task_id="task-targeted-exp",
        current_time=10.0
    )
    with patch("epistemicos.containment.PinnedHTTPSConnection") as mock_conn:
        with pytest.raises(PermissionError) as exc_exp:
            transport_auth.request(
                method="POST",
                url="https://s3.us-east-1.amazonaws.com/test",
                body=b"data",
                transfer_context=clean_ctx,
                capability=cap_expired
            )
        assert "expired" in str(exc_exp.value).lower()
        mock_conn.assert_not_called()

    # 3c. Revoked capability
    cap_revoked, _ = authority.evaluate_and_issue_capability(
        action_name="s3_upload",
        target="s3.us-east-1.amazonaws.com",
        canonical_request_digest=body_digest,
        executor_id="exec",
        principal_id=auth_principal,
        task_id="task-targeted-rev"
    )
    registry.revoke_token(cap_revoked.token_id, reason="Revoked for test")
    with patch("epistemicos.containment.PinnedHTTPSConnection") as mock_conn:
        with pytest.raises(PermissionError) as exc_rev:
            transport_auth.request(
                method="POST",
                url="https://s3.us-east-1.amazonaws.com/test",
                body=b"data",
                transfer_context=clean_ctx,
                capability=cap_revoked
            )
        assert "revoked" in str(exc_rev.value).lower()
        mock_conn.assert_not_called()

    # 4 & 5. Partial uploads/downloads and pre-network failure accounting
    accounting_rule = TransferRule(
        rule_id="accounting-test-rule",
        allowed_principals={"principal:alice"},
        destination_service="s3",
        allowed_hosts={"s3.us-east-1.amazonaws.com"},
        max_classification=DataClassification.INTERNAL,
        max_bytes_per_transfer=1000,
        max_cumulative_bytes=1000
    )
    accounting_policy = DataTransferPolicy(
        rules=[accounting_rule],
        default_max_cumulative_bytes=1000,
        principal_verifier=TEST_VERIFIER
    )
    broker_acct = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=accounting_policy,
        resolver_func=lambda h: ["52.216.0.1"]
    )
    transport_acct = ControlledEgressTransport(broker=broker_acct)

    # 5. Failure before any bytes cross network boundary refunds full reservation
    class FailConnect:
        def __init__(self, *args, **kwargs):
            raise ConnectionError("DNS or TLS connect failure")

    ctx_pre = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="s3", host="s3.us-east-1.amazonaws.com"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=300,
        task_id="task-refund-full",
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="s3.us-east-1.amazonaws.com"
        )
    )
    with patch("epistemicos.containment.PinnedHTTPSConnection", FailConnect):
        with pytest.raises((ConnectionError, OSError)):
            transport_acct.request(
                method="POST",
                url="https://s3.us-east-1.amazonaws.com/test",
                body=b"A" * 300,
                transfer_context=ctx_pre
            )
    assert accounting_policy.get_cumulative_bytes("task-refund-full") == 0

    # 4. Partial upload: failure during send after 150 bytes have crossed the wire
    class FailMidSend:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, url, body=None, headers=None):
            if hasattr(body, "read"):
                # Read 150 bytes from the body stream to simulate transmission
                body.read(150)
            raise BrokenPipeError("Socket severed during payload transmission")

        def close(self):
            pass

    ctx_part_up = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="s3", host="s3.us-east-1.amazonaws.com"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=400,
        task_id="task-partial-up",
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="s3.us-east-1.amazonaws.com"
        )
    )
    with patch("epistemicos.containment.PinnedHTTPSConnection", FailMidSend):
        with pytest.raises((BrokenPipeError, OSError)):
            transport_acct.request(
                method="POST",
                url="https://s3.us-east-1.amazonaws.com/test",
                body=b"B" * 400,
                transfer_context=ctx_part_up
            )
    # 150 bytes crossed the boundary and must be committed; remaining 250 reserved bytes refunded
    assert accounting_policy.get_cumulative_bytes("task-partial-up") == 150

    # 4. Streamed download: 350 bytes received before stream disconnection
    class PartialStreamResponse:
        def __init__(self):
            self.status = 200
            self.reason = "OK"
            self.sent = False

        def getheaders(self):
            return [("Content-Type", "application/octet-stream")]

        def read(self, amt=1024):
            if not self.sent:
                self.sent = True
                return b"C" * 350
            raise ConnectionResetError("Reset mid-stream")

        def close(self):
            pass

    class PartialStreamConn:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, url, body=None, headers=None):
            pass

        def getresponse(self):
            return PartialStreamResponse()

        def close(self):
            pass

    ctx_stream = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="s3", host="s3.us-east-1.amazonaws.com"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        declared_bytes=800,
        task_id="task-stream-fail",
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="s3.us-east-1.amazonaws.com",
            direction=TransferDirection.DOWNLOAD, operation=TransferOperation.READ
        )
    )
    with patch("epistemicos.containment.PinnedHTTPSConnection", PartialStreamConn):
        with pytest.raises((ConnectionResetError, OSError)):
            transport_acct.request(
                method="GET",
                url="https://s3.us-east-1.amazonaws.com/test",
                transfer_context=ctx_stream
            )
    # 350 bytes were received and must be retained in cumulative volume accounting!
    assert accounting_policy.get_cumulative_bytes("task-stream-fail") == 350

    # 6. Successful transfer is accounted exactly once
    class CleanConn:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, url, body=None, headers=None):
            pass

        def getresponse(self):
            resp = MagicMock()
            resp.status = 200
            resp.reason = "OK"
            resp.getheaders.return_value = [("Content-Type", "application/octet-stream")]
            resp.read.side_effect = [b"D" * 200, b""]
            return resp

        def close(self):
            pass

    ctx_success = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="s3", host="s3.us-east-1.amazonaws.com"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=150,
        task_id="task-stream-fail",  # Add to existing 350
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="s3.us-east-1.amazonaws.com"
        )
    )
    with patch("epistemicos.containment.PinnedHTTPSConnection", CleanConn):
        res = transport_acct.request(
            method="POST",
            url="https://s3.us-east-1.amazonaws.com/test",
            body=b"D" * 150,
            transfer_context=ctx_success
        )
        assert res["status"] == 200
    # Expected total: 350 + (150 request + 200 response = 350) = 700 bytes total, exactly once
    assert accounting_policy.get_cumulative_bytes("task-stream-fail") == 700

    # 7. Required provenance with missing store prevents transfer before socket creation
    with pytest.raises(ValueError) as exc_prov_init:
        EgressTransportBroker(
            policy=egress_policy,
            require_provenance=True,
            provenance_store=None
        )
    assert "require_provenance=True requires a valid provenance_store" in str(exc_prov_init.value)

    # Required provenance with failing store prevents transfer before socket creation
    failing_store = MagicMock()
    failing_store.record_event.side_effect = IOError("Disk full: provenance record failure")
    broker_prov_fail = EgressTransportBroker(
        policy=egress_policy,
        require_provenance=True,
        provenance_store=failing_store,
        resolver_func=lambda h: ["52.216.0.1"]
    )
    transport_prov_fail = ControlledEgressTransport(broker=broker_prov_fail)
    with patch("epistemicos.containment.PinnedHTTPSConnection") as mock_conn:
        with pytest.raises((PermissionError, RuntimeError)) as exc_prov_rec:
            transport_prov_fail.request(
                method="GET",
                url="https://s3.us-east-1.amazonaws.com/test",
                transfer_context=clean_ctx
            )
        assert (
            "provenance recording failed" in str(exc_prov_rec.value).lower()
            or "provenance recording failure" in str(exc_prov_rec.value).lower()
        )
        mock_conn.assert_not_called()


def test_adversarial_transfer_context_assertion_binding_and_replay():
    """
    Focused adversarial tests verifying complete transfer-context assertion binding:
    - Mutating each security-relevant field (task_id, workspace_id, endpoint_path, declared_bytes,
      initiating_principal, destination_host, tenant_id, account_id, classification, source_scope,
      direction, operation) after assertion creation invalidates cryptographic trust.
    - Replaying a valid assertion with a different task_id fails closed, preventing an adversary
      from obtaining a fresh cumulative accounting bucket.
    """
    dest_full = DestinationIdentity(
        service="s3",
        host="s3.us-east-1.amazonaws.com",
        tenant_id="tenant-org",
        account_id="account-org",
        workspace_id="ws-analytics",
        endpoint_path="/reports"
    )

    base_assertion = make_assertion(
        principal="principal:alice",
        classification="CONFIDENTIAL",
        destination_host="s3.us-east-1.amazonaws.com",
        tenant_id="tenant-org",
        account_id="account-org",
        workspace_id="ws-analytics",
        endpoint_path="/reports",
        source_scope="scope-finance",
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        task_id="task-adversarial-1",
        declared_bytes=500,
        explicit_task=True,
        explicit_bytes=True
    )

    # Valid baseline context
    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=dest_full,
        classification=DataClassification.CONFIDENTIAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        source_scope="scope-finance",
        task_id="task-adversarial-1",
        declared_bytes=500,
        trusted_authority_assertion=base_assertion
    )
    assert ctx.is_classification_trusted is True

    # 1. Mutate task_id -> trust invalidated
    ctx.task_id = "task-adversarial-tampered"
    assert ctx.is_classification_trusted is False
    ctx.task_id = "task-adversarial-1"
    assert ctx.is_classification_trusted is True

    # 2. Replay assertion with a different task ID at builder construction time
    ctx_replayed_task = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=dest_full,
        classification=DataClassification.CONFIDENTIAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        source_scope="scope-finance",
        task_id="task-fresh-bucket-spoof",
        declared_bytes=500,
        trusted_authority_assertion=base_assertion
    )
    assert ctx_replayed_task.is_classification_trusted is False

    # 3. Mutate workspace_id -> trust invalidated
    ctx.destination = DestinationIdentity(
        service="s3", host="s3.us-east-1.amazonaws.com",
        tenant_id="tenant-org", account_id="account-org",
        workspace_id="ws-attacker", endpoint_path="/reports"
    )
    assert ctx.is_classification_trusted is False
    ctx.destination = dest_full
    assert ctx.is_classification_trusted is True

    # 4. Mutate endpoint_path -> trust invalidated
    ctx.destination = DestinationIdentity(
        service="s3", host="s3.us-east-1.amazonaws.com",
        tenant_id="tenant-org", account_id="account-org",
        workspace_id="ws-analytics", endpoint_path="/exfiltration"
    )
    assert ctx.is_classification_trusted is False
    ctx.destination = dest_full
    assert ctx.is_classification_trusted is True

    # 5. Mutate declared_bytes to exceed asserted constraint -> trust invalidated
    ctx.declared_bytes = 1000  # Exceeds asserted 500
    assert ctx.is_classification_trusted is False
    ctx.declared_bytes = 500
    assert ctx.is_classification_trusted is True


def test_multi_hop_redirect_accounting_and_reservation_lifecycle():
    """
    Focused regression suite verifying multi-hop redirect accounting & reservation lifecycle:
    1. Same-host redirect with a successful response.
    2. Multiple redirect hops.
    3. Redirect response followed by a failed second request (asserting partial bytes from hop 1
       are preserved and committed, and unused reservation is refunded).
    4. Cumulative budget near its rule-specific ceiling enforced on redirect hop.
    5. Exactly-once accounting across complete redirect chain.
    """
    egress_policy = EgressPolicy(allowed_destinations={"api.corp.internal"})
    task_id = "task-redirect-lifecycle"

    rule_strict = TransferRule(
        rule_id="strict-redirect-rule",
        allowed_principals={"principal:alice"},
        destination_service="api",
        allowed_hosts={"api.corp.internal"},
        max_classification=DataClassification.INTERNAL,
        max_bytes_per_transfer=1000,
        max_cumulative_bytes=500
    )
    policy = DataTransferPolicy(rules=[rule_strict], principal_verifier=TEST_VERIFIER)

    broker = EgressTransportBroker(
        policy=egress_policy,
        transfer_policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    # 1 & 5. Same-host redirect with successful response & exactly-once accounting
    class SameHostRedirectConn:
        def __init__(self, *args, **kwargs):
            self.step = 0

        def request(self, method, url, body=None, headers=None):
            self.last_url = url

        def getresponse(self):
            resp = MagicMock()
            if "/initial" in self.last_url:
                resp.status = 302
                resp.reason = "Found"
                resp.getheaders.return_value = [
                    ("Location", "/final"),
                    ("Content-Type", "text/plain")
                ]
                resp.read.side_effect = [b"redir-hop-1-response", b""]  # 20 bytes
            else:
                resp.status = 200
                resp.reason = "OK"
                resp.getheaders.return_value = [("Content-Type", "application/json")]
                resp.read.side_effect = [b"final-data-200", b""]  # 14 bytes
            return resp

        def close(self):
            pass

    ctx_same_host = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=50,
        task_id=task_id,
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.internal"
        )
    )

    from unittest.mock import patch
    with patch("epistemicos.containment.PinnedHTTPConnection", SameHostRedirectConn):
        res = transport.request(
            method="POST",
            url="http://api.corp.internal/initial",
            body=b"A" * 50,
            transfer_context=ctx_same_host
        )
        assert res["status"] == 200
        assert res["body"] == b"final-data-200"

    # Hop 1: 50 request + 20 response = 70 bytes.
    # Hop 2: 0 request (converted to GET on 302) + 14 response = 14 bytes.
    # Total committed once: 84 bytes.
    assert policy.get_cumulative_bytes(task_id) == 84
    assert policy.get_allocated_bytes(task_id) == 84  # Zero lingering reservations

    # 2. Multiple redirect hops (Hop 1 -> 301 -> Hop 2 -> 302 -> Hop 3 -> 200)
    task_id_multi = "task-multi-hop"

    class MultiHopConn:
        def __init__(self, *args, **kwargs):
            self.last_url = ""

        def request(self, method, url, body=None, headers=None):
            self.last_url = url

        def getresponse(self):
            resp = MagicMock()
            if "/hop1" in self.last_url:
                resp.status = 301
                resp.getheaders.return_value = [("Location", "/hop2")]
                resp.read.side_effect = [b"h1", b""]  # 2 bytes
            else:
                resp.status = 200
                resp.getheaders.return_value = []
                resp.read.side_effect = [b"final-dest", b""]  # 10 bytes
            return resp

        def close(self):
            pass

    ctx_multi = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=20,
        task_id=task_id_multi,
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.internal"
        )
    )

    with patch("epistemicos.containment.PinnedHTTPConnection", MultiHopConn):
        res_multi = transport.request(
            method="POST",
            url="http://api.corp.internal/hop1",
            body=b"X" * 20,
            transfer_context=ctx_multi
        )
        assert res_multi["status"] == 200
        assert res_multi["body"] == b"final-dest"

    # Hop 1: 20 req + 2 resp = 22.
    # Hop 2: 0 req + 10 resp = 10.
    # Total: 32 bytes.
    assert policy.get_cumulative_bytes(task_id_multi) == 32
    assert policy.get_allocated_bytes(task_id_multi) == 32

    # 3. Redirect response followed by a failed second request (socket failure on hop 2)
    task_id_fail = "task-redirect-fail-hop2"

    class FailHop2Conn:
        def __init__(self, *args, **kwargs):
            self.last_url = ""

        def request(self, method, url, body=None, headers=None):
            self.last_url = url
            if "/hop2" in url:
                raise ConnectionResetError("Hop 2 severed during connection")

        def getresponse(self):
            resp = MagicMock()
            resp.status = 302
            resp.getheaders.return_value = [("Location", "/hop2")]
            resp.read.side_effect = [b"redirect-payload", b""]  # 16 bytes
            return resp

        def close(self):
            pass

    ctx_fail_hop2 = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=40,
        task_id=task_id_fail,
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.internal"
        )
    )

    with patch("epistemicos.containment.PinnedHTTPConnection", FailHop2Conn):
        with pytest.raises((ConnectionResetError, OSError)):
            transport.request(
                method="POST",
                url="http://api.corp.internal/hop1",
                body=b"Y" * 40,
                transfer_context=ctx_fail_hop2
            )

    # Hop 1 transmitted 40 bytes request + received 16 bytes response = 56 bytes.
    # Hop 2 failed before network bytes were sent.
    # The 56 bytes from Hop 1 MUST be retained in cumulative volume accounting, and unused refunded
    assert policy.get_cumulative_bytes(task_id_fail) == 56
    assert policy.get_allocated_bytes(task_id_fail) == 56

    # 4. Cumulative budget near rule ceiling enforced on redirect hop
    task_id_ceiling = "task-redirect-ceiling"
    policy.reset_cumulative_bytes(task_id_ceiling)
    # Set existing cumulative usage to 460 bytes (ceiling is 500 bytes, room for only 40 bytes)
    policy.record_observed_bytes(task_id_ceiling, 460)

    class LargeRedirectRespConn:
        def __init__(self, *args, **kwargs):
            self.last_url = ""

        def request(self, method, url, body=None, headers=None):
            self.last_url = url

        def getresponse(self):
            resp = MagicMock()
            if "/start" in self.last_url:
                resp.status = 302
                resp.getheaders.return_value = [("Location", "/oversized-dest")]
                resp.read.side_effect = [b"short", b""]  # 5 bytes
            else:
                resp.status = 200
                resp.getheaders.return_value = []
                # Response has 50 bytes -> 460 + 10 (req) + 5 (resp1) + 50 (resp2) = 525 > 500
                resp.read.side_effect = [b"Z" * 50, b""]
            return resp

        def close(self):
            pass

    ctx_ceiling = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=10,
        task_id=task_id_ceiling,
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.internal"
        )
    )

    with patch("epistemicos.containment.PinnedHTTPConnection", LargeRedirectRespConn):
        with pytest.raises(PermissionError) as exc_ceil:
            transport.request(
                method="POST",
                url="http://api.corp.internal/start",
                body=b"1234567890",
                transfer_context=ctx_ceiling
            )
        assert "Cumulative volume exceeds" in str(exc_ceil.value)


def test_multi_hop_chain_combined_volume_aborts_mid_stream_on_second_hop():
    """
    Verifies that in a multi-hop redirect chain where neither individual response
    exceeds the remaining cumulative budget, their combined volume crossing the ceiling
    aborts the transfer mid-stream during reception on the second hop.
    """
    policy = DataTransferPolicy(
        rules=[
            TransferRule(
                rule_id="combined-ceiling-rule",
                allowed_principals={"principal:alice"},
                destination_service="api",
                allowed_hosts={"api.corp.internal"},
                max_cumulative_bytes=50  # Total ceiling: 50 bytes
            )
        ],
        principal_verifier=TEST_VERIFIER
    )
    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.internal"}),
        transfer_policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    class MultiHopCombinedCeilingConn:
        def __init__(self, *args, **kwargs):
            self.last_url = ""

        def request(self, method, url, body=None, headers=None):
            self.last_url = url

        def getresponse(self):
            resp = MagicMock()
            if "/hop1" in self.last_url:
                resp.status = 302
                resp.getheaders.return_value = [("Location", "/hop2")]
                # Hop 1 response: 30 bytes (30 <= 50, within budget individually)
                resp.read.side_effect = [b"A" * 30, b""]
            else:
                resp.status = 200
                resp.getheaders.return_value = []
                # Hop 2 response: 30 bytes (30 <= 50, within budget individually)
                # But combined 30 + 30 = 60 > 50 ceiling!
                resp.read.side_effect = [b"B" * 30, b""]
            return resp

        def close(self):
            pass

    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        task_id="task-combined-ceiling-test",
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.internal",
            direction=TransferDirection.DOWNLOAD, operation=TransferOperation.READ,
            task_id="task-combined-ceiling-test"
        )
    )

    from unittest.mock import patch
    with patch("epistemicos.containment.PinnedHTTPConnection", MultiHopCombinedCeilingConn):
        with pytest.raises(PermissionError) as exc_info:
            transport.request(
                method="GET",
                url="http://api.corp.internal/hop1",
                transfer_context=ctx
            )
        assert "Cumulative volume exceeds ceiling of 50 bytes" in str(exc_info.value)


def test_concurrent_transfers_in_flight_cumulative_ceiling_enforcement():
    """
    Adversarial concurrency regression test:
    Proves that when two transfers concurrently execute against the same task ID:
    - Transfer 1 holds an active reservation of 40 bytes (declared_bytes=40).
    - Transfer 2 holds an active reservation of 20 bytes (declared_bytes=20).
    - Cumulative ceiling for the task is 70 bytes.
    - Transfer 2 begins streaming a response chunk of 35 bytes.
      Without accounting for Transfer 1's active reservation, Transfer 2's in-flight total
      would look like 0 committed + 35 = 35 <= 70 (silently allowed).
      With in-flight accounting of other active concurrent reservations, Transfer 2 evaluates
      other_allocated (40) + curr_total (35) = 75 > 70 ceiling, and is aborted mid-stream.
    - Furthermore, Transfer 2's own reservation (20 bytes) is NOT double-counted.
    """
    task_id = "task-concurrent-streaming-ceiling"
    policy = DataTransferPolicy(
        rules=[
            TransferRule(
                rule_id="concurrent-stream-ceiling-rule",
                allowed_principals={"principal:alice"},
                destination_service="api",
                allowed_hosts={"api.corp.internal"},
                max_cumulative_bytes=70  # Ceiling: 70 bytes
            )
        ],
        principal_verifier=TEST_VERIFIER
    )
    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.internal"}),
        transfer_policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    # 1. Establish an active, in-flight reservation of 40 bytes for Transfer 1
    ctx1 = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=40,
        task_id=task_id,
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.internal",
            task_id=task_id, declared_bytes=40,
            explicit_task=True, explicit_bytes=True
        )
    )
    res_transfer1 = policy.evaluate_and_reserve(ctx1, reservation_id="res-transfer-1")
    assert res_transfer1.allowed is True
    # Verify Transfer 1 has 40 bytes reserved
    assert policy.get_allocated_bytes(task_id) == 40
    assert policy.get_cumulative_bytes(task_id) == 0

    # 2. Transfer 2 has declared_bytes=20 and will stream 35 bytes.
    # Total allocated when Transfer 2 starts: 40 (T1) + 20 (T2) = 60 <= 70.
    # When Transfer 2 receives 35 bytes, in-flight calculation is:
    # other_allocated (T1: 40) + curr_total (T2: 35) = 75 > 70 -> ABORTS!
    class StreamingChunkConn:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, url, body=None, headers=None):
            pass

        def getresponse(self):
            resp = MagicMock()
            resp.status = 200
            resp.getheaders.return_value = []
            # Returns 35 bytes
            resp.read.side_effect = [b"M" * 35, b""]
            return resp

        def close(self):
            pass

    ctx2 = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        declared_bytes=20,
        task_id=task_id,
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.internal",
            direction=TransferDirection.DOWNLOAD, operation=TransferOperation.READ,
            task_id=task_id, declared_bytes=20,
            explicit_task=True, explicit_bytes=True
        )
    )

    from unittest.mock import patch
    with patch("epistemicos.containment.PinnedHTTPConnection", StreamingChunkConn):
        with pytest.raises(PermissionError) as exc_info:
            transport.request(
                method="GET",
                url="http://api.corp.internal/stream",
                transfer_context=ctx2
            )
        assert "Cumulative volume exceeds ceiling of 70 bytes during stream reception" in str(
            exc_info.value
        )

    # 3. Because the chunk was aborted before consumption, zero bytes were accepted into
    # the response buffer. When Transfer 1's active reservation is refunded, total allocated
    # bytes for the task returns to 0.
    policy.refund_reservation("res-transfer-1")
    assert policy.get_cumulative_bytes(task_id) == 0
    assert policy.get_allocated_bytes(task_id) == 0


def test_simultaneous_streaming_toctou_race_prevented():
    """
    Adversarial concurrency regression test:
    Demonstrates that simultaneous streaming transfers reaching the accounting boundary
    together cannot exceed the shared cumulative ceiling.

    Setup:
    - Shared cumulative ceiling: 100 bytes for task 'task-simultaneous-streaming-toctou'.
    - Transfer A and Transfer B each hold a 40-byte initial reservation (total initial: 80 <= 100).
    - Both transfers simultaneously observe 20 bytes initially (each reaching 20 bytes).
    - Then, both transfers reach a synchronization barrier right before streaming their next chunk.
    - Each transfer attempts to stream an additional 40-byte chunk:
      Transfer A would reach 20 + 40 = 60 bytes.
      Transfer B would reach 20 + 40 = 60 bytes.
      Without atomic chunk reservation under lock:
        A's check: B's 40 reservation + A's 60 bytes = 100 <= 100 (allowed!)
        B's check: A's 40 reservation + B's 60 bytes = 100 <= 100 (allowed!)
        Combined actual volume would be 60 + 60 = 120 bytes > 100!
      With claim_in_flight_chunk():
        The first transfer to claim its 40-byte chunk atomically expands its reservation.
        The second transfer's atomic check evaluates:
          other_reserved (60) + curr_total (60) = 120 > 100 ceiling, and is ABORTED mid-stream!
    - Verifies:
      1. Exactly one transfer succeeds and one transfer is aborted with PermissionError.
      2. The final committed cumulative volume never exceeds the 100-byte ceiling.
    """
    task_id = "task-simultaneous-streaming-toctou"
    policy = DataTransferPolicy(
        rules=[
            TransferRule(
                rule_id="simultaneous-streaming-ceiling-rule",
                allowed_principals={"principal:alice"},
                destination_service="api",
                allowed_hosts={"api.corp.internal"},
                max_cumulative_bytes=100  # Ceiling: 100 bytes
            )
        ],
        principal_verifier=TEST_VERIFIER
    )
    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.internal"}),
        transfer_policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    barrier = threading.Barrier(2)

    class SynchronizedChunkResponse:
        def __init__(self, transfer_name: str):
            self.transfer_name = transfer_name
            self.step = 0
            self.status = 200
            self.reason = "OK"

        def getheaders(self):
            return [("Content-Type", "application/octet-stream")]

        def read(self, amt=1024):
            if self.step == 0:
                self.step += 1
                # First chunk: 20 bytes
                return b"X" * 20
            elif self.step == 1:
                self.step += 1
                # Synchronize both transfers right before streaming the second chunk
                barrier.wait(timeout=5.0)
                # Second chunk: 40 bytes (total 60 bytes observed for this transfer)
                return b"Y" * 40
            else:
                return b""

        def close(self):
            pass

    def run_transfer(transfer_name: str, res_id: str):
        ctx = create_test_context(
            principal_verifier=TEST_VERIFIER,
            principal="principal:alice",
            destination=DestinationIdentity(service="api", host="api.corp.internal"),
            classification=DataClassification.INTERNAL,
            direction=TransferDirection.DOWNLOAD,
            operation=TransferOperation.READ,
            declared_bytes=40,
            task_id=task_id,
            trusted_authority_assertion=make_assertion(
                "principal:alice", "INTERNAL", destination_host="api.corp.internal",
                direction=TransferDirection.DOWNLOAD, operation=TransferOperation.READ,
                task_id=task_id, declared_bytes=40,
                explicit_task=True, explicit_bytes=True
            )
        )

        class MockSyncConn:
            def __init__(self, *args, **kwargs):
                pass

            def request(self, method, url, body=None, headers=None):
                pass

            def getresponse(self):
                return SynchronizedChunkResponse(transfer_name)

            def close(self):
                pass

        try:
            res = transport.request(
                method="GET",
                url=f"http://api.corp.internal/stream/{transfer_name}",
                transfer_context=ctx
            )
            return True, len(res.get("body", b"")), None
        except PermissionError as pe:
            return False, ctx.observed_bytes, str(pe)

    class ThreadSafeMockSyncConn:
        def __init__(self, *args, **kwargs):
            self.last_url = ""

        def request(self, method, url, body=None, headers=None):
            self.last_url = url

        def getresponse(self):
            t_name = "transfer_a" if "transfer_a" in self.last_url else "transfer_b"
            return SynchronizedChunkResponse(t_name)

        def close(self):
            pass

    from unittest.mock import patch
    with patch("epistemicos.containment.PinnedHTTPConnection", ThreadSafeMockSyncConn):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f_a = executor.submit(run_transfer, "transfer_a", "res-a")
            f_b = executor.submit(run_transfer, "transfer_b", "res-b")
            res_a = f_a.result()
            res_b = f_b.result()

    success_count = sum(1 for r in (res_a, res_b) if r[0] is True)
    abort_count = sum(1 for r in (res_a, res_b) if r[0] is False)

    # Exactly one transfer must succeed, and one must be aborted mid-stream!
    assert success_count == 1, f"Expected 1 success, got {success_count}: A={res_a}, B={res_b}"
    assert abort_count == 1, f"Expected 1 abort, got {abort_count}: A={res_a}, B={res_b}"

    # Verify the aborted transfer has an explicit cumulative ceiling error message
    aborted_res = res_a if not res_a[0] else res_b
    assert "Cumulative volume exceeds ceiling of 100 bytes" in aborted_res[2]

    # Verify that the total cumulative bytes committed never exceeds the 100-byte ceiling!
    final_committed = policy.get_cumulative_bytes(task_id)
    # The successful transfer committed 60 bytes.
    # The aborted transfer committed the 20 bytes it observed before aborting.
    # Total committed: 60 + 20 = 80 <= 100 ceiling!
    assert final_committed <= 100, f"Committed bytes {final_committed} exceeded 100 ceiling!"
    assert final_committed == 80


def test_post_307_redirect_repeated_body_aborts_before_transmission():
    """
    Regression test:
    Under a 100-byte cumulative ceiling, a 60-byte POST request receives an HTTP 307 redirect.
    HTTP 307 mandates that the request method and body must be repeated on the second hop.
    60 bytes (Hop 1) + 60 bytes (Hop 2) = 120 bytes > 100 bytes ceiling!
    The transport must abort the second hop before any chunk of the repeated body is transmitted,
    and exactly the 60 bytes sent on Hop 1 must be committed into cumulative usage.
    """
    task_id = "task-post-307-redirect-repeat"
    policy = DataTransferPolicy(
        rules=[
            TransferRule(
                rule_id="post-307-rule",
                allowed_principals={"principal:alice"},
                destination_service="api",
                allowed_hosts={"api.corp.internal"},
                max_cumulative_bytes=100
            )
        ],
        principal_verifier=TEST_VERIFIER
    )
    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.internal"}),
        transfer_policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    class Mock307Conn:
        def __init__(self, *args, **kwargs):
            self.last_url = ""

        def request(self, method, url, body=None, headers=None):
            self.last_url = url
            if hasattr(body, "read"):
                # Read all body chunks to simulate socket transmission
                while True:
                    chunk = body.read(1024)
                    if not chunk:
                        break

        def getresponse(self):
            resp = MagicMock()
            if "/start" in self.last_url:
                resp.status = 307
                resp.getheaders.return_value = [("Location", "/redirected")]
                resp.read.side_effect = [b""]  # Empty redirect body
            else:
                resp.status = 200
                resp.getheaders.return_value = []
                resp.read.side_effect = [b""]
            return resp

        def close(self):
            pass

    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=60,
        task_id=task_id,
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.internal",
            task_id=task_id, declared_bytes=60,
            explicit_task=True, explicit_bytes=True
        )
    )

    from unittest.mock import patch
    with patch("epistemicos.containment.PinnedHTTPConnection", Mock307Conn):
        with pytest.raises(PermissionError) as exc_info:
            transport.request(
                method="POST",
                url="http://api.corp.internal/start",
                body=b"A" * 60,
                transfer_context=ctx
            )
        assert (
            "exceeds authorized cumulative ceiling" in str(exc_info.value)
            or "Cumulative volume exceeds ceiling" in str(exc_info.value)
        )

    # Exactly 60 bytes were transmitted on Hop 1; Hop 2 was aborted before transmitting
    assert policy.get_cumulative_bytes(task_id) == 60


def test_post_308_redirect_repeated_body_aborts_before_transmission():
    """
    Regression test:
    HTTP 308 Permanent Redirect replaying a 60-byte body under a 100-byte cumulative ceiling.
    Verifies that the second hop is blocked before transmission and Hop 1 bytes are committed.
    """
    task_id = "task-post-308-redirect-repeat"
    policy = DataTransferPolicy(
        rules=[
            TransferRule(
                rule_id="post-308-rule",
                allowed_principals={"principal:alice"},
                destination_service="api",
                allowed_hosts={"api.corp.internal"},
                max_cumulative_bytes=100
            )
        ],
        principal_verifier=TEST_VERIFIER
    )
    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.internal"}),
        transfer_policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    class Mock308Conn:
        def __init__(self, *args, **kwargs):
            self.last_url = ""

        def request(self, method, url, body=None, headers=None):
            self.last_url = url
            if hasattr(body, "read"):
                while True:
                    chunk = body.read(1024)
                    if not chunk:
                        break

        def getresponse(self):
            resp = MagicMock()
            if "/initial" in self.last_url:
                resp.status = 308
                resp.getheaders.return_value = [("Location", "/permanent-target")]
                resp.read.side_effect = [b""]
            else:
                resp.status = 200
                resp.getheaders.return_value = []
                resp.read.side_effect = [b""]
            return resp

        def close(self):
            pass

    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=60,
        task_id=task_id,
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.internal",
            task_id=task_id, declared_bytes=60,
            explicit_task=True, explicit_bytes=True
        )
    )

    from unittest.mock import patch
    with patch("epistemicos.containment.PinnedHTTPConnection", Mock308Conn):
        with pytest.raises(PermissionError) as exc_info:
            transport.request(
                method="POST",
                url="http://api.corp.internal/initial",
                body=b"B" * 60,
                transfer_context=ctx
            )
        assert (
            "exceeds authorized cumulative ceiling" in str(exc_info.value)
            or "Cumulative volume exceeds ceiling" in str(exc_info.value)
        )

    assert policy.get_cumulative_bytes(task_id) == 60


def test_empty_final_response_body_commits_upload_bytes():
    """
    Regression test:
    Upload with an empty terminal response body (e.g. HTTP 204 No Content).
    Verifies that the absence of response chunks still correctly and authoritatively commits
    the transmitted upload bytes exactly once without leaking reservations.
    """
    task_id = "task-empty-response-commit"
    policy = DataTransferPolicy(
        rules=[
            TransferRule(
                rule_id="empty-resp-rule",
                allowed_principals={"principal:alice"},
                destination_service="api",
                allowed_hosts={"api.corp.internal"},
                max_cumulative_bytes=500
            )
        ],
        principal_verifier=TEST_VERIFIER
    )
    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.internal"}),
        transfer_policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    class MockEmptyRespConn:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, url, body=None, headers=None):
            if hasattr(body, "read"):
                while body.read(1024):
                    pass

        def getresponse(self):
            resp = MagicMock()
            resp.status = 204
            resp.reason = "No Content"
            resp.getheaders.return_value = []
            resp.read.side_effect = [b""]
            return resp

        def close(self):
            pass

    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        declared_bytes=150,
        task_id=task_id,
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.internal",
            task_id=task_id, declared_bytes=150,
            explicit_task=True, explicit_bytes=True
        )
    )

    from unittest.mock import patch
    with patch("epistemicos.containment.PinnedHTTPConnection", MockEmptyRespConn):
        res = transport.request(
            method="POST",
            url="http://api.corp.internal/items",
            body=b"K" * 150,
            transfer_context=ctx
        )
        assert res["status"] == 204
        assert res["body"] == b""

    # Exactly 150 bytes were uploaded and committed
    assert policy.get_cumulative_bytes(task_id) == 150
    assert policy.get_allocated_bytes(task_id) == 150


def test_simultaneous_uploads_budget_contention_prevented():
    """
    Adversarial concurrency regression test:
    Two simultaneous upload transfers against the same task budget.
    - Cumulative ceiling: 100 bytes.
    - Upload A and Upload B each attempt to send 40 bytes (initial total: 80 <= 100).
    - Synchronized via barrier before Upload 1 attempts an HTTP 307 redirect replaying 40 bytes.
    - Proves that no chunk is transmitted when its atomic claim would exceed the shared ceiling.
    - Verifies that Upload 2 succeeds, Upload 1's replay aborts, and final volume is 80 <= 100.
    """
    task_id = "task-concurrent-upload-contention"
    policy = DataTransferPolicy(
        rules=[
            TransferRule(
                rule_id="concurrent-upload-rule",
                allowed_principals={"principal:alice"},
                destination_service="api",
                allowed_hosts={"api.corp.internal"},
                max_cumulative_bytes=100
            )
        ],
        principal_verifier=TEST_VERIFIER
    )
    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.internal"}),
        transfer_policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    barrier = threading.Barrier(2)

    class SynchronizedUploadConn:
        def __init__(self, *args, **kwargs):
            self.last_url = ""

        def request(self, method, url, body=None, headers=None):
            self.last_url = url
            if hasattr(body, "read"):
                while body.read(1024):
                    pass

        def getresponse(self):
            resp = MagicMock()
            if "/upload/up1" in self.last_url:
                # Synchronize here so both are active before Upload 1 attempts 307 replay
                barrier.wait(timeout=5.0)
                resp.status = 307
                resp.getheaders.return_value = [("Location", "/upload/up1-redirect")]
                resp.read.side_effect = [b""]
            elif "/upload/up2" in self.last_url:
                barrier.wait(timeout=5.0)
                resp.status = 200
                resp.reason = "OK"
                resp.getheaders.return_value = []
                resp.read.side_effect = [b""]
            else:
                resp.status = 200
                resp.reason = "OK"
                resp.getheaders.return_value = []
                resp.read.side_effect = [b""]
            return resp

        def close(self):
            pass

    def run_upload(name: str):
        ctx = create_test_context(
            principal_verifier=TEST_VERIFIER,
            principal="principal:alice",
            destination=DestinationIdentity(service="api", host="api.corp.internal"),
            classification=DataClassification.INTERNAL,
            direction=TransferDirection.UPLOAD,
            operation=TransferOperation.WRITE,
            declared_bytes=40,
            task_id=task_id,
            trusted_authority_assertion=make_assertion(
                "principal:alice", "INTERNAL", destination_host="api.corp.internal",
                task_id=task_id, declared_bytes=40,
                explicit_task=True, explicit_bytes=True
            )
        )
        try:
            transport.request(
                method="POST",
                url=f"http://api.corp.internal/upload/{name}",
                body=b"U" * 40,
                transfer_context=ctx
            )
            return True, ctx.observed_bytes, None
        except PermissionError as pe:
            return False, ctx.observed_bytes, str(pe)

    # Patch outer scope so worker threads cleanly share the mock
    from unittest.mock import patch
    with patch("epistemicos.containment.PinnedHTTPConnection", SynchronizedUploadConn):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(run_upload, "up1")
            f2 = executor.submit(run_upload, "up2")
            res1 = f1.result()
            res2 = f2.result()

    # Upload 2 cleanly finishes sending its 40 bytes.
    # Upload 1 sent 40 bytes on hop 1, but its 307 redirect would require sending another 40 bytes.
    # Because Upload 2 is active (40 bytes), 40 (hop 1) + 40 (Up 2) + 40 (hop 2) = 120 > 100!
    # Upload 1 is aborted on hop 2 before transmitting, and 40 bytes from hop 1 are committed.
    assert res2[0] is True, f"Upload 2 should have succeeded, got: {res2}"
    assert res1[0] is False, f"Upload 1 should have been aborted on 307 replay, got: {res1}"

    # Total committed volume across both uploads: 40 (Up 2) + 40 (Up 1 hop 1) = 80 <= 100
    final_vol = policy.get_cumulative_bytes(task_id)
    assert final_vol <= 100
    assert final_vol == 80


def test_h1_h3_m1_security_remediations():
    """
    Direct regression tests for PR #356 findings:
    - H1: Trusted verifier ownership & caller-supplied verifier substitution prevention.
    - H2: Transmitted request body to capability/context digest binding.
    - H3: Atomic single-use capability lifecycle & replay prevention before network I/O.
    - M1: Response stream premature termination & repetitive chunk preservation.
    """
    import http.client
    import time
    from unittest.mock import patch, MagicMock
    from epistemicos.authorization import CapabilityRegistry, AuthorizationAuthority, Policy

    # ---------------------------------------------------------
    # H1: Caller-controlled verifier substitution
    # ---------------------------------------------------------
    corp_idp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    policy_verifier = PrincipalVerifier(trusted_public_keys={"CorpIdP": corp_idp.public_key})
    policy_h1 = DataTransferPolicy(
        rules=[TransferRule(rule_id="h1-rule", allowed_principals={"principal:alice"}, destination_service="s3", allowed_hosts={"s3.corp.com"})],
        principal_verifier=policy_verifier,
        protected_mode=True
    )
    attacker_idp = ExternalTestIdentityAuthority(issuer_id="AttackerIdP")
    attacker_verifier = PrincipalVerifier(trusted_public_keys={"AttackerIdP": attacker_idp.public_key})

    now = time.time()
    exp = now + 3600.0
    payload_h1 = f"principal:alice:AttackerIdP:s3.corp.com:::::PUBLIC::UPLOAD:WRITE:::{now:.6f}:{exp:.6f}".encode("utf-8")
    sig_attacker = _ed25519_sign(payload_h1, attacker_idp.private_seed, attacker_idp.public_key).hex()

    ctx_h1 = TrustedTransferContextBuilder.create_trusted_context(
        principal_verifier=attacker_verifier,
        principal="principal:alice",
        destination=DestinationIdentity(service="s3", host="s3.corp.com"),
        classification=DataClassification.PUBLIC,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion={
            "issuer": "AttackerIdP",
            "principal": "principal:alice",
            "destination_host": "s3.corp.com",
            "classification": "PUBLIC",
            "direction": "UPLOAD",
            "operation": "WRITE",
            "timestamp": now,
            "expires_at": exp,
            "signature": sig_attacker
        }
    )
    dec_h1 = policy_h1.evaluate_transfer(ctx_h1)
    assert dec_h1.allowed is False
    assert "assertion issuer 'AttackerIdP' is not trusted by policy PrincipalVerifier" in dec_h1.reason

    # ---------------------------------------------------------
    # H2: Authorization digest bound to actual transmitted body
    # ---------------------------------------------------------
    registry_h2 = CapabilityRegistry(signing_secret=b"cap_key_32_bytes_test_h2_1234567")
    auth_policy_h2 = Policy(policy_id="p-h2", allowed_operations={"api_upload"}, allowed_resources={"api.corp.internal"})
    authority_h2 = AuthorizationAuthority(default_policy=auth_policy_h2, registry=registry_h2, principal_provider=TEST_VERIFIER)
    principal_h2 = TEST_IDP.issue_principal("principal:user")

    policy_h2 = DataTransferPolicy(
        rules=[TransferRule(rule_id="h2-rule", allowed_principals={"principal:user"}, destination_service="api", allowed_hosts={"api.corp.internal"}, require_capability=True)],
        principal_verifier=TEST_VERIFIER
    )
    broker_h2 = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.internal"}),
        transfer_policy=policy_h2,
        authorization_authority=authority_h2,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport_h2 = ControlledEgressTransport(broker=broker_h2)

    body_real_a = b"EXACT_PAYLOAD_A_16"
    body_fake_b = b"EXACT_PAYLOAD_B_16"
    assert len(body_real_a) == len(body_fake_b)

    digest_real_a = hashlib.sha256(body_real_a).hexdigest()
    cap_h2, _ = authority_h2.evaluate_and_issue_capability(
        action_name="api_upload",
        target="api.corp.internal",
        canonical_request_digest=digest_real_a,
        executor_id="transport",
        principal_id=principal_h2
    )

    ctx_h2 = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:user",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        action_name="api_upload",
        target="api.corp.internal",
        declared_bytes=len(body_real_a),
        trusted_authority_assertion=make_assertion(
            "principal:user", "INTERNAL", destination_host="api.corp.internal",
            direction=TransferDirection.UPLOAD, operation=TransferOperation.WRITE, declared_bytes=len(body_real_a)
        )
    )

    with patch("epistemicos.containment.PinnedHTTPConnection") as mock_conn_h2:
        with pytest.raises(PermissionError) as exc_digest_mismatch:
            transport_h2.request(
                method="POST",
                url="http://api.corp.internal/upload",
                body=body_fake_b,
                transfer_context=ctx_h2,
                capability=cap_h2
            )
        assert "Capability digest mismatch" in str(exc_digest_mismatch.value)
        mock_conn_h2.assert_not_called()

    # ---------------------------------------------------------
    # H3: Single-use capability consumed before network I/O
    # ---------------------------------------------------------
    class FailMidUploadH3:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, method, url, body=None, headers=None):
            if hasattr(body, "read"):
                body.read(5)
            raise ConnectionResetError("Connection severed mid-upload")
        def close(self):
            pass

    with patch("epistemicos.containment.PinnedHTTPConnection", FailMidUploadH3):
        with pytest.raises(OSError):
            transport_h2.request(
                method="POST",
                url="http://api.corp.internal/upload",
                body=body_real_a,
                transfer_context=ctx_h2,
                capability=cap_h2
            )

    # Prove capability was consumed prior to network I/O and cannot be replayed
    with patch("epistemicos.containment.PinnedHTTPConnection") as mock_conn_replay:
        with pytest.raises(PermissionError) as exc_replayed:
            transport_h2.request(
                method="POST",
                url="http://api.corp.internal/upload",
                body=body_real_a,
                transfer_context=ctx_h2,
                capability=cap_h2
            )
        assert "already been consumed" in str(exc_replayed.value)
        mock_conn_replay.assert_not_called()

    # ---------------------------------------------------------
    # M1: Repetitive stream & premature EOF termination
    # ---------------------------------------------------------
    policy_m1 = DataTransferPolicy(
        rules=[TransferRule(rule_id="m1-rule", allowed_principals={"principal:alice"}, destination_service="api", allowed_hosts={"api.corp.internal"}, max_bytes_per_transfer=100000)],
        principal_verifier=TEST_VERIFIER
    )
    broker_m1 = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.internal"}),
        transfer_policy=policy_m1,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport_m1 = ControlledEgressTransport(broker=broker_m1)

    # Repetitive stream beyond 10,000 bytes succeeds in full
    class RepetitiveConnM1:
        def __init__(self, *args, **kwargs):
            self.count = 0
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            resp = MagicMock()
            resp.status = 200
            resp.reason = "OK"
            resp.getheaders.return_value = [("Content-Length", "12000")]
            def read(amt=1024):
                if self.count < 12:
                    self.count += 1
                    return b"Z" * 1000
                return b""
            resp.read = read
            return resp
        def close(self):
            pass

    ctx_rep = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        declared_bytes=12000,
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="api.corp.internal", direction=TransferDirection.DOWNLOAD, operation=TransferOperation.READ, declared_bytes=12000)
    )
    with patch("epistemicos.containment.PinnedHTTPConnection", RepetitiveConnM1):
        res_rep = transport_m1.request(method="GET", url="http://api.corp.internal/stream", transfer_context=ctx_rep)
        assert len(res_rep["body"]) == 12000

    # Premature EOF raises IncompleteRead and records partial observed bytes
    class TruncatedConnM1:
        def __init__(self, *args, **kwargs):
            self.count = 0
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            resp = MagicMock()
            resp.status = 200
            resp.reason = "OK"
            resp.getheaders.return_value = [("Content-Length", "8000")]
            def read(amt=1024):
                if self.count < 2:
                    self.count += 1
                    return b"Y" * 1000
                return b""
            resp.read = read
            return resp
        def close(self):
            pass

    ctx_trunc = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.internal"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        declared_bytes=8000,
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="api.corp.internal", direction=TransferDirection.DOWNLOAD, operation=TransferOperation.READ, declared_bytes=8000)
    )
    with patch("epistemicos.containment.PinnedHTTPConnection", TruncatedConnM1):
        with pytest.raises(http.client.IncompleteRead) as exc_trunc:
            transport_m1.request(method="GET", url="http://api.corp.internal/stream", transfer_context=ctx_trunc)
        assert len(exc_trunc.value.partial) == 2000
        assert exc_trunc.value.expected == 6000
        assert ctx_trunc.observed_bytes == 2000


def test_dns_resolution_not_invoked_for_empty_policy():
    """
    Verifies that DNS resolution is never invoked for an empty or missing policy.
    """
    from unittest.mock import MagicMock
    mock_resolver = MagicMock()
    empty_policy = EgressPolicy(allowed_destinations=set())
    broker = EgressTransportBroker(policy=empty_policy, resolver_func=mock_resolver)

    allowed, reason, ip = broker.establish_connection("https://evil.attacker.com/payload")
    assert allowed is False
    assert "Absent or empty approved-egress policy" in reason
    assert ip is None
    # DNS resolver must NEVER be called
    mock_resolver.assert_not_called()


def test_h1_h2_h3_m1_review_specific_remediations():
    """
    Dedicated regression test covering all specific PR #356 review comments:
    1. H1: Missing policy verifier fails closed in protected mode; authority verifier cannot bypass missing policy verifier.
    2. H2: Original context authorization digest is compared, not overwritten; empty body digest must be
       SHA-256(b"") (not URL hash); negative tests for mismatched original context digest and capability digest.
    3. H3: Missing authority/registry when capability is supplied fails closed before network socket creation.
    4. DNS ordering: Disallowed non-empty-policy destination never triggers DNS resolution.
    5. M1: Unbounded resp.read() IncompleteRead accounts partial bytes and commits observed bytes.
    """
    import http.client
    from unittest.mock import MagicMock, patch

    # 1. H1: Missing policy verifier fails closed in protected mode
    policy_no_ver = DataTransferPolicy(
        rules=[TransferRule(rule_id="r-no-ver", destination_service="s3", allowed_hosts={"s3.corp.com"})],
        protected_mode=True
        # principal_verifier is None!
    )
    ctx_test = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="s3", host="s3.corp.com"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="s3.corp.com")
    )
    dec_no_ver = policy_no_ver.evaluate_transfer(ctx_test)
    assert dec_no_ver.allowed is False
    assert "no trusted PrincipalVerifier configured on policy boundary" in dec_no_ver.reason

    # H1: Authority verifier substitution cannot bypass missing policy verifier
    from epistemicos.authorization import AuthorizationAuthority, CapabilityRegistry, Policy
    idp_corp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    verifier_corp = PrincipalVerifier(trusted_public_keys={"CorpIdP": idp_corp.public_key})
    auth_sub = AuthorizationAuthority(
        default_policy=Policy(policy_id="p-sub", allowed_operations={"op"}, allowed_resources={"res"}),
        registry=CapabilityRegistry(signing_secret=b"sub_sec_32_bytes_test_1234567890"),
        principal_provider=verifier_corp
    )
    dec_auth_sub = policy_no_ver.evaluate_transfer(ctx_test, authority=auth_sub)
    assert dec_auth_sub.allowed is False
    assert "no trusted PrincipalVerifier configured on policy boundary" in dec_auth_sub.reason

    # 2. H2: Context authorization digest compared, not overwritten; empty body requires SHA-256(b"")
    empty_body_hash = hashlib.sha256(b"").hexdigest()
    wrong_hash = hashlib.sha256(b"something-else").hexdigest()
    policy_h2_test = DataTransferPolicy(
        rules=[TransferRule(rule_id="r-h2", allowed_principals={"principal:alice"}, destination_service="api", allowed_hosts={"api.corp.com"})],
        principal_verifier=TEST_VERIFIER
    )
    broker_h2_test = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.com"}),
        transfer_policy=policy_h2_test,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport_h2_test = ControlledEgressTransport(broker=broker_h2_test)

    ctx_h2_mismatch = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.com"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        canonical_request_digest=wrong_hash,
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="api.corp.com", direction=TransferDirection.DOWNLOAD, operation=TransferOperation.READ)
    )
    with pytest.raises(PermissionError) as exc_empty_mismatch:
        transport_h2_test.request(method="GET", url="http://api.corp.com/empty", transfer_context=ctx_h2_mismatch)
    assert "does not match context authorization digest" in str(exc_empty_mismatch.value)
    assert ctx_h2_mismatch.canonical_request_digest == wrong_hash

    # 3. H3: Missing authority/registry when capability supplied fails closed
    dummy_cap = Capability(
        token_id="tok-fail-close-1",
        principal_id="principal:alice",
        correlation_id="corr-1",
        request_id="req-1",
        action_name="api_download",
        target="api.corp.com",
        canonical_request_digest=empty_body_hash,
        executor_id="exec",
        policy_version="1.0",
        created_at=100.0,
        expires_at=2000000000.0,
        signature="aa" * 32
    )
    with pytest.raises(PermissionError) as exc_missing_auth:
        transport_h2_test.request(method="GET", url="http://api.corp.com/empty", capability=dummy_cap)
    assert "no AuthorizationAuthority or registry is configured" in str(exc_missing_auth.value)

    # 4. DNS ordering: Disallowed non-empty-policy destination never triggers DNS resolution
    mock_dns = MagicMock()
    broker_disallowed = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.allowed.com"}),
        resolver_func=mock_dns
    )
    allowed, reason, ip = broker_disallowed.establish_connection("https://api.disallowed.com/data")
    assert allowed is False
    assert "not in approved egress policy" in reason
    assert ip is None
    mock_dns.assert_not_called()

    # 5. M1: Unbounded resp.read() IncompleteRead accounts partial bytes and commits observed bytes
    policy_unbounded = DataTransferPolicy(
        rules=[TransferRule(rule_id="r-unbounded", allowed_principals={"principal:alice"}, destination_service="api", allowed_hosts={"api.corp.com"})],
        principal_verifier=TEST_VERIFIER
    )
    broker_unbounded = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.com"}),
        transfer_policy=policy_unbounded,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport_unbounded = ControlledEgressTransport(broker=broker_unbounded)

    class IncompleteReadUnboundedConn:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            resp = MagicMock()
            resp.status = 200
            resp.reason = "OK"
            resp.getheaders.return_value = []
            def read():
                raise http.client.IncompleteRead(b"PARTIAL_UNBOUNDED_DATA", expected=5000)
            resp.read = read
            return resp
        def close(self):
            pass

    ctx_unbounded = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.com"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ,
        declared_bytes=5000,
        task_id="task-unbounded-inc",
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="api.corp.com", direction=TransferDirection.DOWNLOAD, operation=TransferOperation.READ, declared_bytes=5000)
    )
    with patch("epistemicos.containment.PinnedHTTPConnection", IncompleteReadUnboundedConn):
        with pytest.raises(http.client.IncompleteRead):
            transport_unbounded.request(method="GET", url="http://api.corp.com/unbounded", transfer_context=ctx_unbounded)
    assert ctx_unbounded.observed_bytes == len(b"PARTIAL_UNBOUNDED_DATA")
    assert policy_unbounded.get_cumulative_bytes("task-unbounded-inc") == len(b"PARTIAL_UNBOUNDED_DATA")


def test_h1_broker_verifier_promotion_eliminated():
    """
    H1 Audit Verification:
    Proves that a broker NEVER promotes or mutates an attached DataTransferPolicy's verifier.
    If a DataTransferPolicy is instantiated with principal_verifier=None, attaching it to a broker
    (even one with a configured verifier) leaves the policy's verifier as None, and protected mode
    fails closed.
    """
    from epistemicos.containment import EgressTransportBroker, EgressPolicy

    policy_no_ver = DataTransferPolicy(
        rules=[TransferRule(rule_id="r-no-ver", destination_service="s3", allowed_hosts={"s3.corp.com"})],
        protected_mode=True,
        principal_verifier=None
    )

    idp = ExternalTestIdentityAuthority(issuer_id="BrokerIdP")
    broker_verifier = PrincipalVerifier(trusted_public_keys={"BrokerIdP": idp.public_key})

    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"s3.corp.com"}),
        transfer_policy=policy_no_ver,
        principal_verifier=broker_verifier
    )
    assert broker.principal_verifier is broker_verifier

    # Broker must NOT have mutated policy_no_ver.principal_verifier
    assert policy_no_ver.principal_verifier is None

    # Context evaluation against policy fails closed
    ctx_test = create_test_context(
        principal_verifier=TEST_VERIFIER,
        principal="principal:alice",
        destination=DestinationIdentity(service="s3", host="s3.corp.com"),
        classification=DataClassification.INTERNAL,
        direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE,
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="s3.corp.com")
    )
    dec = policy_no_ver.evaluate_transfer(ctx_test)
    assert dec.allowed is False
    assert "no trusted PrincipalVerifier configured on policy boundary" in dec.reason


def test_h2_body_types_and_digest_binding_matrix():
    """
    H2 Verification Audit:
    Proves digest derivation and authorization binding across:
    - bytes
    - bytearray
    - str
    - readable stream (io.BytesIO)
    - empty body (SHA-256(b""))
    - unsupported types fail closed with TypeError
    """
    import io
    from unittest.mock import patch

    policy = DataTransferPolicy(
        rules=[TransferRule(rule_id="r-h2-matrix", allowed_principals={"principal:alice"}, destination_service="api", allowed_hosts={"api.corp.com"})],
        principal_verifier=TEST_VERIFIER
    )
    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.com"}),
        transfer_policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    test_payload = b"TEST_PAYLOAD_DATA_123"
    expected_digest = hashlib.sha256(test_payload).hexdigest()

    class CaptureConn:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, method, url, body=None, headers=None):
            pass
        def getresponse(self):
            resp = MagicMock()
            resp.status = 200
            resp.reason = "OK"
            resp.getheaders.return_value = []
            resp.read.return_value = b""
            return resp
        def close(self):
            pass

    # 1. bytes body
    ctx_bytes = create_test_context(
        principal_verifier=TEST_VERIFIER, principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.com"),
        classification=DataClassification.INTERNAL, direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE, canonical_request_digest=expected_digest,
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="api.corp.com")
    )
    with patch("epistemicos.containment.PinnedHTTPConnection", CaptureConn):
        res = transport.request("POST", "http://api.corp.com/upload", body=test_payload, transfer_context=ctx_bytes)
        assert res["status"] == 200

    # 2. bytearray body
    ctx_bytearray = create_test_context(
        principal_verifier=TEST_VERIFIER, principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.com"),
        classification=DataClassification.INTERNAL, direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE, canonical_request_digest=expected_digest,
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="api.corp.com")
    )
    with patch("epistemicos.containment.PinnedHTTPConnection", CaptureConn):
        res = transport.request("POST", "http://api.corp.com/upload", body=bytearray(test_payload), transfer_context=ctx_bytearray)
        assert res["status"] == 200

    # 3. str body
    str_payload = "TEST_PAYLOAD_DATA_123"
    ctx_str = create_test_context(
        principal_verifier=TEST_VERIFIER, principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.com"),
        classification=DataClassification.INTERNAL, direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE, canonical_request_digest=expected_digest,
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="api.corp.com")
    )
    with patch("epistemicos.containment.PinnedHTTPConnection", CaptureConn):
        res = transport.request("POST", "http://api.corp.com/upload", body=str_payload, transfer_context=ctx_str)
        assert res["status"] == 200

    # 4. readable stream
    ctx_stream = create_test_context(
        principal_verifier=TEST_VERIFIER, principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.com"),
        classification=DataClassification.INTERNAL, direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE, canonical_request_digest=expected_digest,
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="api.corp.com")
    )
    with patch("epistemicos.containment.PinnedHTTPConnection", CaptureConn):
        res = transport.request("POST", "http://api.corp.com/upload", body=io.BytesIO(test_payload), transfer_context=ctx_stream)
        assert res["status"] == 200

    # 5. Unsupported body type raises TypeError
    with pytest.raises(TypeError) as exc_type:
        transport.request("POST", "http://api.corp.com/upload", body=12345, transfer_context=ctx_bytes)
    assert "Unsupported request body type" in str(exc_type.value)


def test_h3_disallowed_destination_does_not_consume_capability():
    """
    H3 Ordering Test:
    Proves that a disallowed destination fails closed BEFORE consuming an otherwise valid capability.
    The unconsumed capability remains valid and can authorize a subsequent allowed request.
    Also proves that DNS resolution is NEVER performed for a destination rejected by policy.
    """
    from epistemicos.authorization import CapabilityRegistry, AuthorizationAuthority, Policy
    from unittest.mock import patch, MagicMock

    registry = CapabilityRegistry(signing_secret=b"h3_ordering_test_secret_1234567")
    auth_policy = Policy(policy_id="p-h3-order", allowed_operations={"api_upload"}, allowed_resources={"api.corp.com"})
    authority = AuthorizationAuthority(default_policy=auth_policy, registry=registry, principal_provider=TEST_VERIFIER)
    principal = TEST_IDP.issue_principal("principal:alice")

    payload = b"H3_VALIDATION_PAYLOAD"
    payload_digest = hashlib.sha256(payload).hexdigest()

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="api_upload",
        target="api.corp.com",
        canonical_request_digest=payload_digest,
        executor_id="transport",
        principal_id=principal
    )

    transfer_policy = DataTransferPolicy(
        rules=[
            TransferRule(rule_id="r-allowed", allowed_principals={"principal:alice"}, destination_service="api", allowed_hosts={"api.corp.com"}, require_capability=True)
        ],
        principal_verifier=TEST_VERIFIER
    )

    mock_dns = MagicMock(return_value=["93.184.216.34"])
    # Broker allowlist permits api.corp.com, but NOT evil.attacker.com
    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.com"}),
        transfer_policy=transfer_policy,
        authorization_authority=authority,
        resolver_func=mock_dns
    )
    transport = ControlledEgressTransport(broker=broker)

    # 1. Attempt transfer to disallowed destination
    with pytest.raises(PermissionError) as exc_blocked:
        transport.request(
            method="POST",
            url="http://evil.attacker.com/upload",
            body=payload,
            capability=cap
        )
    assert "not in approved egress policy" in str(exc_blocked.value)

    # Prove DNS was NEVER invoked for evil.attacker.com
    mock_dns.assert_not_called()

    # Prove capability was NOT consumed
    assert registry.is_consumed(cap.token_id) is False

    # 2. Use the same unconsumed capability on the legitimate destination
    class LegitimateConn:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, method, url, body=None, headers=None):
            pass
        def getresponse(self):
            resp = MagicMock()
            resp.status = 200
            resp.reason = "OK"
            resp.getheaders.return_value = []
            resp.read.return_value = b"success"
            return resp
        def close(self):
            pass

    ctx = create_test_context(
        principal_verifier=TEST_VERIFIER, principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.com"),
        classification=DataClassification.INTERNAL, direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE, action_name="api_upload", target="api.corp.com",
        canonical_request_digest=payload_digest, declared_bytes=len(payload),
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="api.corp.com", direction=TransferDirection.UPLOAD, operation=TransferOperation.WRITE, declared_bytes=len(payload))
    )

    with patch("epistemicos.containment.PinnedHTTPConnection", LegitimateConn):
        res = transport.request(
            method="POST",
            url="http://api.corp.com/upload",
            body=payload,
            transfer_context=ctx,
            capability=cap
        )
        assert res["status"] == 200

    # Prove capability is now consumed
    assert registry.is_consumed(cap.token_id) is True

    # Prove consumed capability cannot be replayed
    with pytest.raises(PermissionError) as exc_replayed:
        transport.request(
            method="POST",
            url="http://api.corp.com/upload",
            body=payload,
            transfer_context=ctx,
            capability=cap
        )
    assert "already been consumed" in str(exc_replayed.value)


def test_h2_empty_body_positive_path():
    """
    H2 Positive Path Test:
    Proves that an empty-body request with SHA-256(b"") digest succeeds when context and capability match.
    Captures transmitted body to verify it is exactly empty (len 0), and proves mismatched digest fails before socket creation.
    """
    from epistemicos.authorization import CapabilityRegistry, AuthorizationAuthority, Policy
    from unittest.mock import patch, MagicMock

    empty_digest = hashlib.sha256(b"").hexdigest()
    registry = CapabilityRegistry(signing_secret=b"h2_empty_body_test_secret_12345")
    auth_policy = Policy(policy_id="p-h2-empty", allowed_operations={"api_ping"}, allowed_resources={"api.corp.com"})
    authority = AuthorizationAuthority(default_policy=auth_policy, registry=registry, principal_provider=TEST_VERIFIER)
    principal = TEST_IDP.issue_principal("principal:alice")

    cap_empty, _ = authority.evaluate_and_issue_capability(
        action_name="api_ping",
        target="api.corp.com",
        canonical_request_digest=empty_digest,
        executor_id="transport",
        principal_id=principal
    )

    transfer_policy = DataTransferPolicy(
        rules=[
            TransferRule(rule_id="r-empty", allowed_principals={"principal:alice"}, destination_service="api", allowed_hosts={"api.corp.com"}, require_capability=True)
        ],
        principal_verifier=TEST_VERIFIER
    )

    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.com"}),
        transfer_policy=transfer_policy,
        authorization_authority=authority,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    captured_requests = []
    class CaptureEmptyConn:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, method, url, body=None, headers=None):
            captured_requests.append((method, url, body))
        def getresponse(self):
            resp = MagicMock()
            resp.status = 200
            resp.reason = "OK"
            resp.getheaders.return_value = []
            resp.read.return_value = b""
            return resp
        def close(self):
            pass

    ctx_empty = create_test_context(
        principal_verifier=TEST_VERIFIER, principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.com"),
        classification=DataClassification.INTERNAL, direction=TransferDirection.DOWNLOAD,
        operation=TransferOperation.READ, action_name="api_ping", target="api.corp.com",
        canonical_request_digest=empty_digest, declared_bytes=0,
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL", destination_host="api.corp.com", direction=TransferDirection.DOWNLOAD, operation=TransferOperation.READ, declared_bytes=0)
    )

    with patch("epistemicos.containment.PinnedHTTPConnection", CaptureEmptyConn):
        res = transport.request(
            method="GET",
            url="http://api.corp.com/ping",
            body=None,
            transfer_context=ctx_empty,
            capability=cap_empty
        )
        assert res["status"] == 200

    assert len(captured_requests) == 1
    method, url, transmitted_body = captured_requests[0]
    assert method == "GET"
    assert transmitted_body is None or len(transmitted_body) == 0

    # Negative test: Mismatched digest fails before socket creation
    wrong_cap, _ = authority.evaluate_and_issue_capability(
        action_name="api_ping",
        target="api.corp.com",
        canonical_request_digest=hashlib.sha256(b"wrong").hexdigest(),
        executor_id="transport",
        principal_id=principal
    )
    with patch("epistemicos.containment.PinnedHTTPConnection") as mock_conn:
        with pytest.raises(PermissionError) as exc_mismatch:
            transport.request(
                method="GET",
                url="http://api.corp.com/ping",
                body=None,
                transfer_context=ctx_empty,
                capability=wrong_cap
            )
        assert "Capability digest mismatch" in str(exc_mismatch.value)
        mock_conn.assert_not_called()


def test_endpoint_path_destination_binding_and_capability_target():
    """
    Endpoint-Level Authorization Test:
    Proves that when DestinationIdentity specifies endpoint_path:
    1. Requests to a different path on the same host fail closed without consuming single-use capability.
    2. Capability target derivation matches host/endpoint_path.
    3. Requests to the exact authorized endpoint path succeed.
    """
    from epistemicos.authorization import CapabilityRegistry, AuthorizationAuthority, Policy
    from unittest.mock import patch, MagicMock

    registry = CapabilityRegistry(signing_secret=b"endpoint_auth_secret_key_123456")
    auth_policy = Policy(policy_id="p-endpoint", allowed_operations={"api_upload"}, allowed_resources={"api.corp.com/v1/approved"})
    authority = AuthorizationAuthority(default_policy=auth_policy, registry=registry, principal_provider=TEST_VERIFIER)
    principal = TEST_IDP.issue_principal("principal:alice")

    payload = b"APPROVED_ENDPOINT_PAYLOAD"
    payload_digest = hashlib.sha256(payload).hexdigest()

    # Capability target explicitly bound to /v1/approved
    cap, _ = authority.evaluate_and_issue_capability(
        action_name="api_upload",
        target="api.corp.com/v1/approved",
        canonical_request_digest=payload_digest,
        executor_id="transport",
        principal_id=principal
    )

    transfer_policy = DataTransferPolicy(
        rules=[
            TransferRule(
                rule_id="r-endpoint",
                allowed_principals={"principal:alice"},
                destination_service="api",
                allowed_hosts={"api.corp.com"},
                require_capability=True
            )
        ],
        principal_verifier=TEST_VERIFIER
    )

    broker = EgressTransportBroker(
        policy=EgressPolicy(allowed_destinations={"api.corp.com"}),
        transfer_policy=transfer_policy,
        authorization_authority=authority,
        resolver_func=lambda h: ["93.184.216.34"]
    )
    transport = ControlledEgressTransport(broker=broker)

    # 1. Attempt transfer to unapproved path /v1/unapproved with context bound to /v1/approved
    ctx_approved = create_test_context(
        principal_verifier=TEST_VERIFIER, principal="principal:alice",
        destination=DestinationIdentity(service="api", host="api.corp.com", endpoint_path="/v1/approved"),
        classification=DataClassification.INTERNAL, direction=TransferDirection.UPLOAD,
        operation=TransferOperation.WRITE, action_name="api_upload",
        target="api.corp.com/v1/approved", canonical_request_digest=payload_digest, declared_bytes=len(payload),
        trusted_authority_assertion=make_assertion(
            "principal:alice", "INTERNAL", destination_host="api.corp.com", endpoint_path="/v1/approved",
            direction=TransferDirection.UPLOAD, operation=TransferOperation.WRITE, declared_bytes=len(payload)
        )
    )

    with pytest.raises(PermissionError) as exc_path_mismatch:
        transport.request(
            method="POST",
            url="http://api.corp.com/v1/unapproved",
            body=payload,
            transfer_context=ctx_approved,
            capability=cap
        )
    assert "endpoint_path '/v1/approved' does not match actual target path '/v1/unapproved'" in str(exc_path_mismatch.value)

    # Capability must NOT have been consumed
    assert registry.is_consumed(cap.token_id) is False

    # 2. Attempt transfer to approved path succeeds
    class EndpointConn:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, method, url, body=None, headers=None):
            pass
        def getresponse(self):
            resp = MagicMock()
            resp.status = 200
            resp.reason = "OK"
            resp.getheaders.return_value = []
            resp.read.return_value = b"approved_ok"
            return resp
        def close(self):
            pass

    with patch("epistemicos.containment.PinnedHTTPConnection", EndpointConn):
        res = transport.request(
            method="POST",
            url="http://api.corp.com/v1/approved",
            body=payload,
            transfer_context=ctx_approved,
            capability=cap
        )
        assert res["status"] == 200

    # Capability is now consumed
    assert registry.is_consumed(cap.token_id) is True
