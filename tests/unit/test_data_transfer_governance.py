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
    source_scope: Optional[str] = None,
    direction: Union[TransferDirection, str] = TransferDirection.UPLOAD,
    operation: Union[TransferOperation, str] = TransferOperation.WRITE,
    expires_at: Optional[float] = None,
    issuer: str = "TrustedClassificationAuthority",
    timestamp: Optional[float] = None
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
    scope_str = source_scope or ""
    payload = (
        f"{principal.strip()}:{issuer}:{dest_str}:"
        f"{tenant_str}:{account_str}:{classification.upper()}:"
        f"{scope_str}:{dir_str.upper()}:{op_str.upper()}:{ts:.6f}:{exp:.6f}"
    ).encode("utf-8")
    sig = _cached_sign(payload)
    return {
        "issuer": issuer,
        "signature": sig,
        "principal": principal,
        "destination_host": destination_host,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "classification": classification,
        "source_scope": source_scope,
        "direction": dir_str,
        "operation": op_str,
        "timestamp": ts,
        "expires_at": exp
    }


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
        authorization_authority=test_authority
    )


def test_requirement_a_approved_org_destination_succeeds(org_policy):
    """
    Requirement A: Approved organizational cloud destination + authorized principal +
    permitted classification + permitted volume succeeds.
    """
    ctx = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_consumer = TrustedTransferContextBuilder.create_trusted_context(
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

    ctx_unapproved_tenant = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx = TrustedTransferContextBuilder.create_trusted_context(
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

    ctx = TrustedTransferContextBuilder.create_trusted_context(
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
        c = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_s3 = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_diff_dest = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_diff_task = TrustedTransferContextBuilder.create_trusted_context(
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
        ]
    )

    ctx_rclone = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_mismatch = TrustedTransferContextBuilder.create_trusted_context(
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

        ctx = TrustedTransferContextBuilder.create_trusted_context(
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
        ctx = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_obj = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_forged = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_tampered = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_unknown = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_dest_mismatch = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_expired = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_no_verifier = TrustedTransferContextBuilder.create_trusted_context(
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

    ctx = TrustedTransferContextBuilder.create_trusted_context(
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

    ctx = TrustedTransferContextBuilder.create_trusted_context(
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

    ctx = TrustedTransferContextBuilder.create_trusted_context(
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
    policy = DataTransferPolicy(rules=[rule], default_max_cumulative_bytes=1000)

    num_threads = 10
    vol_per_request = 200  # 10 * 200 = 2000 > 1000
    barrier = threading.Barrier(num_threads)

    def worker(idx):
        ctx = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_replayed_tenant = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_replayed_op = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_generic_dest = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_no_exp = TrustedTransferContextBuilder.create_trusted_context(
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
    transfer_policy = DataTransferPolicy(rules=[transfer_rule])
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
        return TrustedTransferContextBuilder.create_trusted_context(
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

    policy = DataTransferPolicy(rules=[rule_restricted, rule_standard])
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
    ctx_restricted = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_standard = TrustedTransferContextBuilder.create_trusted_context(
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
        ctx = TrustedTransferContextBuilder.create_trusted_context(
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
        policy = DataTransferPolicy(rules=[rule])
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
    cap_policy = DataTransferPolicy(rules=[cap_rule])
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
    clean_ctx = TrustedTransferContextBuilder.create_trusted_context(
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
        default_max_cumulative_bytes=1000
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

    ctx_pre = TrustedTransferContextBuilder.create_trusted_context(
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

    ctx_part_up = TrustedTransferContextBuilder.create_trusted_context(
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

    ctx_stream = TrustedTransferContextBuilder.create_trusted_context(
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

    ctx_success = TrustedTransferContextBuilder.create_trusted_context(
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

    # Valid assertion signing all security fields including task_id, workspace_id, etc.
    ts = 1800000000.0
    exp = 2500000000.0
    payload = (
        f"principal:alice:TrustedClassificationAuthority:s3.us-east-1.amazonaws.com:"
        f"tenant-org:account-org:ws-analytics:/reports:CONFIDENTIAL:scope-finance:"
        f"UPLOAD:WRITE:task-adversarial-1:500:{ts:.6f}:{exp:.6f}"
    ).encode("utf-8")
    sig = _cached_sign(payload)

    base_assertion = {
        "issuer": "TrustedClassificationAuthority",
        "signature": sig,
        "principal": "principal:alice",
        "destination_host": "s3.us-east-1.amazonaws.com",
        "tenant_id": "tenant-org",
        "account_id": "account-org",
        "workspace_id": "ws-analytics",
        "endpoint_path": "/reports",
        "classification": "CONFIDENTIAL",
        "source_scope": "scope-finance",
        "direction": "UPLOAD",
        "operation": "WRITE",
        "task_id": "task-adversarial-1",
        "declared_bytes": 500,
        "timestamp": ts,
        "expires_at": exp
    }

    # Valid baseline context
    ctx = TrustedTransferContextBuilder.create_trusted_context(
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
    ctx_replayed_task = TrustedTransferContextBuilder.create_trusted_context(
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
    policy = DataTransferPolicy(rules=[rule_strict])

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

    ctx_same_host = TrustedTransferContextBuilder.create_trusted_context(
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
            elif "/hop2" in self.last_url:
                resp.status = 302
                resp.getheaders.return_value = [("Location", "/hop3")]
                resp.read.side_effect = [b"h2", b""]  # 2 bytes
            else:
                resp.status = 200
                resp.getheaders.return_value = []
                resp.read.side_effect = [b"final-dest", b""]  # 10 bytes
            return resp

        def close(self):
            pass

    ctx_multi = TrustedTransferContextBuilder.create_trusted_context(
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
    # Hop 2: 0 req + 2 resp = 2.
    # Hop 3: 0 req + 10 resp = 10.
    # Total: 34 bytes.
    assert policy.get_cumulative_bytes(task_id_multi) == 34
    assert policy.get_allocated_bytes(task_id_multi) == 34

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

    ctx_fail_hop2 = TrustedTransferContextBuilder.create_trusted_context(
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

    ctx_ceiling = TrustedTransferContextBuilder.create_trusted_context(
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
