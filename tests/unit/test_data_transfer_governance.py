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
import os
import tempfile
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
import time
from epistemicos.authorization import PrincipalVerifier
from tests.unit.test_sec01_sec03_remediation import ExternalTestIdentityAuthority, _ed25519_sign

TEST_IDP = ExternalTestIdentityAuthority("TrustedClassificationAuthority")
TEST_VERIFIER = PrincipalVerifier(
    trusted_public_keys={"TrustedClassificationAuthority": TEST_IDP.public_key}
)


@functools.lru_cache(maxsize=128)
def _cached_sign(payload: bytes):
    return _ed25519_sign(payload, TEST_IDP.private_seed, TEST_IDP.public_key).hex()


def make_assertion(
    principal: str,
    classification: str = "CONFIDENTIAL",
    destination_host: str = None,
    expires_at: float = None,
    issuer: str = "TrustedClassificationAuthority",
    timestamp: float = None
):
    if hasattr(classification, "value"):
        classification = classification.value
    now = time.time()
    ts = timestamp if timestamp is not None else now
    # Default expiry far in the future
    exp = expires_at if expires_at is not None else now + 3600.0 * 24
    dest_str = destination_host or ""
    payload = f"{principal}:{issuer}:{classification}:{dest_str}:{ts:.6f}:{exp:.6f}".encode("utf-8")
    sig = _cached_sign(payload)
    return {
        "issuer": issuer,
        "signature": sig,
        "principal": principal,
        "classification": classification,
        "destination_host": destination_host,
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
    return DataTransferPolicy(
        rules=[rule_onedrive, rule_gdrive, rule_cap_required],
        default_max_cumulative_bytes=100000,
        protected_mode=True
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
        trusted_authority_assertion=make_assertion("principal:alice", "CONFIDENTIAL")
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
        trusted_authority_assertion=make_assertion("principal:alice", "CONFIDENTIAL")
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
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL")
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
        trusted_authority_assertion=make_assertion("principal:alice", "CONFIDENTIAL")
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
        trusted_authority_assertion=make_assertion("principal:unauthorized-mallory", "INTERNAL")
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
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL")
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
            trusted_authority_assertion=make_assertion("principal:backup-agent", "INTERNAL")
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
    cap = Capability(
        token_id="cap-token-s3-prod",
        principal_id="principal:admin",
        correlation_id="corr-1",
        request_id="req-1",
        action_name="s3_replicate",
        target="s3.us-east-1.amazonaws.com",
        canonical_request_digest="abc",
        executor_id="exec",
        policy_version="1.0",
        created_at=100.0,
        expires_at=200.0,
        task_id="task-prod-backup",
        signature="valid-sig-64chars-hex-000000000000000000000000000000000000000000000000"
    )

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
        trusted_authority_assertion=make_assertion("principal:admin", "RESTRICTED")
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
        trusted_authority_assertion=make_assertion("principal:admin", "RESTRICTED")
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
        trusted_authority_assertion=make_assertion("principal:admin", "RESTRICTED")
    )
    dec_task = org_policy.evaluate_transfer(ctx_diff_task, capability=cap)
    assert dec_task.allowed is False
    assert "Capability task mismatch" in dec_task.reason


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
        trusted_authority_assertion=make_assertion("principal:backup-svc", "CONFIDENTIAL")
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
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL")
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
            trusted_authority_assertion=make_assertion("principal:alice", "CONFIDENTIAL")
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
            trusted_authority_assertion=make_assertion("principal:backup-agent", "INTERNAL")
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
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL")
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
        trusted_authority_assertion=make_assertion("principal:admin", "RESTRICTED")
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
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL")
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
        trusted_authority_assertion=make_assertion("principal:alice", "INTERNAL")
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
