"""
Unit and integration tests for EpistemicOS Observatory Data Adapters.
"""

import json
import pytest
from pathlib import Path

from epistemicos.ui.adapters import ObservatoryDataAdapter
from epistemicos.provenance import ProvenanceEvent, ProvenanceEventType, ProvenanceSource


@pytest.fixture
def mock_logs(tmp_path):
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"

    # Write ablation table
    ablation_data = {
        "version": "1.0.0",
        "baselines": {
            "Permission-Only Gating": {
                "sample_count": 10,
                "confusion_matrix": {"TC": 1, "FC": 2, "TR": 4, "FR": 3},
                "accuracy_pct": 50.0,
                "accuracy_95ci": [23.66, 76.34],
                "false_positive_rate_pct": 75.0,
                "false_negative_rate_pct": 33.33,
                "avg_latency_ms": 3.265
            }
        },
        "threshold_ablations": {
            "z_threshold_1.0": {"z_threshold": 1.0, "TC": 3, "FC": 0, "TR": 6, "FR": 1, "precision": 100.0, "recall": 100.0}
        },
        "attribution": {"stopping_benefit": "Entropy gate truncates high-surprisal sequences instantly."}
    }
    ablation_file.write_text(json.dumps(ablation_data), encoding="utf-8")

    # Write per case
    per_case_data = [
        {"case_id": "case_1", "family": "Family_A", "prompt": "test prompt", "status": "COMPLETED", "gate_action": "ALLOW"}
    ]
    per_case_file.write_text(json.dumps(per_case_data), encoding="utf-8")

    return {
        "audit": str(audit_file),
        "provenance": str(provenance_file),
        "ablation": str(ablation_file),
        "per_case": str(per_case_file)
    }


def test_overview_missing_files(tmp_path):
    """Verifies that missing files yield explicit UNAVAILABLE/unverified status without throwing."""
    adapter = ObservatoryDataAdapter(
        audit_log_path=str(tmp_path / "missing_audit.jsonl"),
        provenance_log_path=str(tmp_path / "missing_prov.jsonl"),
        ablation_table_path=str(tmp_path / "missing_abl.json"),
        per_case_results_path=str(tmp_path / "missing_case.json")
    )

    overview = adapter.get_overview()
    assert overview["metrics"]["total_executions"] is None
    assert overview["metrics"]["authorization_denials"] is None
    assert overview["metrics"]["halts"] is None
    assert overview["status_flags"]["provenance_data_available"] is False
    assert overview["audit_integrity"]["status"] == "UNAVAILABLE"
    assert overview["provenance_integrity"]["status"] == "UNAVAILABLE"


def test_malformed_json_resilience(tmp_path):
    """Verifies fail-closed handling and parse error tracking for corrupted JSON lines."""
    prov_file = tmp_path / "corrupt_prov.jsonl"
    prov_file.write_text("{\"valid\": 1}\nNOT_VALID_JSON\n{\"valid\": 2}\n", encoding="utf-8")

    adapter = ObservatoryDataAdapter(
        audit_log_path=str(tmp_path / "missing_audit.jsonl"),
        provenance_log_path=str(prov_file)
    )

    overview = adapter.get_overview()
    assert overview["metrics"]["parse_error_count"] >= 1

    prov_data = adapter.get_provenance_explorer_data()
    assert len(prov_data["events"]) == 2
    assert prov_data["parse_error_count"] == 1


def test_execution_trace_outcomes(mock_logs):
    """Verifies distinct classification of DENIED, HALTED, COMPLETED, FAILED, and OUTCOME_UNKNOWN."""
    adapter = ObservatoryDataAdapter(
        audit_log_path=mock_logs["audit"],
        provenance_log_path=mock_logs["provenance"]
    )

    # Populate provenance log with multiple correlation traces
    prov_store = adapter.provenance_log_path

    event_denied = {
        "schema_version": "1.0.0",
        "event_id": "e1",
        "event_type": "AUTHORIZATION_DENIED",
        "provenance_source": "GOVERNANCE_GATE",
        "correlation_id": "corr_denied",
        "request_id": "req_1",
        "action_name": "db_drop",
        "target": "prod_db",
        "canonical_request_digest": "digest1",
        "timestamp": "2025-01-01T00:00:00Z",
        "sequence_number": 1,
        "prev_hash": "genesis",
        "entry_hash": "hash1"
    }

    event_halted = {
        "schema_version": "1.0.0",
        "event_id": "e2",
        "event_type": "EGRESS_BLOCKED",
        "provenance_source": "EGRESS_GATE",
        "correlation_id": "corr_halted",
        "request_id": "req_2",
        "action_name": "http_post",
        "target": "external_url",
        "canonical_request_digest": "digest2",
        "timestamp": "2025-01-01T00:01:00Z",
        "sequence_number": 2,
        "prev_hash": "hash1",
        "entry_hash": "hash2"
    }

    with open(prov_store, "w", encoding="utf-8") as f:
        f.write(json.dumps(event_denied) + "\n")
        f.write(json.dumps(event_halted) + "\n")

    traces = adapter.get_execution_traces()
    status_map = {t["correlation_id"]: t["status"] for t in traces}

    assert status_map["corr_denied"] == "DENIED"
    assert status_map["corr_halted"] == "HALTED"


def test_reconciliation_mismatch_detection(mock_logs):
    """Verifies that reconciliation flags contradictory states (e.g. execution without auth)."""
    adapter = ObservatoryDataAdapter(
        audit_log_path=mock_logs["audit"],
        provenance_log_path=mock_logs["provenance"]
    )

    prov_store = adapter.provenance_log_path
    unauthorized_exec = {
        "schema_version": "1.0.0",
        "event_id": "e3",
        "event_type": "EXECUTION_STARTED",
        "provenance_source": "EXECUTOR",
        "correlation_id": "corr_unauth",
        "request_id": "req_3",
        "action_name": "delete_file",
        "target": "/etc/shadow",
        "canonical_request_digest": "digest3",
        "timestamp": "2025-01-01T00:02:00Z",
        "authorization_token_id": "unauthorized_token",
        "sequence_number": 1,
        "prev_hash": "genesis",
        "entry_hash": "hash3"
    }

    with open(prov_store, "w", encoding="utf-8") as f:
        f.write(json.dumps(unauthorized_exec) + "\n")

    trace = adapter.get_execution_trace_by_id("corr_unauth")
    assert trace is not None
    rec = trace["reconciliation"]
    assert rec["valid"] is False
    assert rec["status"] == "RECONCILIATION_MISMATCH"
    assert any("without authorization granted" in v for v in rec["violations"])


def test_execution_trace_missing_fields_handling(mock_logs):
    """Verifies handling of events with missing optional fields (missing timestamp, target, action)."""
    adapter = ObservatoryDataAdapter(
        audit_log_path=mock_logs["audit"],
        provenance_log_path=mock_logs["provenance"]
    )

    prov_store = adapter.provenance_log_path
    partial_event = {
        "schema_version": "1.0.0",
        "event_id": "e_partial",
        "event_type": "ACTION_PROPOSED",
        "provenance_source": "AGENT_SHELL",
        "correlation_id": "corr_partial",
        "sequence_number": 1,
        "prev_hash": "genesis",
        "entry_hash": "hash_p1"
    }

    with open(prov_store, "w", encoding="utf-8") as f:
        f.write(json.dumps(partial_event) + "\n")

    trace = adapter.get_execution_trace_by_id("corr_partial")
    assert trace is not None
    assert trace["action_name"] == "UNKNOWN"
    assert trace["target"] == "UNKNOWN"
    assert trace["start_time"] == "UNKNOWN"
    assert trace["status"] == "OUTCOME_UNKNOWN"
    assert trace["event_count"] == 1


def test_benchmark_data_loading(mock_logs):
    """Verifies benchmark workbench data structure parsing."""
    adapter = ObservatoryDataAdapter(
        ablation_table_path=mock_logs["ablation"],
        per_case_results_path=mock_logs["per_case"]
    )

    data = adapter.get_benchmark_data()
    assert data["ablation_table"]["available"] is True
    assert "Permission-Only Gating" in data["ablation_table"]["data"]["baselines"]
    assert data["per_case_results"]["available"] is True
    assert len(data["per_case_results"]["data"]) == 1


def test_provenance_explorer_summary_panels_and_findings(mock_logs):
    """Verifies provenance explorer returns 4 verification summary panels and actionable findings."""
    adapter = ObservatoryDataAdapter(
        audit_log_path=mock_logs["audit"],
        provenance_log_path=mock_logs["provenance"]
    )

    # Test missing file case
    data_missing = adapter.get_provenance_explorer_data()
    assert "summary_panels" in data_missing
    panels = data_missing["summary_panels"]
    assert panels["availability"]["status"] == "UNAVAILABLE"
    assert panels["integrity"]["status"] == "UNAVAILABLE"
    assert panels["coverage"]["status"] == "UNAVAILABLE"
    assert panels["authenticity"]["status"] == "NOT ESTABLISHED"
    assert any(f["code"] == "LOG_FILE_MISSING" for f in data_missing["findings"])

    # Test valid provenance events case recorded via store
    from epistemicos.provenance import LocalProvenanceStore, ProvenanceEvent
    store = LocalProvenanceStore(log_path=mock_logs["provenance"])
    event_valid = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="prov_ev_1",
        event_type="ACTION_PROPOSED",
        provenance_source="AGENT_ADAPTER",
        correlation_id="corr_test_1",
        request_id="req_test_1",
        action_name="read_file",
        target="data.txt",
        canonical_request_digest="digest_123",
        timestamp="2025-01-01T00:00:00Z"
    )
    store.record_event(event_valid)

    data_valid = adapter.get_provenance_explorer_data()
    panels_valid = data_valid["summary_panels"]
    assert panels_valid["availability"]["status"] == "AVAILABLE"
    assert panels_valid["availability"]["record_count"] == 1
    assert panels_valid["integrity"]["status"] == "VERIFIED"
    assert panels_valid["authenticity"]["status"] == "NOT ESTABLISHED"
    assert len(data_valid["events"]) == 1
    assert data_valid["events"][0]["event_id"] == "prov_ev_1"


def test_provenance_explorer_corrupted_hash_chain_finding(mock_logs):
    """Verifies critical finding generation when hash chain is broken."""
    adapter = ObservatoryDataAdapter(
        audit_log_path=mock_logs["audit"],
        provenance_log_path=mock_logs["provenance"]
    )

    corrupt_event = {
        "schema_version": "1.0.0",
        "event_id": "prov_corrupt",
        "event_type": "ACTION_PROPOSED",
        "provenance_source": "AGENT_ADAPTER",
        "correlation_id": "corr_corrupt",
        "request_id": "req_corrupt",
        "action_name": "run",
        "target": "target",
        "canonical_request_digest": "digest",
        "timestamp": "2025-01-01T00:00:00Z",
        "sequence_number": 5,  # Mismatched sequence number (expected 1)
        "prev_hash": "wrong_prev_hash",
        "entry_hash": "bad_entry_hash"
    }

    with open(mock_logs["provenance"], "w", encoding="utf-8") as f:
        f.write(json.dumps(corrupt_event) + "\n")

    data = adapter.get_provenance_explorer_data()
    assert data["summary_panels"]["integrity"]["status"] == "CORRUPTED"
    assert any(f["code"] == "HASH_CHAIN_CORRUPTED" for f in data["findings"])


def test_coverage_for_failed_execution_with_complete_evidence(mock_logs):
    """
    Verifies that a failed execution with complete, reconciled evidence
    is NOT classified as an incomplete trace in coverage calculations.
    """
    from epistemicos.provenance import LocalProvenanceStore, ProvenanceEvent
    store = LocalProvenanceStore(log_path=mock_logs["provenance"])

    # Complete lifecycle for a failed execution
    e1 = ProvenanceEvent("1.0.0", "ev1", "ACTION_PROPOSED", "AGENT_ADAPTER", "corr_fail", "req1", "run", "tgt", "dig", "2025-01-01T00:00:00Z")
    e2 = ProvenanceEvent("1.0.0", "ev2", "AUTHORIZATION_GRANTED", "GOVERNANCE_GATE", "corr_fail", "req1", "run", "tgt", "dig", "2025-01-01T00:00:01Z", authorization_token_id="tok1")
    e3 = ProvenanceEvent("1.0.0", "ev3", "EXECUTION_STARTED", "EXECUTOR", "corr_fail", "req1", "run", "tgt", "dig", "2025-01-01T00:00:02Z", authorization_token_id="tok1", execution_attempt_id="att1")
    e4 = ProvenanceEvent("1.0.0", "ev4", "EXECUTION_FAILED", "EXECUTOR", "corr_fail", "req1", "run", "tgt", "dig", "2025-01-01T00:00:03Z", authorization_token_id="tok1", execution_attempt_id="att1")

    for e in (e1, e2, e3, e4):
        store.record_event(e)

    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])

    # Trace status should be FAILED, but reconciliation should be valid
    traces = adapter.get_execution_traces()
    assert len(traces) == 1
    assert traces[0]["status"] == "FAILED"
    assert traces[0]["reconciliation"]["valid"] is True

    # Coverage panel should NOT report incomplete trace
    data = adapter.get_provenance_explorer_data()
    assert data["summary_panels"]["coverage"]["status"] == "UNVERIFIED"
    assert "0 of 1" not in data["summary_panels"]["coverage"]["message"]
    assert "missing terminal" not in data["summary_panels"]["coverage"]["message"]


def test_coverage_for_incomplete_execution_trace(mock_logs):
    """Verifies that an execution started without terminal event yields INCOMPLETE coverage."""
    from epistemicos.provenance import LocalProvenanceStore, ProvenanceEvent
    store = LocalProvenanceStore(log_path=mock_logs["provenance"])

    e1 = ProvenanceEvent("1.0.0", "ev1", "ACTION_PROPOSED", "AGENT_ADAPTER", "corr_inc", "req1", "run", "tgt", "dig", "2025-01-01T00:00:00Z")
    e2 = ProvenanceEvent("1.0.0", "ev2", "AUTHORIZATION_GRANTED", "GOVERNANCE_GATE", "corr_inc", "req1", "run", "tgt", "dig", "2025-01-01T00:00:01Z", authorization_token_id="tok1")
    e3 = ProvenanceEvent("1.0.0", "ev3", "EXECUTION_STARTED", "EXECUTOR", "corr_inc", "req1", "run", "tgt", "dig", "2025-01-01T00:00:02Z", authorization_token_id="tok1", execution_attempt_id="att1")

    for e in (e1, e2, e3):
        store.record_event(e)

    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])

    data = adapter.get_provenance_explorer_data()
    cov = data["summary_panels"]["coverage"]
    assert cov["status"] == "INCOMPLETE"
    assert "1 of 1" in cov["message"]


def test_corrupted_hash_chain_coverage_contradiction_prevention(mock_logs):
    """
    Verifies that when integrity is CORRUPTED and no trace is flagged as incomplete,
    the coverage message does NOT claim 'Valid local cryptographic sequence chaining verifies log continuity'.
    """
    # Complete event lifecycle (e.g. AUTHORIZATION_DENIED), but with a bad entry_hash that corrupts the chain
    corrupt_event = {
        "schema_version": "1.0.0",
        "event_id": "prov_corrupt",
        "event_type": "AUTHORIZATION_DENIED",
        "provenance_source": "GOVERNANCE_GATE",
        "correlation_id": "corr_corrupt",
        "request_id": "req_corrupt",
        "action_name": "run",
        "target": "target",
        "canonical_request_digest": "digest",
        "timestamp": "2025-01-01T00:00:00Z",
        "sequence_number": 1,
        "prev_hash": "genesis",
        "entry_hash": "bad_entry_hash"
    }

    with open(mock_logs["provenance"], "w", encoding="utf-8") as f:
        f.write(json.dumps(corrupt_event) + "\n")

    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])
    data = adapter.get_provenance_explorer_data()

    assert data["summary_panels"]["integrity"]["status"] == "CORRUPTED"
    cov = data["summary_panels"]["coverage"]
    assert cov["status"] == "UNVERIFIED"
    assert "failed integrity verification" in cov["message"].lower()
    assert "valid local cryptographic sequence chaining" not in cov["message"].lower()


def test_fully_readable_provenance_log(mock_logs):
    """Verifies that a log where all entries parse yields AVAILABLE status with 0 parse errors."""
    from epistemicos.provenance import LocalProvenanceStore, ProvenanceEvent
    store = LocalProvenanceStore(log_path=mock_logs["provenance"])

    e1 = ProvenanceEvent("1.0.0", "ev1", "ACTION_PROPOSED", "AGENT_ADAPTER", "corr_1", "req1", "run", "tgt", "dig", "2025-01-01T00:00:00Z")
    store.record_event(e1)

    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])
    data = adapter.get_provenance_explorer_data()

    assert data["parse_error_count"] == 0
    assert len(data["events"]) == 1
    assert data["summary_panels"]["availability"]["status"] == "AVAILABLE"
    assert "fully accessible" in data["summary_panels"]["availability"]["message"].lower()


def test_partially_readable_provenance_log(mock_logs):
    """Verifies that a log containing both valid and malformed entries yields PARTIAL availability status."""
    from epistemicos.provenance import LocalProvenanceStore, ProvenanceEvent
    store = LocalProvenanceStore(log_path=mock_logs["provenance"])

    e1 = ProvenanceEvent("1.0.0", "ev1", "ACTION_PROPOSED", "AGENT_ADAPTER", "corr_1", "req1", "run", "tgt", "dig", "2025-01-01T00:00:00Z")
    store.record_event(e1)

    # Append malformed line directly
    with open(mock_logs["provenance"], "a", encoding="utf-8") as f:
        f.write("MALFORMED_NON_JSON_LINE\n")

    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])
    data = adapter.get_provenance_explorer_data()

    assert data["parse_error_count"] == 1
    assert len(data["events"]) == 1
    assert data["summary_panels"]["availability"]["status"] == "PARTIAL"
    assert "partially readable" in data["summary_panels"]["availability"]["message"].lower()
    assert any(f["code"] == "PARSE_ERRORS_DETECTED" for f in data["findings"])


def test_all_entries_fail_to_parse_provenance_log(mock_logs):
    """Verifies that a log whose entries all fail to parse yields CORRUPTED availability status."""
    with open(mock_logs["provenance"], "w", encoding="utf-8") as f:
        f.write("BAD_LINE_1\nBAD_LINE_2\n")

    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])
    data = adapter.get_provenance_explorer_data()

    assert data["parse_error_count"] == 2
    assert len(data["events"]) == 0
    assert data["summary_panels"]["availability"]["status"] == "CORRUPTED"


def test_empty_readable_provenance_log(mock_logs):
    """Verifies that an empty existing file produces EMPTY availability status."""
    Path(mock_logs["provenance"]).touch()

    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])
    data = adapter.get_provenance_explorer_data()

    assert data["summary_panels"]["availability"]["status"] == "EMPTY"
    assert data["summary_panels"]["coverage"]["status"] == "UNAVAILABLE"


def test_unestablished_source_authenticity(mock_logs):
    """Verifies that source authenticity panel consistently reports NOT ESTABLISHED with scope details."""
    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])
    data = adapter.get_provenance_explorer_data()

    auth = data["summary_panels"]["authenticity"]
    assert auth["status"] == "NOT ESTABLISHED"
    assert "hardware enclave" in auth["message"].lower()
    assert "scope" in auth
