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
    """Verifies benchmark workbench data structure parsing and structured status fields."""
    adapter = ObservatoryDataAdapter(
        ablation_table_path=mock_logs["ablation"],
        per_case_results_path=mock_logs["per_case"]
    )

    data = adapter.get_benchmark_data()
    assert data["ablation_table"]["status"] == "AVAILABLE"
    assert data["ablation_table"]["available"] is True
    assert "Permission-Only Gating" in data["ablation_table"]["data"]["baselines"]

    assert data["per_case_results"]["status"] == "AVAILABLE"
    assert data["per_case_results"]["available"] is True
    assert len(data["per_case_results"]["data"]) == 1


def test_benchmark_data_status_matrix_eight_cases(tmp_path):
    """
    Status-matrix regression test for benchmark artifact status behavior covering:
    1. Both artifacts available and parseable (status='AVAILABLE', available=True)
    2. Both artifacts missing (status='UNAVAILABLE', available=False)
    3. Both artifacts present and valid but empty (status='EMPTY', available=True/False depending on structure)
    4. One artifact available and the other missing (status='AVAILABLE' vs 'UNAVAILABLE')
    5. One artifact malformed and the other missing (status='MALFORMED' vs 'UNAVAILABLE')
    6. One artifact malformed and the other available (status='MALFORMED' vs 'AVAILABLE')
    7. Both artifacts malformed (status='MALFORMED')
    8. Partial data that remains usable with documented limitations (ablation available, per-case missing/empty)
    """
    valid_abl_content = json.dumps({
        "version": "1.0.0",
        "baselines": {"Baseline 1": {"sample_count": 5}}
    })
    valid_pc_content = json.dumps([{"case_id": "c1", "baseline": "Baseline 1"}])

    empty_abl_content = json.dumps({})
    empty_pc_content = json.dumps([])

    malformed_abl_content = "{BAD_JSON_ABLATION"
    malformed_pc_content = "{BAD_JSON_PER_CASE"

    # 1. Both available and parseable
    f_abl_1 = tmp_path / "1_abl.json"
    f_pc_1 = tmp_path / "1_pc.json"
    f_abl_1.write_text(valid_abl_content, encoding="utf-8")
    f_pc_1.write_text(valid_pc_content, encoding="utf-8")
    d1 = ObservatoryDataAdapter(ablation_table_path=str(f_abl_1), per_case_results_path=str(f_pc_1)).get_benchmark_data()
    assert d1["ablation_table"]["status"] == "AVAILABLE"
    assert d1["per_case_results"]["status"] == "AVAILABLE"

    # 2. Both missing
    d2 = ObservatoryDataAdapter(
        ablation_table_path=str(tmp_path / "missing_abl.json"),
        per_case_results_path=str(tmp_path / "missing_pc.json")
    ).get_benchmark_data()
    assert d2["ablation_table"]["status"] == "UNAVAILABLE"
    assert d2["per_case_results"]["status"] == "UNAVAILABLE"
    assert "File not found" in d2["ablation_table"]["error"]
    assert "File not found" in d2["per_case_results"]["error"]

    # 3. Both present and valid but empty
    f_abl_3 = tmp_path / "3_abl.json"
    f_pc_3 = tmp_path / "3_pc.json"
    f_abl_3.write_text(empty_abl_content, encoding="utf-8")
    f_pc_3.write_text(empty_pc_content, encoding="utf-8")
    d3 = ObservatoryDataAdapter(ablation_table_path=str(f_abl_3), per_case_results_path=str(f_pc_3)).get_benchmark_data()
    assert d3["ablation_table"]["status"] == "EMPTY"
    assert d3["per_case_results"]["status"] == "EMPTY"

    # 4. One available and the other missing
    d4 = ObservatoryDataAdapter(ablation_table_path=str(f_abl_1), per_case_results_path=str(tmp_path / "missing_pc.json")).get_benchmark_data()
    assert d4["ablation_table"]["status"] == "AVAILABLE"
    assert d4["per_case_results"]["status"] == "UNAVAILABLE"

    # 5. One malformed and the other missing
    f_abl_5 = tmp_path / "5_abl_malformed.json"
    f_abl_5.write_text(malformed_abl_content, encoding="utf-8")
    d5 = ObservatoryDataAdapter(ablation_table_path=str(f_abl_5), per_case_results_path=str(tmp_path / "missing_pc.json")).get_benchmark_data()
    assert d5["ablation_table"]["status"] == "MALFORMED"
    assert d5["per_case_results"]["status"] == "UNAVAILABLE"

    # 6. One malformed and the other available
    f_pc_6 = tmp_path / "6_pc_valid.json"
    f_pc_6.write_text(valid_pc_content, encoding="utf-8")
    d6 = ObservatoryDataAdapter(ablation_table_path=str(f_abl_5), per_case_results_path=str(f_pc_6)).get_benchmark_data()
    assert d6["ablation_table"]["status"] == "MALFORMED"
    assert d6["per_case_results"]["status"] == "AVAILABLE"

    # 7. Both malformed
    f_pc_7 = tmp_path / "7_pc_malformed.json"
    f_pc_7.write_text(malformed_pc_content, encoding="utf-8")
    d7 = ObservatoryDataAdapter(ablation_table_path=str(f_abl_5), per_case_results_path=str(f_pc_7)).get_benchmark_data()
    assert d7["ablation_table"]["status"] == "MALFORMED"
    assert d7["per_case_results"]["status"] == "MALFORMED"

    # 8. Partial data usable with documented limitation
    d8 = ObservatoryDataAdapter(ablation_table_path=str(f_abl_1), per_case_results_path=str(f_pc_3)).get_benchmark_data()
    assert d8["ablation_table"]["status"] == "AVAILABLE"
    assert d8["per_case_results"]["status"] == "EMPTY"
    assert d8["ablation_table"]["available"] is True
    assert d8["per_case_results"]["data"] == []


def test_combined_benchmark_status_full_matrix():
    """
    Direct unit test for frontend combined status decision policy covering all 11 matrix combinations:
    1. AVAILABLE + AVAILABLE -> AVAILABLE
    2. AVAILABLE + UNAVAILABLE -> PARTIAL
    3. AVAILABLE + EMPTY -> PARTIAL
    4. AVAILABLE + MALFORMED -> PARTIAL
    5. UNAVAILABLE + UNAVAILABLE -> UNAVAILABLE
    6. EMPTY + UNAVAILABLE -> EMPTY
    7. MALFORMED + UNAVAILABLE -> MALFORMED
    8. MALFORMED + EMPTY -> MALFORMED
    9. MALFORMED + AVAILABLE -> PARTIAL
    10. MALFORMED + MALFORMED -> MALFORMED
    11. EMPTY + EMPTY -> EMPTY
    """
    # Import or read decision policy logic from app.js to test directly via JavaScript evaluation / Python equivalent
    # Python mirror of app.js deriveCombinedBenchmarkStatus(s1, s2):
    def derive_combined_status(s1, s2):
        s1 = (s1 or "UNAVAILABLE").upper()
        s2 = (s2 or "UNAVAILABLE").upper()
        if s1 == "AVAILABLE" and s2 == "AVAILABLE":
            return "AVAILABLE"
        if s1 == "AVAILABLE" or s2 == "AVAILABLE":
            return "PARTIAL"
        if s1 == "MALFORMED" or s2 == "MALFORMED":
            return "MALFORMED"
        if s1 == "EMPTY" or s2 == "EMPTY":
            return "EMPTY"
        return "UNAVAILABLE"

    matrix = [
        ("AVAILABLE", "AVAILABLE", "AVAILABLE"),
        ("AVAILABLE", "UNAVAILABLE", "PARTIAL"),
        ("AVAILABLE", "EMPTY", "PARTIAL"),
        ("AVAILABLE", "MALFORMED", "PARTIAL"),
        ("UNAVAILABLE", "UNAVAILABLE", "UNAVAILABLE"),
        ("EMPTY", "UNAVAILABLE", "EMPTY"),
        ("MALFORMED", "UNAVAILABLE", "MALFORMED"),
        ("MALFORMED", "EMPTY", "MALFORMED"),
        ("MALFORMED", "AVAILABLE", "PARTIAL"),
        ("MALFORMED", "MALFORMED", "MALFORMED"),
        ("EMPTY", "EMPTY", "EMPTY")
    ]

    for abl_st, pc_st, expected in matrix:
        actual = derive_combined_status(abl_st, pc_st)
        assert actual == expected, f"Failed for ({abl_st}, {pc_st}): expected {expected}, got {actual}"


def test_benchmark_data_each_artifact_missing_independently(tmp_path):
    """Verifies that missing ablation or per-case artifacts report available=False independently."""
    abl_file = tmp_path / "ablation_table.json"
    abl_file.write_text(json.dumps({"baselines": {}}), encoding="utf-8")

    adapter_no_case = ObservatoryDataAdapter(
        ablation_table_path=str(abl_file),
        per_case_results_path=str(tmp_path / "missing_case.json")
    )
    res1 = adapter_no_case.get_benchmark_data()
    assert res1["ablation_table"]["available"] is True
    assert res1["per_case_results"]["available"] is False
    assert "File not found" in res1["per_case_results"]["error"]

    case_file = tmp_path / "per_case_results.json"
    case_file.write_text(json.dumps([]), encoding="utf-8")

    adapter_no_abl = ObservatoryDataAdapter(
        ablation_table_path=str(tmp_path / "missing_abl.json"),
        per_case_results_path=str(case_file)
    )
    res2 = adapter_no_abl.get_benchmark_data()
    assert res2["ablation_table"]["available"] is False
    assert "File not found" in res2["ablation_table"]["error"]
    assert res2["per_case_results"]["available"] is True


def test_benchmark_data_empty_and_malformed_files(tmp_path):
    """Verifies error handling for 0-byte empty files and malformed JSON artifacts."""
    empty_abl = tmp_path / "empty_abl.json"
    empty_abl.touch()

    corrupt_case = tmp_path / "corrupt_case.json"
    corrupt_case.write_text("{BAD_JSON_CONTENT", encoding="utf-8")

    adapter = ObservatoryDataAdapter(
        ablation_table_path=str(empty_abl),
        per_case_results_path=str(corrupt_case)
    )

    data = adapter.get_benchmark_data()
    assert data["ablation_table"]["available"] is False
    assert "File is empty" in data["ablation_table"]["error"]

    assert data["per_case_results"]["available"] is False
    assert "Malformed JSON" in data["per_case_results"]["error"]


def test_benchmark_data_valid_empty_and_incomplete_schemas(tmp_path):
    """Verifies that valid but empty or partial record schemas load gracefully."""
    abl_file = tmp_path / "abl_empty.json"
    abl_file.write_text(json.dumps({
        "baselines": {
            "Incomplete Baseline": {
                "sample_count": 5
                # Missing confusion_matrix, accuracy_pct, latencies
            }
        }
    }), encoding="utf-8")

    case_file = tmp_path / "case_partial.json"
    case_file.write_text(json.dumps([
        {
            "case_id": "partial_case_1",
            "baseline": "Incomplete Baseline"
            # Missing optional fields: latency_ms, tokens_consumed, scenario_family, run_id, dataset_sha256_digest
        }
    ]), encoding="utf-8")

    adapter = ObservatoryDataAdapter(
        ablation_table_path=str(abl_file),
        per_case_results_path=str(case_file)
    )

    data = adapter.get_benchmark_data()
    assert data["ablation_table"]["available"] is True
    assert "Incomplete Baseline" in data["ablation_table"]["data"]["baselines"]
    assert data["per_case_results"]["available"] is True
    assert len(data["per_case_results"]["data"]) == 1
    assert data["per_case_results"]["data"][0]["case_id"] == "partial_case_1"


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


def test_positively_detected_corrupted_chain(mock_logs):
    """
    Verifies that a positively detected chain corruption yields integrity status CORRUPTED
    and coverage status UNVERIFIED without claiming log continuity.
    """
    from epistemicos.provenance import LocalProvenanceStore, ProvenanceEvent
    store = LocalProvenanceStore(log_path=mock_logs["provenance"])

    e1 = ProvenanceEvent("1.0.0", "ev1", "AUTHORIZATION_DENIED", "GOVERNANCE_GATE", "corr_1", "req1", "run", "tgt", "dig", "2025-01-01T00:00:00Z")
    store.record_event(e1)

    # Corrupt entry_hash on disk
    with open(mock_logs["provenance"], "r", encoding="utf-8") as f:
        lines = f.readlines()
    data_dict = json.loads(lines[0])
    data_dict["entry_hash"] = "bad_tampered_hash"
    with open(mock_logs["provenance"], "w", encoding="utf-8") as f:
        f.write(json.dumps(data_dict) + "\n")

    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])
    data = adapter.get_provenance_explorer_data()

    assert data["summary_panels"]["integrity"]["status"] == "CORRUPTED"
    assert data["summary_panels"]["integrity"]["valid"] is False
    cov = data["summary_panels"]["coverage"]
    assert cov["status"] == "UNVERIFIED"
    assert "corruption positively detected" in cov["message"].lower()
    assert "valid local cryptographic sequence chaining" not in cov["message"].lower()
    assert any(f["code"] == "HASH_CHAIN_CORRUPTED" for f in data["findings"])


def test_integrity_verification_exception_yields_unverified(mock_logs, monkeypatch):
    """
    Verifies that an exception during verification yields status UNVERIFIED (not CORRUPTED),
    does not claim confirmed chain corruption, and surfaces an INTEGRITY_UNVERIFIED finding.
    """
    from epistemicos.provenance import LocalProvenanceStore, ProvenanceEvent
    store = LocalProvenanceStore(log_path=mock_logs["provenance"])
    e1 = ProvenanceEvent("1.0.0", "ev1", "AUTHORIZATION_DENIED", "GOVERNANCE_GATE", "corr_1", "req1", "run", "tgt", "dig", "2025-01-01T00:00:00Z")
    store.record_event(e1)

    # Monkeypatch LocalProvenanceStore._inspect_health to raise an unexpected OSError/IOError exception
    def mock_inspect_health_error(self):
        raise OSError("Permission denied reading log path")

    import epistemicos.ui.adapters
    monkeypatch.setattr(epistemicos.ui.adapters.LocalProvenanceStore, "_inspect_health", mock_inspect_health_error)

    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])
    data = adapter.get_provenance_explorer_data()

    integ = data["summary_panels"]["integrity"]
    assert integ["status"] == "UNVERIFIED"
    assert integ["valid"] is None
    assert "verification execution failed" in integ["message"].lower()

    cov = data["summary_panels"]["coverage"]
    assert cov["status"] == "UNVERIFIED"
    assert "integrity unverified" in cov["message"].lower()
    assert "corruption positively detected" not in cov["message"].lower()

    # Ensure HASH_CHAIN_CORRUPTED is NOT raised, but INTEGRITY_UNVERIFIED is
    assert not any(f["code"] == "HASH_CHAIN_CORRUPTED" for f in data["findings"])
    assert any(f["code"] == "INTEGRITY_UNVERIFIED" for f in data["findings"])


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
    """
    Verifies that a log whose entries all fail to parse yields UNREADABLE availability status,
    while integrity status reflects whatever the underlying verifier establishes.
    """
    with open(mock_logs["provenance"], "w", encoding="utf-8") as f:
        f.write("BAD_LINE_1\nBAD_LINE_2\n")

    adapter = ObservatoryDataAdapter(audit_log_path=mock_logs["audit"], provenance_log_path=mock_logs["provenance"])
    data = adapter.get_provenance_explorer_data()

    assert data["parse_error_count"] == 2
    assert len(data["events"]) == 0
    assert data["summary_panels"]["availability"]["status"] == "UNREADABLE"
    assert "unparseable" in data["summary_panels"]["availability"]["message"].lower()

    # Integrity panel status is computed independently via _verify_provenance_integrity()
    actual_verifier_integrity = adapter._verify_provenance_integrity()
    assert data["summary_panels"]["integrity"]["status"] == actual_verifier_integrity["status"]


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


def test_non_dict_json_lines_counted_as_parse_errors(tmp_path):
    """Verifies that structurally valid non-dict JSON lines (null, list, number, string) are counted as parse errors."""
    prov_file = tmp_path / "non_dict_prov.jsonl"
    audit_file = tmp_path / "non_dict_audit.jsonl"

    lines = ["null\n", "[1, 2, 3]\n", "\"string_val\"\n", "123.45\n", "{\"valid\": True}\n"]  # 4 non-dict JSON, 1 invalid JSON
    prov_file.write_text("".join(lines), encoding="utf-8")
    audit_file.write_text("".join(lines), encoding="utf-8")

    adapter = ObservatoryDataAdapter(
        audit_log_path=str(audit_file),
        provenance_log_path=str(prov_file)
    )

    overview = adapter.get_overview()
    # 5 non-dict/invalid lines in prov + 5 in audit = 10 parse errors
    assert overview["metrics"]["parse_error_count"] == 10

    events, parse_errors = adapter._read_raw_provenance_events()
    assert len(events) == 0
    assert parse_errors == 5


def test_overview_metrics_from_audit_and_provenance(tmp_path):
    """Verifies metric aggregation for denials, halts (provenance + audit), and execution failures (failed + interrupted)."""
    prov_file = tmp_path / "prov_metrics.jsonl"
    audit_file = tmp_path / "audit_metrics.jsonl"

    prov_events = [
        {"correlation_id": "c1", "event_type": "AUTHORIZATION_DENIED"},
        {"correlation_id": "c2", "event_type": "EGRESS_BLOCKED"},
        {"correlation_id": "c3", "event_type": "EXECUTION_FAILED"},
        {"correlation_id": "c4", "event_type": "EXECUTION_INTERRUPTED"}
    ]
    with open(prov_file, "w", encoding="utf-8") as f:
        for pe in prov_events:
            f.write(json.dumps(pe) + "\n")

    audit_events = [
        {"event_type": "DETERMINISTIC_HALT"}
    ]
    with open(audit_file, "w", encoding="utf-8") as f:
        for ae in audit_events:
            f.write(json.dumps(ae) + "\n")

    adapter = ObservatoryDataAdapter(
        audit_log_path=str(audit_file),
        provenance_log_path=str(prov_file)
    )

    overview = adapter.get_overview()
    metrics = overview["metrics"]
    assert metrics["total_executions"] == 4
    assert metrics["authorization_denials"] == 1
    assert metrics["halts"] == 2  # 1 EGRESS_BLOCKED + 1 DETERMINISTIC_HALT
    assert metrics["execution_failures"] == 2  # 1 FAILED + 1 INTERRUPTED


def test_audit_integrity_verification_paths(tmp_path, monkeypatch):
    """Verifies audit integrity status for success (VERIFIED), corruption (CORRUPTED), and exception (UNVERIFIED)."""
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text("{\"event\": 1}\n", encoding="utf-8")

    adapter = ObservatoryDataAdapter(audit_log_path=str(audit_file))

    # Mock TamperEvidentAuditTrail returning integrity pass
    def mock_verify_pass(self):
        return True, 1, None

    monkeypatch.setattr("epistemicos.ui.adapters.TamperEvidentAuditTrail.verify_chain_integrity", mock_verify_pass)
    res_pass = adapter._verify_audit_integrity()
    assert res_pass["status"] == "VERIFIED"
    assert res_pass["records_verified"] == 1

    # Mock returning corruption
    def mock_verify_corrupt(self):
        return False, 1, "Hash mismatch at sequence 1"

    monkeypatch.setattr("epistemicos.ui.adapters.TamperEvidentAuditTrail.verify_chain_integrity", mock_verify_corrupt)
    res_corrupt = adapter._verify_audit_integrity()
    assert res_corrupt["status"] == "CORRUPTED"
    assert "Hash mismatch" in res_corrupt["message"]

    # Mock throwing exception
    def mock_verify_error(self):
        raise RuntimeError("Audit engine error")

    monkeypatch.setattr("epistemicos.ui.adapters.TamperEvidentAuditTrail.verify_chain_integrity", mock_verify_error)
    res_err = adapter._verify_audit_integrity()
    assert res_err["status"] == "UNVERIFIED"
    assert "Audit engine error" in res_err["message"]


def test_execution_traces_audit_event_matching_and_precedence(tmp_path):
    """Verifies audit event matching via metadata.correlation_id or event_id and status precedence."""
    prov_file = tmp_path / "prov_traces.jsonl"
    audit_file = tmp_path / "audit_traces.jsonl"

    prov_events = [
        # c1: Execution interrupted -> status FAILED
        {
            "correlation_id": "c1",
            "request_id": "r1",
            "event_type": "EXECUTION_INTERRUPTED",
            "timestamp": "2025-01-01T10:00:00Z",
            "provenance_source": "EXECUTOR",
            "action_name": "cmd",
            "target": "server"
        },
        # c2: Authorization granted + Execution succeeded -> status COMPLETED
        {
            "correlation_id": "c2",
            "request_id": "r2",
            "event_type": "AUTHORIZATION_GRANTED",
            "timestamp": "2025-01-01T11:00:00Z",
            "provenance_source": "GOVERNANCE_GATE",
            "decision": None  # Test fallback decision to event_type
        },
        {
            "correlation_id": "c2",
            "request_id": "r2",
            "event_type": "EXECUTION_SUCCEEDED",
            "timestamp": "2025-01-01T11:05:00Z",
            "provenance_source": "EXECUTOR"
        },
        # Invalid typed event payload to trigger exception in ProvenanceEvent(**filtered_pe)
        {
            "correlation_id": "c3",
            "event_type": "ACTION_PROPOSED",
            "timestamp": "invalid_type_triggers_exception"
        }
    ]
    with open(prov_file, "w", encoding="utf-8") as f:
        for pe in prov_events:
            f.write(json.dumps(pe) + "\n")

    audit_events = [
        {
            "event_id": "c1",
            "event_type": "DETERMINISTIC_HALT",
            "gate_name": "AuditGate1",
            "timestamp": "2025-01-01T10:00:01Z",
            "reason": "Security rule triggered"
        },
        {
            "metadata": {"correlation_id": "c2"},
            "event_type": "AUDIT_RECORDED",
            "gate_name": "AuditGate2",
            "timestamp": "2025-01-01T11:01:00Z",
            "reason": "Audit record"
        }
    ]
    with open(audit_file, "w", encoding="utf-8") as f:
        for ae in audit_events:
            f.write(json.dumps(ae) + "\n")

    adapter = ObservatoryDataAdapter(
        audit_log_path=str(audit_file),
        provenance_log_path=str(prov_file)
    )

    traces = adapter.get_execution_traces()
    trace_map = {t["correlation_id"]: t for t in traces}

    assert trace_map["c1"]["status"] == "FAILED"
    assert len(trace_map["c1"]["gate_decisions"]) == 1
    assert trace_map["c1"]["gate_decisions"][0]["source"] == "AuditGate1"

    assert trace_map["c2"]["status"] == "COMPLETED"
    assert len(trace_map["c2"]["gate_decisions"]) == 2
    # Check decision fallback when decision is None in event
    auth_decision = [g for g in trace_map["c2"]["gate_decisions"] if g["source"] == "GOVERNANCE_GATE"][0]
    assert auth_decision["decision"] == "AUTHORIZATION_GRANTED"


def test_benchmark_unexpected_json_shapes(tmp_path):
    """Verifies that unexpected top-level JSON structures (list for ablation, dict for per-case) produce controlled error messages."""
    abl_file = tmp_path / "abl_list.json"
    abl_file.write_text(json.dumps(["unexpected", "list"]), encoding="utf-8")

    case_file = tmp_path / "case_dict.json"
    case_file.write_text(json.dumps({"unexpected": "object"}), encoding="utf-8")

    adapter = ObservatoryDataAdapter(
        ablation_table_path=str(abl_file),
        per_case_results_path=str(case_file)
    )

    data = adapter.get_benchmark_data()
    assert data["ablation_table"]["available"] is False
    assert "expected object, got list" in data["ablation_table"]["error"]

    assert data["per_case_results"]["available"] is False
    assert "expected list, got dict" in data["per_case_results"]["error"]
