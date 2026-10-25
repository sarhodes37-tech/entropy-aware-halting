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
