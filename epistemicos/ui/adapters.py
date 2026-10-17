"""
EpistemicOS Control Plane Observatory - Data Adapters.

Extracts, aggregates, and validates data from EpistemicOS audit trails,
provenance stores, reconciliation reports, and benchmark result artifacts.
Enforces fail-closed error handling and explicit unavailable/unverified states.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from epistemicos.audit import TamperEvidentAuditTrail
from epistemicos.provenance import (
    LocalProvenanceStore,
    ProvenanceEvent,
    ProvenanceReconciler,
    ReconciliationReport
)


class ObservatoryDataAdapter:
    """
    Adapter reading raw EpistemicOS audit logs, provenance stores,
    and benchmark result JSON files to produce structured dashboard views.
    """

    def __init__(
        self,
        audit_log_path: str = "logs/epistemic_audit.jsonl",
        provenance_log_path: str = "logs/provenance_audit.jsonl",
        ablation_table_path: str = "results/ablation_table.json",
        per_case_results_path: str = "results/per_case_results.json"
    ):
        self.audit_log_path = Path(audit_log_path)
        self.provenance_log_path = Path(provenance_log_path)
        self.ablation_table_path = Path(ablation_table_path)
        self.per_case_results_path = Path(per_case_results_path)

    # -------------------------------------------------------------------------
    # Overview View Adapter
    # -------------------------------------------------------------------------
    def get_overview(self) -> Dict[str, Any]:
        """
        Derives overview metrics from actual audit and provenance stores.
        Uses explicit unavailable/unverified states when logs do not exist or are empty.
        """
        audit_integrity = self._verify_audit_integrity()
        provenance_integrity = self._verify_provenance_integrity()

        provenance_events, parse_errors = self._read_raw_provenance_events()
        audit_events, audit_parse_errors = self._read_raw_audit_events()

        # Metric derivations
        correlations = set()
        denials = 0
        halts = 0
        failures = 0

        for pe in provenance_events:
            corr = pe.get("correlation_id")
            if corr:
                correlations.add(corr)

            event_type = pe.get("event_type")
            if event_type == "AUTHORIZATION_DENIED":
                denials += 1
            elif event_type == "EGRESS_BLOCKED":
                halts += 1
            elif event_type in ("EXECUTION_FAILED", "EXECUTION_INTERRUPTED"):
                failures += 1

        for ae in audit_events:
            event_type = ae.get("event_type")
            if event_type == "DETERMINISTIC_HALT":
                halts += 1

        has_provenance_data = self.provenance_log_path.exists() and self.provenance_log_path.stat().st_size > 0
        has_audit_data = self.audit_log_path.exists() and self.audit_log_path.stat().st_size > 0

        return {
            "metrics": {
                "total_executions": len(correlations) if has_provenance_data else None,
                "authorization_denials": denials if has_provenance_data else None,
                "halts": halts if (has_provenance_data or has_audit_data) else None,
                "execution_failures": failures if has_provenance_data else None,
                "parse_error_count": parse_errors + audit_parse_errors
            },
            "status_flags": {
                "provenance_data_available": has_provenance_data,
                "audit_data_available": has_audit_data
            },
            "audit_integrity": audit_integrity,
            "provenance_integrity": provenance_integrity
        }

    # -------------------------------------------------------------------------
    # Execution Trace Explorer Adapter
    # -------------------------------------------------------------------------
    def get_execution_traces(self) -> List[Dict[str, Any]]:
        """
        Aggregates provenance and audit events by correlation_id into execution traces.
        """
        provenance_events, _ = self._read_raw_provenance_events()
        audit_events, _ = self._read_raw_audit_events()

        # Group provenance events by correlation_id
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for pe in provenance_events:
            corr = pe.get("correlation_id") or "UNKNOWN_CORRELATION"
            grouped.setdefault(corr, []).append(pe)

        reconciler = ProvenanceReconciler()
        traces = []

        for corr_id, pe_list in grouped.items():
            # Convert raw dicts to ProvenanceEvent dataclasses for reconciler
            typed_events: List[ProvenanceEvent] = []
            for pe in pe_list:
                try:
                    filtered_pe = {
                        k: v for k, v in pe.items()
                        if k in ProvenanceEvent.__dataclass_fields__
                    }
                    typed_events.append(ProvenanceEvent(**filtered_pe))
                except Exception:
                    continue

            # Reconcile correlation
            reconciliation = reconciler.reconcile_correlation(corr_id, typed_events)

            # Determine lifecycle execution status
            status = self._determine_execution_status(pe_list)

            # Collect gate decisions and evidence
            gate_decisions = []
            auth_evidence = None
            action_name = "UNKNOWN"
            target = "UNKNOWN"
            request_id = "UNKNOWN"
            start_time = None
            end_time = None

            for pe in pe_list:
                if pe.get("action_name") and pe.get("action_name") != "UNKNOWN":
                    action_name = pe.get("action_name")
                if pe.get("target") and pe.get("target") != "UNKNOWN":
                    target = pe.get("target")
                if pe.get("request_id") and pe.get("request_id") != "UNKNOWN":
                    request_id = pe.get("request_id")

                ts = pe.get("timestamp")
                if ts:
                    if start_time is None or ts < start_time:
                        start_time = ts
                    if end_time is None or ts > end_time:
                        end_time = ts

                if pe.get("event_type") in ("AUTHORIZATION_GRANTED", "AUTHORIZATION_DENIED"):
                    gate_decisions.append({
                        "source": pe.get("provenance_source"),
                        "decision": pe.get("decision") or pe.get("event_type"),
                        "timestamp": pe.get("timestamp"),
                        "policy_version": pe.get("policy_version")
                    })
                    auth_evidence = {
                        "authorization_token_id": pe.get("authorization_token_id"),
                        "canonical_request_digest": pe.get("canonical_request_digest"),
                        "policy_version": pe.get("policy_version"),
                        "granted": pe.get("event_type") == "AUTHORIZATION_GRANTED"
                    }

            # Collect matching audit events for this correlation / request if available
            for ae in audit_events:
                meta = ae.get("metadata") or {}
                if meta.get("correlation_id") == corr_id or ae.get("event_id") == corr_id:
                    gate_decisions.append({
                        "source": ae.get("gate_name"),
                        "decision": ae.get("event_type"),
                        "timestamp": ae.get("timestamp"),
                        "reason": ae.get("reason")
                    })

            traces.append({
                "correlation_id": corr_id,
                "request_id": request_id,
                "action_name": action_name,
                "target": target,
                "status": status,
                "start_time": start_time or "UNKNOWN",
                "end_time": end_time or "UNKNOWN",
                "event_count": len(pe_list),
                "gate_decisions": gate_decisions,
                "authorization_evidence": auth_evidence or {
                    "authorization_token_id": None,
                    "canonical_request_digest": None,
                    "policy_version": None,
                    "granted": None
                },
                "reconciliation": reconciliation.to_dict(),
                "provenance_events": pe_list
            })

        # Sort by correlation_id descending or timestamp
        traces.sort(key=lambda t: t.get("start_time", ""), reverse=True)
        return traces

    def get_execution_trace_by_id(self, correlation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single execution trace by correlation_id."""
        traces = self.get_execution_traces()
        for trace in traces:
            if trace.get("correlation_id") == correlation_id:
                return trace
        return None

    # -------------------------------------------------------------------------
    # Provenance Explorer Adapter
    # -------------------------------------------------------------------------
    def get_provenance_explorer_data(self) -> Dict[str, Any]:
        """
        Returns all provenance events, hash chain integrity validation status,
        and explicit disclaimers.
        """
        events, parse_errors = self._read_raw_provenance_events()
        integrity = self._verify_provenance_integrity()

        return {
            "disclaimer": (
                "DISCLAIMER: Valid cryptographic hash chain integrity verifies local "
                "append-only sequence chaining, but does NOT prove external source authenticity, "
                "non-repudiation, or trace completeness."
            ),
            "integrity": integrity,
            "parse_error_count": parse_errors,
            "events": events
        }

    # -------------------------------------------------------------------------
    # Benchmark Workbench Adapter
    # -------------------------------------------------------------------------
    def get_benchmark_data(self) -> Dict[str, Any]:
        """
        Loads measured benchmark results from results/ablation_table.json
        and results/per_case_results.json.
        """
        ablation_table = None
        ablation_error = None
        per_case_results = None
        per_case_error = None

        if self.ablation_table_path.exists():
            try:
                with open(self.ablation_table_path, "r", encoding="utf-8") as f:
                    ablation_table = json.load(f)
            except Exception as e:
                ablation_error = f"Malformed JSON in ablation table: {str(e)}"
        else:
            ablation_error = "File not found: results/ablation_table.json"

        if self.per_case_results_path.exists():
            try:
                with open(self.per_case_results_path, "r", encoding="utf-8") as f:
                    per_case_results = json.load(f)
            except Exception as e:
                per_case_error = f"Malformed JSON in per-case results: {str(e)}"
        else:
            per_case_error = "File not found: results/per_case_results.json"

        return {
            "ablation_table": {
                "available": ablation_table is not None,
                "data": ablation_table,
                "error": ablation_error
            },
            "per_case_results": {
                "available": per_case_results is not None,
                "data": per_case_results,
                "error": per_case_error
            }
        }

    # -------------------------------------------------------------------------
    # Private Helper Methods
    # -------------------------------------------------------------------------
    def _read_raw_provenance_events(self) -> Tuple[List[Dict[str, Any]], int]:
        events = []
        parse_errors = 0
        if not self.provenance_log_path.exists():
            return events, parse_errors

        with open(self.provenance_log_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    data = json.loads(line_str)
                    events.append(data)
                except Exception:
                    parse_errors += 1
        return events, parse_errors

    def _read_raw_audit_events(self) -> Tuple[List[Dict[str, Any]], int]:
        events = []
        parse_errors = 0
        if not self.audit_log_path.exists():
            return events, parse_errors

        with open(self.audit_log_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    data = json.loads(line_str)
                    events.append(data)
                except Exception:
                    parse_errors += 1
        return events, parse_errors

    def _verify_audit_integrity(self) -> Dict[str, Any]:
        if not self.audit_log_path.exists():
            return {
                "status": "UNAVAILABLE",
                "valid": None,
                "records_verified": 0,
                "message": "Audit log file does not exist"
            }
        try:
            trail = TamperEvidentAuditTrail(log_file_path=str(self.audit_log_path))
            valid, count, err = trail.verify_chain_integrity()
            return {
                "status": "VERIFIED" if valid else "CORRUPTED",
                "valid": valid,
                "records_verified": count,
                "message": err or "Integrity verified successfully"
            }
        except Exception as e:
            return {
                "status": "CORRUPTED",
                "valid": False,
                "records_verified": 0,
                "message": f"Verification error: {str(e)}"
            }

    def _verify_provenance_integrity(self) -> Dict[str, Any]:
        if not self.provenance_log_path.exists():
            return {
                "status": "UNAVAILABLE",
                "valid": None,
                "records_verified": 0,
                "message": "Provenance log file does not exist"
            }
        try:
            store = LocalProvenanceStore(log_path=str(self.provenance_log_path))
            healthy, last_hash, count, _ = store._inspect_health()
            return {
                "status": "VERIFIED" if healthy else "CORRUPTED",
                "valid": healthy,
                "last_hash": last_hash,
                "records_verified": count,
                "message": "Integrity verified successfully" if healthy else "Chain corruption detected"
            }
        except Exception as e:
            return {
                "status": "CORRUPTED",
                "valid": False,
                "records_verified": 0,
                "message": f"Verification error: {str(e)}"
            }

    def _determine_execution_status(self, events: List[Dict[str, Any]]) -> str:
        """
        Determines execution outcome state:
        DENIED, HALTED, COMPLETED, FAILED, or OUTCOME_UNKNOWN.
        """
        event_types = [e.get("event_type") for e in events]

        if "AUTHORIZATION_DENIED" in event_types:
            return "DENIED"
        if "EGRESS_BLOCKED" in event_types:
            return "HALTED"
        if "EXECUTION_FAILED" in event_types or "EXECUTION_INTERRUPTED" in event_types:
            return "FAILED"
        if "EXECUTION_SUCCEEDED" in event_types:
            return "COMPLETED"

        return "OUTCOME_UNKNOWN"
