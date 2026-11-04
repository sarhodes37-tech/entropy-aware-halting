import json
from epistemicos.provenance import (
    LocalProvenanceStore,
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource,
)


def _unfiltered_get_events_for_correlation(store: LocalProvenanceStore, correlation_id: str):
    """Reference unoptimized implementation that parses every line without pre-filtering."""
    events = []
    if not store.log_path.exists():
        return events

    with open(store.log_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                if data.get("correlation_id") == correlation_id:
                    filtered_data = {
                        k: v for k, v in data.items()
                        if k in ProvenanceEvent.__dataclass_fields__
                    }
                    events.append(ProvenanceEvent(**filtered_data))
            except Exception:
                continue
    return events


def test_provenance_correlation_prefilter_equivalence(tmp_path):
    log_file = tmp_path / "test_prov.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))

    # Record multiple events across multiple correlation IDs
    for i in range(15):
        corr = f"corr-{i % 5}"
        ev = ProvenanceEvent(
            schema_version="1.0.0",
            event_id=f"evt-{i}",
            event_type=ProvenanceEventType.ACTION_PROPOSED.value,
            provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
            correlation_id=corr,
            request_id=f"req-{i}",
            action_name="test_action",
            target="test_target",
            canonical_request_digest="abc123digest",
            timestamp="2026-11-04T00:00:00Z"
        )
        store.record_event(ev)

    # Check exact equivalence across all correlation IDs
    for cid in ["corr-0", "corr-1", "corr-2", "corr-3", "corr-4", "nonexistent-corr"]:
        res_optimized = store.get_events_for_correlation(cid)
        res_reference = _unfiltered_get_events_for_correlation(store, cid)

        assert len(res_optimized) == len(res_reference)
        for opt_ev, ref_ev in zip(res_optimized, res_reference):
            assert opt_ev.event_id == ref_ev.event_id
            assert opt_ev.correlation_id == ref_ev.correlation_id
            assert opt_ev.sequence_number == ref_ev.sequence_number


def test_provenance_correlation_prefilter_edge_cases(tmp_path):
    log_file = tmp_path / "edge_cases.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))

    # Empty store
    assert store.get_events_for_correlation("any-id") == []
    assert store.get_events_for_correlation("") == []
    assert store.get_events_for_correlation(None) == []  # type: ignore

    # Substring false match protection: "corr-1" must not match "corr-10" or "pre-corr-1"
    ev1 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="evt-corr-1",
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="corr-1",
        request_id="req-1",
        action_name="test_action",
        target="test_target",
        canonical_request_digest="abc",
        timestamp="2026-11-04T00:00:00Z"
    )
    ev10 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="evt-corr-10",
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="corr-10",
        request_id="req-10",
        action_name="test_action",
        target="test_target",
        canonical_request_digest="def",
        timestamp="2026-11-04T00:00:00Z"
    )
    store.record_event(ev1)
    store.record_event(ev10)

    events_1 = store.get_events_for_correlation("corr-1")
    assert len(events_1) == 1
    assert events_1[0].event_id == "evt-corr-1"

    events_10 = store.get_events_for_correlation("corr-10")
    assert len(events_10) == 1
    assert events_10[0].event_id == "evt-corr-10"
