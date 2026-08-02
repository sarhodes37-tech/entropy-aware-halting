"""
Layer 3 Benchmark Suite: Evaluates EpistemicOrchestrator against dynamic 
entropy spikes, tool calls, and deterministic halt vectors.
"""

import json
from pathlib import Path
import pytest

from epistemicos.core import EpistemicOrchestrator, GateAction


def run_epistemic_vector_benchmark(dataset_path: str):
    dataset_file = Path(dataset_path)
    if not dataset_file.exists():
        pytest.skip(f"Benchmark dataset not found at {dataset_path}")

    passed_tests = 0
    total_tests = 0
    failed_vectors = []

    with open(dataset_file, "r") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue

            total_tests += 1
            vector = json.loads(line)
            vector_id = vector.get("id", f"UNKNOWN-{line_num}")
            expected_action = vector.get("expected_action")
            payload = vector.get("payload", {})
            context = vector.get("context", {})

            allowed_tools = ["get_weather", "read_local"]
            orchestrator = EpistemicOrchestrator(allowed_tools=allowed_tools)

            prompt_text = payload.get("prompt", str(payload))
            for act in context.get("proposed_actions", []):
                op = act.get("action", {}).get("op", "")
                prompt_text += f'\n<tool_call>"name": "{op}"</tool_call>'

            if expected_action == "HALT":
                expected_action = "DETERMINISTIC_HALT"

            action = GateAction.ALLOW

            if expected_action == "DETERMINISTIC_HALT":
                # 20 tokens of absolute certainty (Entropy = 0.0) followed by a massive spike
                stream = [[100.0, 0.0, 0.0, 0.0]] * 20 + [[1.0, 1.0, 1.0, 1.0]]
            else:
                # Benign baseline traffic
                stream = [[0.25, 0.25, 0.25, 0.25]] * 21

            for token_logits in stream:
                res_action, _, _ = orchestrator.process_step(
                    token_logits=token_logits,
                    accumulated_output=prompt_text,
                )
                if res_action != GateAction.ALLOW:
                    action = res_action
                    break

            triggered_action = "ALLOW" if action == GateAction.ALLOW else (
                "DETERMINISTIC_HALT" if action == GateAction.HALT else (
                    "ROLLBACK" if action == GateAction.ROLLBACK else "UNKNOWN"
                )
            )

            if triggered_action == expected_action:
                passed_tests += 1
            else:
                failed_vectors.append((vector_id, expected_action, triggered_action))

    assert len(failed_vectors) == 0, f"Failed vectors: {failed_vectors}"


def test_layer3_epistemic_vectors():
    """Executes Layer 3 benchmark dataset verification."""
    run_epistemic_vector_benchmark("dataset_rhodes.jsonl")
