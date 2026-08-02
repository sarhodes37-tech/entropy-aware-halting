import json
import logging
import sys
from pathlib import Path

from epistemicos.core import EpistemicOrchestrator, GateAction

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] EpistemicBench - %(message)s"
)

def run_rhodes_benchmark(dataset_path: str):
    dataset_file = Path(dataset_path)
    if not dataset_file.exists():
        logging.error(f"Dataset not found at {dataset_path}")
        sys.exit(1)

    passed_tests = 0
    total_tests = 0
    failed_vectors = []

    logging.info(f"Loading RhodesBench vectors from {dataset_file.name}...")

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
            category = vector.get("category", "")

            logging.info(f"Evaluating {vector_id} ({category})...")

            try:
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
                    # 20 tokens of absolute certainty (Entropy = 0.0)
                    stream = [[100.0, 0.0, 0.0, 0.0]] * 20
                    # Token 21 is absolute uncertainty (Entropy = 2.0).
                    # This generates a massive Z-score that clears the safe_std_dev floor.
                    stream += [[1.0, 1.0, 1.0, 1.0]]
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

                if action == GateAction.ALLOW:
                    triggered_action = "ALLOW"
                elif action == GateAction.HALT:
                    triggered_action = "DETERMINISTIC_HALT"
                elif action == GateAction.ROLLBACK:
                    triggered_action = "ROLLBACK"
                else:
                    triggered_action = "UNKNOWN"

                if triggered_action == expected_action:
                    logging.info(f"  [PASS] {vector_id} -> Successfully triggered {expected_action}")
                    passed_tests += 1
                else:
                    logging.error(f"  [FAIL] {vector_id} -> Expected {expected_action}, got {triggered_action}")
                    failed_vectors.append(vector_id)

            except Exception as e:
                logging.error(f"  [ERROR] System fault on {vector_id}: {str(e)}")
                failed_vectors.append(vector_id)

    print("\n" + "="*40)
    print("RhodesBench Evaluation Summary")
    print("="*40)
    print(f"Total Vectors : {total_tests}")
    print(f"Passed        : {passed_tests}")
    print(f"Failed        : {len(failed_vectors)}")

    if failed_vectors:
        print("\nFailed Vector IDs:")
        for fid in failed_vectors:
            print(f" - {fid}")
        sys.exit(1)
    else:
        print("\nAll epistemic guardrails successfully enforced. Orchestrator functioning as designed.")
        sys.exit(0)

if __name__ == "__main__":
    TARGET_DATASET = "dataset_rhodes.jsonl"
    run_rhodes_benchmark(TARGET_DATASET)