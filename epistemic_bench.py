import time
import json
import statistics
from typing import List, Dict, Any

# Migrate imports from engine/gates to the optimized core
from epistemicos.core import EpistemicOrchestrator, GateAction
from epistemicos.cpr import CanonicalProblemRepresentation

class EpistemicBench:
    def __init__(self, dataset_path: str):
        self.dataset = self._load_dataset(dataset_path)

        # Define the ablation matrix
        self.configurations = {
            "Baseline (No Gates)": [],
            "+ Entropy Gate": ["entropy"],
            "+ Permission Gate": ["entropy", "permission"],
            "Full EpistemicOS": ["entropy", "permission", "triangulation"]
        }

    def _load_dataset(self, path: str) -> List[Dict[str, Any]]:
        dataset = []
        with open(path, "r") as f:
            for line in f:
                if line.strip():
                    dataset.append(json.loads(line))
        return dataset

    def _build_orchestrator(self, config: List[str]) -> EpistemicOrchestrator:
        # The core.py EpistemicOrchestrator expects a list of allowed tools 
        allowed_tools = [
            "get_weather", "read", "query", "update_db", 
            "write_db", "api_call", "issue_binder", "rescind_binder"
        ]
        # Pass the active gate config directly so execution is short-circuited natively
        return EpistemicOrchestrator(allowed_tools=allowed_tools, active_gates=config)

    def run_ablation_study(self):
        print("Starting EpistemicBench Ablation Study...\n")

        for config_name, gates in self.configurations.items():
            print(f"--- Evaluating Configuration: {config_name} ---")
            engine = self._build_orchestrator(gates)

            metrics = {"TC": 0, "FC": 0, "TR": 0, "FR": 0}
            latencies = []

            for task in self.dataset:
                start_time = time.perf_counter_ns()

                # Map the dataset JSON schema to core.py process_step inputs
                payload = task.get("payload", {})
                prompt_text = payload.get("prompt", str(payload))
                
                context = task.get("context", {})
                # Default to neutral logprobs if missing
                logprobs = context.get("token_logprobs", [0.25, 0.25, 0.25, 0.25]) 
                category = task.get("category", "")

                # Execute the optimized pipeline natively (disabled gates are bypassed)
                action, exec_latency, reasons = engine.process_step(
                    token_logits=logprobs,
                    accumulated_output=prompt_text,
                    category=category
                )

                exec_time_ms = (time.perf_counter_ns() - start_time) / 1_000_000.0
                latencies.append(exec_time_ms)

                # Normalize GateAction enums to legacy expected strings for metrics tracking
                actual_status = "COMMITTED" if action == GateAction.ALLOW else "ROLLED_BACK"
                expected = task.get("expected_action", "ALLOW")
                
                if expected in ["HALT", "DETERMINISTIC_HALT"]:
                    expected = "ROLLBACK"
                elif expected == "ALLOW":
                    expected = "COMMIT"

                if expected == "COMMIT" and actual_status == "COMMITTED":
                    metrics["TC"] += 1
                elif expected == "ROLLBACK" and actual_status == "COMMITTED":
                    metrics["FC"] += 1
                elif expected == "ROLLBACK" and actual_status == "ROLLED_BACK":
                    metrics["TR"] += 1
                elif expected == "COMMIT" and actual_status == "ROLLED_BACK":
                    metrics["FR"] += 1

            self._print_results(metrics, latencies)

    def _print_results(self, m: Dict[str, int], latencies: List[float]):
        tc, fc, tr, fr = m["TC"], m["FC"], m["TR"], m["FR"]

        # Handle division by zero natively
        commit_precision = (tc / (tc + fc) * 100) if (tc + fc) > 0 else 0.0
        rollback_recall = (tr / (tr + fc) * 100) if (tr + fc) > 0 else 0.0
        false_rollback_rate = (fr / (fr + tc) * 100) if (fr + tc) > 0 else 0.0
        avg_latency = statistics.mean(latencies) if latencies else 0.0

        print(f"Commit Precision:      {commit_precision:.2f}%")
        print(f"Rollback Recall:       {rollback_recall:.2f}%")
        print(f"False Rollback Rate:   {false_rollback_rate:.2f}%")
        print(f"Avg Execution Latency: {avg_latency:.2f} ms")
        print("-" * 40 + "\n")

if __name__ == "__main__":
    benchmark = EpistemicBench("dataset_adversarial.jsonl")
    benchmark.run_ablation_study()
