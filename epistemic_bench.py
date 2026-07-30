import time
import json
import statistics
from typing import List, Dict, Any

from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate, TriangulationGate
from epistemicos.cpr import CanonicalProblemRepresentation

class EpistemicBench:
    def __init__(self, dataset_path: str):
        self.dataset = self._load_dataset(dataset_path)
        self.priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}

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
        os = EpistemicOrchestrator(prior_probabilities=self.priors)
        if "entropy" in config:
            os.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
        if "permission" in config:
            os.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))

        # Enable CryptoGate only if triangulation is requested (for full EpistemicOS), or unconditionally
        # Wait, the prompt implies + Entropy Gate should evaluate only Entropy Gate.
        # Let's ensure the baseline really has *no* gates.
        if "triangulation" in config: # The full config adds triangulation
            from epistemicos.gates import CryptoAttestationGate
            os.register_gate("CryptoAttestationGate", CryptoAttestationGate(required_algorithm="ML-DSA", expiry_year=2030))
            os.register_gate("TriangulationGate", TriangulationGate(max_divergence_threshold=0.15))
        return os

    def run_ablation_study(self):
        print("Starting EpistemicBench Ablation Study...\n")

        for config_name, gates in self.configurations.items():
            print(f"--- Evaluating Configuration: {config_name} ---")
            engine = self._build_orchestrator(gates)

            metrics = {"TC": 0, "FC": 0, "TR": 0, "FR": 0}
            latencies = []

            for task in self.dataset:
                # Start Latency Timer
                start_time = time.perf_counter_ns()

                # Merge heterogeneous telemetry into raw payload so TriangulationGate can read it
                payload = task["payload"].copy()
                if "heterogeneous_telemetry" in task["context"]:
                    payload["heterogeneous_telemetry"] = task["context"]["heterogeneous_telemetry"]

                result = engine.process_submission(
                    raw_payload=payload,
                    likelihoods=self.priors,
                    token_logprobs=task["context"]["token_logprobs"],
                    proposed_actions=task["context"]["proposed_actions"],
                    crypto_metadata=task["context"].get("cryptography")
                )

                # Stop Latency Timer (convert ns to ms)
                exec_time_ms = (time.perf_counter_ns() - start_time) / 1_000_000.0
                latencies.append(exec_time_ms)

                actual_status = result["receipt"]["status"]
                expected = task["expected_action"]

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
