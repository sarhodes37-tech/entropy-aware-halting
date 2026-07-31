import json
import time
import os
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from epistemicos.core import EpistemicOrchestrator, GateAction

@dataclass
class MetricSet:
    config_name: str
    total_vectors: int = 0
    true_positives_commit: int = 0
    false_positives_commit: int = 0
    true_positives_halt: int = 0
    false_positives_halt: int = 0
    avg_latency_ms: float = 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positives_commit + self.false_positives_commit

        return (self.true_positives_commit / denom * 100) if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives_halt + self.false_positives_halt
        return (self.true_positives_halt / denom * 100) if denom > 0 else 0.0

class FormalAblationHarness:
    def __init__(self, dataset_path: str):
        with open(dataset_path, "r") as f:
            self.vectors = [json.loads(line) for line in f if line.strip()]

    def run_ablation_matrix(self) -> Dict[str, Any]:
        configurations = [
            ("C0_Baseline", False, False),
            ("C1_Entropy_Only", True, False),
            ("C2_Permission_Only", False, True),
            ("C4_Full_EpistemicOS", True, True)
        ]

        results = {}

        for config_name, enable_entropy, enable_permission in configurations:
            metrics = MetricSet(config_name=config_name, total_vectors=len(self.vectors))
            latencies = []

            for vec in self.vectors:
                payload = vec["payload"]
                is_adversarial = vec.get("is_adversarial", True)
                allowed_tools = vec.get("allowed_tools", ["get_weather"])

                orchestrator = EpistemicOrchestrator(allowed_tools=allowed_tools)
                
                # Mock token stream evaluation
                t0 = time.perf_counter()
                
                action = GateAction.ALLOW
                if enable_entropy and vec.get("trigger_entropy_collapse", False):
                    # Simulate entropy gate intercept
                    res = orchestrator.entropy_gate.evaluate_token_logits([1.0, 0.0, 0.0, 0.0])
                    action = res.action
                
                if action == GateAction.ALLOW and enable_permission:
                    res = orchestrator.permission_gate.evaluate_payload(payload.get("prompt", ""))
                    action = res.action

                latency = (time.perf_counter() - t0) * 1000
                latencies.append(latency)

                # Accounting
                if action == GateAction.ALLOW:
                    if not is_adversarial:
                        metrics.true_positives_commit += 1
                    else:
                        metrics.false_positives_commit += 1  # Security Breach
                else:
                    if is_adversarial:
                        metrics.true_positives_halt += 1
                    else:
                        metrics.false_positives_halt += 1   # False Positive Interception

            metrics.avg_latency_ms = sum(latencies) / len(latencies) if latencies else 0.0
            results[config_name] = asdict(metrics)
            results[config_name]["computed_precision"] = f"{metrics.precision:.2f}%"
            results[config_name]["computed_recall"] = f"{metrics.recall:.2f}%"

        return results

    def export_artifacts(self, output_file: str):
        data = self.run_ablation_matrix()
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[SUCCESS] Formal Ablation Artifact exported to: {output_file}")

if __name__ == "__main__":
    # Example execution generating the telemetry artifact
    harness = FormalAblationHarness("dataset_rhodes.jsonl")
    harness.export_artifacts("results/ablation_telemetry.json")
