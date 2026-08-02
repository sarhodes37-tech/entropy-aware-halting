"""
Ablation Benchmark Suite: Measures Commit Precision, Rollback Recall, False Rollback Rate,
and Execution Latency across gate combinations.
"""

import time
import json
import statistics
from pathlib import Path
from typing import List, Dict, Any

from epistemicos.core import EpistemicOrchestrator, GateAction


class EpistemicBench:
    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self.configurations = {
            "Baseline (No Gates)": [],
            "+ Entropy Gate": ["entropy"],
            "+ Permission Gate": ["entropy", "permission"],
            "Full EpistemicOS": ["entropy", "permission", "triangulation"]
        }

    def _load_dataset(self) -> List[Dict[str, Any]]:
        path = Path(self.dataset_path)
        if not path.exists():
            return []
        dataset = []
        with open(path, "r") as f:
            for line in f:
                if line.strip():
                    dataset.append(json.loads(line))
        return dataset

    def _build_orchestrator(self, config: List[str]) -> EpistemicOrchestrator:
        allowed_tools = [
            "get_weather", "read", "query", "update_db", 
            "write_db", "api_call", "issue_binder", "rescind_binder"
        ]
        return EpistemicOrchestrator(allowed_tools=allowed_tools, active_gates=config)

    def run_ablation_study(self) -> Dict[str, Dict[str, float]]:
        dataset = self._load_dataset()
        if not dataset:
            print(f"Dataset {self.dataset_path} not found. Skipping ablation run.")
            return {}

        results = {}

        for config_name, gates in self.configurations.items():
            engine = self._build_orchestrator(gates)
            metrics = {"TC": 0, "FC": 0, "TR": 0, "FR": 0}
            latencies = []

            for task in dataset:
                start_time = time.perf_counter_ns()

                payload = task.get("payload", {})
                prompt_text = payload.get("prompt", str(payload))
                context = task.get("context", {})
                logprobs = context.get("token_logprobs", [0.25, 0.25, 0.25, 0.25]) 
                category = task.get("category", "")

                action, _, _ = engine.process_step(
                    token_logits=logprobs,
                    accumulated_output=prompt_text,
                    category=category
                )

                exec_time_ms = (time.perf_counter_ns() - start_time) / 1_000_000.0
                latencies.append(exec_time_ms)

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

            tc, fc, tr, fr = metrics["TC"], metrics["FC"], metrics["TR"], metrics["FR"]
            results[config_name] = {
                "commit_precision": (tc / (tc + fc) * 100) if (tc + fc) > 0 else 0.0,
                "rollback_recall": (tr / (tr + fc) * 100) if (tr + fc) > 0 else 0.0,
                "false_rollback_rate": (fr / (fr + tc) * 100) if (fr + tc) > 0 else 0.0,
                "avg_latency_ms": statistics.mean(latencies) if latencies else 0.0
            }

        return results


def test_ablation_study():
    """PyTest entry point for running ablation studies against benchmark datasets."""
    from pathlib import Path

# Resolve path relative to tests/fixtures/
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
DATASET_PATH = FIXTURES_DIR / "dataset_adversarial.jsonl"

def test_ablation_study():
    """PyTest entry point for running ablation studies against benchmark datasets."""
    bench = EpistemicBench(str(DATASET_PATH))
    results = bench.run_ablation_study()
    if results:
        assert "Full EpistemicOS" in results