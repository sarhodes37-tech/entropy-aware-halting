"""
Ablation Benchmark Suite: Measures Commit Precision, Rollback Recall, False Rollback Rate,
and Execution Latency across gate combinations.
"""

import time
import json
import statistics
from pathlib import Path
from typing import List, Dict, Any

from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate, TriangulationGate
from benchmarks.run_full_benchmark import ComprehensiveBenchmarkRunner


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
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    dataset.append(json.loads(line))
        return dataset

    def _build_orchestrator(self, config: List[str]) -> EpistemicOrchestrator:
        allowed_tools = [
            "get_weather", "read", "query", "update_db", 
            "write_db", "api_call", "issue_binder", "rescind_binder",
            "reroute_freight", "network_ping"
        ]
        engine = EpistemicOrchestrator(audit_log_path="logs/audit.jsonl")
        gates = []
        if "permission" in config:
            gates.append(PermissionGate(allowed_actions=allowed_tools))
        if "entropy" in config:
            gates.append(EntropyGate(z_threshold=1.5, window_size=10))
        if "triangulation" in config:
            gates.append(TriangulationGate())
        engine.gates = gates
        return engine

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
                context = task.get("context", {})

                res = engine.process_submission(raw_payload=payload, context=context)

                exec_time_ms = (time.perf_counter_ns() - start_time) / 1_000_000.0
                latencies.append(exec_time_ms)

                actual_status = "COMMITTED" if res.get("status") == "ALLOWED" else "ROLLED_BACK"
                expected = task.get("expected_action", "ALLOW")

                if expected in ["HALT", "DETERMINISTIC_HALT", "ROLLBACK"]:
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
    dataset_path = Path(__file__).parent / "data" / "eval_set.jsonl"
    bench = EpistemicBench(str(dataset_path))
    results = bench.run_ablation_study()
    if results:
        assert "Full EpistemicOS" in results


def test_full_benchmark_runner():
    """PyTest entry point verifying full benchmark runner script and N=100 evaluation outputs."""
    runner = ComprehensiveBenchmarkRunner()
    results = runner.run_benchmark()
    assert "baselines" in results
    assert "eval_sample_count" in results
    assert results["eval_sample_count"] == 100
    assert "Ungated Generation" in results["baselines"]
    assert "Active Execution-Gated Recovery" in results["baselines"]
    assert "threshold_ablations" in results
    assert "paired_mcnemar_comparisons" in results

    # Verify per-case results artifact
    per_case_path = Path("results/per_case_results.json")
    assert per_case_path.exists()
    with open(per_case_path, "r", encoding="utf-8") as f:
        case_records = json.load(f)
    assert len(case_records) == 600  # 100 cases * 6 baselines

    # Verify unique IDs in eval_set
    dataset = runner.load_dataset(runner.eval_dataset_path)
    assert len(dataset) == 100
    unique_ids = {item["id"] for item in dataset}
    assert len(unique_ids) == 100
