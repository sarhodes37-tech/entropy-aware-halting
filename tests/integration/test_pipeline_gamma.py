"""
Integration test suite for EpistemicOS Pipeline & EntropyAwareScheduler.
Validates economic halting boundaries across parametric Gamma (Γ) thresholds.
"""

import math
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Generator
import pytest

from audit import TamperEvidentAuditTrail, AuditLogLevel


# =====================================================================
# Mock Pipeline & Scheduler Infrastructure
# =====================================================================

class MockEntropyAwareScheduler:
    """
    Simulates the EntropyAwareScheduler window evaluation over logit/probability traces.
    """
    def __init__(self, gamma: float = 0.80, window: int = 2):
        self.gamma = gamma
        self.window = window

    def calculate_entropy(self, probs: List[float]) -> float:
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def evaluate_step(self, probability_history: List[List[float]]) -> Dict[str, Any]:
        """
        Evaluates cumulative entropy shock over the configured sliding window.
        """
        if len(probability_history) < self.window:
            return {"should_halt": False, "total_drop": 0.0, "current_step": len(probability_history) - 1}

        entropies = [self.calculate_entropy(p) for p in probability_history]
        
        # Calculate deltas (positive value = entropy/uncertainty spike)
        entropy_gains = [0.0] + [entropies[i] - entropies[i - 1] for i in range(1, len(entropies))]

        current_step = len(probability_history) - 1
        window_start = max(0, current_step - self.window + 1)
        recent_gains = entropy_gains[window_start : current_step + 1]
        cumulative_shock = sum(g for g in recent_gains if g > 0)

        should_halt = cumulative_shock > self.gamma

        return {
            "should_halt": should_halt,
            "total_drop": round(cumulative_shock, 4),
            "current_step": current_step,
            "entropy_bits": round(entropies[-1], 4),
        }


class MockPipeline:
    """
    Pipeline runtime execution harness wiring logit processing, scheduler halting,
    and tamper-evident audit trail recording.
    """
    def __init__(self, scheduler: MockEntropyAwareScheduler, audit_trail: TamperEvidentAuditTrail):
        self.scheduler = scheduler
        self.audit_trail = audit_trail

    def execute_trace(self, trace: List[List[float]], model_id: str = "mock-llm-v1") -> Dict[str, Any]:
        history: List[List[float]] = []
        halted_at_step = None
        
        for step, probs in enumerate(trace):
            history.append(probs)
            eval_result = self.scheduler.evaluate_step(history)

            if eval_result["should_halt"]:
                halted_at_step = step
                self.audit_trail.record_event(
                    event_type=AuditLogLevel.HALT,
                    gate_name="EntropyAwareScheduler",
                    reason=f"Cumulative entropy shock ({eval_result['total_drop']} bits) exceeded gamma threshold ({self.scheduler.gamma})",
                    model_id=model_id,
                    execution_latency_ms=1.24,
                    payload_snippet=f"Step {step} distribution: {probs}",
                    metadata={"step": step, "gamma": self.scheduler.gamma, "drop_bits": eval_result["total_drop"]}
                )
                break
            else:
                self.audit_trail.record_event(
                    event_type=AuditLogLevel.INFO,
                    gate_name="EntropyAwareScheduler",
                    reason="Step passed entropy evaluation",
                    model_id=model_id,
                    execution_latency_ms=0.85,
                    payload_snippet=f"Step {step} distribution: {probs}",
                    metadata={"step": step, "entropy_bits": eval_result["entropy_bits"]}
                )

        return {
            "completed": halted_at_step is None,
            "halted_step": halted_at_step,
            "total_steps_executed": len(history),
        }


# =====================================================================
# Fixtures & Test Data
# =====================================================================

# Synthetic trace triggering an entropy shock (+0.9165 bits) at Step 2
TRACE_NEGATIVE_YIELD = [
    [0.34, 0.33, 0.33],  # Step 0: H = 1.5848 (Baseline)
    [0.90, 0.05, 0.05],  # Step 1: H = 0.5690 (Confidence peak)
    [0.50, 0.30, 0.20],  # Step 2: H = 1.4855 (Entropy Shock: +0.9165 bits)
    [0.20, 0.40, 0.40],  # Step 3: H = 1.5219 (Drift)
    [0.34, 0.33, 0.33],  # Step 4
    [0.34, 0.33, 0.33],  # Step 5
]


@pytest.fixture
def temp_audit_file() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_audit.jsonl"


# =====================================================================
# Integration Test Cases
# =====================================================================

@pytest.mark.parametrize(
    "gamma, expected_halt_step, should_halt",
    [
        (0.40, 2, True),   # Over-sensitive threshold
        (0.60, 2, True),   # Moderate threshold
        (0.80, 2, True),   # Optimal production boundary (Γ*)
        (1.00, None, False), # Under-sensitive threshold (misses shock)
        (1.20, None, False), # Under-sensitive threshold
    ],
)
def test_pipeline_gamma_sweep_boundaries(
    gamma: float, expected_halt_step: int, should_halt: bool, temp_audit_file: Path
):
    """
    Validates that Pipeline execution accurately halts at Step 2 across varying Gamma settings.
    """
    audit_logger = TamperEvidentAuditTrail(log_file_path=str(temp_audit_file))
    scheduler = MockEntropyAwareScheduler(gamma=gamma, window=2)
    pipeline = MockPipeline(scheduler=scheduler, audit_trail=audit_logger)

    result = pipeline.execute_trace(TRACE_NEGATIVE_YIELD)

    assert (result["halted_step"] is not None) == should_halt
    assert result["halted_step"] == expected_halt_step

    # Verify audit trail recorded events and maintained hash integrity
    is_valid, record_count, error_msg = audit_logger.verify_chain_integrity()
    assert is_valid, f"Audit chain corrupted: {error_msg}"
    assert record_count == result["total_steps_executed"]


def test_optimal_gamma_audit_payload(temp_audit_file: Path):
    """
    Verifies that a gamma-triggered halt at optimal threshold (Γ = 0.80) writes a 
    DETERMINISTIC_HALT entry into the audit trail.
    """
    audit_logger = TamperEvidentAuditTrail(log_file_path=str(temp_audit_file))
    scheduler = MockEntropyAwareScheduler(gamma=0.80, window=2)
    pipeline = MockPipeline(scheduler=scheduler, audit_trail=audit_logger)

    result = pipeline.execute_trace(TRACE_NEGATIVE_YIELD)

    assert result["halted_step"] == 2

    # Verify audit file contents
    is_valid, count, _ = audit_logger.verify_chain_integrity()
    assert is_valid
    assert count == 3  # Steps 0, 1 (INFO) + Step 2 (HALT)

    with open(temp_audit_file, "r", encoding="utf-8") as f:
        lines = [f.readline() for _ in range(3)]
        final_entry = json.loads(lines[-1])

    assert final_entry["event_type"] == AuditLogLevel.HALT.value
    assert final_entry["gate_name"] == "EntropyAwareScheduler"
    assert final_entry["metadata"]["gamma"] == 0.80
    assert final_entry["metadata"]["drop_bits"] == 0.9165
