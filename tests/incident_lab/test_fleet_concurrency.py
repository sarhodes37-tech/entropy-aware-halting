"""
Pytest Test Suite for Fleet Concurrency and Aggregate Budget Enforcement.

Executes concurrent multi-agent requests with bounded deterministic synchronization
to verify thread safety, aggregate budget containment, and cross-agent credential reuse rules.
"""

import threading
import uuid
import pytest
from concurrent.futures import ThreadPoolExecutor
from tests.incident_lab.fixtures.scenario_fixtures import FleetMultiAgentEnvironment
from epistemicos.core import EpistemicOrchestrator
from epistemicos.models import PermissionScope


def test_concurrent_fleet_aggregate_budget_containment():
    """Verify that 10 concurrent agents cannot exceed the aggregate budget limit of 3."""
    env = FleetMultiAgentEnvironment(max_aggregate_budget=3)
    barrier = threading.Barrier(10)

    allowed_results = []
    denied_results = []
    results_lock = threading.Lock()

    def agent_worker(agent_index):
        agent_id = f"ConcurrentAgent-{agent_index}"
        dest = f"http://fleet-api-{agent_index}.org/data"

        # Synchronize all threads before firing
        barrier.wait()

        allowed = env.record_agent_attempt(agent_id, dest, credential=None)
        with results_lock:
            if allowed:
                allowed_results.append(agent_id)
            else:
                denied_results.append(agent_id)

    with ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(agent_worker, range(10)))

    assert env.total_attempts == 10
    assert env.aggregate_budget_consumed == 3
    assert len(allowed_results) == 3
    assert len(denied_results) == 7


def test_concurrent_cross_agent_credential_reuse_blocking():
    """Verify that concurrent cross-agent credential reuse is detected and blocked."""
    env = FleetMultiAgentEnvironment(max_aggregate_budget=10)
    shared_credential = "SHARED-FLEET-SECRET-999"
    barrier = threading.Barrier(4)

    outcomes = []
    lock = threading.Lock()

    def agent_credential_worker(idx_agent_tuple):
        idx, agent_id = idx_agent_tuple
        dest = f"http://fleet-api-{idx}.org/resource"

        barrier.wait()

        allowed = env.record_agent_attempt(agent_id, dest, credential=shared_credential)
        with lock:
            outcomes.append((agent_id, allowed))

    agents = [f"Agent-{i}" for i in range(4)]
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(agent_credential_worker, enumerate(agents)))

    # Exactly one agent (the first to record) gets allowed for the credential, others are blocked
    allowed_count = sum(1 for _, allowed in outcomes if allowed)
    denied_count = sum(1 for _, allowed in outcomes if not allowed)

    assert allowed_count == 1
    assert denied_count == 3
    assert env.cross_agent_credential_uses == 3


def test_orchestrator_concurrent_trajectory_isolation(tmp_path):
    """Verify that EpistemicOrchestrator safely handles concurrent submissions across independent trajectories."""
    orchestrator = EpistemicOrchestrator(audit_log_path=str(tmp_path / "concurrent_audit.jsonl"))
    scope = PermissionScope(
        allowed_resources=["public_api"],
        allowed_operations=["read"],
        expires_at=0
    )

    barrier = threading.Barrier(5)
    orchestrator_statuses = []
    lock = threading.Lock()

    def submit_worker(worker_idx):
        traj_id = f"traj-concurrent-{worker_idx}-{uuid.uuid4()}"
        payload = {
            "policy_id": "POL-CONCURRENT",
            "fleet_data": {"vehicle_count": 1},
            "scope": scope.model_dump(),
            "proposed_actions": [
                {"op": "read", "node": "public_api"}
            ]
        }
        ctx = {
            "token_count": 5,
            "token_logprobs": [-0.01] * 5,
            "trusted_scope": scope,
            "proposed_actions": payload["proposed_actions"],
            "correlation_id": traj_id
        }

        barrier.wait()

        res = orchestrator.process_submission(payload, ctx, trajectory_id=traj_id)
        with lock:
            orchestrator_statuses.append(res["status"])

    with ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(submit_worker, range(5)))

    assert len(orchestrator_statuses) == 5
    assert all(st == "ALLOWED" for st in orchestrator_statuses)
