"""
Unit tests for EpistemicOrchestrator per-trajectory scheduler serialization
and concurrency invariants.
"""

import math
import threading
import concurrent.futures
import pytest
from epistemicos.core import EpistemicOrchestrator
from epistemicos.scheduler import EntropyAwareScheduler


def test_duplicate_scheduler_allocation():
    """
    Test A: Duplicate scheduler allocation.
    Forces two threads to reach the scheduler-creation decision for the same
    previously unseen trajectory before allowing either thread to proceed.
    Verifies that the implementation registers exactly one scheduler instance,
    records both steps sequentially with sequential step indices, and accumulates costs correctly.
    """
    orchestrator = EpistemicOrchestrator()
    trajectory_id = "test_dup_traj"

    # Barrier to force both threads into the scheduler lookup before either assigns
    lookup_barrier = threading.Barrier(2)

    original_process_step = orchestrator.process_step

    # Controlled process_step wrapper to force interleaving
    def hooked_process_step(probabilities, cost, state, trajectory_id=None):
        traj_key = trajectory_id or (state if isinstance(state, str) else None)
        # Force both threads into the lookup decision before acquiring registry lock / creating scheduler
        if traj_key == "test_dup_traj" and traj_key not in orchestrator._schedulers:
            lookup_barrier.wait(timeout=2.0)
        return original_process_step(probabilities, cost, state, trajectory_id=trajectory_id)

    results = [None, None]
    exceptions = []

    def worker(idx, probs, cost, state):
        try:
            res = hooked_process_step(probs, cost, state, trajectory_id=trajectory_id)
            results[idx] = res
        except Exception as e:
            exceptions.append(e)

    t1 = threading.Thread(target=worker, args=(0, [0.5, 0.5], 1.5, "state_1"))
    t2 = threading.Thread(target=worker, args=(1, [0.4, 0.6], 2.5, "state_2"))

    t1.start()
    t2.start()
    t1.join(timeout=3.0)
    t2.join(timeout=3.0)

    assert not exceptions, f"Exceptions occurred during execution: {exceptions}"
    assert results[0] is not None and results[1] is not None

    # Verify registry invariants
    assert len(orchestrator._schedulers) == 1
    assert trajectory_id in orchestrator._schedulers
    sched = orchestrator._schedulers[trajectory_id]

    # Verify history and cost accumulation
    assert len(sched.history) == 2
    assert sched.history[0].step_index == 0
    assert sched.history[1].step_index == 1
    assert math.isclose(sched.total_cost, 4.0)

    # Verify sequential equivalence
    ref_orchestrator = EpistemicOrchestrator()
    ref_res1 = ref_orchestrator.process_step([0.5, 0.5], 1.5, "state_1", trajectory_id="ref_traj")
    ref_res2 = ref_orchestrator.process_step([0.4, 0.6], 2.5, "state_2", trajectory_id="ref_traj")
    ref_sched = ref_orchestrator._schedulers["ref_traj"]

    assert len(ref_sched.history) == len(sched.history)
    assert ref_sched.total_cost == sched.total_cost


def test_concurrent_mutation_of_existing_scheduler():
    """
    Test B: Concurrent mutation of an existing scheduler.
    Prepopulates a trajectory's scheduler, then uses controlled hooks to make two
    threads contend for step() on that same trajectory.
    Verifies that state transitions execute serially and preserve accounting invariants.
    """
    orchestrator = EpistemicOrchestrator()
    trajectory_id = "test_mut_traj"

    # Prepopulate initial step
    orchestrator.process_step([0.5, 0.5], cost=1.0, state="init_state", trajectory_id=trajectory_id)
    sched = orchestrator._schedulers[trajectory_id]
    assert len(sched.history) == 1

    start_barrier = threading.Barrier(2)
    exceptions = []

    def worker(probs, cost, state):
        try:
            start_barrier.wait(timeout=2.0)
            orchestrator.process_step(probs, cost, state, trajectory_id=trajectory_id)
        except Exception as e:
            exceptions.append(e)

    t1 = threading.Thread(target=worker, args=([0.6, 0.4], 2.0, "state_A"))
    t2 = threading.Thread(target=worker, args=([0.3, 0.7], 3.0, "state_B"))

    t1.start()
    t2.start()
    t1.join(timeout=3.0)
    t2.join(timeout=3.0)

    assert not exceptions, f"Exceptions during concurrent mutation: {exceptions}"

    # Invariants verification
    assert len(sched.history) == 3
    step_indices = [h.step_index for h in sched.history]
    assert step_indices == [0, 1, 2]
    assert math.isclose(sched.total_cost, 6.0)  # 1.0 + 2.0 + 3.0
    assert len(sched.entropy_history) == 3
    assert len(sched.utility_history) == 3


def test_different_trajectory_independence():
    """
    Test C: Different-trajectory independence.
    Verifies that concurrent operations for two different trajectory IDs
    maintain separate scheduler instances and histories, and that a blocked
    operation on one trajectory does not block progress on another trajectory.
    """
    orchestrator = EpistemicOrchestrator()

    traj_a = "trajectory_A"
    traj_b = "trajectory_B"

    # Pre-register traj_a lock to simulate a hold on traj_a
    orchestrator.process_step([0.5, 0.5], 1.0, "state_a0", trajectory_id=traj_a)
    lock_a = orchestrator._trajectory_locks[traj_a]

    b_completed = threading.Event()
    a_acquired = threading.Event()

    def worker_a():
        with lock_a:
            a_acquired.set()
            # Simulate long-running step on trajectory A
            threading.Event().wait(timeout=0.2)

    def worker_b():
        # Wait until worker_a holds lock_a
        a_acquired.wait(timeout=2.0)
        # Should complete immediately without waiting for lock_a
        res_b = orchestrator.process_step([0.5, 0.5], 1.0, "state_b0", trajectory_id=traj_b)
        if res_b:
            b_completed.set()

    t_a = threading.Thread(target=worker_a)
    t_b = threading.Thread(target=worker_b)

    t_a.start()
    t_b.start()

    # Worker B must complete within 0.15s, while Worker A holds lock_a for 0.2s
    completed_in_time = b_completed.wait(timeout=0.15)

    t_a.join(timeout=3.0)
    t_b.join(timeout=3.0)

    assert completed_in_time, "Trajectory B was blocked by Trajectory A's lock!"

    # Verify independence of instances and histories
    sched_a = orchestrator._schedulers[traj_a]
    sched_b = orchestrator._schedulers[traj_b]

    assert id(sched_a) != id(sched_b)
    assert len(sched_a.history) == 1
    assert len(sched_b.history) == 1
