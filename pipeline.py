"""
EpistemicOS Production Pipeline Execution Engine.
Interfaces HuggingFace autoregressive generation with EntropyAwareScheduler, 
VectorHygieneManager, and PreExecutionFrictionGate.
"""

import json
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import torch
import torch.nn.functional as F

from scheduler import EntropyAwareScheduler
from utils import get_model_and_tokenizer
from vector_hygiene import VectorHygieneManager
from friction_window import PreExecutionFrictionGate

# Lazy-loaded global singletons
_MODEL = None
_TOKENIZER = None
_DEVICE = None


def _get_execution_context() -> Tuple[Any, Any, str]:
    """Lazy initializer for model, tokenizer, and device to prevent import side effects."""
    global _MODEL, _TOKENIZER, _DEVICE
    if _MODEL is None or _TOKENIZER is None or _DEVICE is None:
        _MODEL, _TOKENIZER, _DEVICE = get_model_and_tokenizer()
    return _MODEL, _TOKENIZER, _DEVICE


def _append_audit_ledger(audit_entry: Dict[str, Any], ledger_path: str = "audit_ledger.json") -> None:
    """Helper to append audit veto entries safely to the audit ledger JSON array."""
    ledger = []
    try:
        with open(ledger_path, "r", encoding="utf-8") as f:
            ledger = json.load(f)
            if not isinstance(ledger, list):
                ledger = []
    except (FileNotFoundError, json.JSONDecodeError):
        ledger = []

    ledger.append(audit_entry)

    with open(ledger_path, "w", encoding="utf-8") as f:
        json.dump(ledger, f, indent=2)


def evaluate_eac_robust(
    prompt: Optional[str] = None,
    max_new_tokens: int = 256,
    system_prompt: Optional[str] = None,
    chat_history: Optional[List[Dict[str, str]]] = None,
    model: Optional[Any] = None,
    tokenizer: Optional[Any] = None,
    device: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes real-time generation with information-theoretic entropy monitoring.

    Args:
        prompt: Raw user input string (used if chat_history is not supplied).
        max_new_tokens: Maximum token generation budget.
        system_prompt: System directive override.
        chat_history: Full structured chat conversation history.
        model, tokenizer, device: Optional explicit execution dependencies.

    Returns:
        Dict containing trace_steps, final_text, halt_directive, halt_step, and trajectory_id.
    """
    # 1. Resolve Model Dependencies
    if model is None or tokenizer is None or device is None:
        exec_model, exec_tokenizer, exec_device = _get_execution_context()
    else:
        exec_model, exec_tokenizer, exec_device = model, tokenizer, device

    # 2. Format Chat Messages
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    else:
        messages.append({"role": "system", "content": "You are an expert Python coder."})

    if chat_history:
        messages.extend(chat_history)
    elif prompt:
        messages.append({"role": "user", "content": prompt})
    else:
        raise ValueError("Either 'prompt' or 'chat_history' must be provided to evaluate_eac_robust.")

    prompt_formatted = exec_tokenizer.apply_chat_template(
        messages, 
        tokenize=False, 
        add_generation_prompt=True
    )
    inputs = exec_tokenizer(prompt_formatted, return_tensors="pt").to(exec_device)

    # 3. Initialize Governance Subsystems
    scheduler = EntropyAwareScheduler()
    hygiene_manager = VectorHygieneManager(db_client=None)
    friction_gate = PreExecutionFrictionGate()

    generated_tokens: List[str] = []
    current_input_ids = inputs.input_ids
    past_key_values = None
    trajectory_id = uuid.uuid4().hex

    halt_directive = "COMPLETED"
    halt_step = 0

    # 4. Autoregressive Generation & Entropy Monitoring Loop
    for i in range(max_new_tokens):
        halt_step = i
        with torch.no_grad():
            outputs = exec_model(
                current_input_ids,
                past_key_values=past_key_values,
                use_cache=True
            )
            next_token_logits = outputs.logits[:, -1, :]
            past_key_values = outputs.past_key_values

        probs = F.softmax(next_token_logits[0], dim=-1)
        next_token_id = torch.argmax(next_token_logits, dim=-1)
        next_token_text = exec_tokenizer.decode(next_token_id[0])

        # Inform scheduler of new probability distribution
        result = scheduler.step(probabilities=probs, cost=0.03, state=next_token_text)
        generated_tokens.append(next_token_text)

        # Stage vector for hygiene tracking
        hygiene_manager.stage_vectors(trajectory_id, [next_token_id.item()])
        current_input_ids = next_token_id.unsqueeze(0)

        if result.halt:
            halt_directive = result.directive
            if result.directive == "NEGATIVE_YIELD":
                # Compute prompt hash for auditability
                raw_prompt_str = prompt or str(chat_history)
                prompt_hash = hashlib.sha256(raw_prompt_str.encode("utf-8")).hexdigest()

                audit_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "prompt_hash": prompt_hash,
                    "active_constraint": "NEGATIVE_YIELD",
                    "entropy_at_failure": scheduler.history[-1].entropy if scheduler.history else None,
                    "rejected_trajectory": "".join(generated_tokens),
                    "status": "VETO_APPLIED - DFR ROUTED"
                }
                _append_audit_ledger(audit_entry)
                hygiene_manager.revoke_trajectory(trajectory_id)
            break

    # Commit trajectory if generation succeeded or halted normally (OPTIMAL_CONVERGENCE)
    if halt_directive != "NEGATIVE_YIELD":
        hygiene_manager.commit_trajectory(trajectory_id)

    # 5. Build Trace Step Metadata
    trace_steps = []
    for step_idx, m in enumerate(scheduler.history):
        trace_steps.append({
            "step": step_idx,
            "text": m.state,
            "entropy": m.entropy,
            "token_count": 1
        })

    # Rollback to optimal state if best_step recorded
    best_cutoff = getattr(result, "best_step", len(generated_tokens) - 1)
    final_trace_text = "".join(generated_tokens[:best_cutoff + 1])

    return {
        "trace_steps": trace_steps,
        "final_text": final_trace_text,
        "halt_directive": halt_directive,
        "halt_step": halt_step,
        "trajectory_id": trajectory_id
    }


if __name__ == "__main__":
    test_prompt = "Solve for x: 3x + 5 = 20. Show step-by-step calculations. Put your final answer inside \\boxed{}."
    res = evaluate_eac_robust(prompt=test_prompt)
    print("\n--- Execution Result ---")
    print(f"Halt Directive: {res['halt_directive']} at step {res['halt_step']}")
    print(f"Final Trace Text: {res['final_text']}")
