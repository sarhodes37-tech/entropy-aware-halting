import json
import datetime
import hashlib
import uuid
import torch
import torch.nn.functional as F
from scheduler import EntropyAwareScheduler
from utils import get_model_and_tokenizer
from vector_hygiene import VectorHygieneManager
from friction_window import PreExecutionFrictionGate

model, tokenizer, device = get_model_and_tokenizer()

hygiene_manager = VectorHygieneManager(db_client=None)
friction_gate = PreExecutionFrictionGate()

def evaluate_eac_robust(prompt, max_new_tokens=256):
    messages = [
        {"role": "system", "content": "You are an expert Python coder."},
        {"role": "user", "content": prompt}
    ]
    prompt_formatted = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt_formatted, return_tensors="pt").to(device)
    prompt_length = inputs.input_ids.shape[1]

    scheduler = EntropyAwareScheduler()

    generated_tokens = []
    current_input_ids = inputs.input_ids
    past_key_values = None
    trajectory_id = uuid.uuid4().hex

    print("\nExtracting logprobs and computing token entropy...")

    for i in range(max_new_tokens):
        with torch.no_grad():
            outputs = model(
                current_input_ids,
                past_key_values=past_key_values,
                use_cache=True
            )
            next_token_logits = outputs.logits[:, -1, :]
            past_key_values = outputs.past_key_values

        probs = F.softmax(next_token_logits[0], dim=-1)

        next_token_id = torch.argmax(next_token_logits, dim=-1)
        next_token_text = tokenizer.decode(next_token_id[0])

        result = scheduler.step(probabilities=probs, cost=0.03, state=next_token_text)
        generated_tokens.append(next_token_text)

        hygiene_manager.stage_vectors(trajectory_id, [next_token_id.item()])

        current_input_ids = next_token_id.unsqueeze(0)

        if result.halt:
            print(f"Halting at step {i} due to {result.directive}. Best step was {result.best_step} with state {result.best_state}.")
            if result.directive == "NEGATIVE_YIELD":
                audit_entry = {
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "prompt_hash": hashlib.sha256(prompt.encode('utf-8')).hexdigest(),
                    "active_constraint": "NEGATIVE_YIELD",
                    "entropy_at_failure": scheduler.history[-1].entropy if scheduler.history else None,
                    "rejected_trajectory": "".join(generated_tokens),
                    "status": "VETO_APPLIED - DFR ROUTED"
                }
                with open("audit_ledger.json", "a") as f:
                    f.write(json.dumps(audit_entry) + "\n")
                hygiene_manager.revoke_trajectory(trajectory_id)
            break

    if not result.halt or result.directive != "NEGATIVE_YIELD":
        hygiene_manager.commit_trajectory(trajectory_id)

    trace_steps = []
    for step_idx in range(len(scheduler.history)):
        m = scheduler.history[step_idx]
        trace_steps.append({
            "step": step_idx,
            "text": m.state,
            "entropy": m.entropy,
            "token_count": 1
        })

    print(f"Evaluating state-aware EAC on extracted trace with {len(trace_steps)} steps.")
    for step in trace_steps[:3]:
        print(step)
    if len(trace_steps) > 3:
        print("...")

    final_trace_text = "".join(generated_tokens[:result.best_step + 1])
    print("\nFinal trace text (after rollback):", final_trace_text)

    # TODO: Agent tool-calling logic will eventually interface with friction_gate.stage_action() here
    return trace_steps

if __name__ == "__main__":
    prompt = "Solve for x: 3x + 5 = 20. Show step-by-step calculations. Put your final answer inside \\boxed{}."
    evaluate_eac_robust(prompt)
