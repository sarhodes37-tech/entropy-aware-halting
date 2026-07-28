import torch
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer
from scheduler import EntropyAwareScheduler

device = "cuda" if torch.cuda.is_available() else "cpu"
model_name = "gpt2" # Using gpt2 as a lightweight model
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name).to(device)

def evaluate_eac_robust(prompt, max_new_tokens=256):
    inputs = tokenizer(prompt, return_tensors="pt").to(device)
    prompt_length = inputs.input_ids.shape[1]

    scheduler = EntropyAwareScheduler()

    generated_tokens = []
    current_input_ids = inputs.input_ids
    past_key_values = None

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

        current_input_ids = next_token_id.unsqueeze(0)

        if result.halt:
            print(f"Halting at step {i} due to {result.directive}. Best step was {result.best_step} with state {result.best_state}.")
            break

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

    return trace_steps

if __name__ == "__main__":
    prompt = "Solve for x: 3x + 5 = 20. Show step-by-step calculations. Put your final answer inside \\boxed{}."
    evaluate_eac_robust(prompt)
