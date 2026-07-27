import torch
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer

device = "cuda" if torch.cuda.is_available() else "cpu"
model_name = "gpt2" # Using gpt2 as a lightweight model
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name).to(device)

def evaluate_eac_robust(trace_steps):
    print(f"Evaluating state-aware EAC on extracted trace with {len(trace_steps)} steps.")
    for step in trace_steps[:3]:
        print(step)
    if len(trace_steps) > 3:
        print("...")

# ==============================================================================
# 3. EXTRACTION PIPELINE
# ==============================================================================
def extract_trace_entropy_hf(prompt, max_new_tokens=256):
    inputs = tokenizer(prompt, return_tensors="pt").to(device)
    prompt_length = inputs.input_ids.shape[1]

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            return_dict_in_generate=True,
            output_scores=True,
            do_sample=False
        )

    gen_tokens = outputs.sequences[0][prompt_length:]
    logits_per_step = outputs.scores

    trace_steps = []
    log2 = torch.log(torch.tensor(2.0, device=device))

    for idx, (token_id, logits) in enumerate(zip(gen_tokens, logits_per_step)):
        probs = F.softmax(logits[0], dim=-1)
        log_probs = F.log_softmax(logits[0], dim=-1)

        # Calculate Shannon Entropy H = -sum(p * log2(p))
        entropy_bits = -torch.sum(probs * (log_probs / log2)).item()

        token_text = tokenizer.decode([token_id])
        trace_steps.append({
            "step": idx,
            "text": token_text,
            "entropy": float(entropy_bits),
            "token_count": 1
        })

    return trace_steps

# ==============================================================================
# 4. RUN EXTRACTION AND EVALUATION
# ==============================================================================
prompt = "Solve for x: 3x + 5 = 20. Show step-by-step calculations. Put your final answer inside \\boxed{} равенства. "

print("\nExtracting logprobs and computing token entropy...")
trace_steps = extract_trace_entropy_hf(prompt)

# Evaluate state-aware EAC on the extracted trace
evaluate_eac_robust(trace_steps)
