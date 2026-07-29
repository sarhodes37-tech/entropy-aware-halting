import torch
import torch.nn.functional as F
import torch.distributions as dist
from transformers import AutoModelForCausalLM, AutoTokenizer
from utils import get_model_and_tokenizer

model, tokenizer, device = get_model_and_tokenizer()

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
    messages = [
        {"role": "system", "content": "You are an expert Python coder."},
        {"role": "user", "content": prompt}
    ]
    prompt_formatted = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt_formatted, return_tensors="pt").to(device)
    prompt_length = inputs.input_ids.shape[1]

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            return_dict_in_generate=True,
            output_scores=True,
            do_sample=False,
            repetition_penalty=1.0
        )

    gen_tokens = outputs.sequences[0][prompt_length:]
    logits_per_step = outputs.scores

    trace_steps = []
    log2 = torch.log(torch.tensor(2.0, device=device))

    for idx, (token_id, logits) in enumerate(zip(gen_tokens, logits_per_step)):
        # Calculate Shannon Entropy using torch.distributions.Categorical
        entropy_bits = (dist.Categorical(logits=logits[0]).entropy() / log2).item()

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
