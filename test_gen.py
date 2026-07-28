import torch
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer

device = "cuda" if torch.cuda.is_available() else "cpu"
model_name = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name).to(device)

prompt = "Extract the company 'Acme Corp' and revenue '500' into a JSON object with keys 'company' and 'revenue'. Output ONLY valid JSON and nothing else."
chat_prompt = f"<|system|>\nYou are a helpful assistant. Output ONLY valid JSON.</s>\n<|user|>\n{prompt}</s>\n<|assistant|>\n"
inputs = tokenizer(chat_prompt, return_tensors="pt").to(device)
prompt_length = inputs.input_ids.shape[1]

with torch.no_grad():
    outputs = model.generate(
        **inputs,
        max_new_tokens=50,
        return_dict_in_generate=True,
        output_scores=True,
        do_sample=False,
        pad_token_id=tokenizer.eos_token_id
    )

gen_tokens = outputs.sequences[0][prompt_length:]
logits_per_step = outputs.scores

log2 = torch.log(torch.tensor(2.0, device=device))
for idx, (token_id, logits) in enumerate(zip(gen_tokens, logits_per_step)):
    probs = F.softmax(logits[0], dim=-1)
    log_probs = F.log_softmax(logits[0], dim=-1)
    entropy_bits = -torch.sum(probs * (log_probs / log2)).item()
    token_text = tokenizer.decode([token_id])
    print(f"Step {idx:02d} | Token: {repr(token_text)} | Entropy: {entropy_bits:.4f}")
