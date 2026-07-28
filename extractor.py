import torch
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer

class TraceExtractor:
    def __init__(self, model_name):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(model_name).to(self.device)

    def extract_trajectory(self, prompt, max_new_tokens=150):
        chat_prompt = f"<|system|>\nYou are a helpful assistant. Output ONLY valid JSON.</s>\n<|user|>\n{prompt}</s>\n<|assistant|>\n"
        inputs = self.tokenizer(chat_prompt, return_tensors="pt").to(self.device)
        prompt_length = inputs.input_ids.shape[1]

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                return_dict_in_generate=True,
                output_scores=True,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id
            )

        gen_tokens = outputs.sequences[0][prompt_length:]
        logits_per_step = outputs.scores

        trace_steps = []
        log2 = torch.log(torch.tensor(2.0, device=self.device))

        current_text = ""
        for idx, (token_id, logits) in enumerate(zip(gen_tokens, logits_per_step)):
            probs = F.softmax(logits[0], dim=-1)
            log_probs = F.log_softmax(logits[0], dim=-1)
            entropy_bits = -torch.sum(probs * (log_probs / log2)).item()

            token_text = self.tokenizer.decode([token_id])
            current_text += token_text

            trace_steps.append({
                "step": idx,
                "text": token_text,
                "entropy": float(entropy_bits),
                "clean_prefix": current_text
            })

        return trace_steps
