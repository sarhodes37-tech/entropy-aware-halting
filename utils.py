import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

def get_model_and_tokenizer(model_name="Qwen/Qwen2.5-Coder-1.5B-Instruct"):
    """
    Initializes and returns the model, tokenizer, and device.
    """
    device = "cuda" if torch.cuda.is_available() else "cpu"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name).to(device)

    return model, tokenizer, device
