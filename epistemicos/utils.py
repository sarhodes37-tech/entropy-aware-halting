"""
EpistemicOS Utilities Module.
Provides hardware-accelerated model and tokenizer loaders, device auto-detection,
and VRAM-optimized precision configuration for benchmarking and trace extraction.
"""

import logging
from typing import Tuple, Any, Optional
import torch

logger = logging.getLogger("EpistemicOS.Utils")


def get_optimal_device() -> str:
    """Detects best available compute device (CUDA -> MPS -> CPU)."""
    if torch.cuda.is_available():
        return "cuda"
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def get_model_and_tokenizer(
    model_name: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
    device: Optional[str] = None,
    torch_dtype: Optional[Any] = None,
    trust_remote_code: bool = True
) -> Tuple[Any, Any, str]:
    """
    Initializes and returns the HuggingFace model, tokenizer, and compute device.
    Applies automatic float16/bfloat16 casting on GPU backends to optimize memory usage.
    """
    from transformers import AutoModelForCausalLM, AutoTokenizer

    target_device = device or get_optimal_device()

    # Determine memory-efficient precision based on hardware
    if torch_dtype is None:
        if target_device == "cuda":
            dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        elif target_device == "mps":
            dtype = torch.float16
        else:
            dtype = torch.float32
    else:
        dtype = torch_dtype

    logger.info(f"Loading '{model_name}' on [{target_device}] with dtype {dtype}...")

    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        trust_remote_code=trust_remote_code
    )

    # Ensure pad token is defined for batch trace extraction
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=dtype,
        trust_remote_code=trust_remote_code
    ).to(target_device)

    model.eval()
    return model, tokenizer, target_device
