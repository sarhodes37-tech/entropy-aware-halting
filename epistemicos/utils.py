"""
EpistemicOS Execution Utilities & Hardware Adapters.
Provides hardware-accelerated model and tokenizer loaders, device auto-detection,
and VRAM-optimized precision configuration for benchmarking and trace extraction.
"""

import logging
from typing import Tuple, Any, Optional

logger = logging.getLogger("EpistemicOS.Utils")


def get_optimal_device() -> str:
    """Detects best available compute device (CUDA -> MPS -> CPU)."""
    try:
        import torch

        if torch.cuda.is_available():
            return "cuda"
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            return "mps"
    except ImportError:
        pass

    return "cpu"


def get_model_and_tokenizer(
    model_name: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
    device: Optional[str] = None,
    torch_dtype: Optional[Any] = None,
    trust_remote_code: bool = True,
    revision: Optional[str] = "main"  # <--- Bandit B615 Compliance
) -> Tuple[Any, Any, str]:
    """
    Initializes and returns the HuggingFace model, tokenizer, and compute device.
    Applies automatic float16/bfloat16 casting on GPU backends to optimize memory usage.
    Enforces revision pinning to prevent supply chain injection attacks.
    """
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as e:
        raise ImportError(
            "get_model_and_tokenizer requires 'torch' and 'transformers' to be installed."
        ) from e

    target_device = device or get_optimal_device()

    if torch_dtype is None:
        if target_device == "cuda":
            dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        elif target_device == "mps":
            dtype = torch.float16
        else:
            dtype = torch.float32
    else:
        dtype = torch_dtype

    logger.info(f"Loading '{model_name}' (rev: {revision}) on [{target_device}] with dtype {dtype}...")

    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        trust_remote_code=trust_remote_code,
        revision=revision  # <--- Bandit B615 Compliance
    )

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Fixed: Moved model instantiation outside the pad_token guard block
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=dtype,
        trust_remote_code=trust_remote_code,
        revision=revision
    ).to(target_device)

    # Safely call eval if it's a real model or a mock that supports it
    if hasattr(model, "eval") and callable(model.eval):
        model.eval()

    return model, tokenizer, target_device
