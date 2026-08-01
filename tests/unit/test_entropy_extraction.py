"""
Unit test suite for step-wise token entropy extraction from logit tensors.
"""

import pytest
import torch
from epistemicos.pipeline import compute_step_entropy_bits, extract_generation_entropy_trace


def test_entropy_bits_uniform_distribution():
    """
    Uniform distribution across 4 tokens must yield exactly 2.0 bits of entropy.
    H(X) = - 4 * (0.25 * log2(0.25)) = 2.0 bits
    """
    uniform_logits = torch.tensor([1.0, 1.0, 1.0, 1.0])
    entropy = compute_step_entropy_bits(uniform_logits)
    assert pytest.approx(entropy, abs=1e-4) == 2.0


def test_entropy_bits_deterministic_distribution():
    """
    Deterministic distribution (one high logit, rest negative infinity) must yield ~0.0 bits.
    """
    deterministic_logits = torch.tensor([100.0, -100.0, -100.0, -100.0])
    entropy = compute_step_entropy_bits(deterministic_logits)
    assert pytest.approx(entropy, abs=1e-4) == 0.0


def test_generation_trace_formatting():
    """Validates step-wise generation trace formatting with mock token decoding."""
    class MockTokenizer:
        def decode(self, token_ids):
            return f"token_{token_ids[0]}"

    mock_scores = (
        torch.tensor([[1.0, 1.0, 1.0, 1.0]]),  # Uniform -> 2.0 bits
        torch.tensor([[100.0, -100.0, -100.0, -100.0]])  # Deterministic -> 0.0 bits
    )
    mock_gen_tokens = torch.tensor([101, 102])

    trace = extract_generation_entropy_trace(mock_scores, mock_gen_tokens, MockTokenizer())

    assert len(trace) == 2
    assert trace[0]["step"] == 0
    assert trace[0]["token_text"] == "token_101"
    assert pytest.approx(trace[0]["entropy_bits"], abs=1e-4) == 2.0

    assert trace[1]["step"] == 1
    assert trace[1]["token_text"] == "token_102"
    assert pytest.approx(trace[1]["entropy_bits"], abs=1e-4) == 0.0


@pytest.mark.slow
def test_real_transformer_entropy_integration():
    """Integration test using a lightweight transformer (runs only if explicitly requested)."""
    transformers = pytest.importorskip("transformers")
    from transformers import AutoModelForCausalLM, AutoTokenizer

    model_name = "sshleifer/tiny-gpt2"  # Ultra-lightweight model for fast integration testing
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name)

    inputs = tokenizer("Hello", return_tensors="pt")
    outputs = model.generate(
        **inputs,
        max_new_tokens=3,
        return_dict_in_generate=True,
        output_scores=True
    )

    gen_tokens = outputs.sequences[0][inputs.input_ids.shape[1]:]
    trace = extract_generation_entropy_trace(outputs.scores, gen_tokens, tokenizer)

    assert len(trace) == 3
    assert all("entropy_bits" in step for step in trace)
