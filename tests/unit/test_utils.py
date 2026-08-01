"""
Unit test suite for epistemicos.utils module.
Validates device auto-detection and helper configuration.
"""

from unittest.mock import MagicMock, patch
import pytest
from epistemicos.utils import get_optimal_device, get_model_and_tokenizer


def test_get_optimal_device_fallback():
    """Validates device selection hierarchy."""
    device = get_optimal_device()
    assert device in ("cuda", "mps", "cpu")


@patch("transformers.AutoTokenizer.from_pretrained")
@patch("transformers.AutoModelForCausalLM.from_pretrained")
def test_get_model_and_tokenizer_mocked(mock_model, mock_tokenizer):
    """Validates model loader parameters and evaluation mode setting."""
    fake_tokenizer = MagicMock()
    fake_tokenizer.pad_token = None
    fake_tokenizer.eos_token = "<|endoftext|>"
    mock_tokenizer.return_value = fake_tokenizer

    fake_model = MagicMock()
    mock_model.return_value = fake_model

    model, tokenizer, device = get_model_and_tokenizer(
        model_name="mock/test-model",
        device="cpu"
    )

    assert device == "cpu"
    assert tokenizer.pad_token == "<|endoftext|>"
    fake_model.eval.assert_called_once()
