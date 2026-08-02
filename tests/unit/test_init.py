"""
Unit test suite for epistemicos package initialization and lazy imports.
"""

from unittest.mock import patch
import epistemicos


@patch("epistemicos.utils.get_optimal_device")
def test_lazy_get_optimal_device(mock_get_device):
    """Validates lazy loading delegation for get_optimal_device."""
    mock_get_device.return_value = "mps"
    
    result = epistemicos.get_optimal_device()
    
    assert result == "mps"
    mock_get_device.assert_called_once()


@patch("epistemicos.utils.get_model_and_tokenizer")
def test_lazy_get_model_and_tokenizer(mock_get_model):
    """Validates lazy loading delegation for get_model_and_tokenizer with arguments."""
    mock_get_model.return_value = ("mock_model", "mock_tokenizer", "cuda")
    
    model, tokenizer, device = epistemicos.get_model_and_tokenizer(
        model_name="mock/test-model",
        device="cuda",
        torch_dtype="bfloat16",
        trust_remote_code=False,
        revision="v2.1"
    )
    
    assert model == "mock_model"
    assert tokenizer == "mock_tokenizer"
    assert device == "cuda"
    
    mock_get_model.assert_called_once_with(
        model_name="mock/test-model",
        device="cuda",
        torch_dtype="bfloat16",
        trust_remote_code=False,
        revision="v2.1"
    )
