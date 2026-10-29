"""
Unit test suite for epistemicos.utils module.
Validates device auto-detection and helper configuration.
"""

import pytest
from unittest.mock import MagicMock, patch
from epistemicos.utils import extract_metadata, get_optimal_device, normalize_policy_name


def test_extract_metadata_none_payload():
    """Validates extract_metadata handles None payload gracefully."""
    assert extract_metadata(None) == {}


def test_extract_metadata_missing_key():
    """Validates extract_metadata returns empty dict when 'metadata' key is absent."""
    payload = {"data": "test_value"}
    assert extract_metadata(payload) == {}


def test_extract_metadata_valid_dict():
    """Validates extract_metadata extracts valid metadata dictionary."""
    payload = {"metadata": {"source": "unit_test", "id": 123}}
    assert extract_metadata(payload) == {"source": "unit_test", "id": 123}


def test_extract_metadata_non_dict_value():
    """Validates extract_metadata handles non-dict metadata value gracefully."""
    payload = {"metadata": "invalid_metadata"}
    assert extract_metadata(payload) == {}


@pytest.mark.parametrize(
    "input_name, expected_output",
    [
        ("Read Policy", "read_policy"),
        ("  WRITE_POLICY  ", "write_policy"),
        ("Admin Policy v1", "admin_policy_v1"),
        ("", ""),
        (None, ""),
        ("  ", ""),
        ("Already_Normalized", "already_normalized"),
        ("lowercase", "lowercase"),
        ("  Multiple   Spaces  Policy ", "multiple___spaces__policy"),
    ],
)
def test_normalize_policy_name(input_name, expected_output):
    """Validates normalize_policy_name handles string normalization and empty/None edge cases."""
    assert normalize_policy_name(input_name) == expected_output


def test_get_optimal_device_fallback():
    """Validates device selection hierarchy."""
    device = get_optimal_device()
    assert device in ("cuda", "mps", "cpu")




def test_get_model_and_tokenizer_mocked():
    """Validates model loader parameters and evaluation mode setting."""
    pytest.importorskip("transformers")
    from epistemicos.utils import get_model_and_tokenizer

    with patch("transformers.AutoTokenizer.from_pretrained") as mock_tokenizer, \
         patch("transformers.AutoModelForCausalLM.from_pretrained") as mock_model:
        fake_tokenizer = MagicMock()
        fake_tokenizer.pad_token = None
        fake_tokenizer.eos_token = "<|endoftext|>"
        mock_tokenizer.return_value = fake_tokenizer

        fake_model = MagicMock()
        # Ensure .to(device) returns the original mock instance
        fake_model.to.return_value = fake_model
        mock_model.return_value = fake_model

        model, tokenizer, device = get_model_and_tokenizer(
            model_name="mock/test-model",
            device="cpu"
        )

        assert device == "cpu"
        assert tokenizer.pad_token == "<|endoftext|>"

        # Now this will correctly register the call
        fake_model.eval.assert_called_once()
