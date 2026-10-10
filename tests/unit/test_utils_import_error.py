"""
Separate test file to cleanly test ImportError for torch.
Prevents module reload side effects from breaking the main transformers tests.
"""

from unittest.mock import patch
import epistemicos.utils

import pytest

def test_get_optimal_device_import_error_coverage():
    """Validates fallback to cpu when torch is not installed and records coverage correctly."""
    # Hide torch from sys.modules to simulate an environment without torch installed
    with patch.dict("sys.modules", {"torch": None}):
        device = epistemicos.utils.get_optimal_device()
        assert device == "cpu"

def test_get_model_and_tokenizer_import_error_coverage():
    """Validates ImportError is raised when transformers is missing."""
    with patch.dict("sys.modules", {"transformers": None}):
        with pytest.raises(ImportError, match="get_model_and_tokenizer requires 'torch' and 'transformers' to be installed."):
            epistemicos.utils.get_model_and_tokenizer()
