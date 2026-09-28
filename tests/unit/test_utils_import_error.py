"""
Separate test file to cleanly test ImportError for torch.
Prevents module reload side effects from breaking the main transformers tests.
"""

from unittest.mock import patch
import epistemicos.utils

def test_get_optimal_device_import_error_coverage():
    """Validates fallback to cpu when torch is not installed and records coverage correctly."""
    # Hide torch from sys.modules to simulate an environment without torch installed
    with patch.dict("sys.modules", {"torch": None}):
        device = epistemicos.utils.get_optimal_device()
        assert device == "cpu"
