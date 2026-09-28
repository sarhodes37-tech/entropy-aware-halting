"""
Separate test file to cleanly test ImportError for torch.
Prevents module reload side effects from breaking the main transformers tests.
"""

import sys
import importlib
import builtins
from unittest.mock import patch
import epistemicos.utils

def test_get_optimal_device_import_error_coverage():
    """Validates fallback to cpu when torch is not installed and records coverage correctly."""
    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "torch":
            raise ImportError("Mocked ImportError for torch")
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        if "torch" in sys.modules:
            del sys.modules["torch"]

        # Reloading epistemicos.utils while the mock is active
        # ensures the `import torch` inside get_optimal_device()
        # triggers our mocked ImportError and coverage records the pass block.
        importlib.reload(epistemicos.utils)

        device = epistemicos.utils.get_optimal_device()
        assert device == "cpu"

    # Restore utils module so other tests see it clean
    importlib.reload(epistemicos.utils)
