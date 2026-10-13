"""
Pytest configuration for EpistemicOS.
"""

import os

def pytest_sessionstart(session):
    """Ensure output directories exist before tests run."""
    os.makedirs("results", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
