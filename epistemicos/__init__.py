# epistemicos/__init__.py

from importlib import import_module
from typing import Any, Optional, Tuple

from epistemicos.core import EpistemicOrchestrator
from epistemicos.scheduler import EntropyAwareScheduler, StepMetrics, DecisionResult
from epistemicos.models import CanonicalProblemRepresentation, BeliefObject
from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel
from epistemicos.vector_hygiene import VectorHygieneManager

# Utilities: expose via lazy wrappers to avoid heavy imports at package import time
def get_optimal_device() -> str:
    """Lazily import and delegate to epistemicos.utils.get_optimal_device."""
    return import_module("epistemicos.utils").get_optimal_device()


def get_model_and_tokenizer(
    model_name: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
    device: Optional[str] = None,
    torch_dtype: Optional[Any] = None,
    trust_remote_code: bool = True,
    revision: Optional[str] = "main",
) -> Tuple[Any, Any, str]:
    """Lazily import and delegate to epistemicos.utils.get_model_and_tokenizer."""
    return import_module("epistemicos.utils").get_model_and_tokenizer(
        model_name=model_name,
        device=device,
        torch_dtype=torch_dtype,
        trust_remote_code=trust_remote_code,
        revision=revision,
    )


__all__ = [
    # Core Orchestration
    "EpistemicOrchestrator",
    "EntropyAwareScheduler",
    "StepMetrics",
    "DecisionResult",
    
    # Domain Models
    "CanonicalProblemRepresentation",
    "BeliefObject",
    
    # Security & Accountability
    "TamperEvidentAuditTrail",
    "AuditLogLevel",
    "VectorHygieneManager",
    
    # Utilities
    "get_optimal_device",
    "get_model_and_tokenizer",
]
