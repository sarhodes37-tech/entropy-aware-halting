# epistemicos/__init__.py

from epistemicos.core import EpistemicOrchestrator
from epistemicos.scheduler import EntropyAwareScheduler, StepMetrics, DecisionResult
from epistemicos.models import CanonicalProblemRepresentation, BeliefObject
from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel
from epistemicos.vector_hygiene import VectorHygieneManager

# Optional: Expose the utils safely since they are lazy-loaded
from epistemicos.utils import get_optimal_device, get_model_and_tokenizer

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
