# epistemicos/__init__.py

import sys

# Runtime security-floor enforcement:
# Python versions below 3.11.4 lack critical security updates and standard library DoS mitigations (e.g., CVE-2023-24329).
# A minimum runtime of Python 3.11.4 is strictly required.
MIN_SUPPORTED_PYTHON_VERSION = (3, 11, 4)
if sys.version_info < MIN_SUPPORTED_PYTHON_VERSION:
    curr_major = sys.version_info[0]
    curr_minor = sys.version_info[1]
    curr_micro = sys.version_info[2] if len(sys.version_info) > 2 else 0
    raise RuntimeError(
        f"Unsupported Python runtime: EpistemicOS requires Python {MIN_SUPPORTED_PYTHON_VERSION[0]}.{MIN_SUPPORTED_PYTHON_VERSION[1]}.{MIN_SUPPORTED_PYTHON_VERSION[2]}+ "
        f"(current interpreter is Python {curr_major}.{curr_minor}.{curr_micro}). "
        f"Python runtimes below 3.11.4 contain unpatched standard-library security exposures. "
        f"Please upgrade to a supported Python runtime."
    )

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
    trust_remote_code: bool = False,
    revision: Optional[str] = "main",
) -> Tuple[Any, Any, str]:
    """
    Lazily import and delegate to epistemicos.utils.get_model_and_tokenizer.

    Defaults to trust_remote_code=False for security. Explicit opt-in is required
    for custom remote code models. For security-sensitive deployments, revision pinning
    using immutable commit SHAs (e.g. revision="a1b2c3d4...") is strongly recommended.
    """
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

# Expose Shower Curtain subsystem
from epistemicos.shower_curtain import (
    ShowerCurtainEngine,
    ShowerCurtainGate,
    ShowerCurtainOpenAIAdapter,
    SensitiveDataDetector,
    PrivacyPolicy,
    LocalMappingVault
)

# Expose Action Policy & Egress Subsystems
from epistemicos.containment import (
    ContainmentGuard,
    ContainmentReceipt,
    ContainmentViolationType,
    EgressPolicy,
    EgressTransportBroker,
    ControlledEgressTransport,
    normalize_destination_host
)

from epistemicos.action_policy import (
    ActionCategory,
    ActionRegistry,
    RegisteredActionDefinition,
    SideEffectPolicyEngine,
    TypedHumanApprovalRecord,
    ActionRequest,
    ActionPolicy,
    PolicyDecision as ActionPolicyDecision,
)

# Expose Execution Provenance subsystem
from epistemicos.provenance import (
    ExecutionContext,
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource,
    ProvenanceStore,
    LocalProvenanceStore,
    TrustedExecutionBoundary,
    ProvenanceReconciler,
    ReconciliationReport
)

# Expose Semantic Uncertainty subsystem
from epistemicos.semantic_uncertainty import (
    SemanticUncertaintyEstimator,
    SemanticUncertaintyResult,
    SemanticUncertaintyStatus,
    SemanticResolver,
    ExactAndNormalizedResolver,
    Candidate,
    ClusterInfo
)

__all__.extend([
    "ShowerCurtainEngine",
    "ShowerCurtainGate",
    "ShowerCurtainOpenAIAdapter",
    "SensitiveDataDetector",
    "PrivacyPolicy",
    "LocalMappingVault",
    "ExecutionContext",
    "ProvenanceEvent",
    "ProvenanceEventType",
    "ProvenanceSource",
    "ProvenanceStore",
    "LocalProvenanceStore",
    "TrustedExecutionBoundary",
    "ProvenanceReconciler",
    "ReconciliationReport",
    "SemanticUncertaintyEstimator",
    "SemanticUncertaintyResult",
    "SemanticUncertaintyStatus",
    "SemanticResolver",
    "ExactAndNormalizedResolver",
    "Candidate",
    "ClusterInfo",
    "ContainmentGuard",
    "ContainmentReceipt",
    "ContainmentViolationType",
    "EgressPolicy",
    "EgressTransportBroker",
    "ControlledEgressTransport",
    "normalize_destination_host",
    "ActionCategory",
    "ActionRegistry",
    "RegisteredActionDefinition",
    "SideEffectPolicyEngine",
    "TypedHumanApprovalRecord",
    "ActionRequest",
    "ActionPolicy",
    "ActionPolicyDecision",
])
