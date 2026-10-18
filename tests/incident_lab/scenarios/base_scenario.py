"""
Base interface and result model for EpistemicOS Incident Lab Scenarios.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from tests.incident_lab.fixtures.base_fixture import SecurityOutcomeStatus


@dataclass
class DimensionASecurityOutcome:
    status: SecurityOutcomeStatus
    invariant_description: str
    attempt_observed: bool = True
    authorization_decision: str = "HALTED"
    execution_boundary_decision: str = "PREVENTED"
    executor_invocation_observed: bool = False
    operation_completed: bool = False
    unauthorized_side_effects_count: int = 0
    data_disclosed_or_mutated: Any = None
    containment_recovery_outcome: str = "CONTAINED"
    provenance_evidence_integrity: str = "UNVERIFIED"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, SecurityOutcomeStatus) else str(self.status)
        return d


@dataclass
class DimensionBLegitimateTaskBehavior:
    authorized_operations_attempted: int = 0
    authorized_operations_succeeded: int = 0
    false_denials_count: int = 0
    incorrect_authorizations_count: int = 0
    unnecessary_halting_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScenarioEvaluationReport:
    scenario_id: str
    scenario_name: str
    execution_path_exercised: str
    dimension_a_security: DimensionASecurityOutcome
    dimension_b_task: DimensionBLegitimateTaskBehavior
    variants_evaluated: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    unprotected_baseline: Dict[str, Any] = field(default_factory=dict)
    architectural_gaps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "execution_path_exercised": self.execution_path_exercised,
            "dimension_a_security": self.dimension_a_security.to_dict(),
            "dimension_b_task": self.dimension_b_task.to_dict(),
            "variants_evaluated": self.variants_evaluated,
            "unprotected_baseline": self.unprotected_baseline,
            "architectural_gaps": self.architectural_gaps
        }


class IncidentScenario(ABC):
    """Abstract base class for all incident scenario evaluators."""

    @abstractmethod
    def run_evaluation(self) -> ScenarioEvaluationReport:
        pass
