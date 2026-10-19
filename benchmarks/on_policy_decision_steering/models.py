"""Data models and enums for On-Policy Decision Steering benchmark harness."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Condition(str, Enum):
    """Experimental conditions A through F as defined in v3.0.0 specification."""
    A_BASELINE = "A_BASELINE"
    B_CLAIM_ONLY = "B_CLAIM_ONLY"
    C_DIRECT_EVIDENCE = "C_DIRECT_EVIDENCE"
    D_RETRIEVAL_MEDIATED = "D_RETRIEVAL_MEDIATED"
    E_SOURCE_ASSESSMENT = "E_SOURCE_ASSESSMENT"
    F_EXPERIMENTAL_GATE = "F_EXPERIMENTAL_GATE"


@dataclass
class Candidate:
    """Representation of a candidate option in a scenario."""
    candidate_id: str
    title: str
    description: str
    baseline_rank: int
    is_target_option: bool = False
    is_adversarial_option: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "title": self.title,
            "description": self.description,
            "baseline_rank": self.baseline_rank,
            "is_target_option": self.is_target_option,
            "is_adversarial_option": self.is_adversarial_option,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Candidate":
        return cls(
            candidate_id=data["candidate_id"],
            title=data["title"],
            description=data.get("description", ""),
            baseline_rank=data["baseline_rank"],
            is_target_option=data.get("is_target_option", False),
            is_adversarial_option=data.get("is_adversarial_option", False),
            metadata=data.get("metadata", {}),
        )


@dataclass
class RetrievalResult:
    """Representation of mock retrieval search output."""
    query: str
    returned_fixture_ids: List[str]
    raw_passages: List[str]
    origin_domains: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "returned_fixture_ids": self.returned_fixture_ids,
            "raw_passages": self.raw_passages,
            "origin_domains": self.origin_domains,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RetrievalResult":
        return cls(
            query=data["query"],
            returned_fixture_ids=data.get("returned_fixture_ids", []),
            raw_passages=data.get("raw_passages", []),
            origin_domains=data.get("origin_domains", []),
        )


@dataclass
class Scenario:
    """Representation of an evaluation scenario."""
    scenario_id: str
    description: str
    candidates: List[Candidate]
    unfamiliar_term: str
    query: str
    attack_variant: str  # e.g., "direct_steering", "retrieval_steering", "invalid_inference", "benign_control"
    partition: str  # "dev" or "held_out"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "description": self.description,
            "candidates": [c.to_dict() for c in self.candidates],
            "unfamiliar_term": self.unfamiliar_term,
            "query": self.query,
            "attack_variant": self.attack_variant,
            "partition": self.partition,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Scenario":
        return cls(
            scenario_id=data["scenario_id"],
            description=data.get("description", ""),
            candidates=[Candidate.from_dict(c) for c in data.get("candidates", [])],
            unfamiliar_term=data.get("unfamiliar_term", ""),
            query=data.get("query", ""),
            attack_variant=data.get("attack_variant", ""),
            partition=data.get("partition", "dev"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class TrialResult:
    """Representation of a single scenario-condition execution trial result."""
    trial_id: str
    scenario_id: str
    condition: Condition
    output_ranking: List[str]
    retrieval_calls: List[RetrievalResult]
    is_valid: bool
    invalid_reason: Optional[str]
    applied_intervention: str
    execution_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trial_id": self.trial_id,
            "scenario_id": self.scenario_id,
            "condition": self.condition.value,
            "output_ranking": self.output_ranking,
            "retrieval_calls": [r.to_dict() for r in self.retrieval_calls],
            "is_valid": self.is_valid,
            "invalid_reason": self.invalid_reason,
            "applied_intervention": self.applied_intervention,
            "execution_time_ms": self.execution_time_ms,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrialResult":
        return cls(
            trial_id=data["trial_id"],
            scenario_id=data["scenario_id"],
            condition=Condition(data["condition"]),
            output_ranking=data.get("output_ranking", []),
            retrieval_calls=[RetrievalResult.from_dict(r) for r in data.get("retrieval_calls", [])],
            is_valid=data.get("is_valid", True),
            invalid_reason=data.get("invalid_reason"),
            applied_intervention=data.get("applied_intervention", ""),
            execution_time_ms=data.get("execution_time_ms", 0.0),
        )


@dataclass
class DatasetManifest:
    """Manifest verifying cryptographic digest and partition metadata over dataset files."""
    dataset_version: str
    dataset_path: str
    sha256_digest: str
    total_scenarios: int
    dev_scenarios: int
    held_out_scenarios: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_version": self.dataset_version,
            "dataset_path": self.dataset_path,
            "sha256_digest": self.sha256_digest,
            "total_scenarios": self.total_scenarios,
            "dev_scenarios": self.dev_scenarios,
            "held_out_scenarios": self.held_out_scenarios,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DatasetManifest":
        return cls(
            dataset_version=data["dataset_version"],
            dataset_path=data["dataset_path"],
            sha256_digest=data["sha256_digest"],
            total_scenarios=data["total_scenarios"],
            dev_scenarios=data["dev_scenarios"],
            held_out_scenarios=data["held_out_scenarios"],
        )
