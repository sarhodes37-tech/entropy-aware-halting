"""
EpistemicOS Unified Domain Models & Mathematical Kernels.

Consolidates the Canonical Problem Representation (CPR), Zero-Trust 
Permission Scopes, Bayesian Belief Objects, Popperian falsification 
contracts, and Token Surprisal kernels into a single source of truth.
"""

import math
import os
import sys
import time
from enum import Enum
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field, model_validator


# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================

_DEFAULT_QUARANTINE_SUBNETS = [
    s.strip() for s in os.getenv("EPISTEMICOS_QUARANTINE_SUBNETS", "").split(",") if s.strip()
]
DEFAULT_REDACTION_KEYS = frozenset({"api_key", "token", "password", "secret"})


# ==========================================
# MEMORY PROFILING UTILITIES
# ==========================================

SCALAR_TYPES = frozenset({str, int, float, bool, type(None), bytes, bytearray})


def _estimate_payload_size(obj: Any, seen: Optional[Set[int]] = None) -> int:
    """
    Estimates memory footprint of nested structures without triggering
    expensive string allocation overhead using a unified iterative DFS stack.
    Bypasses recursive call overhead for dictionaries and iterables.
    """
    if seen is None:
        seen = set()

    # Fast path for root scalar objects
    if type(obj) in SCALAR_TYPES:
        return sys.getsizeof(obj)

    # Micro-optimization: localize lookup attributes
    getsizeof = sys.getsizeof
    scalar_types = SCALAR_TYPES
    add_seen = seen.add

    total_size = 0
    stack = [obj]
    pop = stack.pop
    append = stack.append

    while stack:
        curr = pop()
        curr_type = type(curr)

        # Scalars are counted directly without ID tracking to avoid collapsing interned singletons
        if curr_type in scalar_types:
            total_size += getsizeof(curr)
            continue

        curr_id = id(curr)
        if curr_id in seen:
            continue
        add_seen(curr_id)

        total_size += getsizeof(curr)

        if issubclass(curr_type, dict):
            for k, v in curr.items():
                if type(k) in scalar_types:
                    total_size += getsizeof(k)
                else:
                    append(k)

                if type(v) in scalar_types:
                    total_size += getsizeof(v)
                else:
                    append(v)
        elif issubclass(curr_type, (list, tuple, set, frozenset)):
            for item in curr:
                if type(item) in scalar_types:
                    total_size += getsizeof(item)
                else:
                    append(item)

    return total_size


# ==========================================
# ENUMS & STATUSES
# ==========================================

class EpistemicStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    CONFIRMED = "CONFIRMED"
    FALSIFIED = "FALSIFIED"
    EXPIRED = "EXPIRED"
    CONTRADICTED = "CONTRADICTED"


# ==========================================
# MATHEMATICAL KERNELS
# ==========================================

class TokenSurprisalSensor:
    """Canonical statistical sensor for token-level surprisal anomaly detection."""
    def __init__(self, z_threshold: float = 2.85, window_size: int = 10, std_floor: float = 0.05):
        self.z_threshold = z_threshold
        self.window_size = window_size
        self.std_floor = std_floor

    def compute_z_scores(self, logprobs: List[float]) -> List[float]:
        if not logprobs:
            return []

        sanitized_logprobs = []
        for i, lp in enumerate(logprobs):
            if type(lp) in (float, int):
                if math.isnan(lp) or math.isinf(lp):
                    raise ValueError(f"Malformed or non-finite logprob encountered at index {i}: {lp}")
                sanitized_logprobs.append(float(lp))
            else:
                try:
                    val = float(lp)
                    if math.isnan(val) or math.isinf(val):
                        raise ValueError(f"Malformed or non-finite logprob encountered at index {i}: {val}")
                    sanitized_logprobs.append(val)
                except (TypeError, ValueError) as e:
                    raise ValueError(f"Malformed or non-finite logprob encountered at index {i}: {lp}") from e

        surprisals = [-lp for lp in sanitized_logprobs]
        z_scores = []

        sum_x = 0.0
        sum_sq = 0.0

        for i, h in enumerate(surprisals):
            if i < 2:
                z_scores.append(0.0)
                sum_x += h
                sum_sq += h * h
                continue

            n = min(i, self.window_size)
            mean_h = sum_x / n
            variance = (sum_sq / n) - (mean_h * mean_h)
            if variance < 0.0:
                variance = 0.0

            std_h = max(math.sqrt(variance), self.std_floor)
            z_scores.append(float((h - mean_h) / std_h))

            sum_x += h
            sum_sq += h * h

            if i >= self.window_size:
                old_val = surprisals[i - self.window_size]
                sum_x -= old_val
                sum_sq -= old_val * old_val

        return z_scores

    def evaluate(self, logprobs: List[float]) -> Dict[str, Any]:
        """Evaluates token surprisal z-scores and flags anomalies."""
        try:
            z_scores = self.compute_z_scores(logprobs)
        except ValueError as e:
            return {
                "passed": False,
                "reason": "MALFORMED_NON_FINITE_LOGPROBS",
                "error": str(e),
                "max_z_score": 0.0,
                "flagged_tokens": len(logprobs) if logprobs else 1,
                "token_z_scores": []
            }

        if any(not math.isfinite(z) for z in z_scores):
            non_finite_count = sum(1 for z in z_scores if not math.isfinite(z))
            sanitized_z_scores = [z if math.isfinite(z) else None for z in z_scores]
            return {
                "passed": False,
                "reason": "MALFORMED_NON_FINITE_LOGPROBS",
                "error": f"Derived Z-scores contain {non_finite_count} non-finite value(s)",
                "max_z_score": 0.0,
                "flagged_tokens": len(logprobs) if logprobs else 1,
                "token_z_scores": sanitized_z_scores
            }

        flagged_count = sum(1 for z in z_scores if z > self.z_threshold)
        max_z = float(max(z_scores)) if z_scores else 0.0

        return {
            "passed": flagged_count == 0,
            "max_z_score": max_z,
            "flagged_tokens": flagged_count,
            "token_z_scores": z_scores
        }


class BayesianBeliefKernel:
    """Stateful kernel for tracking risk hypotheses over time."""
    def __init__(self, prior_probabilities: Dict[str, float]):
        self.beliefs = prior_probabilities

    def update_beliefs(self, likelihoods: Dict[str, float]) -> Dict[str, float]:
        unnormalized_posteriors = {}
        for hypothesis, prior in self.beliefs.items():
            likelihood = likelihoods.get(hypothesis, 1.0)
            unnormalized_posteriors[hypothesis] = likelihood * prior

        total_evidence = sum(unnormalized_posteriors.values())
        if total_evidence > 0:
            self.beliefs = {
                h: v / total_evidence for h, v in unnormalized_posteriors.items()
            }

        return self.beliefs

    def get_map_estimate(self) -> str:
        return max(self.beliefs, key=self.beliefs.get)


# ==========================================
# EPISTEMIC & MEMORY GOVERNANCE SCHEMAS
# ==========================================

class PopperianContract(BaseModel):
    """Mandatory falsification contract attached to every hypothesis or belief claim."""
    claim_id: str = Field(..., description="Unique ID for the asserted claim.")
    target_metric: str = Field(..., description="Observable variable used for falsification.")
    falsification_threshold: float = Field(..., description="Threshold theta that invalidates the claim if breached.")
    comparison_operator: str = Field(..., description="Operator for threshold check: '>', '<', '==', '!=', '>=', '<='.")
    observation_window_days: int = Field(..., description="Time horizon Delta_t in days to observe the metric.")
    falsification_impact_posterior: float = Field(default=0.0, ge=0.0, le=1.0, description="Assigned posterior probability P(H|F) if falsification trigger fires.")

    def evaluate_falsification(self, observed_value: float) -> bool:
        op = self.comparison_operator
        thresh = self.falsification_threshold
        if op == ">": return observed_value > thresh
        elif op == "<": return observed_value < thresh
        elif op == ">=": return observed_value >= thresh
        elif op == "<=": return observed_value <= thresh
        elif op == "==": return math.isclose(observed_value, thresh)
        elif op == "!=": return not math.isclose(observed_value, thresh)
        else: raise ValueError(f"Unsupported comparison operator: {op}")


class BayesFactorUpdate(BaseModel):
    """Calculates Bayes Factor Lambda(E) = P(E|H) / P(E|~H) and log-Bayes factor in decibans."""
    evidence_id: str = Field(..., description="Unique ID for the submitted evidence.")
    source_provenance: List[str] = Field(..., description="Audit chain of primary sources.")
    p_evidence_given_hypothesis: float = Field(..., gt=0.0, lt=1.0)
    p_evidence_given_not_hypothesis: float = Field(..., gt=0.0, lt=1.0)
    bayes_factor: Optional[float] = Field(None)
    bayes_factor_db: Optional[float] = Field(None)

    @model_validator(mode='after')
    def compute_bayes_factors(self) -> 'BayesFactorUpdate':
        p_h = self.p_evidence_given_hypothesis
        p_nh = self.p_evidence_given_not_hypothesis
        bf = p_h / p_nh
        self.bayes_factor = round(bf, 4)
        self.bayes_factor_db = round(10.0 * math.log10(bf), 2)
        return self


class BeliefObject(BaseModel):
    """Layer 4 Memory Governance Schema: Complete state lifecycle object for institutional claims."""
    belief_id: str
    cpr_frame_id: str
    assertion: str
    prior_probability: float = Field(..., ge=0.0, le=1.0)
    current_posterior: float = Field(..., ge=0.0, le=1.0)
    status: EpistemicStatus = Field(default=EpistemicStatus.UNVERIFIED)
    evidence_ledger: List[BayesFactorUpdate] = Field(default_factory=list)
    popp_contract: PopperianContract
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_days: int = Field(default=180)
    invalidation_triggers: List[str] = Field(default_factory=list)

    def update_belief(self, update: BayesFactorUpdate) -> None:
        eps = 1e-7
        p = max(eps, min(1.0 - eps, self.current_posterior))
        prior_odds = p / (1.0 - p)
        bf = update.bayes_factor if update.bayes_factor is not None else (update.p_evidence_given_hypothesis / update.p_evidence_given_not_hypothesis)
        posterior_odds = bf * prior_odds
        new_posterior = posterior_odds / (1.0 + posterior_odds)
        self.current_posterior = round(float(new_posterior), 4)
        self.evidence_ledger.append(update)

    def check_and_apply_falsification(self, observed_metric_value: float) -> bool:
        if self.popp_contract.evaluate_falsification(observed_metric_value):
            self.status = EpistemicStatus.FALSIFIED
            self.current_posterior = self.popp_contract.falsification_impact_posterior
            return True
        return False


# ==========================================
# ZERO-TRUST PERMISSION SCOPES
# ==========================================

class PermissionScope(BaseModel):
    allowed_resources: List[str] = Field(default_factory=list)
    allowed_operations: List[str] = Field(default_factory=list)
    expires_at: float = Field(default_factory=lambda: time.time() + 15.0)
    max_attempts: int = Field(default=3)
    attempt_count: int = Field(default=1)
    max_payload_bytes: int = Field(default=4096)
    max_row_count: int = Field(default=50)
    origin_subnet: Optional[str] = None
    is_rmm_origin: bool = False
    quarantine_subnets: List[str] = Field(
        default_factory=lambda: list(_DEFAULT_QUARANTINE_SUBNETS)
    )

    def is_quarantined_channel(self) -> bool:
        if self.is_rmm_origin: return True
        if self.origin_subnet: return any(prefix in self.origin_subnet for prefix in self.quarantine_subnets)
        return False

    def validate_action(self, action: Dict[str, Any]) -> bool:
        if self.attempt_count > self.max_attempts or time.time() > self.expires_at: return False
        op = action.get("op")
        target = action.get("node") or action.get("endpoint") or action.get("table") or action.get("policy")

        # Explicit operation and target fields required when scope restricts them
        if self.allowed_operations and (not op or op not in self.allowed_operations):
            return False
        if self.allowed_resources and (not target or target not in self.allowed_resources):
            return False

        if self.is_quarantined_channel():
            mutating_operations = {"update_db", "write_db", "reroute_freight", "halt_payments", "issue_binder", "bind_policy", "cancel_policy", "release_buffer"}
            if op in mutating_operations: return False

        return True

    def validate_egress(self, response_payload: Any) -> bool:
        # Replaced inefficient string serialization with recursive size estimation
        if _estimate_payload_size(response_payload) > self.max_payload_bytes: 
            return False

        def count_max_records(data: Any) -> int:
            # Replaced recursive generator expressions with an iterative stack-based DFS
            # algorithm. This prevents RecursionError on deeply nested payloads and
            # reduces iteration overhead for improved execution speed.
            max_records = 0
            stack = [data]
            while stack:
                current = stack.pop()
                if isinstance(current, list):
                    if len(current) > max_records:
                        max_records = len(current)
                    stack.extend(current)
                elif isinstance(current, dict):
                    if len(current) > max_records:
                        max_records = len(current)
                    stack.extend(current.values())
            return max_records

        if count_max_records(response_payload) > self.max_row_count: 
            return False

        return True


# ==========================================
# CANONICAL PROBLEM REPRESENTATION (CPR)
# ==========================================

class CanonicalProblemRepresentation(BaseModel):
    policy_id: str
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    fleet_data: Optional[Dict[str, Any]] = None
    risk_details: Optional[Dict[str, Any]] = None
    primary_metric: Optional[float] = None
    scope: PermissionScope = Field(default_factory=PermissionScope)
    SENSITIVE_FIELDS: Set[str] = Field(
        default={"banking_routing", "account_number", "ssn", "account_balance_usd", "proprietary_cargo"},
        exclude=True
    )

    def __init__(self, **data):
        super().__init__(**data)
        if not data.get("scope"):
            self.scope = PermissionScope(
                allowed_resources=["logistics_db", "risk_profiles", "/underwriting/flag", "POL-2026-N99", "/bind_policy", "/cancel_policy", "/issue_binder"],
                allowed_operations=["read", "query", "update_db", "write_db", "send_api_alert", "api_call", "issue_binder", "revert", "remove", "replace", "rescind_binder"]
            )

    def mask_egress_payload(self, custom_redactions: Optional[Set[str]] = None) -> Dict[str, Any]:
        """
        Redact sensitive information from the raw payload before egress.
        """
        to_redact = custom_redactions if custom_redactions is not None else DEFAULT_REDACTION_KEYS
        return {k: v for k, v in self.raw_payload.items() if k.lower() not in to_redact}

    def serialize_for_belief_kernel(self) -> List[float]:
        if self.fleet_data:
            v_count = self.fleet_data.get("vehicle_count", 0) / 100.0
            radius = self.fleet_data.get("operating_radius_miles", 0) / 1000.0
            loss_mod = self.fleet_data.get("loss_modifier", 1.0)
            return [v_count, radius, loss_mod]
        elif self.risk_details:
            loss_mod = self.risk_details.get("loss_ratio_3yr", self.risk_details.get("loss_mod", 1.0))
            return [self.primary_metric or 0.0, loss_mod]
        return [0.0, 0.0, 0.0]
