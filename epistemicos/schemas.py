"""
EpistemicOS Core Schemas.
Defines Bayesian belief objects, Popperian falsification contracts,
deciban evidence updates, and Layer 4 memory governance lifecycles.
"""

import math
from enum import Enum
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, model_validator


class EpistemicStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    CONFIRMED = "CONFIRMED"
    FALSIFIED = "FALSIFIED"
    EXPIRED = "EXPIRED"
    CONTRADICTED = "CONTRADICTED"


class PopperianContract(BaseModel):
    """
    Mandatory falsification contract attached to every hypothesis or belief claim.
    Enforces Popperian empirical testability prior to Kernel state ingestion.
    """
    claim_id: str = Field(..., description="Unique ID for the asserted claim.")
    target_metric: str = Field(..., description="Observable variable used for falsification (e.g., 'loss_ratio', 'spread_bps').")
    falsification_threshold: float = Field(..., description="Numerical threshold theta that invalidates the claim if breached.")
    comparison_operator: str = Field(..., description="Operator for threshold check: '>', '<', '==', '!=', '>=', '<='.")
    observation_window_days: int = Field(..., description="Time horizon Delta_t in days to observe the metric.")
    falsification_impact_posterior: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Assigned posterior probability P(H|F) if falsification trigger fires."
    )

    def evaluate_falsification(self, observed_value: float) -> bool:
        """Evaluates whether an observed metric breaches the falsification threshold."""
        op = self.comparison_operator
        thresh = self.falsification_threshold

        if op == ">":
            return observed_value > thresh
        elif op == "<":
            return observed_value < thresh
        elif op == ">=":
            return observed_value >= thresh
        elif op == "<=":
            return observed_value <= thresh
        elif op == "==":
            return math.isclose(observed_value, thresh)
        elif op == "!=":
            return not math.isclose(observed_value, thresh)
        else:
            raise ValueError(f"Unsupported comparison operator: {op}")


class BayesFactorUpdate(BaseModel):
    """
    Represents an evidence submission designed to update a Bayesian Belief Object.
    Calculates Bayes Factor Lambda(E) = P(E|H) / P(E|~H) and log-Bayes factor in decibans.
    """
    evidence_id: str = Field(..., description="Unique ID for the submitted evidence.")
    source_provenance: List[str] = Field(..., description="Audit chain of primary sources (URLs, document hashes).")
    p_evidence_given_hypothesis: float = Field(..., gt=0.0, lt=1.0, description="P(E|H) Likelihood of evidence if hypothesis is true.")
    p_evidence_given_not_hypothesis: float = Field(..., gt=0.0, lt=1.0, description="P(E|~H) Likelihood of evidence if hypothesis is false.")
    bayes_factor: Optional[float] = Field(None, description="Calculated Bayes Factor Lambda(E) = P(E|H)/P(E|~H).")
    bayes_factor_db: Optional[float] = Field(None, description="Log-Bayes Factor in decibans: 10 * log10(Lambda).")

    @model_validator(mode='after')
    def compute_bayes_factors(self) -> 'BayesFactorUpdate':
        p_h = self.p_evidence_given_hypothesis
        p_nh = self.p_evidence_given_not_hypothesis

        # Compute Bayes Factor Lambda
        bf = p_h / p_nh
        self.bayes_factor = round(bf, 4)

        # Compute log-Bayes factor in decibans: 10 * log10(Lambda)
        self.bayes_factor_db = round(10.0 * math.log10(bf), 2)
        return self


class BeliefObject(BaseModel):
    """
    Layer 4 Memory Governance Schema: Complete state lifecycle object for institutional claims.
    """
    belief_id: str = Field(..., description="Canonical ID for the belief object.")
    cpr_frame_id: str = Field(..., description="The Canonical Problem Representation frame this belief lives in.")
    assertion: str = Field(..., description="Plain-language description of the claim.")
    prior_probability: float = Field(..., ge=0.0, le=1.0, description="Initial P(H).")
    current_posterior: float = Field(..., ge=0.0, le=1.0, description="Updated P(H|E_1...E_n).")
    status: EpistemicStatus = Field(default=EpistemicStatus.UNVERIFIED)

    # Audit & Provenance
    evidence_ledger: List[BayesFactorUpdate] = Field(default_factory=list)
    popp_contract: PopperianContract = Field(..., description="Bound Popperian contract.")

    # Lifecycle & Memory Governance
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_days: int = Field(default=180, description="Time-To-Live in days before Layer 4 forces eviction/re-audit.")
    invalidation_triggers: List[str] = Field(default_factory=list, description="System event tags that force immediate status -> EXPIRED.")

    def update_belief(self, update: BayesFactorUpdate) -> None:
        """
        Updates current posterior probability using the odds-ratio form of Bayes' Rule:
        O(H|E) = Lambda(E) * O(H)
        P(H|E) = O(H|E) / (1 + O(H|E))
        """
        eps = 1e-7
        # Clip current posterior to avoid division by zero
        p = max(eps, min(1.0 - eps, self.current_posterior))
        prior_odds = p / (1.0 - p)

        bf = update.bayes_factor if update.bayes_factor is not None else (update.p_evidence_given_hypothesis / update.p_evidence_given_not_hypothesis)
        posterior_odds = bf * prior_odds

        new_posterior = posterior_odds / (1.0 + posterior_odds)
        self.current_posterior = round(float(new_posterior), 4)
        self.evidence_ledger.append(update)

    def check_and_apply_falsification(self, observed_metric_value: float) -> bool:
        """
        Evaluates metric against bound PopperianContract.
        If breached, sets status to FALSIFIED and applies impact posterior.
        """
        if self.popp_contract.evaluate_falsification(observed_metric_value):
            self.status = EpistemicStatus.FALSIFIED
            self.current_posterior = self.popp_contract.falsification_impact_posterior
            return True
        return False
