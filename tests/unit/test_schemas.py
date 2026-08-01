"""
Unit test suite for epistemicos.schemas module.
Validates Bayes factor calculations, deciban logging, odds-ratio updating,
and Popperian contract falsification.
"""

import pytest
from epistemicos.schemas import (
    EpistemicStatus,
    PopperianContract,
    BayesFactorUpdate,
    BeliefObject
)


def test_bayes_factor_deciban_calculation():
    """Validates Lambda and deciban (10 log10 Lambda) computation."""
    update = BayesFactorUpdate(
        evidence_id="EV-001",
        source_provenance=["https://audit.epistemicos.internal/doc/101"],
        p_evidence_given_hypothesis=0.80,
        p_evidence_given_not_hypothesis=0.20
    )

    # Lambda = 0.80 / 0.20 = 4.0
    assert update.bayes_factor == 4.0
    # Decibans = 10 * log10(4.0) = 6.02 dB
    assert update.bayes_factor_db == 6.02


def test_odds_ratio_belief_update():
    """Validates Bayesian posterior update using odds ratios."""
    contract = PopperianContract(
        claim_id="CLM-001",
        target_metric="loss_ratio",
        falsification_threshold=0.75,
        comparison_operator=">",
        observation_window_days=30
    )

    belief = BeliefObject(
        belief_id="BEL-100",
        cpr_frame_id="CPR-400",
        assertion="Underwriting risk remains within preferred band.",
        prior_probability=0.50,
        current_posterior=0.50,
        popp_contract=contract
    )

    # Supporting evidence (BF = 4.0)
    update = BayesFactorUpdate(
        evidence_id="EV-001",
        source_provenance=["doc_hash_123"],
        p_evidence_given_hypothesis=0.80,
        p_evidence_given_not_hypothesis=0.20
    )

    belief.update_belief(update)

    # Prior odds = 0.5 / 0.5 = 1.0. Posterior odds = 4.0 * 1.0 = 4.0.
    # Posterior P = 4.0 / 5.0 = 0.80.
    assert belief.current_posterior == 0.80
    assert len(belief.evidence_ledger) == 1


def test_popperian_falsification_trigger():
    """Validates that breaching threshold flips status to FALSIFIED and applies posterior impact."""
    contract = PopperianContract(
        claim_id="CLM-002",
        target_metric="spread_bps",
        falsification_threshold=150.0,
        comparison_operator=">",
        observation_window_days=14,
        falsification_impact_posterior=0.01
    )

    belief = BeliefObject(
        belief_id="BEL-200",
        cpr_frame_id="CPR-500",
        assertion="Market spread will remain below 150 bps.",
        prior_probability=0.70,
        current_posterior=0.70,
        popp_contract=contract
    )

    # Metric safe (120.0 < 150.0)
    assert belief.check_and_apply_falsification(120.0) is False
    assert belief.status == EpistemicStatus.UNVERIFIED

    # Metric breaches threshold (165.0 > 150.0)
    assert belief.check_and_apply_falsification(165.0) is True
    assert belief.status == EpistemicStatus.FALSIFIED
    assert belief.current_posterior == 0.01
