"""
Semantic Uncertainty Module for EpistemicOS.

Prototype implementing meaning-level conclusion clustering, semantic entropy calculation,
and decision-sensitive disagreement metrics alongside formal status indicators.

Phase 2 & Phase 3 Architecture:
- Explicit separation between Semantic Uncertainty, Evidence Sufficiency, Factual Correctness,
  Decision Sensitivity, and Resolution Opportunity.
- Pluggable SemanticResolver interface allowing deterministic baselines or model judges.
- Mathematical rigor: Shannon entropy in bits computed from cluster probabilities,
  normalized entropy bounded in [0, 1].
"""

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union


class SemanticUncertaintyStatus(str, Enum):
    VALID = "VALID"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    MALFORMED_INPUT = "MALFORMED_INPUT"
    UNRESOLVED_COMPARISON = "UNRESOLVED_COMPARISON"


@dataclass
class Candidate:
    """Represents a candidate output or conclusion with optional probability and decision action."""
    text: str
    probability: Optional[float] = None
    action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SemanticComparisonResult:
    """Outcome of comparing two candidates with a SemanticResolver."""
    is_equivalent: bool
    similarity_score: float  # 0.0 to 1.0
    is_contradiction: bool = False
    affects_decision: bool = False
    resolver_confidence: float = 1.0  # 1.0 = fully confident, <1.0 = ambiguous


class SemanticResolver:
    """Abstract interface / base class for semantic equivalence resolution."""

    def resolve(self, candidate_a: Candidate, candidate_b: Candidate) -> SemanticComparisonResult:
        raise NotImplementedError("Subclasses must implement resolve()")


class ExactAndNormalizedResolver(SemanticResolver):
    """
    Deterministic baseline semantic resolver.
    Normalizes text (case, whitespace, punctuation), detects negation reversals,
    quantity/entity discrepancies, and decision action mismatches.
    """

    NEGATION_WORDS = {"not", "no", "never", "cannot", "none", "neither", "nor", "deny", "rejected", "false"}

    def __init__(self, confidence_threshold: float = 0.85):
        self.confidence_threshold = confidence_threshold

    def _normalize(self, text: str) -> str:
        clean = re.sub(r"[^\w\s]", "", text.strip().lower())
        return " ".join(clean.split())

    def _extract_tokens(self, text: str) -> List[str]:
        return self._normalize(text).split()

    def _extract_numbers(self, text: str) -> List[str]:
        return re.findall(r"\b\d+(?:\.\d+)?\b", text)

    def _has_negation_flip(self, tokens_a: List[str], tokens_b: List[str]) -> bool:
        negs_a = set(tokens_a) & self.NEGATION_WORDS
        negs_b = set(tokens_b) & self.NEGATION_WORDS
        return len(negs_a) != len(negs_b)

    def resolve(self, candidate_a: Candidate, candidate_b: Candidate) -> SemanticComparisonResult:
        norm_a = self._normalize(candidate_a.text)
        norm_b = self._normalize(candidate_b.text)

        # Exact match after normalization
        if norm_a == norm_b:
            action_diff = (candidate_a.action is not None and candidate_b.action is not None and candidate_a.action != candidate_b.action)
            return SemanticComparisonResult(
                is_equivalent=not action_diff,
                similarity_score=1.0,
                is_contradiction=False,
                affects_decision=action_diff,
                resolver_confidence=1.0
            )

        tokens_a = self._extract_tokens(candidate_a.text)
        tokens_b = self._extract_tokens(candidate_b.text)
        nums_a = self._extract_numbers(candidate_a.text)
        nums_b = self._extract_numbers(candidate_b.text)

        # Check for negation flip
        neg_flip = self._has_negation_flip(tokens_a, tokens_b)

        # Check for quantity/number mismatch
        number_mismatch = (nums_a != nums_b) and (len(nums_a) > 0 or len(nums_b) > 0)

        # Check action difference
        affects_decision = False
        if candidate_a.action is not None and candidate_b.action is not None:
            affects_decision = (candidate_a.action != candidate_b.action)

        # Calculate token overlap Jaccard index
        set_a, set_b = set(tokens_a), set(tokens_b)
        intersection = set_a & set_b
        union = set_a | set_b
        jaccard = len(intersection) / len(union) if union else 1.0

        if neg_flip or number_mismatch or affects_decision:
            is_equivalent = False
            is_contradiction = neg_flip or affects_decision
            resolver_confidence = 0.95
        else:
            # High token similarity without negation/quantity flip -> treat as equivalent paraphrase
            is_equivalent = (jaccard >= 0.7)
            is_contradiction = False
            resolver_confidence = 0.90 if is_equivalent else 0.80

        return SemanticComparisonResult(
            is_equivalent=is_equivalent,
            similarity_score=jaccard,
            is_contradiction=is_contradiction,
            affects_decision=affects_decision,
            resolver_confidence=resolver_confidence
        )


@dataclass
class ClusterInfo:
    """Details of an identified semantic cluster."""
    cluster_id: int
    representative_text: str
    member_indices: List[int]
    probability: float


@dataclass
class SemanticUncertaintyResult:
    """
    Structured result schema for Semantic Uncertainty Estimation.

    Phase 3 Conceptual Boundaries:
    - semantic_entropy_bits & semantic_disagreement measure MEANING-LEVEL DISAGREEMENT.
    - evidence_sufficiency, factual_correctness are explicitly distinct and NOT inferred from low entropy.
    """
    candidates_analyzed: int
    num_clusters: int
    cluster_distribution: List[ClusterInfo]
    semantic_entropy_bits: Optional[float]
    normalized_semantic_entropy: Optional[float]
    semantic_disagreement: float
    decision_sensitive_disagreement: float
    resolver_ambiguity: float
    status: SemanticUncertaintyStatus
    method_version: str = "SemanticUncertaintyEstimator-v1.0"

    # Explicit Phase 3 distinction placeholders (Not inferred from entropy)
    evidence_sufficiency: Optional[float] = None
    factual_correctness: Optional[float] = None
    resolution_opportunity: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidates_analyzed": self.candidates_analyzed,
            "num_clusters": self.num_clusters,
            "cluster_distribution": [
                {
                    "cluster_id": c.cluster_id,
                    "representative_text": c.representative_text,
                    "member_indices": c.member_indices,
                    "probability": c.probability
                }
                for c in self.cluster_distribution
            ],
            "semantic_entropy_bits": self.semantic_entropy_bits,
            "normalized_semantic_entropy": self.normalized_semantic_entropy,
            "semantic_disagreement": self.semantic_disagreement,
            "decision_sensitive_disagreement": self.decision_sensitive_disagreement,
            "resolver_ambiguity": self.resolver_ambiguity,
            "status": self.status.value,
            "method_version": self.method_version,
            "evidence_sufficiency": self.evidence_sufficiency,
            "factual_correctness": self.factual_correctness,
            "resolution_opportunity": self.resolution_opportunity,
        }


class SemanticUncertaintyEstimator:
    """
    Measures semantic (meaning-level) uncertainty across a set of candidate answers/claims.

    Uses a pluggable SemanticResolver interface to partition candidates into
    semantically equivalent clusters and computes Shannon entropy over the cluster
    distribution.
    """

    VERSION = "SemanticUncertaintyEstimator-v1.0"

    def __init__(self, resolver: Optional[SemanticResolver] = None):
        self.resolver = resolver or ExactAndNormalizedResolver()

    def _parse_candidate(self, cand: Any) -> Optional[Candidate]:
        if isinstance(cand, Candidate):
            return cand
        if isinstance(cand, str):
            return Candidate(text=cand)
        if isinstance(cand, dict):
            text = cand.get("text", "")
            if not isinstance(text, str):
                return None
            prob = cand.get("probability", cand.get("prob", cand.get("weight", None)))
            action = cand.get("action", None)
            return Candidate(text=text, probability=prob, action=action, metadata=cand)
        return None

    def estimate(
        self,
        candidates: Sequence[Union[str, Dict[str, Any], Candidate]],
        decision_context: Optional[Dict[str, Any]] = None
    ) -> SemanticUncertaintyResult:
        """
        Estimates semantic uncertainty for the given candidate list.
        """
        if not candidates:
            return SemanticUncertaintyResult(
                candidates_analyzed=0,
                num_clusters=0,
                cluster_distribution=[],
                semantic_entropy_bits=None,
                normalized_semantic_entropy=None,
                semantic_disagreement=0.0,
                decision_sensitive_disagreement=0.0,
                resolver_ambiguity=0.0,
                status=SemanticUncertaintyStatus.MALFORMED_INPUT,
                method_version=self.VERSION
            )

        parsed_candidates: List[Candidate] = []
        for c in candidates:
            parsed = self._parse_candidate(c)
            if parsed is None or not parsed.text.strip():
                return SemanticUncertaintyResult(
                    candidates_analyzed=len(candidates),
                    num_clusters=0,
                    cluster_distribution=[],
                    semantic_entropy_bits=None,
                    normalized_semantic_entropy=None,
                    semantic_disagreement=0.0,
                    decision_sensitive_disagreement=0.0,
                    resolver_ambiguity=0.0,
                    status=SemanticUncertaintyStatus.MALFORMED_INPUT,
                    method_version=self.VERSION
                )
            parsed_candidates.append(parsed)

        n_candidates = len(parsed_candidates)

        # Single candidate rule: Cannot claim reliable semantic uncertainty measurement
        if n_candidates == 1:
            single_cluster = ClusterInfo(
                cluster_id=0,
                representative_text=parsed_candidates[0].text,
                member_indices=[0],
                probability=1.0
            )
            return SemanticUncertaintyResult(
                candidates_analyzed=1,
                num_clusters=1,
                cluster_distribution=[single_cluster],
                semantic_entropy_bits=0.0,
                normalized_semantic_entropy=0.0,
                semantic_disagreement=0.0,
                decision_sensitive_disagreement=0.0,
                resolver_ambiguity=0.0,
                status=SemanticUncertaintyStatus.INSUFFICIENT_EVIDENCE,
                method_version=self.VERSION
            )

        # Validate candidate probabilities if present
        raw_probs = [c.probability for c in parsed_candidates]
        has_probs = all(p is not None for p in raw_probs)

        if has_probs:
            # Check non-negative & non-NaN
            valid_probs = []
            for p in raw_probs:
                if not isinstance(p, (int, float)) or math.isnan(p) or math.isinf(p) or p < 0.0:
                    return SemanticUncertaintyResult(
                        candidates_analyzed=n_candidates,
                        num_clusters=0,
                        cluster_distribution=[],
                        semantic_entropy_bits=None,
                        normalized_semantic_entropy=None,
                        semantic_disagreement=0.0,
                        decision_sensitive_disagreement=0.0,
                        resolver_ambiguity=0.0,
                        status=SemanticUncertaintyStatus.MALFORMED_INPUT,
                        method_version=self.VERSION
                    )
                valid_probs.append(float(p))

            prob_sum = sum(valid_probs)
            if prob_sum <= 0.0:
                return SemanticUncertaintyResult(
                    candidates_analyzed=n_candidates,
                    num_clusters=0,
                    cluster_distribution=[],
                    semantic_entropy_bits=None,
                    normalized_semantic_entropy=None,
                    semantic_disagreement=0.0,
                    decision_sensitive_disagreement=0.0,
                    resolver_ambiguity=0.0,
                    status=SemanticUncertaintyStatus.MALFORMED_INPUT,
                    method_version=self.VERSION
                )
            normalized_candidate_probs = [p / prob_sum for p in valid_probs]
        else:
            # Assign uniform mass across candidates when explicit probabilities are omitted
            normalized_candidate_probs = [1.0 / n_candidates] * n_candidates

        # Perform clustering using the resolver
        clusters: List[List[int]] = []  # list of member candidate indices
        pairwise_disagreements = 0
        pairwise_decision_disagreements = 0
        total_pairs = 0
        ambiguity_scores = []

        for i in range(n_candidates):
            cand_i = parsed_candidates[i]
            assigned_cluster = None

            for cluster in clusters:
                rep_idx = cluster[0]
                cand_rep = parsed_candidates[rep_idx]
                comp = self.resolver.resolve(cand_i, cand_rep)
                ambiguity_scores.append(1.0 - comp.resolver_confidence)

                if comp.is_equivalent:
                    assigned_cluster = cluster
                    break

            if assigned_cluster is not None:
                assigned_cluster.append(i)
            else:
                clusters.append([i])

        # Compute all pairwise relations for granular metrics
        for i in range(n_candidates):
            for j in range(i + 1, n_candidates):
                total_pairs += 1
                cand_i, cand_j = parsed_candidates[i], parsed_candidates[j]
                comp = self.resolver.resolve(cand_i, cand_j)

                if not comp.is_equivalent:
                    pairwise_disagreements += 1

                if comp.affects_decision:
                    pairwise_decision_disagreements += 1

        semantic_disagreement = pairwise_disagreements / total_pairs if total_pairs > 0 else 0.0
        decision_sensitive_disagreement = pairwise_decision_disagreements / total_pairs if total_pairs > 0 else 0.0
        resolver_ambiguity = sum(ambiguity_scores) / len(ambiguity_scores) if ambiguity_scores else 0.0

        # Construct ClusterInfo and compute cluster probabilities
        cluster_infos: List[ClusterInfo] = []
        cluster_probs: List[float] = []

        for c_idx, member_indices in enumerate(clusters):
            rep_text = parsed_candidates[member_indices[0]].text
            c_prob = sum(normalized_candidate_probs[m] for m in member_indices)
            cluster_infos.append(ClusterInfo(
                cluster_id=c_idx,
                representative_text=rep_text,
                member_indices=member_indices,
                probability=c_prob
            ))
            cluster_probs.append(c_prob)

        # Compute Shannon Entropy H(C) = - sum p * log2(p)
        h_sem = 0.0
        for p in cluster_probs:
            if p > 0.0:
                h_sem -= p * math.log2(p)

        # Compute Normalized Semantic Entropy
        # For K clusters, maximum entropy is log2(K). If K=1, normalized entropy is 0.0.
        num_clusters = len(clusters)
        if num_clusters <= 1:
            norm_h_sem = 0.0
        else:
            norm_h_sem = min(1.0, max(0.0, h_sem / math.log2(num_clusters)))

        # Status determination
        status = SemanticUncertaintyStatus.VALID
        if resolver_ambiguity > 0.4:
            status = SemanticUncertaintyStatus.UNRESOLVED_COMPARISON

        return SemanticUncertaintyResult(
            candidates_analyzed=n_candidates,
            num_clusters=num_clusters,
            cluster_distribution=cluster_infos,
            semantic_entropy_bits=h_sem,
            normalized_semantic_entropy=norm_h_sem,
            semantic_disagreement=semantic_disagreement,
            decision_sensitive_disagreement=decision_sensitive_disagreement,
            resolver_ambiguity=resolver_ambiguity,
            status=status,
            method_version=self.VERSION
        )
