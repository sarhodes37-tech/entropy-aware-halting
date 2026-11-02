"""
Minimal Change Impact and Evidence Invalidation Logic.

Classifies differences between manifests and determines which verification evidence
remains applicable, which is invalidated, and which requires re-evaluation.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from epistemicos.release.models import (
    ReleaseManifest,
    ComponentSpec,
    VerificationEvidenceRecord,
    EvidenceVerificationStatus,
)


class ChangeCategory(str, Enum):
    MODEL_CHANGE = "model_change"
    RUNTIME_CHANGE = "runtime_change"
    DEPENDENCY_CHANGE = "dependency_change"
    POLICY_CHANGE = "policy_change"
    INFRASTRUCTURE_CHANGE = "infrastructure_change"
    COMPONENT_ADDED = "component_added"
    COMPONENT_REMOVED = "component_removed"
    CONFIG_CHANGE = "config_change"
    NO_MATERIAL_CHANGE = "no_material_change"


@dataclass
class ComponentDelta:
    component_id: str
    change_category: ChangeCategory
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    old_digest: Optional[str] = None
    new_digest: Optional[str] = None
    old_config_digest: Optional[str] = None
    new_config_digest: Optional[str] = None
    description: str = ""


@dataclass
class ChangeImpactReport:
    """
    Structured report comparing an old and new ReleaseManifest.
    Identifies changed components, invalidates affected evidence,
    and classifies retained vs re-evaluation required evidence.
    """
    old_manifest_digest: str
    new_manifest_digest: str
    is_identical: bool
    component_deltas: List[ComponentDelta] = field(default_factory=list)
    affected_component_ids: Set[str] = field(default_factory=set)
    retained_evidence: List[VerificationEvidenceRecord] = field(default_factory=list)
    invalidated_evidence: List[VerificationEvidenceRecord] = field(default_factory=list)
    missing_evidence_types: Set[str] = field(default_factory=set)
    can_authorize_without_rerun: bool = False
    invalidation_reasons: List[str] = field(default_factory=list)


class EvidenceInvalidator:
    """
    Evaluates manifest deltas and determines evidence invalidation boundaries.

    Rules for this proof of concept:
    1. If manifests are identical, all valid evidence bound to that manifest is retained.
    2. If a component's artifact digest or config digest changed, any evidence explicitly
       covering that component_id is strictly INVALIDATED.
    3. Evidence bound ONLY to a previous manifest digest cannot satisfy the new manifest
       UNLESS explicitly verified and re-bound.
    4. Unaffected component evidence with explicit component scopes MAY be retained for
       informational audit, but release-level approval strictly requires evidence bound to the
       current release manifest.
    5. Ambiguous or unknown dependencies fail closed.
    """

    @classmethod
    def analyze_change(
        cls,
        old_manifest: ReleaseManifest,
        new_manifest: ReleaseManifest,
        available_evidence: List[VerificationEvidenceRecord]
    ) -> ChangeImpactReport:
        old_digest = old_manifest.compute_manifest_digest()
        new_digest = new_manifest.compute_manifest_digest()

        if old_digest == new_digest:
            # Manifests are identical
            valid_ev = [
                ev for ev in available_evidence
                if ev.is_valid_for_manifest(new_digest)
            ]
            provided_types = {ev.evidence_type for ev in valid_ev}
            missing_types = new_manifest.required_evidence_types - provided_types
            can_auth = (len(missing_types) == 0 and len(valid_ev) >= len(new_manifest.required_evidence_types))

            return ChangeImpactReport(
                old_manifest_digest=old_digest,
                new_manifest_digest=new_digest,
                is_identical=True,
                retained_evidence=valid_ev,
                invalidated_evidence=[],
                missing_evidence_types=missing_types,
                can_authorize_without_rerun=can_auth
            )

        # Detect component-level differences
        deltas: List[ComponentDelta] = []
        affected_components: Set[str] = set()

        old_comp_map = {c.component_id: c for c in old_manifest.components}
        new_comp_map = {c.component_id: c for c in new_manifest.components}

        # Check policy or runtime changes
        if old_manifest.policy_digest != new_manifest.policy_digest or old_manifest.policy_version != new_manifest.policy_version:
            deltas.append(ComponentDelta(
                component_id="policy",
                change_category=ChangeCategory.POLICY_CHANGE,
                old_version=old_manifest.policy_version,
                new_version=new_manifest.policy_version,
                old_digest=old_manifest.policy_digest,
                new_digest=new_manifest.policy_digest,
                description="Authorization policy configuration or version altered"
            ))
            affected_components.add("policy")

        if old_manifest.runtime_identity != new_manifest.runtime_identity:
            deltas.append(ComponentDelta(
                component_id="runtime",
                change_category=ChangeCategory.RUNTIME_CHANGE,
                description=f"Runtime identity changed: '{old_manifest.runtime_identity}' -> '{new_manifest.runtime_identity}'"
            ))
            affected_components.add("runtime")

        # Check removed components
        for comp_id, old_c in old_comp_map.items():
            if comp_id not in new_comp_map:
                deltas.append(ComponentDelta(
                    component_id=comp_id,
                    change_category=ChangeCategory.COMPONENT_REMOVED,
                    old_version=old_c.version,
                    old_digest=old_c.digest,
                    description=f"Component '{comp_id}' removed in new manifest"
                ))
                affected_components.add(comp_id)

        # Check added and modified components
        for comp_id, new_c in new_comp_map.items():
            if comp_id not in old_comp_map:
                deltas.append(ComponentDelta(
                    component_id=comp_id,
                    change_category=ChangeCategory.COMPONENT_ADDED,
                    new_version=new_c.version,
                    new_digest=new_c.digest,
                    description=f"New component '{comp_id}' added in new manifest"
                ))
                affected_components.add(comp_id)
            else:
                old_c = old_comp_map[comp_id]
                digest_changed = (old_c.digest.lower() != new_c.digest.lower())
                config_changed = (old_c.config_digest != new_c.config_digest)
                version_changed = (old_c.version != new_c.version)

                if digest_changed or config_changed or version_changed:
                    # Categorize by component type
                    cat = ChangeCategory.CONFIG_CHANGE
                    if new_c.component_type == "model":
                        cat = ChangeCategory.MODEL_CHANGE
                    elif new_c.component_type == "runtime":
                        cat = ChangeCategory.RUNTIME_CHANGE
                    elif new_c.component_type == "dependency":
                        cat = ChangeCategory.DEPENDENCY_CHANGE
                    elif new_c.component_type == "infrastructure":
                        cat = ChangeCategory.INFRASTRUCTURE_CHANGE

                    deltas.append(ComponentDelta(
                        component_id=comp_id,
                        change_category=cat,
                        old_version=old_c.version,
                        new_version=new_c.version,
                        old_digest=old_c.digest,
                        new_digest=new_c.digest,
                        old_config_digest=old_c.config_digest,
                        new_config_digest=new_c.config_digest,
                        description=f"Component '{comp_id}' modified (digest: {digest_changed}, config: {config_changed})"
                    ))
                    affected_components.add(comp_id)

        # Invalidate evidence
        retained: List[VerificationEvidenceRecord] = []
        invalidated: List[VerificationEvidenceRecord] = []
        reasons: List[str] = []

        for ev in available_evidence:
            # Check 1: Does evidence touch an affected component?
            intersects_affected = bool(ev.evaluated_component_ids.intersection(affected_components))
            if intersects_affected:
                invalidated.append(ev)
                reasons.append(
                    f"Evidence '{ev.evidence_id}' invalidated: touches changed component(s) {sorted(list(ev.evaluated_component_ids.intersection(affected_components)))}"
                )
                continue

            # Check 2: Was evidence bound to the old manifest digest?
            if ev.manifest_digest.lower() == old_digest.lower():
                # Even if its component wasn't modified, the release-level manifest has changed
                invalidated.append(ev)
                reasons.append(
                    f"Evidence '{ev.evidence_id}' invalidated: bound to old manifest digest '{old_digest[:12]}...', not current '{new_digest[:12]}...'"
                )
                continue

            # Check 3: Is evidence directly bound to current new manifest digest and PASS?
            if ev.is_valid_for_manifest(new_digest):
                retained.append(ev)
            else:
                invalidated.append(ev)
                reasons.append(f"Evidence '{ev.evidence_id}' invalidated: status is {ev.status.value}")

        retained_types = {ev.evidence_type for ev in retained}
        missing_types = new_manifest.required_evidence_types - retained_types

        return ChangeImpactReport(
            old_manifest_digest=old_digest,
            new_manifest_digest=new_digest,
            is_identical=False,
            component_deltas=deltas,
            affected_component_ids=affected_components,
            retained_evidence=retained,
            invalidated_evidence=invalidated,
            missing_evidence_types=missing_types,
            can_authorize_without_rerun=(len(missing_types) == 0 and len(retained) > 0),
            invalidation_reasons=reasons
        )
