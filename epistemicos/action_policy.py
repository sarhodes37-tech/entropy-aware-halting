"""
EpistemicOS V1 - Action Classification & Side-Effect Control Module
------------------------------------------------------------------
Defines trusted action classifications, action registry, typed approval requirements,
and side-effect policy enforcement for protected operations.
"""

import time
import uuid
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class ActionCategory(Enum):
    READ_ONLY_LOCAL = "READ_ONLY_LOCAL"
    NETWORK_READ = "NETWORK_READ"
    EXTERNAL_RECONNAISSANCE = "EXTERNAL_RECONNAISSANCE"
    ACCOUNT_CREATION = "ACCOUNT_CREATION"
    MESSAGING_CONTACT = "MESSAGING_CONTACT"
    PUBLIC_REPOSITORY_MUTATION = "PUBLIC_REPOSITORY_MUTATION"
    PACKAGE_PUBLISHING = "PACKAGE_PUBLISHING"
    CREDENTIAL_USAGE = "CREDENTIAL_USAGE"
    DESTRUCTIVE_COMMAND = "DESTRUCTIVE_COMMAND"
    STATE_MUTATION = "STATE_MUTATION"


@dataclass
class RegisteredActionDefinition:
    operation_id: str
    category: ActionCategory
    description: str
    requires_human_approval: bool = False
    allowed_resources: Set[str] = field(default_factory=set)
    is_externally_consequential: bool = False


@dataclass
class TypedHumanApprovalRecord:
    approval_id: str
    operation_id: str
    target_resource: str
    canonical_args_digest: str
    task_id: str
    policy_version: str
    approved_by_principal: str
    timestamp: str
    signature: str


class ActionRegistry:
    """
    Trusted Action Registry classifying operations by real consequences,
    not model self-descriptions or automated natural language claims.
    """

    DEFAULT_ACTIONS = {
        "local_read": RegisteredActionDefinition(
            operation_id="local_read",
            category=ActionCategory.READ_ONLY_LOCAL,
            description="Read-only operations on an expressly in-scope local/test resource",
            requires_human_approval=False,
            is_externally_consequential=False
        ),
        "network_read": RegisteredActionDefinition(
            operation_id="network_read",
            category=ActionCategory.NETWORK_READ,
            description="Network reads against explicitly approved hosts",
            requires_human_approval=False,
            is_externally_consequential=False
        ),
        "external_recon": RegisteredActionDefinition(
            operation_id="external_recon",
            category=ActionCategory.EXTERNAL_RECONNAISSANCE,
            description="Reconnaissance or access against a newly discovered external target",
            requires_human_approval=True,
            is_externally_consequential=True
        ),
        "account_creation": RegisteredActionDefinition(
            operation_id="account_creation",
            category=ActionCategory.ACCOUNT_CREATION,
            description="Account creation or identity changes on an external service",
            requires_human_approval=True,
            is_externally_consequential=True
        ),
        "send_message": RegisteredActionDefinition(
            operation_id="send_message",
            category=ActionCategory.MESSAGING_CONTACT,
            description="Sending email, messaging, or contacting a human",
            requires_human_approval=True,
            is_externally_consequential=True
        ),
        "public_repo_mutation": RegisteredActionDefinition(
            operation_id="public_repo_mutation",
            category=ActionCategory.PUBLIC_REPOSITORY_MUTATION,
            description="Opening or modifying a public issue, pull request, branch, release, or repository",
            requires_human_approval=True,
            is_externally_consequential=True
        ),
        "package_publish": RegisteredActionDefinition(
            operation_id="package_publish",
            category=ActionCategory.PACKAGE_PUBLISHING,
            description="Publishing a package, artifact, or executable",
            requires_human_approval=True,
            is_externally_consequential=True
        ),
        "credential_use": RegisteredActionDefinition(
            operation_id="credential_use",
            category=ActionCategory.CREDENTIAL_USAGE,
            description="Using discovered credentials, another agent's account, or cross-agent resources",
            requires_human_approval=True,
            is_externally_consequential=True
        ),
        "destructive_shell": RegisteredActionDefinition(
            operation_id="destructive_shell",
            category=ActionCategory.DESTRUCTIVE_COMMAND,
            description="Destructive shell or filesystem operations",
            requires_human_approval=True,
            is_externally_consequential=True
        ),
        "financial_state_mutation": RegisteredActionDefinition(
            operation_id="financial_state_mutation",
            category=ActionCategory.STATE_MUTATION,
            description="Persistent financial, account, or other state-changing operations",
            requires_human_approval=True,
            is_externally_consequential=True
        ),
    }

    def __init__(self, custom_actions: Optional[Dict[str, RegisteredActionDefinition]] = None):
        self._actions: Dict[str, RegisteredActionDefinition] = dict(self.DEFAULT_ACTIONS)
        if custom_actions:
            self._actions.update(custom_actions)

    def register_action(self, action_def: RegisteredActionDefinition) -> None:
        self._actions[action_def.operation_id] = action_def

    def lookup_action(self, operation_id: str) -> Optional[RegisteredActionDefinition]:
        return self._actions.get(operation_id)

    def classify_action(self, operation_id: str) -> ActionCategory:
        act = self.lookup_action(operation_id)
        if act:
            return act.category
        return ActionCategory.STATE_MUTATION  # Fail closed to state mutation if unregistered


class SideEffectPolicyEngine:
    """
    Enforces side-effect policies, required typed approvals, and route-change tracking.
    """

    def __init__(
        self,
        registry: Optional[ActionRegistry] = None,
        signing_secret: str = "EPISTEMICOS_APPROVAL_SECRET"
    ):
        self.registry = registry or ActionRegistry()
        self.signing_secret = signing_secret
        self._violation_counts: Dict[str, int] = {}  # Map correlation_id / session_id to attempt count

    def compute_canonical_digest(self, payload: Any) -> str:
        if isinstance(payload, bytes):
            cb = payload
        elif isinstance(payload, str):
            cb = payload.encode("utf-8")
        else:
            import json
            try:
                cb = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            except Exception:
                cb = str(payload).encode("utf-8")
        return hashlib.sha256(cb).hexdigest()

    def record_scope_violation(self, correlation_id: str) -> int:
        count = self._violation_counts.get(correlation_id, 0) + 1
        self._violation_counts[correlation_id] = count
        return count

    def get_violation_count(self, correlation_id: str) -> int:
        return self._violation_counts.get(correlation_id, 0)

    def verify_approval_record(
        self,
        record: TypedHumanApprovalRecord,
        expected_operation_id: str,
        expected_target: str,
        expected_payload: Any,
        expected_task_id: str,
        expected_policy_version: str = "1.0.0"
    ) -> Tuple[bool, str]:
        """
        Validates typed human approval record against Phase 1 criteria:
        Binds specific operation, destination/resource, canonical arguments digest, task, and policy version.
        Generic automated responses ("continue", "best judgement") are rejected.
        """
        if not record or not isinstance(record, TypedHumanApprovalRecord):
            return False, "Invalid or missing approval record"

        if record.operation_id != expected_operation_id:
            return False, f"Approval operation mismatch: expected '{expected_operation_id}', got '{record.operation_id}'"

        if record.target_resource != expected_target:
            return False, f"Approval target mismatch: expected '{expected_target}', got '{record.target_resource}'"

        expected_digest = self.compute_canonical_digest(expected_payload)
        if record.canonical_args_digest != expected_digest:
            return False, "Approval payload digest mismatch"

        if record.task_id != expected_task_id:
            return False, f"Approval task mismatch: expected '{expected_task_id}', got '{record.task_id}'"

        if record.policy_version != expected_policy_version:
            return False, f"Approval policy version mismatch: expected '{expected_policy_version}', got '{record.policy_version}'"

        # Verify signature
        sig_data = f"{record.approval_id}:{record.operation_id}:{record.target_resource}:{record.canonical_args_digest}:{record.task_id}:{record.policy_version}:{record.approved_by_principal}"
        expected_sig = hashlib.sha256(f"{self.signing_secret}:{sig_data}".encode("utf-8")).hexdigest()

        if record.signature != expected_sig:
            return False, "Approval signature verification failed"

        return True, "Approval record validated"

    def evaluate_side_effect_authorization(
        self,
        operation_id: str,
        target_resource: str,
        payload: Any,
        task_id: str,
        correlation_id: str,
        approval_record: Optional[TypedHumanApprovalRecord] = None,
        policy_version: str = "1.0.0"
    ) -> Tuple[bool, str]:
        """
        Evaluates whether an action with external side effects is authorized.
        """
        act = self.registry.lookup_action(operation_id)
        if not act:
            count = self.record_scope_violation(correlation_id)
            return False, f"Authorization denied: Operation '{operation_id}' is unregistered. (Violation count: {count})"

        if act.requires_human_approval or act.is_externally_consequential:
            if not approval_record:
                count = self.record_scope_violation(correlation_id)
                return False, f"Authorization denied: Externally consequential operation '{operation_id}' requires explicit typed human approval. (Violation count: {count})"

            valid, msg = self.verify_approval_record(
                record=approval_record,
                expected_operation_id=operation_id,
                expected_target=target_resource,
                expected_payload=payload,
                expected_task_id=task_id,
                expected_policy_version=policy_version
            )
            if not valid:
                count = self.record_scope_violation(correlation_id)
                return False, f"Authorization denied: Approval verification failed: {msg}. (Violation count: {count})"

        return True, "Action authorized"
