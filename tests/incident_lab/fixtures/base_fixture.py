"""
Base operation tracking interface and data structures for EpistemicOS Incident Lab.

Provides an observable operation executor that tracks:
- Agent and request identity
- Action and resource target
- Destination and recipient
- Payload object
- Authorization context
- Expected side-effect type
- Actual executor invocation status (ATTEMPTED, ADMITTED, INVOKED, COMPLETED, ROLLED_BACK, HALTED)
"""

import threading
import uuid
import time
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Callable


class OperationStatus(Enum):
    ATTEMPTED = "ATTEMPTED"
    ADMITTED = "ADMITTED"
    INVOKED = "INVOKED"
    COMPLETED = "COMPLETED"
    ROLLED_BACK = "ROLLED_BACK"
    HALTED = "HALTED"


class SecurityOutcomeStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNTESTED = "UNTESTED"
    BLOCKED_BY_ARCHITECTURE = "BLOCKED_BY_ARCHITECTURE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class OperationRequest:
    agent_id: str
    request_id: str
    action: str
    resource: str
    destination: Optional[str] = None
    payload: Optional[Dict[str, Any]] = field(default_factory=dict)
    authorization_context: Optional[Dict[str, Any]] = field(default_factory=dict)
    expected_side_effect: Optional[str] = None
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OperationExecutionRecord:
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request: Optional[OperationRequest] = None
    status: OperationStatus = OperationStatus.ATTEMPTED
    intercepting_gate: Optional[str] = None
    executor_invoked: bool = False
    completed: bool = False
    side_effects_produced: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    provenance_event_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, OperationStatus) else str(self.status)
        return d


class ObservableOperationExecutor:
    """
    Instrumented operation executor tracking attempted, admitted, invoked,
    completed, and rolled back operations alongside side-effect records.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.records: List[OperationExecutionRecord] = []
        self.attempts_count: int = 0
        self.invocations_count: int = 0
        self.completions_count: int = 0
        self.halts_count: int = 0

    def record_attempt(self, request: OperationRequest) -> OperationExecutionRecord:
        with self.lock:
            self.attempts_count += 1
            rec = OperationExecutionRecord(
                request=request,
                status=OperationStatus.ATTEMPTED,
                executor_invoked=False,
                completed=False
            )
            self.records.append(rec)
            return rec

    def record_halt(self, record: OperationExecutionRecord, intercepting_gate: str, reason: str):
        with self.lock:
            self.halts_count += 1
            record.status = OperationStatus.HALTED
            record.intercepting_gate = intercepting_gate
            record.error_message = reason

    def execute_instrumented(
        self,
        record: OperationExecutionRecord,
        executor_func: Callable[[], Any],
        side_effect_extractor: Optional[Callable[[Any], Dict[str, Any]]] = None
    ) -> Any:
        with self.lock:
            record.status = OperationStatus.INVOKED
            record.executor_invoked = True
            self.invocations_count += 1

        try:
            result = executor_func()
            with self.lock:
                record.status = OperationStatus.COMPLETED
                record.completed = True
                self.completions_count += 1
                if side_effect_extractor:
                    record.side_effects_produced = side_effect_extractor(result)
            return result
        except Exception as e:
            with self.lock:
                record.status = OperationStatus.ROLLED_BACK
                record.completed = False
                record.error_message = str(e)
            raise

    def reset(self):
        with self.lock:
            self.records.clear()
            self.attempts_count = 0
            self.invocations_count = 0
            self.completions_count = 0
            self.halts_count = 0
