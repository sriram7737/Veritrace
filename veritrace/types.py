"""
veritrace.types
===============
Core data structures shared across all layers. Everything that flows through
the pipeline is one of these typed objects. Keeping them in one place makes the
contract between layers explicit and auditable.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Verdict(str, Enum):
    """Outcome of a safety evaluation."""
    ALLOW = "allow"          # proceed normally
    BLOCK = "block"          # stop unconditionally
    ESCALATE = "escalate"    # route to human / higher authority
    REDACT = "redact"        # proceed but with content removed


class HITLStatus(str, Enum):
    """Status of a human-in-the-loop decision."""
    NOT_REQUIRED = "not_required"   # action was low-risk; no approval needed
    AUTO = "auto"                   # auto-approved by policy
    APPROVED = "approved"           # a human approved
    DENIED = "denied"               # a human denied
    IDLE = "idle"                   # timed out with no response -> did nothing


@dataclass
class RuleResult:
    """Record of a single rule evaluation by the SafetyLayer rule engine."""
    rule_id: str
    fired: bool
    action: Verdict
    detail: str = ""


@dataclass
class LayerEvent:
    """
    A single decision made by a single layer. The ordered list of LayerEvents
    is the spine of the trace and the input to the RCA engine.
    """
    layer: str
    decision: str
    detail: str = ""
    latency_ms: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceEvent:
    """
    The complete, immutable record of one agent call. This is returned as a
    first-class field on every response (never a side channel) and is the unit
    that gets hash-chained and anchored.
    """
    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default"
    session_id: str = "default"
    created_at: float = field(default_factory=time.time)

    input_text: str = ""
    input_hash: str = ""
    output_text: str = ""

    pii_redactions: list[str] = field(default_factory=list)
    pre_verdict: Optional[str] = None
    post_verdict: Optional[str] = None
    rules_evaluated: list[RuleResult] = field(default_factory=list)

    provider: str = ""
    provider_model: str = ""
    provider_cost_usd: float = 0.0
    provider_latency_ms: float = 0.0
    used_fallback: bool = False

    hitl_status: str = HITLStatus.NOT_REQUIRED.value
    layer_events: list[LayerEvent] = field(default_factory=list)
    total_latency_ms: float = 0.0

    # hash-chain fields
    prev_hash: str = ""
    this_hash: str = ""
    anchor_tx_id: str = ""
    anchor_block_number: int = 0
    anchor_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "TraceEvent":
        """Reconstruct a TraceEvent from a dict (e.g. loaded from SQLite JSON)."""
        d = dict(d)  # shallow copy to avoid mutating caller's data
        d["rules_evaluated"] = [
            RuleResult(**{**r, "action": Verdict(r["action"])})
            for r in d.get("rules_evaluated", [])
        ]
        d["layer_events"] = [LayerEvent(**le) for le in d.get("layer_events", [])]
        return cls(**d)


@dataclass
class AgentResponse:
    """What the caller receives. `.output` is the safe text; `.trace` is always present."""
    output: str
    trace: TraceEvent
    blocked: bool = False
    block_reason: str = ""

    @property
    def hitl(self) -> str:
        return self.trace.hitl_status
