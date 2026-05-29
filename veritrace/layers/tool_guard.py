"""Tool-use guardrails for agent actions.

The guard is intentionally deterministic. It does not execute tools; it decides
whether a proposed tool call is allowed before the agent can perform a side
effect. This is the missing boundary between "chat wrapper" and "agent
middleware".
"""
from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from ..types import Verdict


class ToolGuardError(ValueError):
    pass


@dataclass
class ToolPolicy:
    name: str
    schema: dict[str, Any]
    side_effect: str = "read"
    action: Verdict = Verdict.ALLOW
    allowed_tenants: Optional[set[str]] = None
    allowed_actions: Optional[set[str]] = None
    max_calls_per_session: Optional[int] = None
    detail: str = ""


@dataclass
class ToolDecision:
    decision_id: str
    tool_name: str
    tenant_id: str
    session_id: str
    action_label: str
    verdict: Verdict
    reason: str
    side_effect: str
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "tool_name": self.tool_name,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "action_label": self.action_label,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "side_effect": self.side_effect,
            "created_at": self.created_at,
        }


class ToolGuardLayer:
    """Validates proposed tool calls against explicit per-tool policies."""

    def __init__(
        self,
        policies: list[ToolPolicy] | None = None,
        *,
        default_verdict: Verdict = Verdict.BLOCK,
    ) -> None:
        self.policies = {p.name: p for p in (policies or [])}
        self.default_verdict = default_verdict
        self._calls_by_session: dict[tuple[str, str, str], int] = {}
        self.audit_log: list[ToolDecision] = []

    def register(self, policy: ToolPolicy) -> None:
        self.policies[policy.name] = policy

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        tenant_id: str,
        session_id: str,
        action_label: str = "tool_call",
    ) -> ToolDecision:
        policy = self.policies.get(tool_name)
        if policy is None:
            return self._record(
                tool_name, tenant_id, session_id, action_label,
                self.default_verdict, "tool is not registered", "unknown")

        if policy.allowed_tenants is not None and tenant_id not in policy.allowed_tenants:
            return self._record(
                tool_name, tenant_id, session_id, action_label,
                Verdict.BLOCK, "tenant is not allowed to use this tool", policy.side_effect)

        if policy.allowed_actions is not None and action_label not in policy.allowed_actions:
            return self._record(
                tool_name, tenant_id, session_id, action_label,
                Verdict.BLOCK, "action label is not allowed for this tool", policy.side_effect)

        ok, reason = validate_schema(arguments, policy.schema)
        if not ok:
            return self._record(
                tool_name, tenant_id, session_id, action_label,
                Verdict.BLOCK, reason, policy.side_effect)

        key = (tenant_id, session_id, tool_name)
        count = self._calls_by_session.get(key, 0)
        if policy.max_calls_per_session is not None and count >= policy.max_calls_per_session:
            return self._record(
                tool_name, tenant_id, session_id, action_label,
                Verdict.BLOCK, "session tool-call limit exceeded", policy.side_effect)

        self._calls_by_session[key] = count + 1
        return self._record(
            tool_name, tenant_id, session_id, action_label,
            policy.action, policy.detail or "tool call allowed by policy", policy.side_effect)

    def _record(
        self,
        tool_name: str,
        tenant_id: str,
        session_id: str,
        action_label: str,
        verdict: Verdict,
        reason: str,
        side_effect: str,
    ) -> ToolDecision:
        decision = ToolDecision(
            decision_id=str(uuid.uuid4()),
            tool_name=tool_name,
            tenant_id=tenant_id,
            session_id=session_id,
            action_label=action_label,
            verdict=verdict,
            reason=reason,
            side_effect=side_effect,
        )
        self.audit_log.append(decision)
        return decision


def validate_schema(value: Any, schema: dict[str, Any], *, path: str = "$") -> tuple[bool, str]:
    expected_type = schema.get("type")
    if expected_type:
        ok = _type_ok(value, expected_type)
        if not ok:
            return False, f"{path} expected {expected_type}"

    if "enum" in schema and value not in schema["enum"]:
        return False, f"{path} must be one of {schema['enum']}"

    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                return False, f"{path}.{key} is required"
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in properties:
                ok, reason = validate_schema(item, properties[key], path=f"{path}.{key}")
                if not ok:
                    return ok, reason
            elif additional is False:
                return False, f"{path}.{key} is not allowed"

    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return False, f"{path} exceeds maxItems"
        if "minItems" in schema and len(value) < schema["minItems"]:
            return False, f"{path} is below minItems"
        item_schema = schema.get("items")
        if item_schema:
            for idx, item in enumerate(value):
                ok, reason = validate_schema(item, item_schema, path=f"{path}[{idx}]")
                if not ok:
                    return ok, reason

    if isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return False, f"{path} exceeds maxLength"
        if "minLength" in schema and len(value) < schema["minLength"]:
            return False, f"{path} is below minLength"
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            return False, f"{path} does not match required pattern"

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return False, f"{path} is below minimum"
        if "maximum" in schema and value > schema["maximum"]:
            return False, f"{path} exceeds maximum"

    return True, ""


def _type_ok(value: Any, expected: str | list[str]) -> bool:
    if isinstance(expected, list):
        return any(_type_ok(value, item) for item in expected)
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)
