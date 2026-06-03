"""
pramagent.errors
================
Structured error taxonomy for consistent API + layer responses.

Every PramagentError carries:
  code     — machine-readable string (e.g. "INJECTION_DETECTED")
  message  — human-readable description
  layer    — which layer raised it (e.g. "IsolationLayer")
  detail   — optional structured payload (findings, schema violation, etc.)

HTTP mapping is defined here so the API layer never has to guess status codes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class PramagentError(Exception):
    code: str
    message: str
    layer: str = ""
    detail: Optional[Any] = None
    http_status: int = 400

    def to_dict(self) -> dict:
        return {
            "error": self.code,
            "message": self.message,
            "layer": self.layer,
            "detail": self.detail,
        }

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


# ── error catalogue ───────────────────────────────────────────────────────────

class Errors:
    """Factory methods for every well-known error code."""

    # 4xx — client / request errors
    @staticmethod
    def injection_detected(findings: list) -> PramagentError:
        return PramagentError(
            code="INJECTION_DETECTED",
            message="Prompt injection patterns detected in input",
            layer="IsolationLayer",
            detail={"findings": findings},
            http_status=400,
        )

    @staticmethod
    def input_too_large(size: int, limit: int) -> PramagentError:
        return PramagentError(
            code="INPUT_TOO_LARGE",
            message=f"Input size {size} bytes exceeds limit {limit} bytes",
            layer="IsolationLayer",
            detail={"size_bytes": size, "limit_bytes": limit},
            http_status=413,
        )

    @staticmethod
    def tool_blocked(tool: str, reason: str) -> PramagentError:
        return PramagentError(
            code="TOOL_BLOCKED",
            message=f"Tool '{tool}' was blocked by policy",
            layer="ToolGuardLayer",
            detail={"tool": tool, "reason": reason},
            http_status=403,
        )

    @staticmethod
    def tool_schema_violation(tool: str, reason: str) -> PramagentError:
        return PramagentError(
            code="TOOL_SCHEMA_VIOLATION",
            message=f"Tool '{tool}' arguments failed schema validation",
            layer="ToolGuardLayer",
            detail={"tool": tool, "schema_reason": reason},
            http_status=422,
        )

    @staticmethod
    def tool_injection(tool: str, findings: list) -> PramagentError:
        return PramagentError(
            code="TOOL_ARG_INJECTION",
            message=f"Injection patterns detected in arguments for tool '{tool}'",
            layer="ToolGuardLayer",
            detail={"tool": tool, "findings": findings},
            http_status=400,
        )

    @staticmethod
    def output_exfiltration(tool: str, findings: list) -> PramagentError:
        return PramagentError(
            code="OUTPUT_EXFILTRATION",
            message=f"Sensitive data detected in output of tool '{tool}'",
            layer="ToolGuardLayer",
            detail={"tool": tool, "findings": findings},
            http_status=502,
        )

    @staticmethod
    def safety_blocked(rule_ids: list[str]) -> PramagentError:
        return PramagentError(
            code="SAFETY_BLOCKED",
            message="Response blocked by safety rule",
            layer="SafetyLayer",
            detail={"rules": rule_ids},
            http_status=400,
        )

    @staticmethod
    def hitl_idle(action: str) -> PramagentError:
        return PramagentError(
            code="HITL_IDLE",
            message=f"Action '{action}' requires human approval — no approver responded",
            layer="HITLLayer",
            detail={"action": action},
            http_status=202,  # Accepted but not executed
        )

    @staticmethod
    def hitl_denied(action: str) -> PramagentError:
        return PramagentError(
            code="HITL_DENIED",
            message=f"Action '{action}' was denied by a human approver",
            layer="HITLLayer",
            detail={"action": action},
            http_status=403,
        )

    # 5xx — infrastructure errors
    @staticmethod
    def circuit_open(component: str) -> PramagentError:
        return PramagentError(
            code="CIRCUIT_OPEN",
            message=f"{component} circuit breaker is open — service temporarily unavailable",
            layer="ReliabilityLayer",
            detail={"component": component},
            http_status=503,
        )

    @staticmethod
    def provider_error(provider: str, exc: str) -> PramagentError:
        return PramagentError(
            code="PROVIDER_ERROR",
            message=f"LLM provider '{provider}' returned an error",
            layer="ReliabilityLayer",
            detail={"provider": provider, "exception": exc},
            http_status=502,
        )

    @staticmethod
    def rate_limited(retry_after: float) -> PramagentError:
        return PramagentError(
            code="RATE_LIMITED",
            message="Request rate limit exceeded",
            layer="RateLimiter",
            detail={"retry_after_s": retry_after},
            http_status=429,
        )

    @staticmethod
    def backend_unavailable(backend: str, exc: str) -> PramagentError:
        return PramagentError(
            code="BACKEND_UNAVAILABLE",
            message=f"Backend '{backend}' is unavailable",
            layer="Backend",
            detail={"backend": backend, "exception": exc},
            http_status=503,
        )

    @staticmethod
    def isolation_violation(scope: str) -> PramagentError:
        return PramagentError(
            code="ISOLATION_VIOLATION",
            message="Tenant or session scope violation detected",
            layer="IsolationLayer",
            detail={"scope": scope},
            http_status=403,
        )

    @staticmethod
    def llm_judge_blocked(tool: str, reason: str) -> PramagentError:
        return PramagentError(
            code="LLM_JUDGE_BLOCKED",
            message=f"Tool '{tool}' call rejected by LLM safety judge",
            layer="ToolGuardLayer.LLMJudge",
            detail={"tool": tool, "reason": reason},
            http_status=403,
        )


# ── HTTP status helper ────────────────────────────────────────────────────────

HTTP_STATUS_MESSAGES = {
    400: "Bad Request",
    402: "Payment Required",
    403: "Forbidden",
    413: "Payload Too Large",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}
