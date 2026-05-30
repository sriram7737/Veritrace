r"""
Veritrace — Verifiable Trust Infrastructure for Production AI Agents.

Quick start
-----------
    import asyncio
    from veritrace import Veritrace
    from veritrace.layers import SafetyLayer, Rule
    from veritrace.types import Verdict

    armor = Veritrace(
        safety=SafetyLayer(rules=[
            Rule("no_account_disclosure", Verdict.BLOCK, pattern=r"acct[-_ ]?\d{6,}"),
        ])
    )
    resp = asyncio.run(armor.run("Hello", tenant_id="acme", session_id="s1"))
    print(resp.output)
    print(resp.trace.this_hash)
"""
from .core import Veritrace
from .layers import (ComplianceLayer, HITLLayer, IsolationLayer,
                     ObservabilityLayer, ReliabilityLayer, Rule, SafetyLayer,
                     ToolDecision, ToolGuardLayer, ToolPolicy)
from .providers import (AnthropicProvider, BaseProvider, FallbackProvider,
                        GeminiProvider, MockProvider, OllamaProvider,
                        OpenAICompatibleProvider, OpenAIProvider)
from .store import MemoryStore, SQLiteStore
from .auth import APIKeyRegistry, JWTManager
from .otel import OpenTelemetryExporter, OpenTelemetryNotInstalled
from .types import AgentResponse, HITLStatus, TraceEvent, Verdict

__version__ = "0.2.0"
__all__ = [
    "Veritrace",
    "AgentResponse",
    "TraceEvent",
    "Verdict",
    "HITLStatus",
    "IsolationLayer",
    "ObservabilityLayer",
    "ComplianceLayer",
    "SafetyLayer",
    "ReliabilityLayer",
    "HITLLayer",
    "ToolGuardLayer",
    "ToolPolicy",
    "ToolDecision",
    "Rule",
    "MemoryStore",
    "SQLiteStore",
    "APIKeyRegistry",
    "JWTManager",
    "OpenTelemetryExporter",
    "OpenTelemetryNotInstalled",
    "BaseProvider",
    "MockProvider",
    "AnthropicProvider",
    "OpenAIProvider",
    "OpenAICompatibleProvider",
    "GeminiProvider",
    "OllamaProvider",
    "FallbackProvider",
    "__version__",
]
from .classifier import (
    build_classifier, EmbeddingInjectionClassifier, KeywordFallbackClassifier,
    INJECTION_EXEMPLARS, BENIGN_EXEMPLARS,
)
