r"""
Pramagent - trust middleware for AI agents: deterministic guardrails, HITL,
tool policy, and tamper-evident traces.

Quick start
-----------
    import asyncio
    from pramagent import Pramagent
    from pramagent.layers import SafetyLayer, Rule
    from pramagent.types import Verdict

    armor = Pramagent(
        safety=SafetyLayer(rules=[
            Rule("no_account_disclosure", Verdict.BLOCK, pattern=r"acct[-_ ]?\d{6,}"),
        ])
    )
    resp = asyncio.run(armor.run("Hello", tenant_id="acme", session_id="s1"))
    print(resp.output)
    print(resp.trace.this_hash)
"""
from .core import Pramagent
from .layers import (ComplianceLayer, HITLLayer, IsolationLayer,
                     ObservabilityLayer, ReliabilityLayer, Rule, SafetyLayer,
                     ToolDecision, ToolGuardLayer, ToolPolicy)
from .providers import (AnthropicProvider, BaseProvider, FallbackProvider,
                        GeminiProvider, MockProvider, OllamaProvider,
                        OpenAICompatibleProvider, OpenAIProvider)
from .store import MemoryStore, SQLiteStore
from .auth import APIKeyRegistry, JWTManager
from .otel import OpenTelemetryExporter, OpenTelemetryNotInstalled
from .anchoring import EthereumAnchor, EthereumAnchorReceipt
from .redteam import RedTeamReport, run_injection_benchmark
from .types import AgentResponse, HITLStatus, TraceEvent, Verdict
from .usage import (
    InMemoryUsageLedger,
    InMemoryUsageSink,
    UsageLedgerEntry,
    UsageDecision,
    UsageEvent,
    UsageEventSink,
    UsageLimits,
    UsageSnapshot,
    UsageTracker,
    WebhookUsageSink,
)

__version__ = "0.5.5"
__all__ = [
    "Pramagent",
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
    "UsageTracker",
    "UsageLimits",
    "UsageSnapshot",
    "UsageDecision",
    "UsageEvent",
    "UsageEventSink",
    "UsageLedgerEntry",
    "InMemoryUsageLedger",
    "InMemoryUsageSink",
    "WebhookUsageSink",
    "run_injection_benchmark",
    "RedTeamReport",
    "OpenTelemetryExporter",
    "OpenTelemetryNotInstalled",
    "EthereumAnchor",
    "EthereumAnchorReceipt",
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
