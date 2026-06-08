"""
pramagent.adapters.langgraph
============================
LangGraph adapter. Drop a ``PramagentNode`` into any state graph and every
message passing through it is run through the Pramagent trust pipeline before
your downstream nodes see it.

Usage::

    from langgraph.graph import StateGraph
    from pramagent import Pramagent, SafetyLayer
    from pramagent.rules import JAILBREAK_PATTERNS, OWASP_LLM_TOP10
    from pramagent.adapters.langgraph import PramagentNode

    armor = Pramagent(safety=SafetyLayer(rules=[*JAILBREAK_PATTERNS, *OWASP_LLM_TOP10]))

    graph = StateGraph(MyState)
    graph.add_node("guard", PramagentNode(armor=armor))
    graph.add_edge("guard", "llm")
    # ...

The node reads ``state["messages"]`` (or whatever ``input_key`` you set) and
writes ``state["pramagent_trace"]`` with the trace id, verdict, and any
redactions so downstream nodes can branch on the result.
"""
from __future__ import annotations

from typing import Any, Optional

from ..core import Pramagent
from ..types import AgentResponse


class PramagentNode:
    """A LangGraph-compatible node that runs Pramagent on the latest input.

    Parameters
    ----------
    armor : Pramagent
        Pre-configured orchestrator.
    input_key : str
        Key in the state dict to read the prompt from. Default: ``"input"``.
        If ``input_key`` is ``"messages"``, the LAST message's content is used.
    output_key : str
        Key to write the (post-guard) text under. Default: ``"output"``.
    block_key : str
        Key set to True when Pramagent blocked the call. Default: ``"blocked"``.
    tenant_key, session_key : str
        Keys to read tenant/session ids from the state. Default: ``"tenant_id"`` / ``"session_id"``.
    action : str
        Action label for HITL. Default: ``"respond"``.
    """

    def __init__(self, armor: Pramagent, *,
                 input_key: str = "input",
                 output_key: str = "output",
                 block_key: str = "blocked",
                 tenant_key: str = "tenant_id",
                 session_key: str = "session_id",
                 action: str = "respond"):
        self.armor = armor
        self.input_key = input_key
        self.output_key = output_key
        self.block_key = block_key
        self.tenant_key = tenant_key
        self.session_key = session_key
        self.action = action

    def _extract_prompt(self, state: dict) -> str:
        val = state.get(self.input_key, "")
        # LangGraph 'messages' shape: list of dicts or BaseMessage objects
        if self.input_key == "messages" and isinstance(val, list) and val:
            last = val[-1]
            if isinstance(last, dict):
                return str(last.get("content", ""))
            return str(getattr(last, "content", last))
        return str(val)

    async def __call__(self, state: dict) -> dict:
        prompt = self._extract_prompt(state)
        resp: AgentResponse = await self.armor.run(
            prompt,
            tenant_id=str(state.get(self.tenant_key, "default")),
            session_id=str(state.get(self.session_key, "default")),
            action=self.action,
        )
        update = {
            self.output_key: resp.output,
            self.block_key: resp.blocked,
            "pramagent_trace": {
                "call_id": resp.trace.call_id,
                "this_hash": resp.trace.this_hash,
                "pre_verdict": resp.trace.pre_verdict,
                "post_verdict": resp.trace.post_verdict,
                "pii_redactions": list(resp.trace.pii_redactions),
                "hitl_status": resp.trace.hitl_status,
                "block_reason": resp.block_reason,
            },
        }
        return update

    # LangGraph synchronous variant
    def invoke(self, state: dict) -> dict:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Re-entrant: schedule on a new loop in a worker thread.
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    return ex.submit(asyncio.run, self.__call__(state)).result()
        except RuntimeError:
            pass
        return asyncio.run(self.__call__(state))


def install(graph, *, armor: Pramagent, name: str = "pramagent",
            before: Optional[str] = None, after: Optional[str] = None) -> str:
    """Add ``PramagentNode`` to an existing graph and optionally splice it
    between two other nodes. Returns the node name.
    """
    node = PramagentNode(armor=armor)
    graph.add_node(name, node)
    if before is not None:
        graph.add_edge(name, before)
    if after is not None:
        graph.add_edge(after, name)
    return name


__all__ = ["PramagentNode", "install"]
