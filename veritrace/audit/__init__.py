"""
veritrace.audit
===============
Tamper-evident audit backends. The default HashChainBackend is fully
self-contained: each trace's hash includes the previous trace's hash, so any
retroactive edit to an old record breaks every hash after it. This is the
"blockchain-lite" guarantee that needs no external chain to be useful.

EthereumBackend / HyperledgerBackend implement the same interface and anchor
the chain head to an external ledger; they are stubbed here as the integration
points for later phases.
"""
from __future__ import annotations

import hashlib
import json
from typing import Protocol


def canonical_hash(payload: dict, prev_hash: str) -> str:
    """
    Deterministic SHA-256 over the canonical JSON of the payload plus the
    previous hash. Sorting keys guarantees the same bytes every time, which is
    what makes verification and decision-replay possible.
    """
    material = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "|" + prev_hash
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditBackend(Protocol):
    def append(self, payload: dict, prev_hash: str) -> tuple[str, str]:
        """Return (this_hash, anchor_tx_id)."""
        ...

    def verify_chain(self) -> bool:
        ...


class HashChainBackend:
    """Self-contained, in-memory (or file-backed) tamper-evident hash chain."""

    GENESIS = "0" * 64

    def __init__(self) -> None:
        self._records: list[dict] = []   # each: {payload, prev_hash, this_hash}
        self._head: str = self.GENESIS

    @property
    def head(self) -> str:
        return self._head

    def append(self, payload: dict, prev_hash: str | None = None) -> tuple[str, str]:
        prev = prev_hash if prev_hash is not None else self._head
        this_hash = canonical_hash(payload, prev)
        self._records.append({"payload": payload, "prev_hash": prev, "this_hash": this_hash})
        self._head = this_hash
        # anchor_tx_id is local for HashChain; external backends return a real tx id
        return this_hash, f"local:{this_hash[:16]}"

    def verify_chain(self) -> bool:
        """Recompute every hash; return False if any link is broken (tampering)."""
        prev = self.GENESIS
        for rec in self._records:
            expected = canonical_hash(rec["payload"], prev)
            if expected != rec["this_hash"] or rec["prev_hash"] != prev:
                return False
            prev = rec["this_hash"]
        return True

    def records(self) -> list[dict]:
        return list(self._records)


class EthereumBackend:
    """Stub: anchors the chain head to Ethereum. Same interface as HashChain."""
    def __init__(self, rpc_url: str = "", contract: str = ""):
        self.rpc_url, self.contract = rpc_url, contract
        self._chain = HashChainBackend()

    def append(self, payload: dict, prev_hash: str | None = None) -> tuple[str, str]:
        this_hash, _ = self._chain.append(payload, prev_hash)
        # In production: submit this_hash to the smart contract, return real tx hash.
        return this_hash, f"eth:0x{this_hash[:24]}"

    def verify_chain(self) -> bool:
        return self._chain.verify_chain()
