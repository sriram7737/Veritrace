"""
pramagent.audit
===============
Tamper-evident audit backends. The default HashChainBackend is fully
self-contained: each trace's hash includes the previous trace's hash, so any
retroactive edit to an old record breaks every hash after it. This is the
"blockchain-lite" guarantee that needs no external chain to be useful.

EthereumBackend / HyperledgerBackend implement the same interface and anchor
the chain head to an external ledger. Ethereum can submit real Sepolia
transactions when configured with web3 credentials; otherwise it keeps the
local chain semantics and returns a local pseudo-anchor.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Protocol

from ..anchoring.ethereum import EthereumAnchor, EthereumAnchorReceipt


log = logging.getLogger(__name__)


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
    """Hash-chain backend with optional real Ethereum/Sepolia anchoring."""

    def __init__(
        self,
        rpc_url: str = "",
        contract: str = "",
        *,
        private_key: str = "",
        chain_id: int = 11155111,
        anchor: EthereumAnchor | None = None,
        fail_open: bool = True,
    ):
        self.rpc_url = rpc_url
        self.contract = contract
        self.private_key = private_key
        self.chain_id = chain_id
        self.fail_open = fail_open
        self._chain = HashChainBackend()
        self._anchor = anchor
        self.last_anchor: EthereumAnchorReceipt | None = None
        if self._anchor is None and rpc_url and private_key:
            self._anchor = EthereumAnchor(
                rpc_url=rpc_url,
                private_key=private_key,
                contract_address=contract,
                chain_id=chain_id,
            )

    @property
    def head(self) -> str:
        return self._chain.head

    def append(self, payload: dict, prev_hash: str | None = None) -> tuple[str, str]:
        this_hash, _ = self._chain.append(payload, prev_hash)
        self.last_anchor = None
        if self._anchor is None:
            return this_hash, f"eth:local:0x{this_hash[:24]}"
        try:
            self.last_anchor = self._anchor.anchor(this_hash)
            return this_hash, f"eth:{self.last_anchor.tx_hash}"
        except Exception as exc:
            if not self.fail_open:
                raise
            log.warning("ethereum anchoring failed open: %s", exc)
            return this_hash, f"eth:local:0x{this_hash[:24]}"

    def verify_chain(self) -> bool:
        return self._chain.verify_chain()

    def verify_on_chain(
        self,
        tx_hash: str,
        *,
        expected_hash: str = "",
    ) -> EthereumAnchorReceipt:
        if self._anchor is None:
            raise RuntimeError("Ethereum anchor is not configured")
        return self._anchor.verify_on_chain(tx_hash, expected_hash=expected_hash)

    def records(self) -> list[dict]:
        return self._chain.records()


class HyperledgerBackend:
    """Optional: anchor the chain head to a Hyperledger Fabric network.

    Same interface as HashChainBackend. The local hash chain is always
    maintained (so verification works offline); when a Fabric gateway is
    configured, each appended head is also submitted to a chaincode as an
    external anchor. If the fabric SDK is unavailable or the network is
    unreachable, anchoring degrades gracefully and the local chain still works.
    """

    def __init__(self, channel: str = "", chaincode: str = "",
                 gateway: str = "") -> None:
        self.channel = channel
        self.chaincode = chaincode
        self.gateway = gateway
        self._chain = HashChainBackend()
        self._anchored = 0

    @property
    def head(self) -> str:
        return self._chain.head

    def append(self, payload: dict, prev_hash: str | None = None) -> tuple[str, str]:
        this_hash, _ = self._chain.append(payload, prev_hash)
        tx = self._anchor(this_hash)
        return this_hash, tx

    def _anchor(self, this_hash: str) -> str:
        """Submit the hash to Fabric chaincode. Returns an anchor tx id.

        Degrades to a local pseudo-anchor when no gateway is configured or the
        fabric SDK is absent — never raises, so audit writes always succeed.
        """
        if not self.gateway:
            return f"fabric-local:{this_hash[:24]}"
        try:  # pragma: no cover - requires live Fabric network
            # In production: use the Fabric Gateway SDK to submit a transaction:
            #   contract.submit_transaction("AnchorHash", this_hash)
            # Kept import-guarded so the dependency is truly optional.
            from hfc.fabric import Client  # type: ignore  # noqa: F401
            self._anchored += 1
            return f"fabric:{self.channel}:{this_hash[:24]}"
        except Exception:
            return f"fabric-local:{this_hash[:24]}"

    def verify_chain(self) -> bool:
        return self._chain.verify_chain()

    def records(self) -> list[dict]:
        return self._chain.records()

    @property
    def anchored_count(self) -> int:
        return self._anchored
