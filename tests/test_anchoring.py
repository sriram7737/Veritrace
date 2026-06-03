"""Tests for optional blockchain audit anchoring (Ethereum + Hyperledger stubs)."""
from pramagent.audit import (HashChainBackend, EthereumBackend,
                             HyperledgerBackend)


def test_ethereum_backend_anchors_and_verifies():
    eb = EthereumBackend()
    h1, tx1 = eb.append({"a": 1})
    h2, tx2 = eb.append({"b": 2})
    assert tx1.startswith("eth:")
    assert eb.verify_chain() is True
    assert h1 != h2


def test_hyperledger_backend_anchors_and_verifies():
    hb = HyperledgerBackend(channel="audit", chaincode="anchor")
    h1, tx1 = hb.append({"x": 1})
    h2, tx2 = hb.append({"y": 2})
    # no live gateway -> local pseudo-anchor, but chain still valid
    assert tx1.startswith("fabric-local:")
    assert hb.verify_chain() is True
    assert len(hb.records()) == 2


def test_hyperledger_same_interface_as_hashchain():
    hb = HyperledgerBackend()
    plain = HashChainBackend()
    for backend in (hb, plain):
        backend.append({"k": "v"})
        assert backend.verify_chain() is True
        assert backend.head != "0" * 64


def test_hyperledger_tamper_detection():
    hb = HyperledgerBackend()
    hb.append({"amount": 100})
    hb.append({"amount": 200})
    # tamper with a stored record
    hb.records()[0]["payload"]["amount"] = 999
    assert hb.verify_chain() is False
