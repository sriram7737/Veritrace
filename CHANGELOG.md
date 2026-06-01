# Changelog

## v0.4.0 - 2026-06-01

This release adds two high-leverage production-adjacent capabilities while
keeping the claims honest: Veritrace is stronger guardrail and audit middleware,
not certified bank-grade infrastructure.

### Added

- Optional Ethereum/Sepolia anchoring for audit hash heads via `web3.py`.
- Trace anchor metadata: transaction hash, block number, status, chain ID, and
  anchored hash.
- Optional encrypted S3 cold archive wrapper for retention and erasure flows.
- Tests for Ethereum anchoring, fail-open behavior, S3 archive/restore, and
  tenant-scoped archive access.
- First published local smoke-load result.

### Changed

- Package/API version bumped to `0.4.0`.
- Design and status docs now call out Ethereum and S3 as MVP features with
  clear hardening gaps.

### Still Not Proven

- No live Sepolia transaction was run in this checkout because no RPC/private
  key was provided.
- No Docker/Postgres/Redis sustained load test was run because Docker is not
  installed in this environment.
- No external penetration test, SSO/RBAC dashboard hardening, or production key
  management story exists yet.

