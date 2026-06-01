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
- Live Sepolia validation:
  `0x8d0d7bd15c377224acee00f397272bab1007c757080f19523cfc66c8461b5d99`.
- Live AWS S3 archive/restore validation with encrypted fake trace data.
- First published local smoke-load result.

### Changed

- Package/API version bumped to `0.4.0`.
- Design and status docs now call out Ethereum and S3 as MVP features with
  clear hardening gaps.

### Still Not Proven

- No Docker/Postgres/Redis sustained load test was run because Docker is not
  installed in this environment.
- No mainnet anchoring, deployed verifier contract, or production key-management
  runbook exists yet.
- No external penetration test, SSO/RBAC dashboard hardening, or formal
  compliance certification exists yet.
