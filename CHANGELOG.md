# Changelog

## Unreleased

### Added

- In-memory hash-chain usage ledger for pilot billing/analytics evidence.
- `/v1/usage/ledger` and `/usage/ledger` endpoints for ledger inspection.
- `ServiceNowNotifier` as a notify-only HITL escalation adapter.
- Hardening guide that turns the release-gap critique into concrete next steps.
- `MANIFEST.in` and wheel data-file config so implementation status,
  hardening, live-test, red-team, load-test, deployment, and release docs ship
  with distributions.

### Changed

- Usage event sink failures now re-raise when `fail_open=False`.
- README, deployment docs, and implementation status now distinguish local
  ledger evidence from Stripe/Chargebee-grade billing.
- PyPI/package positioning now explicitly says Alpha and points users to live
  test results, implementation status, and the hardening guide.

## v0.4.1 - 2026-06-01

This is a release-hardening patch for packaging, CLI validation, and red-team
smoke testing.

### Added

- PyPI-facing project metadata: classifiers, project URLs, and an `all` extra.
- README install instructions for PyPI and source installs.
- Release checklist covering build, twine check, GitHub tag/release, and PyPI
  publish commands.
- Dynamic red-team validation result:
  `veritrace redteam --json --dynamic --attacks 200 --seed 999`.

### Verified

- `veritrace --help` works from the installed console script.
- `[project.scripts]` exposes `veritrace = "veritrace.cli:main"`.
- `pip install -e .` succeeds.
- Dynamic red-team run caught 200/200 prompts with 0 false positives for seed
  `999`.

### Still Not Proven

- Package is prepared for PyPI, but publishing still requires a PyPI API token.
- Dashboard auth remains MVP-level; no SSO/OIDC/RBAC yet.
- Dynamic red-team mode is useful smoke testing, not third-party jailbreak
  assurance.

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
- Authenticated Docker Compose load validation: 10 minutes, 12,000 requests,
  0 errors, 0 HTTP 5xx, with Redis/Postgres/dashboard healthy after the run.
- Red-team CLI can now run a 100-prompt built-in smoke corpus with
  `veritrace redteam --json --attacks 100`.
- Red-team CLI now supports runtime prompt mutation with reproducible seeds:
  `veritrace redteam --json --dynamic --attacks 100 --seed 123`.

### Changed

- Package/API version bumped to `0.4.0`.
- Design and status docs now call out Ethereum and S3 as MVP features with
  clear hardening gaps.
- Keyword fallback catches classic developer-mode, DAN, indirect tool-output,
  delimiter, and exfiltration jailbreaks in the bundled corpus.
- Keyword fallback was tightened against dynamic variants such as debug mode,
  unrestricted persona, supersede/replace overrides, private data, and system
  directive exfiltration.

### Still Not Proven

- No third-party red-team benchmark, chaos run, or external penetration test has
  been completed.
- No mainnet anchoring, deployed verifier contract, or production key-management
  runbook exists yet.
- No external penetration test, SSO/RBAC dashboard hardening, or formal
  compliance certification exists yet.
