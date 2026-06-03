# Changelog

## v0.5.0 - 2026-06-02

This release completes the public rebrand to Pramagent. It is a
breaking package-name and import-path change.

### Changed

- PyPI/project package renamed to `pramagent`.
- Python import path renamed to `pramagent`.
- Console command renamed to `pramagent`.
- Public API class renamed to `Pramagent`.
- Environment variables, Docker Compose service config, dashboard cookies,
  docs, release notes, and deployment examples now use `PRAMAGENT_*` and
  Pramagent naming.
- Design document filename changed to `docs/Pramagent-Design-Document.docx`.

### Migration

- New installs: `pip install pramagent`
- New imports: `from pramagent import Pramagent`
- New CLI: `pramagent --help`

### Still Not Proven

- This remains Alpha software. The rebrand does not add external certification,
  SSO/OIDC/RBAC, or third-party jailbreak assurance.

## v0.4.4 - 2026-06-02

This is a PyPI listing cleanup patch. It does not change runtime behavior.

### Changed

- Removed the external Pepy downloads badge from README because it rendered as
  a broken image on PyPI for the newly published project.
- Package/API version bumped to `0.4.4`.

## v0.4.3 - 2026-06-02

This is a PyPI/GitHub listing-quality patch. It does not add new runtime
security claims.

### Changed

- README doc links now use absolute GitHub URLs so PyPI does not rewrite them
  into broken `pypi.org/project/pramagent/docs/...` links.
- README now leads with badges, a sharper ToolGuard-first pitch, an inline
  trust-stack diagram, and a bare-install example that works with
  `pip install pramagent`.
- README no longer contains pre-launch wording about PyPI publication.
- Project metadata now includes an Author URL.
- Release checklist and deployment example were updated for `v0.4.3`.

### Still Not Proven

- This remains an Alpha release: no external penetration test, no SSO/OIDC/RBAC,
  no production compliance certification, and no third-party jailbreak
  assurance.

## v0.4.2 - 2026-06-02

### Added

- In-memory hash-chain usage ledger for pilot billing/analytics evidence.
- `/v1/usage/ledger` and `/usage/ledger` endpoints for ledger inspection.
- `ServiceNowNotifier` as a notify-only HITL escalation adapter.
- Hardening guide that turns the release-gap critique into concrete next steps.
- `MANIFEST.in` and wheel data-file config so implementation status,
  hardening, live-test, red-team, load-test, deployment, and release docs ship
  with distributions.
- Live OpenAI and local Ollama smoke-test results in `docs/LIVE_TEST_RESULTS.md`.
- GitHub Actions test matrix now covers Python 3.10, 3.11, 3.12, and 3.13 with
  upgraded pip/setuptools/wheel.

### Changed

- Usage event sink failures now re-raise when `fail_open=False`.
- README, deployment docs, and implementation status now distinguish local
  ledger evidence from Stripe/Chargebee-grade billing.
- PyPI/package positioning now explicitly says Alpha and points users to live
  test results, implementation status, and the hardening guide.
- OpenAI-compatible providers now retry with `max_completion_tokens` when a
  newer OpenAI model rejects legacy `max_tokens`.
- The `dashboard` extra now includes FastAPI/uvicorn so it can be installed
  independently from the `api` extra.

## v0.4.1 - 2026-06-01

This is a release-hardening patch for packaging, CLI validation, and red-team
smoke testing.

### Added

- PyPI-facing project metadata: classifiers, project URLs, and an `all` extra.
- README install instructions for PyPI and source installs.
- Release checklist covering build, twine check, GitHub tag/release, and PyPI
  publish commands.
- Dynamic red-team validation result:
  `pramagent redteam --json --dynamic --attacks 200 --seed 999`.

### Verified

- `pramagent --help` works from the installed console script.
- `[project.scripts]` exposes `pramagent = "pramagent.cli:main"`.
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
keeping the claims honest: Pramagent is stronger guardrail and audit middleware,
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
  `pramagent redteam --json --attacks 100`.
- Red-team CLI now supports runtime prompt mutation with reproducible seeds:
  `pramagent redteam --json --dynamic --attacks 100 --seed 123`.

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
