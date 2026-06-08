# Pramagent Security Scan Report - 2026-06-07

This report records local static and dynamic security scans against Pramagent
after the June 7 hardening pass. It is engineering evidence, not a third-party
penetration test or certification.

## Scope

- Code scanned: `pramagent/` and `deploy/dashboard/`
- Dynamic target: local FastAPI sidecar on `http://127.0.0.1:8091`, scanned
  from Docker as `http://host.docker.internal:8091`
- OpenAPI target: `http://host.docker.internal:8091/openapi.json`
- Authenticated OpenAPI target: local sidecar with `Authorization: Bearer <ci test key>`
- Raw artifacts: `test-results/security/` (ignored by git; local evidence)

## Tool Versions

| Tool | Version / image |
|---|---|
| Bandit | `1.9.4` |
| Semgrep | `semgrep/semgrep@sha256:207983631beecdbe7fa29196c7f4a7a5f29033933cdb76c687ce4a672e07618d` |
| OWASP ZAP | `2.17.0`, `ghcr.io/zaproxy/zaproxy@sha256:2ec1d5d5b44d55cfd02ba9b89cd26852f06d92b7fc0ce9f064b9463babc73074` |

## Commands Run

```powershell
bandit -r pramagent deploy\dashboard -f json -o test-results\security\bandit_pramagent_20260607_postfix.json
bandit -r pramagent deploy\dashboard -f txt -o test-results\security\bandit_pramagent_20260607_postfix.txt

docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:latest `
  semgrep scan --no-git-ignore --metrics=off --config p/security-audit --config p/python `
  --json --output test-results/security/semgrep_pramagent_20260607_postfix.json `
  pramagent deploy/dashboard

docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:latest `
  semgrep scan --no-git-ignore --metrics=off --config p/security-audit --config p/python `
  --text --output test-results/security/semgrep_pramagent_20260607_postfix.txt `
  pramagent deploy/dashboard

docker run --rm -v "$PWD/test-results/security:/zap/wrk/:rw" `
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py `
  -t http://host.docker.internal:8091 `
  -J zap_baseline_20260607_postfix.json -r zap_baseline_20260607_postfix.html `
  -w zap_baseline_20260607_postfix.md -m 5

docker run --rm -v "$PWD/test-results/security:/zap/wrk/:rw" `
  ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py `
  -t http://host.docker.internal:8091/openapi.json -f openapi `
  -J zap_api_20260607_postfix.json -r zap_api_20260607_postfix.html `
  -w zap_api_20260607_postfix.md -d

docker run --rm --user root -v "$PWD/test-results/security:/zap/wrk/:rw" `
  ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py `
  -t http://host.docker.internal:8092/openapi.json -f openapi `
  -J zap_api_authenticated_local.json -r zap_api_authenticated_local.html `
  -w zap_api_authenticated_local.md `
  -z "-config replacer.full_list(0).description=auth-header -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization -config replacer.full_list(0).replacement=Bearer\ ci-test-key" `
  -I
```

## Before / After

| Scanner | Before fixes | After fixes |
|---|---:|---:|
| Bandit | 22 findings: 0 high, 9 medium, 13 low | 0 findings |
| Semgrep | 11 findings / warnings | 0 findings |
| ZAP baseline | 0 fail, 1 warning class | 0 fail, 1 informational warning class |
| ZAP OpenAPI/API | 0 fail, 2 warning classes | 0 fail, 1 low + 4 informational classes |
| ZAP authenticated OpenAPI/API | Not present | 0 fail, 1 low + 3 informational classes |

## Fixes Implemented

| Area | Fix |
|---|---|
| CORS | Removed wildcard default. `PRAMAGENT_CORS_ORIGINS` must opt in to origins; credentialed wildcard is no longer used. |
| Security headers | Added `Cross-Origin-Resource-Policy: same-origin` to API responses. |
| Outbound URLs | Added `pramagent.security.validate_http_url()` / `validate_urllib_request()` and wired them before webhook, Slack, provider, PagerDuty, ServiceNow, and billing webhook calls. |
| Dashboard reset links | Removed dynamic `href="{{ ... }}"` patterns from reset/key templates; reset flow now uses route-local forms and hidden tokens. |
| Logging | Replaced silent `except/pass` paths with warning logs for API key registry, dashboard user store, Postgres connections, and Redis side-effect history. |
| Migration SQL | Removed string-interpolated migration insert construction and selected fixed placeholder SQL per backend dialect. |
| Provider runtime check | Replaced `assert providers` with an explicit `ValueError` so optimized Python cannot remove validation. |
| Scanner hygiene | Added narrow `nosec` / `nosemgrep` annotations only where a preceding validation makes the flagged pattern safe. |
| CI | Added `.github/workflows/security.yml` for Bandit, Semgrep, and OWASP ZAP OpenAPI scans. Bandit/Semgrep now fail CI on any finding. Workflows opt in to Node.js 24 with `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` to remove the GitHub Actions Node 20 deprecation warning. |
| Authenticated ZAP | The ZAP CI job now injects `Authorization: Bearer ci-test-key` through ZAP's replacer so protected `/v1/*` routes are scanned with an authenticated tenant context. |
| Dashboard CSRF | Added signed, expiring double-submit CSRF tokens to pre-auth dashboard forms: `/login`, `/signup`, `/forgot-password`, and `/reset-password`. Existing session-bound CSRF still protects logout and approval actions. |
| NIST AI RMF | Expanded `docs/COMPLIANCE_MAPPING.md` with GOVERN, MAP, MEASURE, and MANAGE self-assessment rows. |

## Remaining ZAP Findings

No ZAP fail-level findings remain.

| Source | Finding | Risk | Disposition |
|---|---|---|---|
| Baseline | `Non-Storable Content` on `/`, `/robots.txt`, `/sitemap.xml` | Informational | These paths return 404 during API-only scanning. Low value; optional root redirect can reduce noise. |
| OpenAPI | `Timestamp Disclosure - Unix` on `/usage?tenant_id=default` | Low | Expected quota/ledger expiry metadata. Keep endpoint tenant-scoped; not a secret. |
| OpenAPI | Many 4xx responses | Informational | Expected. ZAP sends malformed and fuzzed inputs; the sidecar returns validation errors instead of processing them. |
| OpenAPI | `tenant_id` in query URL | Informational | `tenant_id` is not a secret. Long-term API design should derive tenant from auth where possible. |
| OpenAPI | Session-management response identified | Informational | Expected auth/session behavior. |

## Validation

```powershell
python -m pytest tests\test_security_helpers.py tests\test_api.py tests\test_dashboard_security.py tests\test_adapters.py tests\test_providers.py tests\test_usage.py -q --tb=short
# 85 passed

python -m pytest tests\test_dashboard_security.py -q --tb=short
# 25 passed

python -m pytest -q --tb=short
# 449 passed, 1 skipped after the v0.5.20 documentation and security-cleanup release

python -m compileall -q pramagent tests deploy\dashboard
# passed

python -m bandit -r pramagent deploy\dashboard
# No issues identified

docker run --rm -v "${PWD}:/src" -w /src semgrep/semgrep:latest `
  semgrep scan --metrics=off --config p/security-audit --config p/python `
  --error pramagent deploy/dashboard
# 0 findings
```

## Limitations

- This is not an external penetration test.
- ZAP ran locally over HTTP, not against a hardened TLS deployment.
- ZAP OpenAPI CI scan is authenticated with a CI API key, not a real customer
  tenant. It proves protected route scanning works, but does not replace a
  customer-specific authenticated security assessment.
- Semgrep used community rulesets. It is useful coverage, not a replacement for
  manual secure-code review.
- Several `urllib` call sites are intentionally retained for low dependency
  weight, but now have adjacent URL validation and explicit scanner annotations.

## Next Security Work

1. Extend the authenticated ZAP scan to obtain a short-lived CI JWT through
   `/v1/auth/token` in addition to the bearer API-key path.
2. Add stronger dashboard CSP and consider replacing CDN HTMX with a pinned
   local asset for locked-down enterprise deployments.
3. Move dashboard/admin auth toward OIDC + RBAC for enterprise deployments.
4. Schedule an external API/security assessment before claiming production or
   compliance certification.
