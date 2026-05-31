# Veritrace — Control Mapping (SOC 2 / HIPAA / EU AI Act)

This maps Veritrace's implemented controls to common framework expectations.
It is an engineering self-assessment to accelerate an auditor's review — **not**
a certification. Independent audit is required for any compliance claim.

## EU AI Act (high-risk systems)
| Article | Expectation | Veritrace control |
|---|---|---|
| Art. 12 | Automatic record-keeping / logging | Hash-chained immutable trace per call; 180-day retention floor enforced |
| Art. 13 | Transparency | Full trace + RCA replay/incident report per decision |
| Art. 14 | Human oversight | HITLLayer: propose-and-wait, idle-on-silence, escalation, quorum |
| Art. 15 | Accuracy/robustness/security | ToolGuard schema validation, injection defense, circuit breakers |

## HIPAA Security Rule
| Safeguard | Citation | Veritrace control |
|---|---|---|
| Access control | §164.312(a)(1) | API-key + JWT auth, per-tenant isolation, cross-tenant trace guard |
| Audit controls | §164.312(b) | Tamper-evident hash chain + approval audit log |
| Integrity | §164.312(c)(1) | SHA-256 chain verification detects any retroactive edit |
| Transmission security | §164.312(e)(1) | TLS/HSTS headers; encrypted-at-rest SQLite option |
| Minimum necessary | §164.502(b) | PII scrubbing before model exposure |

## SOC 2 (Trust Services Criteria)
| TSC | Veritrace control |
|---|---|
| CC6 (Logical access) | Auth, tenant isolation, rate limiting |
| CC7 (System operations) | OTel tracing, structured logs, health/readiness probes, circuit breakers |
| CC8 (Change management) | Schema migration runner with recorded versions |
| A1 (Availability) | Graceful degradation (Redis/Postgres fail-open to local), retries |
| C1 (Confidentiality) | PII scrubbing, output exfiltration scanning, encrypted store |
| P-series (Privacy) | Consent registry, purpose limitation, retention policy, GDPR erasure endpoint |

## Auditor-facing artifacts
- `ComplianceReporter.to_pdf()/.to_json()` — point-in-time attestation
- `GET /v1/audit/verify` — live hash-chain validity
- `POST /v1/rca/{id}/incident` — per-decision incident report
