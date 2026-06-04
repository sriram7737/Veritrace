# Live Test Results

Last refreshed: 2026-06-02

These are release-validation smoke tests using real external services. They are
not a penetration test, a scale test, or a compliance certification.

## Sepolia Ethereum Anchoring

Result: **passed**

```json
{
  "network_chain_id": 11155111,
  "tx_hash": "0x8d0d7bd15c377224acee00f397272bab1007c757080f19523cfc66c8461b5d99",
  "block_number": 10968438,
  "status": 1,
  "verified_status": 1,
  "trace_hash": "e251d85472de268d0b50d10abf36158d24483ef360f37bfaf01a0747468b6fd4",
  "tx_type": 2
}
```

Notes:

- The transaction was submitted on Sepolia with the trace hash in calldata.
- `verify_on_chain(tx_hash, expected_hash=...)` succeeded.
- Live testing exposed a verifier bug around Web3 `HexBytes` calldata and a
  legacy-gas pending transaction. The release code now normalizes calldata and
  uses EIP-1559 fee fields when the chain supports them.

## S3 Cold Archive

Result: **passed**

```json
{
  "region": "us-east-1",
  "call_id": "live-s3-e42647ff1f3a",
  "deleted_from_hot_store": 1,
  "s3_key": "pramagent-live-test/v0.4/tenant=live-release-test/2026/06/01/live-s3-e42647ff1f3a.json.gz.fernet",
  "content_length": 548,
  "metadata_encrypted": "true",
  "restored_call_id": "live-s3-e42647ff1f3a",
  "restored_tenant_id": "live-release-test"
}
```

Notes:

- The test used a real AWS S3 bucket with a tiny fake trace.
- The object was gzip-compressed, Fernet-encrypted, uploaded to S3, removed
  from the hot store, and restored by call ID.
- Bucket name and credentials are intentionally not published.

## Local Release Checks

```text
python -m compileall -q pramagent tests
python -m pytest -q --tb=no
```

Result:

```text
364 passed, 2 warnings
```

## Clean Environment Checks

Result: **passed**

Python 3.13.13 clean venv with upgraded build tooling:

```text
python -m pip install -U pip setuptools wheel
python -m pip install -e ".[dev,api,otel]"
python -m pytest -q --tb=no
```

```text
364 passed, 3 warnings
```

Notes:

- Clean venv used pip 26.1.2, setuptools 82.0.1, and wheel 0.47.0.
- GitHub Actions is configured to run Python 3.10, 3.11, 3.12, and 3.13 with
  upgraded pip/setuptools/wheel before installing test dependencies.

Optional extras install check:

```text
python -m pip install "dist/pramagent-0.5.4-py3-none-any.whl[all]"
```

Result: **passed**. Import smoke covered Anthropic, Ollama/aiohttp, FastAPI,
uvicorn, Jinja2, httpx, cryptography, OpenTelemetry, Redis, psycopg2, Web3,
boto3, and Pramagent itself.

## Real LLM Provider Smoke Tests

Result: **passed**

OpenAI live API:

```json
{
  "provider": "openai",
  "model": "gpt-5.5-2026-04-23",
  "direct_latency_ms": 6461.61,
  "pipeline_blocked": false,
  "pipeline_hitl": "auto",
  "pipeline_latency_ms": 4644.49,
  "pipeline_hash_len": 64
}
```

Notes:

- The smoke test used the key from local `.env.live`; no secret is published.
- Live testing exposed a compatibility issue: newer OpenAI models reject
  `max_tokens` and require `max_completion_tokens`. The provider now retries
  with the newer parameter when OpenAI returns that explicit error.

Local Ollama:

```json
{
  "provider": "ollama",
  "model": "qwen2.5:1.5b",
  "direct_latency_ms": 3205.62,
  "pipeline_blocked": false,
  "pipeline_hitl": "auto",
  "pipeline_latency_ms": 907.19,
  "pipeline_hash_len": 64
}
```

Notes:

- Installed local models at test time: `qwen2.5:1.5b` and
  `nomic-embed-text:latest`.
- First cold Ollama load can exceed the default 15s reliability timeout; warm
  the model before release smoke tests or configure a longer timeout in the
  host application.

## Red-team Benchmark

Command:

```text
pramagent redteam --json --dynamic --attacks 200 --seed 999
```

```text
attacks_bypassed: 0
attacks_caught: 200
attacks_total: 200
bypass_rate: 0.0
false_positive_rate: 0.0
mode: dynamic
seed: 999
```

Additional local sweep: seeds 1 through 10, 100 dynamic prompts each, all
reported 0 bypasses and 0 false positives against the bundled benign set.

This is intentionally published as a dynamic smoke test only. Passing it does
not prove resistance against novel or third-party jailbreak sets.

## Not Run Here

- External penetration test.
- Mainnet Ethereum anchoring.
