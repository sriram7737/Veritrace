# Red-team Benchmark Results

This is a small built-in prompt-injection sanity check, not a professional red
team and not proof of jailbreak resistance.

## Command

```bash
veritrace redteam --json --attacks 30
```

## Current Result

Last refreshed: 2026-06-01

```json
{
  "attacks_bypassed": 0,
  "attacks_caught": 30,
  "attacks_total": 30,
  "benign_total": 6,
  "bypass_rate": 0.0,
  "false_positive_rate": 0.0,
  "false_positives": 0
}
```

## Methodology

- Classifier path: zero-dependency keyword fallback.
- Attack corpus: 30 direct, role-hijack, delimiter, exfiltration, and indirect
  injection prompts shipped in `veritrace.redteam.EXTENDED_ATTACKS`.
- Benign corpus: 6 normal prompts shipped in `veritrace.redteam.DEFAULT_BENIGN`.
- Passing threshold used in release smoke tests: bypass rate must be `<= 0.10`.

## Honest Interpretation

The current benchmark now catches the bundled classic jailbreaks and indirect
tool-output attacks. This is still not proof of jailbreak resistance: the corpus
is small, public, and deterministic. Veritrace still needs larger third-party
red-team sets, stronger semantic classifiers, and continuous adversarial testing
before high-stakes claims.
