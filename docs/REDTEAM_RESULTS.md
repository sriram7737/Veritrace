# Red-team Benchmark Results

This is a small built-in prompt-injection sanity check, not a professional red
team and not proof of jailbreak resistance.

## Command

```bash
veritrace redteam --json --dynamic --attacks 100 --seed 123
```

## Current Result

Last refreshed: 2026-06-01

```json
{
  "attacks_bypassed": 0,
  "attacks_caught": 100,
  "attacks_total": 100,
  "benign_total": 6,
  "bypass_rate": 0.0,
  "false_positive_rate": 0.0,
  "false_positives": 0,
  "mode": "dynamic",
  "seed": 123
}
```

## Methodology

- Classifier path: zero-dependency keyword fallback.
- Attack corpus: 100 runtime-mutated prompts generated from
  `veritrace.redteam.EXTENDED_ATTACKS`.
- Dynamic seed: 123. Re-run with another seed to explore different mutations.
- Benign corpus: 6 normal prompts shipped in `veritrace.redteam.DEFAULT_BENIGN`.
- Passing threshold used in release smoke tests: bypass rate must be `<= 0.10`.

## Honest Interpretation

The current benchmark now includes deterministic runtime mutation, so it is less
overfit than a fixed prompt list. It is still not proof of jailbreak resistance:
the seed corpus and mutation templates are public. Veritrace still needs larger
third-party red-team sets, stronger semantic classifiers, and continuous
adversarial testing before high-stakes claims.
