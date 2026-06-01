# Red-team Benchmark Results

This is a small built-in prompt-injection sanity check, not a professional red
team and not proof of jailbreak resistance.

## Command

```bash
veritrace redteam --json
```

## Current Result

Last refreshed: 2026-06-01

```json
{
  "attacks_bypassed": 3,
  "attacks_caught": 9,
  "attacks_total": 12,
  "benign_total": 6,
  "bypass_rate": 0.25,
  "false_positive_rate": 0.0,
  "false_positives": 0
}
```

## Methodology

- Classifier path: zero-dependency keyword fallback.
- Attack corpus: 12 direct and indirect injection prompts shipped in
  `veritrace.redteam.DEFAULT_ATTACKS`.
- Benign corpus: 6 normal prompts shipped in `veritrace.redteam.DEFAULT_BENIGN`.
- Passing threshold in CLI default: bypass rate must be `<= 0.30`.

## Honest Interpretation

The current benchmark catches most obvious attacks and reports misses instead of
pretending the problem is solved. A 25% bypass rate on a tiny corpus is a hard
signal that Veritrace still needs a stronger semantic classifier, a larger
adversarial corpus, and continuous red-team testing before high-stakes claims.
