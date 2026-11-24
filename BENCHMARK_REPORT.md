# GitProtect benchmark - T05DB30

Production ScanPipeline; 200 synthetic samples with explicit rule/severity checks.

| Metric | Result |
|---|---|
| Samples | 200 |
| TP / TN / FP / FN | 99 / 100 / 0 / 1 |
| Recall | 99.00% |
| Precision | 100.00% |
| FPR | 0.00% |
| F1 (0-1) | 0.9950 |
| Expected rule/severity failures | 0 |
| Seconds | 0.026235 |
| Acceptance | PASS |

In-memory production ScanPipeline, synthetic dataset; not live GitHub-to-UI latency.

This result does not certify live staging latency. Per-case evidence is in the JSON report.
False negatives remain in the recall denominator. Rule/severity checks apply to detected positives.
CASE-094 is a known false negative: entropy 4.09 is below the configured Base64 threshold 4.2. The threshold is not relaxed to fit the benchmark.

Reproduce: python generate_benchmark_dataset.py; python scripts/run_benchmark.py
