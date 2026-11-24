"""Benchmark the same ScanPipeline used by the API and workers."""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.modules.engine.service import DetectionEngineService
from generate_benchmark_dataset import dataset


def run_benchmark():
    samples = dataset()
    counts = dict(tp=0, tn=0, fp=0, fn=0)
    details = []
    started = time.perf_counter()
    for sample in samples:
        result = DetectionEngineService.evaluate_snippet(sample['content'], sample['file_path'])
        detected = result['is_leaked']
        key = 'tp' if sample['expected_leaked'] and detected else 'fn' if sample['expected_leaked'] else 'fp' if detected else 'tn'
        counts[key] += 1
        findings = result['findings']
        rule_ok = (not sample['expected_leaked'] or not detected or
                   any(f['rule_code'] == sample['rule'] and f['severity'] == sample['severity'] for f in findings))
        schema_ok = all(all(k in f for k in ('secret_masked', 'charset_detected', 'shannon_entropy')) for f in findings)
        masked = all('****' in f['secret_masked'] for f in findings)
        details.append(dict(id=sample['id'], expected_rule=sample['rule'],
                            actual_rules=[f['rule_code'] for f in findings], outcome=key,
                            rule_ok=rule_ok, masked=masked, schema_ok=schema_ok))
    elapsed = time.perf_counter() - started
    precision = counts['tp'] / max(1, counts['tp'] + counts['fp'])
    recall = counts['tp'] / max(1, counts['tp'] + counts['fn'])
    fpr = counts['fp'] / max(1, counts['fp'] + counts['tn'])
    report = dict(samples=len(samples), **counts, precision=precision, recall=recall, fpr=fpr,
                  f1=(2*precision*recall/(precision+recall) if precision+recall else 0),
                  seconds=elapsed, expected_rule_failures=sum(not d['rule_ok'] for d in details),
                  details=details,
                  scope='In-memory production ScanPipeline, synthetic dataset; not live GitHub-to-UI latency.')
    report['passed'] = (len(samples) == 200 and precision >= .85 and recall >= .9 and fpr <= .15
                        and elapsed < 10 and all(d['rule_ok'] and d['masked'] and d['schema_ok'] for d in details))
    return report


def save_report(report, output):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'BENCHMARK_REPORT.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    lines = ['# GitProtect benchmark - T05DB30', '',
             'Production ScanPipeline; 200 synthetic samples with explicit rule/severity checks.', '',
             '| Metric | Result |', '|---|---|']
    for label, value in [('Samples', report['samples']), ('TP / TN / FP / FN', f"{report['tp']} / {report['tn']} / {report['fp']} / {report['fn']}"),
                         ('Recall', f"{report['recall']:.2%}"), ('Precision', f"{report['precision']:.2%}"),
                         ('FPR', f"{report['fpr']:.2%}"), ('F1 (0-1)', f"{report['f1']:.4f}"),
                         ('Expected rule/severity failures', report['expected_rule_failures']),
                         ('Seconds', f"{report['seconds']:.6f}"), ('Acceptance', 'PASS' if report['passed'] else 'FAIL')]:
        lines.append(f'| {label} | {value} |')
    lines += ['', report['scope'], '', 'This result does not certify live staging latency. Per-case evidence is in the JSON report.',
              'False negatives remain in the recall denominator. Rule/severity checks apply to detected positives.',
              'CASE-094 is a known false negative: entropy 4.09 is below the configured Base64 threshold 4.2. The threshold is not relaxed to fit the benchmark.',
              '', 'Reproduce: python generate_benchmark_dataset.py; python scripts/run_benchmark.py']
    (output / 'BENCHMARK_REPORT.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT)
    args = parser.parse_args()
    report = run_benchmark()
    save_report(report, args.output)
    print(json.dumps({k: v for k, v in report.items() if k != 'details'}, indent=2))
    sys.exit(0 if report['passed'] else 1)
