"""Generate 200 reproducible synthetic samples. No provider-issued credentials."""
import json
import random
import string
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def dataset():
    rng = random.Random(20261123)
    values = []
    def token(length, alphabet=string.ascii_letters + string.digits):
        return ''.join(rng.choice(alphabet) for _ in range(length))
    def add(code, content, path, expected=True, severity=None):
        values.append(dict(id=f'CASE-{len(values)+1:03d}', rule=code, file_path=path,
                           content=content, expected_leaked=expected, severity=severity,
                           type='positive' if expected else 'negative'))
    for n in range(15):
        value = 'ghp_' + token(36) if n % 2 else 'github_pat_' + token(22) + '_' + token(59)
        add('RULE-01', f'GITHUB_TOKEN="{value}"', 'src/config.py', severity='critical')
        add('RULE-02', '-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC_NOT_REAL_KEY\n-----END RSA PRIVATE KEY-----',
            f'keys/server_{n}', severity='critical')
        add('RULE-03', f'JWT_SECRET="{token(35)}"', '.env', severity='high')
        key = ('AKIA' if n % 2 else 'ASIA') + token(16, string.ascii_uppercase + string.digits)
        add('RULE-04', f'AWS_ACCESS_KEY_ID="{key}"\nAWS_SECRET_ACCESS_KEY="{token(40)}"',
            'src/aws.py', severity='critical')
        add('RULE-05', f'cccd="001099{n+123456:06d}"; // so can cuoc', 'src/profile.js', severity='high')
        add('RULE-06', 'SLACK_TOKEN="xoxb-12345678901-23456789012-' + token(24) + '"',
            'src/slack.py', severity='high')
    for n in range(10):
        add('RULE-07', f'api_key="{token(32)}"', 'src/settings.py', severity='medium')
    for n in range(20):
        add('', f'JWT_SECRET="{token(35)}"', '.env.example', False)
        add('', f'git_commit="{token(64, string.hexdigits[:16])}"', 'scripts/release.py', False)
        add('', f'test_token="dummy_mock_{token(25)}"', 'tests/test_auth.py', False)
        add('', f'tracking_code="999499{n+123456:06d}"', 'logistics/tracking.py', False)
        add('', f'export const greeting = "Welcome {n}";', 'src/home.js', False)
    return values


if __name__ == '__main__':
    target = ROOT / 'tests/benchmark_dataset_200.json'
    target.write_text(json.dumps(dataset(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Generated {len(dataset())} synthetic samples: {target}')
