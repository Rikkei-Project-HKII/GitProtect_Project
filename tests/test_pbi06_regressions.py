"""PBI-06 regression and HTTP tests. All token values are synthetic."""
import time
import unittest
from unittest.mock import patch

import regex
from fastapi.testclient import TestClient
from app.main import app
from app.modules.engine.regex_engine import RegexEngine
from app.modules.engine.scan_pipeline import ScanPipeline
from app.modules.engine.service import DetectionEngineService

SECRET = 'aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7b'
AWS_ID = 'AKIA' + '23456789ABCDEFGH'
GENERIC = 'a9F3kL8#mZ1$qP90_x!z8WqA'


class TestPBI06Regressions(unittest.TestCase):
    def setUp(self):
        self.pipeline = ScanPipeline()

    def aws_findings(self, text):
        return [f for f in self.pipeline.scan(text, 'config.py')['findings']
                if f['rule_code'] == 'RULE-04']

    def test_aws_pair_and_secret_entropy(self):
        text = f'AWS_ACCESS_KEY_ID="{AWS_ID}"\nAWS_SECRET_ACCESS_KEY="{SECRET}"'
        for path in ('config.py', '.env'):
            with self.subTest(path=path):
                findings = self.pipeline.scan(text, path)['findings']
                self.assertEqual([f['rule_code'] for f in findings], ['RULE-04'])
                self.assertEqual(findings[0]['threshold_applied'], 4.2)
                self.assertEqual(findings[0]['shannon_entropy'],
                                 DetectionEngineService.calculate_shannon_entropy(SECRET))
                self.assertNotIn(SECRET, str(findings))
                self.assertNotIn(AWS_ID, str(findings))

    def test_aws_pair_reversed_unquoted(self):
        text = f'AWS_SECRET_ACCESS_KEY={SECRET}\nAWS_ACCESS_KEY_ID={AWS_ID}'
        self.assertEqual(len(self.aws_findings(text)), 1)

    def test_aws_id_alone_is_not_rule04(self):
        self.assertEqual(self.aws_findings(f'AWS_ACCESS_KEY_ID="{AWS_ID}"'), [])

    def test_aws_requires_context(self):
        self.assertEqual(self.aws_findings(f'value="{AWS_ID}"\nAWS_SECRET_ACCESS_KEY="{SECRET}"'), [])
        self.assertEqual(self.aws_findings(f'AWS_ACCESS_KEY_ID="{AWS_ID}"\nother="{SECRET}"'), [])

    def test_aws_rejects_bad_secret_length_entropy_and_dummy(self):
        for secret in (SECRET[:-1], SECRET+'x', 'a'*40,
                       'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'):
            with self.subTest(length=len(secret)):
                self.assertEqual(self.aws_findings(
                    f'AWS_ACCESS_KEY_ID="{AWS_ID}"\nAWS_SECRET_ACCESS_KEY="{secret}"'), [])

    def test_aws_does_not_pair_distant_values(self):
        text = f'AWS_ACCESS_KEY_ID="{AWS_ID}"\n' + '# padding\n'*30
        text += f'AWS_SECRET_ACCESS_KEY="{SECRET}"'
        self.assertEqual(self.aws_findings(text), [])

    def test_aws_does_not_reuse_secret(self):
        text = f'AWS_ACCESS_KEY_ID="{AWS_ID}"\nAWS_ACCESS_KEY_ID="{AWS_ID}"\nAWS_SECRET_ACCESS_KEY="{SECRET}"'
        self.assertEqual(len(self.aws_findings(text)), 1)

    def test_hash_near_token_comment_is_rejected_before_entropy(self):
        text = '# token metadata\ngit_commit = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"'
        with patch.object(DetectionEngineService, 'evaluate_entropy',
                          side_effect=AssertionError('Hash reached entropy tier')):
            self.assertFalse(self.pipeline.scan(text, 'release.py')['is_leaked'])

    def test_generic_preserves_punctuation_and_exact_span(self):
        value = GENERIC + '=;'
        text = f'# header\napiKey = "{value}";'
        match = RegexEngine().scan(text)['matches'][0]
        self.assertEqual(text[match['start']:match['end']], value)
        finding = self.pipeline.scan(text, 'app.py')['findings'][0]
        self.assertEqual(finding['rule_code'], 'RULE-07')
        self.assertEqual(finding['line_number'], 2)
        self.assertEqual(finding['secret_masked'], self.pipeline.mask_secret(value))

    def test_generic_requires_assignment(self):
        text = f'# password documentation\nvalue = "{GENERIC}"'
        self.assertFalse(self.pipeline.scan(text, 'app.py')['is_leaked'])

    def test_generic_length_boundaries(self):
        alphabet = 'aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW'
        for length, expected in ((19, False), (20, True), (31, True),
                                 (32, True), (128, True), (129, False)):
            value = (alphabet*5)[:length]
            with self.subTest(length=length):
                self.assertEqual(self.pipeline.scan(f'api_key="{value}"', 'app.py')['is_leaked'], expected)

    def test_generic_uuid_mock_and_non_alphanumeric_mix(self):
        for value in ('123e4567-e89b-12d3-a456-426614174000',
                      'dummy_'+GENERIC, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '12345678901234567890'):
            with self.subTest(value=value):
                self.assertFalse(self.pipeline.scan(f'token="{value}"', 'app.py')['is_leaked'])

    def test_fine_grained_pat_real_pattern(self):
        value = 'github_pat_' + 'ABCDEFGHIJKLMNOPQRSTUV' + '_' + ('aB3dE5fG7hI9jK1lM3nO'*3)[:59]
        findings = self.pipeline.scan(f'token="{value}"', 'config.py')['findings']
        self.assertEqual([f['rule_code'] for f in findings], ['RULE-01'])
        self.assertEqual(findings[0]['severity'], 'critical')

    def test_discord_token_hyphen_is_not_split_for_entropy(self):
        tail = ('aB3dE5fG7hI9jK1lM3nO'*4)[:66] + '-x'
        value = 'https://discord.com/api/webhooks/' + '123456789012345678' + '/' + tail
        findings = self.pipeline.scan(value, 'bot.py')['findings']
        self.assertEqual([f['rule_code'] for f in findings], ['RULE-06'])
        self.assertEqual(findings[0]['shannon_entropy'], DetectionEngineService.calculate_shannon_entropy(tail))

    def test_real_regex_timeout(self):
        engine = RegexEngine(patterns=[r'(a+)+$'], timeout=0.005)
        started = time.perf_counter()
        self.assertTrue(engine.scan('a'*10000+'!')['timed_out'])
        self.assertLess(time.perf_counter()-started, 1.0)

    def test_pipeline_timeout_never_returns_clean_result(self):
        pipeline = ScanPipeline(RegexEngine(patterns=[r'(a+)+$'], timeout=0.005))
        with self.assertRaises(TimeoutError):
            pipeline.scan('a'*10000+'!', 'app.py')

    def test_specific_regex_uses_same_deadline(self):
        pipeline = ScanPipeline(RegexEngine(timeout=0.01))
        with patch('app.modules.engine.scan_pipeline.RULE_01_GITHUB_PAT_RE',
                   regex.compile(r'(a+)+$')):
            with self.assertRaises(TimeoutError):
                pipeline.scan('a'*10000+'!', 'app.py')


class TestPBI06HTTP(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def test_rules_list_and_filters(self):
        response = self.client.get('/api/v1/rules')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['total'], 7)
        self.assertEqual(self.client.get('/api/v1/rules?severity=critical').json()['total'], 3)
        self.assertEqual(self.client.get('/api/v1/rules?is_enabled=false').json()['total'], 0)
        self.assertEqual(self.client.get('/api/v1/rules?severity=invalid').status_code, 422)

    def test_evaluate_masks_secret(self):
        response = self.client.post('/api/v1/scan/evaluate-text', json={
            'content': f'apiKey="{GENERIC}"', 'file_path': 'app.py'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['findings'][0]['rule_code'], 'RULE-07')
        self.assertNotIn(GENERIC, response.text)

    def test_evaluate_allowlist(self):
        response = self.client.post('/api/v1/scan/evaluate-text', json={
            'content': f'apiKey="{GENERIC}"', 'file_path': '.env.example'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['file_allowlisted'])
        self.assertFalse(response.json()['is_leaked'])

    def test_request_validation(self):
        for payload in ({'content': ''}, {'content': 'x'*10241},
                        {'content': 'ok', 'unexpected': True}):
            with self.subTest(keys=list(payload)):
                self.assertEqual(self.client.post('/api/v1/scan/evaluate-text', json=payload).status_code, 422)

    def test_timeout_is_explicit_service_error(self):
        with patch.object(DetectionEngineService, 'evaluate_snippet', side_effect=TimeoutError):
            response = self.client.post('/api/v1/scan/evaluate-text', json={'content': 'x'})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {'detail': 'SCAN_TIMEOUT'})


if __name__ == '__main__':
    unittest.main()
