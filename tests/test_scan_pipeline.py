import unittest

from app.modules.engine.scan_pipeline import ScanPipeline
from app.modules.engine.service import DetectionEngineService


class TestScanPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = ScanPipeline()

    # =========================================================================
    # Kiểm thử cơ bản của pipeline và allowlist
    # =========================================================================
    def test_allowlisted_file(self):
        result = self.pipeline.scan(
            "password=someverylongsecret123456",
            ".env.example",
        )

        self.assertTrue(result["file_allowlisted"])
        self.assertFalse(result["is_leaked"])

    def test_ignore_without_context(self):
        result = self.pipeline.scan(
            "aB9xK2pQ7zM4nP8qR5wX",
            "config.py",
        )

        self.assertFalse(result["is_leaked"])

    def test_pipeline_with_secret_context(self):
        content = 'password="aB9xK2pQ7zM4nP8qR5wX"'

        result = self.pipeline.scan(content, "config.py")

        self.assertFalse(result["file_allowlisted"])
        self.assertTrue(result["is_leaked"])
        self.assertGreater(len(result["findings"]), 0)

        finding = result["findings"][0]
        self.assertEqual(finding["rule_code"], "RULE-07")
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["charset_detected"], "base64")
        self.assertTrue(finding["context_matched"])

    def test_mock_directory(self):
        result = self.pipeline.scan(
            "password=someverylongsecret123456",
            "tests/mock/config.py",
        )

        self.assertTrue(result["file_allowlisted"])

    # =========================================================================
    # S2-01: Nhận diện Charset và ngưỡng Shannon Entropy động
    # =========================================================================
    def test_s2_01_charset_priority_and_dynamic_thresholds(self):
        hex_value = "0123456789abcdef0123"
        self.assertEqual(
            DetectionEngineService.detect_charset(hex_value),
            "hex",
        )
        self.assertEqual(
            DetectionEngineService.get_entropy_threshold("hex", 20),
            3.00,
        )
        self.assertEqual(
            DetectionEngineService.get_entropy_threshold("hex", 32),
            3.30,
        )

        base32_value = "ABCDEFGHIJKLMNOP2345"
        self.assertEqual(
            DetectionEngineService.detect_charset(base32_value),
            "base32",
        )
        self.assertEqual(
            DetectionEngineService.get_entropy_threshold("base32", 20),
            3.50,
        )
        self.assertEqual(
            DetectionEngineService.get_entropy_threshold("base32", 32),
            3.90,
        )

        base64_value = "aB9xK2pQ7zM4nP8qR5wX"
        self.assertEqual(
            DetectionEngineService.detect_charset(base64_value),
            "base64",
        )
        self.assertEqual(
            DetectionEngineService.get_entropy_threshold("base64", 20),
            3.80,
        )
        self.assertEqual(
            DetectionEngineService.get_entropy_threshold("base64", 32),
            4.20,
        )

        ascii_value = "a9F3kL8#mZ1$qP90_x!z8WqA"
        self.assertEqual(
            DetectionEngineService.detect_charset(ascii_value),
            "ascii",
        )
        self.assertEqual(
            DetectionEngineService.get_entropy_threshold("ascii", 24),
            3.90,
        )
        self.assertEqual(
            DetectionEngineService.get_entropy_threshold("ascii", 32),
            4.40,
        )

    # =========================================================================
    # S2-02: RULE-05 - Kiểm tra CCCD Việt Nam
    # =========================================================================
    def test_s2_02_rule_05_vietnamese_cccd_validation(self):
        # TC-06: Mã định danh hợp lệ kèm từ khóa ngữ cảnh CCCD.
        valid_cccd_case = (
            'const author_id = "001099012345"; '
            "// so can cuoc cong dan xac thuc"
        )
        result_valid = self.pipeline.scan(
            valid_cccd_case,
            "user_profile.js",
        )

        self.assertTrue(result_valid["is_leaked"])
        self.assertEqual(
            result_valid["findings"][0]["rule_code"],
            "RULE-05",
        )
        self.assertEqual(
            result_valid["findings"][0]["severity"],
            "high",
        )
        self.assertEqual(
            result_valid["findings"][0]["secret_masked"],
            "0010****2345",
        )

        # TC-07: Mã tỉnh không hợp lệ và ngữ cảnh mã vận đơn.
        invalid_cccd_case = (
            'const tracking_code = "999499012345"; '
            "// ma van don chuyen phat nhanh"
        )
        result_invalid = self.pipeline.scan(
            invalid_cccd_case,
            "shipping.js",
        )
        self.assertFalse(result_invalid["is_leaked"])

        # Chuỗi số không có ngữ cảnh CCCD không được cảnh báo.
        order_number_case = 'const order_number = "079201012345";'
        result_order = self.pipeline.scan(
            order_number_case,
            "order.py",
        )
        self.assertFalse(result_order["is_leaked"])

    # =========================================================================
    # S2-03: Allowlist và phân loại RULE-02 - Private Key
    # =========================================================================
    def test_s2_03_allowlist_and_rule_02_private_key_classification(self):
        # TC-02: Khối PRIVATE KEY trong tệp khóa -> Critical.
        private_key_case = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "SYNTHETIC_TEST_KEY_MATERIAL_NOT_A_REAL_PRIVATE_KEY\n"
            "-----END RSA PRIVATE KEY-----"
        )
        result_private_key = self.pipeline.scan(
            private_key_case,
            "id_rsa",
        )

        self.assertTrue(result_private_key["is_leaked"])
        self.assertEqual(
            result_private_key["findings"][0]["rule_code"],
            "RULE-02",
        )
        self.assertEqual(
            result_private_key["findings"][0]["severity"],
            "critical",
        )

        # Chứng chỉ công khai trong tệp PEM -> Medium theo hành vi hiện tại.
        certificate_case = (
            "-----BEGIN CERTIFICATE-----\n"
            "SYNTHETIC_PUBLIC_CERTIFICATE_TEST_DATA\n"
            "-----END CERTIFICATE-----"
        )
        result_certificate = self.pipeline.scan(
            certificate_case,
            "certs/cert.pem",
        )

        self.assertTrue(result_certificate["is_leaked"])
        self.assertEqual(
            result_certificate["findings"][0]["rule_code"],
            "RULE-02",
        )
        self.assertEqual(
            result_certificate["findings"][0]["severity"],
            "medium",
        )

        # TC-03: Tệp .env.example thuộc allowlist.
        env_example_case = (
            'DATABASE_URL="postgres://test_user:test_password@'
            'example.invalid:5432/test_db"'
        )
        result_allowlisted = self.pipeline.scan(
            env_example_case,
            ".env.example",
        )

        self.assertTrue(result_allowlisted["file_allowlisted"])
        self.assertFalse(result_allowlisted["is_leaked"])

    # =========================================================================
    # S2-04: RULE-01, RULE-03, RULE-04, RULE-06 và RULE-07
    # =========================================================================
    def test_s2_04_rules_01_03_04_06_07_and_benchmark_matrix(self):
        # Synthetic values: never issued by a provider, tested with real regexes.
        token_01 = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        result_rule_01 = self.pipeline.scan(f'GITHUB_TOKEN = "{token_01}"', "config.py")

        self.assertTrue(result_rule_01["is_leaked"])
        self.assertEqual(
            result_rule_01["findings"][0]["rule_code"],
            "RULE-01",
        )
        self.assertEqual(
            result_rule_01["findings"][0]["severity"],
            "critical",
        )

        # TC-04: RULE-03 - Secret trong tệp .env -> High.
        env_secret_case = 'JWT_SECRET="s9F#mK2$vL901_x!z8WqA5@dE"'
        result_rule_03 = self.pipeline.scan(
            env_secret_case,
            ".env",
        )

        self.assertTrue(result_rule_03["is_leaked"])
        self.assertEqual(
            result_rule_03["findings"][0]["rule_code"],
            "RULE-03",
        )
        self.assertEqual(
            result_rule_03["findings"][0]["severity"],
            "high",
        )
        self.assertEqual(
            result_rule_03["findings"][0]["charset_detected"],
            "ascii",
        )

        token_04 = "AKIA" + "23456789ABCDEFGH"
        aws_secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7b"
        content_04 = f'AWS_ACCESS_KEY_ID="{token_04}"\nAWS_SECRET_ACCESS_KEY="{aws_secret}"'
        result_rule_04 = self.pipeline.scan(content_04, "aws_config.py")

        self.assertTrue(result_rule_04["is_leaked"])
        self.assertEqual(
            result_rule_04["findings"][0]["rule_code"],
            "RULE-04",
        )
        self.assertEqual(
            result_rule_04["findings"][0]["severity"],
            "critical",
        )

        token_06 = "xoxb-" + "12345678901-23456789012-" + "ABCDEFGHIJKLMNOPQRSTUVWX"
        result_rule_06 = self.pipeline.scan(f'SLACK_TOKEN = "{token_06}"', "bot.py")

        self.assertTrue(result_rule_06["is_leaked"])
        self.assertEqual(
            result_rule_06["findings"][0]["rule_code"],
            "RULE-06",
        )
        self.assertEqual(
            result_rule_06["findings"][0]["severity"],
            "high",
        )

        # TC-05: SHA-256 commit hash không có context secret -> Ignored.
        commit_hash_case = (
            'git_commit = '
            '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";'
        )
        self.assertFalse(
            self.pipeline.scan(
                commit_hash_case,
                "release.py",
            )["is_leaked"]
        )

        # TC-08: Token dummy/mock trong thư mục test -> Suppressed.
        dummy_token_case = (
            'const test_token = '
            '"dummy_mock_Zx8kLm29Qw7Rt5Uh3Vb6Nc4Yp1";'
        )
        self.assertFalse(
            self.pipeline.scan(
                dummy_token_case,
                "tests/test_auth.py",
            )["is_leaked"]
        )

    # =========================================================================
    # S2-05: Danh sách quy tắc và đánh giá đoạn mã nguồn
    # =========================================================================
    def test_s2_05_list_rules_and_evaluate_text_service(self):
        all_rules = DetectionEngineService.list_rules()
        self.assertEqual(all_rules["total"], 7)

        rule_codes = [
            rule["rule_code"]
            for rule in all_rules["items"]
        ]
        self.assertEqual(
            rule_codes,
            [
                "RULE-01",
                "RULE-02",
                "RULE-03",
                "RULE-04",
                "RULE-05",
                "RULE-06",
                "RULE-07",
            ],
        )

        critical_rules = DetectionEngineService.list_rules(
            severity="critical",
        )
        self.assertEqual(critical_rules["total"], 3)

        evaluate_result = DetectionEngineService.evaluate_snippet(
            'apiKey = "a9F3kL8#mZ1$qP90_x!z8WqA"',
            "app.py",
        )
        self.assertTrue(evaluate_result["is_leaked"])
        self.assertEqual(
            evaluate_result["findings"][0]["rule_code"],
            "RULE-07",
        )


if __name__ == "__main__":
    unittest.main()
