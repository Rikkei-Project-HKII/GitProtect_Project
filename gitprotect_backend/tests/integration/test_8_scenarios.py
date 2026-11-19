"""
GitProtect MVP - Integration Test: 8 Ca Kiểm Thử Thực Nghiệm Chuẩn (TC-01..TC-08)
Đặc tả SRS Phần D: Benchmark Validation Matrix (PBI-12 / T05DB30).
"""

import unittest
from app.modules.engine.service import DetectionEngineService


class Test8StandardScenarios(unittest.TestCase):
    def test_tc01_github_fine_grained_pat(self):
        """TC-01: GitHub Fine-grained PAT bí mật trong file config.py -> Phát hiện RULE-01 (Critical)."""
        snippet = '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'
        res = DetectionEngineService.evaluate_snippet(snippet, "config.py")
        self.assertTrue(res["is_leaked"], "TC-01 phải phát hiện rò rỉ PAT")
        rule_codes = [f["rule_code"] for f in res["findings"]]
        self.assertIn("RULE-01", rule_codes)

    def test_tc02_rsa_private_key_root(self):
        """TC-02: Khóa riêng tư RSA máy chủ trong root repo (id_rsa) -> Phát hiện RULE-02 (Critical)."""
        snippet = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m4w...\n-----END RSA PRIVATE KEY-----"
        res = DetectionEngineService.evaluate_snippet(snippet, "id_rsa")
        self.assertTrue(res["is_leaked"], "TC-02 phải phát hiện rò rỉ RSA Private Key")
        rule_codes = [f["rule_code"] for f in res["findings"]]
        self.assertIn("RULE-02", rule_codes)

    def test_tc03_allowlist_env_example(self):
        """TC-03: Tệp mẫu môi trường chứa thông tin giả định (.env.example) -> Bị chặn bởi Allowlist, không cảnh báo."""
        snippet = 'DATABASE_URL="postgres://admin:pass123456@db.internal:5432/prod"'
        res = DetectionEngineService.evaluate_snippet(snippet, ".env.example")
        self.assertFalse(res["is_leaked"], "TC-03 tệp .env.example phải được đưa vào Allowlist bỏ qua")
        self.assertTrue(res["file_allowlisted"])

    def test_tc04_production_env_secret(self):
        """TC-04: Bí mật ký JWT trong tập tin môi trường thực tế (.env) -> Phát hiện RULE-03 (High)."""
        snippet = 'JWT_SECRET="s9F#mK2$vL901_x!z8WqA5@dE"'
        res = DetectionEngineService.evaluate_snippet(snippet, ".env")
        self.assertTrue(res["is_leaked"], "TC-04 tập tin .env thực tế phải kích hoạt RULE-03")
        rule_codes = [f["rule_code"] for f in res["findings"]]
        self.assertIn("RULE-03", rule_codes)

    def test_tc05_safe_git_commit_hash(self):
        """TC-05: Chuỗi SHA-256 Commit Hash vô hại trong script release -> Loại trừ ở Lớp 1, không cảnh báo."""
        snippet = 'git_commit = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";'
        res = DetectionEngineService.evaluate_snippet(snippet, "scripts/release.py")
        self.assertFalse(res["is_leaked"], "TC-05 commit hash vô hại không được tạo cảnh báo sai")

    def test_tc06_valid_vietnamese_cccd(self):
        """TC-06: Số CCCD Việt Nam hợp lệ kèm từ khóa chú thích ngữ cảnh -> Phát hiện RULE-05 (High)."""
        snippet = 'const author_id = "001099012345"; // so can cuoc cong dan xac thuc'
        res = DetectionEngineService.evaluate_snippet(snippet, "src/auth.js")
        self.assertTrue(res["is_leaked"], "TC-06 phải phát hiện số CCCD Việt Nam hợp lệ")
        rule_codes = [f["rule_code"] for f in res["findings"]]
        self.assertIn("RULE-05", rule_codes)

    def test_tc07_invalid_cccd_tracking_code(self):
        """TC-07: Chuỗi 12 chữ số ngẫu nhiên của mã vận đơn bưu chính -> Loại trừ ở Lớp 1, không cảnh báo."""
        snippet = 'const tracking_code = "999499012345"; // ma van don chuyen phat nhanh'
        res = DetectionEngineService.evaluate_snippet(snippet, "logistics/tracking.js")
        self.assertFalse(res["is_leaked"], "TC-07 mã vận đơn không được bắt nhầm thành CCCD")

    def test_tc08_unit_test_mock_token(self):
        """TC-08: Dữ liệu Token giả lập phục vụ kiểm thử đơn vị (Unit Test) -> Bị chặn bởi Lớp 3 Mock Filter."""
        snippet = 'const test_token = "dummy_mock_Zx8kLm29Qw7Rt5Uh3Vb6Nc4Yp1";'
        res = DetectionEngineService.evaluate_snippet(snippet, "tests/test_auth.py")
        self.assertFalse(res["is_leaked"], "TC-08 dữ liệu mock trong thư mục test phải được bỏ qua")


if __name__ == "__main__":
    unittest.main()

