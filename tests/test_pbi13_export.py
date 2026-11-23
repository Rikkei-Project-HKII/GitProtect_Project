"""
Unit Test for Task S3-08a / S3-08b (Task Bonus T05DB33):
Xuất báo cáo an ninh PDF đồ họa cao & Data Masking NFR-01.
"""

import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.modules.dashboard.service import DashboardService


class TestSecurityPdfExport(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_s08a_pdf_export_endpoint(self):
        """Kiểm tra API GET /api/v1/dashboard/export?format=pdf trả về application/pdf chuẩn."""
        response = self.client.get("/api/v1/dashboard/export?format=pdf")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF-1.4"), "Nội dung phải là file PDF-1.4 hợp lệ")

    def test_s08b_secret_masked_in_pdf(self):
        """Kiểm tra báo cáo PDF tuân thủ S3-08b: che toàn bộ bí mật, không để lộ plaintext."""
        pdf_bytes = DashboardService.generate_security_pdf()
        self.assertIn(b"ghp_****1a2b", pdf_bytes, "Chuỗi bí mật PAT phải được che mặt nạ")
        self.assertIn(b"AKIA****5E12", pdf_bytes, "Khóa AWS phải được che mặt nạ")
        self.assertIn(b"0010****2345", pdf_bytes, "Số CCCD phải được che mặt nạ")
        # Đảm bảo không chứa secret plaintext giả định
        self.assertNotIn(b"ghp_realplaintexttoken1234567890", pdf_bytes)


if __name__ == "__main__":
    unittest.main()

