
import unittest

from app.modules.engine.scan_pipeline import ScanPipeline


class TestScanPipeline(unittest.TestCase):

    def setUp(self):
        self.pipeline = ScanPipeline()

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

        self.assertEqual(finding["rule_code"], "ENTROPY-001")
        self.assertEqual(finding["charset_detected"], "base64")
        self.assertTrue(finding["context_matched"])


    def test_mock_directory(self):
        result = self.pipeline.scan(
            "password=someverylongsecret123456",
            "tests/mock/config.py",
        )

        self.assertTrue(result["file_allowlisted"])


if __name__ == "__main__":
    unittest.main()
