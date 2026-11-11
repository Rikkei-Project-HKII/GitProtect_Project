
import unittest

from app.modules.engine.regex_engine import RegexEngine


class TestRegexEngine(unittest.TestCase):

    def test_detect_candidate(self):
        engine = RegexEngine()

        result = engine.scan(
            "password = abcdefghijklmnopqrstuvwxyz123456"
        )

        self.assertTrue(result["success"])
        self.assertFalse(result["timed_out"])
        self.assertGreater(len(result["matches"]), 0)

    def test_ignore_short_string(self):
        engine = RegexEngine()

        result = engine.scan("hello world")

        self.assertTrue(result["success"])
        self.assertEqual(len(result["matches"]), 0)

    def test_timeout_never_exceeds_500ms_config(self):
        engine = RegexEngine(timeout=10)

        self.assertLessEqual(engine.timeout, 0.5)

    def test_invalid_timeout(self):
        with self.assertRaises(ValueError):
            RegexEngine(timeout=0)


if __name__ == "__main__":
    unittest.main()
