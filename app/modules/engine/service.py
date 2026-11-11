
import math
from collections import Counter


ENTROPY_THRESHOLDS = {
    "hex": (3.00, 3.30),
    "base32": (3.50, 3.90),
    "base64": (3.80, 4.20),
    "ascii": (3.90, 4.40),
}

MIN_SECRET_LENGTH = 20


class DetectionEngineService:

    @staticmethod
    def detect_charset(value: str) -> str:
        if not value:
            return "none"

        if all(c in "0123456789abcdefABCDEF" for c in value):
            return "hex"

        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in value):
            return "base32"

        if all(
            c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/="
            for c in value
        ):
            return "base64"

        if all(33 <= ord(c) <= 126 for c in value):
            return "ascii"

        return "none"

    @staticmethod
    def calculate_shannon_entropy(value: str) -> float:
        if not value:
            return 0.0

        length = len(value)
        frequencies = Counter(value)

        entropy = 0.0

        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    @staticmethod
    def get_entropy_threshold(charset: str, length: int) -> float:
        if length < MIN_SECRET_LENGTH:
            raise ValueError(
                "Candidate must contain at least 20 characters"
            )

        if charset not in ENTROPY_THRESHOLDS:
            raise ValueError(f"Unsupported charset: {charset}")

        short_threshold, long_threshold = ENTROPY_THRESHOLDS[charset]

        return short_threshold if length <= 31 else long_threshold

    @staticmethod
    def evaluate_entropy(value: str) -> dict:
        charset = DetectionEngineService.detect_charset(value)
        entropy = DetectionEngineService.calculate_shannon_entropy(value)

        if len(value) < MIN_SECRET_LENGTH or charset == "none":
            return {
                "charset": charset,
                "length": len(value),
                "entropy": entropy,
                "threshold": None,
                "passed": False,
            }

        threshold = DetectionEngineService.get_entropy_threshold(
            charset,
            len(value)
        )

        return {
            "charset": charset,
            "length": len(value),
            "entropy": entropy,
            "threshold": threshold,
            "passed": entropy >= threshold,
        }

    @staticmethod
    def evaluate_snippet(content: str, file_path: str):
        # Import tại đây để tránh circular import.
        from app.modules.engine.scan_pipeline import ScanPipeline

        pipeline = ScanPipeline()
        return pipeline.scan(content, file_path)
