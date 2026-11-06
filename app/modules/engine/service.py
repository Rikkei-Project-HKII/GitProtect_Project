import math
import time

class DetectionEngineService:
    @staticmethod
    def calculate_shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        entropy = 0.0
        length = len(s)
        for char in set(s):
            p_x = s.count(char) / length
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return round(entropy, 2)

    @staticmethod
    def evaluate_snippet(content: str, file_path: str):
        start = time.perf_counter()
        allowlisted = any(content.strip().startswith(x) for x in [".env.example", ".env.sample"]) or file_path.endswith(".example")
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "is_leaked": False,
            "file_allowlisted": allowlisted,
            "execution_time_ms": elapsed_ms,
            "findings": []
        }
