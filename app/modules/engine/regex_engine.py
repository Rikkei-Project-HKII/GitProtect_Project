
import time
import regex


# Giới hạn tối đa theo yêu cầu GitProtect
MAX_SCAN_TIME_SECONDS = 0.5

# Pattern lọc chuỗi liên tục có tối thiểu 20 ký tự
DEFAULT_PATTERNS = [
    r"\S{20,}",
]


class RegexEngine:
    """
    Regex Engine của GitProtect.
    Giới hạn tổng thời gian chạy regex trên một file là 500ms.
    """

    def __init__(self, patterns=None, timeout=MAX_SCAN_TIME_SECONDS):
        self.timeout = min(timeout, MAX_SCAN_TIME_SECONDS)

        if self.timeout <= 0:
            raise ValueError("Regex timeout must be greater than zero")

        selected_patterns = (
            DEFAULT_PATTERNS if patterns is None else patterns
        )

        self.patterns = [
            regex.compile(pattern)
            for pattern in selected_patterns
        ]

    def scan(self, content: str) -> dict:
        start_time = time.perf_counter()
        deadline = start_time + self.timeout

        matches = []

        try:
            for pattern in self.patterns:

                remaining_time = deadline - time.perf_counter()

                if remaining_time <= 0:
                    raise TimeoutError("Regex scan exceeded time limit")

                for match in pattern.finditer(
                    content,
                    timeout=remaining_time
                ):
                    if time.perf_counter() > deadline:
                        raise TimeoutError(
                            "Regex scan exceeded time limit"
                        )

                    matches.append({
                        "value": match.group(),
                        "start": match.start(),
                        "end": match.end(),
                    })

        except TimeoutError:
            elapsed = time.perf_counter() - start_time

            return {
                "success": False,
                "timed_out": True,
                "matches": [],
                "execution_time_ms": round(elapsed * 1000, 2),
                "error": "REGEX_TIMEOUT",
            }

        elapsed = time.perf_counter() - start_time

        return {
            "success": True,
            "timed_out": False,
            "matches": matches,
            "execution_time_ms": round(elapsed * 1000, 2),
            "error": None,
        }
