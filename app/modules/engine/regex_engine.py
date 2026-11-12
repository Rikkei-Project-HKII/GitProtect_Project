
import time
import regex

from app.modules.engine.service import STANDARD_SCAN_RULES


# Giới hạn tối đa theo yêu cầu GitProtect
MAX_SCAN_TIME_SECONDS = 0.5

# RULE-07: chỉ lấy giá trị của phép gán biến nhạy cảm (20–128 ký tự).
DEFAULT_PATTERNS = [
    next(rule["pattern_regex"] for rule in STANDARD_SCAN_RULES
         if rule["rule_code"] == "RULE-07"),
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
        self.value_group = 2 if patterns is None else 0

        self.patterns = [
            regex.compile(pattern)
            for pattern in selected_patterns
        ]

    def scan(self, content: str, deadline: float | None = None) -> dict:
        start_time = time.perf_counter()
        deadline = min(deadline, start_time + self.timeout) if deadline is not None else start_time + self.timeout

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
                        "value": match.group(self.value_group),
                        "start": match.start(self.value_group),
                        "end": match.end(self.value_group),
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
