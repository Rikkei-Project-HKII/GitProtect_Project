
import re
import time

from app.modules.engine.regex_engine import RegexEngine
from app.modules.engine.service import DetectionEngineService


class ScanPipeline:
    """Three-layer GitProtect detection pipeline."""

    CONTEXT_KEYWORDS = (
        "key",
        "secret",
        "token",
        "password",
    )

    ALLOWLIST_FILES = {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        ".env.test",
    }

    MOCK_DIRECTORIES = {
        "mock",
        "mocks",
        "dummy",
        "dummies",
    }

    def __init__(self):
        self.regex_engine = RegexEngine()

    def is_allowlisted(self, file_path: str) -> bool:
        normalized = file_path.replace("\\", "/").lower()
        filename = normalized.rsplit("/", 1)[-1]
        directories = set(normalized.split("/")[:-1])

        return (
            filename in self.ALLOWLIST_FILES
            or bool(directories & self.MOCK_DIRECTORIES)
        )

    def has_context(
        self,
        content: str,
        start: int,
        end: int,
    ) -> bool:
        context = content[
            max(0, start - 50):
            min(len(content), end + 50)
        ].lower()

        return any(
            keyword in context
            for keyword in self.CONTEXT_KEYWORDS
        )

    @staticmethod
    def mask_secret(candidate: str) -> str:
        if len(candidate) <= 8:
            return "*" * len(candidate)

        return (
            candidate[:4]
            + "*" * (len(candidate) - 8)
            + candidate[-4:]
        )

    def scan(self, content: str, file_path: str) -> dict:
        started_at = time.perf_counter()

        # Bỏ qua file mẫu và thư mục mock/dummy.
        if self.is_allowlisted(file_path):
            return {
                "is_leaked": False,
                "file_allowlisted": True,
                "execution_time_ms": round(
                    (time.perf_counter() - started_at) * 1000, 2
                ),
                "findings": [],
            }

        # TIER 1: REGEX PREFILTER
        regex_result = self.regex_engine.scan(content)

        if regex_result["timed_out"]:
            return {
                "is_leaked": False,
                "file_allowlisted": False,
                "execution_time_ms": regex_result["execution_time_ms"],
                "findings": [],
            }

        findings = []

        for match in regex_result["matches"]:
            raw_candidate = match["value"]
            start = match["start"]
            end = match["end"]

            # Tách giá trị bên phải dấu = hoặc : nếu có.
            value_match = re.search(
                r"""(?:=|:)\s*["']?([^"']+)["']?$""",
                raw_candidate,
            )

            if value_match:
                candidate = value_match.group(1).strip()

                # Cập nhật vị trí chính xác của secret trong nội dung.
                leading_spaces = len(value_match.group(1)) - len(
                    value_match.group(1).lstrip()
                )
                start += value_match.start(1) + leading_spaces
                end = start + len(candidate)
            else:
                candidate = raw_candidate

            # Loại chuỗi quá lặp lại.
            if len(set(candidate)) <= 2:
                continue

            repetitive = False

            for size in range(
                1,
                min(5, len(candidate) // 2) + 1
            ):
                if len(candidate) % size == 0:
                    if candidate == candidate[:size] * (
                        len(candidate) // size
                    ):
                        repetitive = True
                        break

            if repetitive:
                continue

            # TIER 2: SHANNON ENTROPY
            entropy_result = DetectionEngineService.evaluate_entropy(
                candidate
            )

            if not entropy_result["passed"]:
                continue

            # TIER 3: CONTEXT ANALYSIS
            if not any(char.isalpha() for char in candidate):
                continue

            if not any(char.isdigit() for char in candidate):
                continue

            if not self.has_context(content, start, end):
                continue

            line_number = content.count("\n", 0, start) + 1

            findings.append({
                "rule_code": "ENTROPY-001",
                "rule_name": "High Entropy Secret Detection",
                "severity": "medium",
                "line_number": line_number,
                "secret_masked": self.mask_secret(candidate),
                "charset_detected": entropy_result["charset"],
                "shannon_entropy": entropy_result["entropy"],
                "threshold_applied": entropy_result["threshold"],
                "context_matched": True,
            })

        elapsed_ms = (time.perf_counter() - started_at) * 1000

        return {
            "is_leaked": len(findings) > 0,
            "file_allowlisted": False,
            "execution_time_ms": round(elapsed_ms, 2),
            "findings": findings,
        }
