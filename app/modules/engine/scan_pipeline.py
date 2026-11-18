import regex as re
import time

from app.modules.engine.regex_engine import RegexEngine
from app.modules.engine.service import DetectionEngineService


UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
STRIP_CHARS = "\"'`;,()[]{}"

# Các biểu thức chính quy chuyên biệt của Bộ 7 Detection Rules chuẩn (RULE-01 đến RULE-07)
RULE_01_GITHUB_PAT_RE = re.compile(
    r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b"
)
RULE_02_PRIVATE_KEY_HEADER_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
)
RULE_03_ENV_ASSIGNMENT_RE = re.compile(
    r'(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|SECRET|PASSWORD|PASSWD|PWD|TOKEN|DATABASE_URL))\s*=\s*(?:"([^"\r\n]{20,})"|\'([^\'\r\n]{20,})\'|([^\s#"\']{20,}))'
)
RULE_04_AWS_KEY_RE = re.compile(
    r"\b((?:AKIA|ASIA|A3T[A-Z0-9])[0-9A-Z]{16})\b"
)
RULE_05_VN_CCCD_RE = re.compile(
    r"\b(0(?:0[1-9]|[1-8][0-9]|9[0-6])[0-3][0-9]{2}[0-9]{6})\b"
)
RULE_06_SLACK_DISCORD_RE = re.compile(
    r"(?i)(xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}|https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,20}\/[a-zA-Z0-9_-]{68})"
)


# Pair only nearby explicit AWS assignments; unrelated strings are not credentials.
AWS_ID_CONTEXT_RE = re.compile(r'(?i)\baws_access_key(?:_id)?[ \t]*=[ \t]*["\']?$')
AWS_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\baws_secret(?:_access_key|_key)?[ \t]*=[ \t]*"
    r"(?:\"([A-Za-z0-9/+]{40})\"|'([A-Za-z0-9/+]{40})'|([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=]))"
)
AWS_PAIR_MAX_GAP = 200


class ScanPipeline:
    """
    Three-layer GitProtect detection pipeline integrating the 7 Standard Detection Rules
    (RULE-01 to RULE-07).
    """

    CONTEXT_KEYWORDS = (
        "key",
        "secret",
        "token",
        "password",
        "passwd",
        "pwd",
        "api_key",
        "apikey",
        "private_key",
        "auth",
    )

    ALLOWLIST_FILES = {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        ".env.test",
    }

    ALLOWLIST_SUFFIXES = (
        ".example",
        ".sample",
        ".template",
    )

    MOCK_DIRECTORIES = {
        "mock",
        "mocks",
        "dummy",
        "dummies",
        "test_keys",
    }

    MOCK_VALUE_MARKERS = (
        "dummy",
        "mock",
        "akiaiosfodnn7example",
        "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
        "xoxb-00000000000",
    )

    def __init__(self, regex_engine: RegexEngine | None = None):
        self.regex_engine = regex_engine or RegexEngine()

    def is_allowlisted(self, file_path: str) -> bool:
        """
        S2-03 (FR-06): Kiểm tra tệp có thuộc danh sách Allowlist mẫu (.env.example,
        .env.sample, .env.template, .env.dist, .env.test) hoặc thư mục mock/dummy không.
        """
        if not file_path:
            return False
        normalized = file_path.replace("\\", "/").lower().strip()
        filename = normalized.rsplit("/", 1)[-1]
        directories = set(normalized.split("/")[:-1])

        if filename in self.ALLOWLIST_FILES:
            return True
        if any(filename.endswith(suffix) for suffix in self.ALLOWLIST_SUFFIXES):
            return True
        if bool(directories & self.MOCK_DIRECTORIES):
            return True
        return False

    @staticmethod
    def _is_env_file(file_path: str) -> bool:
        if not file_path:
            return False
        normalized = file_path.replace("\\", "/").lower().strip()
        filename = normalized.rsplit("/", 1)[-1]
        return filename == ".env" or filename.startswith(".env.")

    @staticmethod
    def _is_pem_or_key_file(file_path: str) -> bool:
        if not file_path:
            return False
        normalized = file_path.replace("\\", "/").lower().strip()
        filename = normalized.rsplit("/", 1)[-1]
        return filename.endswith(".pem") or filename.endswith(".key")

    def has_context(
        self,
        content: str,
        start: int,
        end: int,
    ) -> bool:
        before_ctx = content[max(0, start - 50):start].lower()
        after_ctx = content[end:min(len(content), end + 50)].lower()
        surrounding = f"{before_ctx} {after_ctx}"

        return any(
            keyword in surrounding
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

    @staticmethod
    def _is_repetitive_or_uuid(candidate: str) -> bool:
        if UUID_PATTERN.fullmatch(candidate):
            return True

        if len(set(candidate)) <= 2:
            return True

        for size in range(1, min(5, len(candidate) // 2) + 1):
            if len(candidate) % size == 0:
                if candidate == candidate[:size] * (len(candidate) // size):
                    return True

        return False

    def _is_mock_value(self, value: str) -> bool:
        lower_val = value.lower()
        return any(marker in lower_val for marker in self.MOCK_VALUE_MARKERS)

    @staticmethod
    def _span_overlaps(span: tuple[int, int], occupied_spans: list[tuple[int, int]]) -> bool:
        s_start, s_end = span
        for o_start, o_end in occupied_spans:
            if max(s_start, o_start) < min(s_end, o_end):
                return True
        return False

    @staticmethod
    def _finditer(pattern, content: str, deadline: float):
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise TimeoutError("SCAN_TIMEOUT")
        for match in pattern.finditer(content, timeout=remaining):
            if time.perf_counter() >= deadline:
                raise TimeoutError("SCAN_TIMEOUT")
            yield match

    def _scan_specific_rules(
        self,
        content: str,
        file_path: str,
        deadline: float,
    ) -> tuple[list[dict], list[tuple[int, int]]]:
        """
        Quét các quy tắc định danh cụ thể (RULE-01 đến RULE-06) và trả về
        danh sách findings cùng các khoảng vị trí (start, end) đã khớp để
        RULE-07 không tạo cảnh báo trùng lặp.
        """
        findings: list[dict] = []
        occupied_spans: list[tuple[int, int]] = []

        # 1. RULE-01: GitHub Personal Access Token (PAT) & Fine-grained (Critical)
        for m in self._finditer(RULE_01_GITHUB_PAT_RE, content, deadline):
            token = m.group(1)
            if self._is_mock_value(token):
                continue
            random_part = token.split("_")[-1]
            entropy = DetectionEngineService.calculate_shannon_entropy(random_part)
            if entropy < 3.00:
                continue
            span = (m.start(1), m.end(1))
            occupied_spans.append(span)
            findings.append({
                "rule_code": "RULE-01",
                "rule_name": "GitHub Personal Access Token (PAT) & Fine-grained",
                "severity": "critical",
                "line_number": content.count("\n", 0, span[0]) + 1,
                "secret_masked": self.mask_secret(token),
                "charset_detected": "base64",
                "shannon_entropy": entropy,
                "threshold_applied": 3.00,
                "context_matched": True,
            })

        # 2. RULE-02: Private Keys Block (Critical) & *.pem/*.key without Private Key Header (Medium)
        has_private_key_header = False
        for m in self._finditer(RULE_02_PRIVATE_KEY_HEADER_RE, content, deadline):
            has_private_key_header = True
            header_text = m.group(0)
            span = (m.start(0), m.end(0))
            occupied_spans.append(span)
            findings.append({
                "rule_code": "RULE-02",
                "rule_name": "Private Keys Block (RSA, EC, OpenSSH, DSA)",
                "severity": "critical",
                "line_number": content.count("\n", 0, span[0]) + 1,
                "secret_masked": self.mask_secret(header_text),
                "charset_detected": "none",
                "shannon_entropy": 0.0,
                "threshold_applied": None,
                "context_matched": True,
            })

        if not has_private_key_header and self._is_pem_or_key_file(file_path):
            first_line = (content.strip().splitlines() or [file_path])[0].strip()
            if not self._is_mock_value(first_line):
                findings.append({
                    "rule_code": "RULE-02",
                    "rule_name": "Private Keys Block (RSA, EC, OpenSSH, DSA)",
                    "severity": "medium",
                    "line_number": 1,
                    "secret_masked": self.mask_secret(first_line if len(first_line) >= 9 else f"cert_file_{file_path}"),
                    "charset_detected": "none",
                    "shannon_entropy": 0.0,
                    "threshold_applied": None,
                    "context_matched": True,
                })

        # RULE-04 requires a nearby ID/Secret pair, not an ID alone.
        secrets = list(self._finditer(AWS_SECRET_ASSIGNMENT_RE, content, deadline))
        used_secrets = set()
        for m in self._finditer(RULE_04_AWS_KEY_RE, content, deadline):
            aws_id = m.group(1)
            if self._is_mock_value(aws_id):
                continue
            if not AWS_ID_CONTEXT_RE.search(content[max(0, m.start() - 80):m.start()]):
                continue
            candidates = []
            for secret_match in secrets:
                if secret_match.start() in used_secrets:
                    continue
                gap = max(0, secret_match.start() - m.end(), m.start() - secret_match.end())
                if gap <= AWS_PAIR_MAX_GAP:
                    candidates.append((gap, secret_match.start(), secret_match))
            if not candidates:
                continue
            secret_match = min(candidates, key=lambda item: item[:2])[2]
            group = next(i for i in (1, 2, 3) if secret_match.group(i) is not None)
            secret = secret_match.group(group)
            if self._is_mock_value(secret):
                continue
            entropy_result = DetectionEngineService.evaluate_entropy(secret)
            if not entropy_result["passed"]:
                continue
            used_secrets.add(secret_match.start())
            occupied_spans.extend([m.span(1), secret_match.span(group)])
            findings.append({
                "rule_code": "RULE-04",
                "rule_name": "AWS Access Key ID & Secret Access Key",
                "severity": "critical",
                "line_number": content.count("\n", 0, m.start(1)) + 1,
                "secret_masked": self.mask_secret(aws_id),
                # Entropy metadata describes the paired Secret Access Key.
                "charset_detected": entropy_result["charset"],
                "shannon_entropy": entropy_result["entropy"],
                "threshold_applied": entropy_result["threshold"],
                "context_matched": True,
            })

        # 4. RULE-06: Slack / Discord Bot & Webhook Token (High)
        for m in self._finditer(RULE_06_SLACK_DISCORD_RE, content, deadline):
            bot_token = m.group(1)
            if self._is_mock_value(bot_token):
                continue
            span = (m.start(1), m.end(1))
            if self._span_overlaps(span, occupied_spans):
                continue
            random_tail = (bot_token.rsplit("/", 1)[-1] if bot_token.lower().startswith("https://")
                           else bot_token.rsplit("-", 1)[-1])
            entropy = DetectionEngineService.calculate_shannon_entropy(random_tail)
            if entropy < 3.00:
                continue
            occupied_spans.append(span)
            findings.append({
                "rule_code": "RULE-06",
                "rule_name": "Slack / Discord Bot & Webhook Token",
                "severity": "high",
                "line_number": content.count("\n", 0, span[0]) + 1,
                "secret_masked": self.mask_secret(bot_token),
                "charset_detected": DetectionEngineService.detect_charset(random_tail),
                "shannon_entropy": entropy,
                "threshold_applied": 3.00,
                "context_matched": True,
            })

        # 5. RULE-05: Vietnamese Citizen ID Number - CCCD 12 số (High)
        for m in self._finditer(RULE_05_VN_CCCD_RE, content, deadline):
            cccd = m.group(1)
            span = (m.start(1), m.end(1))
            if self._span_overlaps(span, occupied_spans):
                continue
            surrounding_ctx = (
                content[max(0, span[0] - 50):span[0]]
                + " "
                + content[span[1]:min(len(content), span[1] + 50)]
            )
            if not DetectionEngineService.validate_vietnamese_cccd(cccd, surrounding_ctx):
                continue
            occupied_spans.append(span)
            findings.append({
                "rule_code": "RULE-05",
                "rule_name": "Vietnamese Citizen ID Number (CCCD)",
                "severity": "high",
                "line_number": content.count("\n", 0, span[0]) + 1,
                "secret_masked": self.mask_secret(cccd),
                "charset_detected": "none",
                "shannon_entropy": DetectionEngineService.calculate_shannon_entropy(cccd),
                "threshold_applied": None,
                "context_matched": True,
            })

        # 6. RULE-03: Production Environment Secret File & Assignments (High)
        if self._is_env_file(file_path):
            for m in self._finditer(RULE_03_ENV_ASSIGNMENT_RE, content, deadline):
                val = m.group(2) or m.group(3) or m.group(4)
                if not val:
                    continue
                val_group_idx = 2 if m.group(2) is not None else (3 if m.group(3) is not None else 4)
                span = (m.start(val_group_idx), m.end(val_group_idx))
                if self._span_overlaps(span, occupied_spans):
                    continue
                cleaned_val = val.strip(STRIP_CHARS + " \t")
                if len(cleaned_val) < 20 or self._is_mock_value(cleaned_val):
                    continue
                if self._is_repetitive_or_uuid(cleaned_val):
                    continue
                entropy_res = DetectionEngineService.evaluate_entropy(cleaned_val)
                if not entropy_res["passed"]:
                    continue
                occupied_spans.append((m.start(0), m.end(0)))
                findings.append({
                    "rule_code": "RULE-03",
                    "rule_name": "Production Environment Secret File & Assignments",
                    "severity": "high",
                    "line_number": content.count("\n", 0, span[0]) + 1,
                    "secret_masked": self.mask_secret(cleaned_val),
                    "charset_detected": entropy_res["charset"],
                    "shannon_entropy": entropy_res["entropy"],
                    "threshold_applied": entropy_res["threshold"],
                    "context_matched": True,
                })

        return findings, occupied_spans

    def scan(self, content: str, file_path: str) -> dict:
        started_at = time.perf_counter()
        deadline = started_at + self.regex_engine.timeout
        return self._scan(content, file_path, started_at, deadline)

    def _scan(self, content: str, file_path: str, started_at: float, deadline: float) -> dict:

        # Bỏ qua file mẫu (.env.example, sample...) và thư mục mock/dummy (S2-03).
        if self.is_allowlisted(file_path):
            return {
                "is_leaked": False,
                "file_allowlisted": True,
                "execution_time_ms": round(
                    (time.perf_counter() - started_at) * 1000, 2
                ),
                "findings": [],
            }

        # TIER 1: REGEX PREFILTER (với kiểm soát Anti-ReDoS timeout 500ms)
        regex_result = self.regex_engine.scan(content, deadline=deadline)

        if regex_result["timed_out"]:
            raise TimeoutError("SCAN_TIMEOUT")

        # Quét các quy tắc chuyên biệt RULE-01 đến RULE-06 trước
        findings, occupied_spans = self._scan_specific_rules(content, file_path, deadline)

        # Quét RULE-07 (High Entropy Generic Secret Token) qua Pipeline 3 lớp
        for match in regex_result["matches"]:
            if time.perf_counter() >= deadline:
                raise TimeoutError("SCAN_TIMEOUT")
            candidate = match["value"]
            start, end = match["start"], match["end"]

            if self._span_overlaps((start, end), occupied_spans):
                continue

            if len(candidate) < 20:
                continue

            if self._is_repetitive_or_uuid(candidate):
                continue

            # TIER 2: SHANNON ENTROPY (Hex -> Base32 -> Base64 -> ASCII)
            entropy_result = DetectionEngineService.evaluate_entropy(
                candidate
            )

            if not entropy_result["passed"]:
                continue

            # TIER 3: CONTEXT ANALYSIS & EXCEPTION FILTER
            if self._is_mock_value(candidate):
                continue

            if not any(char.isalpha() for char in candidate):
                continue

            if not any(char.isdigit() for char in candidate):
                continue

            # Assignment context was already validated by RULE-07 in Tier 1.

            line_number = content.count("\n", 0, start) + 1
            occupied_spans.append((start, end))

            findings.append({
                "rule_code": "RULE-07",
                "rule_name": "High Entropy Generic Secret Token",
                "severity": "medium",
                "line_number": line_number,
                "secret_masked": self.mask_secret(candidate),
                "charset_detected": entropy_result["charset"],
                "shannon_entropy": entropy_result["entropy"],
                "threshold_applied": entropy_result["threshold"],
                "context_matched": True,
            })

        if time.perf_counter() >= deadline:
            raise TimeoutError("SCAN_TIMEOUT")
        elapsed_ms = (time.perf_counter() - started_at) * 1000

        return {
            "is_leaked": len(findings) > 0,
            "file_allowlisted": False,
            "execution_time_ms": round(elapsed_ms, 2),
            "findings": findings,
        }