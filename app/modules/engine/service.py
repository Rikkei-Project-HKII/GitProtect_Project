"""
GitProtect MVP - MOD-02: Scanning & Detection Engine Service (FR-06, FR-07, FR-08)
Quy trình lọc 3 lớp (3-Tier Pipeline) & 7 Detection Rules chuẩn hệ thống.
"""

import re
import math
import time
from typing import Dict, Any, List, Optional


class DetectionEngineService:
    # Danh sách tập tin mẫu thuộc Allowlist cần bỏ qua (RULE-03, FR-06)
    ALLOWLIST_FILES = (
        ".env.example", ".env.sample", ".env.template", ".env.dist", ".env.test",
        "sample.env", "example.env"
    )

    # Từ khóa nhận diện mock/dummy test data
    DUMMY_KEYWORDS = ("dummy", "mock", "example", "fake", "placeholder", "test_token")

    # Từ khóa ngữ cảnh CCCD Việt Nam (RULE-05, FR-07)
    CCCD_CONTEXT_KEYWORDS = ("cccd", "cmnd", "can cuoc", "identity", "so can cuoc", "citizen_id")

    # Regex nhận diện 7 Rules chuẩn
    PATTERNS = {
        "RULE-01": (
            r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
            "GitHub Personal Access Token (PAT) & Fine-grained",
            "critical",
        ),
        "RULE-02": (
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            "Private Keys Block (RSA, EC, OpenSSH, DSA)",
            "critical",
        ),
        "RULE-03": (
            r"(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|SECRET|PASSWORD|PASSWD|PWD|TOKEN|DATABASE_URL))\s*=\s*(?:\"([^\"]{20,})\"|'([^']{20,})'|([^\s#\"']{20,}))",
            "Production Environment Secret File & Assignments",
            "high",
        ),
        "RULE-04": (
            r"\b(?:AKIA|ASIA|A3T[A-Z0-9])[0-9A-Z]{16}\b",
            "AWS Access Key ID & Secret Access Key",
            "critical",
        ),
        "RULE-05": (
            r"\b0(?:0[1-9]|[1-8][0-9]|9[0-6])[0-3][0-9]{2}[0-9]{6}\b",
            "Vietnamese Citizen ID Number (CCCD)",
            "high",
        ),
        "RULE-06": (
            r"(?i)(xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}|https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,20}\/[a-zA-Z0-9_-]{68})",
            "Slack / Discord Bot & Webhook Token",
            "high",
        ),
        "RULE-07": (
            r"(?i)\b[a-z0-9_]*(?:token|secret|password|passwd|pwd|api_?key|private_?key|auth)[a-z0-9_]*\s*[:=]\s*(?:[\"'])([^\"'\s]{20,128})(?:[\"'])",
            "High Entropy Generic Secret Token",
            "medium",
        ),
    }

    @staticmethod
    def calculate_shannon_entropy(s: str) -> float:
        """Tính toán Shannon Entropy H(X) theo công thức toán học Phần A."""
        if not s:
            return 0.0
        entropy = 0.0
        length = len(s)
        for char in set(s):
            p_x = s.count(char) / length
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return round(entropy, 2)

    @classmethod
    def mask_secret(cls, raw: str) -> str:
        """Tạo mặt nạ dữ liệu (Data Masking) chuẩn NFR-01: Tiền tố + '****' + 4 ký tự cuối."""
        if not raw or len(raw) <= 8:
            return "****"
        if raw.startswith("ghp_"):
            return f"ghp_****{raw[-4:]}"
        if raw.startswith("github_pat_"):
            return f"github_pat_****{raw[-4:]}"
        if raw.startswith("-----BEGIN"):
            return "-----BEGIN **** KEY-----"
        return f"{raw[:4]}****{raw[-4:]}"

    @classmethod
    def evaluate_snippet(cls, content: str, file_path: str = "snippet.txt") -> Dict[str, Any]:
        """Thực thi Pipeline quét 3 lớp trên nội dung văn bản."""
        start_time = time.perf_counter()
        findings: List[Dict[str, Any]] = []

        lower_path = (file_path or "").lower()
        is_allowlisted_file = any(
            lower_path.endswith(f) or f in lower_path for f in cls.ALLOWLIST_FILES
        )

        is_test_dir = any(
            part in lower_path for part in ("tests/", "test/", "spec/", "mock/", "fixture/")
        )

        # LỚP 1: Tiền lọc Định dạng & Độ dài (Regex)
        for rule_code, (pattern, rule_name, default_sev) in cls.PATTERNS.items():
            matches = list(re.finditer(pattern, content, re.MULTILINE))
            if not matches:
                continue

            for match in matches:
                matched_str = match.group(0)

                # LỚP 3: Ngoại lệ Allowlist & Mock Filter
                # Nếu là tệp mẫu (.env.example / .env.sample / .env.template...) -> bỏ qua hoàn toàn
                if is_allowlisted_file:
                    continue

                # Nếu là thư mục test hoặc chứa dummy/mock -> bỏ qua
                lower_matched = matched_str.lower()
                if (is_test_dir or any(d in lower_matched for d in cls.DUMMY_KEYWORDS)) and rule_code != "RULE-05":
                    continue

                # LỚP 2: Phân tích Shannon Entropy & Ngữ cảnh
                if rule_code == "RULE-05":
                    # Kiểm tra ngữ cảnh xung quanh có chứa từ khóa CCCD/CMND không
                    start_idx = max(0, match.start() - 60)
                    end_idx = min(len(content), match.end() + 60)
                    context_window = content[start_idx:end_idx].lower()
                    if not any(kw in context_window for kw in cls.CCCD_CONTEXT_KEYWORDS):
                        continue  # Loại trừ số điện thoại/mã vận đơn không có ngữ cảnh CCCD

                elif rule_code in ("RULE-01", "RULE-03", "RULE-04", "RULE-06", "RULE-07"):
                    # Kiểm tra độ dài & Shannon Entropy
                    secret_val = match.group(len(match.groups())) or matched_str
                    entropy = cls.calculate_shannon_entropy(secret_val)
                    if len(secret_val) >= 20 and entropy < 3.0:
                        continue  # Loại trừ chuỗi lặp lại hoặc có entropy quá thấp

                # Đã vượt qua cả 3 lớp -> Ghi nhận cảnh báo vi phạm
                masked_val = cls.mask_secret(matched_str)
                findings.append({
                    "rule_code": rule_code,
                    "rule_name": rule_name,
                    "severity": default_sev,
                    "matched_snippet": masked_val,
                    "line_number": content[:match.start()].count("\n") + 1,
                    "entropy": cls.calculate_shannon_entropy(matched_str),
                })

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "is_leaked": len(findings) > 0,
            "file_allowlisted": is_allowlisted_file,
            "execution_time_ms": elapsed_ms,
            "findings": findings,
        }
