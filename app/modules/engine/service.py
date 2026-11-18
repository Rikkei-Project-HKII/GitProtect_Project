import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional


ENTROPY_THRESHOLDS = {
    "hex": (3.00, 3.30),
    "base32": (3.50, 3.90),
    "base64": (3.80, 4.20),
    "ascii": (3.90, 4.40),
}

MIN_SECRET_LENGTH = 20

RULES_REDIS_CACHE_KEY = "gitprotect:rules:all"
RULES_REDIS_CACHE_TTL = 300

# Danh sách 7 quy tắc quét chuẩn hệ thống (RULE-01 đến RULE-07) đồng bộ 100% với CSDL & SRS
STANDARD_SCAN_RULES: list[dict[str, Any]] = [
    {
        "id": 1,
        "rule_code": "RULE-01",
        "rule_name": "GitHub Personal Access Token (PAT) & Fine-grained",
        "description": "Phát hiện GitHub Classic PAT (ghp_) và Fine-grained PAT (github_pat_) bị lộ trong mã nguồn.",
        "pattern_regex": r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
        "charset_type": "none",
        "min_entropy_threshold": 3.00,
        "min_entropy_threshold_long": None,
        "min_length": 20,
        "context_keywords": "github,pat,token,auth,ghp",
        "default_severity": "critical",
        "allowlist_patterns": "dummy,mock,example",
        "is_enabled": True,
        "created_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": 2,
        "rule_code": "RULE-02",
        "rule_name": "Private Keys Block (RSA, EC, OpenSSH, DSA)",
        "description": "Phát hiện khối khóa riêng tư (BEGIN PRIVATE KEY) mức Critical; tệp *.pem/*.key không có header xếp Medium.",
        "pattern_regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        "charset_type": "none",
        "min_entropy_threshold": None,
        "min_entropy_threshold_long": None,
        "min_length": 20,
        "context_keywords": "private_key,id_rsa,id_ed25519,pem,key",
        "default_severity": "critical",
        "allowlist_patterns": "tests/mock,test_keys,dummy_key",
        "is_enabled": True,
        "created_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": 3,
        "rule_code": "RULE-03",
        "rule_name": "Production Environment Secret File & Assignments",
        "description": "Phát hiện biến môi trường nhạy cảm trong file .env thực tế; loại trừ các tệp mẫu allowlist (.env.example...).",
        "pattern_regex": r'(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|SECRET|PASSWORD|PASSWD|PWD|TOKEN|DATABASE_URL))\s*=\s*(?:"([^"\r\n]{20,})"|\'([^\'\r\n]{20,})\'|([^\s#"\']{20,}))',
        "charset_type": "dynamic",
        "min_entropy_threshold": None,
        "min_entropy_threshold_long": None,
        "min_length": 20,
        "context_keywords": "KEY,SECRET,PASSWORD,PASSWD,PWD,TOKEN,DATABASE_URL",
        "default_severity": "high",
        "allowlist_patterns": ".env.example,.env.sample,.env.template,.env.dist,.env.test",
        "is_enabled": True,
        "created_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": 4,
        "rule_code": "RULE-04",
        "rule_name": "AWS Access Key ID & Secret Access Key",
        "description": "Phát hiện cặp phép gán AWS Access Key ID và Secret Access Key 40 ký tự gần nhau (khoảng cách tối đa 200 ký tự); entropy được kiểm tra trên Secret theo bảng ngưỡng động.",
        "pattern_regex": r"\b(?:AKIA|ASIA|A3T[A-Z0-9])[0-9A-Z]{16}\b",
        "charset_type": "dynamic",
        "min_entropy_threshold": None,
        "min_entropy_threshold_long": None,
        "min_length": 20,
        "context_keywords": "aws_access_key,aws_secret,akia,asia,aws",
        "default_severity": "critical",
        "allowlist_patterns": "AKIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "is_enabled": True,
        "created_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": 5,
        "rule_code": "RULE-05",
        "rule_name": "Vietnamese Citizen ID Number (CCCD)",
        "description": "Nhận diện số Căn cước công dân Việt Nam 12 chữ số (mã tỉnh 001-096, mã thế kỷ/giới tính 0-3) kèm từ khóa ngữ cảnh.",
        "pattern_regex": r"\b0(?:0[1-9]|[1-8][0-9]|9[0-6])[0-3][0-9]{2}[0-9]{6}\b",
        "charset_type": "none",
        "min_entropy_threshold": None,
        "min_entropy_threshold_long": None,
        "min_length": 20,
        "context_keywords": "cccd,cmnd,can cuoc,identity,so can cuoc",
        "default_severity": "high",
        "allowlist_patterns": "order_number,tracking_code,phone",
        "is_enabled": True,
        "created_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": 6,
        "rule_code": "RULE-06",
        "rule_name": "Slack / Discord Bot & Webhook Token",
        "description": "Phát hiện Slack Bot Token (xoxb-) và Discord Webhook URL có phần ngẫu nhiên đạt ngưỡng Entropy >= 3.0 bits.",
        "pattern_regex": r"(?i)(xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}|https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,20}\/[a-zA-Z0-9_-]{68})",
        "charset_type": "none",
        "min_entropy_threshold": 3.00,
        "min_entropy_threshold_long": None,
        "min_length": 20,
        "context_keywords": "slack,discord,webhook,xoxb,bot_token",
        "default_severity": "high",
        "allowlist_patterns": "xoxb-00000000000,dummy,mock",
        "is_enabled": True,
        "created_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": 7,
        "rule_code": "RULE-07",
        "rule_name": "High Entropy Generic Secret Token",
        "description": "Phát hiện chuỗi bí mật ngẫu nhiên cao (Zero-day/Generic Secret) qua pipeline 3 lớp và bảng ngưỡng động Phần A.",
        "pattern_regex": r'(?i)\b[a-z0-9_]*(?:token|secret|password|passwd|pwd|api_?key|private_?key|auth)[a-z0-9_]*\s*[:=]\s*(["\'])([^"\'\s]{20,128})\1',
        "charset_type": "dynamic",
        "min_entropy_threshold": None,
        "min_entropy_threshold_long": None,
        "min_length": 20,
        "context_keywords": "token,secret,password,passwd,pwd,api_key,apikey,private_key,auth",
        "default_severity": "medium",
        "allowlist_patterns": ".env.example,.env.sample,.env.template,.env.dist,.env.test,dummy,mock",
        "is_enabled": True,
        "created_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 11, 6, 20, 0, 0, tzinfo=timezone.utc),
    },
]

_CCCD_REGEX = re.compile(r"^\d{12}$")
_CCCD_CONTEXT_KEYWORDS = (
    "cccd",
    "cmnd",
    "can cuoc",
    "căn cước",
    "identity",
    "so can cuoc",
    "số căn cước",
)
_CCCD_NEGATIVE_KEYWORDS = (
    "order_number",
    "tracking_code",
    "ma van don",
    "mã vận đơn",
    "phone",
    "so dien thoai",
)


class DetectionEngineService:

    @staticmethod
    def detect_charset(value: str) -> str:
        """
        S2-01: Tự động nhận diện tập ký tự theo đúng thứ tự ưu tiên:
        Hex -> Base32 -> Base64 -> ASCII.
        """
        if not value:
            return "none"

        if all(c in "0123456789abcdefABCDEF" for c in value):
            return "hex"

        # Base32 chuẩn A-Z và 2-7 (hỗ trợ ký tự padding '=' ở cuối nếu có)
        stripped_b32 = value.rstrip("=")
        if stripped_b32 and all(
            c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in stripped_b32
        ) and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for c in value):
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
    def validate_vietnamese_cccd(
        candidate: str,
        surrounding_context: str = "",
    ) -> bool:
        """
        S2-02 (RULE-05 - FR-07): Kiểm tra số Căn cước công dân Việt Nam 12 chữ số:
        - 3 số đầu: mã tỉnh/thành phố [001 - 096]
        - Số thứ 4: mã thế kỷ & giới tính [0 - 3]
        - 2 số tiếp theo: năm sinh [00 - 99]
        - 6 số cuối: số ngẫu nhiên
        - Bắt buộc có từ khóa ngữ cảnh CCCD/CMND trong phạm vi 50 ký tự.
        """
        if not candidate or not _CCCD_REGEX.fullmatch(candidate):
            return False

        province_code = int(candidate[:3])
        if not (1 <= province_code <= 96):
            return False

        century_gender = int(candidate[3])
        if century_gender not in (0, 1, 2, 3):
            return False

        ctx_lower = (surrounding_context or "").lower()
        has_positive_ctx = any(kw in ctx_lower for kw in _CCCD_CONTEXT_KEYWORDS)
        if not has_positive_ctx:
            return False

        has_negative_ctx = any(kw in ctx_lower for kw in _CCCD_NEGATIVE_KEYWORDS)
        if has_negative_ctx and not any(
            kw in ctx_lower for kw in ("cccd", "cmnd", "can cuoc", "căn cước", "so can cuoc")
        ):
            return False

        return True

    @staticmethod
    def list_rules(
        is_enabled: Optional[bool] = None,
        severity: Optional[Any] = None,
        db: Optional[Any] = None,
        redis_client: Optional[Any] = None,
    ) -> dict[str, Any]:
        """
        S2-05: Lấy danh sách 7 quy tắc quét chuẩn (RULE-01 đến RULE-07),
        hỗ trợ lọc theo `is_enabled`, `severity` và cache trên Redis RAM.
        """
        rules_data: Optional[list[dict[str, Any]]] = None

        # 1. Thử đọc từ Redis cache nếu có kết nối
        if redis_client is not None:
            try:
                cached = redis_client.get(RULES_REDIS_CACHE_KEY)
                if cached:
                    if isinstance(cached, bytes):
                        cached = cached.decode("utf-8")
                    rules_data = json.loads(cached)
            except Exception:
                rules_data = None

        # 2. Thử đọc từ CSDL nếu truyền Session db
        if rules_data is None and db is not None:
            try:
                from sqlalchemy import select
                from app.models.scan_rule import ScanRule

                rows = db.scalars(select(ScanRule).order_by(ScanRule.id.asc())).all()
                if rows:
                    rules_data = [
                        {
                            "id": r.id,
                            "rule_code": r.rule_code,
                            "rule_name": r.rule_name,
                            "description": r.description,
                            "pattern_regex": r.pattern_regex,
                            "charset_type": r.charset_type,
                            "min_entropy_threshold": (
                                float(r.min_entropy_threshold)
                                if r.min_entropy_threshold is not None
                                else None
                            ),
                            "min_entropy_threshold_long": (
                                float(r.min_entropy_threshold_long)
                                if r.min_entropy_threshold_long is not None
                                else None
                            ),
                            "min_length": r.min_length,
                            "context_keywords": r.context_keywords,
                            "default_severity": r.default_severity,
                            "allowlist_patterns": r.allowlist_patterns,
                            "is_enabled": bool(r.is_enabled),
                            "created_at": r.created_at,
                            "updated_at": r.updated_at,
                        }
                        for r in rows
                    ]
            except Exception:
                rules_data = None

        # 3. Fallback về bộ 7 quy tắc chuẩn trong bộ nhớ
        if not rules_data:
            rules_data = [dict(item) for item in STANDARD_SCAN_RULES]

        # Lưu lại vào Redis cache nếu có redis_client
        if redis_client is not None:
            try:
                serializable = [
                    {
                        **r,
                        "created_at": (
                            r["created_at"].isoformat()
                            if hasattr(r["created_at"], "isoformat")
                            else str(r["created_at"])
                        ),
                        "updated_at": (
                            r["updated_at"].isoformat()
                            if hasattr(r["updated_at"], "isoformat")
                            else str(r["updated_at"])
                        ),
                    }
                    for r in rules_data
                ]
                redis_client.set(
                    RULES_REDIS_CACHE_KEY,
                    json.dumps(serializable),
                    ex=RULES_REDIS_CACHE_TTL,
                )
            except Exception:
                pass

        severity_val = (
            severity.value if hasattr(severity, "value") else (str(severity).lower() if severity else None)
        )

        filtered = []
        for rule in rules_data:
            if is_enabled is not None and bool(rule["is_enabled"]) != bool(is_enabled):
                continue
            if severity_val is not None and str(rule["default_severity"]).lower() != severity_val:
                continue
            filtered.append(rule)

        return {
            "items": filtered,
            "total": len(filtered),
        }

    @staticmethod
    def evaluate_snippet(content: str, file_path: str):
        # Import tại đây để tránh circular import.
        from app.modules.engine.scan_pipeline import ScanPipeline

        pipeline = ScanPipeline()
        return pipeline.scan(content, file_path)

    @staticmethod
    def enqueue_commit_scan(
        job_payload: dict[str, Any],
        redis_client: Optional[Any] = None,
    ) -> str:
        from app.modules.engine.worker import ScanQueueWorker

        worker = ScanQueueWorker(redis_client=redis_client)
        return worker.enqueue_job(job_payload, redis_client=redis_client)

    @staticmethod
    def consume_next_scan_job(
        redis_client: Optional[Any] = None,
        db: Optional[Any] = None,
        timeout: int = 0,
    ) -> Optional[dict[str, Any]]:
        from app.modules.engine.worker import ScanQueueWorker

        worker = ScanQueueWorker(redis_client=redis_client)
        return worker.consume_once(
            redis_client=redis_client,
            db=db,
            timeout=timeout,
        )