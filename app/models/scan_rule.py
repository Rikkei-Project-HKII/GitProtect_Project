"""
GitProtect MVP (v1.1 Baseline - GP-2026-SCRUM)
Model 2: ScanRule - Quản lý bộ quy tắc phát hiện bí mật & Shannon Entropy (RULE-01..RULE-07)
"""

from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    String,
    Text,
    Numeric,
    Boolean,
    Enum,
    UniqueConstraint,
    CheckConstraint,
    Index,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects import mysql

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.security_alert import SecurityAlert


class ScanRule(Base):
    __tablename__ = "scan_rules"

    __table_args__ = (
        UniqueConstraint("rule_code", name="uk_rule_code"),
        CheckConstraint(
            "charset_type IN ('hex','base32','base64','ascii','dynamic','none')",
            name="chk_rule_charset_type",
        ),
        CheckConstraint(
            "min_entropy_threshold IS NULL OR (min_entropy_threshold BETWEEN 0.00 AND 8.00)",
            name="chk_rule_min_entropy_short",
        ),
        CheckConstraint(
            "min_entropy_threshold_long IS NULL OR (min_entropy_threshold_long BETWEEN 0.00 AND 8.00)",
            name="chk_rule_min_entropy_long",
        ),
        CheckConstraint(
            "min_length >= 20",
            name="chk_rule_min_length",
        ),
        CheckConstraint(
            "default_severity IN ('critical','high','medium','low')",
            name="chk_rule_default_severity",
        ),
        Index("idx_rule_name", "rule_name"),
        Index("idx_rule_enabled", "is_enabled"),
        {
            "mysql_engine": "InnoDB",
            "mysql_charset": "utf8mb4",
            "mysql_collate": "utf8mb4_unicode_ci",
        },
    )

    id: Mapped[int] = mapped_column(
        mysql.BIGINT(),
        primary_key=True,
        autoincrement=True,
        nullable=False,
        comment="Khóa chính định danh quy tắc quét bí mật trong hệ thống",
    )
    rule_code: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Mã hiệu quy tắc chuẩn hóa duy nhất (ví dụ: RULE-01, RULE-05)",
    )
    rule_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        comment="Tên định danh quy tắc phát hiện bí mật hiển thị trên giao diện",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Mô tả chi tiết mục tiêu nghiệp vụ, loại bí mật cần quét và cơ chế phát hiện",
    )
    pattern_regex: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Biểu thức chính quy ở Lớp 1 (kiểm soát Anti-ReDoS timeout 500ms/file)",
    )
    charset_type: Mapped[str] = mapped_column(
        Enum("hex", "base32", "base64", "ascii", "dynamic", "none", name="enum_rule_charset_type"),
        nullable=False,
        server_default=text("'none'"),
        default="none",
        comment="Tập ký tự áp dụng cho Lớp 2; 'dynamic' tự nhận diện Hex -> Base32 -> Base64 -> ASCII",
    )
    min_entropy_threshold: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(4, 2),
        nullable=True,
        comment="Ngưỡng Shannon Entropy tối thiểu dải 20–31 ký tự (NULL nếu tra bảng động Phần A)",
    )
    min_entropy_threshold_long: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(4, 2),
        nullable=True,
        comment="Ngưỡng Shannon Entropy tối thiểu dải >= 32 ký tự (NULL nếu charset 'none' hoặc 'dynamic')",
    )
    min_length: Mapped[int] = mapped_column(
        mysql.INTEGER(),
        nullable=False,
        server_default=text("20"),
        default=20,
        comment="Độ dài chuỗi tối thiểu để kích hoạt thuật toán tính toán Entropy (mặc định = 20)",
    )
    context_keywords: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Danh sách từ khóa ngữ cảnh gán biến bắt buộc ở Lớp 3 (key, secret, token, password...)",
    )
    default_severity: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", name="enum_rule_default_severity"),
        nullable=False,
        server_default=text("'medium'"),
        default="medium",
        comment="Mức độ nghiêm trọng mặc định gán cho cảnh báo khi quy tắc được kích hoạt",
    )
    allowlist_patterns: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Danh sách mẫu tệp hoặc từ khóa được loại trừ ở Lớp 3 (.env.example, sample...)",
    )
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("1"),
        default=True,
        comment="Cờ bật/tắt kích hoạt quy tắc trong tiến trình quét tự động",
    )
    created_at: Mapped[datetime] = mapped_column(
        mysql.TIMESTAMP(),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        comment="Thời điểm tạo quy tắc quét trong cơ sở dữ liệu",
    )
    updated_at: Mapped[datetime] = mapped_column(
        mysql.TIMESTAMP(),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
        comment="Thời điểm cập nhật biểu thức regex hoặc ngưỡng entropy gần nhất",
    )

    # Relationships
    security_alerts: Mapped[List[SecurityAlert]] = relationship(
        "SecurityAlert",
        back_populates="scan_rule",
    )

    def __repr__(self) -> str:
        return f"<ScanRule id={self.id} rule_code={self.rule_code!r} severity={self.default_severity}>"
