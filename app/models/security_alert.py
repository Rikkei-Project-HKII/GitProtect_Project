"""
GitProtect MVP (v1.1 Baseline - GP-2026-SCRUM)
Model 3: SecurityAlert - Lưu trữ cảnh báo rò rỉ bí mật (secret_masked) & Dependabot
"""

from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional
from datetime import datetime

from sqlalchemy import (
    Integer,
    String,
    CHAR,
    Text,
    Boolean,
    Enum,
    ForeignKey,
    UniqueConstraint,
    CheckConstraint,
    Index,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects import mysql

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.repository import Repository
    from app.models.scan_rule import ScanRule
    from app.models.alert_status_history import AlertStatusHistory


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    __table_args__ = (
        UniqueConstraint("repo_id", "fingerprint", name="uk_repo_fp"),
        CheckConstraint(
            "source IN ('gitprotect_scanner', 'github_native')",
            name="chk_sa_source",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')",
            name="chk_sa_severity",
        ),
        CheckConstraint(
            "status IN ('open', 'in_review', 'resolved', 'false_positive', 'ignored')",
            name="chk_sa_status",
        ),
        CheckConstraint(
            "status <> 'false_positive' OR (resolution_note IS NOT NULL AND CHAR_LENGTH(TRIM(resolution_note)) >= 10)",
            name="chk_sa_false_positive_note_len",
        ),
        Index("idx_alert_number", "alert_number"),
        Index("idx_cve_id", "cve_id"),
        Index("idx_commit_sha", "commit_sha"),
        Index("idx_author_email", "author_email"),
        Index("idx_spoofing", "email_spoofing_flag"),
        Index("idx_repo_sev_stat", "repo_id", "severity", "status"),
        Index("idx_detected_at", "detected_at"),
        Index("idx_file_path", "file_path", mysql_length={"file_path": 255}),
        {
            "mysql_engine": "InnoDB",
            "mysql_charset": "utf8mb4",
            "mysql_collate": "utf8mb4_unicode_ci",
        },
    )

    id: Mapped[int] = mapped_column(
        mysql.BIGINT().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
        nullable=False,
        comment="Khóa chính định danh duy nhất cho từng bản ghi cảnh báo bảo mật",
    )
    repo_id: Mapped[int] = mapped_column(
        mysql.BIGINT(),
        ForeignKey("repositories.id", ondelete="CASCADE", name="fk_sa_repo"),
        nullable=False,
        comment="Khóa ngoại liên kết tới kho lưu trữ xảy ra sự cố rò rỉ bí mật",
    )
    rule_id: Mapped[Optional[int]] = mapped_column(
        mysql.BIGINT(),
        ForeignKey("scan_rules.id", ondelete="SET NULL", name="fk_sa_rule"),
        nullable=True,
        comment="Khóa ngoại liên kết quy tắc quét kích hoạt cảnh báo (NULL nếu từ GitHub Native)",
    )
    fingerprint: Mapped[str] = mapped_column(
        CHAR(64),
        nullable=False,
        comment=(
            "Khóa chống trùng lặp HMAC-SHA256: scanner dùng HMAC(key, repo_id|file_path|secret); "
            "native dùng HMAC(key, repo_id|'native'|alert_number)"
        ),
    )
    alert_number: Mapped[Optional[int]] = mapped_column(
        mysql.BIGINT(),
        nullable=True,
        comment="Mã số cảnh báo gốc từ GitHub Secret Scanning / Dependabot khi đồng bộ",
    )
    source: Mapped[str] = mapped_column(
        Enum("gitprotect_scanner", "github_native", name="enum_alert_source"),
        nullable=False,
        server_default=text("'gitprotect_scanner'"),
        default="gitprotect_scanner",
        comment="Nguồn phát hiện cảnh báo: 'gitprotect_scanner' hoặc 'github_native'",
    )
    package_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Tên gói thư viện phụ thuộc bị phát hiện lỗ hổng (từ Dependabot Alerts)",
    )
    cve_id: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="Mã định danh lỗ hổng bảo mật quốc tế CVE / GHSA (từ Dependabot Alerts)",
    )
    fixed_version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Phiên bản an toàn đã khắc phục lỗ hổng được khuyến nghị nâng cấp",
    )
    rule_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        comment="Tên định danh quy tắc phát hiện (ví dụ: 'GitHub PAT', 'Private Key')",
    )
    severity: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", name="enum_alert_severity"),
        nullable=False,
        server_default=text("'medium'"),
        default="medium",
        comment="4 mức độ nghiêm trọng rủi ro theo chuẩn bảo mật quốc tế",
    )
    file_path: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
        comment="Đường dẫn tương đối của tập tin chứa bí mật trong repository",
    )
    line_number: Mapped[Optional[int]] = mapped_column(
        mysql.INTEGER(),
        nullable=True,
        comment="Số dòng phát hiện chuỗi ký tự bí mật trong tập tin mã nguồn",
    )
    commit_sha: Mapped[Optional[str]] = mapped_column(
        String(40),
        nullable=True,
        comment="Mã băm SHA-1 của commit chứa rò rỉ (NULL đối với cảnh báo từ Dependabot)",
    )
    author_name: Mapped[Optional[str]] = mapped_column(
        String(150),
        nullable=True,
        comment="Tên tác giả thực hiện commit chứa bí mật rò rỉ",
    )
    author_email: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Địa chỉ email của commit author dùng phục vụ kiểm toán tác giả",
    )
    signature_verified: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        comment="Cờ xác thực chữ ký điện tử GPG/SSH của commit từ GitHub API",
    )
    email_spoofing_flag: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("0"),
        default=False,
        comment="Cảnh báo giả mạo email nếu commit author không thuộc tổ chức xác thực",
    )
    secret_masked: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Chuỗi bí mật đã che: tiền_tố + '****' + 4_ký_tự_cuối (NULL nếu alert Dependabot)",
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "open",
            "in_review",
            "resolved",
            "false_positive",
            "ignored",
            name="enum_alert_status",
        ),
        nullable=False,
        server_default=text("'open'"),
        default="open",
        comment="Vòng đời xử lý: 'open', 'in_review', 'resolved', 'false_positive', 'ignored'",
    )
    resolution_note: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Ghi chú bắt buộc tối thiểu 10 ký tự khi chuyển trạng thái 'false_positive'",
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        mysql.TIMESTAMP(),
        nullable=True,
        comment="Thời điểm Internal Operator hoặc Hệ thống cập nhật giải quyết cảnh báo",
    )
    detected_at: Mapped[datetime] = mapped_column(
        mysql.TIMESTAMP(),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        comment="Thời điểm hệ thống phát hiện sự cố rò rỉ qua Webhook hoặc Quét mã",
    )

    # Relationships
    repository: Mapped[Repository] = relationship(
        "Repository",
        back_populates="security_alerts",
    )
    scan_rule: Mapped[Optional[ScanRule]] = relationship(
        "ScanRule",
        back_populates="security_alerts",
    )
    status_history: Mapped[List[AlertStatusHistory]] = relationship(
        "AlertStatusHistory",
        back_populates="alert",
        cascade="all",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<SecurityAlert id={self.id} rule_name={self.rule_name!r} severity={self.severity} status={self.status}>"
