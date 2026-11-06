"""
GitProtect MVP (v1.1 Baseline - GP-2026-SCRUM)
Model 1: Repository - Quản lý kho lưu trữ kết nối qua GitHub PAT & trạng thái quét
"""

from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional
from datetime import datetime

from sqlalchemy import (
    String,
    Text,
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


class Repository(Base):
    __tablename__ = "repositories"

    __table_args__ = (
        UniqueConstraint("github_repo_id", name="uk_github_repo"),
        CheckConstraint(
            "repo_url LIKE 'https://github.com/%'",
            name="chk_repo_url_github_prefix",
        ),
        CheckConstraint(
            "connection_status IN ('active', 'error')",
            name="chk_repo_connection_status",
        ),
        CheckConstraint(
            "scan_status IN ('pending', 'running', 'completed', 'failed')",
            name="chk_repo_scan_status",
        ),
        Index("idx_repo_name", "repo_name"),
        Index("idx_conn_status", "connection_status"),
        Index("idx_scan_status", "scan_status"),
        Index("idx_last_scanned", "last_scanned_at"),
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
        comment="Khóa chính định danh kho lưu trữ trong hệ thống nội bộ",
    )
    github_repo_id: Mapped[int] = mapped_column(
        mysql.BIGINT(),
        nullable=False,
        comment="ID kho lưu trữ gốc từ GitHub API, tránh kết nối trùng lặp",
    )
    repo_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Tên kho lưu trữ đầy đủ (ví dụ: 'organization/backend-api')",
    )
    repo_url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="Đường dẫn URL GitHub chính thức của kho lưu trữ",
    )
    default_branch: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        server_default=text("'main'"),
        default="main",
        comment="Nhánh mặc định lấy từ GitHub API ('main' làm giá trị dự phòng)",
    )
    access_token_encrypted: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Personal Access Token (PAT) đã mã hóa AES-256-GCM kèm IV riêng at-rest",
    )
    webhook_secret_encrypted: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Secret key xác thực chữ ký HMAC-SHA256 của Webhook đã mã hóa AES-256-GCM at-rest",
    )
    connection_status: Mapped[str] = mapped_column(
        Enum("active", "error", name="enum_repo_connection_status"),
        nullable=False,
        server_default=text("'active'"),
        default="active",
        comment="Trạng thái kết nối: 'active' (bình thường), 'error' (lỗi kết nối/token)",
    )
    scan_status: Mapped[str] = mapped_column(
        Enum("pending", "running", "completed", "failed", name="enum_repo_scan_status"),
        nullable=False,
        server_default=text("'pending'"),
        default="pending",
        comment="Trạng thái tiến trình quét (FR-10): pending, running, completed, failed",
    )
    last_error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Ghi nhận chi tiết mã và nguyên nhân lỗi (401 Bad Token, 404 Repo Not Found, 403 Rate Limit)",
    )
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(
        mysql.TIMESTAMP(),
        nullable=True,
        comment="Thời điểm hoàn thành lần quét mã gần đây nhất",
    )
    created_at: Mapped[datetime] = mapped_column(
        mysql.TIMESTAMP(),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        comment="Thời điểm kho lưu trữ được kết nối vào hệ thống GitProtect",
    )
    updated_at: Mapped[datetime] = mapped_column(
        mysql.TIMESTAMP(),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
        comment="Thời điểm cập nhật trạng thái kho lưu trữ gần nhất",
    )

    # Relationships
    security_alerts: Mapped[List[SecurityAlert]] = relationship(
        "SecurityAlert",
        back_populates="repository",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<Repository id={self.id} repo_name={self.repo_name!r} status={self.connection_status}>"
