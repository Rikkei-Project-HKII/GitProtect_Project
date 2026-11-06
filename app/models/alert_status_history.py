"""
GitProtect MVP (v1.1 Baseline - GP-2026-SCRUM)
Model 4: AlertStatusHistory - Nhật ký kiểm toán trạng thái bất biến Append-Only (AC-01..AC-05)
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Optional
from datetime import datetime

from sqlalchemy import (
    String,
    Text,
    Enum,
    ForeignKey,
    CheckConstraint,
    Index,
    event,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects import mysql

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.security_alert import SecurityAlert


class AlertStatusHistory(Base):
    __tablename__ = "alert_status_history"

    __table_args__ = (
        CheckConstraint(
            "old_status IS NULL OR old_status IN ('open','in_review','resolved','false_positive','ignored')",
            name="chk_ash_old_status",
        ),
        CheckConstraint(
            "new_status IN ('open','in_review','resolved','false_positive','ignored')",
            name="chk_ash_new_status",
        ),
        CheckConstraint(
            "actor_type IN ('system', 'internal_operator')",
            name="chk_ash_actor_type",
        ),
        CheckConstraint(
            "new_status <> 'false_positive' OR (resolution_note IS NOT NULL AND CHAR_LENGTH(TRIM(resolution_note)) >= 10)",
            name="chk_ash_false_positive_note_len",
        ),
        Index("idx_ash_alert_id", "alert_id"),
        Index("idx_ash_actor_type", "actor_type"),
        Index("idx_ash_created_at", "created_at"),
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
        comment="Khóa chính định danh bản ghi nhật ký kiểm toán trạng thái cảnh báo",
    )
    alert_id: Mapped[int] = mapped_column(
        mysql.BIGINT(),
        ForeignKey("security_alerts.id", ondelete="RESTRICT", name="fk_ash_alert"),
        nullable=False,
        comment="Khóa ngoại tham chiếu cảnh báo; ON DELETE RESTRICT bảo vệ toàn vẹn lịch sử",
    )
    old_status: Mapped[Optional[str]] = mapped_column(
        Enum(
            "open",
            "in_review",
            "resolved",
            "false_positive",
            "ignored",
            name="enum_ash_old_status",
        ),
        nullable=True,
        comment="Trạng thái trước khi chuyển đổi (NULL đối với bản ghi khởi tạo ban đầu)",
    )
    new_status: Mapped[str] = mapped_column(
        Enum(
            "open",
            "in_review",
            "resolved",
            "false_positive",
            "ignored",
            name="enum_ash_new_status",
        ),
        nullable=False,
        comment="Trạng thái mới được áp dụng cho cảnh báo bảo mật",
    )
    actor_type: Mapped[str] = mapped_column(
        Enum("system", "internal_operator", name="enum_ash_actor_type"),
        nullable=False,
        comment=(
            "Nguồn thực hiện hành động: 'system' (Worker/Webhook/Dependabot) hoặc "
            "'internal_operator' (UI/API nội bộ). Backend tự xác định, không nhận từ client"
        ),
    )
    actor_label: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Nhãn tác nhân hiển thị lưu dạng snapshot tại thời điểm phát sinh sự kiện",
    )
    resolution_note: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Lý do giải trình khi chuyển trạng thái (bắt buộc >= 10 ký tự khi 'false_positive')",
    )
    created_at: Mapped[datetime] = mapped_column(
        mysql.TIMESTAMP(),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        comment="Thời điểm tạo bản ghi lịch sử (Bảng Append-only cấm UPDATE/DELETE)",
    )

    # Relationships
    alert: Mapped[SecurityAlert] = relationship(
        "SecurityAlert",
        back_populates="status_history",
    )

    def __repr__(self) -> str:
        return f"<AlertStatusHistory id={self.id} alert_id={self.alert_id} new_status={self.new_status}>"


# Ràng buộc Append-Only ở tầng ORM (AC-05 defense-in-depth)
@event.listens_for(AlertStatusHistory, "before_update")
def receive_before_update(mapper, connection, target):
    raise ValueError(
        "AC-05 Violation: alert_status_history is an Append-Only audit table. UPDATE is strictly prohibited."
    )


@event.listens_for(AlertStatusHistory, "before_delete")
def receive_before_delete(mapper, connection, target):
    raise ValueError(
        "AC-05 Violation: alert_status_history is an Append-Only audit table. DELETE is strictly prohibited."
    )
