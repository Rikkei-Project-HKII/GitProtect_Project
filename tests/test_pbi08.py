"""
Unit & Integration Tests for PBI-08 (AC-01..AC-05):
Quản lý Vòng đời Cảnh báo, Actor Tự động & Nhật ký Append-Only (T05DB2B)
"""

import unittest
from datetime import datetime
from pydantic import ValidationError

from app.core.enums import AlertStatusEnum, SeverityEnum, AlertSourceEnum, ActorTypeEnum
from app.modules.alerts.schemas import (
    AlertStatusUpdateRequest,
    SecurityAlertDetailResponse,
    AlertStatusHistoryItem,
    AlertStatusUpdateResponse,
    AlertHistoryListResponse,
    AlertPaginatedListResponse,
)


class TestPBI08TaskS208a(unittest.TestCase):
    """
    S2-08a: Xây dựng Pydantic Schema cho PATCH /api/v1/alerts/{id}/status
    với model_config = ConfigDict(extra='forbid') (AC-03).
    """

    def test_ac03_reject_actor_field(self):
        """Client truyền 'actor' -> từ chối extra_forbidden (AC-03)."""
        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.IN_REVIEW,
                actor="internal_operator",
            )
        self.assertIn("extra_forbidden", str(ctx.exception))

    def test_ac03_reject_changed_by_field(self):
        """Client truyền 'changed_by' -> từ chối extra_forbidden (AC-03)."""
        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.RESOLVED,
                changed_by="admin",
            )
        self.assertIn("extra_forbidden", str(ctx.exception))

    def test_ac03_reject_actor_type_and_label_fields(self):
        """Client truyền 'actor_type' hoặc 'actor_label' -> từ chối (AC-03)."""
        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.IN_REVIEW,
                actor_type="system",
            )
        self.assertIn("extra_forbidden", str(ctx.exception))

        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.IN_REVIEW,
                actor_label="root",
            )
        self.assertIn("extra_forbidden", str(ctx.exception))

    def test_ac03_reject_operator_name(self):
        """Client truyền 'operator_name' -> từ chối (AC-03)."""
        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.IN_REVIEW,
                operator_name="Nguyen Van A",
            )
        self.assertIn("extra_forbidden", str(ctx.exception))

    def test_valid_request_allowed_fields_only(self):
        """Request chỉ chứa new_status và resolution_note hợp lệ -> Thành công."""
        req = AlertStatusUpdateRequest(
            new_status=AlertStatusEnum.IN_REVIEW,
            resolution_note="Đang tiến hành rà soát",
        )
        self.assertEqual(req.new_status, AlertStatusEnum.IN_REVIEW)
        self.assertEqual(req.resolution_note, "Đang tiến hành rà soát")


if __name__ == "__main__":
    unittest.main()
