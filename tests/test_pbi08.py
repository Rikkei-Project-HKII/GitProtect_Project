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


class TestPBI08TaskS208b(unittest.TestCase):
    """
    S2-08b: Ràng buộc độ dài resolution_note >= 10 ký tự khi chuyển trạng thái false_positive (AC-01).
    """

    def test_ac01_false_positive_none_note_fails(self):
        """false_positive với resolution_note=None -> Bị từ chối."""
        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.FALSE_POSITIVE,
                resolution_note=None,
            )
        self.assertIn("AC-01 Violation", str(ctx.exception))

    def test_ac01_false_positive_empty_note_fails(self):
        """false_positive với note rỗng -> Bị từ chối."""
        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.FALSE_POSITIVE,
                resolution_note="",
            )
        self.assertIn("AC-01 Violation", str(ctx.exception))

    def test_ac01_false_positive_whitespace_only_fails(self):
        """false_positive với note toàn khoảng trắng -> Bị từ chối."""
        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.FALSE_POSITIVE,
                resolution_note="         ",
            )
        self.assertIn("AC-01 Violation", str(ctx.exception))

    def test_ac01_false_positive_less_than_10_chars_fails(self):
        """false_positive với note 9 ký tự -> Bị từ chối."""
        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.FALSE_POSITIVE,
                resolution_note="123456789",
            )
        self.assertIn("AC-01 Violation", str(ctx.exception))

    def test_ac01_false_positive_exactly_10_chars_succeeds(self):
        """false_positive với đúng 10 ký tự -> Chấp thuận."""
        req = AlertStatusUpdateRequest(
            new_status=AlertStatusEnum.FALSE_POSITIVE,
            resolution_note="1234567890",
        )
        self.assertEqual(req.new_status, AlertStatusEnum.FALSE_POSITIVE)
        self.assertEqual(req.resolution_note, "1234567890")

    def test_ac01_false_positive_valid_note_trims(self):
        """false_positive với chuỗi hợp lệ kèm khoảng trắng đầu/cuối -> Tự động strip."""
        req = AlertStatusUpdateRequest(
            new_status=AlertStatusEnum.FALSE_POSITIVE,
            resolution_note="   Khóa kiểm thử môi trường test local   ",
        )
        self.assertEqual(req.new_status, AlertStatusEnum.FALSE_POSITIVE)
        self.assertEqual(req.resolution_note, "Khóa kiểm thử môi trường test local")

    def test_ac01_other_statuses_do_not_require_10_chars(self):
        """Các trạng thái khác (in_review, resolved, ignored, open) không bắt buộc note >= 10 ký tự."""
        req1 = AlertStatusUpdateRequest(new_status=AlertStatusEnum.IN_REVIEW)
        self.assertIsNone(req1.resolution_note)

        req2 = AlertStatusUpdateRequest(new_status=AlertStatusEnum.RESOLVED, resolution_note="Fix xong")
        self.assertEqual(req2.resolution_note, "Fix xong")

        req3 = AlertStatusUpdateRequest(new_status=AlertStatusEnum.IGNORED, resolution_note="ignore")
        self.assertEqual(req3.resolution_note, "ignore")


class TestPBI08TaskS208c(unittest.TestCase):
    """
    S2-08c: Cài đặt logic Backend tự gán actor_type và actor_label snapshot ('system' / 'internal_operator') (AC-01, AC-02).
    """

    def setUp(self):
        from sqlalchemy import create_engine, event
        from sqlalchemy.orm import sessionmaker
        from app.models import SecurityAlert, AlertStatusHistory

        self.engine = create_engine("sqlite:///:memory:")
        @event.listens_for(self.engine, "connect")
        def connect(dbapi_connection, connection_record):
            dbapi_connection.create_function("CHAR_LENGTH", 1, lambda s: len(s) if s else 0)

        SecurityAlert.__table__.create(self.engine)
        AlertStatusHistory.__table__.create(self.engine)

        SessionTest = sessionmaker(bind=self.engine)
        self.db = SessionTest()

        self.test_alert = SecurityAlert(
            id=1,
            repo_id=1,
            fingerprint="b" * 64,
            source="gitprotect_scanner",
            rule_name="GitHub PAT",
            severity="critical",
            file_path="config.py",
            status="open",
            detected_at=datetime.utcnow(),
        )
        self.db.add(self.test_alert)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_ac01_backend_assigns_internal_operator(self):
        """API cập nhật -> Backend tự động gán actor_type='internal_operator', actor_label='internal_operator' (AC-01)."""
        from app.modules.alerts.service import AlertLifecycleService

        req = AlertStatusUpdateRequest(
            new_status=AlertStatusEnum.IN_REVIEW,
            resolution_note="Đang thẩm tra an ninh nội bộ",
        )
        result = AlertLifecycleService.update_alert_status_atomic(
            db=self.db,
            alert_id=1,
            req=req,
        )

        self.assertEqual(result["history_entry"].actor_type, "internal_operator")
        self.assertEqual(result["history_entry"].actor_label, "internal_operator")
        self.assertEqual(result["history_entry"].new_status, "in_review")

    def test_ac02_backend_assigns_system_for_workers(self):
        """Worker/Job thực thi cập nhật -> Backend gán actor_type='system', actor_label='system' (AC-02)."""
        from app.modules.alerts.service import AlertLifecycleService

        result = AlertLifecycleService.record_system_status_change(
            db=self.db,
            alert_id=1,
            new_status=AlertStatusEnum.RESOLVED,
            resolution_note="Worker tự động giải quyết",
        )

        self.assertEqual(result["history_entry"].actor_type, "system")
        self.assertEqual(result["history_entry"].actor_label, "system")
        self.assertEqual(result["history_entry"].new_status, "resolved")


if __name__ == "__main__":
    unittest.main()
