"""
Unit & Integration Tests for PBI-08 (AC-01..AC-05):
Quản lý Vòng đời Cảnh báo, Actor Tự động & Nhật ký Append-Only (T05DB2B)
"""

import unittest
from datetime import datetime, timezone
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
            detected_at=datetime.now(timezone.utc).replace(tzinfo=None),
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


class TestPBI08TaskS208d(unittest.TestCase):
    """
    S2-08d: Triển khai Atomic Transaction cập nhật bảng security_alerts và chèn alert_status_history (AC-04).
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
            id=10,
            repo_id=1,
            fingerprint="c" * 64,
            source="gitprotect_scanner",
            rule_name="AWS Secret",
            severity="critical",
            file_path="aws.py",
            status="open",
            detected_at=datetime.now(),
        )
        self.db.add(self.test_alert)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_ac04_atomic_commit_updates_both(self):
        """Cập nhật thành công: alert và history đều được lưu vào CSDL (AC-04)."""
        from app.models import SecurityAlert, AlertStatusHistory
        from app.modules.alerts.service import AlertLifecycleService

        req = AlertStatusUpdateRequest(
            new_status=AlertStatusEnum.IN_REVIEW,
            resolution_note="Bắt đầu phân tích mã độc",
        )
        res = AlertLifecycleService.update_alert_status_atomic(db=self.db, alert_id=10, req=req)
        self.assertTrue(res["transaction_committed"])

        # Xác thực trực tiếp từ CSDL
        alert_db = self.db.query(SecurityAlert).filter(SecurityAlert.id == 10).first()
        self.assertEqual(alert_db.status, "in_review")
        self.assertEqual(alert_db.resolution_note, "Bắt đầu phân tích mã độc")

        history_db = self.db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id == 10).all()
        self.assertEqual(len(history_db), 1)
        self.assertEqual(history_db[0].old_status, "open")
        self.assertEqual(history_db[0].new_status, "in_review")

    def test_ac04_rollback_on_validation_failure(self):
        """Khi vi phạm ràng buộc (ví dụ false_positive thiếu note): Rollback toàn bộ, alert giữ nguyên trạng thái cũ (AC-04)."""
        from app.models import SecurityAlert, AlertStatusHistory
        from app.modules.alerts.service import AlertLifecycleService

        bad_req = AlertStatusUpdateRequest.model_construct(
            new_status=AlertStatusEnum.FALSE_POSITIVE,
            resolution_note="ngắn",
        )
        with self.assertRaises(ValueError) as ctx:
            AlertLifecycleService.update_alert_status_atomic(db=self.db, alert_id=10, req=bad_req)
        self.assertIn("AC-01 Violation", str(ctx.exception))

        # Alert giữ nguyên trạng thái 'open'
        alert_db = self.db.query(SecurityAlert).filter(SecurityAlert.id == 10).first()
        self.assertEqual(alert_db.status, "open")

        # Không có bản ghi lịch sử nào được ghi
        hist_count = self.db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id == 10).count()
        self.assertEqual(hist_count, 0)

    def test_ac04_resolved_at_set_and_cleared_properly(self):
        """Khi resolved -> set resolved_at; khi reopen sang in_review -> resolved_at trở về None."""
        from app.models import SecurityAlert
        from app.modules.alerts.service import AlertLifecycleService

        # 1. Chuyển sang resolved -> có resolved_at
        req1 = AlertStatusUpdateRequest(new_status=AlertStatusEnum.RESOLVED, resolution_note="Đã thu hồi token")
        res1 = AlertLifecycleService.update_alert_status_atomic(db=self.db, alert_id=10, req=req1)
        alert_db = self.db.query(SecurityAlert).filter(SecurityAlert.id == 10).first()
        self.assertIsNotNone(alert_db.resolved_at)

        # 2. Mở lại sang in_review -> resolved_at bị xoá về None
        req2 = AlertStatusUpdateRequest(new_status=AlertStatusEnum.IN_REVIEW, resolution_note="Phát hiện token vẫn còn hiệu lực")
        res2 = AlertLifecycleService.update_alert_status_atomic(db=self.db, alert_id=10, req=req2)
        alert_db = self.db.query(SecurityAlert).filter(SecurityAlert.id == 10).first()
        self.assertEqual(alert_db.status, "in_review")
        self.assertIsNone(alert_db.resolved_at)


class TestPBI08TaskS208e(unittest.TestCase):
    """
    S2-08e: Triển khai API GET /api/v1/alerts, GET /api/v1/alerts/{id}, GET /api/v1/alerts/{id}/history (Append-only AC-05).
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

        # Seed sample alerts
        self.a1 = SecurityAlert(
            id=101, repo_id=1, fingerprint="1" * 64, source="gitprotect_scanner",
            rule_name="GitHub PAT", severity="critical", file_path="a.py", status="open",
            detected_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        self.a2 = SecurityAlert(
            id=102, repo_id=1, fingerprint="2" * 64, source="gitprotect_scanner",
            rule_name="Slack Token", severity="high", file_path="b.py", status="in_review",
            detected_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        self.a3 = SecurityAlert(
            id=103, repo_id=2, fingerprint="3" * 64, source="github_native",
            rule_name="Dependabot", severity="medium", file_path="package.json", status="resolved",
            detected_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        self.db.add_all([self.a1, self.a2, self.a3])
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_get_alerts_list_filtering_and_pagination(self):
        """GET /api/v1/alerts hỗ trợ lọc theo repo_id, severity, status, source và phân trang."""
        import asyncio
        from app.modules.alerts.router import list_alerts

        # Lọc theo repo_id = 1
        res = asyncio.run(list_alerts(repo_id=1, db=self.db))
        self.assertEqual(res["total"], 2)
        self.assertEqual(len(res["items"]), 2)

        # Lọc theo severity = critical
        res_sev = asyncio.run(list_alerts(severity=SeverityEnum.CRITICAL, db=self.db))
        self.assertEqual(res_sev["total"], 1)
        self.assertEqual(res_sev["items"][0].id, 101)

        # Phân trang page_size = 2
        res_page = asyncio.run(list_alerts(page=1, page_size=2, db=self.db))
        self.assertEqual(res_page["total"], 3)
        self.assertEqual(len(res_page["items"]), 2)

    def test_get_alert_by_id(self):
        """GET /api/v1/alerts/{id} trả về chi tiết hoặc 404 khi không tồn tại."""
        import asyncio
        from fastapi import HTTPException
        from app.modules.alerts.router import get_alert

        res = asyncio.run(get_alert(id=101, db=self.db))
        self.assertEqual(res.id, 101)
        self.assertEqual(res.rule_name, "GitHub PAT")

        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(get_alert(id=999, db=self.db))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_get_alert_history_chronological(self):
        """GET /api/v1/alerts/{id}/history trả về danh sách lịch sử tuần tự theo thời gian."""
        import asyncio
        from fastapi import HTTPException
        from app.modules.alerts.router import get_history, update_status

        # Tạo 2 bước chuyển trạng thái
        req1 = AlertStatusUpdateRequest(new_status=AlertStatusEnum.IN_REVIEW, resolution_note="Bắt đầu duyệt")
        asyncio.run(update_status(id=101, req=req1, db=self.db))

        req2 = AlertStatusUpdateRequest(new_status=AlertStatusEnum.RESOLVED, resolution_note="Đã đổi token mới")
        asyncio.run(update_status(id=101, req=req2, db=self.db))

        hist = asyncio.run(get_history(id=101, db=self.db))
        self.assertEqual(hist["total"], 2)
        self.assertEqual(hist["items"][0].new_status, "in_review")
        self.assertEqual(hist["items"][1].new_status, "resolved")

        # Alert không tồn tại -> 404
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(get_history(id=999, db=self.db))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_ac05_append_only_orm_blocks_update_and_delete(self):
        """AC-05: CSDL Append-Only, chặn tuyệt đối thao tác UPDATE hoặc DELETE bản ghi lịch sử."""
        from app.models import AlertStatusHistory

        # Thêm 1 bản ghi lịch sử
        entry = AlertStatusHistory(
            alert_id=101,
            old_status="open",
            new_status="in_review",
            actor_type="internal_operator",
            actor_label="internal_operator",
            resolution_note="Khởi tạo",
        )
        self.db.add(entry)
        self.db.commit()

        # Kiểm tra chặn UPDATE
        entry.resolution_note = "Thay đổi nội dung lịch sử trái phép"
        with self.assertRaises(ValueError) as ctx:
            self.db.commit()
        self.assertIn("AC-05 Violation", str(ctx.exception))
        self.db.rollback()

        # Kiểm tra chặn DELETE
        with self.assertRaises(ValueError) as ctx:
            self.db.delete(entry)
            self.db.commit()
        self.assertIn("AC-05 Violation", str(ctx.exception))
        self.db.rollback()

    def test_ac05_no_history_modification_endpoints(self):
        """AC-05: Hệ thống không cung cấp bất kỳ API nào để sửa (PUT/PATCH) hoặc xóa (DELETE) lịch sử."""
        from app.modules.alerts.router import router

        history_routes = [r for r in router.routes if "/history" in r.path]
        methods = {m for r in history_routes for m in r.methods}

        # Chỉ cho phép phương thức GET trên endpoint history
        self.assertEqual(methods, {"GET"})
        self.assertNotIn("PUT", methods)
        self.assertNotIn("PATCH", methods)
        self.assertNotIn("DELETE", methods)
        self.assertNotIn("POST", methods)


if __name__ == "__main__":
    unittest.main()
