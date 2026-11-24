"""
Integration & Automated Test Suite for PBI-11 (T05DB2F):
Kiểm thử Tự động Bộ tiêu chí AC-01 đến AC-05 & Pentest Hệ thống (Sprint 3)
Phụ trách: TV1 & Cả nhóm
"""

import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.schema import CreateTable

from app.main import app
from app.db.session import get_db
from app.models import Base, Repository, SecurityAlert, AlertStatusHistory
from app.core.enums import AlertStatusEnum
from app.modules.alerts.service import AlertLifecycleService


def create_test_db():
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False}
    )

    with engine.begin() as conn:
        conn.connection.driver_connection.create_function(
            "CHAR_LENGTH", 1, lambda s: len(s) if s else 0
        )
        for table in Base.metadata.sorted_tables:
            ddl = str(CreateTable(table).compile(engine)).replace(" ON UPDATE CURRENT_TIMESTAMP", "")
            conn.exec_driver_sql(ddl)

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, SessionLocal


class TestPBI11TaskS302a(unittest.TestCase):
    """
    S3-02a: Viết Pytest kiểm thử AC-01 (note >= 10 ký tự, actor internal_operator)
    và AC-02 (Worker gán system).
    """

    def setUp(self):
        self.engine, self.SessionLocal = create_test_db()

        # Seed initial test repository & alert
        with self.SessionLocal() as db:
            repo = Repository(
                id=1,
                github_repo_id=12345,
                repo_name="org/test-repo",
                default_branch="main",
                access_token_encrypted="dummy_pat",
                repo_url="https://github.com/org/test-repo",
            )
            db.add(repo)
            self.test_alert = SecurityAlert(
                id=1,
                repo_id=1,
                fingerprint="a" * 64,
                source="gitprotect_scanner",
                rule_name="GitHub PAT",
                severity="critical",
                file_path="src/config.py",
                status="open",
                detected_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
            db.add(self.test_alert)
            db.commit()

        # Override FastAPI get_db dependency
        def override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.engine.dispose()

    # --- AC-01 Tests ---

    def test_ac01_http_patch_false_positive_rejected_when_note_none(self):
        """AC-01: PATCH sang false_positive không có resolution_note -> 422 Unprocessable Entity."""
        res = self.client.patch(
            "/api/v1/alerts/1/status",
            json={"new_status": "false_positive"}
        )
        self.assertEqual(res.status_code, 422)
        self.assertIn("AC-01 Violation", res.text)

    def test_ac01_http_patch_false_positive_rejected_when_note_empty(self):
        """AC-01: PATCH sang false_positive với resolution_note='' -> 422."""
        res = self.client.patch(
            "/api/v1/alerts/1/status",
            json={"new_status": "false_positive", "resolution_note": ""}
        )
        self.assertEqual(res.status_code, 422)
        self.assertIn("AC-01 Violation", res.text)

    def test_ac01_http_patch_false_positive_rejected_when_note_whitespace_only(self):
        """AC-01: PATCH sang false_positive với resolution_note toàn khoảng trắng -> 422."""
        res = self.client.patch(
            "/api/v1/alerts/1/status",
            json={"new_status": "false_positive", "resolution_note": "        "}
        )
        self.assertEqual(res.status_code, 422)
        self.assertIn("AC-01 Violation", res.text)

    def test_ac01_http_patch_false_positive_rejected_when_note_under_10_chars(self):
        """AC-01: PATCH sang false_positive với resolution_note 9 ký tự -> 422."""
        res = self.client.patch(
            "/api/v1/alerts/1/status",
            json={"new_status": "false_positive", "resolution_note": "123456789"}
        )
        self.assertEqual(res.status_code, 422)
        self.assertIn("AC-01 Violation", res.text)

    def test_ac01_http_patch_false_positive_accepted_when_note_at_least_10_chars(self):
        """AC-01: PATCH sang false_positive với resolution_note >= 10 ký tự -> 200, actor='internal_operator'."""
        res = self.client.patch(
            "/api/v1/alerts/1/status",
            json={
                "new_status": "false_positive",
                "resolution_note": "Khóa test dummy môi trường staging"
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["alert"]["id"], 1)
        self.assertEqual(data["alert"]["status"], "false_positive")
        self.assertEqual(data["history_entry"]["actor_type"], "internal_operator")
        self.assertEqual(data["history_entry"]["actor_label"], "internal_operator")
        self.assertTrue(data["transaction_committed"])

        # Xác thực trong CSDL
        with self.SessionLocal() as db:
            alert = db.query(SecurityAlert).filter(SecurityAlert.id == 1).first()
            self.assertEqual(alert.status, "false_positive")
            self.assertEqual(alert.resolution_note, "Khóa test dummy môi trường staging")

            history = db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id == 1).all()
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0].actor_type, "internal_operator")
            self.assertEqual(history[0].actor_label, "internal_operator")
            self.assertEqual(history[0].new_status, "false_positive")

    def test_ac01_http_patch_other_statuses_do_not_require_10_chars(self):
        """AC-01: Các trạng thái in_review, resolved, ignored không bắt buộc note >= 10 ký tự."""
        # in_review không cần note
        res1 = self.client.patch("/api/v1/alerts/1/status", json={"new_status": "in_review"})
        self.assertEqual(res1.status_code, 200)

        # resolved với note ngắn (< 10 ký tự) vẫn hợp lệ
        res2 = self.client.patch("/api/v1/alerts/1/status", json={"new_status": "resolved", "resolution_note": "Đã đổi"})
        self.assertEqual(res2.status_code, 200)

        # ignored với note ngắn vẫn hợp lệ
        res3 = self.client.patch("/api/v1/alerts/1/status", json={"new_status": "ignored", "resolution_note": "Bỏ qua"})
        self.assertEqual(res3.status_code, 200)

    # --- AC-02 Tests ---

    def test_ac02_worker_system_actor_assignment(self):
        """AC-02: Worker/Background job cập nhật alert -> Backend tự động gán actor_type='system', actor_label='system'."""
        with self.SessionLocal() as db:
            result = AlertLifecycleService.record_system_status_change(
                db=db,
                alert_id=1,
                new_status=AlertStatusEnum.RESOLVED,
                resolution_note="Worker tự động giải quyết sau khi quét commit mới",
            )
            self.assertTrue(result["transaction_committed"])
            self.assertEqual(result["history_entry"].actor_type, "system")
            self.assertEqual(result["history_entry"].actor_label, "system")
            self.assertEqual(result["history_entry"].new_status, "resolved")

            # Kiểm tra CSDL
            history = db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id == 1).first()
            self.assertIsNotNone(history)
            self.assertEqual(history.actor_type, "system")
            self.assertEqual(history.actor_label, "system")

    def test_ac02_worker_reopen_alert_as_system(self):
        """AC-02: Worker quét lại phát hiện secret vẫn tồn tại -> Tự động chuyển alert sang in_review với actor='system'."""
        with self.SessionLocal() as db:
            # Đầu tiên resolve alert
            AlertLifecycleService.record_system_status_change(
                db=db,
                alert_id=1,
                new_status=AlertStatusEnum.RESOLVED,
                resolution_note="Resolved by system",
            )
            # Hệ thống quét lại và reopen
            reopen_res = AlertLifecycleService.record_system_status_change(
                db=db,
                alert_id=1,
                new_status=AlertStatusEnum.IN_REVIEW,
                resolution_note="Phát hiện lại secret qua webhook push",
            )
            self.assertEqual(reopen_res["history_entry"].actor_type, "system")
            self.assertEqual(reopen_res["history_entry"].actor_label, "system")
            self.assertEqual(reopen_res["history_entry"].old_status, "resolved")
            self.assertEqual(reopen_res["history_entry"].new_status, "in_review")

            # Tổng cộng có 2 bản ghi lịch sử đều mang actor 'system'
            histories = db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id == 1).order_by(AlertStatusHistory.created_at.asc()).all()
            self.assertEqual(len(histories), 2)
            for h in histories:
                self.assertEqual(h.actor_type, "system")
                self.assertEqual(h.actor_label, "system")



class TestPBI11TaskS302b(unittest.TestCase):
    """
    S3-02b: Viết Pytest kiểm thử AC-03 (Pydantic extra='forbid' từ chối request client chứa actor/changed_by).
    """

    def setUp(self):
        self.engine, self.SessionLocal = create_test_db()

        with self.SessionLocal() as db:
            repo = Repository(
                id=1,
                github_repo_id=12345,
                repo_name="org/test-repo",
                default_branch="main",
                access_token_encrypted="dummy_pat",
                repo_url="https://github.com/org/test-repo",
            )
            db.add(repo)
            self.test_alert = SecurityAlert(
                id=2,
                repo_id=1,
                fingerprint="b" * 64,
                source="gitprotect_scanner",
                rule_name="AWS Secret Key",
                severity="critical",
                file_path="src/aws.py",
                status="open",
                detected_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
            db.add(self.test_alert)
            db.commit()

        def override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.engine.dispose()

    # --- Pydantic Schema direct validation tests ---

    def test_ac03_schema_rejects_actor(self):
        """Schema từ chối trường 'actor' với extra_forbidden."""
        from pydantic import ValidationError
        from app.modules.alerts.schemas import AlertStatusUpdateRequest

        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(new_status=AlertStatusEnum.IN_REVIEW, actor="attacker")
        self.assertIn("extra_forbidden", str(ctx.exception))

    def test_ac03_schema_rejects_changed_by(self):
        """Schema từ chối trường 'changed_by' với extra_forbidden."""
        from pydantic import ValidationError
        from app.modules.alerts.schemas import AlertStatusUpdateRequest

        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(new_status=AlertStatusEnum.IN_REVIEW, changed_by="superadmin")
        self.assertIn("extra_forbidden", str(ctx.exception))

    def test_ac03_schema_rejects_actor_type_and_label(self):
        """Schema từ chối trường 'actor_type' và 'actor_label'."""
        from pydantic import ValidationError
        from app.modules.alerts.schemas import AlertStatusUpdateRequest

        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(new_status=AlertStatusEnum.IN_REVIEW, actor_type="system")
        self.assertIn("extra_forbidden", str(ctx.exception))

        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(new_status=AlertStatusEnum.IN_REVIEW, actor_label="internal_operator")
        self.assertIn("extra_forbidden", str(ctx.exception))

    def test_ac03_schema_rejects_operator_name_and_arbitrary_fields(self):
        """Schema từ chối trường 'operator_name' và các trường tuỳ ý."""
        from pydantic import ValidationError
        from app.modules.alerts.schemas import AlertStatusUpdateRequest

        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(new_status=AlertStatusEnum.IN_REVIEW, operator_name="Admin User")
        self.assertIn("extra_forbidden", str(ctx.exception))

        with self.assertRaises(ValidationError) as ctx:
            AlertStatusUpdateRequest(new_status=AlertStatusEnum.IN_REVIEW, is_admin=True)
        self.assertIn("extra_forbidden", str(ctx.exception))

    # --- HTTP API Integration via TestClient ---

    def test_ac03_http_rejects_payload_with_actor(self):
        """HTTP PATCH từ chối payload kèm 'actor' -> Trả về 422 Unprocessable Entity."""
        res = self.client.patch(
            "/api/v1/alerts/2/status",
            json={"new_status": "in_review", "actor": "fake_internal_operator"}
        )
        self.assertEqual(res.status_code, 422)
        self.assertIn("extra_forbidden", res.text)

    def test_ac03_http_rejects_payload_with_changed_by(self):
        """HTTP PATCH từ chối payload kèm 'changed_by' -> Trả về 422 Unprocessable Entity."""
        res = self.client.patch(
            "/api/v1/alerts/2/status",
            json={"new_status": "in_review", "changed_by": "root"}
        )
        self.assertEqual(res.status_code, 422)
        self.assertIn("extra_forbidden", res.text)

    def test_ac03_http_rejects_payload_with_actor_type_and_label(self):
        """HTTP PATCH từ chối payload kèm 'actor_type' hoặc 'actor_label' -> Trả về 422."""
        res1 = self.client.patch(
            "/api/v1/alerts/2/status",
            json={"new_status": "in_review", "actor_type": "system"}
        )
        self.assertEqual(res1.status_code, 422)
        self.assertIn("extra_forbidden", res1.text)

        res2 = self.client.patch(
            "/api/v1/alerts/2/status",
            json={"new_status": "in_review", "actor_label": "internal_operator"}
        )
        self.assertEqual(res2.status_code, 422)
        self.assertIn("extra_forbidden", res2.text)

    def test_ac03_http_rejects_payload_with_operator_name(self):
        """HTTP PATCH từ chối payload kèm 'operator_name' -> Trả về 422."""
        res = self.client.patch(
            "/api/v1/alerts/2/status",
            json={"new_status": "in_review", "operator_name": "Nguyen Van B"}
        )
        self.assertEqual(res.status_code, 422)
        self.assertIn("extra_forbidden", res.text)

    def test_ac03_db_state_untouched_after_rejected_requests(self):
        """Sau khi các request giả mạo actor bị từ chối, CSDL giữ nguyên trạng thái cũ và không có lịch sử rác."""
        # Gửi nhiều request giả mạo
        self.client.patch("/api/v1/alerts/2/status", json={"new_status": "resolved", "actor": "hacker"})
        self.client.patch("/api/v1/alerts/2/status", json={"new_status": "ignored", "changed_by": "admin"})

        with self.SessionLocal() as db:
            alert = db.query(SecurityAlert).filter(SecurityAlert.id == 2).first()
            self.assertEqual(alert.status, "open")
            self.assertIsNone(alert.resolved_at)

            # Không có lịch sử nào được sinh ra
            hist_count = db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id == 2).count()
            self.assertEqual(hist_count, 0)



class TestPBI11TaskS302c(unittest.TestCase):
    """
    S3-02c: Viết Pytest kiểm thử AC-04 (Rollback Transaction khi xảy ra lỗi ghi lịch sử).
    """

    def setUp(self):
        self.engine, self.SessionLocal = create_test_db()

        with self.SessionLocal() as db:
            repo = Repository(
                id=1,
                github_repo_id=12345,
                repo_name="org/test-repo",
                default_branch="main",
                access_token_encrypted="dummy_pat",
                repo_url="https://github.com/org/test-repo",
            )
            db.add(repo)
            self.test_alert = SecurityAlert(
                id=3,
                repo_id=1,
                fingerprint="c" * 64,
                source="gitprotect_scanner",
                rule_name="Slack Bot Token",
                severity="high",
                file_path="src/slack.py",
                status="open",
                detected_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
            db.add(self.test_alert)
            db.commit()

        def override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.engine.dispose()

    def test_ac04_successful_atomic_commit(self):
        """AC-04: Cập nhật thành công cập nhật đồng thời security_alerts và chèn alert_status_history trong 1 transaction."""
        from app.modules.alerts.schemas import AlertStatusUpdateRequest

        with self.SessionLocal() as db:
            req = AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.IN_REVIEW,
                resolution_note="Bắt đầu phân tích cảnh báo an ninh",
            )
            res = AlertLifecycleService.update_alert_status_atomic(db=db, alert_id=3, req=req)
            self.assertTrue(res["transaction_committed"])

        # Kiểm tra CSDL từ phiên mới
        with self.SessionLocal() as db:
            alert = db.query(SecurityAlert).filter(SecurityAlert.id == 3).first()
            self.assertEqual(alert.status, "in_review")
            self.assertEqual(alert.resolution_note, "Bắt đầu phân tích cảnh báo an ninh")

            histories = db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id == 3).all()
            self.assertEqual(len(histories), 1)
            self.assertEqual(histories[0].old_status, "open")
            self.assertEqual(histories[0].new_status, "in_review")

    def test_ac04_rollback_when_history_insertion_fails(self):
        """AC-04: Giả lập lỗi CSDL khi chèn alert_status_history -> Toàn bộ transaction phải rollback, alert giữ nguyên 'open'."""
        from unittest.mock import patch
        from sqlalchemy.exc import SQLAlchemyError
        from app.modules.alerts.schemas import AlertStatusUpdateRequest

        with self.SessionLocal() as db:
            req = AlertStatusUpdateRequest(
                new_status=AlertStatusEnum.RESOLVED,
                resolution_note="Cố gắng giải quyết alert",
            )

            # Mock flush của db ném SQLAlchemyError khi ghi history
            original_flush = db.flush
            def mock_flush(*args, **kwargs):
                raise SQLAlchemyError("Simulated DB Crash/Disk Full during history insert")

            db.flush = mock_flush

            with self.assertRaises(SQLAlchemyError):
                AlertLifecycleService.update_alert_status_atomic(db=db, alert_id=3, req=req)

        # Kiểm tra CSDL: Alert phải được rollback hoàn toàn về 'open'
        with self.SessionLocal() as db:
            alert = db.query(SecurityAlert).filter(SecurityAlert.id == 3).first()
            self.assertEqual(alert.status, "open")
            self.assertIsNone(alert.resolved_at)

            # Không có bản ghi lịch sử nào
            count = db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id == 3).count()
            self.assertEqual(count, 0)

    def test_ac04_rollback_on_validation_failure(self):
        """AC-04: Vi phạm ràng buộc nghiệp vụ (false_positive note < 10 ký tự) -> Rollback, alert giữ nguyên trạng thái cũ."""
        from app.modules.alerts.schemas import AlertStatusUpdateRequest

        bad_req = AlertStatusUpdateRequest.model_construct(
            new_status=AlertStatusEnum.FALSE_POSITIVE,
            resolution_note="ngắn",
        )

        with self.SessionLocal() as db:
            with self.assertRaises(ValueError) as ctx:
                AlertLifecycleService.update_alert_status_atomic(db=db, alert_id=3, req=bad_req)
            self.assertIn("AC-01 Violation", str(ctx.exception))

        with self.SessionLocal() as db:
            alert = db.query(SecurityAlert).filter(SecurityAlert.id == 3).first()
            self.assertEqual(alert.status, "open")
            self.assertEqual(db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id == 3).count(), 0)

    def test_ac04_resolved_at_lifecycle_consistency(self):
        """AC-04: resolved_at được set khi resolved/false_positive và xóa về None khi reopen in_review/open."""
        from app.modules.alerts.schemas import AlertStatusUpdateRequest

        with self.SessionLocal() as db:
            # 1. Chuyển sang resolved -> có resolved_at
            req1 = AlertStatusUpdateRequest(new_status=AlertStatusEnum.RESOLVED, resolution_note="Thu hồi key")
            AlertLifecycleService.update_alert_status_atomic(db=db, alert_id=3, req=req1)
            alert = db.query(SecurityAlert).filter(SecurityAlert.id == 3).first()
            self.assertIsNotNone(alert.resolved_at)

            # 2. Reopen sang in_review -> resolved_at bị reset về None
            req2 = AlertStatusUpdateRequest(new_status=AlertStatusEnum.IN_REVIEW, resolution_note="Phát hiện tái sử dụng")
            AlertLifecycleService.update_alert_status_atomic(db=db, alert_id=3, req=req2)
            alert = db.query(SecurityAlert).filter(SecurityAlert.id == 3).first()
            self.assertIsNone(alert.resolved_at)



class TestPBI11TaskS302d(unittest.TestCase):
    """
    S3-02d: Viết Pytest kiểm thử AC-05 (Append-only & chặn tuyệt đối API UPDATE/DELETE lịch sử).
    """

    def setUp(self):
        self.engine, self.SessionLocal = create_test_db()

        with self.SessionLocal() as db:
            repo = Repository(
                id=1,
                github_repo_id=12345,
                repo_name="org/test-repo",
                default_branch="main",
                access_token_encrypted="dummy_pat",
                repo_url="https://github.com/org/test-repo",
            )
            db.add(repo)
            self.test_alert = SecurityAlert(
                id=4,
                repo_id=1,
                fingerprint="d" * 64,
                source="gitprotect_scanner",
                rule_name="Private Key Leak",
                severity="critical",
                file_path="keys/id_rsa",
                status="open",
                detected_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
            db.add(self.test_alert)
            db.commit()

        def override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.engine.dispose()

    def test_ac05_http_blocks_modification_methods_on_history(self):
        """AC-05: Chặn tuyệt đối các HTTP method PUT/PATCH/DELETE/POST trên endpoint /history (Trả về 405 Method Not Allowed)."""
        # PUT
        res_put = self.client.put("/api/v1/alerts/4/history", json={"note": "hacked"})
        self.assertEqual(res_put.status_code, 405)

        # PATCH
        res_patch = self.client.patch("/api/v1/alerts/4/history", json={"note": "hacked"})
        self.assertEqual(res_patch.status_code, 405)

        # DELETE
        res_delete = self.client.delete("/api/v1/alerts/4/history")
        self.assertEqual(res_delete.status_code, 405)

        # POST
        res_post = self.client.post("/api/v1/alerts/4/history", json={"new_status": "in_review"})
        self.assertEqual(res_post.status_code, 405)

    def test_ac05_routes_only_allow_get_for_history(self):
        """AC-05: Router inspection - kiểm tra hệ thống không đăng ký bất kỳ method sửa/xóa nào cho /history."""
        from app.modules.alerts.router import router

        history_routes = [r for r in router.routes if "/history" in r.path]
        self.assertTrue(len(history_routes) > 0)
        allowed_methods = {method for r in history_routes for method in r.methods}

        self.assertEqual(allowed_methods, {"GET"})
        self.assertNotIn("PUT", allowed_methods)
        self.assertNotIn("PATCH", allowed_methods)
        self.assertNotIn("DELETE", allowed_methods)
        self.assertNotIn("POST", allowed_methods)

    def test_ac05_orm_strictly_blocks_update(self):
        """AC-05: Ở tầng ORM, can thiệp UPDATE vào bản ghi AlertStatusHistory bị chặn ngay lập tức bởi ValueError."""
        with self.SessionLocal() as db:
            entry = AlertStatusHistory(
                alert_id=4,
                old_status="open",
                new_status="in_review",
                actor_type="internal_operator",
                actor_label="internal_operator",
                resolution_note="Bản ghi ban đầu",
            )
            db.add(entry)
            db.commit()

            # Cố tình sửa đổi nội dung
            entry.resolution_note = "Sửa đổi trái phép nội dung nhật ký kiểm toán"
            with self.assertRaises(ValueError) as ctx:
                db.commit()
            self.assertIn("AC-05 Violation", str(ctx.exception))
            db.rollback()

    def test_ac05_orm_strictly_blocks_delete(self):
        """AC-05: Ở tầng ORM, can thiệp DELETE bản ghi AlertStatusHistory bị chặn ngay lập tức bởi ValueError."""
        with self.SessionLocal() as db:
            entry = AlertStatusHistory(
                alert_id=4,
                old_status="open",
                new_status="in_review",
                actor_type="internal_operator",
                actor_label="internal_operator",
                resolution_note="Bản ghi kiểm toán",
            )
            db.add(entry)
            db.commit()

            # Cố tình xóa bản ghi
            with self.assertRaises(ValueError) as ctx:
                db.delete(entry)
                db.commit()
            self.assertIn("AC-05 Violation", str(ctx.exception))
            db.rollback()

    def test_ac05_get_history_chronological_order(self):
        """AC-05: GET /api/v1/alerts/{id}/history trả về dữ liệu lịch sử tuần tự thời gian tăng dần."""
        # Thực hiện 2 lần đổi trạng thái hợp lệ
        res1 = self.client.patch("/api/v1/alerts/4/status", json={"new_status": "in_review", "resolution_note": "Bắt đầu"})
        self.assertEqual(res1.status_code, 200)

        res2 = self.client.patch("/api/v1/alerts/4/status", json={"new_status": "resolved", "resolution_note": "Hoàn tất xử lý"})
        self.assertEqual(res2.status_code, 200)

        # Đọc lịch sử
        hist_res = self.client.get("/api/v1/alerts/4/history")
        self.assertEqual(hist_res.status_code, 200)
        hist_data = hist_res.json()

        self.assertEqual(hist_data["alert_id"], 4)
        self.assertEqual(hist_data["total"], 2)
        items = hist_data["items"]
        self.assertEqual(items[0]["new_status"], "in_review")
        self.assertEqual(items[1]["new_status"], "resolved")

        # 404 cho alert không tồn tại
        not_found_res = self.client.get("/api/v1/alerts/99999/history")
        self.assertEqual(not_found_res.status_code, 404)



class TestPBI11TaskS302e(unittest.TestCase):
    """
    S3-02e: Pentest an toàn:
    1. Giả mạo Webhook HMAC-SHA256 (missing signature, tampered payload, forged key, replay).
    2. Injection string gây ReDoS (Catastrophic Backtracking) đảm bảo timeout <= 500ms.
    3. Kiểm tra an ninh CSDL với AES-256-GCM (không rò rỉ plaintext, unique IV, chống tampering, no hardcoded key).
    """

    def setUp(self):
        self.engine, self.SessionLocal = create_test_db()
        self.webhook_secret = "super-secret-webhook-key-pentest"

        with self.SessionLocal() as db:
            from app.core.security import crypto_service
            repo = Repository(
                id=10,
                github_repo_id=999,
                repo_name="org/pentest-repo",
                default_branch="main",
                access_token_encrypted=crypto_service.encrypt("ghp_testToken12345678901234567890123456"),
                webhook_secret_encrypted=crypto_service.encrypt(self.webhook_secret),
                repo_url="https://github.com/org/pentest-repo",
            )
            db.add(repo)
            db.commit()

        def override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.engine.dispose()

    # =========================================================================
    # 1. PENTEST WEBHOOK HMAC-SHA256
    # =========================================================================

    def _generate_signature(self, secret: str, body: bytes) -> str:
        import hmac
        import hashlib
        return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    def test_pentest_webhook_hmac_missing_signature_rejected(self):
        """Pentest Webhook: Gửi webhook không kèm chữ ký X-Hub-Signature-256 -> Bị từ chối 401."""
        body = b'{"repository": {"id": 999}}'
        headers = {
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "delivery-pentest-01",
        }
        res = self.client.post("/api/v1/webhooks/github", content=body, headers=headers)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Invalid webhook signature", res.text)

    def test_pentest_webhook_hmac_malformed_signature_format_rejected(self):
        """Pentest Webhook: Gửi signature sai định dạng chuẩn (không bắt đầu bằng sha256=) -> Bị từ chối 401."""
        body = b'{"repository": {"id": 999}}'
        headers = {
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "delivery-pentest-02",
            "X-Hub-Signature-256": "md5=1234567890abcdef1234567890abcdef",
        }
        res = self.client.post("/api/v1/webhooks/github", content=body, headers=headers)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Invalid webhook signature", res.text)

    def test_pentest_webhook_hmac_forged_secret_rejected(self):
        """Pentest Webhook: Giả mạo chữ ký bằng secret của attacker -> Bị từ chối 401."""
        body = b'{"repository": {"id": 999}}'
        forged_sig = self._generate_signature("attacker-fake-secret", body)
        headers = {
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "delivery-pentest-03",
            "X-Hub-Signature-256": forged_sig,
        }
        res = self.client.post("/api/v1/webhooks/github", content=body, headers=headers)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Invalid webhook signature", res.text)

    def test_pentest_webhook_hmac_tampered_payload_rejected(self):
        """Pentest Webhook: Ký hợp lệ với payload gốc nhưng sửa đổi nội dung body khi gửi -> 401 Mismatch."""
        original_body = b'{"repository": {"id": 999}, "commits": []}'
        valid_sig = self._generate_signature(self.webhook_secret, original_body)

        # Attacker chèn thêm dữ liệu vào payload
        tampered_body = b'{"repository": {"id": 999}, "commits": [], "malicious": true}'
        headers = {
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "delivery-pentest-04",
            "X-Hub-Signature-256": valid_sig,
        }
        res = self.client.post("/api/v1/webhooks/github", content=tampered_body, headers=headers)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Invalid webhook signature", res.text)

    def test_pentest_webhook_valid_signature_and_replay_protection(self):
        """Pentest Webhook: Chữ ký hợp lệ -> 200 queued; Replay cùng delivery ID -> duplicate_ignored."""
        import json
        from unittest.mock import patch, AsyncMock

        sha = "f" * 40
        body = json.dumps({
            "repository": {"id": 999},
            "ref": "refs/heads/main",
            "commits": [{"id": sha}]
        }).encode()
        sig = self._generate_signature(self.webhook_secret, body)
        headers = {
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "delivery-pentest-replay-check",
            "X-Hub-Signature-256": sig,
        }

        with patch("app.modules.ingestion.webhook.Redis") as mock_redis_cls, \
             patch("app.modules.ingestion.webhook.GitHubClient.request", new_callable=AsyncMock,
                   side_effect=[{"sha": sha, "commit": {
                       "author": {"name": "Test", "email": "test@organization.vn"},
                       "committer": {"name": "Test", "email": "test@organization.vn"},
                       "verification": {"verified": True}}}, "+diff"]):
            mock_redis = mock_redis_cls.return_value.__aenter__.return_value
            # Lần 1: chưa tồn tại -> enqueue thành công
            mock_redis.exists.return_value = False
            mock_redis.eval.return_value = 1

            res1 = self.client.post("/api/v1/webhooks/github", content=body, headers=headers)
            self.assertEqual(res1.status_code, 200)
            self.assertEqual(res1.json()["status"], "queued")

            # Lần 2: Replay attack cùng delivery ID -> Redis phát hiện key đã có
            mock_redis.exists.return_value = True
            res2 = self.client.post("/api/v1/webhooks/github", content=body, headers=headers)
            self.assertEqual(res2.status_code, 200)
            self.assertEqual(res2.json()["status"], "duplicate_ignored")

    # =========================================================================
    # 2. PENTEST REGEX REDOS (CATASTROPHIC BACKTRACKING)
    # =========================================================================

    def test_pentest_redos_catastrophic_backtracking_enforces_timeout(self):
        """Pentest ReDoS: Mẫu regex lồng nhau (a+)+$ với chuỗi tấn công 'a'*10000 + '!' phải ngắt timeout an toàn <= 500ms."""
        import time
        from app.modules.engine.regex_engine import RegexEngine
        from app.modules.engine.scan_pipeline import ScanPipeline

        # Pattern kinh điển gây Catastrophic Backtracking
        evil_patterns = [r"^(a+)+$"]
        engine = RegexEngine(patterns=evil_patterns, timeout=0.01)

        # Input tấn công
        evil_input = "a" * 10000 + "!"

        start_time = time.perf_counter()
        scan_res = engine.scan(evil_input)
        elapsed = time.perf_counter() - start_time

        # Kiểm tra RegexEngine ngắt an toàn với timed_out = True
        self.assertTrue(scan_res["timed_out"])
        self.assertEqual(scan_res["error"], "REGEX_TIMEOUT")
        self.assertLess(elapsed, 0.5, f"ReDoS không ngắt kịp thời gian: {elapsed}s")

        # Kiểm tra ScanPipeline ném TimeoutError an toàn
        pipeline = ScanPipeline(engine)
        with self.assertRaises(TimeoutError):
            pipeline.scan(evil_input, "app.py")

    def test_pentest_redos_long_repeated_payload_on_standard_rules(self):
        """Pentest ReDoS: Chuỗi độc hại dài 50,000 ký tự lặp lại quét qua RegexEngine chuẩn hoàn thành hoặc timeout an toàn < 0.6s."""
        import time
        from app.modules.engine.regex_engine import RegexEngine

        engine = RegexEngine(timeout=0.4)
        malicious_input = 'ghp_' + ('_' * 25000) + ' ' + ('AKIA' + '0' * 25000)

        start_time = time.perf_counter()
        try:
            res = engine.scan(malicious_input)
            self.assertIsInstance(res, dict)
        except TimeoutError:
            pass  # Timeout an toàn chấp nhận được
        elapsed = time.perf_counter() - start_time

        self.assertLess(elapsed, 0.6, f"Engine bị nghẽn CPU bởi payload lớn: {elapsed}s")

    # =========================================================================
    # 3. PENTEST AES-256-GCM DATABASE CIPHERTEXT SECURITY
    # =========================================================================

    def test_pentest_aes256gcm_ciphertext_never_exposes_plaintext_in_db(self):
        """Pentest AES-256-GCM: Dữ liệu nhạy cảm lưu trong CSDL tuyệt đối không chứa raw token plaintext."""
        with self.SessionLocal() as db:
            repo = db.query(Repository).filter(Repository.id == 10).first()
            # Raw PAT được lưu là "ghp_testToken12345678901234567890123456"
            self.assertNotIn("ghp_", repo.access_token_encrypted)
            self.assertNotIn("testToken", repo.access_token_encrypted)
            self.assertNotIn(self.webhook_secret, repo.webhook_secret_encrypted)

    def test_pentest_aes256gcm_unique_nonce_per_encryption(self):
        """Pentest AES-256-GCM: Hai lần mã hóa cùng một plaintext sinh ra 2 ciphertext hoàn toàn khác nhau (chống IV reuse)."""
        from app.core.security import crypto_service

        token = "ghp_ConsistentPlaintextToken1234567890"
        c1 = crypto_service.encrypt(token)
        c2 = crypto_service.encrypt(token)

        self.assertNotEqual(c1, c2, "LỖI AN NINH NGHIÊM TRỌNG: Tái sử dụng IV/Nonce trong AES-256-GCM!")
        # Nhưng cả hai đều giải mã ra đúng plaintext ban đầu
        self.assertEqual(crypto_service.decrypt(c1), token)
        self.assertEqual(crypto_service.decrypt(c2), token)

    def test_pentest_aes256gcm_tampered_ciphertext_fails_closed(self):
        """Pentest AES-256-GCM: Sửa đổi bit trong ciphertext (Bit-flipping attack) -> InvalidTag, tuyệt đối không trả về dữ liệu rác."""
        import base64
        from cryptography.exceptions import InvalidTag
        from app.core.security import crypto_service

        token = "ghp_SecretToProtectAgainstTampering123"
        encrypted_b64 = crypto_service.encrypt(token)
        raw_bytes = bytearray(base64.b64decode(encrypted_b64))

        # Attacker đảo 1 byte trong ciphertext payload
        raw_bytes[15] ^= 0xFF
        tampered_b64 = base64.b64encode(bytes(raw_bytes)).decode()

        with self.assertRaises(InvalidTag):
            crypto_service.decrypt(tampered_b64)

    def test_pentest_aes256gcm_wrong_master_key_fails_closed(self):
        """Pentest AES-256-GCM: Cố tình giải mã bằng khóa AES khác -> Ném InvalidTag."""
        from cryptography.exceptions import InvalidTag
        from app.core.security import CryptoService, crypto_service

        token = "ghp_SecretConfidentialData12345"
        encrypted_b64 = crypto_service.encrypt(token)

        # Attacker khởi tạo service với master key ngẫu nhiên khác
        other_key = CryptoService.generate_master_key_hex()
        attacker_service = CryptoService(master_key_hex=other_key)

        with self.assertRaises(InvalidTag):
            attacker_service.decrypt(encrypted_b64)

    def test_pentest_aes256gcm_no_hardcoded_fallback_key(self):
        """Pentest AES-256-GCM: Khi thiếu biến môi trường, hệ thống ném ValueError, tuyệt đối không dùng fallback key cố định."""
        import os
        from unittest.mock import patch
        from app.core.security import CryptoService
        import app.core.security as security_mod
        import app.core.config as config_mod

        with patch.dict(os.environ, {}, clear=True), \
             patch.object(config_mod.settings, "AES_MASTER_KEY_HEX", None), \
             patch.object(security_mod.settings, "AES_MASTER_KEY_HEX", None):
            with self.assertRaises(ValueError) as ctx:
                CryptoService(master_key_hex=None)
            self.assertIn("Thiếu cấu hình khóa AES Master Key", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
