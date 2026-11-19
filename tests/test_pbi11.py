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


if __name__ == "__main__":
    unittest.main()
