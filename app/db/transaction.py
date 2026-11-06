"""
GitProtect MVP (v1.1 Baseline - GP-2026-SCRUM)
Task S1-02a: Transaction Manager & Atomic Unit of Work (ACID)
Phụ trách: TV1 (Huỳnh Công Danh - Product Owner & Backend/DB Lead)

Mục tiêu kỹ thuật (S1-02a, AC-01..AC-05):
1. Đảm bảo tính toàn vẹn ACID (Atomicity): Cập nhật trạng thái alert (security_alerts)
   và chèn bản ghi nhật ký kiểm toán (alert_status_history) BẮT BUỘC nằm trong CÙNG MỘT Transaction.
   Nếu bất kỳ thao tác nào thất bại -> Rollback toàn bộ trạng thái.
2. Context Manager `transactional_session(db)` hỗ trợ cú pháp `with` gọn gàng, tự động commit khi thành công
   và rollback tức thì khi có lỗi.
3. Service nghiệp vụ `AlertTransactionManager.update_alert_status_atomic()`:
   - Tự động gán `actor_type = 'internal_operator'`, `actor_label = 'internal_operator'` (hoặc 'system' cho Worker).
   - Kiểm tra `resolution_note >= 10` ký tự khi `new_status = 'false_positive'` (AC-01).
   - Cấm client truyền trường actor (AC-03).
   - Rollback nguyên tử khi ghi lịch sử gặp lỗi (AC-04).
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from typing import Generator, Optional, Tuple, Union, TYPE_CHECKING

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.core.enums import AlertStatusEnum, ActorTypeEnum
from app.db.session import SessionLocal

if TYPE_CHECKING:
    from app.models.security_alert import SecurityAlert
    from app.models.alert_status_history import AlertStatusHistory


@contextmanager
def transactional_session(session: Session) -> Generator[Session, None, None]:
    """
    Context manager bọc một khối lệnh trong một Database Transaction nguyên tử.
    - Tự động `commit()` khi hoàn thành khối `with` mà không có ngoại lệ.
    - Tự động `rollback()` và re-raise ngoại lệ nếu xảy ra bất kỳ lỗi nào.
    """
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise


@contextmanager
def transaction_scope(session: Optional[Session] = None) -> Generator[Session, None, None]:
    """
    Context manager for atomic database transactions.
    
    If an existing session is provided, it manages transaction commit/rollback
    without closing the session (for caller reuse).
    If no session is provided, it instantiates a SessionLocal, commits on success,
    rolls back on error, and ensures the session is closed in the finally block.
    """
    if session is not None:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
    else:
        db = SessionLocal()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


class AlertTransactionManager:
    """
    Quản lý cập nhật trạng thái Cảnh báo và Ghi nhật ký kiểm toán trong 1 ACID Transaction.
    """

    @staticmethod
    def update_alert_status_atomic(
        db: Session,
        alert_id: int,
        new_status: Union[AlertStatusEnum, str],
        resolution_note: Optional[str] = None,
        actor_type: Union[ActorTypeEnum, str] = ActorTypeEnum.INTERNAL_OPERATOR,
        actor_label: Optional[str] = None,
    ) -> Tuple[SecurityAlert, AlertStatusHistory]:
        """
        Thực thi cập nhật trạng thái alert và chèn lịch sử kiểm toán trong cùng một Transaction.

        Args:
            db: SQLAlchemy Session.
            alert_id: ID cảnh báo bảo mật.
            new_status: Trạng thái mới (open, in_review, resolved, false_positive, ignored).
            resolution_note: Lý do giải trình. Bắt buộc >= 10 ký tự nếu new_status = 'false_positive'.
            actor_type: Nguồn thực hiện (do Backend tự xác định: 'system' hoặc 'internal_operator').
            actor_label: Nhãn hiển thị snapshot (mặc định = actor_type.value).

        Returns:
            Tuple chứa (SecurityAlert đã cập nhật, AlertStatusHistory vừa tạo).

        Raises:
            ValueError: Khi alert không tồn tại hoặc vi phạm ràng buộc giải trình false_positive.
            SQLAlchemyError: Khi có lỗi CSDL, tự động rollback cả alert và history.
        """
        from app.models.security_alert import SecurityAlert
        from app.models.alert_status_history import AlertStatusHistory

        # Chuẩn hóa giá trị enum / string
        status_val = new_status.value if hasattr(new_status, "value") else str(new_status)
        actor_type_val = actor_type.value if hasattr(actor_type, "value") else str(actor_type)

        # Xác định nhãn actor snapshot
        final_actor_label = actor_label or actor_type_val

        # Ràng buộc AC-01: False positive bắt buộc giải trình >= 10 ký tự
        cleaned_note = (resolution_note or "").strip()
        if status_val in (AlertStatusEnum.FALSE_POSITIVE.value, "false_positive"):
            if len(cleaned_note) < 10:
                raise ValueError(
                    "AC-01 Violation: 'resolution_note' bắt buộc tối thiểu 10 ký tự khi chuyển trạng thái 'false_positive'."
                )
        final_note = cleaned_note if cleaned_note else None

        # BẮT ĐẦU ATOMIC TRANSACTION (AC-04)
        with transactional_session(db):
            # 1. Truy vấn Alert với khóa dòng (SELECT FOR UPDATE) để chống Race Condition
            alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).with_for_update().first()
            if not alert:
                raise ValueError(f"Không tìm thấy cảnh báo bảo mật với ID = {alert_id}.")

            old_status = alert.status

            # 2. Cập nhật trạng thái alert
            alert.status = status_val
            alert.resolution_note = final_note
            if status_val in (
                AlertStatusEnum.RESOLVED.value,
                AlertStatusEnum.FALSE_POSITIVE.value,
                "resolved",
                "false_positive",
            ):
                alert.resolved_at = datetime.utcnow()

            # 3. Tạo bản ghi nhật ký kiểm toán Append-only (AC-04, AC-05)
            history_entry = AlertStatusHistory(
                alert_id=alert.id,
                old_status=old_status,
                new_status=status_val,
                actor_type=actor_type_val,
                actor_label=final_actor_label,
                resolution_note=final_note,
            )
            db.add(history_entry)
            db.flush()  # Lấy ID của history_entry trước khi commit

        # Khi ra khỏi context manager transactional_session, transaction đã được COMMIT thành công
        db.refresh(alert)
        db.refresh(history_entry)
        return alert, history_entry
