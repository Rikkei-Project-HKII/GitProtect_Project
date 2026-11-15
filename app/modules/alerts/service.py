from __future__ import annotations
from typing import Any, Optional
from sqlalchemy.orm import Session

from app.modules.alerts.schemas import AlertStatusUpdateRequest
from app.db.transaction import AlertTransactionManager
from app.core.enums import ActorTypeEnum


class AlertLifecycleService:
    @staticmethod
    def update_alert_status_atomic(
        db_or_alert_id: Any = None,
        alert_id_or_req: Any = None,
        req_or_db: Any = None,
        *,
        db: Optional[Session] = None,
        alert_id: Optional[int] = None,
        req: Optional[AlertStatusUpdateRequest] = None,
        **kwargs: Any,
    ):
        """
        Cập nhật trạng thái alert và chèn alert_status_history trong CÙNG MỘT Transaction (AC-04).
        Backend tự động xác định actor_type='internal_operator', actor_label='internal_operator' (AC-01, AC-03).
        Gọi AlertTransactionManager với phiên DB thật.

        Hỗ trợ gọi theo các dạng chữ ký:
          - update_alert_status_atomic(db, alert_id, req)
          - update_alert_status_atomic(db=db, alert_id=alert_id, req=req)
          - update_alert_status_atomic(alert_id, req, db=db)
          - update_alert_status_atomic(alert_id, req)
        """
        actual_db: Optional[Session] = db
        actual_alert_id: Optional[int] = alert_id
        actual_req: Optional[AlertStatusUpdateRequest] = req

        # Xử lý các đối số truyền theo vị trí (positional args)
        if isinstance(db_or_alert_id, Session):
            actual_db = db_or_alert_id
            if alert_id_or_req is not None:
                actual_alert_id = alert_id_or_req
            if req_or_db is not None:
                actual_req = req_or_db
        elif isinstance(db_or_alert_id, int):
            actual_alert_id = db_or_alert_id
            if alert_id_or_req is not None:
                actual_req = alert_id_or_req
            if isinstance(req_or_db, Session):
                actual_db = req_or_db

        if actual_alert_id is None or actual_req is None:
            raise ValueError("alert_id và req là bắt buộc.")

        if actual_db is None:
            from app.db.session import SessionLocal
            with SessionLocal() as session:
                return AlertLifecycleService.update_alert_status_atomic(
                    db=session,
                    alert_id=actual_alert_id,
                    req=actual_req,
                )

        alert, history_entry = AlertTransactionManager.update_alert_status_atomic(
            db=actual_db,
            alert_id=actual_alert_id,
            new_status=actual_req.new_status,
            resolution_note=actual_req.resolution_note,
            actor_type=ActorTypeEnum.INTERNAL_OPERATOR,
            actor_label="internal_operator",
        )
        return {
            "alert": alert,
            "history_entry": history_entry,
            "transaction_committed": True,
        }
