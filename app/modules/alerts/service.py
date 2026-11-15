"""
GitProtect MVP - Phân hệ MOD-03: Alert & Lifecycle Management
Task S2-08c: Cài đặt logic Backend tự gán actor_type và actor_label snapshot ('system' / 'internal_operator') (AC-01, AC-02).
"""

from __future__ import annotations
from typing import Any, Optional, Union
from sqlalchemy.orm import Session

from app.modules.alerts.schemas import AlertStatusUpdateRequest
from app.db.transaction import AlertTransactionManager
from app.core.enums import ActorTypeEnum, AlertStatusEnum


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
        actor_type: Union[ActorTypeEnum, str] = ActorTypeEnum.INTERNAL_OPERATOR,
        actor_label: Optional[str] = None,
        **kwargs: Any,
    ):
        """
        Cập nhật trạng thái alert và chèn alert_status_history trong CÙNG MỘT Transaction (AC-04).
        Backend tự động xác định actor_type='internal_operator', actor_label='internal_operator' (AC-01, AC-03)
        hoặc actor_type='system', actor_label='system' khi được gọi bởi Background Job/Worker (AC-02).
        Gọi AlertTransactionManager với phiên DB thật.
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

        # Xử lý actor_type & snapshot actor_label (AC-01, AC-02)
        resolved_actor_type = kwargs.get("actor_type", actor_type)
        if isinstance(resolved_actor_type, str):
            resolved_actor_type = ActorTypeEnum(resolved_actor_type)
        resolved_actor_label = kwargs.get("actor_label", actor_label) or resolved_actor_type.value

        if actual_db is None:
            from app.db.session import SessionLocal
            with SessionLocal() as session:
                return AlertLifecycleService.update_alert_status_atomic(
                    db=session,
                    alert_id=actual_alert_id,
                    req=actual_req,
                    actor_type=resolved_actor_type,
                    actor_label=resolved_actor_label,
                )

        alert, history_entry = AlertTransactionManager.update_alert_status_atomic(
            db=actual_db,
            alert_id=actual_alert_id,
            new_status=actual_req.new_status,
            resolution_note=actual_req.resolution_note,
            actor_type=resolved_actor_type,
            actor_label=resolved_actor_label,
        )
        return {
            "alert": alert,
            "history_entry": history_entry,
            "transaction_committed": True,
        }

    @classmethod
    def record_system_status_change(
        cls,
        db: Session,
        alert_id: int,
        new_status: Union[AlertStatusEnum, str],
        resolution_note: Optional[str] = None,
    ):
        """Helper cho Worker/Background Job thực hiện cập nhật với actor='system' (AC-02)."""
        status_enum = AlertStatusEnum(new_status) if isinstance(new_status, str) else new_status
        req = AlertStatusUpdateRequest(new_status=status_enum, resolution_note=resolution_note)
        return cls.update_alert_status_atomic(
            db=db,
            alert_id=alert_id,
            req=req,
            actor_type=ActorTypeEnum.SYSTEM,
            actor_label="system",
        )
