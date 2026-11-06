from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Extra, Field, root_validator
from app.core.enums import AlertStatusEnum, SeverityEnum, AlertSourceEnum, ActorTypeEnum

class StrictBase(BaseModel):
    class Config:
        extra = Extra.forbid

class SecurityAlertDetailResponse(BaseModel):
    id: int
    repo_id: int
    rule_id: Optional[int] = None
    fingerprint: str = Field(..., min_length=64, max_length=64)
    alert_number: Optional[int] = None
    source: AlertSourceEnum
    package_name: Optional[str] = None
    cve_id: Optional[str] = None
    fixed_version: Optional[str] = None
    rule_name: str
    severity: SeverityEnum
    file_path: str
    line_number: Optional[int] = None
    commit_sha: Optional[str] = None
    author_name: Optional[str] = None
    author_email: Optional[str] = None
    signature_verified: Optional[bool] = None
    email_spoofing_flag: bool = False
    secret_masked: Optional[str] = None
    status: AlertStatusEnum
    resolution_note: Optional[str] = None
    resolved_at: Optional[datetime] = None
    detected_at: datetime

    class Config:
        from_attributes = True

class AlertPaginatedListResponse(BaseModel):
    items: List[SecurityAlertDetailResponse]
    total: int
    page: int = 1
    page_size: int = 50

class AlertStatusUpdateRequest(StrictBase):
    new_status: AlertStatusEnum = Field(..., description="Trạng thái mới cần chuyển sang")
    resolution_note: Optional[str] = Field(default=None, description="Lý do giải trình (Bắt buộc >= 10 ký tự khi false_positive)")

    @root_validator(skip_on_failure=True)
    def validate_false_positive_note(cls, values):
        new_status = values.get("new_status")
        note = values.get("resolution_note")
        if new_status == AlertStatusEnum.FALSE_POSITIVE:
            cleaned = (note or "").strip()
            if len(cleaned) < 10:
                raise ValueError("AC-01 Violation: resolution_note bắt buộc >= 10 ký tự khi đánh dấu false_positive.")
            values["resolution_note"] = cleaned
        elif note is not None:
            values["resolution_note"] = note.strip() or None
        return values

class AlertStatusHistoryItem(BaseModel):
    id: int
    alert_id: int
    old_status: Optional[AlertStatusEnum] = None
    new_status: AlertStatusEnum
    actor_type: ActorTypeEnum
    actor_label: str
    resolution_note: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class AlertStatusUpdateResponse(BaseModel):
    alert: SecurityAlertDetailResponse
    history_entry: AlertStatusHistoryItem
    transaction_committed: bool = True

class AlertHistoryListResponse(BaseModel):
    alert_id: int
    items: List[AlertStatusHistoryItem]
    total: int
