from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.core.enums import AlertStatusEnum, SeverityEnum, AlertSourceEnum, ActorTypeEnum


class StrictBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SecurityAlertDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

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


class AlertPaginatedListResponse(BaseModel):
    items: List[SecurityAlertDetailResponse]
    total: int
    page: int = 1
    page_size: int = 50


class AlertStatusUpdateRequest(StrictBase):
    new_status: AlertStatusEnum = Field(..., description="Trạng thái mới cần chuyển sang")
    resolution_note: Optional[str] = Field(default=None, description="Lý do giải trình (Bắt buộc >= 10 ký tự khi false_positive)")

    @model_validator(mode="after")
    def validate_false_positive_note(self) -> "AlertStatusUpdateRequest":
        if self.new_status == AlertStatusEnum.FALSE_POSITIVE:
            cleaned = (self.resolution_note or "").strip()
            if len(cleaned) < 10:
                raise ValueError("AC-01 Violation: resolution_note bắt buộc >= 10 ký tự khi đánh dấu false_positive.")
            self.resolution_note = cleaned
        elif self.resolution_note is not None:
            self.resolution_note = self.resolution_note.strip() or None
        return self


class AlertStatusHistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int
    old_status: Optional[AlertStatusEnum] = None
    new_status: AlertStatusEnum
    actor_type: ActorTypeEnum
    actor_label: str
    resolution_note: Optional[str] = None
    created_at: datetime


class AlertStatusUpdateResponse(BaseModel):
    alert: SecurityAlertDetailResponse
    history_entry: AlertStatusHistoryItem
    transaction_committed: bool = True


class AlertHistoryListResponse(BaseModel):
    alert_id: int
    items: List[AlertStatusHistoryItem]
    total: int
