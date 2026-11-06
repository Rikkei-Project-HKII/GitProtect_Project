from datetime import datetime
from typing import List, Literal, Optional
from pydantic import BaseModel, Extra, Field
from app.core.enums import ScanStatusEnum, SeverityEnum, CharsetTypeEnum, ActorTypeEnum

class StrictBase(BaseModel):
    class Config:
        extra = Extra.forbid

class ScanJobTriggerResponse(BaseModel):
    job_id: str
    repo_id: int
    default_branch: str
    scan_status: ScanStatusEnum = ScanStatusEnum.RUNNING
    progress_pct: int = Field(default=0, ge=0, le=100)
    redis_key: str
    actor_type: ActorTypeEnum = ActorTypeEnum.SYSTEM
    actor_label: str = "system"
    started_at: datetime

class ScanJobStatusResponse(BaseModel):
    job_id: str
    repo_id: int
    scan_status: ScanStatusEnum
    progress_pct: int = Field(..., ge=0, le=100)
    scanned_files: int = 0
    total_files: int = 0
    alerts_detected: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None

class EvaluateTextRequest(StrictBase):
    content: str = Field(..., min_length=1, max_length=10240)
    file_path: str = Field(default=".env", max_length=1000)

class EvaluateTextFinding(BaseModel):
    rule_code: str
    rule_name: str
    severity: SeverityEnum
    line_number: int
    secret_masked: str
    charset_detected: Literal["hex", "base32", "base64", "ascii", "none"]
    shannon_entropy: float
    threshold_applied: Optional[float] = None
    context_matched: bool = True

class EvaluateTextResponse(BaseModel):
    is_leaked: bool
    file_allowlisted: bool
    execution_time_ms: float
    findings: List[EvaluateTextFinding] = []

class ScanRuleResponse(BaseModel):
    id: int
    rule_code: str
    rule_name: str
    description: str
    pattern_regex: str
    charset_type: CharsetTypeEnum
    min_entropy_threshold: Optional[float] = None
    min_entropy_threshold_long: Optional[float] = None
    min_length: int = 20
    context_keywords: Optional[str] = None
    default_severity: SeverityEnum
    allowlist_patterns: Optional[str] = None
    is_enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ScanRuleListResponse(BaseModel):
    items: List[ScanRuleResponse]
    total: int

class ScanRuleCreateRequest(StrictBase):
    rule_code: str = Field(..., max_length=50)
    rule_name: str = Field(..., max_length=150)
    description: str
    pattern_regex: str
    charset_type: CharsetTypeEnum = CharsetTypeEnum.DYNAMIC
    min_entropy_threshold: Optional[float] = None
    min_entropy_threshold_long: Optional[float] = None
    min_length: int = 20
    context_keywords: Optional[str] = None
    default_severity: SeverityEnum = SeverityEnum.MEDIUM
    allowlist_patterns: Optional[str] = None
    is_enabled: bool = True

class NativeAlertSyncResponse(BaseModel):
    repo_id: int
    synced_secret_alerts: int
    synced_dependabot_alerts: int
    new_alerts_inserted: int
    duplicates_skipped: int
    actor_type: ActorTypeEnum = ActorTypeEnum.SYSTEM
    actor_label: str = "system"
    synced_at: datetime
