from typing import Optional
from fastapi import Depends
from redis.exceptions import RedisError
from app.db.session import get_db
from app.modules.engine import initial_scan
from app.modules.engine.scan_alerts import repository, sync_native
from fastapi import APIRouter, HTTPException, status
from app.core.enums import SeverityEnum
from app.modules.engine.schemas import (
    ScanJobTriggerResponse, ScanJobStatusResponse,
    EvaluateTextRequest, EvaluateTextResponse,
    ScanRuleListResponse, ScanRuleCreateRequest, ScanRuleResponse,
    NativeAlertSyncResponse
)
from app.modules.engine.service import DetectionEngineService

router = APIRouter(prefix="", tags=["MOD-02: Scanning & Detection Engine"])

@router.post("/scan/trigger/{repo_id}", response_model=ScanJobTriggerResponse, status_code=status.HTTP_202_ACCEPTED, summary="Kích hoạt quét toàn diện khởi tạo (Initial Scan FR-10)")
def trigger_scan(repo_id: int, db=Depends(get_db)):
    repo = repository(db, repo_id, lock=True)
    try:
        with initial_scan.redis_client() as redis:
            job = initial_scan.enqueue(repo, redis)
            if job["scan_status"] == "pending":
                repo.scan_status = "pending"
                db.commit()
            return job
    except RedisError:
        raise HTTPException(503, "Scan queue unavailable") from None

@router.post("/scan/evaluate-text", response_model=EvaluateTextResponse, summary="Kiểm tra nhanh đoạn mã nguồn theo pipeline 3 lớp & 7 quy tắc (FR-06, FR-07, FR-08)")
async def evaluate_text(req: EvaluateTextRequest):
    try:
        return DetectionEngineService.evaluate_snippet(req.content, req.file_path)
    except TimeoutError:
        raise HTTPException(status_code=503, detail="SCAN_TIMEOUT") from None

@router.get("/scan/jobs/{id}", response_model=ScanJobStatusResponse, summary="Tra cứu tiến độ phần trăm (%) và trạng thái tiến trình quét nền (FR-10)")
def get_scan_job(id: str):
    try:
        with initial_scan.redis_client() as redis:
            return initial_scan.status(redis, id)
    except RedisError:
        raise HTTPException(503, "Scan queue unavailable") from None

@router.get("/rules", response_model=ScanRuleListResponse, summary="Lấy danh sách 7 quy tắc quét chuẩn hệ thống (RULE-01 đến RULE-07)")
async def list_rules(is_enabled: Optional[bool] = None, severity: Optional[SeverityEnum] = None):
    return DetectionEngineService.list_rules(is_enabled=is_enabled, severity=severity)

@router.post("/rules", response_model=ScanRuleResponse, status_code=status.HTTP_201_CREATED, summary="[COULD - v2.0] Thêm quy tắc quét tùy chỉnh mở rộng")
async def create_custom_rule(req: ScanRuleCreateRequest):
    return {
        "id": 8,
        "rule_code": req.rule_code,
        "rule_name": req.rule_name,
        "description": req.description,
        "pattern_regex": req.pattern_regex,
        "charset_type": req.charset_type,
        "min_entropy_threshold": req.min_entropy_threshold,
        "min_entropy_threshold_long": req.min_entropy_threshold_long,
        "min_length": req.min_length,
        "context_keywords": req.context_keywords,
        "default_severity": req.default_severity,
        "allowlist_patterns": req.allowlist_patterns,
        "is_enabled": req.is_enabled,
        "created_at": "2026-11-06T20:00:00Z",
        "updated_at": "2026-11-06T20:00:00Z"
    }

@router.post("/sync/native-alerts/{repo_id}", response_model=NativeAlertSyncResponse, summary="Đồng bộ một chiều (pull) cảnh báo từ GitHub Secret Scanning & Dependabot (FR-03)")
def sync_native_alerts(repo_id: int, db=Depends(get_db)):
    return sync_native(repo_id, db)
