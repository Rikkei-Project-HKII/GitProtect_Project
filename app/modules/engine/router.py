from typing import Optional
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
async def trigger_scan(repo_id: int):
    return {
        "job_id": f"job_repo_{repo_id}_init",
        "repo_id": repo_id,
        "default_branch": "main",
        "scan_status": "running",
        "progress_pct": 0,
        "redis_key": f"scan:job:job_repo_{repo_id}_init",
        "actor_type": "system",
        "actor_label": "system",
        "started_at": "2026-11-06T20:00:00Z"
    }

@router.post("/scan/evaluate-text", response_model=EvaluateTextResponse, summary="Kiểm tra nhanh đoạn mã nguồn theo pipeline 3 lớp & 7 quy tắc (FR-06, FR-07, FR-08)")
async def evaluate_text(req: EvaluateTextRequest):
    try:
        return DetectionEngineService.evaluate_snippet(req.content, req.file_path)
    except TimeoutError:
        raise HTTPException(status_code=503, detail="SCAN_TIMEOUT") from None

@router.get("/scan/jobs/{id}", response_model=ScanJobStatusResponse, summary="Tra cứu tiến độ phần trăm (%) và trạng thái tiến trình quét nền (FR-10)")
async def get_scan_job(id: str):
    return {
        "job_id": id,
        "repo_id": 1,
        "scan_status": "running",
        "progress_pct": 65,
        "scanned_files": 32,
        "total_files": 49,
        "alerts_detected": 2
    }

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
async def sync_native_alerts(repo_id: int):
    return {
        "repo_id": repo_id,
        "synced_secret_alerts": 2,
        "synced_dependabot_alerts": 3,
        "new_alerts_inserted": 4,
        "duplicates_skipped": 1,
        "actor_type": "system",
        "actor_label": "system",
        "synced_at": "2026-11-06T20:00:00Z"
    }