from typing import Optional
from fastapi import APIRouter, Query, Response
from app.modules.dashboard.schemas import (
    DashboardMetricsResponse, RepoBreakdownListResponse,
    DashboardTrendResponse, AuthorAuditResponse
)
from app.modules.dashboard.service import DashboardService

router = APIRouter(prefix="", tags=["MOD-04: Dashboard & Author Auditing"])

@router.get("/dashboard/metrics", response_model=DashboardMetricsResponse, summary="Lấy số liệu KPI tổng quan đa kho lưu trữ trên Website Dashboard (FR-05)")
async def get_metrics(repo_id: Optional[int] = None):
    return DashboardService.get_kpi_metrics(repo_id)

@router.get("/dashboard/repo-breakdown", response_model=RepoBreakdownListResponse, summary="Thống kê sức khỏe bảo mật và điểm số rủi ro theo từng kho lưu trữ (FR-05)")
async def get_repo_breakdown():
    return {"items": [], "total": 0}

@router.get("/dashboard/trend", response_model=DashboardTrendResponse, summary="Lấy chuỗi thời gian xu hướng phát hiện và xử lý rò rỉ theo ngày/tuần (FR-05)")
async def get_trend(period: str = "7d", repo_id: Optional[int] = None):
    return {"period": period, "series": [], "cached_ttl_seconds": 60}

@router.get("/audit/authors/{repo_id}", response_model=AuthorAuditResponse, summary="Kiểm toán danh tính tác giả commit & cảnh báo giả mạo email (FR-09)")
async def audit_authors(repo_id: int, spoofing_only: bool = False):
    return {
        "repo_id": repo_id,
        "allowed_email_domains": ["organization.vn"],
        "total_commits_audited": 12,
        "spoofing_violations_count": 1,
        "items": []
    }

@router.get("/dashboard/export", summary="Xuất báo cáo tổng hợp tình trạng an ninh mã nguồn định dạng CSV hoặc PDF")
async def export_report(format: str = Query("csv", regex="^(csv|pdf)$")):
    if format == "csv":
        return Response(content="id,repo_name,rule_name,severity,secret_masked\n", media_type="text/csv")
    return Response(content=b"%PDF-1.4 Mock Export Content", media_type="application/pdf")
