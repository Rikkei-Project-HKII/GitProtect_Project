"""MOD-04 Dashboard router (S2-09a)."""
from typing import Literal, Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.dashboard.schemas import MetricsResponse, RepoBreakdownResponse, TrendResponse
from app.modules.dashboard.service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["MOD-04: Dashboard"])


@router.get("/metrics", response_model=MetricsResponse, summary="KPI 4 mức độ nghiêm trọng (cache 60s)")
def get_metrics(db: Session = Depends(get_db)):
    return DashboardService.get_metrics(db)


@router.get("/repo-breakdown", response_model=RepoBreakdownResponse, summary="Phân bố cảnh báo theo kho (cache 60s)")
def get_repo_breakdown(db: Session = Depends(get_db)):
    return DashboardService.get_repo_breakdown(db)


@router.get("/trend", response_model=TrendResponse, summary="Xu hướng rò rỉ theo ngày/tuần (cache 60s)")
def get_trend(
    granularity: Literal["day", "week"] = "day",
    days: int = Query(30, ge=7, le=180),
    db: Session = Depends(get_db)
):
    return DashboardService.get_trend(db, granularity, days)


@router.get("/export", summary="Xuất báo cáo an ninh (CSV/PDF) - S3-08a, S3-08b")
def export_report(
    format: str = Query("csv", pattern="^(csv|pdf)$"),
    db: Session = Depends(get_db)
):
    if format == "csv":
        return Response(content="id,repo_name,rule_name,severity,secret_masked\n", media_type="text/csv")
    pdf_bytes = DashboardService.generate_security_pdf(db)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=GitProtect_Security_Report.pdf",
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )
