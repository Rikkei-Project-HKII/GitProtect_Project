"""MOD-04 Dashboard service (S2-09a): KPI, repo breakdown, trend + Redis cache TTL 60s."""
import csv
import io
import json
from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Optional, Tuple

import redis
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from sqlalchemy import func, case
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.enums import AlertStatusEnum, SeverityEnum
from app.models import Repository, SecurityAlert

CACHE_TTL = 60
SEVERITIES = tuple(s.value for s in SeverityEnum)  # critical, high, medium, low
# "Đang mở" = chưa xử lý xong
OPEN_STATUSES = (AlertStatusEnum.OPEN.value, AlertStatusEnum.IN_REVIEW.value)
WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}  # TODO: chỉnh theo công thức Risk Score trong SRS

_redis = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, decode_responses=True,
                     socket_connect_timeout=1, socket_timeout=1)


def _sev(v) -> str:
    return str(getattr(v, "value", v)).lower()


def _cached(key: str, builder):
    """Cache-aside TTL 60s; Redis lỗi thì vẫn trả dữ liệu từ DB (fail-open)."""
    try:
        hit = _redis.get(key)
        if hit:
            return json.loads(hit)
    except redis.RedisError:
        pass
    data = builder()
    try:
        _redis.setex(key, CACHE_TTL, json.dumps(data, default=str))
    except redis.RedisError:
        pass
    return data


class DashboardService:
    @staticmethod
    def get_metrics(db: Session) -> dict:
        def build():
            open_expr = case((SecurityAlert.status.in_(OPEN_STATUSES), 1), else_=0)
            rows = (
                db.query(SecurityAlert.severity, func.count(SecurityAlert.id), func.sum(open_expr))
                .group_by(SecurityAlert.severity)
                .all()
            )
            out = {s: 0 for s in SEVERITIES}
            open_total = 0
            for sev, cnt, opened in rows:
                if _sev(sev) in out:
                    out[_sev(sev)] = int(cnt)
                open_total += int(opened or 0)
            out["total"] = sum(out[s] for s in SEVERITIES)
            out["open_total"] = open_total
            out["risk_score"] = float(sum(out[s] * w for s, w in WEIGHTS.items()))
            return out
        return _cached("dashboard:metrics", build)

    @staticmethod
    def get_repo_breakdown(db: Session) -> dict:
        def build():
            rows = (
                db.query(SecurityAlert.repo_id, SecurityAlert.severity, func.count(SecurityAlert.id))
                .group_by(SecurityAlert.repo_id, SecurityAlert.severity)
                .all()
            )
            names = dict(db.query(Repository.id, Repository.repo_name).all())
            repos = {}
            for repo_id, sev, cnt in rows:
                item = repos.setdefault(repo_id, {"repo_id": repo_id, "repo_name": names.get(repo_id, f"repo-{repo_id}"),
                                                  "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
                if _sev(sev) in SEVERITIES:
                    item[_sev(sev)] = int(cnt)
                    item["total"] += int(cnt)
            items = sorted(repos.values(), key=lambda x: (-x["critical"], -x["high"], -x["total"]))
            return {"items": items}
        return _cached("dashboard:repo-breakdown", build)

    @staticmethod
    def get_trend(db: Session, granularity: str = "day", days: int = 30) -> dict:
        def build():
            since = datetime.utcnow() - timedelta(days=days)
            day_col = func.date(SecurityAlert.detected_at)
            rows = (
                db.query(day_col, SecurityAlert.severity, func.count(SecurityAlert.id))
                .filter(SecurityAlert.detected_at >= since)
                .group_by(day_col, SecurityAlert.severity)
                .all()
            )
            buckets = defaultdict(lambda: {s: 0 for s in SEVERITIES})
            for d, sev, cnt in rows:
                d = d if isinstance(d, date) else date.fromisoformat(str(d))
                if granularity == "week":
                    d = d - timedelta(days=d.weekday())  # gom về thứ Hai
                if _sev(sev) in SEVERITIES:
                    buckets[d][_sev(sev)] += int(cnt)
            points = []
            for d in sorted(buckets):
                b = buckets[d]
                points.append({"period": d.isoformat(), **b, "total": sum(b.values())})
            return {"granularity": granularity, "points": points}
        return _cached(f"dashboard:trend:{granularity}:{days}", build)

    @staticmethod
    def export_report(
        db: Session,
        format: str = "csv",
        repo_id: Optional[int] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Tuple[bytes, str, str]:
        """
        Xuất báo cáo tổng kết tình trạng an ninh mã nguồn định dạng CSV hoặc PDF (S3-05a).
        Truy vấn dữ liệu thật: Query bảng security_alerts kết hợp repositories.
        Tuyệt đối chỉ lấy cột secret_masked để đảm bảo không lộ plaintext secret.
        """
        query = (
            db.query(
                SecurityAlert.id,
                Repository.repo_name,
                SecurityAlert.rule_name,
                SecurityAlert.severity,
                SecurityAlert.status,
                SecurityAlert.source,
                SecurityAlert.file_path,
                SecurityAlert.line_number,
                SecurityAlert.secret_masked,
                SecurityAlert.detected_at,
            )
            .outerjoin(Repository, SecurityAlert.repo_id == Repository.id)
        )

        if repo_id is not None:
            query = query.filter(SecurityAlert.repo_id == repo_id)
        if severity:
            sev_val = severity.value if hasattr(severity, "value") else str(severity)
            query = query.filter(SecurityAlert.severity == sev_val)
        if status:
            stat_val = status.value if hasattr(status, "value") else str(status)
            query = query.filter(SecurityAlert.status == stat_val)

        alerts = query.order_by(SecurityAlert.detected_at.desc(), SecurityAlert.id.desc()).all()

        if format == "csv":
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow([
                "id", "repo_name", "rule_name", "severity", "status",
                "source", "file_path", "line_number", "secret_masked", "detected_at"
            ])
            for a in alerts:
                writer.writerow([
                    a.id,
                    a.repo_name or "N/A",
                    a.rule_name or "N/A",
                    _sev(a.severity),
                    str(getattr(a.status, "value", a.status)),
                    a.source or "gitprotect_scanner",
                    a.file_path or "",
                    a.line_number if a.line_number is not None else "",
                    a.secret_masked or "",
                    a.detected_at.isoformat() if a.detected_at else "",
                ])
            return out.getvalue().encode("utf-8"), "text/csv; charset=utf-8", "gitprotect_report.csv"

        # PDF generation using ReportLab
        kpi_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in alerts:
            s = _sev(a.severity)
            if s in kpi_counts:
                kpi_counts[s] += 1

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=landscape(A4),
            leftMargin=25,
            rightMargin=25,
            topMargin=25,
            bottomMargin=25,
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#0F172A"),
            spaceAfter=4,
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#64748B"),
            spaceAfter=10,
        )
        cell_style = ParagraphStyle(
            "Cell",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#334155"),
        )
        header_cell_style = ParagraphStyle(
            "HeaderCell",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.white,
            fontName="Helvetica-Bold",
        )

        elements = [
            Paragraph("GitProtect - Báo Cáo Tổng Hợp An Ninh Mã Nguồn & Rò Rỉ Bí Mật", title_style),
            Paragraph(
                f"Thời gian kết xuất: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} • Môi trường: Staging • Chuẩn: ISO/IEC 27001 Confidential",
                subtitle_style,
            ),
        ]

        # Bảng KPI
        total_alerts = len(alerts)
        kpi_data = [
            [
                Paragraph("<b>Mức độ</b>", header_cell_style),
                Paragraph("<b>Critical</b>", header_cell_style),
                Paragraph("<b>High</b>", header_cell_style),
                Paragraph("<b>Medium</b>", header_cell_style),
                Paragraph("<b>Low</b>", header_cell_style),
                Paragraph("<b>Tổng cảnh báo</b>", header_cell_style),
            ],
            [
                Paragraph("Số lượng", cell_style),
                Paragraph(str(kpi_counts["critical"]), cell_style),
                Paragraph(str(kpi_counts["high"]), cell_style),
                Paragraph(str(kpi_counts["medium"]), cell_style),
                Paragraph(str(kpi_counts["low"]), cell_style),
                Paragraph(str(total_alerts), cell_style),
            ],
        ]
        kpi_table = Table(kpi_data, colWidths=[120, 70, 70, 70, 70, 90])
        kpi_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F8FAFC")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        elements.append(kpi_table)
        elements.append(Spacer(1, 12))

        # Bảng danh sách cảnh báo (đã che)
        table_headers = ["ID", "Repository", "Rule Name", "Severity", "Status", "Source", "File & Line", "Secret (Masked)", "Detected At"]
        col_widths = [25, 90, 120, 50, 55, 75, 145, 120, 100]
        alert_rows = [[Paragraph(f"<b>{h}</b>", header_cell_style) for h in table_headers]]

        for a in alerts:
            sev_str = _sev(a.severity).capitalize()
            status_str = str(getattr(a.status, "value", a.status))
            file_loc = f"{a.file_path}:{a.line_number}" if a.line_number is not None else (a.file_path or "")
            dt_str = a.detected_at.strftime("%Y-%m-%d %H:%M:%S") if a.detected_at else ""
            alert_rows.append([
                Paragraph(str(a.id), cell_style),
                Paragraph(a.repo_name or "N/A", cell_style),
                Paragraph(a.rule_name or "N/A", cell_style),
                Paragraph(sev_str, cell_style),
                Paragraph(status_str, cell_style),
                Paragraph(a.source or "gitprotect", cell_style),
                Paragraph(file_loc, cell_style),
                Paragraph(f"<code>{a.secret_masked or ''}</code>", cell_style),
                Paragraph(dt_str, cell_style),
            ])

        alert_table = Table(alert_rows, colWidths=col_widths, repeatRows=1)
        alert_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        elements.append(alert_table)

        doc.build(elements)
        return buf.getvalue(), "application/pdf", "gitprotect_report.pdf"
