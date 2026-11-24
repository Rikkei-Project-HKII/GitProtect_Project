"""MOD-04 Dashboard service (S2-09a): KPI, repo breakdown, trend + Redis cache TTL 60s."""
import json
from collections import defaultdict
from datetime import date, datetime, timedelta

import redis
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
            for item in repos.values():
                item['risk_score'] = sum(item[s] * weight for s, weight in WEIGHTS.items())
            items = sorted(repos.values(), key=lambda x: (-x['risk_score'], -x['critical'], -x['total']))
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
