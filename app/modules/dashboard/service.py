"""MOD-04 Dashboard service (S2-09a): KPI, repo breakdown, trend + Redis cache TTL 60s."""
import json
import time
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
OPEN_STATUSES = (AlertStatusEnum.OPEN.value, AlertStatusEnum.IN_REVIEW.value)
WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}

_redis = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    decode_responses=True,
    socket_connect_timeout=0.2,
    socket_timeout=0.2,
)

_mem_cache = {}
_mem_cache_time = {}


def _sev(v) -> str:
    return str(getattr(v, "value", v)).lower()


def _cached(key: str, builder):
    """Cache-aside TTL 60s; fallback in-memory nếu Redis không sẵn sàng."""
    now = time.time()
    if key in _mem_cache and (now - _mem_cache_time.get(key, 0)) < CACHE_TTL:
        return _mem_cache[key]

    try:
        hit = _redis.get(key)
        if hit:
            res = json.loads(hit)
            _mem_cache[key] = res
            _mem_cache_time[key] = now
            return res
    except Exception:
        pass

    data = builder()
    _mem_cache[key] = data
    _mem_cache_time[key] = now

    try:
        _redis.setex(key, CACHE_TTL, json.dumps(data, default=str))
    except Exception:
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
                item = repos.setdefault(repo_id, {
                    "repo_id": repo_id,
                    "repo_name": names.get(repo_id, f"repo-{repo_id}"),
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0,
                    "risk_score": 0
                })
                if _sev(sev) in SEVERITIES:
                    item[_sev(sev)] = int(cnt)
                    item["total"] += int(cnt)
            for item in repos.values():
                item["risk_score"] = sum(item[s] * WEIGHTS[s] for s in SEVERITIES)
            items = sorted(repos.values(), key=lambda x: (-x["risk_score"], -x["critical"], -x["total"]))
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
                    d = d - timedelta(days=d.weekday())
                if _sev(sev) in SEVERITIES:
                    buckets[d][_sev(sev)] += int(cnt)
            points = []
            for d in sorted(buckets):
                b = buckets[d]
                points.append({"period": d.isoformat(), **b, "total": sum(b.values())})
            return {"granularity": granularity, "points": points}
        return _cached(f"dashboard:trend:{granularity}:{days}", build)
