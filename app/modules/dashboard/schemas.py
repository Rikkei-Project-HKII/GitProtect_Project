"""MOD-04 Dashboard - Pydantic schemas (S2-09a)."""
from datetime import date
from typing import List, Literal, Optional
from pydantic import BaseModel


class MetricsResponse(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0
    open_total: int = 0
    risk_score: float = 0.0


class RepoBreakdownItem(BaseModel):
    repo_id: int
    repo_name: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0
    risk_score: int = 0


class RepoBreakdownResponse(BaseModel):
    items: List[RepoBreakdownItem]


class TrendPoint(BaseModel):
    period: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0


class TrendResponse(BaseModel):
    granularity: Literal["day", "week"]
    points: List[TrendPoint]
