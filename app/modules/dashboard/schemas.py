from datetime import date, datetime
from typing import List, Literal, Optional
from pydantic import BaseModel


class CommitAuthorAuditItem(BaseModel):
    commit_sha: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    reasons: List[str]
    signature_verified: bool
    email_spoofing_flag: bool
    spoofing_notice: Optional[str] = None
    detected_at: datetime


class AuthorAuditResponse(BaseModel):
    repo_id: int
    allowed_email_domains: List[str]
    page: int
    page_size: int
    total_commits_audited: int
    spoofing_violations_count: int
    items: List[CommitAuthorAuditItem]


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
    period: date
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0


class TrendResponse(BaseModel):
    granularity: Literal["day", "week"]
    points: List[TrendPoint]
