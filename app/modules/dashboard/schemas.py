from datetime import date, datetime
from typing import List, Literal, Optional
from pydantic import BaseModel, Field
from app.core.enums import ConnectionStatusEnum

class SeverityCountBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

class SourceCountBreakdown(BaseModel):
    gitprotect_scanner: int = 0
    github_native: int = 0

class RepositoriesSummaryBreakdown(BaseModel):
    total_repos: int = 0
    active_repos: int = 0
    error_repos: int = 0

class DashboardMetricsResponse(BaseModel):
    total_alerts: int
    open_alerts: int
    resolved_alerts: int
    severity_breakdown: SeverityCountBreakdown
    source_breakdown: SourceCountBreakdown
    repositories_summary: RepositoriesSummaryBreakdown
    cached_ttl_seconds: int = 60

class RepoRiskBreakdownItem(BaseModel):
    repo_id: int
    repo_name: str
    connection_status: ConnectionStatusEnum
    open_alerts_count: int
    severity_breakdown: SeverityCountBreakdown
    risk_score: int
    last_scanned_at: Optional[datetime] = None

class RepoBreakdownListResponse(BaseModel):
    items: List[RepoRiskBreakdownItem]
    total: int

class TrendDataPoint(BaseModel):
    date: date
    new_alerts: int
    resolved_alerts: int

class DashboardTrendResponse(BaseModel):
    period: Literal["7d", "30d"] = "7d"
    series: List[TrendDataPoint]
    cached_ttl_seconds: int = 60

class CommitAuthorAuditItem(BaseModel):
    commit_sha: str
    author_name: str
    author_email: str
    signature_verified: bool
    email_spoofing_flag: bool
    spoofing_notice: Optional[str] = None
    detected_at: datetime

class AuthorAuditResponse(BaseModel):
    repo_id: int
    allowed_email_domains: List[str]
    total_commits_audited: int
    spoofing_violations_count: int
    items: List[CommitAuthorAuditItem]
