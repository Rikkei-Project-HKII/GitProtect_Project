from datetime import datetime
from typing import List, Literal, Optional
from pydantic import BaseModel, Extra, Field
from app.core.enums import ConnectionStatusEnum, ScanStatusEnum, ActorTypeEnum

class StrictBase(BaseModel):
    class Config:
        extra = Extra.forbid

class RepoConnectRequest(StrictBase):
    repo_url: str = Field(..., max_length=500, regex=r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")
    github_pat: str = Field(..., min_length=20)
    webhook_secret: Optional[str] = Field(default=None, min_length=16)
    trigger_initial_scan: bool = Field(default=True)

class RepositoryResponse(BaseModel):
    id: int
    github_repo_id: int
    repo_name: str
    repo_url: str
    default_branch: str
    connection_status: ConnectionStatusEnum
    scan_status: ScanStatusEnum
    last_error_message: Optional[str] = None
    last_scanned_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class RepositoryListResponse(BaseModel):
    items: List[RepositoryResponse]
    total: int
    page: int = 1
    page_size: int = 20

class GitHubCommitAuthor(BaseModel):
    name: str
    email: str
    username: Optional[str] = None

class GitHubCommitItem(BaseModel):
    id: str
    message: str
    timestamp: Optional[datetime] = None
    author: GitHubCommitAuthor
    added: List[str] = []
    modified: List[str] = []
    removed: List[str] = []

class GitHubRepoSub(BaseModel):
    id: int
    full_name: str
    html_url: str
    default_branch: Optional[str] = "main"

class GitHubWebhookPushPayload(BaseModel):
    ref: str
    after: str
    repository: GitHubRepoSub
    commits: List[GitHubCommitItem] = []

class WebhookAckResponse(BaseModel):
    status: Literal["queued", "duplicate_ignored", "ping_ok"]
    delivery_id: str
    queued_commits_count: int = 0
    actor_type: ActorTypeEnum = ActorTypeEnum.SYSTEM
    actor_label: str = "system"
