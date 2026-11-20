"""One identity record per pushed commit, including commits without scan findings."""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CommitAuthorAudit(Base):
    __tablename__ = "commit_author_audits"

    repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), primary_key=True)
    commit_sha: Mapped[str] = mapped_column(String(40), primary_key=True)
    author_name: Mapped[str] = mapped_column(Text)
    author_email: Mapped[str] = mapped_column(Text)
    author_domain: Mapped[str] = mapped_column(String(253))
    committer_name: Mapped[str] = mapped_column(Text)
    committer_email: Mapped[str] = mapped_column(Text)
    signature_verified: Mapped[bool] = mapped_column(Boolean)
    detected_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.current_timestamp())
