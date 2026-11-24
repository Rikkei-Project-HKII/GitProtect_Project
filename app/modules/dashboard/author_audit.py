"""FR-09: GitHub's verification result and the configured author email domains."""
import re
from fastapi import HTTPException
from sqlalchemy import func, or_, select

from app.core.config import settings
from app.models import CommitAuthorAudit, Repository

NOTICE = "Email Spoofing Notice"


def allowed_domains():
    return sorted({d.strip().lower() for d in settings.ALLOWED_EMAIL_DOMAINS if d.strip()})


def email_domain(email):
    local, at, domain = email.strip().rpartition("@")
    if (not at or not local or "@" in local or any(c.isspace() for c in local)
            or len(domain) > 253 or not domain.isascii()
            or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", s)
                       for s in domain.split("."))):
        return ""
    return domain.lower()


def commit_identity(data, sha):
    """Read git header identities, not the GitHub account profile or the pusher."""
    try:
        header = data["commit"]
        verified = header["verification"]["verified"]
        if data["sha"] != sha or type(verified) is not bool:
            raise ValueError()
        identity = {"signature_verified": verified}
        for role in ("author", "committer"):
            person = header[role]
            for field in ("name", "email"):
                value = person[field]
                if not isinstance(value, str):
                    raise ValueError()
                identity[f"{role}_{field}"] = value
        return identity
    except (KeyError, ValueError, TypeError):
        raise HTTPException(502, "Incomplete or mismatched GitHub commit metadata") from None


def reasons(domain, verified, domains):
    result = []
    if domain not in domains:
        result.append("Email tác giả không thuộc domain được phép")
    if not verified:
        result.append("GitHub chưa xác minh chữ ký commit")
    return result


def record_identity(db, repo_id, sha, identity):
    # Worker already holds the repository row lock through commit.
    row = db.get(CommitAuthorAudit, (repo_id, sha))
    if row is None:
        row = CommitAuthorAudit(repo_id=repo_id, commit_sha=sha, **identity,
                                author_domain=email_domain(identity["author_email"]))
        db.add(row)
    return dict(author_name=row.author_name[:150], author_email=row.author_email[:255],
                signature_verified=row.signature_verified,
                email_spoofing_flag=bool(reasons(row.author_domain, row.signature_verified, allowed_domains())))


def report(db, repo_id, spoofing_only, page, page_size):
    if db.get(Repository, repo_id) is None:
        raise HTTPException(404, "Repository not found")
    domains = allowed_domains()
    table = CommitAuthorAudit
    query = select(table).where(table.repo_id == repo_id)
    flagged = or_(table.author_domain.not_in(domains), table.signature_verified.is_(False))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    violations = db.scalar(select(func.count()).select_from(query.where(flagged).subquery()))
    if spoofing_only:
        query = query.where(flagged)
    query = query.order_by(table.detected_at.desc(), table.commit_sha).offset((page-1)*page_size).limit(page_size)
    items = []
    for row in db.scalars(query):
        why = reasons(row.author_domain, row.signature_verified, domains)
        items.append(dict(commit_sha=row.commit_sha, author_name=row.author_name, author_email=row.author_email,
                          committer_name=row.committer_name, committer_email=row.committer_email,
                          signature_verified=row.signature_verified, email_spoofing_flag=bool(why),
                          spoofing_notice=NOTICE if why else None, reasons=why, detected_at=row.detected_at))
    return dict(repo_id=repo_id, allowed_email_domains=domains, total_commits_audited=total,
                spoofing_violations_count=violations, items=items, page=page, page_size=page_size)
