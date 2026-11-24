"""FR-09 and integration acceptance checks on the current main branch."""
import json
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.core.config import settings
from app.models import CommitAuthorAudit
from app.modules.dashboard.author_audit import commit_identity, email_domain, reasons
from app.modules.engine.regex_engine import RegexEngine
from app.modules.engine.scan_pipeline import ScanPipeline
from app.modules.engine.service import DetectionEngineService as Engine
from app.modules.engine.worker import QUEUE
from test_pbi07 import services


def identity(email, verified):
    return {"author_name": "Author", "author_email": email, "signature_verified": verified,
            "committer_name": "Committer", "committer_email": "committer@other.example"}


def scan_job(sha, author=None):
    job = {"repository_id": 1, "commit_sha": sha, "delivery_id": "fixture",
           "diff": "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+print(1)"}
    if author is not None:
        job["commit_identity"] = author
    return job


@pytest.mark.parametrize("email,verified,count", [
    ("Author@ORG.EXAMPLE", True, 0), ("a@org.example", False, 1),
    ("a@other.example", True, 1), ("a@other.example", False, 2),
    ("a@org.example.invalid", True, 1), ("a@sub.org.example", True, 1),
    ("a@@org.example", True, 1), ("", True, 1),
])
def test_domain_and_signature(email, verified, count):
    assert len(reasons(email_domain(email), verified, ["org.example"])) == count


def test_untrusted_or_missing_verification_is_not_a_signature():
    sha = "a"*40
    person = {"name": "Author", "email": "a@org.example"}
    for supplied_sha, flag in [(sha, "false"), (sha, None), ("b"*40, True)]:
        with pytest.raises(HTTPException) as exc:
            commit_identity({"sha": supplied_sha, "commit": {
                "author": person, "committer": person, "verification": {"verified": flag}}}, sha)
        assert exc.value.status_code == 502


def test_commit_without_findings_audited_once_and_repo_filtered(services, monkeypatch):
    client, sessions, redis, _ = services
    monkeypatch.setattr(settings, "ALLOWED_EMAIL_DOMAINS", [" ORG.EXAMPLE "])
    url = "/api/v1/audit/authors/1"
    assert client.get(url).json()["total_commits_audited"] == 0
    assert client.get("/api/v1/audit/authors/999").status_code == 404
    for n, author in enumerate([identity("x@org.example", True), identity("y@org.example", False),
                                identity("z@outside.example", True), None]):
        sha = f"{n:040x}"
        assert Engine.enqueue_commit_scan(scan_job(sha, author), redis) == sha
        with sessions() as db:
            result = Engine.consume_next_scan_job(redis, db)
        assert result == {"commit_sha": sha, "new_alerts": 0}
    assert redis.llen(QUEUE) == 0
    all_rows = client.get(url).json()
    assert (all_rows["total_commits_audited"], all_rows["spoofing_violations_count"]) == (3, 2)
    assert all_rows["allowed_email_domains"] == ["org.example"]
    clean = next(x for x in all_rows["items"] if x["commit_sha"] == "0"*40)
    assert clean["signature_verified"] and not clean["email_spoofing_flag"]
    for page in (1, 2):
        response = client.get(url, params={"spoofing_only": True, "page": page, "page_size": 1}).json()
        assert response["items"][0]["spoofing_notice"] == "Email Spoofing Notice"
        assert response["total_commits_audited"] == 3


def test_worker_timeout_rolls_back_records_failure_and_allows_next_job(services):
    _, sessions, redis, _ = services
    Engine.enqueue_commit_scan(scan_job("a"*40, identity("a@org.example", True)), redis)
    with sessions() as db, patch.object(ScanPipeline, "scan", side_effect=TimeoutError("SCAN_TIMEOUT")):
        result = Engine.consume_next_scan_job(redis, db)
        assert result["status"] == "failed" and result["error"] == "SCAN_TIMEOUT"
        assert not result["scan_complete"]
        assert db.scalar(select(CommitAuthorAudit)) is None
    key = "gitprotect:scan_timeout:1:" + "a"*40
    assert json.loads(redis.get(key)) == result and redis.ttl(key) > 0
    assert redis.llen(QUEUE) == 0
    Engine.enqueue_commit_scan(scan_job("b"*40), redis)
    with sessions() as db:
        assert Engine.consume_next_scan_job(redis, db) == {"commit_sha": "b"*40, "new_alerts": 0}


def test_file_budget_is_shared_between_hunks(services):
    _, sessions, redis, _ = services
    job = scan_job("e"*40)
    job["diff"] += "\n@@ -8,0 +10 @@\n+print(2)"
    Engine.enqueue_commit_scan(job, redis)
    with sessions() as db, patch("app.modules.engine.worker.perf_counter", side_effect=[0, .3, 1, 1.3]), patch.object(
        ScanPipeline, "scan", return_value={"findings": []}
    ) as scan:
        result = Engine.consume_next_scan_job(redis, db)
    assert result["error"] == "SCAN_TIMEOUT"
    assert [c.kwargs["time_budget"] for c in scan.call_args_list] == pytest.approx([.5, .2])


def test_timeout_through_http(services):
    client, *_ = services
    # Exhaust the shared deadline; keep the entire normal service/HTTP path.
    with patch("app.modules.engine.scan_pipeline.RegexEngine", return_value=RegexEngine(timeout=1e-15)):
        response = client.post("/api/v1/scan/evaluate-text", json={"content": "x", "file_path": "a.py"})
    assert response.status_code == 503
    assert response.json() == {"detail": "SCAN_TIMEOUT"}
