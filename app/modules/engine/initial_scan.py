"""Initial scan queue. Run the worker with python -m app.modules.engine.initial_scan."""
import json
import time
from uuid import uuid4

from fastapi import HTTPException
from redis import Redis

from app.core.config import settings
from app.db.session import SessionLocal
from app.modules.engine.repository_api import RepositoryAPI
from app.modules.engine.scan_alerts import now, repository, store_alert
from app.modules.engine.scan_pipeline import ScanPipeline

QUEUE = "scan:initial:queue"
LEASE = 180
RETENTION = 86400

# A queue member stays durable until completion. Its score is its next claim time.
ENQUEUE = """
local existing = redis.call('GET', KEYS[3])
if existing then return existing end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('SET', KEYS[3], ARGV[1])
redis.call('ZADD', KEYS[2], 0, ARGV[1])
return ARGV[1]
"""
CLAIM = """
local now = tonumber(redis.call('TIME')[1])
local job = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now, 'LIMIT', 0, 1)[1]
if not job then return false end
redis.call('ZADD', KEYS[1], now + tonumber(ARGV[2]), job)
redis.call('SET', 'scan:lease:' .. job, ARGV[1], 'EX', ARGV[2])
return job
"""
UPDATE = """
if redis.call('GET', KEYS[3]) ~= ARGV[2] then return 0 end
if ARGV[4] == 'finished' then
    redis.call('SET', KEYS[2], ARGV[3], 'EX', ARGV[6])
    redis.call('ZREM', KEYS[1], ARGV[1])
    redis.call('DEL', KEYS[3], KEYS[4])
else
    redis.call('SET', KEYS[2], ARGV[3])
    redis.call('EXPIRE', KEYS[3], ARGV[5])
    redis.call('ZADD', KEYS[1], tonumber(redis.call('TIME')[1]) + tonumber(ARGV[5]), ARGV[1])
end
return 1
"""


def redis_client():
    return Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, decode_responses=True,
                 socket_connect_timeout=3, socket_timeout=5)


def status(redis, job_id):
    data = redis.get("scan:job:" + job_id)
    if data is None:
        raise HTTPException(404, "Scan job not found")
    return json.loads(data)


def enqueue(repo, redis):
    job_id = uuid4().hex
    job = dict(job_id=job_id, repo_id=repo.id, default_branch=repo.default_branch,
               scan_status="pending", started_at=now().isoformat(), progress_pct=0,
               scanned_files=0, total_files=0, alerts_detected=0)
    actual = redis.eval(ENQUEUE, 3, "scan:job:" + job_id, QUEUE, f"scan:active:{repo.id}",
                        job_id, json.dumps(job))
    return {**status(redis, actual), "redis_key": "scan:job:" + actual}


def enqueue_connected(repo):
    with redis_client() as redis:
        return enqueue(repo, redis)


class LeaseLost(Exception):
    pass


def publish(redis, job, token, finished=False):
    jid = job["job_id"]
    if not redis.eval(UPDATE, 4, QUEUE, "scan:job:" + jid, "scan:lease:" + jid,
                      f"scan:active:{job['repo_id']}", jid, token, json.dumps(job),
                      "finished" if finished else "running", LEASE, RETENTION):
        raise LeaseLost()


def run_job(redis, job, token, db):
    repo_id = job["repo_id"]
    repo = repository(db, repo_id, lock=True)
    job.update(scan_status="running", scanned_files=0, alerts_detected=0, progress_pct=0)
    publish(redis, job, token)
    repo.scan_status = "running"
    db.commit()
    api = RepositoryAPI.connect(repo)
    try:
        sha, files = api.snapshot(job["default_branch"], lambda: publish(redis, job, token))
        job.update(total_files=len(files), commit_sha=sha)
        pipeline = ScanPipeline()
        for index, (path, blob) in enumerate(files, 1):
            publish(redis, job, token)
            content = api.read_text(blob)
            if content is not None:
                for finding in pipeline.scan(content, path)["findings"]:
                    line = finding["line_number"]
                    store_alert(db, repo_id, ("scan", path, blob, line, finding["rule_code"], finding["secret_masked"]),
                                dict(source="gitprotect_scanner", commit_sha=sha, file_path=path,
                                     line_number=line, rule_name=finding["rule_name"],
                                     severity=finding["severity"], secret_masked=finding["secret_masked"][:255]))
                    job["alerts_detected"] += 1
            job.update(scanned_files=index, progress_pct=min(99, index * 100 // len(files)))
            publish(redis, job, token)
        repo = repository(db, repo_id, lock=True)
        publish(redis, job, token)
        repo.scan_status, repo.last_scanned_at = "completed", now()
        db.commit()
        job.update(scan_status="completed", progress_pct=100, finished_at=now().isoformat())
        publish(redis, job, token, finished=True)
    finally:
        api.client.close()


def consume(redis):
    token = uuid4().hex
    job_id = redis.eval(CLAIM, 1, QUEUE, token, LEASE)
    if not job_id:
        return False
    job = status(redis, job_id)
    with SessionLocal() as db:
        try:
            run_job(redis, job, token, db)
        except LeaseLost:
            db.rollback()
        except Exception as exc:
            db.rollback()
            repo = repository(db, job["repo_id"], lock=True)
            publish(redis, job, token)
            repo.scan_status = "failed"
            db.commit()
            job.update(scan_status="failed", finished_at=now().isoformat(),
                       error_message=f"Initial scan failed ({type(exc).__name__})")
            publish(redis, job, token, finished=True)
    return True


if __name__ == "__main__":
    with redis_client() as connection:
        while True:
            if not consume(connection):
                time.sleep(1)
