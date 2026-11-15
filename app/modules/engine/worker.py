"""Consume the FIFO populated by the GitHub push webhook."""
import ast
import json
import logging
import re
import time
from contextlib import nullcontext

from app.db.session import SessionLocal
from app.modules.engine.initial_scan import redis_client as connect_redis
from app.modules.engine.scan_alerts import repository, store_alert
from app.modules.engine.scan_pipeline import ScanPipeline

QUEUE = "gitprotect:scan_queue"
ACK = """
if redis.call('LINDEX', KEYS[1], 0) == ARGV[1] then
    return redis.call('LPOP', KEYS[1])
end
"""
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def hunks(diff):
    """Yield new-side hunk text, its first line and the added line numbers."""
    path = None
    start = None
    lines, added = [], set()
    for line in diff.split("\n") + ["diff --git "]:
        match = HUNK.match(line)
        if line.startswith("diff --git ") or match:
            if start is not None and path and added:
                yield path, start, "\n".join(lines), added
            lines, added = [], set()
            start = int(match[1]) if match else None
            if not match:
                path = None
        elif start is None and line.startswith("+++ "):
            name = line[4:].split("\t", 1)[0]
            if name.startswith('"'):
                name = ast.literal_eval("b" + name).decode("utf-8", "replace")
            path = name.removeprefix("b/") if name != "/dev/null" else None
        elif start is not None and line.startswith(("+", " ")):
            if line.startswith("+"):
                added.add(start + len(lines))
            lines.append(line[1:])


class ScanQueueWorker:
    def __init__(self, redis_client=None):
        self.redis = redis_client

    def enqueue_job(self, job_payload, redis_client=None):
        with self.connection(redis_client) as cache:
            cache.rpush(QUEUE, json.dumps(job_payload))
        return job_payload["commit_sha"]

    def connection(self, cache):
        existing = cache if cache is not None else self.redis
        return nullcontext(existing) if existing is not None else connect_redis()

    def consume_once(self, redis_client=None, db=None, timeout=0):
        with self.connection(redis_client) as cache:
            deadline = time.monotonic() + timeout
            while (raw := cache.lindex(QUEUE, 0)) is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                time.sleep(min(0.1, remaining))
            job = json.loads(raw)
            with (nullcontext(db) if db is not None else SessionLocal()) as session:
                try:
                    repo = repository(session, job["repository_id"], lock=True)
                    pipeline = ScanPipeline()
                    inserted = 0
                    for path, start, content, added in hunks(job["diff"]):
                        for f in pipeline.scan(content, path)["findings"]:
                            line = start + f["line_number"] - 1
                            if line not in added:
                                continue
                            fields = dict(source="gitprotect_scanner", commit_sha=job["commit_sha"],
                                          file_path=path, line_number=line, rule_name=f["rule_name"],
                                          severity=f["severity"], secret_masked=f["secret_masked"][:255])
                            inserted += store_alert(session, repo.id, ("push", job["commit_sha"], path,
                                                    line, f["rule_code"], f["secret_masked"]), fields)
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
            # A crash before ACK replays the job. The fingerprint prevents duplicate alerts.
            cache.eval(ACK, 1, QUEUE, raw)
            return {"commit_sha": job["commit_sha"], "new_alerts": inserted}


if __name__ == "__main__":
    with connect_redis() as cache:
        worker = ScanQueueWorker(cache)
        while True:
            try:
                worker.consume_once(timeout=1)
            except Exception as exc:
                logging.error("Push job retained for retry (%s)", type(exc).__name__)
                time.sleep(2)

