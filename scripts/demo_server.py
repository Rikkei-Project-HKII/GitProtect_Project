"""Isolated local demo. Real app/services; synthetic GitHub, SQLite and fakeredis Lua.

Run with: python scripts/demo_server.py
Never imported by the production application. No outbound GitHub mutations.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import tempfile
import threading
import time
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Separate process and ephemeral key/database; do not read a deployment .env.
os.environ['PYTHON_DOTENV_DISABLED'] = '1'
os.environ['GITPROTECT_AES_MASTER_KEY'] = secrets.token_hex(32)
TEMP = tempfile.TemporaryDirectory(prefix='gitprotect-demo-')
os.environ['DATABASE_URL'] = 'sqlite:///' + (Path(TEMP.name) / 'demo.db').as_posix()
os.environ['GITHUB_WEBHOOK_CALLBACK_URL'] = 'https://demo.invalid/api/v1/webhooks/github'
os.environ['ALLOWED_EMAIL_DOMAINS'] = 'gitprotect.example'

import fakeredis
import fakeredis.aioredis
import httpx
import uvicorn
from fastapi import HTTPException
from sqlalchemy import event, select
from sqlalchemy.schema import CreateTable

from app.main import app
from app.db.session import engine, SessionLocal
from app.models import Base, Repository, SecurityAlert
from app.core.security import crypto_service
from app.modules.engine import initial_scan, worker
from app.modules.engine.repository_api import RepositoryAPI
from app.modules.engine.scan_pipeline import ScanPipeline
from app.modules.engine.scan_alerts import store_alert
from app.modules.ingestion import service as ingestion, webhook
from app.modules.dashboard import service as dashboard
from app.modules.dashboard.author_audit import record_identity

DEMO_PAT = 'demo-local-token-not-a-github-credential'
DEMO_SECRET = 'demo-local-webhook-secret-only'
SERVER = fakeredis.FakeServer()
COMMIT_DATA = {}
STOP = threading.Event()
WORKER_THREAD = None
WORKER_ERROR = None
from generate_benchmark_dataset import dataset
SAMPLES = dataset()
FILES = {f['file_path']: f['content'] for f in SAMPLES[:7]}
FILES['src/settings.py'] = 'api_key="aB9xK2pQ7zM4nP8qR5wX6hJ3tY0vL1sE"'
FILES['.env.example'] = 'JWT_SECRET="aB9xK2pQ7zM4nP8qR5wX6hJ3tY0vL1sE"'


def cache(*args, **kwargs):
    return fakeredis.FakeRedis(server=SERVER, decode_responses=True)


@event.listens_for(engine, 'connect')
def sqlite_setup(connection, _):
    connection.create_function('CHAR_LENGTH', 1, lambda value: len(value) if value is not None else None)
    connection.execute('PRAGMA foreign_keys=ON')
    connection.execute('PRAGMA busy_timeout=10000')


with engine.begin() as connection:
    for table in Base.metadata.sorted_tables:
        connection.exec_driver_sql(str(CreateTable(table).compile(engine)).replace(' ON UPDATE CURRENT_TIMESTAMP', ''))


def repo_metadata(owner, name):
    if owner.lower() != 'gitprotect-demo':
        raise HTTPException(422, 'Demo chỉ nhận repo GitProtect-Demo. Không dùng PAT thật ở đây.')
    return dict(id=zlib.crc32(f'{owner.lower()}/{name.lower()}'.encode()), full_name=f'{owner}/{name}',
                default_branch='main', html_url=f'https://github.com/{owner}/{name}')


class DemoGitHubClient:
    def __init__(self, token, client=None):
        if token != DEMO_PAT:
            raise HTTPException(401, 'Dùng nút Kết nối repo mẫu hoặc token demo-local-token-not-a-github-credential.')

    async def repository(self, owner, name):
        return repo_metadata(owner, name)

    async def create_webhook(self, owner, name, callback, secret):
        return {'id': repo_metadata(owner, name)['id']}

    async def delete_webhook(self, *args):
        return None

    async def request(self, method, path, headers=None):
        sha = path.rsplit('/', 1)[-1]
        if sha not in COMMIT_DATA:
            raise HTTPException(404, 'Unknown demo commit')
        record = COMMIT_DATA[sha]
        if headers and headers.get('Accept') == 'application/vnd.github.diff':
            return record['diff']
        return record['metadata']


def github_fixture(request):
    # RepositoryAPI still parses GitHub tree/blob/native responses normally.
    tail = '/'.join(request.url.path.split('/')[4:])
    if tail == 'commits/main':
        data = {'sha': 'a'*40, 'commit': {'tree': {'sha': 'root'}}}
    elif tail == 'git/trees/root':
        data = {'tree': [dict(path=path, type='blob', mode='100644', sha=f'blob-{i}')
                         for i, path in enumerate(FILES)]}
    elif tail.startswith('git/blobs/blob-'):
        time.sleep(.04)
        content = list(FILES.values())[int(tail.rsplit('-', 1)[-1])]
        data = {'encoding': 'base64', 'content': base64.b64encode(content.encode()).decode()}
    elif tail == 'secret-scanning/alerts':
        data = [dict(number=1, state='open', secret_type='synthetic_token',
                     secret_type_display_name='GitHub Secret Scanning (demo)', secret='NEVER_EXPORT_THIS_RAW_VALUE')]
    elif tail == 'dependabot/alerts':
        data = [dict(number=1, state='open', dependency={'manifest_path': 'package.json'},
                     security_advisory={'cve_id': 'DEMO-ADVISORY-001'},
                     security_vulnerability={'severity': 'low', 'package': {'name': 'demo-package'},
                                             'first_patched_version': {'identifier': '2.0.0'}})]
    else:
        return httpx.Response(404, json={'message': 'Unknown demo resource'})
    return httpx.Response(200, json=data)


def repository_api(repo):
    return RepositoryAPI(httpx.Client(base_url='https://api.github.com',
                                     transport=httpx.MockTransport(github_fixture)), repo.repo_name)


ingestion.GitHubClient = webhook.GitHubClient = DemoGitHubClient
RepositoryAPI.connect = staticmethod(repository_api)
webhook.Redis = lambda *a, **k: fakeredis.aioredis.FakeRedis(server=SERVER, decode_responses=True)
initial_scan.redis_client = worker.connect_redis = cache
dashboard._redis = cache()


def clear_dashboard():
    connection = cache()
    keys = list(connection.scan_iter('dashboard:*'))
    if keys:
        connection.delete(*keys)


def seed():
    with SessionLocal.begin() as db:
        for i, name in enumerate(['payment-api', 'customer-web', 'infra-config'], 1):
            meta = repo_metadata('GitProtect-Demo', name)
            repo = Repository(id=i, github_repo_id=meta['id'], repo_name=meta['full_name'],
                              repo_url=meta['html_url'], default_branch='main', connection_status='active',
                              scan_status='completed', last_scanned_at=datetime.now(timezone.utc),
                              access_token_encrypted=crypto_service.encrypt(DEMO_PAT),
                              webhook_secret_encrypted=crypto_service.encrypt(DEMO_SECRET))
            db.add(repo)
            db.flush()
            for n, (path, content) in enumerate(FILES.items()):
                for f in ScanPipeline().scan(content, path)['findings']:
                    fields = dict(source='gitprotect_scanner', rule_name=f['rule_name'], severity=f['severity'],
                                  file_path=path, line_number=f['line_number'], secret_masked=f['secret_masked'],
                                  commit_sha=str(i)*40, detected_at=datetime.now(timezone.utc)-timedelta(days=n+i))
                    store_alert(db, i, ('seed', path, f['rule_code']), fields, resolved=(n % 4 == 0))
            for n, email in enumerate(['hoan@gitprotect.example', 'contributor@external.example']):
                identity = dict(author_name='Demo contributor', author_email=email,
                                committer_name='Demo contributor', committer_email=email, signature_verified=n == 0)
                record_identity(db, i, str(i+n+4)*40, identity)


def consume():
    global WORKER_ERROR
    connection = cache()
    while not STOP.wait(.15):
        try:
            initial = initial_scan.consume(connection)
            pushed = worker.ScanQueueWorker(connection).consume_once()
            if initial or pushed:
                clear_dashboard()
            WORKER_ERROR = None
        except Exception as exc:
            WORKER_ERROR = type(exc).__name__
            logging.exception('Demo worker failure')
            STOP.wait(1)


@app.middleware('http')
async def demo_response(request, call_next):
    response = await call_next(request)
    response.headers['X-GitProtect-Demo'] = 'synthetic-data'
    if request.method in ('POST', 'PATCH') and response.status_code < 400:
        clear_dashboard()
    return response


@app.get('/api/demo/info', tags=['Local demo only'])
def info():
    return dict(demo=True, storage='Temporary SQLite + fakeredis Lua', github='Synthetic fixtures; no GitHub mutations',
                worker_error=WORKER_ERROR, data_resets_on_restart=True,
                excluded=['Production TLS/MySQL/Redis deployment', 'RBAC/Auth excluded from MVP', 'Custom rule creation v2.0'])


@app.get('/api/demo/samples', tags=['Local demo only'])
def samples():
    labels = ['GitHub PAT', 'Private key', 'Secret trong .env', 'AWS key pair', 'CCCD', 'Slack token', 'Generic secret']
    examples = []
    for i, label in enumerate(labels, 1):
        row = next(row for row in SAMPLES if row['rule'] == f'RULE-{i:02d}')
        examples.append(dict(label=label, path=row['file_path'], content=row['content']))
    examples.append(dict(label='Allowlist .env.example', path='.env.example', content=examples[2]['content']))
    return examples


@app.post('/api/demo/connect', tags=['Local demo only'])
async def connect():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://demo') as client:
        response = await client.post('/api/v1/repos/connect', json=dict(
            repo_url='https://github.com/GitProtect-Demo/presentation-'+uuid4().hex[:6], github_pat=DEMO_PAT,
            webhook_secret=DEMO_SECRET, trigger_initial_scan=True))
    if response.status_code != 201:
        raise HTTPException(response.status_code, response.json())
    return response.json()


@app.post('/api/demo/webhook/{scenario}', tags=['Local demo only'])
async def demonstrate_webhook(scenario: str):
    if scenario not in ('valid', 'invalid', 'replay', 'spoofed'):
        raise HTTPException(404, 'Unknown scenario')
    sha = hashlib.sha1(uuid4().bytes, usedforsecurity=False).hexdigest()
    email = 'unknown@external.example' if scenario == 'spoofed' else 'hoan@gitprotect.example'
    person = {'name': 'Demo contributor', 'email': email}
    COMMIT_DATA[sha] = dict(metadata={'sha': sha, 'commit': {'author': person, 'committer': person,
                            'verification': {'verified': scenario != 'spoofed'}}},
                           diff='diff --git a/src/demo.py b/src/demo.py\n--- a/src/demo.py\n+++ b/src/demo.py\n@@ -0,0 +1 @@\n+'
                           + FILES['src/config.py'] + '\n')
    with SessionLocal() as db:
        repo = db.get(Repository, 1)
        body = json.dumps({'repository': {'id': repo.github_repo_id}, 'ref': 'refs/heads/main',
                           'commits': [{'id': sha}]}).encode()
    signature = hmac.new(DEMO_SECRET.encode(), body, hashlib.sha256).hexdigest()
    headers = {'X-Hub-Signature-256': 'sha256=' + ('0'*64 if scenario == 'invalid' else signature),
               'X-GitHub-Delivery': uuid4().hex, 'X-GitHub-Event': 'push', 'Content-Type': 'application/json'}
    started = time.perf_counter()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://demo') as client:
        response = await client.post('/api/v1/webhooks/github', content=body, headers=headers)
        result = dict(scenario=scenario, http_status=response.status_code, response=response.json(), commit_sha=sha)
        if scenario == 'replay':
            repeated = await client.post('/api/v1/webhooks/github', content=body, headers=headers)
            result['redelivery'] = dict(http_status=repeated.status_code, response=repeated.json())
    if response.status_code == 200:
        for _ in range(60):
            with SessionLocal() as db:
                count = len(db.scalars(select(SecurityAlert).where(SecurityAlert.commit_sha == sha)).all())
            if count:
                break
            await asyncio.sleep(.05)
        result['alerts_created'] = count
    result['elapsed_ms'] = round((time.perf_counter()-started)*1000, 1)
    result['scope'] = 'Local pipeline using synthetic GitHub data; not live staging latency'
    return result


@app.on_event('startup')
def start_demo():
    global WORKER_THREAD
    seed()
    WORKER_THREAD = threading.Thread(target=consume, daemon=True)
    WORKER_THREAD.start()


@app.on_event('shutdown')
def stop_demo():
    STOP.set()
    if WORKER_THREAD:
        WORKER_THREAD.join(timeout=5)
    engine.dispose()


if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=8014)
