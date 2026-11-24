import csv
import io

import pytest
from pypdf import PdfReader

from test_pbi07 import services  # shared isolated DB and Redis fixtures
from app.models import Repository, SecurityAlert
from app.modules.dashboard import exports
from app.modules.engine.service import DetectionEngineService


def test_export_is_filtered_masked_and_spreadsheet_safe(services):
    client, sessions, _, _ = services
    with sessions.begin() as db:
        db.add(Repository(id=2, github_repo_id=8, repo_name='team/other', default_branch='main',
                          access_token_encrypted='NEVER_EXPORT_CREDENTIAL', repo_url='https://github.com/team/other'))
        for i, repo, masked, severity in [(1,1,'raw_legacy_secret_DO_NOT_EXPORT','high'),
                                          (2,2,'ghp_************************abcd','critical')]:
            db.add(SecurityAlert(id=i, repo_id=repo, fingerprint=str(i)*64, rule_name='GitHub PAT',
                                 severity=severity, status='open', file_path='=HYPERLINK("bad")',
                                 line_number=i, commit_sha='a'*40, secret_masked=masked))
    csv_response = client.get('/api/v1/dashboard/export?format=csv&repo_id=1&severity=high')
    assert csv_response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(csv_response.content.decode('utf-8-sig'))))
    assert len(rows) == 1 and rows[0]['repo_name'] == 'team/repo'
    assert rows[0]['secret_masked'] == '[REDACTED]'
    assert rows[0]['file_path'].startswith("'=HYPERLINK")
    assert csv_response.headers['cache-control'] == 'no-store'
    pdf = client.get('/api/v1/dashboard/export?format=pdf')
    assert pdf.status_code == 200 and pdf.content.startswith(b'%PDF')
    text = '\n'.join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
    assert 'team/repo' in text and 'team/other' in text and '****' in text
    for secret in ['raw_legacy_secret_DO_NOT_EXPORT', 'NEVER_EXPORT_CREDENTIAL']:
        assert secret not in csv_response.text and secret not in text
    assert client.get('/api/v1/dashboard/export?format=zip').status_code == 422
    assert client.get('/api/v1/dashboard/export?repo_id=999').status_code == 404


def test_empty_export_and_row_limit(services, monkeypatch):
    client, sessions, _, _ = services
    response = client.get('/api/v1/dashboard/export?format=pdf')
    assert response.status_code == 200
    assert len(PdfReader(io.BytesIO(response.content)).pages) == 1
    with sessions.begin() as db:
        db.add(SecurityAlert(id=1, repo_id=1, fingerprint='a'*64, rule_name='Rule',
                             severity='low', status='open', file_path='src/config.py'))
    monkeypatch.setattr(exports, 'MAX_ROWS', 0)
    assert client.get('/api/v1/dashboard/export?format=csv').status_code == 413


@pytest.mark.parametrize('value', ['=1+1', ' +1', '@SUM(A1)', '\tvalue', '\rvalue', '\nvalue'])
def test_csv_formula_neutralization(value):
    assert exports.csv_cell(value).startswith("'")


def test_random_token_containing_mock_is_not_a_placeholder():
    from generate_benchmark_dataset import dataset
    sample = next(row for row in dataset() if row['id'] == 'CASE-012')
    result = DetectionEngineService.evaluate_snippet(
        sample['content'], sample['file_path'])
    assert any(f['rule_code'] == 'RULE-06' for f in result['findings'])
