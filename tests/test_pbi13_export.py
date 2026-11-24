"""T05DB33: integrated PDF reads real rows and masked data."""
import io
from pypdf import PdfReader
from test_pbi07 import services
from app.models import SecurityAlert


def test_s08a_pdf_export_endpoint(services):
    client, _, _, _ = services
    response = client.get('/api/v1/dashboard/export?format=pdf')
    assert response.status_code == 200
    assert response.headers['content-type'] == 'application/pdf'
    assert response.content.startswith(b'%PDF')
    assert len(PdfReader(io.BytesIO(response.content)).pages) == 1


def test_s08b_secret_masked_in_pdf(services):
    client, sessions, _, _ = services
    with sessions.begin() as db:
        for index, masked in enumerate(['ghp_****1a2b', 'AKIA****5E12', '0010****2345'], 1):
            db.add(SecurityAlert(id=index, repo_id=1, fingerprint=str(index)*64,
                                 rule_name='PDF fixture', severity='high', file_path='src/config.py',
                                 secret_masked=masked, status='open'))
    response = client.get('/api/v1/dashboard/export?format=pdf')
    text = '\n'.join(page.extract_text() for page in PdfReader(io.BytesIO(response.content)).pages)
    for masked in ['ghp_****1a2b', 'AKIA****5E12', '0010****2345']:
        assert masked in text
    assert 'team/repo' in text and 'organization/payment-api' not in text
