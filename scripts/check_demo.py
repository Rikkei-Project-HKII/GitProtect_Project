"""Exercise the running disposable demo; refuses a non-demo endpoint."""
import io
import json
import time
from pathlib import Path

import httpx
from pypdf import PdfReader


def main():
    results = []
    with httpx.Client(base_url='http://127.0.0.1:8014', timeout=15, trust_env=False) as client:
        info = client.get('/api/demo/info')
        info.raise_for_status()
        assert info.json()['demo'] is True and info.headers['x-gitprotect-demo'] == 'synthetic-data'
        for case in ('valid', 'invalid', 'replay', 'spoofed'):
            r = client.post('/api/demo/webhook/' + case)
            r.raise_for_status()
            result = r.json()
            assert result['http_status'] == (401 if case == 'invalid' else 200)
            if case != 'invalid':
                assert result['alerts_created'] == 1
            if case == 'replay':
                assert result['redelivery']['response']['status'] == 'duplicate_ignored'
            if case == 'spoofed':
                report = client.get('/api/v1/audit/authors/1?spoofing_only=true').json()
                assert any(row['commit_sha'] == result['commit_sha'] for row in report['items'])
            results.append({'check': 'webhook_' + case, 'passed': True, 'local_ms': result['elapsed_ms']})

        connected = client.post('/api/demo/connect')
        connected.raise_for_status()
        repo_id = connected.json()['id']
        response = client.post('/api/v1/scan/trigger/' + str(repo_id))
        response.raise_for_status()
        job_id = response.json()['job_id']
        for _ in range(100):
            job = client.get('/api/v1/scan/jobs/' + job_id).json()
            if job['scan_status'] in ('completed', 'failed'):
                break
            time.sleep(.1)
        assert job['scan_status'] == 'completed' and job['progress_pct'] == 100
        results.append({'check': 'connect_and_initial_scan', 'passed': True, 'files': job['scanned_files']})

        first = client.post('/api/v1/sync/native-alerts/' + str(repo_id)).json()
        repeat = client.post('/api/v1/sync/native-alerts/' + str(repo_id)).json()
        assert first['new_alerts_inserted'] == 2 and repeat['duplicates_skipped'] == 2
        results.append({'check': 'native_sync_dedup', 'passed': True})

        alerts = client.get('/api/v1/alerts', params={'repo_id': repo_id}).json()['items']
        alert_id = alerts[0]['id']
        route = '/api/v1/alerts/' + str(alert_id)
        assert client.patch(route + '/status', json={'new_status': 'false_positive', 'resolution_note': 'short'}).status_code == 422
        assert client.patch(route + '/status', json={'new_status': 'in_review', 'actor': 'spoofed'}).status_code == 422
        changed = client.patch(route + '/status', json={'new_status': 'in_review', 'resolution_note': 'Demo automated verification'})
        changed.raise_for_status()
        history = client.get(route + '/history').json()['items']
        assert any(row['new_status'] == 'in_review' and row['actor_label'] == 'internal_operator' for row in history)
        results.append({'check': 'status_validation_and_audit', 'passed': True})

        output = Path(__file__).resolve().parents[1] / 'output' / 'demo'
        output.mkdir(parents=True, exist_ok=True)
        for fmt in ('csv', 'pdf'):
            response = client.get('/api/v1/dashboard/export', params={'format': fmt})
            response.raise_for_status()
            text = (response.content.decode('utf-8-sig') if fmt == 'csv' else
                    '\n'.join(p.extract_text() for p in PdfReader(io.BytesIO(response.content)).pages))
            assert '****' in text and 'NEVER_EXPORT_THIS_RAW_VALUE' not in text
            assert 'demo-local-token-not-a-github-credential' not in text
            (output / ('gitprotect-demo-report.' + fmt)).write_bytes(response.content)
            results.append({'check': 'masked_export_' + fmt, 'passed': True})
        assert client.get('/api/demo/info').json()['worker_error'] is None
        (output / 'checks.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
