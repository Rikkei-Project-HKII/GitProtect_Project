"""Tests for S3-05a: GET /api/v1/dashboard/export (CSV & PDF)."""
import csv
import io
from app.models import Repository, SecurityAlert
from test_pbi07 import services


def test_export_csv_and_pdf(services):
    client, sessions, cache, routes = services

    # Seed test repository and alerts
    with sessions.begin() as db:
        repo = db.get(Repository, 1)
        alert1 = SecurityAlert(
            id=101,
            repo_id=repo.id,
            fingerprint="fp101",
            source="gitprotect_scanner",
            rule_name="High Entropy Generic Secret Token",
            severity="critical",
            file_path="src/config.py",
            line_number=42,
            secret_masked="ghp_****1a2b",
            status="open",
        )
        alert2 = SecurityAlert(
            id=102,
            repo_id=repo.id,
            fingerprint="fp102",
            source="github_native",
            rule_name="Dependabot",
            severity="high",
            file_path="package.json",
            line_number=10,
            secret_masked="npm_****9z8y",
            status="resolved",
        )
        db.add_all([alert1, alert2])

    # 1. Test CSV export
    res_csv = client.get("/api/v1/dashboard/export?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert 'attachment; filename="gitprotect-security-report.csv"' in res_csv.headers["content-disposition"]
    csv_text = res_csv.text
    header = "id,repo_name,rule_name,severity,status,source,file_path,line_number,secret_masked,detected_at"
    assert set(header.split(",")) <= set(next(csv.reader(io.StringIO(csv_text.lstrip("\ufeff")))))
    assert "ghp_****1a2b" in csv_text
    assert "npm_****9z8y" in csv_text
    assert "never-store" not in csv_text  # Plaintext secret must never be exposed

    # 2. Test PDF export
    res_pdf = client.get("/api/v1/dashboard/export?format=pdf")
    assert res_pdf.status_code == 200
    assert "application/pdf" in res_pdf.headers["content-type"]
    assert 'attachment; filename="gitprotect-security-report.pdf"' in res_pdf.headers["content-disposition"]
    assert res_pdf.content.startswith(b"%PDF")
    assert len(res_pdf.content) > 500

    # 3. Test filtering by severity
    res_filtered = client.get("/api/v1/dashboard/export?format=csv&severity=critical")
    assert res_filtered.status_code == 200
    assert "ghp_****1a2b" in res_filtered.text
    assert "npm_****9z8y" not in res_filtered.text

    # 4. Test filtering by status
    res_status = client.get("/api/v1/dashboard/export?format=csv&status=resolved")
    assert res_status.status_code == 200
    assert "npm_****9z8y" in res_status.text
    assert "ghp_****1a2b" not in res_status.text
