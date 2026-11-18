"""Store scan findings and pull-only native alerts with system audit entries."""
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select

from app.core.config import settings
from app.models import Repository, SecurityAlert, AlertStatusHistory
from app.modules.engine.repository_api import RepositoryAPI


def now():
    return datetime.now(timezone.utc)


def repository(db, repo_id, *, lock=False):
    stmt = select(Repository).where(Repository.id == repo_id)
    repo = db.scalar(stmt.with_for_update() if lock else stmt)
    if repo is None:
        raise HTTPException(404, "Repository not found")
    return repo


def fingerprint(*parts):
    key = os.getenv("GITPROTECT_AES_MASTER_KEY") or settings.AES_MASTER_KEY_HEX
    return hmac.new(bytes.fromhex(key), json.dumps(parts).encode(), hashlib.sha256).hexdigest()


def audit(db, alert, old):
    db.add(AlertStatusHistory(alert_id=alert.id, old_status=old, new_status=alert.status,
                              actor_type="system", actor_label="system"))


def store_alert(db, repo_id, identity, fields, resolved=False):
    fp = fingerprint(repo_id, *identity)
    alert = db.scalar(select(SecurityAlert).where(SecurityAlert.repo_id == repo_id,
                                                  SecurityAlert.fingerprint == fp))
    if alert is None:
        alert = SecurityAlert(repo_id=repo_id, fingerprint=fp, **fields,
                              status="resolved" if resolved else "open",
                              resolved_at=now() if resolved else None)
        db.add(alert)
        db.flush()
        audit(db, alert, None)
        return True
    for name, value in fields.items():
        setattr(alert, name, value)
    if resolved and alert.status in ("open", "in_review"):
        old = alert.status
        alert.status, alert.resolved_at = "resolved", now()
        audit(db, alert, old)
    return False


def native_fields(kind, row):
    fields = dict(source="github_native", alert_number=row["number"])
    if kind == "secret-scanning":
        fields.update(rule_name=row.get("secret_type_display_name") or row["secret_type"],
                      severity="high", file_path="(repository)", secret_masked="****")
    else:
        vuln, advisory = row["security_vulnerability"], row["security_advisory"]
        fields.update(rule_name="Dependabot", severity=vuln["severity"],
                      file_path=row["dependency"]["manifest_path"],
                      package_name=vuln["package"]["name"],
                      cve_id=advisory.get("cve_id") or advisory.get("ghsa_id"),
                      fixed_version=(vuln.get("first_patched_version") or {}).get("identifier"))
    return fields


def sync_native(repo_id, db):
    repo = repository(db, repo_id, lock=True)
    api = RepositoryAPI.connect(repo)
    counts = {}
    inserted = 0
    try:
        for kind in ("secret-scanning", "dependabot"):
            counts[kind] = 0
            for row in api.pages(kind + "/alerts"):
                inserted += store_alert(db, repo_id, ("native", kind, row["number"]),
                                        native_fields(kind, row), row["state"] != "open")
                counts[kind] += 1
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        api.client.close()
    return dict(repo_id=repo_id, synced_secret_alerts=counts["secret-scanning"],
                synced_dependabot_alerts=counts["dependabot"], new_alerts_inserted=inserted,
                duplicates_skipped=sum(counts.values()) - inserted, synced_at=now())
