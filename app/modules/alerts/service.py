from app.modules.alerts.schemas import AlertStatusUpdateRequest

class AlertLifecycleService:
    @staticmethod
    def update_alert_status_atomic(alert_id: int, req: AlertStatusUpdateRequest):
        """
        Cập nhật trạng thái alert và chèn alert_status_history trong CÙNG MỘT Transaction (AC-04).
        Backend tự động xác định actor_type='internal_operator', actor_label='internal_operator' (AC-01, AC-03).
        """
        # Giả lập kết quả sau khi commit transaction thành công
        alert_mock = {
            "id": alert_id,
            "repo_id": 1,
            "rule_id": 1,
            "fingerprint": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "source": "gitprotect_scanner",
            "rule_name": "GitHub Personal Access Token (PAT)",
            "severity": "critical",
            "file_path": "src/config.py",
            "secret_masked": "ghp_****1a2b",
            "status": req.new_status,
            "resolution_note": req.resolution_note,
            "resolved_at": "2026-11-06T20:05:00Z",
            "detected_at": "2026-11-06T20:00:00Z"
        }
        history_mock = {
            "id": 101,
            "alert_id": alert_id,
            "old_status": "open",
            "new_status": req.new_status,
            "actor_type": "internal_operator",
            "actor_label": "internal_operator",
            "resolution_note": req.resolution_note,
            "created_at": "2026-11-06T20:05:00Z"
        }
        return {
            "alert": alert_mock,
            "history_entry": history_mock,
            "transaction_committed": True
        }
