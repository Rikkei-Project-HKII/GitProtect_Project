class DashboardService:
    @staticmethod
    def get_kpi_metrics(repo_id=None):
        return {
            "total_alerts": 28,
            "open_alerts": 15,
            "resolved_alerts": 13,
            "severity_breakdown": {"critical": 3, "high": 8, "medium": 12, "low": 5},
            "source_breakdown": {"gitprotect_scanner": 21, "github_native": 7},
            "repositories_summary": {"total_repos": 4, "active_repos": 3, "error_repos": 1},
            "cached_ttl_seconds": 60
        }
