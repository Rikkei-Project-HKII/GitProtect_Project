"""
GitProtect MVP (v1.1 Baseline - GP-2026-SCRUM)
Task S1-01a: Alembic Migration khởi tạo 4 bảng CSDL MySQL 8 chuẩn hóa (3NF)
Phụ trách: TV1 (Huỳnh Công Danh - Product Owner & Backend/DB Lead)

Revision ID: 0001_create_v1_tables
Revises: None
Create Date: 2026-11-05 21:52:00

4 Bảng chính được khởi tạo (đã loại bỏ `users` & `user_repo_access` trong phạm vi MVP):
1. `repositories`         - Quản lý kho lưu trữ kết nối qua GitHub PAT & trạng thái quét (13 cột)
2. `scan_rules`           - Quản lý bộ 7 quy tắc phát hiện chuẩn RULE-01..RULE-07 & ngưỡng Entropy (15 cột)
3. `security_alerts`      - Lưu trữ cảnh báo rò rỉ bí mật (đã che `secret_masked`) & Dependabot (23 cột)
4. `alert_status_history` - Nhật ký kiểm toán trạng thái bất biến Append-only (AC-01..AC-05) (8 cột)
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# Revision identifiers, used by Alembic.
revision: str = "0001_create_v1_tables"
down_revision = None
branch_labels = ("0001_s1_01a_init",)
depends_on = None

MYSQL_TABLE_ARGS = {
    "mysql_engine": "InnoDB",
    "mysql_charset": "utf8mb4",
    "mysql_collate": "utf8mb4_unicode_ci",
}


def upgrade() -> None:
    # =========================================================================
    # BẢNG 1: repositories (13 cột)
    # Lưu thông tin kho lưu trữ kết nối qua GitHub PAT (mã hóa AES-256-GCM at-rest)
    # =========================================================================
    op.create_table(
        "repositories",
        sa.Column(
            "id",
            mysql.BIGINT(),
            primary_key=True,
            autoincrement=True,
            nullable=False,
            comment="Khóa chính định danh kho lưu trữ trong hệ thống nội bộ",
        ),
        sa.Column(
            "github_repo_id",
            mysql.BIGINT(),
            nullable=False,
            comment="ID kho lưu trữ gốc từ GitHub API, tránh kết nối trùng lặp",
        ),
        sa.Column(
            "repo_name",
            sa.String(255),
            nullable=False,
            comment="Tên kho lưu trữ đầy đủ (ví dụ: 'organization/backend-api')",
        ),
        sa.Column(
            "repo_url",
            sa.String(500),
            nullable=False,
            comment="Đường dẫn URL GitHub chính thức của kho lưu trữ",
        ),
        sa.Column(
            "default_branch",
            sa.String(100),
            nullable=False,
            server_default=sa.text("'main'"),
            comment="Nhánh mặc định lấy từ GitHub API ('main' làm giá trị dự phòng)",
        ),
        sa.Column(
            "access_token_encrypted",
            sa.Text(),
            nullable=False,
            comment="Personal Access Token (PAT) đã mã hóa AES-256-GCM kèm IV riêng at-rest",
        ),
        sa.Column(
            "webhook_secret_encrypted",
            sa.Text(),
            nullable=True,
            comment="Secret key xác thực chữ ký HMAC-SHA256 của Webhook đã mã hóa AES-256-GCM at-rest",
        ),
        sa.Column(
            "connection_status",
            sa.Enum("active", "error", name="enum_repo_connection_status"),
            nullable=False,
            server_default=sa.text("'active'"),
            comment="Trạng thái kết nối: 'active' (bình thường), 'error' (lỗi kết nối/token)",
        ),
        sa.Column(
            "scan_status",
            sa.Enum("pending", "running", "completed", "failed", name="enum_repo_scan_status"),
            nullable=False,
            server_default=sa.text("'pending'"),
            comment="Trạng thái tiến trình quét (FR-10): pending, running, completed, failed",
        ),
        sa.Column(
            "last_error_message",
            sa.Text(),
            nullable=True,
            comment="Ghi nhận chi tiết mã và nguyên nhân lỗi (401 Bad Token, 404 Repo Not Found, 403 Rate Limit)",
        ),
        sa.Column(
            "last_scanned_at",
            mysql.TIMESTAMP(),
            nullable=True,
            comment="Thời điểm hoàn thành lần quét mã gần đây nhất",
        ),
        sa.Column(
            "created_at",
            mysql.TIMESTAMP(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            comment="Thời điểm kho lưu trữ được kết nối vào hệ thống GitProtect",
        ),
        sa.Column(
            "updated_at",
            mysql.TIMESTAMP(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
            comment="Thời điểm cập nhật trạng thái kho lưu trữ gần nhất",
        ),
        sa.UniqueConstraint("github_repo_id", name="uk_github_repo"),
        sa.CheckConstraint(
            "repo_url LIKE 'https://github.com/%'",
            name="chk_repo_url_github_prefix",
        ),
        sa.CheckConstraint(
            "connection_status IN ('active', 'error')",
            name="chk_repo_connection_status",
        ),
        sa.CheckConstraint(
            "scan_status IN ('pending', 'running', 'completed', 'failed')",
            name="chk_repo_scan_status",
        ),
        **MYSQL_TABLE_ARGS,
    )
    op.create_index("idx_repo_name", "repositories", ["repo_name"], unique=False)
    op.create_index("idx_conn_status", "repositories", ["connection_status"], unique=False)
    op.create_index("idx_scan_status", "repositories", ["scan_status"], unique=False)
    op.create_index("idx_last_scanned", "repositories", ["last_scanned_at"], unique=False)

    # =========================================================================
    # BẢNG 2: scan_rules (15 cột)
    # Lưu bộ 7 quy tắc phát hiện chuẩn (RULE-01..RULE-07) & cấu hình Shannon Entropy
    # =========================================================================
    scan_rules_table = op.create_table(
        "scan_rules",
        sa.Column(
            "id",
            mysql.BIGINT(),
            primary_key=True,
            autoincrement=True,
            nullable=False,
            comment="Khóa chính định danh quy tắc quét bí mật trong hệ thống",
        ),
        sa.Column(
            "rule_code",
            sa.String(50),
            nullable=False,
            comment="Mã hiệu quy tắc chuẩn hóa duy nhất (ví dụ: RULE-01, RULE-05)",
        ),
        sa.Column(
            "rule_name",
            sa.String(150),
            nullable=False,
            comment="Tên định danh quy tắc phát hiện bí mật hiển thị trên giao diện",
        ),
        sa.Column(
            "description",
            sa.Text(),
            nullable=False,
            comment="Mô tả chi tiết mục tiêu nghiệp vụ, loại bí mật cần quét và cơ chế phát hiện",
        ),
        sa.Column(
            "pattern_regex",
            sa.Text(),
            nullable=False,
            comment="Biểu thức chính quy ở Lớp 1 (kiểm soát Anti-ReDoS timeout 500ms/file)",
        ),
        sa.Column(
            "charset_type",
            sa.Enum("hex", "base32", "base64", "ascii", "dynamic", "none", name="enum_rule_charset_type"),
            nullable=False,
            server_default=sa.text("'none'"),
            comment="Tập ký tự áp dụng cho Lớp 2; 'dynamic' tự nhận diện Hex -> Base32 -> Base64 -> ASCII",
        ),
        sa.Column(
            "min_entropy_threshold",
            sa.Numeric(4, 2),
            nullable=True,
            comment="Ngưỡng Shannon Entropy tối thiểu dải 20–31 ký tự (NULL nếu tra bảng động Phần A)",
        ),
        sa.Column(
            "min_entropy_threshold_long",
            sa.Numeric(4, 2),
            nullable=True,
            comment="Ngưỡng Shannon Entropy tối thiểu dải >= 32 ký tự (NULL nếu charset 'none' hoặc 'dynamic')",
        ),
        sa.Column(
            "min_length",
            mysql.INTEGER(),
            nullable=False,
            server_default=sa.text("20"),
            comment="Độ dài chuỗi tối thiểu để kích hoạt thuật toán tính toán Entropy (mặc định = 20)",
        ),
        sa.Column(
            "context_keywords",
            sa.Text(),
            nullable=True,
            comment="Danh sách từ khóa ngữ cảnh gán biến bắt buộc ở Lớp 3 (key, secret, token, password...)",
        ),
        sa.Column(
            "default_severity",
            sa.Enum("critical", "high", "medium", "low", name="enum_rule_default_severity"),
            nullable=False,
            server_default=sa.text("'medium'"),
            comment="Mức độ nghiêm trọng mặc định gán cho cảnh báo khi quy tắc được kích hoạt",
        ),
        sa.Column(
            "allowlist_patterns",
            sa.Text(),
            nullable=True,
            comment="Danh sách mẫu tệp hoặc từ khóa được loại trừ ở Lớp 3 (.env.example, sample...)",
        ),
        sa.Column(
            "is_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("1"),
            comment="Cờ bật/tắt kích hoạt quy tắc trong tiến trình quét tự động",
        ),
        sa.Column(
            "created_at",
            mysql.TIMESTAMP(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            comment="Thời điểm tạo quy tắc quét trong cơ sở dữ liệu",
        ),
        sa.Column(
            "updated_at",
            mysql.TIMESTAMP(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
            comment="Thời điểm cập nhật biểu thức regex hoặc ngưỡng entropy gần nhất",
        ),
        sa.UniqueConstraint("rule_code", name="uk_rule_code"),
        sa.CheckConstraint(
            "charset_type IN ('hex','base32','base64','ascii','dynamic','none')",
            name="chk_rule_charset_type",
        ),
        sa.CheckConstraint(
            "min_entropy_threshold IS NULL OR (min_entropy_threshold BETWEEN 0.00 AND 8.00)",
            name="chk_rule_min_entropy_short",
        ),
        sa.CheckConstraint(
            "min_entropy_threshold_long IS NULL OR (min_entropy_threshold_long BETWEEN 0.00 AND 8.00)",
            name="chk_rule_min_entropy_long",
        ),
        sa.CheckConstraint(
            "min_length >= 20",
            name="chk_rule_min_length",
        ),
        sa.CheckConstraint(
            "default_severity IN ('critical','high','medium','low')",
            name="chk_rule_default_severity",
        ),
        **MYSQL_TABLE_ARGS,
    )
    op.create_index("idx_rule_name", "scan_rules", ["rule_name"], unique=False)
    op.create_index("idx_rule_enabled", "scan_rules", ["is_enabled"], unique=False)

    # =========================================================================
    # BẢNG 3: security_alerts (23 cột)
    # Lưu trữ cảnh báo rò rỉ bí mật (chỉ lưu secret_masked) & cảnh báo Dependabot
    # =========================================================================
    op.create_table(
        "security_alerts",
        sa.Column(
            "id",
            mysql.BIGINT(),
            primary_key=True,
            autoincrement=True,
            nullable=False,
            comment="Khóa chính định danh duy nhất cho từng bản ghi cảnh báo bảo mật",
        ),
        sa.Column(
            "repo_id",
            mysql.BIGINT(),
            nullable=False,
            comment="Khóa ngoại liên kết tới kho lưu trữ xảy ra sự cố rò rỉ bí mật",
        ),
        sa.Column(
            "rule_id",
            mysql.BIGINT(),
            nullable=True,
            comment="Khóa ngoại liên kết quy tắc quét kích hoạt cảnh báo (NULL nếu từ GitHub Native)",
        ),
        sa.Column(
            "fingerprint",
            sa.CHAR(64),
            nullable=False,
            comment=(
                "Khóa chống trùng lặp HMAC-SHA256: scanner dùng HMAC(key, repo_id|file_path|secret); "
                "native dùng HMAC(key, repo_id|'native'|alert_number)"
            ),
        ),
        sa.Column(
            "alert_number",
            mysql.BIGINT(),
            nullable=True,
            comment="Mã số cảnh báo gốc từ GitHub Secret Scanning / Dependabot khi đồng bộ",
        ),
        sa.Column(
            "source",
            sa.Enum("gitprotect_scanner", "github_native", name="enum_alert_source"),
            nullable=False,
            server_default=sa.text("'gitprotect_scanner'"),
            comment="Nguồn phát hiện cảnh báo: 'gitprotect_scanner' hoặc 'github_native'",
        ),
        sa.Column(
            "package_name",
            sa.String(255),
            nullable=True,
            comment="Tên gói thư viện phụ thuộc bị phát hiện lỗ hổng (từ Dependabot Alerts)",
        ),
        sa.Column(
            "cve_id",
            sa.String(50),
            nullable=True,
            comment="Mã định danh lỗ hổng bảo mật quốc tế CVE / GHSA (từ Dependabot Alerts)",
        ),
        sa.Column(
            "fixed_version",
            sa.String(100),
            nullable=True,
            comment="Phiên bản an toàn đã khắc phục lỗ hổng được khuyến nghị nâng cấp",
        ),
        sa.Column(
            "rule_name",
            sa.String(150),
            nullable=False,
            comment="Tên định danh quy tắc phát hiện (ví dụ: 'GitHub PAT', 'Private Key')",
        ),
        sa.Column(
            "severity",
            sa.Enum("critical", "high", "medium", "low", name="enum_alert_severity"),
            nullable=False,
            server_default=sa.text("'medium'"),
            comment="4 mức độ nghiêm trọng rủi ro theo chuẩn bảo mật quốc tế",
        ),
        sa.Column(
            "file_path",
            sa.String(1000),
            nullable=False,
            comment="Đường dẫn tương đối của tập tin chứa bí mật trong repository",
        ),
        sa.Column(
            "line_number",
            mysql.INTEGER(),
            nullable=True,
            comment="Số dòng phát hiện chuỗi ký tự bí mật trong tập tin mã nguồn",
        ),
        sa.Column(
            "commit_sha",
            sa.String(40),
            nullable=True,
            comment="Mã băm SHA-1 của commit chứa rò rỉ (NULL đối với cảnh báo từ Dependabot)",
        ),
        sa.Column(
            "author_name",
            sa.String(150),
            nullable=True,
            comment="Tên tác giả thực hiện commit chứa bí mật rò rỉ",
        ),
        sa.Column(
            "author_email",
            sa.String(255),
            nullable=True,
            comment="Địa chỉ email của commit author dùng phục vụ kiểm toán tác giả",
        ),
        sa.Column(
            "signature_verified",
            sa.Boolean(),
            nullable=True,
            comment="Cờ xác thực chữ ký điện tử GPG/SSH của commit từ GitHub API",
        ),
        sa.Column(
            "email_spoofing_flag",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("0"),
            comment="Cảnh báo giả mạo email nếu commit author không thuộc tổ chức xác thực",
        ),
        sa.Column(
            "secret_masked",
            sa.String(255),
            nullable=True,
            comment="Chuỗi bí mật đã che: tiền_tố + '****' + 4_ký_tự_cuối (NULL nếu alert Dependabot)",
        ),
        sa.Column(
            "status",
            sa.Enum(
                "open",
                "in_review",
                "resolved",
                "false_positive",
                "ignored",
                name="enum_alert_status",
            ),
            nullable=False,
            server_default=sa.text("'open'"),
            comment="Vòng đời xử lý: 'open', 'in_review', 'resolved', 'false_positive', 'ignored'",
        ),
        sa.Column(
            "resolution_note",
            sa.Text(),
            nullable=True,
            comment="Ghi chú bắt buộc tối thiểu 10 ký tự khi chuyển trạng thái 'false_positive'",
        ),
        sa.Column(
            "resolved_at",
            mysql.TIMESTAMP(),
            nullable=True,
            comment="Thời điểm Internal Operator hoặc Hệ thống cập nhật giải quyết cảnh báo",
        ),
        sa.Column(
            "detected_at",
            mysql.TIMESTAMP(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            comment="Thời điểm hệ thống phát hiện sự cố rò rỉ qua Webhook hoặc Quét mã",
        ),
        sa.ForeignKeyConstraint(
            ["repo_id"],
            ["repositories.id"],
            name="fk_sa_repo",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["scan_rules.id"],
            name="fk_sa_rule",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("repo_id", "fingerprint", name="uk_repo_fp"),
        sa.CheckConstraint(
            "source IN ('gitprotect_scanner', 'github_native')",
            name="chk_sa_source",
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')",
            name="chk_sa_severity",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'in_review', 'resolved', 'false_positive', 'ignored')",
            name="chk_sa_status",
        ),
        sa.CheckConstraint(
            "status <> 'false_positive' OR (resolution_note IS NOT NULL AND CHAR_LENGTH(TRIM(resolution_note)) >= 10)",
            name="chk_sa_false_positive_note_len",
        ),
        **MYSQL_TABLE_ARGS,
    )
    op.create_index("idx_alert_number", "security_alerts", ["alert_number"], unique=False)
    op.create_index("idx_cve_id", "security_alerts", ["cve_id"], unique=False)
    op.create_index("idx_commit_sha", "security_alerts", ["commit_sha"], unique=False)
    op.create_index("idx_author_email", "security_alerts", ["author_email"], unique=False)
    op.create_index("idx_spoofing", "security_alerts", ["email_spoofing_flag"], unique=False)
    op.create_index(
        "idx_repo_sev_stat",
        "security_alerts",
        ["repo_id", "severity", "status"],
        unique=False,
    )
    op.create_index("idx_detected_at", "security_alerts", ["detected_at"], unique=False)
    # Prefix index 255 ký tự cho cột VARCHAR(1000) trên MySQL 8 utf8mb4 theo đúng thiết kế CSDL
    op.create_index(
        "idx_file_path",
        "security_alerts",
        ["file_path"],
        unique=False,
        mysql_length={"file_path": 255},
    )

    # =========================================================================
    # BẢNG 4: alert_status_history (8 cột)
    # Nhật ký kiểm toán trạng thái bất biến Append-Only (AC-01 đến AC-05)
    # =========================================================================
    op.create_table(
        "alert_status_history",
        sa.Column(
            "id",
            mysql.BIGINT(),
            primary_key=True,
            autoincrement=True,
            nullable=False,
            comment="Khóa chính định danh bản ghi nhật ký kiểm toán trạng thái cảnh báo",
        ),
        sa.Column(
            "alert_id",
            mysql.BIGINT(),
            nullable=False,
            comment="Khóa ngoại tham chiếu cảnh báo; ON DELETE RESTRICT bảo vệ toàn vẹn lịch sử",
        ),
        sa.Column(
            "old_status",
            sa.Enum(
                "open",
                "in_review",
                "resolved",
                "false_positive",
                "ignored",
                name="enum_ash_old_status",
            ),
            nullable=True,
            comment="Trạng thái trước khi chuyển đổi (NULL đối với bản ghi khởi tạo ban đầu)",
        ),
        sa.Column(
            "new_status",
            sa.Enum(
                "open",
                "in_review",
                "resolved",
                "false_positive",
                "ignored",
                name="enum_ash_new_status",
            ),
            nullable=False,
            comment="Trạng thái mới được áp dụng cho cảnh báo bảo mật",
        ),
        sa.Column(
            "actor_type",
            sa.Enum("system", "internal_operator", name="enum_ash_actor_type"),
            nullable=False,
            comment=(
                "Nguồn thực hiện hành động: 'system' (Worker/Webhook/Dependabot) hoặc "
                "'internal_operator' (UI/API nội bộ). Backend tự xác định, không nhận từ client"
            ),
        ),
        sa.Column(
            "actor_label",
            sa.String(100),
            nullable=False,
            comment="Nhãn tác nhân hiển thị lưu dạng snapshot tại thời điểm phát sinh sự kiện",
        ),
        sa.Column(
            "resolution_note",
            sa.Text(),
            nullable=True,
            comment="Lý do giải trình khi chuyển trạng thái (bắt buộc >= 10 ký tự khi 'false_positive')",
        ),
        sa.Column(
            "created_at",
            mysql.TIMESTAMP(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            comment="Thời điểm tạo bản ghi lịch sử (Bảng Append-only cấm UPDATE/DELETE)",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["security_alerts.id"],
            name="fk_ash_alert",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "old_status IS NULL OR old_status IN ('open','in_review','resolved','false_positive','ignored')",
            name="chk_ash_old_status",
        ),
        sa.CheckConstraint(
            "new_status IN ('open','in_review','resolved','false_positive','ignored')",
            name="chk_ash_new_status",
        ),
        sa.CheckConstraint(
            "actor_type IN ('system', 'internal_operator')",
            name="chk_ash_actor_type",
        ),
        sa.CheckConstraint(
            "new_status <> 'false_positive' OR (resolution_note IS NOT NULL AND CHAR_LENGTH(TRIM(resolution_note)) >= 10)",
            name="chk_ash_false_positive_note_len",
        ),
        **MYSQL_TABLE_ARGS,
    )
    op.create_index("idx_ash_alert_id", "alert_status_history", ["alert_id"], unique=False)
    op.create_index("idx_ash_actor_type", "alert_status_history", ["actor_type"], unique=False)
    op.create_index("idx_ash_created_at", "alert_status_history", ["created_at"], unique=False)

    # =========================================================================
    # RÀNG BUỘC APPEND-ONLY CẤP CƠ SỞ DỮ LIỆU (AC-05)
    # Tạo Trigger MySQL 8 chặn tuyệt đối thao tác UPDATE và DELETE trên bảng lịch sử
    # =========================================================================
    op.execute(
        """
        CREATE TRIGGER trg_ash_prevent_update
        BEFORE UPDATE ON alert_status_history
        FOR EACH ROW
        BEGIN
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'AC-05 Violation: alert_status_history is an Append-Only audit table. UPDATE is strictly prohibited.';
        END;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_ash_prevent_delete
        BEFORE DELETE ON alert_status_history
        FOR EACH ROW
        BEGIN
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'AC-05 Violation: alert_status_history is an Append-Only audit table. DELETE is strictly prohibited.';
        END;
        """
    )

    # =========================================================================
    # SEED DỮ LIỆU KHỞI TẠO: 7 QUY TẮC QUÉT CHUẨN HỆ THỐNG (RULE-01 ĐẾN RULE-07)
    # Đồng bộ 100% với trang tính 'Quy tắc quét & Entropy' (Phần C)
    # =========================================================================
    op.bulk_insert(
        scan_rules_table,
        [
            {
                "rule_code": "RULE-01",
                "rule_name": "GitHub Personal Access Token (PAT) & Fine-grained",
                "description": "Phát hiện GitHub Classic PAT (ghp_) và Fine-grained PAT (github_pat_) bị lộ trong mã nguồn.",
                "pattern_regex": r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
                "charset_type": "none",
                "min_entropy_threshold": 3.00,
                "min_entropy_threshold_long": None,
                "min_length": 20,
                "context_keywords": "github,pat,token,auth,ghp",
                "default_severity": "critical",
                "allowlist_patterns": "dummy,mock,example",
                "is_enabled": True,
            },
            {
                "rule_code": "RULE-02",
                "rule_name": "Private Keys Block (RSA, EC, OpenSSH, DSA)",
                "description": "Phát hiện khối khóa riêng tư (BEGIN PRIVATE KEY) mức Critical; tệp *.pem/*.key không có header xếp Medium.",
                "pattern_regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
                "charset_type": "none",
                "min_entropy_threshold": None,
                "min_entropy_threshold_long": None,
                "min_length": 20,
                "context_keywords": "private_key,id_rsa,id_ed25519,pem,key",
                "default_severity": "critical",
                "allowlist_patterns": "tests/mock,test_keys,dummy_key",
                "is_enabled": True,
            },
            {
                "rule_code": "RULE-03",
                "rule_name": "Production Environment Secret File & Assignments",
                "description": "Phát hiện biến môi trường nhạy cảm trong file .env thực tế; loại trừ các tệp mẫu allowlist (.env.example...).",
                "pattern_regex": r'(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|SECRET|PASSWORD|PASSWD|PWD|TOKEN|DATABASE_URL))\s*=\s*(?:"([^"\r\n]{20,})"|\'([^\'\r\n]{20,})\'|([^\s#"\']{20,}))',
                "charset_type": "dynamic",
                "min_entropy_threshold": None,
                "min_entropy_threshold_long": None,
                "min_length": 20,
                "context_keywords": "KEY,SECRET,PASSWORD,PASSWD,PWD,TOKEN,DATABASE_URL",
                "default_severity": "high",
                "allowlist_patterns": ".env.example,.env.sample,.env.template,.env.dist,.env.test",
                "is_enabled": True,
            },
            {
                "rule_code": "RULE-04",
                "rule_name": "AWS Access Key ID & Secret Access Key",
                "description": "Phát hiện khóa truy cập AWS IAM (AKIA/ASIA/A3T) đi kèm AWS Secret Access Key có Shannon Entropy cao.",
                "pattern_regex": r"\b(?:AKIA|ASIA|A3T[A-Z0-9])[0-9A-Z]{16}\b",
                "charset_type": "dynamic",
                "min_entropy_threshold": None,
                "min_entropy_threshold_long": None,
                "min_length": 20,
                "context_keywords": "aws_access_key,aws_secret,akia,asia,aws",
                "default_severity": "critical",
                "allowlist_patterns": "AKIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "is_enabled": True,
            },
            {
                "rule_code": "RULE-05",
                "rule_name": "Vietnamese Citizen ID Number (CCCD)",
                "description": "Nhận diện số Căn cước công dân Việt Nam 12 chữ số (mã tỉnh 001-096, mã thế kỷ/giới tính 0-3) kèm từ khóa ngữ cảnh.",
                "pattern_regex": r"\b0(?:0[1-9]|[1-8][0-9]|9[0-6])[0-3][0-9]{2}[0-9]{6}\b",
                "charset_type": "none",
                "min_entropy_threshold": None,
                "min_entropy_threshold_long": None,
                "min_length": 20,
                "context_keywords": "cccd,cmnd,can cuoc,identity,so can cuoc",
                "default_severity": "high",
                "allowlist_patterns": "order_number,tracking_code,phone",
                "is_enabled": True,
            },
            {
                "rule_code": "RULE-06",
                "rule_name": "Slack / Discord Bot & Webhook Token",
                "description": "Phát hiện Slack Bot Token (xoxb-) và Discord Webhook URL có phần ngẫu nhiên đạt ngưỡng Entropy >= 3.0 bits.",
                "pattern_regex": r"(?i)(xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}|https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,20}\/[a-zA-Z0-9_-]{68})",
                "charset_type": "none",
                "min_entropy_threshold": 3.00,
                "min_entropy_threshold_long": None,
                "min_length": 20,
                "context_keywords": "slack,discord,webhook,xoxb,bot_token",
                "default_severity": "high",
                "allowlist_patterns": "xoxb-00000000000,dummy,mock",
                "is_enabled": True,
            },
            {
                "rule_code": "RULE-07",
                "rule_name": "High Entropy Generic Secret Token",
                "description": "Phát hiện chuỗi bí mật ngẫu nhiên cao (Zero-day/Generic Secret) qua pipeline 3 lớp và bảng ngưỡng động Phần A.",
                "pattern_regex": r'(?i)\b[a-z0-9_]*(?:token|secret|password|passwd|pwd|api_?key|private_?key|auth)[a-z0-9_]*\s*[:=]\s*(["\'])([^"\'\s]{20,128})\1',
                "charset_type": "dynamic",
                "min_entropy_threshold": None,
                "min_entropy_threshold_long": None,
                "min_length": 20,
                "context_keywords": "token,secret,password,passwd,pwd,api_key,apikey,private_key,auth",
                "default_severity": "medium",
                "allowlist_patterns": ".env.example,.env.sample,.env.template,.env.dist,.env.test,dummy,mock",
                "is_enabled": True,
            },
        ],
    )


def downgrade() -> None:
    # Xóa Trigger bảo vệ Append-only trước khi xóa bảng
    op.execute("DROP TRIGGER IF EXISTS trg_ash_prevent_delete;")
    op.execute("DROP TRIGGER IF EXISTS trg_ash_prevent_update;")

    # Xóa 4 bảng theo thứ tự ngược lại của khóa ngoại (FK dependency order)
    op.drop_index("idx_ash_created_at", table_name="alert_status_history")
    op.drop_index("idx_ash_actor_type", table_name="alert_status_history")
    op.drop_index("idx_ash_alert_id", table_name="alert_status_history")
    op.drop_table("alert_status_history")

    op.drop_index("idx_file_path", table_name="security_alerts")
    op.drop_index("idx_detected_at", table_name="security_alerts")
    op.drop_index("idx_repo_sev_stat", table_name="security_alerts")
    op.drop_index("idx_spoofing", table_name="security_alerts")
    op.drop_index("idx_author_email", table_name="security_alerts")
    op.drop_index("idx_commit_sha", table_name="security_alerts")
    op.drop_index("idx_cve_id", table_name="security_alerts")
    op.drop_index("idx_alert_number", table_name="security_alerts")
    op.drop_table("security_alerts")

    op.drop_index("idx_rule_enabled", table_name="scan_rules")
    op.drop_index("idx_rule_name", table_name="scan_rules")
    op.drop_table("scan_rules")

    op.drop_index("idx_last_scanned", table_name="repositories")
    op.drop_index("idx_scan_status", table_name="repositories")
    op.drop_index("idx_conn_status", table_name="repositories")
    op.drop_index("idx_repo_name", table_name="repositories")
    op.drop_table("repositories")
