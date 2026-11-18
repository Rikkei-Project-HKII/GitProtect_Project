# GitProtect Backend Service (GP-2026-SCRUM - MVP v1.1)

Kiến trúc backend phân lớp chuẩn công nghiệp (Production Modular Architecture) phục vụ đồ án GitProtect.

## 1. Cấu trúc thư mục theo phân hệ (Modules)

```text
gitprotect_backend/
├── app/
│   ├── core/                  # Cấu hình chung, mã hóa AES-256-GCM & Enums
│   │   ├── config.py          # Biến môi trường, database, redis settings
│   │   ├── enums.py           # 7 Enums chuẩn hóa CSDL (Severity, Status, ActorType...)
│   │   └── security.py        # CryptoService AES-256-GCM kèm IV 12 bytes ngẫu nhiên
│   ├── modules/
│   │   ├── ingestion/         # [MOD-01 - TV2] Cổng GitHub Webhook & Kết nối PAT
│   │   │   ├── schemas.py     # Request/Response Pydantic schemas MOD-01
│   │   │   ├── service.py     # Webhook verification & PAT onboarding logic
│   │   │   └── router.py      # Endpoints: /webhooks/github, /repos/connect, /repos
│   │   ├── engine/            # [MOD-02 - TV3] Động cơ quét 3 lớp & Shannon Entropy
│   │   │   ├── schemas.py     # Request/Response Pydantic schemas MOD-02
│   │   │   ├── service.py     # Tính Shannon Entropy H(X) & Pipeline 3 lớp
│   │   │   └── router.py      # Endpoints: /scan/trigger, /evaluate-text, /rules...
│   │   ├── alerts/            # [MOD-03 - TV1] Quản lý vòng đời cảnh báo & Audit Trail
│   │   │   ├── schemas.py     # AlertStatusUpdateRequest (extra='forbid', note >= 10)
│   │   │   ├── service.py     # Atomic Database Transaction & Append-only history
│   │   │   └── router.py      # Endpoints: /alerts, /alerts/{id}, /status, /history
│   │   └── dashboard/         # [MOD-04 - TV4] Giám sát KPI & Kiểm toán tác giả commit
│   │       ├── schemas.py     # Dashboard metrics, trend & spoofing schemas
│   │       ├── service.py     # Tổng hợp số liệu KPI, tính điểm rủi ro Risk Score
│   │       └── router.py      # Endpoints: /dashboard/metrics, /trend, /export...
│   └── api/
│       └── v1.py              # Gom toàn bộ 4 router phân hệ vào prefix /api/v1
├── tests/                     # Thư mục unit test & integration test (AC-01..AC-05)
├── main.py                    # Khởi tạo FastAPI Application
├── requirements.txt           # Thư viện phụ thuộc
└── README.md                  # Hướng dẫn chạy & phân công
```

## 2. Hướng dẫn chạy

```bash
# Cài đặt thư viện
pip install -r requirements.txt

# Khởi chạy Backend API
python3 main.py
# Hoặc: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

- Truy cập Swagger UI trực quan: `http://localhost:8000/docs`
- Truy cập ReDoc tài liệu chi tiết: `http://localhost:8000/redoc`

### PBI-07 — Initial Scan và GitHub Native Alerts

Khởi động MySQL với migration đã áp dụng và Redis. Dùng cùng cấu hình MySQL,
Redis và khóa mã hóa PAT cho API và tiến trình worker. Từ thư mục gốc:

    python -m app.modules.engine.initial_scan

Kết nối repo với `trigger_initial_scan=true` (mặc định), hoặc gọi
`POST /api/v1/scan/trigger/{repo_id}`. Endpoint trả 202 và job_id; khi
job đang chờ/chạy, gọi lại sẽ nhận cùng ID. Theo dõi qua
`GET /api/v1/scan/jobs/{job_id}`. Redis lưu kết quả cuối 24 giờ.
Worker lấy snapshot của nhánh mặc định, duyệt các thư mục và quét blob văn bản
UTF-8 bằng bộ quy tắc PBI-06; bỏ qua binary, symlink và submodule. Nếu worker
bị dừng, worker khác có thể nhận lại job khi lease 180 giây hết hạn.

`POST /api/v1/sync/native-alerts/{repo_id}` kéo các trang Secret Scanning và
Dependabot từ GitHub. PAT cần quyền đọc Contents, Secret scanning alerts và
Dependabot alerts trên repo đã bật các tính năng tương ứng. Alert và lịch sử
system được ghi cùng transaction; lỗi từ một nguồn sẽ rollback lần đồng bộ.
