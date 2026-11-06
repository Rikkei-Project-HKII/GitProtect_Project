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
