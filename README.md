# GitProtect Full-Stack Platform (GP-2026-SCRUM - MVP v1.1)

Hệ thống Giám sát An toàn, Kết nối GitHub Repository & Quét Bí mật Mã nguồn Tự động.

---

## 1. Cấu Trúc Mã Nguồn

```text
GitProtect/
├── app/                        # Mã nguồn FastAPI Backend phân lớp (MOD-01 đến MOD-04)
│   ├── core/                  # Cấu hình chung, mã hóa AES-256-GCM & Enums
│   ├── modules/
│   │   ├── ingestion/         # [MOD-01] GitHub Webhook & Kết nối PAT
│   │   ├── engine/            # [MOD-02] Động cơ quét 3 lớp & Shannon Entropy
│   │   ├── alerts/            # [MOD-03] Quản lý vòng đời cảnh báo & Audit Trail (AC-01..05)
│   │   └── dashboard/         # [MOD-04] KPI Dashboard & Xuất báo cáo CSV/PDF
│   ├── api/v1.py              # Gom toàn bộ 4 phân hệ vào prefix /api/v1
│   ├── models/                # SQLAlchemy ORM models (4 bảng lõi)
│   └── db/                    # Session & Alembic metadata
├── alembic/                    # Database migrations script (MySQL 8)
├── alembic.ini                 # Cấu hình Alembic migration
├── gitprotect_frontend/        # Website Dashboard Single Page Application (React, Vite, Tailwind)
│   ├── src/                   # Components, Pages (Dashboard, Repositories, Alerts), API clients
│   ├── Dockerfile             # Multi-stage production build (Node 20 -> Nginx)
│   └── nginx.conf             # Cấu hình SPA routing try_files cho React Router
├── nginx/                      # Nginx Gateway Reverse Proxy (Môi trường Staging)
│   ├── nginx.conf             # TLS 1.2/1.3, SSL Termination, Proxy /api/ sang backend, / sang frontend
│   └── ssl/                   # Chứng chỉ số tự ký (staging.crt, staging.key)
├── tests/                      # Bộ kiểm thử tự động (82 test cases unit & integration)
├── Dockerfile                  # Dockerfile đóng gói Backend & Worker (Python 3.11-slim)
├── entrypoint.sh               # Entrypoint script tự động chờ DB và chạy alembic upgrade head
├── docker-compose.yml          # Cấu hình Docker Compose Staging full-stack 6 services
├── .env.example                # Khai báo mẫu toàn bộ biến môi trường
├── requirements.txt            # Thư viện phụ thuộc Python
└── main.py                     # Entrypoint chạy trực tiếp Backend API
```

---

## 2. Triển Khai Môi Trường Staging Bằng Docker Compose (S3-06a)

Khởi động toàn bộ 6 container (MySQL 8, Redis 7, Backend, Worker, Frontend React, Nginx Reverse Proxy TLS 1.2+) chỉ với một lệnh:

```bash
# 1. Khởi tạo file cấu hình biến môi trường
cp .env.example .env

# 2. Xây dựng và khởi chạy toàn bộ 6 services trong nền
docker compose up -d --build

# 3. Kiểm tra trạng thái hoạt động của các container
docker compose ps
```

Sau khi khởi chạy thành công:
- **Giao diện Website Dashboard:** `https://localhost` (Giao thức bảo mật HTTPS với TLS 1.2+)
- **API Swagger Documentation:** `https://localhost/docs`
- **OpenAPI JSON Schema:** `https://localhost/openapi.json`
- **API Xuất Báo cáo CSV:** `https://localhost/api/v1/dashboard/export?format=csv`
- **API Xuất Báo cáo PDF:** `https://localhost/api/v1/dashboard/export?format=pdf`

---

## 3. Khởi Chạy Local Cho Nhà Phát Triển (Local Development)

```bash
# 1. Cài đặt thư viện Python
pip install -r requirements.txt

# 2. Thiết lập Master Key AES-256 (64 hex characters)
export GITPROTECT_AES_MASTER_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
# Trên Windows PowerShell:
# $env:GITPROTECT_AES_MASTER_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# 3. Khởi động Backend API
python main.py
# Swagger trực tiếp: http://localhost:8000/docs

# 4. Khởi động Frontend
cd gitprotect_frontend
npm install
npm run dev
# Dashboard trực tiếp: http://localhost:5173
```

---

## 4. Chạy Kiểm Thử Tự Động (Automated Testing)

```bash
# Chạy toàn bộ 82 kiểm thử tự động
pytest -v
```
