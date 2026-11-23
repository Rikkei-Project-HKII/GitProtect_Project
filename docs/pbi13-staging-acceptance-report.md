# Báo Cáo Nghiệm Thu & Đóng Gói Docker Compose Staging [PBI-13]
**Mã Task:** `T05DB31` | **Sprint:** 3 | **Người phụ trách:** TV1 & Cả nhóm  
**Dự án:** GitProtect - Hệ thống Giám sát An toàn, Kết nối GitHub Repository & Quét Bí mật Mã nguồn Tự động (MVP Baseline v1.1 - GP-2026-SCRUM)

---

## 1. Tổng Quan Nhiệm Vụ Hoàn Thành

Task **[PBI-13] Đóng gói Docker Compose Staging, Xuất Báo cáo & Nghiệm thu** bao gồm 4 subtask kỹ thuật chính đã được hoàn thành 100%:

| Subtask | Ký hiệu | Nội dung triển khai | Trạng thái | Commit |
| :--- | :--- | :--- | :--- | :--- |
| **S3-05a** | `T05DB31: S3-05a` | Code API thật xuất báo cáo an ninh CSV/PDF (`GET /api/v1/dashboard/export`), che `secret_masked`, gắn nút Export trên Dashboard UI | **HOÀN THÀNH** | `T05DB31: S3-05a-...` |
| **S3-06a** | `T05DB31: S3-06a` | Cấu hình Docker Compose Staging 6 services hoàn chỉnh (MySQL 8, Redis 7, Backend, Worker, Frontend React, Nginx TLS 1.2+) & `.env.example` | **HOÀN THÀNH** | `T05DB31: S3-06a-...` |
| **S3-05b** | `T05DB31: S3-05b` | Dọn sạch lỗi nhánh cũ: Xóa thư mục rác `gitprotect_backend/` (0-byte), dọn import trùng dashboard, nối `AlertList` & `AlertDetailModal` vào `AlertsPage.jsx`, thống nhất `dashboard.js` dùng `axiosClient.js` | **HOÀN THÀNH** | `T05DB31: S3-05b-...` |
| **S3-06b & S3-06c** | `T05DB31: S3-06b` | Đối chiếu 100% khớp danh mục 18 API Endpoints trên Google Sheets & Tự xác minh 5/6 tiêu chí Checklist nghiệm thu chuẩn Scrum | **HOÀN THÀNH** | `T05DB31: S3-06b-...` |

---

## 2. Chi Tiết Kỹ Thuật

### 2.1. API Xuất Báo Cáo An Ninh CSV/PDF (S3-05a)
- **Endpoint:** `GET /api/v1/dashboard/export`
- **Tham số truy vấn (Query Params):**
  - `format`: `csv` hoặc `pdf` (mặc định: `csv`)
  - `repo_id`: Lọc theo ID kho lưu trữ (tùy chọn)
  - `severity`: Lọc theo mức độ (`critical`, `high`, `medium`, `low`) (tùy chọn)
  - `status`: Lọc theo trạng thái xử lý (`open`, `in_review`, `resolved`, `false_positive`, `ignored`) (tùy chọn)
- **An toàn thông tin (Data Masking):** Tuyệt đối chỉ truy vấn và xuất cột `secret_masked` (ví dụ: `ghp_****1a2b`), không bao giờ để lộ plaintext secret trong file báo cáo hoặc log.
- **Định dạng CSV:**
  - Header: `Content-Type: text/csv; charset=utf-8`, `Content-Disposition: attachment; filename="gitprotect_report.csv"`
  - Cột dữ liệu: `id, repo_name, rule_name, severity, status, source, file_path, line_number, secret_masked, detected_at`
- **Định dạng PDF:**
  - Header: `Content-Type: application/pdf`, `Content-Disposition: attachment; filename="gitprotect_report.pdf"`
  - Sử dụng thư viện `reportlab` với layout khổ A4 nằm ngang (Landscape) chuyên nghiệp:
    - Tiêu đề báo cáo và metadata thời gian kết xuất UTC
    - Bảng thống kê KPI tổng hợp theo 4 mức: Critical, High, Medium, Low và Tổng số vi phạm
    - Bảng chi tiết toàn bộ cảnh báo an ninh đã được che chuỗi secret (`secret_masked`)
- **Dashboard UI:**
  - Đã tích hợp 2 nút thao tác **Xuất CSV** và **Xuất PDF** trực tiếp trên thanh công cụ của `DashboardPage.jsx` (`gitprotect_frontend/src/pages/DashboardPage.jsx`).

### 2.2. Đóng Gói Docker Compose Staging 6 Services (S3-06a)
Chạy full-stack chỉ với một lệnh duy nhất:
```bash
cp .env.example .env
docker compose up -d --build
```

Kiến trúc 6 container trong mạng nội bộ `gitprotect_net`:
1. `mysql` (`mysql:8.0`): Cơ sở dữ liệu quan hệ lưu 4 bảng lõi. Tích hợp Healthcheck định kỳ qua `mysqladmin ping`.
2. `redis` (`redis:7-alpine`): Caching KPI Dashboard (TTL 60s), Deduplication Webhook (`X-GitHub-Delivery`) và hàng đợi quét `gitprotect:scan_queue`. Tích hợp Healthcheck qua `redis-cli ping`.
3. `backend` (`Dockerfile` gốc): FastAPI RESTful API, phụ thuộc `mysql` & `redis` (trạng thái `healthy`). Entrypoint tự động đợi MySQL sẵn sàng và thực thi `alembic upgrade head` trước khi khởi động Uvicorn.
4. `worker` (`Dockerfile` gốc): Dùng chung image với backend, chạy tiến trình nền `python -m app.modules.engine.worker` tiêu thụ hàng đợi `gitprotect:scan_queue`.
5. `frontend` (`gitprotect_frontend/Dockerfile`): Multi-stage build (Node 20 Alpine compile Vite React -> Nginx Alpine serve static production build với cấu hình `try_files $uri $uri/ /index.html;` cho React Router).
6. `nginx` (`nginx/nginx.conf`): Cổng Gateway Reverse Proxy:
   - Cổng 80: Chuyển hướng toàn bộ (HTTP 301) sang cổng 443 HTTPS.
   - Cổng 443 SSL: Bật `ssl_protocols TLSv1.2 TLSv1.3;`, gắn kèm chứng chỉ tự ký (Self-signed Certificate) chuẩn Staging tại `nginx/ssl/staging.crt` và `nginx/ssl/staging.key`.
   - Proxy định tuyến: `/api/`, `/docs`, `/openapi.json` -> `http://backend:8000`, `/` -> `http://frontend:80`.

### 2.3. Dọn Dẹp Mã Nguồn Cũ & Khắc Phục Lỗi Ghép Nhánh (S3-05b)
- Đã xóa triệt để thư mục thừa `gitprotect_backend/` (chứa các file 0-byte do merge conflict cũ).
- Loại bỏ toàn bộ import trùng lặp trong `app/modules/dashboard/router.py` và `app/modules/dashboard/schemas.py`.
- Nối thành công component `AlertList` và `AlertDetailModal` vào `AlertsPage.jsx` (`gitprotect_frontend/src/pages/AlertsPage.jsx`), cho phép Internal Operator theo dõi và cập nhật trạng thái cảnh báo thuận tiện.
- Chuẩn hóa module `gitprotect_frontend/src/api/dashboard.js` dùng thống nhất `axiosClient.js`, tận dụng interceptor unwrap response data và bắt lỗi API tự động.

---

## 3. Đối Soát Danh Mục 18 API Endpoints (S3-06b)

Toàn bộ 18 endpoints trong mã nguồn thực tế khớp 100% với đặc tả trên Google Sheets (**Module & API**):

| STT | Phân hệ (Module) | Phương thức & Endpoint | Khớp Code Thực Tế | Chức năng chính |
| :---: | :--- | :--- | :---: | :--- |
| 1 | MOD-01 | `POST /api/v1/webhooks/github` | Đạt (100%) | Tiếp nhận push event, xác thực HMAC-SHA256, dedup qua Redis |
| 2 | MOD-01 | `POST /api/v1/repos/connect` | Đạt (100%) | Kết nối repo qua PAT, mã hóa AES-256-GCM, đăng ký webhook |
| 3 | MOD-01 | `GET /api/v1/repos` | Đạt (100%) | Liệt kê danh sách kho, connection_status, scan_status |
| 4 | MOD-02 | `POST /api/v1/scan/trigger/{repo_id}` | Đạt (100%) | Kích hoạt quét toàn diện khởi tạo (Initial Scan FR-10) |
| 5 | MOD-02 | `POST /api/v1/scan/evaluate-text` | Đạt (100%) | Tiện ích kiểm tra nhanh đoạn mã, đo Shannon Entropy |
| 6 | MOD-02 | `GET /api/v1/scan/jobs/{id}` | Đạt (100%) | Tra cứu trạng thái và % tiến độ quét thời gian thực từ Redis |
| 7 | MOD-02 | `GET /api/v1/rules` | Đạt (100%) | Lấy danh sách 7 quy tắc quét chuẩn hệ thống (RULE-01..07) |
| 8 | MOD-02 | `POST /api/v1/rules` | Đạt (COULD v2.0) | Đăng ký quy tắc quét tùy biến (mở rộng sau MVP) |
| 9 | MOD-02 | `POST /api/v1/sync/native-alerts/{repo_id}` | Đạt (100%) | Đồng bộ cảnh báo GitHub Secret Scanning & Dependabot |
| 10 | MOD-03 | `GET /api/v1/alerts` | Đạt (100%) | Truy vấn & lọc danh sách cảnh báo (repo, severity, status, source) |
| 11 | MOD-03 | `GET /api/v1/alerts/{id}` | Đạt (100%) | Xem chi tiết cảnh báo (secret_masked, commit SHA, tác giả) |
| 12 | MOD-03 | `PATCH /api/v1/alerts/{id}/status` | Đạt (100%) | Cập nhật trạng thái trong Atomic Transaction (AC-01..AC-04) |
| 13 | MOD-03 | `GET /api/v1/alerts/{id}/history` | Đạt (100%) | Truy xuất lịch sử thay đổi trạng thái append-only (AC-05) |
| 14 | MOD-04 | `GET /api/v1/dashboard/metrics` | Đạt (100%) | KPI tổng quan 4 mức độ nghiêm trọng (Redis cache 60s) |
| 15 | MOD-04 | `GET /api/v1/dashboard/repo-breakdown` | Đạt (100%) | Thống kê vi phạm theo từng repo và tính điểm rủi ro Risk Score |
| 16 | MOD-04 | `GET /api/v1/dashboard/trend` | Đạt (100%) | Chuỗi thời gian xu hướng phát hiện vi phạm theo ngày/tuần |
| 17 | MOD-04 | `GET /api/v1/audit/authors/{repo_id}` | Đạt (100%) | Kiểm toán commit author, signature_verified & Email Spoofing |
| 18 | MOD-04 | `GET /api/v1/dashboard/export` | Đạt (100%) | Xuất báo cáo tổng kết an ninh CSV/PDF (`secret_masked`) |

---

## 4. Tự Xác Minh 5/6 Tiêu Chí Nghiệm Thu Đồ Án (S3-06c)

Đối soát theo **PHẦN 5: CHECKLIST NGHIỆM THU ĐỒ ÁN** trong Google Sheets:

| Tiêu chí | Nội dung tiêu chí | Minh chứng kỹ thuật & Kết quả kiểm thử | Kết quả |
| :---: | :--- | :--- | :---: |
| **1.0** | **Kết nối GitHub Repository (PAT) & Mã hóa AES-256-GCM** | Auth/RBAC loại bỏ hợp lệ đúng phạm vi MVP nội bộ; mã hóa AES-256-GCM khóa 256-bit với IV 12 bytes ngẫu nhiên cho trường `access_token_encrypted` và `webhook_secret_encrypted`. 14 test trong `test_pbi01.py` PASS 100%. | **ĐẠT (PASS)** |
| **2.0** | **Tiếp nhận Webhook Bảo mật & Đồng bộ Dependabot** | Cơ chế chính Webhook qua xác thực HMAC-SHA256 (`X-Hub-Signature-256`); Deduplication ID (`X-GitHub-Delivery`) lưu Redis TTL 24h; Pull cảnh báo Dependabot/Secret Scanning tự gán actor `system`. 4 test trong `test_pbi02.py` và 4 test trong `test_pbi07.py` PASS 100%. | **ĐẠT (PASS)** |
| **3.0** | **Động cơ Quét 3 Lớp & 7 Quy tắc Phát hiện Chuẩn** | Pipeline lọc 3 lớp (Regex -> Shannon Entropy động -> Ngữ cảnh allowlist/CCCD); xử lý đầy đủ 7 detection rules (RULE-01..RULE-07). 4 test trong `test_regex_engine.py` và 9 test trong `test_scan_pipeline.py` PASS 100%. | **ĐẠT (PASS)** |
| **4.0** | **Quản lý Vòng đời Cảnh báo, Actor & Lịch sử Append-only (AC-01..AC-05)** | Backend tự động xác định `actor_type`/`actor_label`; Pydantic chặn client gửi actor ngoài schema; bắt buộc `resolution_note >= 10` ký tự khi false_positive; Cập nhật cảnh báo và ghi lịch sử trong cùng 1 Database Transaction; Cấm UPDATE/DELETE lịch sử. 22 test trong `test_pbi08.py` PASS 100%. | **ĐẠT (PASS)** |
| **5.0** | **Hồ sơ Tài liệu Kỹ thuật MVP Hoàn chỉnh** | Đồng bộ 100% không còn sai lệch giữa code và 5 trang tính Google Sheets (SRS 13 Yêu cầu, Module & API 18 Endpoints, CSDL 4 Bảng, Quy tắc quét & Entropy, Kế hoạch Agile & Scrum). | **ĐẠT (PASS)** |
| **6.0** | **Hiệu năng Quét & Benchmark 200 Mẫu (NFR < 10s, Recall >= 90%, Precision >= 85%)** | Đã cấu hình anti-ReDoS regex timeout 500ms; Dashboard & Export phản hồi tức thời. Tiêu chí số liệu cụ thể sẽ được TV3/TV4 tổng hợp từ kết quả chạy benchmark của task PBI-12. | **CHỜ GHÉP PBI-12** |

---

## 5. Kết Quả Kiểm Thử Toàn Diện

- **Pytest:** 82/82 tests pass 100% trong 1.6 giây:
  ```text
  tests\test_dashboard_integration.py .
  tests\test_export.py .
  tests\test_pbi01.py ..............
  tests\test_pbi02.py ....
  tests\test_pbi06_regressions.py ......................
  tests\test_pbi07.py ....
  tests\test_pbi08.py ......................
  tests\test_regex_engine.py ....
  tests\test_scan_pipeline.py .........
  tests\test_sprint2_demo.py .
  ======================= 82 passed, 8 warnings in 1.61s ========================
  ```
- **Frontend Syntax & Component Tree:** 28/28 JS/JSX files sạch lỗi cú pháp, đã liên kết `DashboardPage.jsx` (2 nút Export) và `AlertsPage.jsx` (`AlertList` + `AlertDetailModal`).
- **Đóng gói Staging:** Đầy đủ 6 containers trong `docker-compose.yml`, reverse proxy Nginx TLS 1.2+ với chứng chỉ self-signed tại `nginx/ssl/`, backend Dockerfile với entrypoint tự chạy Alembic migration.
