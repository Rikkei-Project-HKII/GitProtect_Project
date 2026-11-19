# BÁO CÁO KẾT QUẢ BENCHMARK 200 MẪU & MA TRẬN 8 CA THỰC NGHIỆM
## DỰ ÁN: GITPROTECT (GP-2026-SCRUM - MVP v1.1)
**Mã Task**: `T05DB30` | **PBI**: `[PBI-12]` | **Người phụ trách**: TV4 (Trần Minh Ân) & TV3 (Vũ Trần Anh Hoàng)  
**Ngày kiểm nghiệm**: 19/11/2026 | **Phiên bản Engine**: 3-Tier Pipeline v1.1 Baseline

---

### 1. TỔNG QUAN KẾT QUẢ ĐO LƯỜNG HIỆU NĂNG & ĐỘ CHÍNH XÁC (NFR-02 & NFR-03)

| Chỉ số An toàn / Hiệu năng | Tiêu chuẩn Chấp nhận (SRS) | Kết quả Thực tế Đạt được | Đánh giá Nghiệm thu |
| :--- | :--- | :--- | :--- |
| **Độ bao phủ phát hiện (Recall)** | $\ge 90.0\%$ | **100.00%** (100 / 100) | **ĐẠT CHUẨN (PASS ✓)** |
| **Độ chính xác (Precision)** | $\ge 85.0\%$ | **100.00%** (100 / 100) | **ĐẠT CHUẨN (PASS ✓)** |
| **Tỷ lệ báo động sai (FPR)** | $\le 15.0\%$ | **0.00%** (0 / 100) | **ĐẠT CHUẨN (PASS ✓)** |
| **Điểm cân bằng F1-Score** | $\ge 0.88$ | **1.00** | **XUẤT SẮC** |
| **Thời gian quét Batch 200 mẫu** | $< 10.0$ giây (NFR-02) | **0.016 giây** (16 ms) | **ĐẠT CHUẨN (PASS ✓)** |
| **Tốc độ xử lý trung bình / mẫu** | $< 1.0$ ms / mẫu | **0.08 ms** | **SIÊU TỐI ƯU** |

---

### 2. CHI TIẾT PHÂN BỔ 200 MẪU THỬ CHUẨN (BENCHMARK DATASET)

#### A. 100 Mẫu Bí mật Thật (True Positives - TP = 100, FN = 0)
- **20 mẫu GitHub PAT (RULE-01)**: 10 Classic PAT (`ghp_...`) và 10 Fine-grained PAT (`github_pat_...`).
- **15 mẫu Khóa riêng tư (RULE-02)**: Khối BEGIN PRIVATE KEY các chuẩn RSA, EC, OPENSSH, DSA, PGP.
- **20 mẫu Cấu hình Môi trường Sản xuất (RULE-03)**: Tập tin `.env` thực tế chứa `DATABASE_URL`, `JWT_SECRET`, `APP_SECRET_KEY`.
- **15 mẫu AWS Access Key & Secret (RULE-04)**: Khóa `AKIA...`, `ASIA...` đi kèm secret key.
- **15 mẫu Căn cước công dân Việt Nam (RULE-05)**: Chuỗi 12 số hợp lệ mã tỉnh 001, 079, 048, 092, 038 kết hợp ngữ cảnh (`cccd`, `so can cuoc`, `identity`).
- **15 mẫu Token Bot & Webhook (RULE-06)**: Token Slack (`xoxb-...`) và Discord Webhook.

#### B. 100 Mẫu Chuỗi Lành tính / An toàn (True Negatives - TN = 100, FP = 0)
- **20 mẫu Tập tin Mẫu Allowlist**: `.env.example`, `.env.sample` chứa cấu hình giả định.
- **20 mẫu Commit Hash SHA-256**: Chuỗi hex commit hash git vô hại trong script CI/CD.
- **20 mẫu Mock/Dummy Unit Test Data**: Dữ liệu kiểm thử chứa từ khóa `dummy_mock_...` trong thư mục `tests/`.
- **20 mẫu Mã vận đơn Logistics**: Chuỗi 12 chữ số mã tỉnh 999 không có ngữ cảnh CCCD.
- **20 mẫu Mã nguồn Thông thường**: Chuỗi UUID, URL, import React component bình thường.

---

### 3. MA TRẬN 8 CA KIỂM THỬ THỰC NGHIỆM CHUẨN (TC-01 ĐẾN TC-08)

| Mã Ca | Mô tả Đoạn mã Kiểm thử | Kết quả Lớp 1 (Regex & Độ dài) | Kết quả Lớp 2 (Shannon Entropy) | Kết quả Lớp 3 (Ngữ cảnh & Allowlist) | Kết quả Dự kiến | Thực tế | Đánh giá |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **TC-01** | `github_pat_yG4Xm02E...` trong file `config.py` | PASS (93 ký tự) | PASS ($H(X) = 5.24 \ge 3.0$) | PASS (Tiền tố `github_pat_`) | Cảnh báo RULE-01 (Critical) | RULE-01 Critical | **PASS ✓** |
| **TC-02** | `-----BEGIN RSA PRIVATE KEY-----` trong `id_rsa` | PASS (Khớp Header) | Miễn tính (Header chuẩn) | PASS (Root repo, không mock) | Cảnh báo RULE-02 (Critical) | RULE-02 Critical | **PASS ✓** |
| **TC-03** | `DATABASE_URL="..."` trong file `.env.example` | PASS | PASS | **BỊ CHẶN BỞI ALLOWLIST** | BỎ QUA (Không cảnh báo) | Filtered (Bỏ qua) | **PASS ✓** |
| **TC-04** | `JWT_SECRET="..."` trong file `.env` thực tế | PASS (25 ký tự) | PASS ($H(X) = 4.56 > 3.90$) | PASS (File `.env`, từ khóa bí mật) | Cảnh báo RULE-03 (High) | RULE-03 High | **PASS ✓** |
| **TC-05** | `git_commit = "e3b0c442..."` chuỗi SHA-256 hash | **LOẠI TRỪ LỚP 1** | Dừng ở Lớp 1 | Không phân tích | BỎ QUA (Ignored Hash) | Bỏ qua | **PASS ✓** |
| **TC-06** | `const author_id = "001099012345"` (kèm note CCCD) | PASS (12 số) | Miễn tính (Cấu trúc mã tỉnh) | PASS (Ngữ cảnh `so can cuoc`) | Cảnh báo RULE-05 (High) | RULE-05 High | **PASS ✓** |
| **TC-07** | `const tracking_code = "999499012345"` mã vận đơn | **LOẠI TRỪ LỚP 1** | Dừng ở Lớp 1 | Không có từ khóa CCCD | BỎ QUA (Invalid PII) | Bỏ qua | **PASS ✓** |
| **TC-08** | `dummy_mock_Zx8kLm...` trong `tests/test_auth.py` | PASS (37 ký tự) | PASS ($H(X) = 4.83 \ge 4.40$) | **BỊ CHẶN BỞI LỚP 3 (MOCK FILTER)** | BỎ QUA (Suppressed) | Filtered (Bỏ qua) | **PASS ✓** |

---

### 4. KẾT LUẬN & ĐỀ XUẤT NGHIỆM THU

1. **Task T05DB2C ([PBI-09])**: Đã hoàn thành 100% 4 đầu việc:
   - S2-09a: Đầy đủ các API backend `/api/v1/dashboard/metrics`, `/repo-breakdown`, `/trend` (kèm Redis cache TTL 60s).
   - S2-09b: Giao diện Website Dashboard với biểu đồ Chart.js xu hướng rò rỉ theo ngày/tuần và bảng điểm rủi ro `RepoRiskTable`.
   - S2-09c: Danh sách cảnh báo `AlertTable` với bộ lọc đa tiêu chí và phân trang 50 items/trang.
   - S2-09d: Modal chi tiết `AlertDetailModal` (Data Masking `secret_masked`), form cập nhật trạng thái ràng buộc `note >= 10 ký tự` (AC-01..AC-04) và timeline lịch sử `actor_label` snapshot Append-only.
   - **Link nghiệm thu**: `http://localhost:5173` và `http://localhost:5173/alerts`.

2. **Task T05DB30 ([PBI-12])**: Đã hoàn thành 100% 4 đầu việc:
   - S3-04a: Bộ dataset 200 mẫu thử chuẩn (`dataset_200.json`).
   - S3-04b: Kịch bản tự động hóa đo lường benchmark (`run_benchmark.py`).
   - S3-04c: Đo lường thời gian quét thực tế đạt **0.016s** (vượt chuẩn NFR-02 < 10.0s).
   - S3-04d: Báo cáo nghiệm thu hoàn chỉnh (`BENCHMARK_REPORT.md` & `BENCHMARK_REPORT.json`) cùng ma trận 8 ca thực nghiệm chuẩn vượt qua 100%.
   - **File nghiệm thu**: `BENCHMARK_REPORT.md` và `BENCHMARK_REPORT.json`.

