# Demo GitProtect MVP

Trang trình diễn: http://127.0.0.1:5174/demo

Demo sử dụng API, engine, xác thực HMAC, worker và transaction của ứng dụng. GitHub được mô phỏng bằng fixture; SQLite tạm thay MySQL và fakeredis chạy Lua thay Redis. Không có thao tác gửi tới GitHub, không cần PAT thật. Dữ liệu và khóa mã hóa mới được tạo mỗi lần khởi động.

## Kịch bản trình bày 8–10 phút

| Bước | Thao tác | Kết quả cần quan sát |
|---|---|---|
| 1 | Dashboard | KPI theo severity, xu hướng ngày/tuần, điểm rủi ro từng kho |
| 2 | Demo chức năng → Kết nối repo mẫu | Repo mới được lưu, initial scan tự vào queue. Xem trong Kho lưu trữ |
| 3 | Chọn kho → Quét toàn bộ kho | Tiến độ về completed/100%, cảnh báo mới được lưu. Quét lại không nhân đôi cùng finding |
| 4 | Thử lần lượt 7 mẫu → Quét đoạn mã | Đúng rule/severity, entropy và secret đã mask. Mẫu .env.example bị allowlist |
| 5 | Push hợp lệ; Chữ ký giả; Gửi lại cùng delivery | Lần lượt queued/có alert; HTTP 401; duplicate_ignored/không thêm job |
| 6 | Tác giả đáng ngờ → Dashboard → chọn payment-api | Email ngoài miền và chữ ký chưa xác minh xuất hiện trong báo cáo tác giả |
| 7 | Đồng bộ cảnh báo GitHub hai lần | Secret Scanning + Dependabot xuất hiện. Lần hai duplicates_skipped = 2 |
| 8 | Cảnh báo → Chi tiết → In Review/Resolved | Lưu trạng thái và lịch sử system/internal_operator. False positive từ chối note dưới 10 ký tự |
| 9 | Tải CSV; Tải PDF | CSV UTF-8, PDF nhiều kho có biểu đồ, dữ liệu bí mật chỉ hiển thị dạng masked |

## Khởi động trên Windows

Yêu cầu Python 3.11+ và Node.js 20+. Từ thư mục gốc repository, cài một lần:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-test.txt
cd gitprotect_frontend
npm ci
cd ..
```

Terminal 1:

```powershell
.\.venv\Scripts\python.exe scripts/demo_server.py
```

Terminal 2:

```powershell
cd gitprotect_frontend
$env:VITE_DEMO_MODE='true'
$env:VITE_PROXY_TARGET='http://127.0.0.1:8014'
node node_modules/vite/bin/vite.js --host 127.0.0.1 --port 5174 --strictPort
```

Mở trang trình diễn. API docs: http://127.0.0.1:8014/docs. Dừng bằng Ctrl+C ở hai terminal. Giữ cả hai tiến trình chạy khi trình bày. Không mở cổng demo ra Internet.

## Phạm vi và phần chưa chứng minh

- Không có đăng nhập/RBAC theo phạm vi MVP. POST /rules là bản phác thảo v2.0, không phải chức năng lưu rule hoàn chỉnh.
- Demo không xác nhận kết nối PAT/webhook GitHub thật, TLS, migration MySQL hay Redis bền vững trên staging.
- Độ trễ hiển thị là đo local với fixture, không dùng làm bằng chứng SLA GitHub → staging.
- Task tuần còn cần deployment staging thực tế, hồ sơ 5 tab/Google Sheets, báo cáo nộp LMS, release v1.1-mvp và buổi retrospective. Có demo chạy không đồng nghĩa tất cả điều kiện nghiệm thu đã hoàn thành.
