# Demo động cơ quét 3 lớp và tổng kết Sprint 2

**T05DB2D · Nhóm 7 · Người điều phối: Nguyễn Văn Hoàn · Hạn 18/11/2026**

## Chạy demo

Trên nhánh này, từ thư mục gốc, trong môi trường Python của dự án:

```powershell
python -m pip install -r requirements-test.txt
$env:GITPROTECT_AES_MASTER_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
python -m pytest -q -s tests/test_sprint2_demo.py
```

Khóa trên chỉ dùng cho phiên demo với cơ sở dữ liệu tạm. Bộ demo dùng SQLite, fakeredis có Lua và phản hồi GitHub giả lập. Cả webhook, worker quét diff, API cảnh báo, đồng bộ và transaction đều chạy mã ứng dụng. Với Redis triển khai riêng, chạy worker push bằng `python -m app.modules.engine.worker`.

| Trình tự trình diễn | Bằng chứng cần quan sát |
|---|---|
| Gửi một push có chữ ký HMAC với diff chứa hai dòng mới | Webhook xếp một commit vào hàng đợi. Worker đọc diff, chạy regex, entropy và ngữ cảnh theo quy tắc. API hiển thị một secret và một CCCD thử nghiệm, cả hai đều che giá trị và gắn đúng SHA, dòng 5 và 6. |
| Đọc thời gian và phát lại job | Dòng đầu của demo đo từ lúc gửi webhook đến lúc đọc được hai cảnh báo qua API. Ngưỡng đạt dưới 10 giây. Khi phát lại cùng job, số cảnh báo mới bằng 0. |
| Đồng bộ Dependabot | API đồng bộ trả một cảnh báo Dependabot và cơ sở dữ liệu có mã CVE của dữ liệu mẫu. |
| Chuyển cảnh báo sang resolved | API lịch sử có hai bước: system mở cảnh báo, internal_operator xử lý. Khi cố ý làm ghi lịch sử thất bại ở lần cập nhật tiếp theo, cả trạng thái và lịch sử giữ nguyên. |

**Lần chạy cục bộ ngày 15/11:** 0,258 giây từ webhook đến hai cảnh báo. Toàn bộ suite đạt 76 test và 19 subtest. Thời gian thực từ GitHub tới staging cần đo riêng vì lần chạy này giả lập mạng GitHub và Redis.

## Retrospective và backlog kiểm thử Sprint 3

Hoàn mở buổi họp bằng demo trên. Mỗi thành viên nêu một điều nên giữ và một điểm gây chậm. Nhóm đối chiếu các đề xuất bên dưới với bằng chứng rồi chốt người nhận, hạn và điều kiện nghiệm thu.

| Chủ đề thảo luận | Bằng chứng Sprint 2 | Việc đề xuất |
|---|---|---|
| Ghép các nhánh thường xuyên | [PR #4](https://github.com/Rikkei-Project-HKII/GitProtect_Project/pull/4) dựa trên nhánh detection. Webhook và vòng đời cảnh báo đã vào main qua [PR #6](https://github.com/Rikkei-Project-HKII/GitProtect_Project/pull/6) và [PR #5](https://github.com/Rikkei-Project-HKII/GitProtect_Project/pull/5). | Thống nhất nhánh tích hợp và chạy lại suite sau mỗi lần merge. |
| Đo thời gian thật | Demo cục bộ đạt ngưỡng với một commit ngắn. | Dùng repo staging được nhóm cho phép, tạo push thử, ghi timestamp giao webhook và thời điểm cảnh báo xuất hiện cho cùng SHA. |
| PBI-11 · kiểm thử AC-01 đến AC-05 | Demo đã kiểm tra rollback khi ghi audit lỗi. | Bổ sung kiểm tra cập nhật đồng thời và tính nguyên tử trên MySQL. |
| PBI-12 · benchmark 200 mẫu | Demo có một secret và một CCCD tổng hợp. | Chạy bộ mẫu đã gắn nhãn, ghi dương tính giả, âm tính giả và thời gian xử lý. |

**Ghi trong buổi họp:** thời gian và người tham dự thực tế; link minh chứng staging nếu có; quyết định của nhóm; người nhận và hạn từng việc. Các mục trên là tài liệu chuẩn bị cho buổi họp.

