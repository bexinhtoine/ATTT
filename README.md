# Agentic SOC Platform (đồ án An toàn thông tin)

Hệ thống SIEM thu nhỏ kết hợp **Agentic AI**: client agent thu thập log từ máy Windows/Linux,
gửi tập trung về **Web SOC** để lưu trữ, phát hiện dựa trên luật, hiển thị dashboard, và bốn tác
tử AI (Enrichment, Triage, Investigation, Knowledge) hỗ trợ phân loại - điều tra - tích lũy tri thức.

Báo cáo chi tiết: `docs/BaoCao_Agentic_SOC_Platform.docx`.

## Cấu trúc

```
soc_server/   Web SOC (Flask + SQLite + module AI)
soc_agent/    SOC Agent (client thu thập log, chỉ dùng thư viện chuẩn Python)
tools/        demo_attack.py, test_parsers.py, sample_logs/
docs/         báo cáo Word + ảnh chụp màn hình
```

## Cài đặt

```bash
pip install -r requirements.txt
```

`anthropic` và `psutil` là tùy chọn. Không có khóa Claude API thì AI tự chạy ở **chế độ suy luận cục bộ**.

## Chạy Web SOC

```bash
cd soc_server
python run.py --port 5000
```

Mở http://127.0.0.1:5000. Tài khoản mặc định:

| Tài khoản | Mật khẩu | Vai trò |
| --- | --- | --- |
| admin | Admin@123 | Quản trị viên |
| analyst | Analyst@123 | Chuyên viên phân tích |
| viewer | Viewer@123 | Người xem |

Bật đường LLM: đặt biến môi trường `ANTHROPIC_API_KEY` trước khi khởi động.

## Cài agent trên máy trạm

```bash
cd soc_agent
# Windows (PowerShell quyền Administrator để đọc Security log):
python agent.py --server http://IP_SOC:5000 --token soc-enroll-2026 --register
python agent.py
# Linux:
sudo python3 agent.py --server http://IP_SOC:5000 --token soc-enroll-2026 --register
sudo python3 agent.py
```

Cài thành dịch vụ: `soc_agent/install/soc-agent.service` (Linux) hoặc
`soc_agent/install/install_windows_task.ps1` (Windows).

## Sinh dữ liệu trình diễn (không cần máy trạm thật)

```bash
python tools/demo_attack.py --server http://127.0.0.1:5000 --token soc-enroll-2026
```

Lệnh này đóng vai 4 máy trạm, gửi 5 kịch bản tấn công mô phỏng (dò mật khẩu SSH/RDP,
password spraying, tạo tài khoản + leo thang, xóa log, tấn công web) để kích hoạt luật và tác tử AI.

## Báo cáo và dữ liệu trình diễn

```bash
python tools/rebuild_demo.py            # tạo lại CSDL demo soc_server/instance/soc_demo.db bằng mã hiện tại (server tạm cổng 5055)
python tools/report_figures.py          # sinh hình cơ bản vào docs/figures/
python tools/report_figures_extra.py    # sinh hình bổ sung
python tools/build_report_detail.py     # docs/BaoCao_ChiTiet_NenTang_AgenticSOC.docx (≈150 trang, các phần trong tools/report_parts/)
python tools/build_report.py            # docs/BaoCao_Agentic_SOC_Platform.docx (báo cáo đồ án 3 chương)
```

## Kiểm thử

```bash
python tools/test_parsers.py      # bộ phân tích syslog / access log / Windows Event XML
python tools/test_collectors.py   # FileCollector (đọc phần mới, dòng ghi dở, xoay vòng), JournaldCollector
python tools/test_e2e.py          # toàn tuyến: đăng ký agent -> gửi log -> luật -> AI cục bộ -> web (CSDL tạm)
```

## Độ bền và bảo mật (phiên bản 1.1)

* **Agent không mất log:** hàng đợi chưa gửi được lưu ra `agent_spool.json` khi dừng agent và nạp lại
  khi khởi động; một chu kỳ lỗi không làm chết tiến trình; phản hồi không phải JSON không gây crash.
* **Đọc tệp log đúng:** `FileCollector` đọc theo byte offset (chế độ nhị phân), giữ lại dòng chưa ghi xong,
  nhận biết xoay vòng (rotate/truncate). Windows Event Log đọc theo thứ tự cũ → mới để không bỏ sót.
* **Cấu hình tập trung:** Web SOC gửi `interval_seconds / heartbeat_seconds / batch_size` trong phản hồi
  đăng ký và heartbeat (biến môi trường `SOC_AGENT_INTERVAL`, `SOC_AGENT_HEARTBEAT`, `SOC_AGENT_BATCH_SIZE`);
  agent áp dụng khi `config.json` có `"follow_server_config": true`.
* **Chống CSRF:** mọi form và yêu cầu POST từ trình duyệt phải kèm token (trường ẩn `_csrf_token`
  hoặc header `X-CSRF-Token`); các endpoint của agent xác thực bằng `X-API-Key` được miễn.
* **Cảnh báo cấu hình mặc định:** server ghi cảnh báo khi còn dùng `SECRET_KEY` / enrollment token demo.
  Khi triển khai thật đặt `SOC_SECRET_KEY`, `SOC_ENROLLMENT_TOKEN`, và `SOC_HTTPS=1` nếu chạy sau HTTPS.
