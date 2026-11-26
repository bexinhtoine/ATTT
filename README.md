# Agentic SOC Platform (đồ án An toàn thông tin)

Kho Git lưu mã nguồn nền tảng. Các thư mục `BaiTap/`, `benchmarks/`, `docs/`,
`final_dataset/` và `output/` chỉ lưu cục bộ và được bỏ qua bởi `.gitignore`.
Các hướng dẫn, báo cáo và lệnh đánh giá/so sánh bên dưới tham chiếu tới những
thư mục này cần bản dữ liệu/công cụ cục bộ tương ứng; chúng không đi kèm khi clone.
Web SOC và SOC Agent có thể chạy theo hướng dẫn cài đặt bên dưới mà không cần chúng.

## Incident và đánh giá AI

Đã có menu **Hồ sơ sự cố** (`/incidents`): tạo hồ sơ từ cảnh báo, timeline bằng chứng,
phân công, ghi chú, gợi ý liên kết có xác nhận, gộp/tách và lịch sử thao tác.
Xem [hướng dẫn](docs/Incident_Va_DanhGiaAI.md).

Không cần train model hoặc có API để dùng incident và heuristic. Bộ đánh giá Investigation
so sánh heuristic, LLM một lượt và LLM dùng công cụ; chưa có API thì ghi chưa đo.
Đã bổ sung OpenAI bên cạnh Claude; xem [cấu hình và phương pháp đánh giá](benchmarks/ai_eval/README.md).

```powershell
python tools/evaluate_ai.py --arms heuristic
python tools/test_incidents.py
python tools/test_ai_evaluation.py
```

## So sánh ba nền tảng

Các màn hình nghiệp vụ có bộ chọn **Agentic SOC / Elastic Security / Wazuh /
So sánh cả 3**, giữ lựa chọn khi chuyển menu. Kết quả ngoài được đọc từ API lab
bằng `tools/sync_platform_results.py` hoặc nhập JSON qua tài khoản admin.
Xem [hướng dẫn kết quả theo nền tảng](docs/KetQua_Theo_NenTang.md) để biết phạm vi
đã kết nối và các chức năng còn cần tệp xuất; dữ liệu chưa có được ghi rõ.

Đã bổ sung bộ so sánh **Agentic SOC ↔ ELK/Elastic Security ↔ Wazuh** và menu
**So sánh 3 nền tảng** (`/comparison`). Xem [phương pháp và tiêu chí](docs/SoSanh_3_NenTang_SOC_Elastic_Wazuh.md)
và [hướng dẫn lab](benchmarks/three_way/README.md).

```powershell
python tools/compare_three.py prepare
python tools/compare_three.py run --platform all --allow-partial
python tools/test_threeway.py
```

Pilot dùng 96 episode/192 log canonical tổng hợp. Kết quả nằm trong
`benchmarks/three_way/artifacts/pilot-v1/comparison.html`. Elastic và Wazuh cần dịch vụ thực cùng
cấu hình kết nối; thiếu lab được ghi chưa đo, không sinh kết quả giả. Bài pilot chưa đánh giá
parser log thô, chất lượng AI hoặc hiệu năng toàn tuyến của ba sản phẩm.

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

Đã kiểm tra với Python 3.12.6; nên dùng Python 3.10 trở lên. `tzdata` cung cấp múi giờ trên Windows.
`anthropic` và `psutil` là tùy chọn ở thời điểm chạy. Không có khóa Claude API thì hệ thống dùng
**heuristic cục bộ**, không phải một LLM chạy trên máy.

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
python tools/test_reliability.py  # crash, partial ACK, replay, concurrency, AI/evidence, quyền, KB
python tools/test_upgrade_compatibility.py # chỉ sửa bản sao tạm của DB hiện có
python tools/run_checks.py --live # toàn bộ bộ kiểm tra, gồm HTTP thật và restart server
```

## Độ bền và bảo mật (phiên bản 1.2)

* **Snapshot bền vững:** ghi nguyên tử hàng đợi cùng checkpoint, flush/fsync trước khi gửi; nạp lại
  qua lần dừng đột ngột. Hàng đợi đầy sẽ tạm dừng đọc, không âm thầm loại sự kiện cũ. Phạm vi bảo toàn
  là dữ liệu đã ghi snapshot thành công; nguồn log vẫn cần đủ thời gian lưu trong lúc agent bị nghẽn.
* **ACK từng mục:** phân biệt accepted/duplicate/rejected/retry. Dữ liệu bị từ chối được giữ trong
  `quarantine` của snapshot; ACK lỗi hoặc thiếu sẽ giữ lô để gửi lại. Mỗi sự kiện mới có `event_uid`.
* **Khóa một tiến trình:** CLI ngăn hai agent ghi chung thư mục dữ liệu. Có thể dùng `--data-dir`
  để chạy các agent độc lập. Không xóa snapshot để khắc phục lỗi khi chưa bảo toàn dữ liệu.
* **Tác vụ bền vững:** lưu job phát hiện trong cùng giao dịch với log. Worker phát hiện và AI riêng,
  có lease, heartbeat, thử lại có giới hạn và phục hồi lease hết hạn sau restart. Trang
  **Vận hành hệ thống** (`/operations`) xem lỗi/thử lại; `/api/v1/health` cung cấp trạng thái có đăng nhập.
* **Bảo vệ quyết định analyst:** AI lưu đề xuất riêng; ưu tiên và trạng thái đã được analyst xử lý
  được giữ lại. Kết quả AI tính từ phiên bản cảnh báo cũ được đánh dấu stale trong AIRun, không áp dụng.
* **Tri thức có duyệt:** bài AI là bản nháp. Sửa/lưu bài cần đánh dấu duyệt để tác tử sử dụng;
  bài manual cũ chưa có review được giữ tương thích, bài AI cũ chưa có review không được truy xuất.
* **Bằng chứng AI:** kiểm tra tham chiếu thuộc các sự kiện đã truy xuất; lưu cutoff, mode, input state,
  pipeline version và ID đã xem. Kiểm tra ID chưa thay thế việc analyst xác minh nội dung hỗ trợ nhận định.
* **Luật:** kiểm tra điều kiện không hỗ trợ; replay match không tăng đếm trùng; sequence đối chiếu
  host/user/IP mặc định và đánh giá lại trigger khi tiền đề đến muộn. Vượt giới hạn ứng viên tạo lỗi job rõ ràng.
* **Đọc tệp log đúng:** `FileCollector` đọc theo byte offset (chế độ nhị phân), giữ lại dòng chưa ghi xong,
  nhận biết xoay vòng (rotate/truncate). Windows Event Log đọc theo thứ tự cũ → mới để không bỏ sót.
* **Cấu hình tập trung:** Web SOC gửi `interval_seconds / heartbeat_seconds / batch_size` trong phản hồi
  đăng ký và heartbeat (biến môi trường `SOC_AGENT_INTERVAL`, `SOC_AGENT_HEARTBEAT`, `SOC_AGENT_BATCH_SIZE`);
  agent áp dụng khi `config.json` có `"follow_server_config": true`.
* **Chống CSRF:** mọi form và yêu cầu POST từ trình duyệt phải kèm token (trường ẩn `_csrf_token`
  hoặc header `X-CSRF-Token`); các endpoint của agent xác thực bằng `X-API-Key` được miễn.
* **Cảnh báo cấu hình mặc định:** server ghi cảnh báo khi còn dùng `SECRET_KEY` / enrollment token demo.
  Khi triển khai thật đặt `SOC_SECRET_KEY`, `SOC_ENROLLMENT_TOKEN`, và `SOC_HTTPS=1` nếu chạy sau HTTPS.

Tái đăng ký một hostname hiện có cần API key hiện tại; nếu mất khóa, quản trị viên cấp lại ở trang agent.
Các bảng mới được tạo bổ sung khi khởi động, không yêu cầu xóa DB. Báo cáo Word hiện có mô tả phiên bản
cũ; xem [ghi chú 1.2](docs/NangCap_1_2_Va_KiemChung.md) và `docs/verification/latest.json` cho phạm vi mới.
