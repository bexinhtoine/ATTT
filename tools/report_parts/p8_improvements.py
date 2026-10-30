# -*- coding: utf-8 -*-
"""PHẦN 8. CÁC CẢI TIẾN MÃ NGUỒN ĐÃ THỰC HIỆN (phiên bản 1.1) - mở rộng với trích mã trước/sau."""
from report_lib import *  # noqa: F401,F403

P = "8"


def build():
    h1("PHẦN 8. CÁC CẢI TIẾN MÃ NGUỒN ĐÃ THỰC HIỆN (PHIÊN BẢN 1.1)")
    para("Trong quá trình rà soát mã nguồn để viết báo cáo, các vấn đề sau được phát hiện và sửa. Mỗi mục ghi rõ tệp, vấn đề, cách sửa, trích mã trước/sau và cách kiểm chứng. "
         "Phương pháp rà soát: đọc toàn bộ mã (≈ 6.600 dòng), đối chiếu với tài liệu Python/Flask/Claude API, chạy thử từng thành phần, rồi viết kiểm thử tự động cho các lỗi tìm được để tránh tái diễn.")
    table(["#", "Tệp", "Vấn đề", "Mức", "Cách sửa", "Kiểm chứng"], [
        ["1", "soc_agent/collectors.py (FileCollector)", "Gọi `f.tell()` trong `for line in f` ở chế độ văn bản gây OSError → collector luôn trả rỗng, **không thu được tệp log Linux nào**", "Nghiêm trọng", "Đọc nhị phân bằng `readline()`, giữ lại dòng ghi dở, xử lý xoay vòng", "tools/test_collectors.py (đọc mới, dòng dở, truncate) - đạt"],
        ["2", "soc_agent/collectors.py (WindowsEventLogCollector)", "Đọc mới → cũ (`/rd:true`) với giới hạn 800: khi có > 800 sự kiện mới sẽ bỏ sót phần cũ; lần đầu đọc tới 800 bản ghi chỉ để lấy mốc", "Trung bình", "Lần đầu lấy 1 bản ghi mới nhất; chu kỳ sau đọc cũ → mới (`/rd:false`) để phân trang tự nhiên", "Kiểm tra logic; cần chạy trên Windows với quyền admin để xác nhận thực tế"],
        ["3", "soc_agent/agent.py", "Dừng agent làm mất hàng đợi chưa gửi; phản hồi không phải JSON làm crash; một ngoại lệ bất kỳ làm chết vòng lặp; bỏ qua `config` server gửi", "Cao", "Spool `agent_spool.json` + nạp lại; bắt lỗi JSON; try/except quanh mỗi chu kỳ; `follow_server_config`", "Chạy thử --once; e2e kiểm tra config trả về"],
        ["4", "soc_server/app/enrichment.py", "Python xếp dải IP tài liệu RFC 5737 (203.0.113.x...) là private → trong demo mọi IP tấn công bị coi là nội bộ: không cộng điểm \"IP công cộng\", IOC rỗng, luật R21 (src_ip_public) không kích hoạt", "Cao (với demo)", "Tách `DOCUMENTATION_NETS` và xem như public", "tools/test_e2e.py bước 7: iocs.ips = [203.0.113.66]; demo mới có R21"],
        ["5", "soc_server/app/__init__.py, templates, soc.js", "Không có chống CSRF: trang web độc hại có thể ép trình duyệt đã đăng nhập đổi trạng thái cảnh báo, xóa luật, tạo người dùng", "Cao (bảo mật)", "Token CSRF gắn phiên; trường ẩn trong 15 form POST; header X-CSRF-Token cho fetch; miễn cho endpoint agent", "e2e bước 5 và 7: POST thiếu token → 403, có token → OK"],
        ["6", "soc_server/app/api.py, views.py", "`int()` trên tham số người dùng (agent_id, limit, offset, rule_id, assigned_to) gây lỗi 500", "Thấp", "Hàm `_int()` an toàn, kiểm tra isdigit", "e2e bước 6: /logs?agent_id=abc và /api/v1/events?limit=xyz trả 200"],
        ["7", "soc_server/config.py, __init__.py", "SECRET_KEY và enrollment token mặc định dùng âm thầm; cookie không có cờ Secure; cấu hình agent cố định trong mã", "Trung bình", "Cảnh báo khi khởi động; `SESSION_COOKIE_SECURE` qua SOC_HTTPS=1; `CSRF_ENABLED`; AGENT_* cho cấu hình tập trung", "Nhật ký khởi động"],
        ["8", "soc_server/app/ai/llm.py, auth.py", "Gọi Claude không có timeout (luồng nền có thể treo 10 phút); dict `_failed_attempts` tăng vô hạn", "Thấp", "timeout 180 s, max_retries 2; dọn các mục hết hạn khóa khi > 5000", "Đọc mã"],
        ["9", "tools/demo_attack.py", "Sự kiện mô phỏng thiếu extra.group → tiêu đề cảnh báo R04 hiện \"nhóm đặc quyền ?\"", "Thấp", "Bổ sung group = Administrators / sudo", "rebuild_demo: tiêu đề đúng"],
        ["10", "tools/", "Thiếu kiểm thử toàn tuyến và kiểm thử collector; không có cách tái tạo dữ liệu demo bằng mã mới", "-", "Thêm test_collectors.py, test_e2e.py (9 bước, CSDL tạm), rebuild_demo.py; cập nhật README", "Cả ba bộ kiểm thử đạt"],
    ], widths=[0.3, 1.2, 1.8, 0.6, 1.5, 1.1], size=8.5, caption="Tổng hợp các cải tiến", part=P)

    h2("8.1. Lỗi FileCollector không đọc được tệp log")
    para("Ở chế độ văn bản, Python không cho phép gọi `tell()` trong khi đang lặp bằng iterator của tệp (ngoại lệ *OSError: telling position disabled by next() call*). Vì khối `try/except OSError` bao quanh toàn bộ vòng đọc, ngoại lệ bị nuốt và hàm trả về danh sách rỗng - nghĩa là trên Linux **không có dòng auth.log nào được gửi**, dù agent vẫn báo \"chạy bình thường\". Đây là loại lỗi nguy hiểm vì im lặng.")
    code("# TRƯỚC (rút gọn)\nwith open(self.path, \"r\", encoding=\"utf-8\", errors=\"replace\") as f:\n    f.seek(offset)\n    for line in f:                       # iterator văn bản\n        if not line.endswith(\"\\n\") and f.tell() == size:   # <- OSError tại đây\n            break\n        ...\n\n# SAU\nwith open(self.path, \"rb\") as f:         # nhị phân\n    f.seek(offset)\n    while lines_read < self.max_lines:\n        pos = f.tell(); raw = f.readline()\n        if not raw: break\n        if not raw.endswith(b\"\\n\"): f.seek(pos); break        # dòng ghi dở\n        ev = parsers.parse_line(raw.decode(\"utf-8\", \"replace\"), ...)", size=9)
    para("Kiểm thử `test_collectors.py` tái hiện bốn tình huống (lần đầu, thêm dòng, dòng ghi dở, truncate) và đã đạt. Bài học: không bao giờ bọc một vòng xử lý lớn trong `except` nuốt lỗi; mọi collector nên có kiểm thử với tệp tạm.")

    h2("8.2. Thứ tự đọc Windows Event Log")
    para("Với `/rd:true` (mới nhất trước) và `/c:800`, khi có 1.000 sự kiện mới, agent lấy 800 sự kiện mới nhất, ghi `last_record` = ID lớn nhất, và 200 sự kiện cũ hơn không bao giờ được lấy. Sửa: đọc `/rd:false` (cũ → mới) để các chu kỳ sau tiếp tục từ `last_record`; lần đầu chỉ cần một bản ghi mới nhất để ghi mốc.")
    code("# TRƯỚC: xpath có EventRecordID>N, /rd:true, /c:800  -> lấy 800 mới nhất, bỏ phần giữa\n# SAU\nif not last_record:\n    xml = self._query(\"*\", 1, newest_first=True)             # chỉ lấy mốc\n    ...; return []\nxpath = \"*[System[%sEventRecordID>%d]]\" % (id_filter + \" and \" if id_filter else \"\", last_record)\nxml = self._query(xpath, self.max_events, newest_first=False)   # cũ -> mới, phân trang tự nhiên", size=9)

    h2("8.3. Độ bền của agent")
    bullets([
        "**Spool khi dừng:** `_save_spool()` ghi `{saved_at, hostname, events[]}` vào agent_spool.json trong khối `finally`; `_load_spool()` nạp lại và xóa tệp khi khởi động. Trước đây dừng dịch vụ khi server đang bảo trì làm mất toàn bộ hàng đợi.",
        "**Vòng lặp không chết:** mỗi chu kỳ bọc `try/except Exception` ghi log và tiếp tục; chỉ KeyboardInterrupt mới dừng.",
        "**Phản hồi không phải JSON:** `_request()` trả `(status, text)` thay vì ném ValueError.",
        "**Cấu hình tập trung:** `_apply_server_config()` áp dụng interval/heartbeat/batch từ phản hồi register và heartbeat khi `follow_server_config = true`; server lấy giá trị từ `AGENT_INTERVAL_SECONDS`, `AGENT_HEARTBEAT_SECONDS`, `AGENT_BATCH_SIZE` (biến môi trường SOC_AGENT_*).",
    ])

    h2("8.4. Phân loại địa chỉ IP tài liệu")
    para("`ipaddress.ip_address(\"203.0.113.66\").is_private` trả về True trong Python 3.12 vì các dải RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) nằm trong danh sách địa chỉ không định tuyến toàn cầu. "
         "Dữ liệu trình diễn dùng đúng các dải này để đóng vai Internet, nên toàn bộ chỉ dấu \"IP công cộng\" không được cộng điểm, IOC IP rỗng và luật R21 (`src_ip_public`) không bao giờ kích hoạt. "
         "Sửa: `classify_ip()` kiểm tra `DOCUMENTATION_NETS` trước `is_private` và xếp vào loại public. Trong triển khai thật các dải này không xuất hiện nên không ảnh hưởng; trong lab, hành vi mới đúng với ý đồ.")
    code("DOCUMENTATION_NETS = [ipaddress.ip_network(n) for n in (\"192.0.2.0/24\", \"198.51.100.0/24\", \"203.0.113.0/24\", \"2001:db8::/32\")]\n...\nelif any(addr in net for net in DOCUMENTATION_NETS):\n    t = \"public\"                      # dải tài liệu: xem như địa chỉ ngoài Internet\nelif addr.is_private:\n    t = \"private\"", size=9)
    para("Kết quả: sau khi tạo lại dữ liệu demo, cảnh báo R21 \"Đăng nhập RDP từ Internet\" xuất hiện (19 cảnh báo thay vì 18), Investigation trích IOC ips = [203.0.113.66], và Triage cộng +15 cho IP công cộng.")

    h2("8.5. Chống CSRF")
    para("Ứng dụng dùng cookie phiên để xác thực nên mọi form POST (đổi trạng thái cảnh báo, xóa luật, tạo người dùng, cấp lại khóa agent...) đều có thể bị **Cross-Site Request Forgery**: một trang web khác chứa form ẩn tự gửi tới Web SOC sẽ mang theo cookie của analyst đang đăng nhập. "
         "SameSite=Lax chỉ chặn một phần (không chặn điều hướng GET, và một số trình duyệt cũ bỏ qua). Giải pháp chuẩn OWASP là **synchronizer token**: token ngẫu nhiên gắn phiên, nhúng vào form, so sánh phía server.")
    numbered([
        "`_register_csrf(app)`: hàm Jinja `csrf_token()` sinh/lấy token trong session; `csrf_field()` trả trường ẩn; `before_request` kiểm tra mọi POST/PUT/PATCH/DELETE trừ ba endpoint của agent (xác thực bằng API key, không có phiên).",
        "15 form POST trong 11 template được chèn `{{ csrf_field() }}` tự động bằng script regex; base.html thêm `<meta name=\"csrf-token\">`; `soc.js` gửi header `X-CSRF-Token` trong `postJSON()`.",
        "Khi đăng nhập thành công, `session.clear()` sinh token mới (chống session fixation) - kiểm thử xác nhận token trước và sau đăng nhập khác nhau.",
        "Có thể tắt bằng `CSRF_ENABLED = False` cho kiểm thử API thuần.",
    ])

    h2("8.6. Kiểm tra đầu vào và cấu hình an toàn")
    bullets([
        "`api._int()` thay cho `int()` trực tiếp trên tham số truy vấn; `views.alerts` chỉ lọc rule_id khi `isdigit()`; `alert_update` bỏ qua assigned_to không hợp lệ. Trước đây `/logs?agent_id=abc` trả lỗi 500 và ghi traceback.",
        "`config.py` tách `DEFAULT_SECRET_KEY`, `DEFAULT_ENROLLMENT_TOKEN`; `_warn_insecure_defaults()` ghi cảnh báo khi còn dùng giá trị mặc định; `SESSION_COOKIE_SECURE` theo `SOC_HTTPS`.",
        "`llm.py`: `anthropic.Anthropic(api_key, timeout=180.0, max_retries=2)` - luồng AI nền không treo quá 3 phút × 3 lần khi mạng lỗi; `auth.py` dọn bộ nhớ đếm đăng nhập sai.",
    ])

    h2("8.7. Kiểm thử tự động")
    table(["Bộ kiểm thử", "Phạm vi", "Kết quả"], [
        ["tools/test_parsers.py", "12 dòng syslog/access log + 2 sự kiện Windows XML: action, user, IP, severity, timestamp", "14/14 mẫu đúng"],
        ["tools/test_collectors.py", "FileCollector: lần đầu, đọc mới, dòng ghi dở, truncate; JournaldCollector: chuẩn hóa JSON", "Đạt"],
        ["tools/test_e2e.py", "Flask test client + CSDL tạm: đăng ký (403/201), gửi 10 sự kiện → 4 cảnh báo, gửi lại → 10 trùng, heartbeat, đăng nhập + CSRF (403 thiếu token, token đổi sau đăng nhập), dashboard/stats/log/CSV, tham số sai không gây 500, Triage + Investigation cục bộ (true_positive P1, 2 kỹ thuật, IOC đúng), đóng cảnh báo + Knowledge Agent, các trang chi tiết", "9/9 bước đạt"],
    ], widths=[1.6, 3.8, 1.1], size=9.5, caption="Các bộ kiểm thử", part=P)
    code("$ python tools/test_e2e.py\n1. Đăng ký agent: OK (api_key soc_WdXD...)\n2. Gửi 10 sự kiện -> 4 cảnh báo mới (R15/R18/R08/R10): OK\n3. Chống trùng khi gửi lại lô: OK (duplicates=10)\n4. Heartbeat: OK\n5. Đăng nhập web + chống CSRF (token đổi sau đăng nhập): OK\n6. Dashboard/stats/log/CSV: OK (10 sự kiện, 4 cảnh báo mở)\n7. Tác tử Triage/Investigation cục bộ: verdict=true_positive, P1, điểm 100, 2 kỹ thuật ATT&CK: OK\n8. Đóng cảnh báo + Knowledge Agent sinh bài học: OK\n9. Các trang chi tiết/báo cáo/luật: OK\n\nTất cả 9 bước kiểm thử toàn tuyến đạt.", size=9)
    para("Những gì chưa kiểm chứng: collector Windows Event Log chỉ được rà soát logic, chưa chạy thật trên máy có quyền Administrator trong lần rà soát này; đường LLM chưa chạy vì không cấu hình khóa API (mã đã đối chiếu với tài liệu Claude API: structured outputs qua `output_config.format`, tool use với `strict`, fallback phía máy chủ).")
    page_break()
