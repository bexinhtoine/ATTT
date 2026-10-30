# -*- coding: utf-8 -*-
"""PHẦN 5. XÂY DỰNG CHƯƠNG TRÌNH CLIENT (SOC AGENT) - mở rộng."""
from report_lib import *  # noqa: F401,F403

P = "5"


def build():
    h1("PHẦN 5. XÂY DỰNG CHƯƠNG TRÌNH CLIENT (SOC AGENT)")
    h2("5.1. Yêu cầu và lựa chọn thiết kế")
    table(["Yêu cầu", "Quyết định thiết kế", "Lý do"], [
        ["Chạy trên mọi máy Windows/Linux mà không cài thêm gói", "Chỉ dùng thư viện chuẩn Python 3.8+ (urllib, subprocess, json, re, xml.etree); psutil tùy chọn", "Giảm rào cản triển khai; máy chủ production thường không cho cài pip"],
        ["Không gửi lại log cũ, không bỏ sót log mới", "Mỗi collector giữ **con trỏ** (byte offset + inode, EventRecordID, journal cursor) lưu trong agent_state.json", "Giống registry của Filebeat"],
        ["Chịu được mất mạng/server bảo trì", "Hàng đợi deque 50 000 sự kiện; lô lỗi trả về đầu hàng đợi; **spool ra đĩa** khi dừng; nạp lại khi khởi động", "Không mất bằng chứng khi server tạm ngừng"],
        ["Gửi lại không tạo bản ghi trùng (idempotent)", "Server băm SHA-1 trên (agent, source, timestamp, event_id, định danh, raw)", "Lô có thể bị gửi hai lần khi mất ACK"],
        ["Không làm quá tải máy chủ", "Chu kỳ 10 s, lô ≤ 500, chỉ EventID chọn lọc, lần đầu chỉ ghi mốc không gửi lịch sử", "Security log có thể có hàng trăm nghìn bản ghi cũ"],
        ["An toàn", "Enrollment token khi đăng ký → API key riêng (băm trên server); HTTPS tùy chọn; chạy với quyền tối thiểu cần để đọc log", "Agent lạ không thể gửi dữ liệu giả"],
        ["Quản lý tập trung", "Server trả `config` (chu kỳ, heartbeat, kích thước lô); agent áp dụng khi `follow_server_config = true`", "Như Fleet của Elastic / manager của Wazuh"],
        ["Dễ chẩn đoán", "Log ra stdout có giờ; `--once` chạy một chu kỳ; heartbeat gửi queue_size", "Vận hành viên thấy ngay agent có gửi được không"],
    ], widths=[1.9, 2.6, 2.0], size=9.5, caption="Yêu cầu và quyết định thiết kế của SOC Agent", part=P)
    h3("5.1.1. Các phương án đã cân nhắc")
    table(["Phương án", "Ưu", "Nhược", "Quyết định"], [
        ["Dùng Winlogbeat/Filebeat gửi về Web SOC", "Ổn định, nhiều tính năng", "Phải cài nhị phân, định dạng ECS khác lược đồ, khó tùy biến cho đồ án", "Không chọn; dùng làm tham chiếu"],
        ["Agent Python dùng pywin32 (EvtSubscribe) / python-systemd", "Hiệu năng tốt, đẩy sự kiện thời gian thực", "Phụ thuộc gói ngoài, biên dịch", "Không chọn"],
        ["Agent Python stdlib gọi wevtutil/journalctl, đọc tệp", "Không cài gì thêm, mã ngắn, dễ hiểu", "Tốn vài trăm ms mỗi lần gọi lệnh; độ trễ ≈ chu kỳ", "**Chọn**"],
        ["Đẩy syslog UDP/TCP tới server", "Chuẩn, có sẵn rsyslog", "Không có Windows Event Log XML, không có ACK, không chuẩn hóa tại nguồn", "Không chọn (có thể bổ sung sau)"],
    ], widths=[2.0, 1.4, 2.0, 1.1], size=9.5, caption="Các phương án thiết kế agent", part=P)

    h2("5.2. Kiến trúc và các module")
    figure("14_agent_internals.png", "Kiến trúc bên trong SOC Agent", P, 6.5)
    table(["Tệp", "Dòng", "Nhiệm vụ"], [
        ["soc_agent/agent.py", "≈ 370", "Điểm vào: đọc config.json, đăng ký, vòng lặp thu thập - gửi - heartbeat, lưu trạng thái và spool, tham số dòng lệnh"],
        ["soc_agent/collectors.py", "≈ 290", "Ba collector (FileCollector, WindowsEventLogCollector, JournaldCollector), bộ collector mặc định theo HĐH, tạo collector từ cấu hình"],
        ["soc_agent/parsers.py", "≈ 610", "Bộ phân tích và chuẩn hóa dùng chung với server (bản sao y hệt soc_server/app/parsers.py)"],
        ["soc_agent/config.example.json", "-", "Mẫu cấu hình: server, enrollment_token, interval_seconds, heartbeat_seconds, batch_size, max_queue, verify_tls, follow_server_config, collectors[]"],
        ["soc_agent/install/", "-", "install_windows_task.ps1 (Scheduled Task quyền SYSTEM, chạy lúc khởi động, tự khởi động lại), soc-agent.service (systemd, User=root, Restart=always)"],
        ["agent_state.json (sinh ra)", "-", "api_key, agent_uid, hostname, collector_states {tên: {offset, inode | last_record | cursor}}"],
        ["agent_spool.json (sinh ra khi dừng)", "-", "Hàng đợi chưa gửi: {saved_at, hostname, events[]}"],
    ], widths=[2.0, 0.6, 3.9], size=10, caption="Các tệp của SOC Agent", part=P)
    h3("5.2.1. Tham số cấu hình")
    table(["Khóa", "Mặc định", "Ý nghĩa"], [
        ["server", "http://127.0.0.1:5000", "URL Web SOC (nên là https:// khi triển khai thật)"],
        ["enrollment_token", "soc-enroll-2026", "Bí mật dùng khi đăng ký (phải đổi khi triển khai)"],
        ["hostname", "null (tự lấy)", "Ghi đè tên máy"],
        ["interval_seconds", "10", "Chu kỳ thu thập và gửi"],
        ["heartbeat_seconds", "60", "Chu kỳ heartbeat"],
        ["batch_size", "500", "Số sự kiện mỗi lô (server chấp nhận tối đa 2000)"],
        ["max_queue", "50000", "Kích thước hàng đợi trong bộ nhớ; vượt sẽ bỏ sự kiện cũ nhất"],
        ["verify_tls", "true", "Kiểm tra chứng chỉ HTTPS (--no-verify-tls chỉ cho lab)"],
        ["follow_server_config", "false", "Áp dụng interval/heartbeat/batch do server gửi"],
        ["collectors", "(trống = mặc định theo HĐH)", "Mảng {type: file|winevt|journald, name, path, format, source, channel, event_ids, units}"],
    ], widths=[1.6, 1.5, 3.4], size=10, caption="Tham số config.json", part=P)
    h3("5.2.2. Vòng đời của tiến trình agent")
    code("main()\n  ├─ load_config(): config.json + tham số dòng lệnh (--server, --hostname, --no-verify-tls)\n  ├─ SOCAgent(config)\n  │    ├─ nạp agent_state.json (api_key, con trỏ) và agent_spool.json (sự kiện chưa gửi)\n  │    └─ _build_collectors(): theo config hoặc mặc định theo HĐH; gắn state cho từng collector\n  ├─ --register: register(token) -> POST /agents/register -> lưu api_key, áp dụng config server\n  ├─ --once: run_once(): collect -> flush -> heartbeat -> save\n  └─ run_forever():\n        heartbeat đầu tiên\n        while True:\n            try: collect_once(); flush_queue(); heartbeat mỗi 60 s; save_state mỗi 30 s\n            except Exception: log lỗi, tiếp tục\n            sleep(interval)\n        finally (Ctrl+C / lỗi): _save_state(); _save_spool()")

    h2("5.3. Các bộ thu thập (collector)")
    para("Mọi collector kế thừa `BaseCollector` với ba phương thức: `collect()` trả về danh sách sự kiện chuẩn hóa **mới** kể từ lần gọi trước, `describe()` mô tả để gửi server, và thuộc tính `state` (dict con trỏ) do agent lưu/khôi phục.")
    h3("5.3.1. FileCollector - tệp log văn bản")
    para("Áp dụng cho auth.log, secure, syslog, messages, access.log hoặc bất kỳ tệp văn bản nào (định dạng `syslog`, `access_log`, `plain`). Mã rút gọn (sau khi sửa lỗi ở phiên bản 1.1):")
    code("def collect(self):\n    size = os.path.getsize(self.path); inode = os.stat(self.path).st_ino\n    offset = self.state.get(\"offset\")\n    if offset is None:                       # lần đầu: chỉ ghi mốc, không gửi lịch sử\n        self.state.update({\"offset\": size, \"inode\": inode}); return []\n    if size < offset or (self.state.get(\"inode\") and inode and self.state[\"inode\"] != inode):\n        offset = 0                           # tệp bị cắt / xoay vòng -> đọc lại từ đầu\n    events, lines_read = [], 0\n    with open(self.path, \"rb\") as f:         # nhị phân: tell() hợp lệ sau mỗi readline()\n        f.seek(offset)\n        while lines_read < self.max_lines:\n            pos = f.tell(); raw = f.readline()\n            if not raw: break\n            if not raw.endswith(b\"\\n\"):       # dòng đang được ghi dở -> để lần sau\n                f.seek(pos); break\n            lines_read += 1\n            ev = parsers.parse_line(raw.decode(\"utf-8\", \"replace\"), self.source, self.host, self.fmt)\n            if ev:\n                ev.setdefault(\"extra\", {})[\"offset\"] = f.tell(); events.append(ev)\n        offset = f.tell()\n    self.state.update({\"offset\": offset, \"inode\": inode})\n    return events", size=9)
    table(["Tình huống", "Hành vi", "Kiểm thử"], [
        ["Khởi động lần đầu với tệp 50 MB lịch sử", "offset = size, không gửi gì", "test_collectors: lần đầu trả []"],
        ["Thêm 2 dòng mới", "Đọc đúng 2 dòng, offset tới cuối", "test_collectors: 2 sự kiện"],
        ["Daemon đang ghi dở một dòng", "Giữ lại, lần sau đọc trọn", "test_collectors: dòng dở ghép lại đúng"],
        ["logrotate đổi tên (inode mới) hoặc copytruncate (size < offset)", "Đọc từ 0 của tệp mới", "test_collectors: truncate → 1 sự kiện"],
        ["Tệp tạm không tồn tại", "Trả [], không lỗi", "Mã: os.path.exists"],
        ["Dòng mã hóa lạ (Latin-1)", "decode với errors=replace", "-"],
        ["> max_lines (5000) dòng mới", "Đọc 5000, phần còn lại chu kỳ sau", "-"],
    ], widths=[2.4, 2.3, 1.8], size=9.5, caption="Các tình huống FileCollector xử lý", part=P)
    h3("5.3.2. WindowsEventLogCollector - Windows Event Log")
    para("Gọi `wevtutil qe <kênh> /q:<XPath> /f:RenderedXml /c:<n> /rd:<bool> /e:Events` rồi phân tích XML bằng `xml.etree`. XPath lọc theo danh sách EventID và `EventRecordID > last_record`. "
         "Lần đầu chỉ lấy **một** bản ghi mới nhất (`/rd:true`, `/c:1`) để ghi mốc; các chu kỳ sau đọc theo thứ tự **cũ → mới** (`/rd:false`) tối đa 800 bản ghi, nên nếu có nhiều hơn 800 sự kiện mới thì phần còn lại được lấy ở chu kỳ tiếp theo, không bị bỏ sót.")
    code("# XPath sinh ra cho kênh Security (rút gọn danh sách EventID)\n*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=1102) and EventRecordID>88123]]\n\n# Lệnh đầy đủ\nwevtutil qe Security /q:\"<XPath>\" /f:RenderedXml /c:800 /rd:false /e:Events\n\n# Kết quả: <Events><Event>...</Event><Event>...</Event></Events> -> parsers.parse_windows_event_xml()")
    table(["Kênh mặc định", "EventID thu thập", "Ghi chú"], [
        ["Security", "4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4699, 4719, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4756, 4767, 4768, 4769, 4771, 4776, 1102", "Cần quyền Administrator/SYSTEM"],
        ["System", "7045, 7034, 7036, 7040, 104, 6005, 6006, 6008, 1074", "Dịch vụ, tắt máy, xóa log"],
        ["Application", "1000, 1001, 1002", "Crash ứng dụng"],
        ["(tùy chọn) Microsoft-Windows-PowerShell/Operational", "4104, 4100", "Script block logging"],
        ["(tùy chọn) Microsoft-Windows-Sysmon/Operational", "1, 3, 11, 22", "Cần cài Sysmon"],
    ], widths=[2.2, 3.0, 1.3], size=9.5, caption="Kênh và EventID mặc định của collector Windows", part=P)
    para("Xử lý lỗi: nếu `wevtutil` trả mã lỗi (kênh không tồn tại, XPath không được hỗ trợ trên bản Windows cũ, thiếu quyền), collector thử lại với XPath tối giản 200 bản ghi; nếu vẫn lỗi thì trả [] và chu kỳ sau thử lại - agent không dừng.")
    h3("5.3.3. JournaldCollector - systemd journal")
    para("Gọi `journalctl -o json --no-pager -q [-u unit...] --after-cursor <cursor>`; lần đầu dùng `-n 0 --show-cursor` để lấy con trỏ hiện tại. Mỗi bản ghi JSON được ghép lại thành dòng "
         "`IDENT[PID]: MESSAGE` để tái dùng `parse_syslog_line`, sau đó ghi đè timestamp chính xác từ `__REALTIME_TIMESTAMP` (micro giây) và severity từ `PRIORITY`; `__CURSOR` và `_SYSTEMD_UNIT` được giữ trong extra. "
         "MESSAGE có thể là mảng byte (khi chứa ký tự không in được) - collector ghép lại thành chuỗi. Dùng khi hệ thống không có tệp auth.log/syslog truyền thống (Fedora, Arch, một số container).")
    h3("5.3.4. Bộ collector mặc định và cấu hình tùy chỉnh")
    table(["Hệ điều hành", "Collector được tạo tự động"], [
        ["Windows", "windows-security (Security), windows-system (System), windows-application (Application)"],
        ["Linux có tệp log", "linux-auth (/var/log/auth.log hoặc /var/log/secure), linux-syslog (/var/log/syslog hoặc /var/log/messages)"],
        ["Linux chỉ có journald", "journald (toàn bộ unit)"],
        ["Tùy chỉnh", "Khai báo mảng collectors trong config.json: {type: file|winevt|journald, name, path, format, source, channel, event_ids, units}"],
    ], widths=[1.6, 4.9], size=10, caption="Bộ collector mặc định", part=P)
    code("\"collectors\": [\n  {\"type\": \"winevt\", \"name\": \"windows-security\", \"channel\": \"Security\", \"event_ids\": [4624, 4625, 4672, 4720, 4732, 4740, 1102]},\n  {\"type\": \"winevt\", \"name\": \"powershell\", \"channel\": \"Microsoft-Windows-PowerShell/Operational\", \"event_ids\": [4104]},\n  {\"type\": \"file\", \"name\": \"nginx-access\", \"path\": \"/var/log/nginx/access.log\", \"format\": \"access_log\", \"source\": \"web.access\"},\n  {\"type\": \"file\", \"name\": \"linux-auth\", \"path\": \"/var/log/auth.log\", \"format\": \"syslog\", \"source\": \"linux.auth\"},\n  {\"type\": \"file\", \"name\": \"auditd\", \"path\": \"/var/log/audit/audit.log\", \"format\": \"plain\", \"source\": \"linux.audit\"},\n  {\"type\": \"journald\", \"name\": \"journald\", \"units\": [\"ssh.service\", \"sudo\"]}\n]")

    h2("5.4. Chuẩn hóa dữ liệu (parsers.py)")
    para("`parse_line()` chọn parser theo định dạng; `parse_syslog_line()` thử lần lượt regex RFC 5424 → ISO-8601 → BSD, tách PRI nếu có, rồi `classify_message()` đối chiếu thông điệp với `AUTH_PATTERNS` "
         "(≈ 30 mẫu regex có nhóm đặt tên user/ip/port) để gán action, outcome, category, severity, event_id; nếu không khớp mẫu nào thì suy ra mức từ từ khóa (error, fail, denied...) và category từ tên tiến trình. "
         "`normalize_windows_event()` tra `WINDOWS_EVENT_MAP` theo EventID, lấy user/IP từ các trường EventData tương ứng, xử lý riêng nhóm đặc quyền (4732 vào Administrators → high), NTLM 4776 (Status ≠ 0x0 → thất bại), "
         "PowerShell 4104 (từ khóa -enc, FromBase64String → high). `normalize_event()` cuối cùng bảo đảm đủ trường, đúng kiểu và cắt độ dài trước khi lưu.")
    code("# Một mẫu trong AUTH_PATTERNS: (regex, action, outcome, category, severity, event_id)\n(re.compile(r\"Failed password for (?P<user>\\S+) from (?P<ip>\\S+) port (?P<port>\\d+)\"),\n \"logon_failed\", \"failure\", \"authentication\", \"medium\", \"ssh_failed_password\"),\n\n# Một mục trong WINDOWS_EVENT_MAP: EventID -> (action, outcome, category, severity, trường user, trường IP)\n\"4625\": (\"logon_failed\", \"failure\", \"authentication\", \"medium\", \"TargetUserName\", \"IpAddress\"),\n\n# Thứ tự xử lý một dòng syslog\nparse_syslog_line(line)\n  1. RE_PRI_ONLY: tách <PRI> nếu có -> facility, severity syslog\n  2. RE_SYSLOG_5424 | RE_SYSLOG_ISO | RE_SYSLOG_BSD: thời gian, host, process[pid], msg\n  3. classify_message(process, msg): duyệt AUTH_PATTERNS theo thứ tự, dừng ở mẫu đầu khớp\n  4. không khớp: severity_from_keywords(msg), category theo tên tiến trình (sshd/sudo -> authentication, kernel -> system)\n  5. source = linux.auth nếu category thuộc {authentication, privilege, account} hoặc process in {sshd, sudo, su}", size=9)
    table(["Nhóm mẫu", "Số mẫu", "Ví dụ action"], [
        ["SSH", "7", "logon_failed, logon_success, invalid_user, ssh_max_auth_exceeded, ssh_disconnect, ssh_scan"],
        ["PAM / sudo / su", "6", "pam_auth_failure, sudo_auth_failure, sudo_failed, sudo_command, su_failed, su_success"],
        ["Tài khoản", "6", "user_created, user_deleted, group_created, user_added_to_group (→ privileged), password_changed"],
        ["Phiên", "2", "session_opened, session_closed"],
        ["Hệ thống / dịch vụ / cron", "6", "oom_kill, segfault, service_failed, service_started, service_stopped, cron_command"],
    ], widths=[1.8, 0.8, 3.9], size=10, caption="Các nhóm mẫu AUTH_PATTERNS (chi tiết ở Phụ lục B)", part=P)
    para("Thứ tự các mẫu quan trọng: mẫu \"Failed password for invalid user\" đứng trước mẫu \"Failed password for\" để bắt đúng tên tài khoản; mẫu sudo COMMAND đứng sau mẫu sudo thất bại. Khi thêm mẫu mới cần chạy `tools/test_parsers.py`.")

    h2("5.5. Giao thức với Web SOC")
    figure("15_agent_sequence.png", "Trình tự tương tác giữa SOC Agent và Web SOC", P, 6.0)
    table(["Endpoint", "Xác thực", "Yêu cầu", "Phản hồi"], [
        ["POST /api/v1/agents/register", "enrollment_token trong body", "{enrollment_token, hostname, os_type, os_version, ip_address, agent_version, collectors[]}", "201 {agent_uid, agent_id, api_key (chỉ 1 lần), server_time, config{interval_seconds, batch_size, heartbeat_seconds, max_events_per_batch}}; 403 sai token; 400 thiếu hostname"],
        ["POST /api/v1/logs", "Header X-API-Key", "{events: [sự kiện chuẩn hóa hoặc {raw, source, format} để server tự phân tích]} ≤ 2000 sự kiện, ≤ 16 MB", "200 {received, accepted, duplicates, rejected, alerts_new, alerts_updated, ai_started, server_time}; 401 key sai; 400 body sai"],
        ["POST /api/v1/agents/heartbeat", "Header X-API-Key", "{metrics{cpu_percent, memory_percent, disk_percent, uptime_hours, queue_size}, collectors, agent_version, ip_address}", "200 {ok, server_time, config}"],
    ], widths=[1.6, 1.0, 2.2, 1.7], size=9, caption="Các endpoint dành cho agent", part=P)
    code("# Yêu cầu đăng ký\nPOST /api/v1/agents/register HTTP/1.1\nContent-Type: application/json\nUser-Agent: SOC-Agent/1.1.0\n{\"enrollment_token\": \"soc-enroll-2026\", \"hostname\": \"centos-db01\", \"os_type\": \"linux\",\n \"os_version\": \"CentOS Stream 9\", \"ip_address\": \"192.168.1.21\", \"agent_version\": \"1.1.0\",\n \"collectors\": [{\"type\": \"file\", \"name\": \"linux-auth\", \"path\": \"/var/log/secure\", \"format\": \"syslog\"}]}\n\n# Phản hồi\nHTTP/1.1 201 CREATED\n{\"agent_uid\": \"6f1c...\", \"agent_id\": 4, \"api_key\": \"soc_W8B0...\", \"server_time\": \"2026-10-30T06:20:00Z\",\n \"config\": {\"interval_seconds\": 10, \"batch_size\": 500, \"heartbeat_seconds\": 60, \"max_events_per_batch\": 2000}}\n\n# Gửi lô log\nPOST /api/v1/logs\nX-API-Key: soc_W8B0...\n{\"events\": [{\"timestamp\": \"2026-10-30T06:20:57.000000Z\", \"source\": \"linux.auth\", \"category\": \"authentication\",\n             \"action\": \"logon_failed\", \"outcome\": \"failure\", \"severity\": \"medium\", \"event_id\": \"ssh_failed_password\",\n             \"message\": \"Failed password for root from 203.0.113.66 port 40000 ssh2\", \"user\": \"root\",\n             \"src_ip\": \"203.0.113.66\", \"src_port\": 40000, \"process\": \"sshd\", \"pid\": 100, \"host\": \"centos-db01\",\n             \"raw\": \"Oct 30 13:20:57 centos-db01 sshd[100]: Failed password for root ...\", \"extra\": {\"offset\": 48213}},\n            {\"raw\": \"Oct 30 13:21:00 centos-db01 useradd[3001]: new user: name=backdoor, UID=1002\", \"source\": \"linux.auth\", \"format\": \"syslog\"}]}\n\n# Phản hồi\n{\"received\": 2, \"accepted\": 2, \"duplicates\": 0, \"rejected\": 0, \"alerts_new\": 1, \"alerts_updated\": 0, \"ai_started\": 1, \"server_time\": \"...\"}", size=8.5)
    para("Thiết kế API có ba điểm đáng chú ý: (1) **lược đồ mở** - agent có thể gửi sự kiện đã chuẩn hóa hoặc dòng thô để server phân tích, nên có thể viết agent rất mỏng bằng ngôn ngữ khác (PowerShell, Go) chỉ cần đọc tệp và POST; "
         "(2) **idempotent** - gửi lại không gây trùng; (3) **phản hồi mang thông tin vận hành** - agent biết ngay lô có sinh cảnh báo không và cấu hình mới nhất.")

    h2("5.6. Độ tin cậy và xử lý lỗi")
    figure("34_agent_error_handling.png", "Xử lý lỗi phía agent theo mã trả về", P, 5.6)
    bullets([
        "**Lỗi mạng / HTTP 5xx:** lô được trả về đầu hàng đợi (`extendleft(reversed(batch))`), thử lại ở chu kỳ sau; không có lô nào bị mất trừ khi hàng đợi vượt 50 000 (lúc đó bỏ sự kiện cũ nhất).",
        "**HTTP 401:** API key không còn hợp lệ (admin đã cấp lại khóa) - dừng gửi, giữ hàng đợi, in hướng dẫn chạy lại `--register`.",
        "**Phản hồi không phải JSON** (proxy chặn, trang lỗi HTML): được trả về dạng chuỗi thay vì làm crash vòng lặp.",
        "**Ngoại lệ bất kỳ trong một chu kỳ** (collector lỗi, ổ đĩa đầy...): ghi log và tiếp tục chu kỳ sau; agent không bao giờ chết vì một lỗi đơn lẻ; dịch vụ hệ điều hành khởi động lại nếu tiến trình chết.",
        "**Dừng agent (Ctrl+C, tắt dịch vụ):** lưu trạng thái con trỏ và ghi hàng đợi chưa gửi vào `agent_spool.json`; lần khởi động sau nạp lại và gửi trước.",
        "**Trạng thái bền vững:** `agent_state.json` ghi bằng cách ghi tệp tạm rồi `os.replace` (nguyên tử) mỗi 30 giây và khi dừng, nên mất điện giữa chừng không làm hỏng tệp.",
        "**Đồng hồ sai:** timestamp lấy từ chính log (không phải giờ gửi), server ghi thêm received_at để đối chiếu.",
    ])
    h3("5.6.1. Ước lượng hiệu năng và dung lượng")
    table(["Đại lượng", "Ước lượng", "Căn cứ"], [
        ["CPU của agent", "< 1% trung bình; đỉnh ngắn khi gọi wevtutil", "Chu kỳ 10 s, phần lớn thời gian sleep"],
        ["RAM", "20-40 MB (Python) + hàng đợi (≈ 1 KB/sự kiện → 50 MB khi đầy 50 000)", "Đo thực tế trên Windows 11"],
        ["Thời gian wevtutil", "0,2-1 s cho 800 bản ghi RenderedXml", "Phụ thuộc kích thước kênh"],
        ["Kích thước lô 500 sự kiện", "≈ 400-700 KB JSON (Windows có raw XML lớn)", "Giới hạn 16 MB của server rất dư"],
        ["Lưu trữ server", "≈ 1,5 KB/sự kiện trong SQLite → 1 triệu sự kiện ≈ 1,5 GB", "Cột raw chiếm phần lớn; có thể tắt lưu raw"],
        ["Độ trễ end-to-end", "10-15 s (chu kỳ + xử lý)", "Giảm bằng interval_seconds nhỏ hơn"],
    ], widths=[1.8, 2.7, 2.0], size=10, caption="Ước lượng hiệu năng", part=P)

    h2("5.7. Bảo mật của agent")
    table(["Mối đe dọa", "Biện pháp"], [
        ["Agent giả mạo gửi dữ liệu sai lệch", "Enrollment token khi đăng ký (đổi khỏi mặc định); API key riêng từng máy, lưu băm trên server, có thể thu hồi/cấp lại"],
        ["Nghe lén / sửa dữ liệu trên đường truyền", "HTTPS (reverse proxy nginx/caddy), verify_tls = true; mạng quản trị riêng"],
        ["Lộ API key trên máy trạm", "agent_state.json chỉ đọc được bởi SYSTEM/root; cấp lại khóa khi nghi ngờ"],
        ["Agent bị lợi dụng để đọc tệp nhạy cảm", "Agent chỉ đọc đường dẫn trong config; không nhận lệnh từ server (chỉ nhận cấu hình số)"],
        ["Kẻ tấn công tắt agent để che dấu vết", "Dịch vụ tự khởi động lại; server đánh dấu offline sau 180 s (dashboard thấy ngay); log trước đó đã ở server"],
        ["Tấn công vào server qua dữ liệu log (injection)", "Server chuẩn hóa lại, cắt độ dài, không thực thi; giao diện escape HTML (Jinja2)"],
    ], widths=[2.4, 4.1], size=10, caption="Mô hình đe dọa và biện pháp của agent", part=P)

    h2("5.8. Cài đặt, vận hành và kiểm thử")
    code("# Đăng ký và chạy thử một lần\npython agent.py --server http://IP_SOC:5000 --token soc-enroll-2026 --register --once\n# Chạy liên tục\npython agent.py\n# Windows: cài Scheduled Task (PowerShell quyền Administrator)\n.\\install\\install_windows_task.ps1\n# Linux: cài dịch vụ systemd\nsudo cp -r soc_agent /opt/soc_agent && sudo cp /opt/soc_agent/install/soc-agent.service /etc/systemd/system/\nsudo systemctl daemon-reload && sudo systemctl enable --now soc-agent\nsudo journalctl -u soc-agent -f\n# Kiểm thử collector và parser\npython tools/test_collectors.py\npython tools/test_parsers.py")
    table(["Triệu chứng", "Nguyên nhân thường gặp", "Cách xử lý"], [
        ["\"Đăng ký THẤT BẠI (HTTP 403)\"", "Sai enrollment token", "Kiểm tra SOC_ENROLLMENT_TOKEN trên server"],
        ["\"Gửi lô thất bại (HTTP None)\"", "Không kết nối được server (firewall, sai URL)", "curl thử URL; mở cổng; kiểm tra https"],
        ["\"Heartbeat bị từ chối\" / 401", "Admin đã cấp lại khóa", "Chạy lại --register"],
        ["Windows: không có sự kiện Security", "Không chạy quyền Administrator/SYSTEM, hoặc audit policy chưa bật", "Chạy PowerShell Administrator; auditpol /get"],
        ["Linux: không có sự kiện", "Không có quyền đọc /var/log/auth.log; hệ chỉ dùng journald", "Chạy root; hoặc khai báo collector journald"],
        ["Sự kiện có giờ lệch", "Máy trạm lệch đồng hồ / sai múi giờ", "Bật NTP; kiểm tra TZ"],
        ["Hàng đợi tăng liên tục", "Server chậm hoặc lô bị từ chối", "Xem log server; tăng batch_size; kiểm tra MAX_CONTENT_LENGTH"],
    ], widths=[2.0, 2.3, 2.2], size=9.5, caption="Chẩn đoán sự cố agent", part=P)
    page_break()
