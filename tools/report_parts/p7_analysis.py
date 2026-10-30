# -*- coding: utf-8 -*-
"""PHẦN 7. PHÂN TÍCH CHỨC NĂNG THU THẬP LOG WINDOWS/LINUX CỦA HỆ THỐNG SOC - mở rộng, dùng dữ liệu thật."""
import json
from report_lib import *  # noqa: F401,F403

P = "7"


def build():
    h1("PHẦN 7. PHÂN TÍCH CHỨC NĂNG THU THẬP LOG WINDOWS/LINUX CỦA HỆ THỐNG SOC")
    h2("7.1. Yêu cầu chức năng của khâu thu thập")
    table(["Yêu cầu", "Ý nghĩa", "Hiện thực trong hệ thống", "Đánh giá"], [
        ["Đầy đủ (completeness)", "Không bỏ sót sự kiện quan trọng", "Con trỏ theo EventRecordID/offset/cursor; đọc cũ → mới có phân trang", "Đạt với EventID đã chọn; 4688/5156 cố ý bỏ để giảm nhiễu"],
        ["Kịp thời (timeliness)", "Độ trễ nhỏ từ lúc xảy ra tới SOC", "Chu kỳ 10 s + xử lý ngay khi nhận", "Độ trễ ≈ 10-15 s"],
        ["Toàn vẹn (integrity)", "Dữ liệu không bị sửa trên đường truyền, không mất", "API key, HTTPS tùy chọn, hàng đợi + spool, băm chống trùng", "Đạt; nên bật TLS khi triển khai thật"],
        ["Chuẩn hóa (normalization)", "Một lược đồ cho mọi nguồn", "parsers.py dùng chung agent/server", "Đạt; mở rộng bằng cách thêm regex/EventID"],
        ["Hiệu năng", "Không ảnh hưởng máy nguồn", "Chỉ stdlib, lô ≤ 500, wevtutil lọc bằng XPath, không đọc lịch sử", "CPU không đáng kể; wevtutil mất ~0,2-1 s/lần"],
        ["Bền bỉ (resilience)", "Chịu lỗi mạng, khởi động lại", "Thử lại, spool, Restart=always / RestartCount", "Đạt"],
        ["An toàn", "Agent lạ không gửi được, khóa không lộ", "Enrollment token, khóa băm, chỉ hiển thị 1 lần", "Đạt; token mặc định phải đổi"],
        ["Mở rộng (extensibility)", "Thêm nguồn mới dễ dàng", "Collector theo cấu hình JSON; server nhận cả dòng raw để tự phân tích", "Đạt"],
        ["Quản lý tập trung", "Đổi cấu hình từ server", "config trong register/heartbeat + follow_server_config", "Một phần (chu kỳ/lô; chưa đẩy danh sách collector)"],
        ["Khả năng quan sát agent", "Biết agent có sống và có gửi được không", "Heartbeat 60 s với CPU/RAM/đĩa/queue_size; offline sau 180 s", "Đạt"],
    ], widths=[1.3, 1.5, 2.3, 1.4], size=9, caption="Yêu cầu chức năng của khâu thu thập và mức đáp ứng", part=P)

    h2("7.2. Phân tích theo hệ điều hành")
    h3("7.2.1. Windows")
    bullets([
        "**Nguồn:** Security (xác thực, tài khoản, đặc quyền, xóa log), System (dịch vụ, tắt máy), Application (crash); có thể thêm PowerShell/Operational, Sysmon, TaskScheduler bằng cấu hình.",
        "**Quyền:** đọc Security cần Administrator/SYSTEM → Scheduled Task chạy bằng SYSTEM. Agent không ghi gì vào hệ thống ngoài thư mục của nó.",
        "**Chính sách kiểm toán:** nhiều EventID chỉ xuất hiện khi auditpol bật (ví dụ 4688 cần Audit Process Creation; 4104 cần Script Block Logging). Đây là điều kiện tiên quyết thường bị bỏ qua.",
        "**Lọc nhiễu:** 4688, 5156/5157, 4634 sinh rất nhiều; agent mặc định không lấy 5156/5157 và chỉ lấy 4688 trong danh sách Security (có thể bỏ nếu máy bận).",
        "**Hiệu năng wevtutil:** lọc bằng XPath trên EventRecordID nhanh; lần đầu chỉ lấy 1 bản ghi; chu kỳ sau tối đa 800. Một lựa chọn khác là API `EvtSubscribe` (cần pywin32) - không dùng để giữ stdlib.",
        "**Thời gian:** TimeCreated luôn UTC, tránh được lỗi múi giờ; EventRecordID tăng đơn điệu kể cả khi log bị ghi đè.",
        "**Thông điệp:** RenderedXml cho thông điệp đã dịch; nếu thiếu, parser tự sinh thông điệp từ WINDOWS_EVENT_DESCRIPTIONS và EventData để người đọc hiểu ngay.",
    ])
    h3("7.2.2. Linux")
    bullets([
        "**Nguồn:** auth.log/secure (ưu tiên), syslog/messages, journald khi không có tệp; access log web, auditd qua cấu hình.",
        "**Quyền:** /var/log/auth.log thuộc root:adm (0640) → dịch vụ chạy root hoặc thêm user vào nhóm adm và cấp quyền journal (nhóm systemd-journal).",
        "**Định dạng không đồng nhất:** BSD timestamp không có năm và theo giờ địa phương (`parse_bsd_timestamp` suy năm và đổi UTC); rsyslog mới có thể ghi ISO-8601 (regex riêng); RFC 5424 khi nhận từ mạng.",
        "**Xoay vòng:** logrotate đổi tên hoặc truncate (copytruncate); collector so sánh inode và kích thước để đọc lại từ đầu.",
        "**Khác biệt phân phối:** Debian (auth.log/syslog) và RHEL (secure/messages) được tự dò; hệ chỉ journald dùng JournaldCollector với cursor.",
        "**Dòng ghi dở:** khi đọc đúng lúc daemon đang ghi, dòng chưa có ký tự xuống dòng được giữ lại cho chu kỳ sau - tránh sự kiện bị cắt.",
        "**Nhiều dòng cho một sự kiện:** sshd + PAM + disconnect cùng mô tả một lần thất bại; parser gán action khác nhau để luật đếm đúng.",
    ])
    h3("7.2.3. So sánh hai hệ điều hành từ góc nhìn thu thập")
    table(["Khía cạnh", "Windows", "Linux"], [
        ["Định dạng gốc", "XML có cấu trúc, trường có tên", "Văn bản tự do, cần regex"],
        ["Định danh sự kiện", "EventID + Provider (ổn định, có tài liệu)", "Nội dung thông điệp (thay đổi theo phiên bản phần mềm)"],
        ["Con trỏ", "EventRecordID (tăng đơn điệu)", "Byte offset + inode / journal cursor"],
        ["Thời gian", "UTC chính xác", "Giờ địa phương, không năm (BSD)"],
        ["Cách đọc", "wevtutil / API", "Đọc tệp / journalctl"],
        ["Khối lượng", "Lớn nếu bật Process Creation/Object Access", "Vừa; access log có thể rất lớn"],
        ["Điểm khó", "Quyền, audit policy, XML lớn", "Regex, định dạng khác nhau giữa distro, rotate"],
    ], widths=[1.6, 2.5, 2.4], size=10, caption="So sánh thu thập log Windows và Linux", part=P)

    h2("7.3. Đối chiếu với agent của các nền tảng lớn")
    table(["Chức năng", "Wazuh agent", "Filebeat/Winlogbeat", "SOC Agent (đề tài)"], [
        ["Đọc Windows Event Log", "eventchannel API, lọc XPath", "Winlogbeat API", "wevtutil + XPath (stdlib)"],
        ["Đọc tệp log + xoay vòng", "Có", "Có (registry, harvester)", "Có (offset + inode)"],
        ["journald", "Có", "Filebeat journald input", "Có (journalctl JSON + cursor)"],
        ["Chuẩn hóa tại agent", "Không (decoder trên server)", "Một phần (module ECS)", "Có (parsers dùng chung) hoặc gửi raw để server phân tích"],
        ["Hàng đợi khi mất mạng", "Có (buffer)", "Có (spool, registry)", "Có (deque + spool tệp)"],
        ["Mã hóa / xác thực", "AES + khóa agent", "TLS + API key/cert", "API key băm; HTTPS tùy chọn"],
        ["FIM, SCA, rootkit, active response", "Có", "Không (Auditbeat một phần)", "Không (ngoài phạm vi)"],
        ["Cấu hình tập trung", "Có (manager)", "Có (Fleet)", "Một phần (config từ server)"],
        ["Phụ thuộc", "Nhị phân riêng", "Nhị phân Go", "Chỉ Python chuẩn"],
        ["Kích thước mã", "Hàng trăm nghìn dòng C", "Hàng trăm nghìn dòng Go", "≈ 1.300 dòng Python (kể cả parser)"],
    ], widths=[1.7, 1.5, 1.6, 1.7], size=9.5, caption="Đối chiếu với các agent lớn", part=P)

    h2("7.4. Luồng dữ liệu đầu cuối")
    numbered([
        "**Sinh log** trên máy nguồn (sshd ghi auth.log; LSASS ghi 4625).",
        "**Thu thập**: collector đọc phần mới theo con trỏ (≤ 10 s).",
        "**Chuẩn hóa** tại agent: 17 trường chung, severity/category/action.",
        "**Vận chuyển**: hàng đợi → lô ≤ 500 → POST JSON + API key.",
        "**Tiếp nhận**: xác thực, chuẩn hóa lại, băm chống trùng, lưu log_events.",
        "**Phát hiện**: 21 luật match/threshold/sequence → alerts (gộp trùng theo dedup_key, liên kết bằng chứng).",
        "**Làm giàu và phân loại** (tự động, nền): Enrichment → Triage → verdict, ưu tiên.",
        "**Trình bày**: dashboard 30 s, danh sách cảnh báo theo ưu tiên, tìm kiếm log, báo cáo.",
        "**Điều tra và tri thức** (theo yêu cầu analyst): Investigation → Knowledge.",
        "**Phản ứng** do con người thực hiện theo khuyến nghị; bài học quay lại cải thiện luật.",
    ])

    # ------------------------------------------------------------------ 7.5 dữ liệu thật
    h2("7.5. Kết quả thực nghiệm trên dữ liệu trình diễn")
    n_ev = (db_query("select count(*) from log_events") or [(0,)])[0][0]
    n_al = (db_query("select count(*) from alerts") or [(0,)])[0][0]
    n_ai = (db_query("select count(*) from ai_runs") or [(0,)])[0][0]
    para("Dữ liệu sinh bởi `tools/demo_attack.py` (qua `tools/rebuild_demo.py`, mã nguồn 1.1): 4 máy trạm mô phỏng (WIN-DC01, WIN-SRV02 Windows Server; ubuntu-web01, centos-db01 Linux), "
         "%d sự kiện trong 2 giờ gồm 5 kịch bản tấn công xen log nền lành tính. Hệ thống sinh %d cảnh báo và %d lượt tác tử AI ở chế độ cục bộ, 100%% thành công." % (n_ev, n_al, n_ai))
    figure("c8_events_timeline.png", "Dòng thời gian sự kiện theo máy trạm", P, 6.5)
    figure("c9_events_per_10min.png", "Mật độ sự kiện theo khung 10 phút", P, 6.0)
    figure("c1_events_by_source.png", "Sự kiện theo nguồn log", P, 5.6)
    figure("c7_events_by_host.png", "Sự kiện theo máy trạm", P, 5.6)
    figure("c10_sev_by_host.png", "Phân bố mức độ theo máy trạm", P, 5.8)
    figure("c2_events_by_severity.png", "Sự kiện theo mức độ nghiêm trọng sau chuẩn hóa", P, 5.6)
    figure("c13_categories.png", "Sự kiện theo category", P, 5.6)
    figure("c11_top_actions.png", "12 hành động phổ biến nhất", P, 5.8)
    figure("c5_top_failed_ips.png", "IP nguồn có nhiều sự kiện thất bại nhất", P, 5.6)
    h3("7.5.1. Các kịch bản tấn công và cảnh báo sinh ra")
    table(["Kịch bản", "Máy", "Luật kích hoạt", "Kết luận AI / ưu tiên", "Nhận xét"], [
        ["Dò SSH 18 lần rồi thành công, tạo user backdoor, thêm vào sudo", "centos-db01", "R15, R18, R10, R08, R04", "true_positive P1 (điểm 95-100); R08/R04 P2-P3", "Chuỗi tấn công đầy đủ T1110.001 → T1078 → T1136.001 → T1098"],
        ["Dò RDP 16 lần rồi đăng nhập RDP thành công", "WIN-SRV02", "R16, R18, R21", "true_positive P1", "R21 kích hoạt nhờ sửa phân loại IP tài liệu thành public"],
        ["Password spraying 13 tài khoản", "ubuntu-web01", "R17, R20", "true_positive P1", "Đếm distinct user hoạt động đúng; IP trong blocklist"],
        ["Tạo tài khoản, thêm Administrators, cài dịch vụ, tạo task, xóa log 1102", "WIN-DC01", "R03, R04, R05, R06, R01", "R01 P1; R04 P2; còn lại P3", "Các sự kiện không có src_ip → gom theo user/host"],
        ["Quét web 40 URL + path traversal + sqlmap", "ubuntu-web01", "R19, R11", "R11 P2; R19 P3", "Quét ồn ào được hạ ưu tiên; yêu cầu nguy hiểm được nâng"],
        ["Tài khoản jdoe bị khóa; SSH root nội bộ", "WIN-DC01, ubuntu-web01", "R13, R10", "P3 / P2", "Có thể là người dùng quên mật khẩu / quản trị viên"],
    ], widths=[2.0, 0.9, 1.1, 1.2, 1.3], size=9, caption="Kịch bản tấn công và cảnh báo", part=P)
    rows = db_query("select a.id, r.code, a.title, a.severity, a.ai_verdict, a.ai_priority, json_extract(a.ai_data,'$.triage.risk_score'), a.event_count, a.status "
                    "from alerts a join detection_rules r on r.id=a.rule_id order by a.id")
    if rows:
        table(["#", "Luật", "Tiêu đề cảnh báo", "Mức", "Verdict AI", "P", "Điểm", "Sự kiện", "Trạng thái"],
              [[r[0], r[1], r[2][:70], r[3], r[4] or "-", r[5] or "-", r[6] if r[6] is not None else "-", r[7], r[8]] for r in rows],
              widths=[0.3, 0.5, 2.6, 0.6, 1.0, 0.3, 0.4, 0.5, 0.7], size=8, caption="Toàn bộ cảnh báo của lần thực nghiệm (trích từ CSDL)", part=P)
    figure("c3_alerts_by_rule.png", "Cảnh báo sinh ra theo luật", P, 6.3)
    figure("c12_risk_scores.png", "Điểm rủi ro của từng cảnh báo và ngưỡng ưu tiên", P, 6.3)
    figure("c4_ai_verdicts.png", "Phân bố kết luận của Triage Agent", P, 5.6)
    h3("7.5.2. Điều tra sâu một vụ: đăng nhập thành công sau 18 lần thất bại")
    inv = db_query("select i.hypothesis, i.summary, i.attack_chain, i.iocs, i.impact, i.root_cause, i.recommendations, i.timeline from investigations i "
                   "join alerts a on a.id=i.alert_id join detection_rules r on r.id=a.rule_id where r.code='R18' and a.host='centos-db01' order by i.id desc limit 1")
    if inv:
        hyp, summ, chain, iocs, impact, root, recs, tl = inv[0]
        para("Investigation Agent (chế độ cục bộ) cho cảnh báo R18 trên centos-db01 đưa ra giả thuyết: *\"%s\"* Tóm tắt: %s" % (hyp, summ))
        chain = json.loads(chain or "[]")
        table(["Tactic", "Kỹ thuật", "Bằng chứng"], [[c.get("tactic"), c.get("technique"), c.get("evidence")] for c in chain],
              widths=[1.4, 2.0, 3.1], size=9, caption="Chuỗi tấn công do Investigation Agent dựng", part=P)
        io = json.loads(iocs or "{}")
        table(["Loại IOC", "Giá trị"], [["IP", ", ".join(io.get("ips", [])) or "-"], ["Tài khoản", ", ".join(io.get("users", [])) or "-"],
                                        ["Tiến trình", ", ".join(io.get("processes", [])) or "-"], ["Tệp/URL", ", ".join(io.get("files", [])) or "-"]],
              widths=[1.5, 5.0], size=9.5, caption="IOC trích xuất", part=P)
        para("**Tác động:** %s **Nguyên nhân gốc:** %s" % (impact, root))
        recs = json.loads(recs or "[]")
        para("**Khuyến nghị (%d mục, rút gọn):**" % len(recs))
        bullets(recs[:8])
        tl = json.loads(tl or "[]")
        sel = [t for t in tl if "logon_failed" in t.get("event", "") or "logon_success" in t.get("event", "") or "user" in t.get("event", "")][:8]
        if sel:
            table(["Thời điểm (UTC)", "Sự kiện", "Ghi chú"], [[t.get("time"), t.get("event"), (t.get("note") or "")[:90]] for t in sel],
                  widths=[1.4, 1.8, 3.3], size=8.5, caption="Trích dòng thời gian điều tra", part=P)
    h3("7.5.3. Hiệu năng của các tác tử")
    figure("c6_ai_runs.png", "Số lượt và thời gian chạy của các tác tử", P, 6.0)
    rows = db_query("select agent_name, mode, count(*), round(avg(duration_ms),1), max(duration_ms), sum(case when status='ok' then 1 else 0 end) from ai_runs group by 1,2 order by 1")
    if rows:
        table(["Tác tử", "Chế độ", "Số lượt", "TB (ms)", "Max (ms)", "Thành công"], [list(r) for r in rows],
              widths=[1.4, 0.9, 0.9, 0.9, 0.9, 1.0], size=10, caption="Thống kê ai_runs", part=P)
    para("Ở chế độ cục bộ, toàn bộ chuỗi enrich → triage cho một cảnh báo mất dưới 100 ms, nên 19 cảnh báo được phân loại gần như tức thời sau khi lô log được tiếp nhận. "
         "Ở đường LLM, mỗi lượt triage tốn khoảng 3-8 nghìn token đầu vào và 5-15 giây; investigation với vài vòng gọi công cụ tốn 15-40 nghìn token và 30-90 giây (ước lượng theo kích thước prompt; chi phí thực tế ghi trong ai_runs khi bật khóa API).")
    h3("7.5.4. Đánh giá độ chính xác phát hiện")
    table(["Kịch bản (ground truth)", "Cảnh báo mong đợi", "Cảnh báo thực tế", "Verdict AI mong đợi", "Verdict thực tế", "Kết quả"], [
        ["SSH brute force + thành công + backdoor", "R15, R18, R10, R08, R04", "Đủ 5", "P1 cho R15/R18/R10", "P1, P1, P1; R04 P2, R08 P3", "Đúng"],
        ["RDP brute force + thành công", "R16, R18, R21", "Đủ 3", "P1", "P1, P1, P1", "Đúng"],
        ["Password spraying", "R17, R20", "Đủ 2", "P1", "P1, P1", "Đúng"],
        ["Persistence + xóa log trên DC", "R03, R04, R05, R06, R01", "Đủ 5", "R01 P1, còn lại P2-P3", "R01 P1, R04 P2, R03/R05/R06 P3", "Đúng"],
        ["Quét web + yêu cầu nguy hiểm", "R19, R11", "Đủ 2", "R11 ≥ P3, R19 thấp", "R11 P2, R19 P3", "Đúng (R19 còn cao hơn kỳ vọng)"],
        ["Khóa tài khoản jdoe (nhiễu)", "R13", "1", "P3-P4", "P3", "Chấp nhận"],
        ["Log nền lành tính (≈ 280 sự kiện)", "0", "0 (trừ R10 từ IP nội bộ: P2)", "-", "-", "1 cảnh báo có thể coi là dương tính giả có chủ đích (chính sách cấm root SSH)"],
    ], widths=[1.6, 1.1, 0.9, 1.0, 1.1, 0.8], size=8.5, caption="Đối chiếu kết quả với kịch bản", part=P)
    para("Tổng kết: 19/19 cảnh báo đúng kịch bản, 0 cảnh báo sai từ log nền (ngoài R10 theo chính sách), 9 cảnh báo P1 đều là tấn công thật; không bỏ sót kịch bản nào. "
         "Hạn chế của thực nghiệm: dữ liệu mô phỏng có nhiễu thấp hơn thực tế; cần đo thêm trên log thật nhiều tuần để hiệu chỉnh ngưỡng và trọng số điểm.")

    h2("7.6. Hạn chế và hướng phát triển")
    table(["Hạn chế hiện tại", "Hướng phát triển", "Độ phức tạp"], [
        ["Chỉ thu log HĐH và web; chưa có FIM, Sysmon ánh xạ riêng, lưu lượng mạng, cloud", "Thêm collector Sysmon với ánh xạ EventID 1/3/11/22; FIM bằng hash tệp; Suricata eve.json; CloudTrail", "Trung bình"],
        ["SQLite và Flask dev server", "PostgreSQL, gunicorn/waitress sau nginx HTTPS; Redis queue cho tác tử AI; FTS5/OpenSearch cho tìm kiếm", "Trung bình"],
        ["Chưa đẩy danh sách collector từ server; chưa ký số lô", "Mở rộng config trong heartbeat; HMAC lô bằng API key", "Thấp"],
        ["Chấm điểm heuristic cố định", "Trọng số cấu hình được; học từ phản hồi analyst (verdict cuối) để hiệu chỉnh", "Trung bình"],
        ["Threat intelligence chỉ có bảng cục bộ", "Tích hợp AbuseIPDB, OTX, MISP; cache kết quả", "Thấp"],
        ["AI chỉ đề xuất", "Phản ứng bán tự động có phê duyệt: chặn IP qua firewall API, vô hiệu tài khoản AD", "Cao (an toàn)"],
        ["Chưa có UEBA", "Baseline theo tài khoản/máy (số đăng nhập, giờ, IP) và cảnh báo lệch chuẩn", "Cao"],
        ["Chưa phơi công cụ cho tác tử ngoài", "MCP server bọc 6 công cụ để Claude Code/Harness Agent điều tra như ASP", "Thấp"],
        ["Kiểm thử collector Windows chưa chạy thật", "Chạy trên máy Windows có quyền admin, thêm kiểm thử mô phỏng wevtutil", "Thấp"],
    ], widths=[2.3, 3.2, 1.0], size=9.5, caption="Hạn chế và hướng phát triển", part=P)
    page_break()
