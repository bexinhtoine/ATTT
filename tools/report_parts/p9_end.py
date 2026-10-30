# -*- coding: utf-8 -*-
"""KẾT LUẬN, THUẬT NGỮ, TÀI LIỆU THAM KHẢO, PHỤ LỤC (phụ lục sinh từ mã nguồn thật)."""
import json
import os
import sys

from report_lib import *  # noqa: F401,F403

P = "PL"


def _load_code_tables():
    """Nạp bảng luật, ánh xạ EventID, mẫu regex trực tiếp từ mã nguồn để phụ lục luôn đúng."""
    agent_dir = os.path.join(ROOT, "soc_agent")
    server_dir = os.path.join(ROOT, "soc_server")
    for p in (agent_dir, server_dir):
        if p not in sys.path:
            sys.path.insert(0, p)
    import parsers  # noqa: E402
    from app.seed import DEFAULT_RULES, DEFAULT_KNOWLEDGE, DEMO_IP_REPUTATION  # noqa: E402
    return parsers, DEFAULT_RULES, DEFAULT_KNOWLEDGE, DEMO_IP_REPUTATION


def build():
    # ------------------------------------------------------------------ KẾT LUẬN
    h1("KẾT LUẬN")
    para("Tài liệu đã trình bày đầy đủ bảy khối nền tảng của đề tài và đi sâu hơn ở mỗi khối so với bản đầu. Về lý thuyết, SOC là tổ hợp con người - quy trình - công nghệ với bài toán trung tâm là alert fatigue; "
         "SIEM là bộ khung thu thập → chuẩn hóa → tương quan → cảnh báo → trình bày đã tiến hóa qua bốn thế hệ tới Agentic SOC; các nền tảng ELK, Wazuh, Prometheus cung cấp hình mẫu kiến trúc agent → server → lưu trữ → dashboard "
         "và những kỹ thuật cụ thể (registry offset, decoder/rule, heartbeat) được tái hiện trong đề tài; Agentic SOC Platform cho thấy cách đặt tác tử AI lên trên pipeline đó với mô hình dữ liệu Case - Alert - Artifact - Enrichment - Playbook - Knowledge và nguyên tắc con người quyết định.")
    para("Về thực hành, việc hiểu cấu trúc Windows Event Log (kênh, EventID, EventData, LogonType, Keywords, audit policy) và syslog (facility, severity, PRI, tệp /var/log, journald, auditd) là điều kiện để viết được parser chuẩn hóa 17 trường; "
         "SOC Agent (chỉ thư viện chuẩn, con trỏ bền vững, hàng đợi và spool) và Web SOC (11 bảng, Rule Engine ba loại luật, dashboard, bốn tác tử AI có đường cục bộ, phân quyền, kiểm toán, chống CSRF) hiện thực hóa toàn bộ luồng từ log thô tới tri thức. "
         "Thực nghiệm trên dữ liệu trình diễn tạo lại bằng mã 1.1 cho 19/19 cảnh báo đúng kịch bản, 9 cảnh báo P1 đều là tấn công thật và chuỗi tấn công bốn kỹ thuật ATT&CK được dựng tự động.")
    para("Lần rà soát này cũng sửa một lỗi nghiêm trọng khiến collector tệp Linux không hoạt động, bổ sung chống CSRF, phân loại đúng IP tài liệu, tăng độ bền agent và thêm ba bộ kiểm thử tự động. "
         "Hướng phát triển ưu tiên: triển khai thử trên log thật nhiều tuần để hiệu chỉnh ngưỡng; chuyển sang PostgreSQL và WSGI production; tích hợp threat intelligence trực tuyến; phơi công cụ của tác tử qua MCP để tác tử ngoài (Claude Code) điều tra như mô hình Harness Agent của ASP; và phản ứng bán tự động có phê duyệt.")
    page_break()

    # ------------------------------------------------------------------ THUẬT NGỮ
    h1("BẢNG THUẬT NGỮ")
    terms = [
        ("Agent", "Chương trình chạy trên máy nguồn để thu thập và gửi log/telemetry về máy chủ trung tâm."),
        ("Agentic AI / tác tử AI", "Cách dùng LLM có công cụ và vòng lặp tự quyết định để hoàn thành mục tiêu nhiều bước."),
        ("Alert fatigue", "Tình trạng analyst quá tải vì quá nhiều cảnh báo, phần lớn là nhiễu, dẫn tới bỏ sót cảnh báo thật."),
        ("Artifact / IOC", "Thực thể hoặc chỉ dấu của sự cố: IP, domain, hash, tài khoản, host, tiến trình. IOC = Indicator of Compromise."),
        ("ATT&CK", "Cơ sở tri thức của MITRE về tactic (mục tiêu) và technique (kỹ thuật) của kẻ tấn công, dùng làm ngôn ngữ chung."),
        ("Audit policy", "Chính sách kiểm toán của Windows quyết định sự kiện nào được ghi vào Security log."),
        ("auditd", "Hệ thống kiểm toán mức nhân của Linux ghi syscall và thay đổi tệp theo luật."),
        ("Brute force / password spraying", "Dò mật khẩu: thử nhiều mật khẩu cho một tài khoản / thử một vài mật khẩu cho nhiều tài khoản."),
        ("Case", "Đối tượng xử lý trung tâm trong ASP, gom alert, artifact, enrichment, thảo luận và báo cáo AI của một sự cố."),
        ("Collector", "Thành phần của agent đọc một nguồn log cụ thể (tệp, Windows Event Log, journald) và nhớ con trỏ."),
        ("Correlation (tương quan)", "Kết hợp nhiều sự kiện theo thời gian, nhóm hoặc chuỗi để nhận ra một cuộc tấn công."),
        ("CSRF", "Cross-Site Request Forgery - ép trình duyệt đã đăng nhập gửi yêu cầu ngoài ý muốn; chống bằng token gắn phiên."),
        ["Dedup / dedup_key", "Gộp các lần kích hoạt lặp lại của cùng một cuộc tấn công vào một cảnh báo."],
        ("Detection engineering", "Quy trình phát triển, kiểm thử, triển khai và đo lường luật phát hiện như mã nguồn."),
        ("Dwell time", "Thời gian kẻ tấn công tồn tại trong hệ thống trước khi bị phát hiện."),
        ("ECS / OCSF / CIM", "Các lược đồ chuẩn hóa sự kiện của Elastic / Open Cybersecurity Schema Framework / Splunk."),
        ("EDR / XDR", "Endpoint / Extended Detection and Response - giám sát và phản ứng trên điểm cuối / mở rộng ra nhiều lớp."),
        ("Enrichment (làm giàu)", "Bổ sung ngữ cảnh cho cảnh báo: uy tín IP, tài sản, danh tính, lịch sử, threat intel."),
        ("Enrollment token", "Bí mật dùng chung để agent đăng ký lần đầu và nhận API key riêng."),
        ("EventID / EventRecordID", "Mã loại sự kiện Windows / số thứ tự tăng dần của bản ghi trong kênh."),
        ("Facility / Severity (syslog)", "Nguồn phát sinh (kern, auth, cron...) / mức nghiêm trọng 0-7 của thông điệp syslog."),
        ("False positive (dương tính giả)", "Cảnh báo về hành vi thực ra lành tính."),
        ("FIM", "File Integrity Monitoring - giám sát thay đổi tệp/registry."),
        ("Harness Agent", "Tác tử lập trình như Claude Code, Codex được ASP cho phép thao tác dữ liệu SOC qua CLI/Skills."),
        ("Heartbeat", "Thông điệp định kỳ của agent báo còn sống kèm số liệu tài nguyên."),
        ("Human-in-the-loop", "Nguyên tắc con người duyệt trước các hành động có tác động do AI đề xuất."),
        ("IDS / IPS / NDR", "Phát hiện / ngăn chặn xâm nhập / phát hiện và phản ứng trên mạng."),
        ("Ingest (tiếp nhận)", "Khâu nhận, kiểm tra, chuẩn hóa và lưu dữ liệu log tại server."),
        ("journald / journalctl", "Dịch vụ nhật ký của systemd và công cụ truy vấn."),
        ("Kill Chain", "Mô hình 7 bước của một cuộc tấn công (Lockheed Martin)."),
        ("Knowledge (tri thức)", "Bài học, playbook, kết luận tái sử dụng được tích lũy từ các sự cố."),
        ("LLM", "Large Language Model - mô hình ngôn ngữ lớn (Claude, GPT...)."),
        ("LogonType", "Trường trong 4624/4625 cho biết cách đăng nhập (2 Interactive, 3 Network, 10 RDP...)."),
        ("MCP", "Model Context Protocol - chuẩn mở để tác tử kết nối công cụ và dữ liệu."),
        ("MSSP / MDR", "Nhà cung cấp dịch vụ an ninh quản lý / phát hiện và phản ứng quản lý (thuê ngoài SOC)."),
        ("MTTD / MTTA / MTTR", "Thời gian trung bình để phát hiện / tiếp nhận / xử lý sự cố."),
        ("Normalization (chuẩn hóa)", "Đưa log nhiều định dạng về một lược đồ chung."),
        ("Orchestrator", "Thành phần điều phối chuỗi tác tử và ghi nhật ký lượt chạy."),
        ("Playbook", "Quy trình xử lý một loại sự cố; trong ASP là tác vụ Python tự động quanh Case."),
        ("PRI", "Số ưu tiên syslog = facility × 8 + severity."),
        ("Pyramid of Pain", "Mô hình xếp chỉ dấu theo mức khó thay đổi của kẻ tấn công (hash → TTP)."),
        ("Rule engine", "Bộ máy đánh giá luật phát hiện trên dòng sự kiện."),
        ("SIEM / SIM / SEM", "Security Information and Event Management và hai dòng tiền thân."),
        ("Sigma", "Định dạng luật phát hiện YAML độc lập nền tảng."),
        ("SOAR", "Security Orchestration, Automation and Response - tự động hóa phản ứng theo playbook."),
        ("SOC", "Security Operations Center - trung tâm điều hành an ninh."),
        ("Spool", "Lưu tạm dữ liệu chưa gửi ra đĩa để gửi lại sau."),
        ("Structured outputs", "Ép đầu ra của LLM theo JSON schema."),
        ("Sysmon", "System Monitor của Sysinternals ghi sự kiện tiến trình, mạng, tệp chi tiết trên Windows."),
        ("Threat hunting", "Chủ động tìm dấu hiệu xâm nhập chưa có luật phát hiện."),
        ("Threat intelligence (TI)", "Tình báo về mối đe dọa: IOC, TTP, chiến dịch."),
        ("Tool use (function calling)", "Cơ chế LLM yêu cầu ứng dụng thực thi một hàm và nhận kết quả."),
        ("Triage (phân loại)", "Đánh giá nhanh cảnh báo để quyết định ưu tiên và hướng xử lý."),
        ("TTP", "Tactics, Techniques, Procedures - hành vi của kẻ tấn công."),
        ("UEBA", "User and Entity Behavior Analytics - phân tích hành vi để phát hiện bất thường."),
        ("Verdict", "Kết luận về cảnh báo: tấn công thật, đáng ngờ, dương tính giả."),
        ("WAL", "Write-Ahead Logging - chế độ ghi của SQLite cho phép đọc/ghi đồng thời."),
        ("wevtutil", "Công cụ dòng lệnh Windows để truy vấn và quản lý Event Log."),
        ("XPath", "Ngôn ngữ truy vấn XML dùng để lọc sự kiện Windows."),
    ]
    table(["Thuật ngữ", "Giải thích"], [[t, d] for t, d in terms], widths=[1.9, 4.6], size=10)
    page_break()

    # ------------------------------------------------------------------ TÀI LIỆU THAM KHẢO
    h1("TÀI LIỆU THAM KHẢO")
    refs = [
        ("Microsoft Security, \"What is a security operations center (SOC)?\"", "https://www.microsoft.com/en-us/security/business/security-101/what-is-a-security-operations-center-soc"),
        ("IBM, \"What is SIEM?\"", "https://www.ibm.com/think/topics/siem"),
        ("IBM, \"What is a security operations center (SOC)?\"", "https://www.ibm.com/think/topics/security-operations-center"),
        ("IBM, \"Cost of a Data Breach Report 2024\"", "https://www.ibm.com/reports/data-breach"),
        ("Mandiant, \"M-Trends 2024\"", "https://cloud.google.com/security/resources/m-trends"),
        ("NIST, SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management (2025)", "https://csrc.nist.gov/pubs/sp/800/61/r3/final"),
        ("NIST, SP 800-92, Guide to Computer Security Log Management (2006)", "https://csrc.nist.gov/pubs/sp/800/92/final"),
        ("NIST, Cybersecurity Framework 2.0 (2024)", "https://www.nist.gov/cyberframework"),
        ("MITRE, ATT&CK Enterprise Matrix", "https://attack.mitre.org/matrices/enterprise/"),
        ("Lockheed Martin, \"The Cyber Kill Chain\"", "https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html"),
        ("D. Bianco, \"The Pyramid of Pain\" (2013)", "https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html"),
        ("R. van Os, SOC-CMM", "https://www.soc-cmm.com/"),
        ("Elastic, Elastic Stack documentation", "https://www.elastic.co/elastic-stack"),
        ("Elastic, Elastic Common Schema (ECS) Reference", "https://www.elastic.co/guide/en/ecs/current/index.html"),
        ("Elastic, Winlogbeat / Filebeat Reference", "https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html"),
        ("Elastic, Detection rules repository", "https://github.com/elastic/detection-rules"),
        ("Wazuh, Wazuh documentation - Architecture", "https://documentation.wazuh.com/current/getting-started/architecture.html"),
        ("Wazuh, Ruleset: decoders and rules", "https://documentation.wazuh.com/current/user-manual/ruleset/index.html"),
        ("Prometheus Authors, Prometheus documentation", "https://prometheus.io/docs/introduction/overview/"),
        ("SigmaHQ, Sigma detection format", "https://sigmahq.io/"),
        ("funnywolf, Agentic SOC Platform - GitHub repository (MIT)", "https://github.com/funnywolf/agentic-soc-platform"),
        ("Agentic SOC Platform documentation - Overview", "https://asp.viperrtp.com/asp/overview/"),
        ("Agentic SOC Platform documentation - Deployment, Workspace (Case/Alert/Artifact/Playbook/Knowledge), Development (Playbook), Settings (SIEM)", "https://asp.viperrtp.com/asp/quick-start/deployment/"),
        ("Microsoft Learn, \"Appendix L: Events to Monitor\"", "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor"),
        ("Microsoft Learn, Advanced security audit policy settings", "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings"),
        ("Microsoft Learn, Windows Event Log (Win32 API)", "https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log"),
        ("Microsoft Learn, wevtutil command reference", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil"),
        ("Microsoft Learn, Audit events 4624 / 4625", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624"),
        ("Microsoft, Sysmon (Sysinternals)", "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"),
        ("IETF, RFC 5424 - The Syslog Protocol (2009)", "https://www.rfc-editor.org/rfc/rfc5424"),
        ("IETF, RFC 3164 - The BSD syslog Protocol (2001)", "https://www.rfc-editor.org/rfc/rfc3164"),
        ("IETF, RFC 5737 - IPv4 Address Blocks Reserved for Documentation (2010)", "https://www.rfc-editor.org/rfc/rfc5737"),
        ("freedesktop.org, systemd journalctl(1) manual", "https://www.freedesktop.org/software/systemd/man/latest/journalctl.html"),
        ("rsyslog documentation", "https://www.rsyslog.com/doc/"),
        ("Linux Audit documentation", "https://github.com/linux-audit/audit-documentation"),
        ("Apache Software Foundation, Apache HTTP Server - Log Files", "https://httpd.apache.org/docs/2.4/logs.html"),
        ("Nginx, ngx_http_log_module", "https://nginx.org/en/docs/http/ngx_http_log_module.html"),
        ("Anthropic, Claude Developer Platform documentation", "https://platform.claude.com/docs"),
        ("Anthropic, \"Building effective agents\" (2024)", "https://www.anthropic.com/research/building-effective-agents"),
        ("Model Context Protocol specification", "https://modelcontextprotocol.io/"),
        ("Flask documentation", "https://flask.palletsprojects.com/"),
        ("SQLAlchemy 2.0 documentation", "https://docs.sqlalchemy.org/en/20/"),
        ("Python documentation, ipaddress module", "https://docs.python.org/3/library/ipaddress.html"),
        ("OWASP, Cross-Site Request Forgery Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"),
        ("OWASP, Logging Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"),
        ("OWASP, Top 10 (2021)", "https://owasp.org/Top10/"),
        ("ISO/IEC 27001:2022 Information security management systems", "https://www.iso.org/standard/27001"),
        ("PCI Security Standards Council, PCI DSS v4.0", "https://www.pcisecuritystandards.org/"),
        ("Quốc hội, Luật An toàn thông tin mạng 86/2015/QH13; Luật An ninh mạng 24/2018/QH14", "https://vanban.chinhphu.vn/"),
        ("Chính phủ, Nghị định 85/2016/NĐ-CP; Nghị định 13/2023/NĐ-CP; Bộ TT&TT, Thông tư 12/2022/TT-BTTTT; TCVN 11930:2017", "https://vanban.chinhphu.vn/"),
    ]
    for i, (t, u) in enumerate(refs, 1):
        p = doc.add_paragraph()
        p.add_run("[%d] %s. " % (i, t))
        add_hyperlink(p, u)
    page_break()

    # ------------------------------------------------------------------ PHỤ LỤC
    parsers, DEFAULT_RULES, DEFAULT_KNOWLEDGE, DEMO_IP_REPUTATION = _load_code_tables()
    h1("PHỤ LỤC")
    h2("Phụ lục A. Bộ luật phát hiện mặc định (sinh từ soc_server/app/seed.py)")
    for (code_, name, rtype, sev, cond, thr, win, group_by, distinct, title_t, tactic, tech, desc) in DEFAULT_RULES:
        h4("%s - %s" % (code_, name))
        table(["Thuộc tính", "Giá trị"], [
            ["Loại / mức", "%s / %s" % (rtype, sev)],
            ["Điều kiện (JSON)", json.dumps(cond, ensure_ascii=False)],
            ["Ngưỡng / cửa sổ / gom nhóm / distinct", "%s / %s s / %s / %s" % (thr or "-", win or "-", group_by, distinct or "-")],
            ["Mẫu tiêu đề", title_t],
            ["MITRE", "%s %s" % (tactic or "-", tech or "")],
            ["Mô tả", desc],
        ], widths=[1.8, 4.7], size=9)
    new_section(landscape=True)        # bảng nhiều cột -> trang ngang
    h2("Phụ lục B. Bảng ánh xạ của bộ phân tích (sinh từ parsers.py)")
    h3("B.1. Windows EventID → trường chuẩn hóa")
    rows = []
    for eid, (action, outcome, category, severity, ufield, ipfield) in sorted(parsers.WINDOWS_EVENT_MAP.items(), key=lambda kv: int(kv[0])):
        rows.append([eid, parsers.WINDOWS_EVENT_DESCRIPTIONS.get(eid, ""), action, outcome, category, severity, ufield or "-", ipfield or "-"])
    table(["EventID", "Mô tả", "action", "outcome", "category", "severity", "Trường user", "Trường IP"], rows,
          widths=[0.7, 2.6, 1.9, 0.8, 1.1, 0.8, 1.2, 1.0], size=8.5)
    h3("B.2. Mẫu regex cho log Linux (AUTH_PATTERNS)")
    rows = [[i + 1, rx.pattern, action, outcome, category, severity, eid] for i, (rx, action, outcome, category, severity, eid) in enumerate(parsers.AUTH_PATTERNS)]
    table(["#", "Regex", "action", "outcome", "category", "severity", "event_id"], rows,
          widths=[0.4, 4.6, 1.6, 0.8, 1.1, 0.8, 1.2], size=8.5)
    new_section(landscape=False)
    h3("B.3. Các bảng ánh xạ khác")
    table(["Bảng", "Nội dung"], [
        ["SYSLOG_SEVERITY_MAP", json.dumps(parsers.SYSLOG_SEVERITY_MAP)],
        ["WINDOWS_LEVEL_MAP", json.dumps(parsers.WINDOWS_LEVEL_MAP)],
        ["PRIVILEGED_GROUPS", ", ".join(parsers.PRIVILEGED_GROUPS)],
        ["PRIVILEGED_USERS", ", ".join(parsers.PRIVILEGED_USERS)],
        ["WEB_SUSPECT_MARKERS", ", ".join(parsers.WEB_SUSPECT_MARKERS)],
        ["WEB_SCANNER_AGENTS", ", ".join(parsers.WEB_SCANNER_AGENTS)],
        ["WINDOWS_CHANNEL_SOURCE", json.dumps(parsers.WINDOWS_CHANNEL_SOURCE)],
    ], widths=[1.9, 4.6], size=9)
    h3("B.4. Dữ liệu khởi tạo khác")
    table(["IP", "Verdict", "Nguồn", "Ghi chú"], [list(r) for r in DEMO_IP_REPUTATION], widths=[1.3, 0.9, 0.9, 3.4], size=9.5)
    for k in DEFAULT_KNOWLEDGE:
        h4(k["title"])
        para("Loại: %s · Thẻ: %s · MITRE: %s" % (k["category"], k["tags"], k.get("mitre_technique", "")), italic=True, size=11)
        code(k["content"], size=9)

    h2("Phụ lục C. Mẫu sự kiện chuẩn hóa (JSON)")
    para("Sự kiện Windows 4625 sau chuẩn hóa:")
    code('{\n  "timestamp": "2026-10-26T03:30:00.123456Z",\n  "source": "windows.security",\n  "category": "authentication",\n  "action": "logon_failed",\n  "outcome": "failure",\n  "severity": "medium",\n  "event_id": "4625",\n  "message": "Đăng nhập thất bại - Tài khoản: Administrator, IP nguồn: 203.0.113.66",\n  "user": "Administrator",\n  "src_ip": "203.0.113.66",\n  "src_port": 50123,\n  "process": "Microsoft-Windows-Security-Auditing",\n  "pid": null,\n  "host": "WIN-SRV01",\n  "raw": "<Event xmlns=...>...</Event>",\n  "extra": {"channel": "Security", "record_id": "88123", "level": 0, "keywords": "0x8010000000000000",\n            "TargetUserName": "Administrator", "TargetDomainName": "WIN-SRV01", "Status": "0xc000006d",\n            "SubStatus": "0xc000006a", "LogonType": "10", "IpAddress": "203.0.113.66", "IpPort": "50123"}\n}', size=9)
    para("Sự kiện Linux SSH sau chuẩn hóa:")
    code('{\n  "timestamp": "2026-10-26T03:15:01.000000Z",\n  "source": "linux.auth",\n  "category": "authentication",\n  "action": "logon_failed",\n  "outcome": "failure",\n  "severity": "medium",\n  "event_id": "ssh_failed_password",\n  "message": "Failed password for root from 203.0.113.66 port 51234 ssh2",\n  "user": "root",\n  "src_ip": "203.0.113.66",\n  "src_port": 51234,\n  "process": "sshd",\n  "pid": 2231,\n  "host": "web01",\n  "raw": "Oct 26 10:15:01 web01 sshd[2231]: Failed password for root from 203.0.113.66 port 51234 ssh2",\n  "extra": {"offset": 48213}\n}', size=9)
    para("Sự kiện web access log sau chuẩn hóa:")
    code('{\n  "timestamp": "2026-10-26T03:21:00.000000Z",\n  "source": "web.access",\n  "category": "web",\n  "action": "web_suspicious_request",\n  "outcome": "unknown",\n  "severity": "high",\n  "event_id": "web_suspicious",\n  "message": "198.51.100.23 GET /index.php?page=../../../../etc/passwd -> 403",\n  "user": null, "src_ip": "198.51.100.23", "src_port": null, "process": "httpd", "pid": null, "host": "web01",\n  "raw": "198.51.100.23 - - [26/Oct/2026:10:21:00 +0700] \\"GET /index.php?page=../../../../etc/passwd HTTP/1.1\\" 403 512 \\"-\\" \\"Mozilla/5.0\\"",\n  "extra": {"method": "GET", "url": "/index.php?page=../../../../etc/passwd", "status": 403, "size": "512", "user_agent": "Mozilla/5.0", "referer": "-"}\n}', size=9)

    h2("Phụ lục D. Tham chiếu cấu hình")
    h3("D.1. Web SOC (soc_server/config.py, ghi đè bằng biến môi trường)")
    table(["Tham số", "Biến môi trường", "Mặc định", "Ý nghĩa"], [
        ["SECRET_KEY", "SOC_SECRET_KEY", "(chuỗi demo - phải đổi)", "Ký cookie phiên"],
        ["SESSION_COOKIE_SECURE", "SOC_HTTPS=1", "False", "Chỉ gửi cookie qua HTTPS"],
        ["PERMANENT_SESSION_LIFETIME", "-", "8 giờ", "Hạn phiên đăng nhập"],
        ["MAX_CONTENT_LENGTH", "-", "16 MB", "Kích thước tối đa một yêu cầu"],
        ["CSRF_ENABLED", "-", "True", "Bật chống CSRF"],
        ["SQLALCHEMY_DATABASE_URI", "SOC_DATABASE_URI", "sqlite:///instance/soc.db", "CSDL (PostgreSQL: postgresql+psycopg://...)"],
        ["ENROLLMENT_TOKEN", "SOC_ENROLLMENT_TOKEN", "soc-enroll-2026 (phải đổi)", "Token đăng ký agent"],
        ["AGENT_OFFLINE_AFTER", "SOC_AGENT_OFFLINE_AFTER", "180 s", "Đánh dấu agent offline"],
        ["MAX_EVENTS_PER_BATCH", "-", "2000", "Sự kiện tối đa mỗi lô"],
        ["RETENTION_DAYS", "SOC_RETENTION_DAYS", "30", "Thời gian giữ log_events"],
        ["AGENT_INTERVAL_SECONDS / HEARTBEAT / BATCH_SIZE", "SOC_AGENT_INTERVAL / SOC_AGENT_HEARTBEAT / SOC_AGENT_BATCH_SIZE", "10 / 60 / 500", "Cấu hình tập trung gửi xuống agent"],
        ["PAGE_SIZE", "-", "50", "Số dòng mỗi trang"],
        ["TIMEZONE", "SOC_TIMEZONE", "Asia/Ho_Chi_Minh", "Múi giờ hiển thị"],
        ["LOGIN_MAX_FAILURES / LOGIN_LOCK_SECONDS", "-", "5 / 300", "Khóa đăng nhập"],
        ["ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", "(trống = chế độ cục bộ)", "Khóa Claude API"],
        ["AI_MODEL", "SOC_AI_MODEL", "claude-opus-5-5", "Mô hình"],
        ["AI_AUTO_TRIAGE", "SOC_AI_AUTO_TRIAGE", "1", "Tự động enrich + triage cảnh báo mới"],
        ["AI_MAX_TOOL_ITERATIONS", "-", "8", "Số vòng gọi công cụ tối đa"],
        ["AI_EFFORT", "SOC_AI_EFFORT", "medium", "Mức suy luận"],
    ], widths=[1.9, 1.7, 1.3, 1.6], size=9)
    h3("D.2. SOC Agent (config.json)")
    code('{\n  "server": "https://soc.example.local:5000",\n  "enrollment_token": "soc-enroll-2026",\n  "hostname": null,\n  "interval_seconds": 10,\n  "heartbeat_seconds": 60,\n  "batch_size": 500,\n  "max_queue": 50000,\n  "verify_tls": true,\n  "follow_server_config": true,\n  "collectors": [\n    {"type": "winevt", "name": "windows-security", "channel": "Security",\n     "event_ids": [4624, 4625, 4672, 4688, 4720, 4724, 4732, 4740, 1102]},\n    {"type": "winevt", "name": "sysmon", "channel": "Microsoft-Windows-Sysmon/Operational", "event_ids": [1, 3, 11, 22]},\n    {"type": "file", "name": "nginx-access", "path": "/var/log/nginx/access.log", "format": "access_log", "source": "web.access"},\n    {"type": "file", "name": "linux-auth", "path": "/var/log/auth.log", "format": "syslog", "source": "linux.auth"},\n    {"type": "journald", "name": "journald", "units": ["ssh.service", "sudo"]}\n  ]\n}', size=9)
    h3("D.3. Tệp dịch vụ")
    code("# soc_agent/install/soc-agent.service\n[Unit]\nDescription=Agentic SOC Platform - SOC Agent\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nWorkingDirectory=/opt/soc_agent\nExecStart=/usr/bin/python3 /opt/soc_agent/agent.py\nRestart=always\nRestartSec=10\nUser=root\n[Install]\nWantedBy=multi-user.target\n\n# soc_agent/install/install_windows_task.ps1 (rút gọn)\n$action    = New-ScheduledTaskAction -Execute python -Argument \"agent.py\" -WorkingDirectory $AgentDir\n$trigger   = New-ScheduledTaskTrigger -AtStartup\n$principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest\n$settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)\nRegister-ScheduledTask -TaskName SOCAgent -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force", size=9)

    h2("Phụ lục E. Lệnh vận hành nhanh")
    code("# Cài đặt\npip install -r requirements.txt\n\n# Web SOC\ncd soc_server && python run.py --port 5000\n# (tùy chọn) bật đường LLM\nset ANTHROPIC_API_KEY=sk-ant-...      # Windows\nexport ANTHROPIC_API_KEY=sk-ant-...   # Linux\n# Triển khai thật\nset SOC_SECRET_KEY=<ngẫu nhiên dài>  SOC_ENROLLMENT_TOKEN=<bí mật>  SOC_HTTPS=1  SOC_DATABASE_URI=postgresql+psycopg://...\n\n# Agent\ncd soc_agent\npython agent.py --server http://IP_SOC:5000 --token soc-enroll-2026 --register --once\npython agent.py\n\n# Dữ liệu trình diễn (vào soc.db đang chạy) hoặc tái tạo CSDL demo riêng (soc_demo.db)\npython tools/demo_attack.py --server http://127.0.0.1:5000 --token soc-enroll-2026\npython tools/rebuild_demo.py\n\n# Kiểm thử\npython tools/test_parsers.py\npython tools/test_collectors.py\npython tools/test_e2e.py\n\n# Sinh lại hình và báo cáo này\npython tools/report_figures.py\npython tools/report_figures_extra.py\npython tools/build_report_detail.py")
    h2("Phụ lục F. Cấu trúc mã nguồn và thống kê")
    table(["Thành phần", "Tệp", "Dòng (≈)", "Ghi chú"], [
        ["SOC Agent", "agent.py, collectors.py, parsers.py", "370 + 290 + 610", "Chỉ thư viện chuẩn"],
        ["Web SOC - lõi", "__init__.py, config.py, run.py, models.py, auth.py, api.py, views.py", "260 + 55 + 40 + 430 + 135 + 230 + 560", "Flask + SQLAlchemy"],
        ["Web SOC - xử lý", "ingest.py, detection.py, enrichment.py, stats.py, seed.py, parsers.py", "100 + 270 + 215 + 150 + 170 + 610", "Pipeline và luật"],
        ["Web SOC - AI", "ai/llm.py, tools.py, agents.py, orchestrator.py", "145 + 160 + 460 + 150", "Bốn tác tử"],
        ["Giao diện", "22 template HTML, style.css, soc.js", "≈ 1.500", "Bootstrap 5, Chart.js"],
        ["Công cụ", "demo_attack.py, rebuild_demo.py, test_*.py (3), report_*.py (3), build_report*.py (2), report_parts/ (10)", "≈ 4.500", "Demo, kiểm thử, báo cáo"],
    ], widths=[1.3, 2.6, 1.4, 1.2], size=9.5)
