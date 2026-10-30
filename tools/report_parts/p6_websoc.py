# -*- coding: utf-8 -*-
"""PHẦN 6. ỨNG DỤNG WEB SOC CÓ DASHBOARD - mở rộng."""
from report_lib import *  # noqa: F401,F403

P = "6"


def build():
    h1("PHẦN 6. ỨNG DỤNG WEB SOC CÓ DASHBOARD")
    h2("6.1. Kiến trúc tổng thể và công nghệ")
    figure("d3_architecture.png", "Kiến trúc hệ thống và luồng dữ liệu", P, 6.5)
    table(["Thành phần", "Công nghệ", "Vai trò"], [
        ["Web framework", "Flask 3 + Jinja2, blueprint auth / api / main", "Định tuyến, phiên đăng nhập, render giao diện"],
        ["ORM / CSDL", "SQLAlchemy 2 + SQLite (WAL, foreign_keys ON)", "11 bảng; có thể đổi sang PostgreSQL qua SOC_DATABASE_URI"],
        ["Giao diện", "Bootstrap 5, Bootstrap Icons, Chart.js 4, soc.js", "Dashboard tự làm mới 30 s qua /api/v1/stats"],
        ["AI", "Anthropic SDK (claude-opus-5-5), structured outputs, tool use; fallback cục bộ", "Bốn tác tử + orchestrator"],
        ["Luồng nền", "threading (daemon)", "Đánh dấu agent offline (180 s), xóa log quá hạn (30 ngày), chạy tác tử AI tự động"],
        ["Bảo mật", "Werkzeug (băm mật khẩu), session cookie HttpOnly/SameSite/Secure, CSRF token, API key SHA-256", "Xem 6.8"],
        ["Cấu hình", "config.py + biến môi trường SOC_*", "12 tham số (Phụ lục D)"],
    ], widths=[1.3, 2.6, 2.6], size=10, caption="Công nghệ của Web SOC", part=P)
    code("soc_server/\n  run.py                  # điểm khởi chạy (--port, --init-only, --debug)\n  config.py               # cấu hình, ghi đè bằng biến môi trường SOC_*\n  app/__init__.py         # application factory, CSRF, cảnh báo cấu hình, luồng bảo trì, bộ lọc Jinja\n  app/models.py           # 11 bảng ORM\n  app/auth.py             # đăng nhập, khóa tài khoản, phân quyền, audit\n  app/api.py              # REST API cho agent và giao diện\n  app/views.py            # 30+ trang giao diện\n  app/ingest.py           # tiếp nhận, chuẩn hóa, chống trùng\n  app/detection.py        # Rule Engine\n  app/enrichment.py       # làm giàu ngữ cảnh\n  app/stats.py            # thống kê dashboard/báo cáo\n  app/seed.py             # tài khoản, 21 luật, uy tín IP, playbook mẫu\n  app/parsers.py          # bản sao của soc_agent/parsers.py\n  app/ai/{llm,tools,agents,orchestrator}.py\n  app/templates/*.html (22 mẫu), app/static/{css/style.css, js/soc.js}\n  instance/soc.db         # SQLite")
    h3("6.1.1. Khởi tạo ứng dụng (application factory)")
    code("def create_app(config_object=None, start_background=True):\n    app = Flask(__name__); app.config.from_object(config_object or Config)\n    app.json = SOCJSONProvider(app)              # JSON tiếng Việt không escape, datetime ISO\n    db.init_app(app)\n    with app.app_context():\n        @event.listens_for(db.engine, \"connect\")\n        def _sqlite_pragmas(conn, _):             # WAL, synchronous=NORMAL, foreign_keys=ON\n            ...\n        db.create_all(); seed_all()              # tạo bảng + dữ liệu mặc định (idempotent)\n    app.register_blueprint(auth_bp); app.register_blueprint(api_bp); app.register_blueprint(main_bp)\n    app.before_request(load_current_user)\n    _register_csrf(app); _warn_insecure_defaults(app)\n    app.extensions[\"soc_orchestrator\"] = SOCOrchestrator(app)\n    _register_template_helpers(app); _register_error_handlers(app)\n    if start_background: _start_maintenance(app)\n    return app", size=9)
    para("Mẫu *application factory* cho phép kiểm thử tạo ứng dụng với cấu hình riêng (CSDL tạm, tắt luồng nền) - chính là cách `tools/test_e2e.py` hoạt động. SQLite chạy chế độ WAL để luồng AI nền ghi trong khi request đọc không bị khóa.")

    h2("6.2. Thiết kế cơ sở dữ liệu")
    figure("d2_erd.png", "Sơ đồ thực thể - liên kết", P, 6.5)
    table(["Bảng", "Cột chính", "Ghi chú"], [
        ["users", "username, password_hash, role (admin/analyst/viewer), is_active, failed_logins, last_login", "Mật khẩu băm scrypt/PBKDF2"],
        ["agents", "agent_uid, hostname, os_type, os_version, ip_address, api_key_hash, api_key_prefix, status, last_seen, events_count, collectors(JSON), metrics(JSON)", "Khóa API chỉ lưu băm"],
        ["log_events", "agent_id, received_at, event_time, source, category, action, outcome, severity, event_id, message, user_name, src_ip, src_port, process_name, pid, host, raw, extra(JSON), event_hash(unique)", "Chỉ mục trên các cột lọc"],
        ["detection_rules", "code, name, rule_type, enabled, severity, conditions(JSON), threshold_count, window_seconds, group_by, distinct_field, title_template, mitre_tactic, mitre_technique, hits", "21 luật mặc định is_builtin"],
        ["alerts", "rule_id, agent_id, title, description, severity, status, priority, event_count, first/last_event_time, src_ip, user_name, host, mitre_*, dedup_key, assigned_to, ai_verdict, ai_confidence, ai_priority, ai_summary, ai_data(JSON), ai_mode, resolution_note, resolved_at/by", "Trạng thái new → triaged → investigating → resolved / false_positive"],
        ["alert_events", "alert_id, event_id", "Liên kết N-N bằng chứng, ON DELETE CASCADE"],
        ["investigations", "alert_id, created_by, mode, hypothesis, summary, timeline(JSON), attack_chain(JSON), iocs(JSON), impact, root_cause, recommendations(JSON)", "Mỗi lần điều tra một bản ghi"],
        ["knowledge_articles", "title, summary, content(Markdown), category, tags, source(manual/ai), related_alert_id, related_rule_id, mitre_technique, times_used", "Cơ sở tri thức"],
        ["ai_runs", "alert_id, agent_name, mode(llm/local), model, trigger, started/finished_at, duration_ms, input/output_tokens, tool_calls(JSON), output(JSON), status, error", "Kiểm toán và chi phí AI"],
        ["audit_logs", "user_id, username, action, target, detail, ip, success", "Mọi thao tác quan trọng"],
        ["ip_reputation", "ip(unique), verdict(malicious/suspicious/clean), source, note", "Blocklist/allowlist cục bộ"],
    ], widths=[1.3, 3.6, 1.6], size=9, caption="Các bảng của CSDL", part=P)
    h3("6.2.1. Chỉ mục và hiệu năng truy vấn")
    table(["Bảng", "Chỉ mục", "Truy vấn được tăng tốc"], [
        ["log_events", "event_time, received_at, agent_id, source, category, action, severity, event_id, user_name, src_ip, host, event_hash (unique)", "Lọc trang log, cửa sổ thời gian của luật threshold (event_time + src_ip), chống trùng (event_hash IN)"],
        ["alerts", "rule_id, agent_id, created_at, severity, status, src_ip, user_name, host, dedup_key", "Danh sách cảnh báo, dedup, cảnh báo liên quan"],
        ["ai_runs, investigations", "alert_id", "Trang chi tiết cảnh báo"],
        ["users, agents", "username, hostname, api_key_hash (unique)", "Đăng nhập, xác thực agent"],
    ], widths=[1.2, 3.0, 2.3], size=9.5, caption="Chỉ mục chính", part=P)
    para("Với SQLite, 1 triệu sự kiện vẫn truy vấn dưới 100 ms cho các bộ lọc có chỉ mục; tìm kiếm toàn văn (`q=`) dùng LIKE nên chậm hơn - hướng phát triển là FTS5 hoặc chuyển sang PostgreSQL/OpenSearch.")
    h3("6.2.2. Chính sách lưu trữ")
    para("Luồng bảo trì chạy mỗi 30 giây: đánh dấu agent offline khi `last_seen` cũ hơn 180 giây; mỗi giờ xóa `log_events` cũ hơn RETENTION_DAYS (30). Vì `alert_events` có ON DELETE CASCADE, bằng chứng của cảnh báo cũ sẽ mất liên kết nhưng bản ghi cảnh báo, điều tra và tri thức được giữ vô thời hạn - phù hợp yêu cầu tuân thủ (giữ kết luận) mà vẫn kiểm soát dung lượng.")

    h2("6.3. Pipeline tiếp nhận log (ingest.py)")
    figure("32_ingest_detail.png", "Pipeline tiếp nhận một lô log", P, 6.5)
    code("def ingest(agent, payload_events, run_rules=True):\n    candidates, seen = [], set()\n    for raw in payload_events[:MAX_EVENTS_PER_BATCH]:\n        if raw.get(\"raw\") and not raw.get(\"message\") and not raw.get(\"action\"):   # dòng thô -> server tự phân tích\n            raw = parsers.parse_line(raw[\"raw\"], raw.get(\"source\"), agent.hostname, raw.get(\"format\", \"syslog\"))\n        ev = build_event(raw, agent)              # normalize_event + LogEvent(...) + event_hash\n        if ev.event_hash in seen: duplicates += 1; continue\n        seen.add(ev.event_hash); candidates.append(ev)\n    existing = {h for chunk in chunks(hashes, 500) for (h,) in db.session.query(LogEvent.event_hash).filter(LogEvent.event_hash.in_(chunk))}\n    new_events = [c for c in candidates if c.event_hash not in existing]\n    db.session.add_all(new_events); agent.last_seen = utcnow(); agent.status = \"online\"; db.session.commit()\n    alerts = RuleEngine().evaluate(new_events) if run_rules and new_events else []\n    return {\"received\": ..., \"accepted\": len(new_events), \"duplicates\": ..., \"rejected\": ..., \"alerts\": alerts}", size=9)
    para("`compute_hash` dùng định danh gốc nếu có (`record_id` của Windows, `cursor` của journald, `offset` của tệp, `sim_id` của demo) kết hợp với 500 ký tự đầu của raw, nên hai dòng log giống hệt nhau ở hai vị trí khác nhau trong tệp vẫn là hai sự kiện, còn cùng một dòng gửi lại thì bị loại.")

    h2("6.4. Bộ máy luật phát hiện (detection.py)")
    figure("17_rule_types.png", "Ba loại luật trên trục thời gian", P, 6.5)
    h3("6.4.1. Cú pháp điều kiện")
    para("Điều kiện của luật là JSON với các khóa AND: `source`, `event_id`, `action`, `category`, `outcome`, `host`, `process` (giá trị đơn hoặc danh sách = OR), `severity_min`, `user_in`, "
         "`regex`/`not_regex` trên `field` (mặc định message, hỗ trợ `extra.<key>`), `extra{key: [values]}`, `src_ip_public`. Luật sequence có `precondition`, `trigger`, `min_count`. "
         "Các điều kiện đơn giản được đẩy xuống SQL; regex/extra lọc bằng Python trên tối đa 5000 ứng viên. Gom nhóm theo `group_by` với cơ chế lùi dần src_ip → user_name → host khi sự kiện thiếu IP (đăng nhập cục bộ).")
    code("# Ví dụ luật tùy chỉnh\n# 1. SQL injection trong URL (match, regex trên extra.url)\n{\"category\": \"web\", \"field\": \"extra.url\", \"regex\": \"(union\\\\s+select|'\\\\s*or\\\\s*'?1'?\\\\s*=\\\\s*'?1|sleep\\\\()\"}\n# 2. Đăng nhập RDP ngoài giờ bằng tài khoản quản trị (match, extra + user_in)\n{\"source\": \"windows.security\", \"event_id\": [\"4624\"], \"extra\": {\"LogonType\": [\"10\"]}, \"user_in\": [\"administrator\", \"admin\"]}\n# 3. Dịch vụ cài từ thư mục tạm (match, regex trên extra.ImagePath)\n{\"event_id\": [\"7045\"], \"field\": \"extra.ImagePath\", \"regex\": \"(\\\\\\\\Temp\\\\\\\\|\\\\\\\\AppData\\\\\\\\|\\\\\\\\Users\\\\\\\\Public\\\\\\\\)\"}\n# 4. Nhiều lệnh sudo thất bại của cùng người (threshold, group_by user_name)\n{\"action\": [\"sudo_failed\", \"sudo_auth_failure\"]}   # threshold_count 3, window_seconds 300, group_by user_name\n# 5. Tạo tài khoản rồi thêm vào nhóm đặc quyền trong 10 phút (sequence)\n{\"precondition\": {\"action\": [\"user_created\"]}, \"trigger\": {\"action\": [\"member_added_to_privileged_group\", \"user_added_to_privileged_group\"]}, \"min_count\": 1}", size=9)
    h3("6.4.2. Thuật toán đánh giá")
    code("def evaluate(self, events):                  # events đã commit, sắp theo thời gian\n    results = {}\n    for rule in self.rules:                   # các luật đang bật\n        cond = rule.conditions_dict\n        for ev in events:\n            if rule.rule_type == \"match\" and match_conditions(cond, ev):\n                self._raise(rule, ev, [ev], 1, results)\n            elif rule.rule_type == \"threshold\" and match_conditions(cond, ev):\n                gfield, gval = self._group(rule, ev)\n                cands = self._candidates(cond, gfield, gval, ev.event_time - W, ev.event_time)\n                count = len({event_field(c, rule.distinct_field) for c in cands}) if rule.distinct_field else len(cands)\n                if count >= rule.threshold_count: self._raise(rule, ev, cands, count, results)\n            elif rule.rule_type == \"sequence\" and match_conditions(cond[\"trigger\"], ev):\n                cands = self._candidates(cond[\"precondition\"], gfield, gval, ev.event_time - W, ev.event_time)\n                if len(cands) >= min_count: self._raise(rule, ev, cands + [ev], len(cands), results)\n    db.session.commit(); return list(results.values())", size=9)
    figure("33_dedup_example.png", "Ví dụ gộp 18 sự kiện thành một cảnh báo", P, 6.5)
    para("`_raise()` tìm cảnh báo đang mở có cùng `dedup_key` (rule|host|nhóm) và `last_event_time` trong cửa sổ \"nóng\" (2 × max(window, 600 s)); nếu có thì gộp (tăng event_count, cập nhật thời gian, nâng mức nếu luật cao hơn), nếu không thì tạo mới, tăng `hits` của luật và liên kết bằng chứng. "
         "Độ phức tạp: với lô N sự kiện và R luật là O(N × R) lần kiểm tra điều kiện trong bộ nhớ, cộng thêm một truy vấn SQL cho mỗi sự kiện khớp luật threshold/sequence; với lô 500 sự kiện và 21 luật, thời gian thực đo ≈ 50-150 ms trên SQLite.")
    h3("6.4.3. Bộ luật mặc định")
    table(["Mã", "Tên luật", "Loại", "Mức", "Điều kiện chính", "ATT&CK"], [
        ["R01", "Nhật ký kiểm toán Windows bị xóa", "match", "critical", "windows.security, 1102", "T1070.001"],
        ["R02", "Nhật ký System/Application bị xóa", "match", "high", "104", "T1070.001"],
        ["R03", "Tạo tài khoản Windows", "match", "medium", "4720", "T1136.001"],
        ["R04", "Thêm thành viên nhóm đặc quyền", "match", "high", "action member_added_to_privileged_group / user_added_to_privileged_group", "T1098"],
        ["R05", "Cài dịch vụ mới", "match", "medium", "7045 / 4697", "T1543.003"],
        ["R06", "Tạo Scheduled Task", "match", "medium", "4698", "T1053.005"],
        ["R07", "Thay đổi chính sách kiểm toán", "match", "high", "4719", "T1562.002"],
        ["R08", "Tạo tài khoản Linux", "match", "medium", "action user_created, nguồn linux", "T1136.001"],
        ["R09", "sudo/su thất bại", "match", "medium", "sudo_failed, sudo_auth_failure, su_failed", "T1548.003"],
        ["R10", "SSH root trực tiếp", "match", "medium", "ssh_accepted, user root", "T1078"],
        ["R11", "Yêu cầu web đáng ngờ / máy quét", "match", "high", "web_suspicious_request, web_scanner_detected", "T1190"],
        ["R12", "Sự cố ổn định hệ thống", "match", "low", "oom_kill, segfault, service_crashed, unexpected_shutdown, application_crash", "-"],
        ["R13", "Tài khoản bị khóa", "match", "medium", "4740", "T1110"],
        ["R14", "PowerShell đáng ngờ", "match", "high", "powershell_suspicious_script", "T1059.001"],
        ["R15", "Dò mật khẩu SSH", "threshold", "high", "logon_failed linux ≥ 5 / 120 s theo src_ip", "T1110.001"],
        ["R16", "Dò mật khẩu Windows", "threshold", "high", "4625 ≥ 5 / 120 s theo src_ip", "T1110.001"],
        ["R17", "Password spraying", "threshold", "high", "logon_failed/invalid_user, ≥ 5 user khác nhau / 300 s theo src_ip", "T1110.003"],
        ["R18", "Thành công sau nhiều lần thất bại", "sequence", "critical", "logon_success sau ≥ 3 logon_failed / 600 s", "T1110"],
        ["R19", "Dò quét web (4xx)", "threshold", "medium", "web failure ≥ 30 / 60 s theo src_ip", "T1595"],
        ["R20", "Thử nhiều user không tồn tại", "threshold", "medium", "invalid_user ≥ 10 / 300 s", "T1110"],
        ["R21", "RDP từ Internet", "match", "medium", "4624 LogonType 10, src_ip_public", "T1021.001"],
    ], widths=[0.5, 1.7, 0.7, 0.7, 2.0, 0.9], size=8.5, caption="21 luật mặc định (JSON đầy đủ ở Phụ lục A)", part=P)
    h3("6.4.4. Tinh chỉnh luật và chạy lại trên dữ liệu lịch sử")
    para("Trang Luật phát hiện cho phép sửa JSON điều kiện, ngưỡng, cửa sổ, bật/tắt và **chạy lại** toàn bộ luật trên dữ liệu 1 giờ / 24 giờ / 7 ngày (`RuleEngine.evaluate_range`). "
         "Cơ chế dedup bảo đảm chạy lại không tạo cảnh báo trùng cho các vụ đã có. Quy trình khuyến nghị khi thêm luật: viết điều kiện → chạy lại 7 ngày → xem số cảnh báo và tỷ lệ dương tính giả → thêm `not_regex`/`user_in` loại trừ → bật.")

    h2("6.5. Dashboard và các trang giao diện")
    para("Dashboard là trang đầu sau đăng nhập, tự làm mới mỗi 30 giây bằng JSON từ `/api/v1/stats` và vẽ bằng Chart.js:")
    bullets([
        "**4 thẻ KPI:** sự kiện 24 giờ (và tổng), cảnh báo đang mở (và số mức cao/nghiêm trọng), máy trạm trực tuyến/tổng, cảnh báo AI đã phân loại (và số lượt tác tử).",
        "**Biểu đồ:** sự kiện theo giờ (đường), sự kiện theo mức độ (vành khuyên), cảnh báo theo ngày và mức (cột chồng 7 ngày), nguồn log hàng đầu (cột ngang).",
        "**Bảng:** cảnh báo mới nhất (mức, trạng thái, ưu tiên AI, máy), IP nguồn thất bại nhiều nhất, tài khoản bị thử nhiều nhất, trạng thái máy trạm (online/offline, IP, số sự kiện, lần cuối), máy nhiều sự kiện nhất.",
    ])
    figure("02_dashboard.jpg", "Dashboard giám sát an ninh", P, 6.5)
    code("# stats.py - dữ liệu dashboard (rút gọn)\ndef dashboard_stats():\n    since24 = now - timedelta(hours=24)\n    return {\n      \"kpi\": {\"events_24h\": count(LogEvent.event_time >= since24), \"alerts_open\": count(Alert.status in OPEN), ...},\n      \"events_per_hour\": events_per_hour(24),          # GROUP BY strftime('%Y-%m-%d %H', event_time), điền giờ trống = 0\n      \"alerts_per_day\": alerts_per_day(7),             # GROUP BY ngày, severity\n      \"events_by_severity\": ..., \"top_sources\": group_count(LogEvent.source, since24),\n      \"top_src_ips\": group_count(LogEvent.src_ip, since24, where=LogEvent.outcome == \"failure\"),\n      \"latest_alerts\": [...], \"agents\": [...]}\n\n# soc.js - tự làm mới\nasync function refreshDashboard() { const r = await fetch(\"/api/v1/stats\"); if (r.ok) renderDashboard(await r.json()); }\nsetInterval(refreshDashboard, 30000);", size=9)
    table(["Trang", "Chức năng", "Quyền"], [
        ["Cảnh báo (/alerts)", "Lọc theo trạng thái, mức, máy, luật, verdict AI, từ khóa, khoảng thời gian; sắp xếp theo ưu tiên AI/mức/thời gian; xuất CSV", "Mọi vai trò xem; analyst/admin cập nhật"],
        ["Chi tiết cảnh báo (/alerts/<id>)", "Thông tin, bằng chứng (≤ 200 sự kiện), kết quả Enrichment/Triage, các báo cáo điều tra, bài tri thức, nhật ký ai_runs; nút Phân loại lại / Điều tra sâu / Trích xuất tri thức; form đổi trạng thái, mức, người phụ trách, ghi chú", "analyst/admin"],
        ["Nhật ký log (/logs)", "Lọc đa tiêu chí (máy, nguồn, mức, category, action, outcome, event_id, user, IP, từ khóa, thời gian), phân trang 50, chi tiết từng sự kiện kèm raw/extra và cảnh báo liên quan, xuất CSV ≤ 20 000 dòng", "Mọi vai trò"],
        ["Máy trạm (/agents)", "Danh sách, chi tiết (sự kiện 24h theo nguồn/mức, cảnh báo), cấp lại API key, xóa; hiển thị enrollment token và URL server", "Xem: mọi vai trò; cấp lại/xóa: admin"],
        ["Luật phát hiện (/rules)", "Xem 21 luật, bật/tắt, thêm/sửa (form JSON điều kiện), xóa, chạy lại luật trên 1h/24h/7 ngày dữ liệu lịch sử", "analyst/admin; xóa: admin"],
        ["Cơ sở tri thức (/kb)", "Tìm kiếm, lọc theo loại/nguồn, xem Markdown, thêm/sửa/xóa", "analyst/admin sửa"],
        ["Báo cáo & thống kê (/reports)", "Chọn khoảng thời gian; tổng sự kiện/cảnh báo, theo mức, theo category, theo luật, verdict AI, MTTR, top máy/nguồn/IP/user; chế độ in (PDF)", "Mọi vai trò"],
        ["Uy tín IP (/ip-reputation)", "Thêm/xóa IP vào blocklist/allowlist dùng cho enrichment", "analyst/admin"],
        ["Nhật ký thao tác (/audit)", "Lọc theo hành động/người dùng", "analyst/admin"],
        ["Người dùng (/users), Cài đặt (/settings)", "Quản lý tài khoản, vai trò; xem cấu hình, trạng thái AI, thống kê ai_runs theo tác tử/chế độ, kích thước CSDL", "admin"],
        ["Đổi mật khẩu (/profile/password)", "Đổi mật khẩu của chính mình (≥ 8 ký tự)", "Mọi vai trò"],
    ], widths=[1.6, 3.6, 1.3], size=9, caption="Các trang giao diện", part=P)
    figure("03_alerts.jpg", "Danh sách cảnh báo xếp theo ưu tiên AI", P, 6.3)
    figure("04_alert_triage.jpg", "Chi tiết cảnh báo và kết quả phân loại", P, 6.3)
    figure("06_logs.jpg", "Tra cứu log tập trung", P, 6.3)
    figure("07_reports.jpg", "Trang báo cáo và thống kê", P, 6.3)
    figure("08_agents.jpg", "Danh sách máy trạm đã đăng ký", P, 6.3)
    figure("31_alert_lifecycle.png", "Vòng đời trạng thái của cảnh báo", P, 6.3)

    h2("6.6. Lớp Agentic AI")
    figure("d1_pipeline.png", "Bốn tác tử AI trong vòng đời xử lý cảnh báo", P, 4.3)
    h3("6.6.1. Enrichment Agent (tất định)")
    para("Tổng hợp ngữ cảnh từ chính dữ liệu trong SOC, không cần LLM: phân loại IP (công cộng/nội bộ/loopback; dải tài liệu RFC 5737 được xem như Internet trong lab), uy tín IP, lịch sử 7 ngày của IP "
         "(số sự kiện, thất bại, thành công, máy bị nhắm, tài khoản bị thử), ngữ cảnh tài khoản (đặc quyền?, mới xuất hiện?, hoạt động 24h), ngữ cảnh máy (agent, số sự kiện, cảnh báo mở), MITRE, cảnh báo liên quan, "
         "ngữ cảnh thời gian (ngoài giờ, cuối tuần) và tri thức tương tự. Kết quả kèm danh sách `risk_flags` để Triage và người đọc nắm nhanh. Ví dụ kết quả thật cho cảnh báo R18 trên WIN-SRV02:")
    code("{\"ip\": {\"ip\": \"198.51.100.23\", \"type\": \"public\", \"is_public\": true,\n        \"reputation\": {\"verdict\": \"suspicious\", \"source\": \"blocklist\", \"note\": \"Nguồn dò quét web nhiều lần\"},\n        \"history\": {\"days\": 7, \"total_events\": 17, \"failed_auth\": 16, \"success_auth\": 1,\n                    \"hosts_targeted\": [\"WIN-SRV02\"], \"users_tried\": [\"administrator\", \"admin\"]}},\n \"user\": {\"user\": \"administrator\", \"is_privileged\": true, \"events_24h\": 11, \"failed_24h\": 8, \"success_24h\": 1,\n          \"hosts_24h\": [\"WIN-DC01\", \"WIN-SRV02\"], \"is_new_account\": true},\n \"host\": {\"host\": \"WIN-SRV02\", \"os_type\": \"windows\", \"os_version\": \"Windows Server 2019\", \"events_24h\": 87, \"open_alerts\": 2},\n \"mitre\": {\"technique_id\": \"T1110\", \"technique\": \"Brute Force\", \"tactic\": \"Credential Access\"},\n \"related_alerts\": [{\"id\": 7, \"title\": \"Dò mật khẩu Windows từ 198.51.100.23 tới WIN-SRV02 (5 lần thất bại)\", ...}],\n \"time\": {\"local_time\": \"2026-10-26 07:18:20 +07\", \"off_hours\": false, \"weekend\": false},\n \"risk_flags\": [\"IP nguồn là địa chỉ công cộng (từ Internet)\", \"IP nguồn nằm trong danh sách uy tín xấu (suspicious)\",\n                \"IP này đã có 1 lần xác thực THÀNH CÔNG\", \"Tài khoản mục tiêu là tài khoản đặc quyền\", ...],\n \"knowledge_matches\": [{\"id\": 1, \"title\": \"Playbook: Xử lý cảnh báo dò mật khẩu SSH/RDP\", ...}]}", size=8.5)
    h3("6.6.2. Triage Agent")
    figure("18_triage_scoring.png", "Thuật toán chấm điểm rủi ro của Triage Agent", P, 6.5)
    para("Đường LLM gửi cảnh báo + enrichment + ≤ 40 sự kiện mẫu + tri thức liên quan cho Claude và yêu cầu JSON theo `TRIAGE_SCHEMA`. Đường cục bộ chấm điểm heuristic như hình. Kết quả ghi vào alert.ai_* và chuyển trạng thái new → triaged.")
    code("TRIAGE_SCHEMA = {\"type\": \"object\", \"properties\": {\n    \"verdict\": {\"enum\": [\"true_positive\", \"likely_true_positive\", \"suspicious\", \"likely_false_positive\", \"false_positive\"]},\n    \"severity\": {\"enum\": [\"critical\", \"high\", \"medium\", \"low\", \"info\"]},\n    \"priority\": {\"type\": \"integer\", \"minimum\": 1, \"maximum\": 5},\n    \"confidence\": {\"type\": \"number\", \"minimum\": 0, \"maximum\": 1},\n    \"risk_score\": {\"type\": \"integer\", \"minimum\": 0, \"maximum\": 100},\n    \"summary\": {\"type\": \"string\"}, \"reasoning\": {\"type\": \"string\"},\n    \"evidence\": {\"type\": \"array\", \"items\": {\"type\": \"string\"}},\n    \"recommended_actions\": {\"type\": \"array\", \"items\": {\"type\": \"string\"}},\n    \"needs_investigation\": {\"type\": \"boolean\"}, \"mitre_tactic\": {\"type\": \"string\"}, \"mitre_technique\": {\"type\": \"string\"}},\n  \"required\": [...tất cả...], \"additionalProperties\": False}\n\n# Kết quả thật (chế độ cục bộ) cho cảnh báo #19 R18 trên centos-db01\n{\"verdict\": \"true_positive\", \"severity\": \"critical\", \"priority\": 1, \"confidence\": 0.9, \"risk_score\": 100,\n \"evidence\": [\"IP nguồn 203.0.113.66 là địa chỉ công cộng\", \"IP nguồn nằm trong blocklist (malicious)\",\n              \"IP này đã có 1 lần xác thực thành công trong 7 ngày\", \"Tài khoản mục tiêu 'root' là tài khoản đặc quyền\",\n              \"Tài khoản mới xuất hiện trong 24 giờ\", \"Chuỗi sự kiện: thành công sau nhiều lần thất bại\"],\n \"recommended_actions\": [\"Chặn IP nguồn tại firewall / fail2ban\", \"Kiểm tra có đăng nhập thành công nào từ IP này không\", ...],\n \"needs_investigation\": true, \"mitre_tactic\": \"Credential Access\", \"mitre_technique\": \"T1110\"}", size=8.5)
    h3("6.6.3. Investigation Agent")
    figure("19_agentic_loop.png", "Vòng lặp tác tử của Investigation Agent", P, 6.5)
    para("Đường LLM dùng `run_with_tools()`: mô hình được cấp 6 công cụ chỉ-đọc (`query_events`, `lookup_ip`, `get_host_info`, `get_related_alerts`, `search_knowledge`, `mitre_lookup`, đều `strict`), "
         "tự quyết định gọi tối đa 8 vòng, kết quả cuối ép theo `INVESTIGATION_SCHEMA` (hypothesis, summary, timeline, attack_chain, iocs, impact, root_cause, recommendations, confidence). "
         "Đường cục bộ thu sự kiện ±15 phút trên cùng máy và ±60/15 phút từ cùng IP, gộp sự kiện lặp thành dòng thời gian, suy chuỗi ATT&CK từ thứ tự hành vi, trích IOC và sinh giả thuyết theo mẫu. "
         "Kết quả lưu bảng investigations và chuyển trạng thái sang investigating.")
    table(["Công cụ", "Tham số", "Trả về", "Dùng để"], [
        ["query_events", "host, src_ip, user, source, keyword, minutes_before, minutes_after, limit", "Danh sách sự kiện rút gọn quanh thời điểm cảnh báo", "Dựng dòng thời gian, tìm hành động sau đăng nhập"],
        ["lookup_ip", "ip", "Phân loại, uy tín, lịch sử 7 ngày", "Đánh giá IP"],
        ["get_host_info", "host", "HĐH, trạng thái agent, số sự kiện, cảnh báo mở", "Ngữ cảnh máy"],
        ["get_related_alerts", "host, src_ip, user, days", "Cảnh báo liên quan", "Nối các vụ"],
        ["search_knowledge", "query, limit", "Bài tri thức khớp (tăng times_used)", "Áp playbook"],
        ["mitre_lookup", "technique_id", "Tên tactic/kỹ thuật, URL", "Gắn nhãn"],
    ], widths=[1.2, 2.2, 1.7, 1.4], size=9, caption="Sáu công cụ của tác tử", part=P)
    code("# llm.py - vòng lặp tác tử (rút gọn)\ndef run_with_tools(self, system, user_content, tools, executor, schema, max_tokens):\n    messages = [{\"role\": \"user\", \"content\": user_content}]\n    tool_defs = [{**t, \"strict\": True} for t in tools]\n    output_config = {\"effort\": self.effort, \"format\": {\"type\": \"json_schema\", \"schema\": schema}}\n    for _ in range(self.max_tool_iterations + 1):\n        resp = self._create(model=self.model, max_tokens=max_tokens, system=system, messages=messages,\n                            tools=tool_defs, output_config=output_config)      # fallbacks=\"default\" khi được hỗ trợ\n        if resp.stop_reason == \"refusal\": raise LLMUnavailable(\"Mô hình từ chối yêu cầu\")\n        tool_uses = [b for b in resp.content if b.type == \"tool_use\"]\n        if resp.stop_reason != \"tool_use\" or not tool_uses:\n            return json.loads(\"\".join(b.text for b in resp.content if b.type == \"text\")), tool_log, usage\n        messages.append({\"role\": \"assistant\", \"content\": resp.content})\n        results = []\n        for tu in tool_uses:                      # thực thi MỌI tool_use rồi trả về trong MỘT message\n            try: out = executor(tu.name, tu.input or {}); is_error = False\n            except Exception as exc: out, is_error = \"Lỗi khi thực thi công cụ: %s\" % exc, True\n            results.append({\"type\": \"tool_result\", \"tool_use_id\": tu.id, \"content\": str(out)[:20000], **({\"is_error\": True} if is_error else {})})\n        messages.append({\"role\": \"user\", \"content\": results})\n    raise LLMUnavailable(\"Vượt quá %d vòng gọi công cụ\" % self.max_tool_iterations)", size=8.5)
    figure("05_alert_investigation.jpg", "Báo cáo điều tra: chuỗi tấn công MITRE, IOC, dòng thời gian", P, 6.3)
    h3("6.6.4. Knowledge Agent")
    para("Knowledge Agent chạy khi analyst đóng cảnh báo với tùy chọn trích xuất tri thức (hoặc bấm nút): từ triage + investigation + ghi chú xử lý sinh bài học Markdown (dấu hiệu, phân loại, phản ứng, dương tính giả, bài học) "
         "lưu `knowledge_articles` nguồn `ai`. Bài học sau đó được `search_knowledge` tìm thấy và đưa vào ngữ cảnh của các cảnh báo tương tự - tạo vòng lặp tích lũy. Ví dụ bài học sinh ra từ cảnh báo R18 (dữ liệu thật):")
    code("## Dấu hiệu nhận biết\n- Luật kích hoạt: Đăng nhập thành công sau nhiều lần thất bại (R18)\n- Kỹ thuật: T1110 Brute Force\n- Bằng chứng tiêu biểu: IP nguồn 203.0.113.66 là địa chỉ công cộng; IP nguồn nằm trong blocklist (malicious); IP này đã có 1 lần xác thực thành công trong 7 ngày; Tài khoản mục tiêu 'root' là tài khoản đặc quyền\n\n## Cách phân loại\n- Kết luận lần này: true_positive (độ tin cậy 90%, ưu tiên P1)\n- Giả thuyết điều tra: Kẻ tấn công từ 203.0.113.66 dò mật khẩu và đã đăng nhập thành công bằng tài khoản 'root' trên centos-db01; cần coi máy là đã bị xâm nhập cho tới khi chứng minh ngược lại.\n\n## Phản ứng\n- Chặn IP nguồn tại firewall / fail2ban\n- Kiểm tra có đăng nhập thành công nào từ IP này không\n- Bật MFA và chính sách khóa tài khoản cho tài khoản bị nhắm\n\n## Dương tính giả thường gặp\n- Nguồn nội bộ, số lần thấp, trong giờ hành chính; script giám sát dùng mật khẩu cũ.\n\n## Bài học\n- Đã chặn IP tại firewall, đặt lại mật khẩu root, tắt PasswordAuthentication.", size=9)
    figure("09_kb.jpg", "Cơ sở tri thức: bài học do AI sinh và playbook thủ công", P, 6.3)
    h3("6.6.5. Orchestrator và nhật ký ai_runs")
    para("**Orchestrator** điều phối chuỗi enrich → triage → investigate → knowledge, bảo đảm có enrichment trước các bước sau, ghi bảng ai_runs (mode, model, tokens, tool_calls, thời gian, lỗi), "
         "chạy nền (thread) khi tự động và đồng bộ khi người dùng bấm nút. Mọi tác tử có hai đường: LLM khi có `ANTHROPIC_API_KEY`, cục bộ khi không có hoặc khi API lỗi/từ chối; lý do fallback được ghi lại.")
    code("def run(self, alert_id, stages=(\"enrich\", \"triage\"), trigger=\"manual\", username=None):\n    alert = db.session.get(Alert, alert_id); llm = LLMClient.from_app(self.app); executor = ToolExecutor(alert)\n    ai_data = alert.ai or {}; context = {k: ai_data.get(k) for k in (\"enrichment\", \"triage\", \"investigation\")}\n    for stage in stages:\n        if stage != \"enrich\" and not context.get(\"enrichment\"):      # luôn có enrichment trước\n            context[\"enrichment\"] = self._execute(alert, \"enrich\", ...)\n        results[stage] = self._execute(alert, stage, llm, executor, context, trigger, username, ai_data)\n    return results\n\ndef _execute(...):                      # một lượt chạy = một dòng ai_runs\n    run = AIRun(alert_id=alert.id, agent_name=stage, trigger=trigger, mode=\"local\"); db.session.add(run); db.session.flush()\n    try:\n        result = agent_cls(llm, executor, alert, context).run()      # LLM hoặc local\n        run.mode, run.input_tokens, run.output_tokens, run.tool_calls = result[\"_mode\"], ..., dumps(result[\"_tool_calls\"])\n        self._apply(alert, stage, clean, run.mode, context, ai_data, username)   # ghi alert.ai_*, investigations, knowledge_articles\n    except Exception as exc:\n        db.session.rollback(); run = db.session.merge(run); run.status, run.error = \"error\", str(exc)\n    run.finished_at = utcnow(); run.duration_ms = ...; db.session.commit()", size=8.5)
    table(["Tác tử", "Kích hoạt", "Đầu vào", "Đầu ra", "Ghi vào"], [
        ["Enrichment", "Tự động khi có cảnh báo mới; trước mọi tác tử khác", "Cảnh báo, CSDL", "Dict ngữ cảnh + risk_flags + knowledge_matches", "alert.ai_data.enrichment"],
        ["Triage", "Tự động sau Enrichment; nút \"Phân loại lại\"", "Cảnh báo + enrichment + 40 sự kiện + tri thức", "verdict, severity, priority, confidence, risk_score, summary, evidence, actions", "alert.ai_* , status→triaged"],
        ["Investigation", "Nút \"Điều tra sâu\"; API /ai/investigate hoặc /ai/full", "Trên + triage; công cụ", "hypothesis, timeline, attack_chain, iocs, impact, root_cause, recommendations", "investigations, status→investigating"],
        ["Knowledge", "Khi đóng cảnh báo (tùy chọn); nút \"Trích xuất tri thức\"", "Triage + investigation + ghi chú", "title, summary, content (Markdown), tags, category", "knowledge_articles (source=ai)"],
    ], widths=[1.0, 1.7, 1.4, 1.5, 0.9], size=9, caption="Tổng hợp bốn tác tử", part=P)

    h2("6.7. Quản trị, phân quyền và kiểm toán")
    table(["Vai trò", "Quyền"], [
        ["admin", "Toàn quyền: người dùng, máy trạm (cấp lại khóa, xóa), luật (xóa), cài đặt, mọi chức năng của analyst"],
        ["analyst", "Xử lý cảnh báo (trạng thái, mức, phụ trách, ghi chú), chạy tác tử AI, thêm/sửa luật, bật/tắt, chạy lại luật, cơ sở tri thức, uy tín IP, xem audit"],
        ["viewer", "Chỉ xem dashboard, cảnh báo, log, máy trạm, luật, tri thức, báo cáo; xuất CSV"],
    ], widths=[1.0, 5.5], size=10, caption="Ba vai trò", part=P)
    para("Mọi thao tác quan trọng được ghi vào `audit_logs` với người dùng, hành động, đối tượng, chi tiết, IP và kết quả: login_success/failed/locked, logout, alert_update, alert_status, ai_run, rule_create/update/toggle/delete, rules_replay, kb_save/delete, user_save/delete, agent_registered/rekeyed/rekey/delete, ip_reputation_set/delete, export_logs/alerts, report_view, password_change. "
         "Nhật ký này vừa phục vụ tuân thủ, vừa là bằng chứng khi chính tài khoản SOC bị lạm dụng.")

    h2("6.8. Bảo mật của chính Web SOC")
    figure("20_security_layers.png", "Các lớp bảo vệ của Web SOC", P, 6.3)
    table(["Mối đe dọa (OWASP)", "Biện pháp trong mã nguồn"], [
        ["Broken authentication", "Mật khẩu băm Werkzeug (scrypt), khóa 5 phút sau 5 lần sai theo (user, IP), session.clear() khi đăng nhập (chống session fixation), cookie HttpOnly + SameSite=Lax (+ Secure khi SOC_HTTPS=1), hết hạn 8 giờ"],
        ["Broken access control", "Decorator login_required / role_required trên từng route; API trả 401/403 JSON; viewer không thấy menu quản trị"],
        ["CSRF", "Token gắn phiên (secrets.token_urlsafe(32)), so sánh hằng thời gian (hmac.compare_digest), trường ẩn trong 15 form và header X-CSRF-Token cho fetch; endpoint agent miễn vì dùng API key"],
        ["Injection", "SQLAlchemy tham số hóa; Jinja2 autoescape; JSON điều kiện luật được parse và kiểm tra kiểu"],
        ["Security misconfiguration", "Cảnh báo khi SECRET_KEY/enrollment token mặc định; MAX_CONTENT_LENGTH 16 MB; giới hạn 2000 sự kiện/lô, 5000 sự kiện/API"],
        ["Sensitive data exposure", "API key agent chỉ lưu băm SHA-256, hiển thị bản rõ một lần; khuyến nghị HTTPS"],
        ["Logging & monitoring failures", "audit_logs; ai_runs; log server"],
        ["Open redirect", "Tham số next chỉ chấp nhận đường dẫn nội bộ bắt đầu bằng / (không //)"],
    ], widths=[1.8, 4.7], size=9.5, caption="Đối chiếu OWASP Top 10 và biện pháp", part=P)
    code("# __init__.py - chống CSRF (rút gọn)\n@app.before_request\ndef csrf_protect():\n    if request.method not in (\"POST\", \"PUT\", \"PATCH\", \"DELETE\"): return\n    if request.path.startswith((\"/api/v1/agents/register\", \"/api/v1/agents/heartbeat\", \"/api/v1/logs\")): return\n    expected = session.get(\"_csrf_token\") or \"\"\n    sent = request.headers.get(\"X-CSRF-Token\") or request.form.get(\"_csrf_token\") or \"\"\n    if not expected or not sent or not hmac.compare_digest(expected, sent):\n        return (jsonify({\"error\": \"Thiếu hoặc sai CSRF token\"}), 403) if request.path.startswith(\"/api/\") else (render_template(\"error.html\", code=403, ...), 403)", size=9)

    h2("6.9. Tham chiếu API")
    table(["Phương thức & đường dẫn", "Xác thực", "Mô tả"], [
        ["POST /api/v1/agents/register", "enrollment token", "Đăng ký/cấp lại khóa cho máy trạm"],
        ["POST /api/v1/logs", "X-API-Key", "Gửi lô sự kiện"],
        ["POST /api/v1/agents/heartbeat", "X-API-Key", "Báo còn sống + số liệu"],
        ["GET /api/v1/stats", "phiên", "Số liệu dashboard (JSON)"],
        ["GET /api/v1/events?host=&source=&severity=&category=&action=&outcome=&event_id=&user=&src_ip=&q=&from=&to=&limit=&offset=&raw=1", "phiên", "Truy vấn sự kiện có bộ lọc (tối đa 5000/lần)"],
        ["POST /api/v1/alerts/<id>/ai/<enrich|triage|investigate|knowledge|full>", "phiên + X-CSRF-Token, analyst/admin", "Chạy một giai đoạn AI, trả kết quả và ai_data"],
        ["POST /api/v1/alerts/<id>/status {status, note}", "phiên + X-CSRF-Token, analyst/admin", "Đổi trạng thái cảnh báo"],
    ], widths=[2.6, 1.6, 2.3], size=9.5, caption="Tham chiếu API", part=P)
    code("# Ví dụ dùng API từ script (sau khi đăng nhập bằng requests.Session)\ns = requests.Session()\npage = s.get(\"http://127.0.0.1:5000/login\").text\ntoken = re.search(r'name=\"_csrf_token\" value=\"([^\"]+)\"', page).group(1)\ns.post(\"http://127.0.0.1:5000/login\", data={\"username\": \"analyst\", \"password\": \"Analyst@123\", \"_csrf_token\": token})\ntoken = re.search(r'name=\"csrf-token\" content=\"([^\"]+)\"', s.get(\"http://127.0.0.1:5000/\").text).group(1)\nr = s.get(\"http://127.0.0.1:5000/api/v1/events\", params={\"src_ip\": \"203.0.113.66\", \"limit\": 50}).json()\nr = s.post(\"http://127.0.0.1:5000/api/v1/alerts/19/ai/investigate\", headers={\"X-CSRF-Token\": token}).json()\nprint(r[\"ai_data\"][\"investigation\"][\"attack_chain\"])", size=9)
    page_break()
