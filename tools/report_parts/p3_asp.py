# -*- coding: utf-8 -*-
"""PHẦN 3. AGENTIC SOC PLATFORM (mở rộng)."""
from report_lib import *  # noqa: F401,F403

P = "3"


def build():
    h1("PHẦN 3. AGENTIC SOC PLATFORM (ASP)")
    # ------------------------------------------------------------------ 3.1
    h2("3.1. Nền tảng Agentic AI")
    h3("3.1.1. Từ LLM tới tác tử")
    para("**Mô hình ngôn ngữ lớn (LLM)** như Claude sinh văn bản từ ngữ cảnh đầu vào. Dùng \"thô\", LLM chỉ là một hàm hỏi - đáp một lượt. "
         "**Agentic AI** là cách dùng LLM như một **tác tử** (agent): mô hình được trao **công cụ** (tool) để tự quyết định gọi (truy vấn CSDL, tra cứu IP, tìm tri thức), "
         "quan sát kết quả, lập luận tiếp và lặp lại cho tới khi hoàn thành mục tiêu - gọi là *vòng lặp tác tử* (agentic loop). "
         "Anthropic phân biệt hai mức: **workflow** (các bước gọi LLM do mã lập trình điều phối theo đường cố định) và **agent** (LLM tự điều khiển tiến trình và việc dùng công cụ). "
         "Hệ thống đề tài dùng cả hai: Enrichment và Triage là workflow (một lượt, đầu ra theo schema); Investigation là agent (tự chọn gọi công cụ).")
    table(["Khái niệm", "Giải thích", "Trong hệ thống"], [
        ["System prompt", "Chỉ dẫn vai trò, ràng buộc, ngôn ngữ cho mô hình", "SYSTEM_PROMPT: \"chuyên gia SOC bậc 2... trả lời tiếng Việt, dựa trên bằng chứng, không bịa\""],
        ["Tool use (function calling)", "Mô hình trả về tool_use {name, input}; ứng dụng thực thi và trả tool_result; lặp", "6 công cụ chỉ đọc trong ai/tools.py; vòng lặp run_with_tools()"],
        ["Structured outputs", "Ép đầu ra theo JSON schema (output_config.format)", "TRIAGE_SCHEMA, INVESTIGATION_SCHEMA, KNOWLEDGE_SCHEMA"],
        ["Adaptive thinking / effort", "Mô hình tự quyết định mức suy luận; effort điều chỉnh độ sâu", "Mặc định của claude-opus-5-5; AI_EFFORT=medium"],
        ["Context / grounding", "Đưa dữ liệu thật vào prompt để giảm ảo giác", "Cảnh báo + enrichment + ≤ 40 sự kiện + tri thức tương tự"],
        ["Human-in-the-loop", "Người duyệt trước hành động có tác động", "AI chỉ khuyến nghị; analyst đổi trạng thái, chặn IP"],
        ["Fallback", "Đường dự phòng khi mô hình không khả dụng", "run_local() heuristic; server-side fallback khi mô hình từ chối"],
        ["MCP (Model Context Protocol)", "Chuẩn mở để tác tử kết nối công cụ/dữ liệu ngoài", "ASP dùng CLI + Skills cho Harness Agent; đề tài có thể phơi công cụ qua MCP (hướng phát triển)"],
    ], widths=[1.6, 2.6, 2.3], size=9.5, caption="Các khái niệm Agentic AI", part=P)
    h3("3.1.2. Vòng lặp tác tử")
    code("messages = [user_prompt]\nlặp tối đa N vòng:\n    resp = model(messages, tools, schema)\n    nếu resp.stop_reason == \"tool_use\":\n        với mỗi tool_use trong resp: result = executor(name, input)   # chỉ đọc CSDL\n        messages += [assistant(resp.content), user(tool_results)]\n        tiếp tục\n    nếu resp.stop_reason == \"end_turn\": trả về json.loads(text)       # theo schema\n    nếu \"refusal\" / lỗi: ném LLMUnavailable -> run_local()")
    h3("3.1.3. Rủi ro và kiểm soát")
    figure("26_llm_risks.png", "Rủi ro khi dùng LLM trong SOC và biện pháp kiểm soát", P, 6.5)
    para("Nguyên tắc an toàn quan trọng là **human-in-the-loop** và **công cụ chỉ đọc**: tác tử đề xuất, con người quyết định các hành động có tác động (chặn IP, khóa tài khoản). "
         "Mọi lượt chạy được ghi vào bảng `ai_runs` (mode, model, tokens, tool_calls, lỗi) để kiểm toán và tính chi phí.")

    # ------------------------------------------------------------------ 3.2
    h2("3.2. Giới thiệu dự án funnywolf/agentic-soc-platform")
    para("Dự án tự mô tả: *\"Agentic SOC Platform is an open-source security operations platform built on Agentic AI, enabling agents to proactively participate in triage, investigation, "
         "enrichment, and knowledge accumulation so security teams can move from alert fatigue to AI-assisted decision-making.\"* "
         "Tài liệu chính thức bổ sung: ASP \"provides security teams with a complete workflow from alert ingestion, automatic aggregation, AI analysis to response disposition\" và đặt "
         "alerts, cases, entities, enrichment, knowledge và playbook trong cùng một không gian làm việc, để analyst \"review evidence, confirm AI reports, and make disposition decisions around Case\".")
    table(["Thông tin", "Giá trị (tra cứu ngày 30/10/2026)"], [
        ["Kho mã nguồn", "[github.com/funnywolf/agentic-soc-platform](https://github.com/funnywolf/agentic-soc-platform)"],
        ["Trang chủ / tài liệu", "[asp.viperrtp.com](https://asp.viperrtp.com) (VitePress, có bản tiếng Anh và tiếng Trung)"],
        ["Mô tả GitHub", "\"A powerful, flexible, open-source, and agent-centric automated security operations platform (AI SOC)\""],
        ["Ngày tạo / cập nhật gần nhất", "07/09/2025 / 29/09/2026"],
        ["Sao / fork", "≈ 1.221 sao, 222 fork; thành viên chương trình 404Starlink (Knownsec)"],
        ["Giấy phép", "MIT (theo README và tài liệu)"],
        ["Ngôn ngữ", "Python (≈ 985 KB mã, backend Django), TypeScript (≈ 602 KB, frontend Vite + Ant Design), Shell, Dockerfile"],
        ["Chủ đề (topics)", "agentic-soc, ai, blueteam, cybersecurity, dify, langchain, langgraph, llm, siem, soar"],
        ["Thư mục chính", "backend/ (Django), frontend/, cli/ (asp-cli), deploy/ (asp-compose, release_tool.py), docs/, development/, asp-doc (submodule), asp-marketplace (submodule plugin Claude Code)"],
        ["Ứng dụng Django (backend/apps)", "accounts, agent_api, agentic, alerts, artifacts, attachments, audit, cases, comments, common, dashboard, enrichments, inbox, knowledge, playbooks, preferences, realtime, settings, webhook"],
    ], widths=[1.8, 4.7], size=10, caption="Thông tin dự án ASP", part=P)
    h3("3.2.1. Chín điểm nhấn theo README")
    table(["Điểm nhấn", "Nội dung (diễn giải từ README)"], [
        ["Alert floods → actionable cases", "Module nhận cảnh báo từ SIEM/Webhook, trích IOC, tương quan tín hiệu liên quan và sinh Case/Alert/Artifact để hàng loạt log hội tụ thành số ít Case khả thi"],
        ["AI investigation, seconds not hours", "Tự động sinh severity, confidence, impact, priority, verdict và báo cáo điều tra có cấu trúc"],
        ["One click to drive complex investigations", "Từ mỗi Case khởi chạy LLM investigation, trích tri thức, làm giàu threat intel và CMDB; SOAR truyền thống và AI trong cùng hệ Playbook"],
        ["Deep Harness Agent integration", "Phơi năng lực ASP cho Claude Code / Codex / OpenCode qua CLI và plugin: tác tử thao tác Case, tìm log, tra TI, viết Module/Playbook"],
        ["Multi-SIEM access", "Splunk, ELK, tìm kiếm log hợp nhất, nhận cảnh báo webhook"],
        ["Automated threat intelligence enrichment", "Làm giàu IOC/Artifact với uy tín, pulse, tài sản, danh tính, lịch sử"],
        ["Knowledge accumulation", "Trích tri thức tái sử dụng từ Case đã đóng, thảo luận, quy trình phản ứng"],
        ["Collaboration, audit, access control", "Đăng nhập Local/LDAP, vai trò, API Key, Inbox, Audit Log"],
        ["Low-cost adaptation", "Module Python cho nguồn cảnh báo mới, Playbook cho LLM và hành động tự động; MIT, triển khai riêng"],
    ], widths=[2.0, 4.5], size=9.5, caption="Các điểm nhấn của ASP", part=P)

    # ------------------------------------------------------------------ 3.3
    h2("3.3. Các khái niệm cốt lõi")
    figure("09_asp_datamodel_mapping.png", "Mô hình dữ liệu cốt lõi của ASP và ánh xạ sang Web SOC của đề tài", P, 6.3)
    table(["Khái niệm", "Định nghĩa theo tài liệu ASP", "Ghi chú"], [
        ["Case", "\"the core disposition object in ASP and the war room for analyst collaborative investigation\" - gom alerts, entities, enrichment, knowledge, playbooks, báo cáo AI, thảo luận và timeline", "Trường: Status (New, In Progress, On Hold, Resolved, Closed), Severity/Confidence/Impact/Priority (thủ công và AI), Verdict/Verdict (AI), Assignee, Summary, Correlation UID"],
        ["Alert", "\"an alert record from SIEM, EDR, cloud platforms, or Webhook... the evidence layer and detection context layer of Case\"", "Giữ rule, product, MITRE tactic/technique, Raw Data, Unmapped; thường không đóng độc lập mà qua Case"],
        ["Artifact", "\"an entity, evidence item, or IOC in a security incident, such as IP, domain, URL, file hash, account, host, process, registry key, cloud resource\"", "Có Type, Role (Target, Actor, Affected, Related), Value; \"transforms fields in alerts into investigatable objects\""],
        ["Enrichment", "Ngữ cảnh ngoài gắn với Artifact/Alert/Case: threat intelligence, reputation, asset (CMDB), identity, history, vulnerability", "Có thể do Playbook hoặc analyst thêm"],
        ["Module", "Mã Python xử lý luồng cảnh báo: \"extract IOCs, map fields, correlate signals, and generate Case / Alert / Artifact\"", "Đọc từ Redis Stream; triết lý \"code-first\" thay vì kéo-thả"],
        ["Playbook", "\"a Case-oriented automation task\" - lớp Python kế thừa BasePlaybook với NAME, DESC, TAGS, run(); trạng thái Pending → Running → Success/Failed", "Mẫu có sẵn: investigation.py, knowledge_extraction.py, threat_intelligence_enrichment.py, cmdb_enrichment.py, case_summary.py"],
        ["Knowledge", "\"accumulate reusable security experience\": kết luận xử lý, dương tính giả, bước điều tra; nguồn Manual hoặc Case; có Expires At", "Knowledge Extraction chỉ chạy khi Case đã có verdict; một Case tối đa một Knowledge"],
        ["Harness Agent", "Tác tử lập trình bên ngoài (Claude Code, Codex, OpenCode) dùng asp-cli + Skills để thao tác Case, tìm log SIEM, tra threat intel, viết Module/Playbook", "\"Harness Agent first\": tái dùng tác tử người dùng đã có thay vì xây hệ tác tử riêng"],
        ["Comments / Log-Timeline", "Thảo luận và dấu vết thao tác trên Case; LLM đọc Comments khi phân tích", "Những gì analyst viết ảnh hưởng tới báo cáo AI và tri thức"],
        ["Related Cases / Suggested Cases", "Quan hệ Related / Duplicate of / Parent of; gợi ý Case liên quan theo Artifact chung (≤ 20 Artifact, ≤ 10 kết quả)", "Tương đương related_alerts trong enrichment của đề tài"],
    ], widths=[1.1, 3.1, 2.3], size=9.5, caption="Khái niệm cốt lõi của ASP", part=P)
    h3("3.3.1. Các trường của Case và Alert")
    table(["Case", "Alert"], [
        ["Case ID, Title, Status, Severity, Confidence, Impact, Priority (+ bản AI), Verdict (+ AI), Assignee, Summary, Correlation UID, Created/Closed time",
         "Alert ID, Case, Title, Severity, Confidence, Impact, Risk Level, Disposition, Action, Status, Rule ID, Rule Name, Correlation UID, Source UID, Product Vendor/Name/Feature, Tactic, Technique, Sub-technique, Raw Data, Unmapped"],
    ], widths=[3.2, 3.3], size=9.5, caption="Trường dữ liệu của Case và Alert (theo tài liệu ASP)", part=P)
    para("Nhận xét: ASP tách bạch **đánh giá của AI** và **đánh giá của người** thành hai bộ cột song song (Severity vs Severity (AI), Verdict vs Verdict (AI)). Đề tài áp dụng cùng nguyên tắc: "
         "`severity`/`status` do analyst, `ai_verdict`/`ai_priority`/`ai_confidence`/`ai_summary` do tác tử.")

    # ------------------------------------------------------------------ 3.4
    h2("3.4. Luồng xử lý: từ cảnh báo tới tri thức")
    figure("08_asp_pipeline.png", "Luồng xử lý và các thành phần của ASP", P, 6.5)
    table(["Giai đoạn", "ASP làm gì (theo tài liệu)", "Đề tài"], [
        ["Alert ingestion", "Nhận cảnh báo từ SIEM / Webhook / ELK Index Action và ghi vào Redis Stream", "Nhận log thô từ agent; Rule Engine tự sinh cảnh báo"],
        ["Module processing", "Module Python trích IOC, ánh xạ trường, tương quan tín hiệu, sinh Case / Alert / Artifact", "parsers.py + detection.py + dedup_key"],
        ["Case investigation", "Analyst xem bằng chứng, thảo luận, xem Timeline, xác nhận đánh giá rủi ro", "Trang chi tiết cảnh báo, bằng chứng, ghi chú"],
        ["AI analysis & enrichment", "LLM sinh báo cáo điều tra; Playbook bổ sung threat intelligence, CMDB, trích tri thức", "Enrichment/Triage/Investigation Agent"],
        ["Harness Agent collaboration", "CLI và Skills cho tác tử truy vấn SIEM, thao tác tài nguyên, viết Module/Playbook", "Chưa có (hướng phát triển: MCP server)"],
        ["Knowledge capture", "Rút kinh nghiệm tái sử dụng từ Case đã xác nhận thành Knowledge cấp tổ chức", "Knowledge Agent"],
        ["Governance", "Người dùng/API Key, LDAP, Audit Log, Inbox cho cộng tác, kiểm toán và phân quyền", "users, audit_logs, API key agent"],
    ], widths=[1.5, 3.2, 1.8], size=9.5, caption="Bảy giai đoạn của ASP và đối chiếu", part=P)
    h3("3.4.1. Playbook: cấu trúc mã và vòng đời")
    para("Playbook của ASP là một lớp Python đặt trong `custom/playbooks/` (hoặc `backend/playbooks/` khi phát triển), được worker nền `run_agentic_playbook_worker` thực thi. "
         "Giá trị trả về ghi vào Remark; ngoại lệ ghi vào bản ghi thất bại. Tài liệu khuyến nghị kết quả phải được ghi ngược vào Case, Knowledge, Enrichment hoặc Comment thay vì chỉ in ra log.")
    code("from apps.agentic.runtime.base import BasePlaybook\n\nclass Playbook(BasePlaybook):\n    NAME = \"CMDB Enrichment\"\n    DESC = \"Tra cứu tài sản cho các Artifact của Case.\"\n    TAGS = [\"System\"]\n\n    def run(self):\n        if self.case is None:\n            raise ValueError(\"Playbook requires a linked case.\")\n        # self.case: Case kích hoạt; self.user_input: yêu cầu bổ sung của người dùng\n        ...\n        return \"Execution summary\"")
    table(["Playbook mẫu", "Chức năng"], [
        ["investigation.py", "Kích hoạt điều tra AI cho Case, ghi báo cáo ngược vào Case"],
        ["knowledge_extraction.py", "Trích tri thức tái sử dụng từ Case đã có verdict của analyst"],
        ["threat_intelligence_enrichment.py", "Tra threat intel cho Artifact của Case, ghi vào Artifact Enrichment"],
        ["custom/playbooks/cmdb_enrichment.py", "Tra CMDB cho Artifact, ghi vào Enrichment"],
        ["custom/playbooks/case_summary.py", "Đọc prompt hệ thống theo ngôn ngữ, gọi LLM sinh Case Summary"],
    ], widths=[2.6, 3.9], size=10, caption="Các Playbook mẫu của ASP", part=P)
    para("Đối chiếu: bốn tác tử của đề tài tương ứng Investigation (Investigation Agent), Knowledge Extraction (Knowledge Agent), TI Enrichment (Enrichment Agent với bảng uy tín IP cục bộ); "
         "Triage Agent là bổ sung riêng vì đề tài tự sinh cảnh báo từ log thô nên cần bước chấm điểm ngay sau phát hiện.")

    # ------------------------------------------------------------------ 3.5
    h2("3.5. Kiến trúc kỹ thuật và triển khai")
    bullets([
        "**Backend:** Django (Python, quản lý phụ thuộc bằng uv), REST API có Swagger UI tại /api/docs/ và OpenAPI schema tại /api/schema/, ASGI (uvicorn) cho WebSocket thời gian thực; worker nền `run_agentic_playbook_worker`, `run_dashboard_cache_worker`.",
        "**Frontend:** Vite + React + Ant Design (TypeScript); quy ước ưu tiên component và CSS mặc định của Ant Design.",
        "**Dữ liệu:** PostgreSQL (CSDL chính), Redis / Redis Stack (Stream cảnh báo, cache, UI cổng 8001), RustFS (lưu trữ đối tượng tương thích S3 cho tệp đính kèm, console cổng 9001).",
        "**Tích hợp SIEM:** Splunk (Host, Port 8089, Username, Password, Scheme, Verify) và Elasticsearch (Host, API Key, Verify Certs, Request Timeout; *ELK Index Action*: Process Alert From Index Enabled, Action Index, Poll Interval, Action Size - worker đọc tài liệu action của Kibana rồi đưa vào luồng webhook); cấu hình index tìm kiếm cho Harness Agent bằng YAML trong `custom/data/siem/`; khóa bí mật ẩn mặc định và mọi thao tác ghi Audit Log.",
        "**LLM:** cấu hình trong System Settings; các topic của repo cho thấy dùng hệ sinh thái LangChain/LangGraph và Dify.",
        "**Quản trị:** đăng nhập Local/LDAP, vai trò Admin/User/Viewer, API Keys, Inbox, Audit Log.",
    ])
    h3("3.5.1. Các bước triển khai bằng Docker Compose")
    numbered([
        "Chuẩn bị Linux 64-bit (Debian 12/13, Ubuntu 22.04-26.04, RHEL/Rocky/Alma 8-10, CentOS Stream 9/10) có Docker Engine + Compose plugin; mở cổng 443; không phơi 8001 và 9001 ra ngoài.",
        "Tải gói: `curl -fL -o asp-compose.tar.gz https://github.com/FunnyWolf/agentic-soc-platform/releases/latest/download/asp-compose.tar.gz && tar -xzf asp-compose.tar.gz && cd asp-compose` (không đổi tên thư mục vì ảnh hưởng tên volume).",
        "Chứng chỉ (tùy chọn): đặt `certs/asp.crt`, `certs/asp.key`; nếu không, frontend tự sinh chứng chỉ tự ký.",
        "Khởi tạo: `./scripts/init.sh` - tạo thư mục runtime và compose.override.yaml, tạo `.env` với mật khẩu ngẫu nhiên (Django, PostgreSQL, Redis, RustFS), kéo image từ GHCR, chạy migration, khởi động dịch vụ.",
        "Kiểm tra: `./scripts/doctor.sh` xác nhận PostgreSQL, Redis, Django, custom definitions và bucket RustFS/S3.",
        "Tạo quản trị: `docker compose exec asp-web python manage.py createsuperuser`; truy cập `https://<server>/`.",
        "Cấu hình System Settings: LLM, SIEM (Splunk/ELK), Threat Intelligence, LDAP; triển khai Module/Playbook tùy chỉnh trong `custom/`.",
    ])
    table(["Khía cạnh", "ASP", "Web SOC đề tài"], [
        ["Số dịch vụ", "≥ 6 container (web, worker, postgres, redis, rustfs, frontend)", "1 tiến trình Python"],
        ["Yêu cầu tài nguyên", "Máy chủ Linux, Docker, vài GB RAM", "Bất kỳ máy có Python 3.8+"],
        ["Bí mật", "Sinh ngẫu nhiên trong .env bởi init.sh", "Biến môi trường SOC_SECRET_KEY, SOC_ENROLLMENT_TOKEN (cảnh báo nếu để mặc định)"],
        ["HTTPS", "Mặc định, tự ký nếu thiếu", "Qua reverse proxy; SOC_HTTPS=1 bật cookie Secure"],
        ["Nguồn dữ liệu", "Cảnh báo đã có từ SIEM khác", "Log thô từ agent tự viết"],
    ], widths=[1.5, 2.6, 2.4], size=10, caption="So sánh triển khai", part=P)

    # ------------------------------------------------------------------ 3.6
    h2("3.6. ASP khác gì SIEM/SOAR truyền thống?")
    para("Tài liệu ASP nêu rõ: ASP \"is not an AI chat entry point added on top of a traditional alert list\" và không ép người dùng mô tả tự động hóa bằng kéo-thả hay tệp cấu hình tĩnh; "
         "nó giữ trải nghiệm và mô hình dữ liệu của SOAR trưởng thành nhưng đưa logic xử lý vào **mã Python**, và tích hợp LLM, Playbook, Harness Agent vào **cùng một quy trình SOC** thay vì xây hệ tác tử tách biệt. "
         "Kết quả: công việc của analyst chuyển từ \"xử lý từng cảnh báo\" sang \"xem xét kết quả phân tích của AI và đưa ra phán quyết cuối cùng\". Bốn lợi thế được nêu: không gian làm việc và mô hình dữ liệu chuẩn; "
         "linh hoạt code-first; phù hợp phát triển có tác tử hỗ trợ (Skills giúp Harness Agent viết Module/Playbook); Harness Agent first; mã nguồn mở, triển khai riêng.")
    table(["Tiêu chí", "SOAR truyền thống", "ASP"], [
        ["Cách mô tả tự động hóa", "Kéo-thả workflow, cấu hình tĩnh", "Mã Python (Module, Playbook)"],
        ["Vai trò AI", "Không hoặc chatbot gắn thêm", "LLM trong cùng quy trình: điều tra, tri thức, làm giàu"],
        ["Tác tử lập trình", "Không", "Harness Agent (Claude Code...) qua CLI/Skills thao tác dữ liệu và viết mã"],
        ["Đối tượng trung tâm", "Ticket/Incident", "Case war room với Alert, Artifact, Enrichment, Knowledge"],
        ["Tri thức", "Wiki rời", "Knowledge trích tự động từ Case có verdict"],
    ], widths=[1.8, 2.2, 2.5], size=10, caption="ASP và SOAR truyền thống", part=P)

    # ------------------------------------------------------------------ 3.7
    h2("3.7. Vận dụng vào đề tài")
    table(["Ý tưởng của ASP", "Cách đề tài hiện thực ở quy mô nhỏ"], [
        ["Alert → Case hội tụ, gộp trùng", "Cảnh báo có `dedup_key` (rule|host|nhóm); lần kích hoạt tiếp theo gộp vào cảnh báo đang mở, tăng event_count và liên kết bằng chứng"],
        ["Artifact / IOC", "Trường user, src_ip, host, process của mỗi sự kiện; Investigation Agent trích danh sách iocs {ips, users, processes, files}"],
        ["Enrichment (TI, CMDB, lịch sử)", "`enrichment.py`: phân loại IP, bảng uy tín IP, lịch sử 7 ngày, ngữ cảnh tài khoản/máy/thời gian, cảnh báo liên quan"],
        ["Playbook Investigation (LLM)", "Investigation Agent: agentic loop với 6 công cụ chỉ-đọc, JSON theo schema; đường cục bộ khi không có LLM"],
        ["Knowledge Extraction", "Knowledge Agent sinh bài học khi analyst đóng cảnh báo (tùy chọn), lưu `knowledge_articles` nguồn ai"],
        ["Verdict / Priority do AI và do người", "Cột ai_verdict/ai_priority/ai_confidence bên cạnh status/severity do analyst đặt"],
        ["Audit Log, phân quyền, API Key", "Bảng audit_logs, ba vai trò, API key băm SHA-256 cho agent"],
        ["Comments ảnh hưởng tới AI", "resolution_note của analyst được đưa vào prompt của Knowledge Agent"],
        ["Module thu thập từ SIEM", "Đề tài tự thu thập log thô (SOC Agent) thay vì nhận alert từ SIEM khác - vì vậy có thêm Rule Engine"],
        ["Harness Agent / Skills", "Chưa có; hướng phát triển: phơi 6 công cụ của ToolExecutor qua MCP server để Claude Code điều tra trực tiếp"],
    ], widths=[2.3, 4.2], size=10, caption="Vận dụng ý tưởng ASP vào đề tài", part=P)
    figure("27_mode_selection.png", "Lựa chọn đường chạy LLM / cục bộ của tác tử trong đề tài", P, 5.8)
    h2("3.8. Liên kết tham khảo cho Phần 3")
    link_line("README (GitHub)", "https://github.com/funnywolf/agentic-soc-platform/blob/master/README.md")
    link_line("ASP Overview", "https://asp.viperrtp.com/asp/overview/")
    link_line("ASP Quick Start - Deployment", "https://asp.viperrtp.com/asp/quick-start/deployment/")
    link_line("ASP Workspace - Case", "https://asp.viperrtp.com/asp/workspace/case/")
    link_line("ASP Workspace - Alert", "https://asp.viperrtp.com/asp/workspace/alert/")
    link_line("ASP Workspace - Artifact", "https://asp.viperrtp.com/asp/workspace/artifact/")
    link_line("ASP Workspace - Playbook", "https://asp.viperrtp.com/asp/workspace/playbook/")
    link_line("ASP Workspace - Knowledge", "https://asp.viperrtp.com/asp/workspace/knowledge/")
    link_line("ASP Development - Playbook", "https://asp.viperrtp.com/asp/development/playbook/")
    link_line("ASP Settings - SIEM (Splunk / ELK)", "https://asp.viperrtp.com/asp/settings/siem/")
    link_line("GitHub Releases (asp-compose)", "https://github.com/funnywolf/agentic-soc-platform/releases")
    link_line("Anthropic - Building effective agents", "https://www.anthropic.com/research/building-effective-agents")
    link_line("Anthropic - Claude Developer Platform: tool use", "https://platform.claude.com/docs/en/build-with-claude/tool-use")
    link_line("Model Context Protocol", "https://modelcontextprotocol.io/")
    page_break()
