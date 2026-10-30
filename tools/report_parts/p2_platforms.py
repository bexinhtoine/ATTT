# -*- coding: utf-8 -*-
"""PHẦN 2. KHẢO SÁT CÁC HỆ THỐNG SOC/SIEM THAM KHẢO (mở rộng)."""
from report_lib import *  # noqa: F401,F403

P = "2"


def build():
    h1("PHẦN 2. KHẢO SÁT CÁC HỆ THỐNG SOC/SIEM THAM KHẢO")
    para("Mục tiêu của phần này là nắm **khái niệm và mô hình kiến trúc** của các nền tảng phổ biến, từ đó rút ra hình mẫu cho hệ thống tự xây dựng: "
         "mọi nền tảng đều có cùng bộ khung *agent/collector → vận chuyển → lưu trữ/chỉ mục → phát hiện → trình bày*. Với mỗi nền tảng, báo cáo trình bày "
         "kiến trúc, cách cấu hình thu thập log Windows/Linux, cách viết luật phát hiện, ưu nhược điểm và bài học áp dụng.")

    # ------------------------------------------------------------------ 2.1 ELK
    h2("2.1. Elastic Stack (ELK)")
    h3("2.1.1. Tổng quan và kiến trúc")
    para("**ELK** là viết tắt của ba thành phần gốc: **E**lasticsearch, **L**ogstash, **K**ibana; sau này có thêm **Beats** (và Elastic Agent) nên Elastic gọi chung là Elastic Stack. "
         "Đây là nền tảng phân tích log phổ biến nhất thế giới (giấy phép Elastic License 2.0/SSPL, có thêm lựa chọn AGPL-3.0 từ 2024) và là nền của nhiều SIEM thương mại; "
         "OpenSearch là nhánh mã nguồn mở Apache 2.0 do AWS tách ra năm 2021, được Wazuh và Graylog sử dụng.")
    figure("05_elk_architecture.png", "Kiến trúc Elastic Stack", P, 6.3)
    table(["Thành phần", "Vai trò", "Chi tiết kỹ thuật"], [
        ["Beats", "Bộ thu thập nhẹ (Go) cài trên máy nguồn", "Filebeat (tệp log, có module cho nginx/apache/system), Winlogbeat (Windows Event Log), Metricbeat, Packetbeat, Auditbeat; gửi qua HTTPS/Lumberjack, có registry nhớ offset"],
        ["Elastic Agent + Fleet", "Agent hợp nhất thay thế Beats", "Quản lý tập trung chính sách thu thập từ Kibana (Fleet), tích hợp Endpoint Security (EDR)"],
        ["Logstash", "Đường ống xử lý (JVM)", "input → filter (grok, dissect, mutate, geoip, date) → output; có thể thay bằng Ingest Pipeline ngay trong Elasticsearch"],
        ["Elasticsearch", "Lưu trữ và tìm kiếm phân tán", "Tài liệu JSON, chỉ mục đảo ngược (Lucene), shard/replica, Index Lifecycle Management (hot-warm-cold-frozen-delete), truy vấn DSL/KQL/ES|QL"],
        ["Kibana", "Giao diện", "Discover, Dashboard, Lens, Alerting, ứng dụng Security (SIEM) với luật phát hiện, timeline, case"],
        ["ECS", "Elastic Common Schema", "Lược đồ chuẩn: @timestamp, event.category/action/outcome, source.ip, user.name, host.name, process.name..."],
    ], widths=[1.4, 1.8, 3.3], size=9.5, caption="Thành phần Elastic Stack", part=P)
    h3("2.1.2. Thu thập log Windows và Linux với Beats")
    para("Winlogbeat đọc Windows Event Log qua API, nhớ bookmark từng kênh trong registry file; Filebeat đọc tệp bằng *harvester* nhớ offset và xử lý xoay vòng theo inode. "
         "Cấu hình rút gọn:")
    code("# winlogbeat.yml\nwinlogbeat.event_logs:\n  - name: Security\n    event_id: 4624, 4625, 4648, 4672, 4720, 4732, 4740, 1102\n    ignore_older: 72h\n  - name: System\n    event_id: 7045, 7036, 104\n  - name: Microsoft-Windows-Sysmon/Operational\noutput.elasticsearch:\n  hosts: [\"https://es01:9200\"]\n  api_key: \"${ES_API_KEY}\"\n\n# filebeat.yml\nfilebeat.inputs:\n  - type: filestream\n    id: auth\n    paths: [/var/log/auth.log, /var/log/secure]\n  - type: journald\n    id: journal\n    units: [ssh.service, sudo]\nfilebeat.modules:\n  - module: nginx\n    access: {enabled: true}")
    para("Nhận xét: SOC Agent của đề tài tái hiện đúng ba cơ chế này - `WindowsEventLogCollector` (EventID chọn lọc, con trỏ EventRecordID), `FileCollector` (offset + inode), "
         "`JournaldCollector` (cursor) - nhưng bằng thư viện chuẩn Python để không phải cài nhị phân.")
    h3("2.1.3. Chuẩn hóa với Logstash/Ingest Pipeline và ECS")
    code("# Logstash filter: tách dòng syslog BSD\nfilter {\n  grok {\n    match => { \"message\" => \"%{SYSLOGTIMESTAMP:ts} %{SYSLOGHOST:host.name} %{DATA:process.name}(?:\\[%{POSINT:process.pid}\\])?: %{GREEDYDATA:msg}\" }\n  }\n  grok {\n    match => { \"msg\" => \"Failed password for (invalid user )?%{USERNAME:user.name} from %{IP:source.ip} port %{POSINT:source.port}\" }\n    add_field => { \"event.action\" => \"logon-failed\" \"event.outcome\" => \"failure\" }\n  }\n  date { match => [\"ts\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\"] timezone => \"Asia/Ho_Chi_Minh\" }\n}")
    para("Lược đồ ECS định nghĩa hàng trăm trường có tên và kiểu thống nhất; bảng dưới đối chiếu các trường ECS với lược đồ 17 trường của hệ thống đề tài.")
    table(["ECS", "Hệ thống đề tài", "Ghi chú"], [
        ["@timestamp", "timestamp", "ISO-8601 UTC"],
        ["event.dataset / event.provider", "source / process", "linux.auth, windows.security"],
        ["event.code", "event_id", "EventID hoặc mã parser"],
        ["event.category (authentication, process, file...)", "category", "Cùng ý tưởng, tập giá trị nhỏ hơn"],
        ["event.action", "action", "logon_failed, user_created..."],
        ["event.outcome (success/failure/unknown)", "outcome", "Giống hệt"],
        ["event.severity / log.level", "severity", "Thang 5 mức chuẩn hóa"],
        ["user.name, source.ip, source.port", "user, src_ip, src_port", "Giống"],
        ["host.name, process.pid", "host, pid", "Giống"],
        ["message, event.original", "message, raw", "Giống"],
        ["winlog.event_data.*, http.*", "extra (JSON)", "Trường đặc thù"],
    ], widths=[2.4, 1.6, 2.5], size=9.5, caption="Đối chiếu ECS và lược đồ chuẩn hóa của đề tài", part=P)
    h3("2.1.4. Phát hiện và trực quan trong Kibana")
    para("Ứng dụng Elastic Security có hơn 1.000 luật phát hiện dựng sẵn (kho `elastic/detection-rules`, gắn ATT&CK), hỗ trợ các loại luật: *query* (KQL/Lucene), *threshold*, *EQL sequence* (chuỗi sự kiện), *indicator match* (threat intel), *machine learning*, *new terms*. Ba loại đầu tương ứng match/threshold/sequence của đề tài. Ví dụ:")
    code("# KQL - truy vấn\nevent.code: 4625 and source.ip: 203.0.113.66\n\n# Threshold rule: >= 5 lần 4625 cùng source.ip trong 2 phút\nquery: event.code:4625   threshold.field: source.ip   threshold.value: 5   timeframe: 2m\n\n# EQL sequence: thành công sau thất bại trong 10 phút\nsequence by source.ip with maxspan=10m\n  [authentication where event.outcome == \"failure\"] with runs=3\n  [authentication where event.outcome == \"success\"]")
    h3("2.1.5. Ưu nhược điểm và bài học")
    bullets([
        "**Ưu điểm:** tìm kiếm cực nhanh trên dữ liệu lớn, hệ sinh thái module thu thập phong phú, SIEM app có sẵn hàng trăm luật gắn ATT&CK, Fleet quản lý agent tập trung, AI Assistant (bản trả phí).",
        "**Nhược điểm:** tốn RAM/đĩa (mỗi node JVM ≥ 8 GB), cần tinh chỉnh cluster/ILM, chi phí bản quyền cho tính năng nâng cao; không có agent bảo mật chủ động (FIM, SCA) như Wazuh.",
        "**Bài học cho đề tài:** lược đồ chuẩn hóa `parsers.py` lấy cảm hứng từ ECS; cơ chế *registry* nhớ offset của Filebeat được tái hiện bằng `collector_states` trong `agent_state.json`; ba loại luật tương ứng query/threshold/EQL; phản hồi `config` trong heartbeat mô phỏng Fleet.",
    ])
    link_line("Elastic Stack", "https://www.elastic.co/elastic-stack")
    link_line("Elastic Common Schema (ECS) reference", "https://www.elastic.co/guide/en/ecs/current/index.html")
    link_line("Winlogbeat / Filebeat documentation", "https://www.elastic.co/guide/en/beats/libbeat/current/index.html")
    link_line("Elastic Security detection rules (GitHub)", "https://github.com/elastic/detection-rules")
    link_line("OpenSearch", "https://opensearch.org/")

    # ------------------------------------------------------------------ 2.2 Wazuh
    h2("2.2. Wazuh")
    h3("2.2.1. Tổng quan và kiến trúc")
    para("**Wazuh** là nền tảng mã nguồn mở (GPLv2) hợp nhất **XDR** và **SIEM**, phát triển từ OSSEC năm 2015. Wazuh có agent bảo mật chủ động cài trên Windows/Linux/macOS, "
         "máy chủ phân tích với hệ thống *decoder* và *rule*, bộ chỉ mục dựa trên OpenSearch và dashboard. Đây là hình mẫu trực tiếp cho kiến trúc *agent → server → lưu trữ → dashboard* của đề tài.")
    figure("06_wazuh_architecture.png", "Kiến trúc Wazuh", P, 6.3)
    table(["Thành phần", "Chức năng", "Ghi chú"], [
        ["Wazuh agent", "Thu thập log (tệp, Windows Event Channel, journald), giám sát toàn vẹn tệp (FIM), đánh giá cấu hình (SCA, CIS benchmark), phát hiện lỗ hổng (CVE), rootcheck, kiểm kê hệ thống, active response", "Cấu hình `ossec.conf`; dùng ít tài nguyên; đăng ký bằng khóa với manager"],
        ["Wazuh server (manager)", "Nhận sự kiện qua TCP/UDP 1514 (mã hóa AES), đăng ký agent qua 1515, API REST 55000; phân tích bằng decoder (tách trường) rồi rule (cho điểm 0-15, gắn MITRE, PCI, GDPR, HIPAA)", "Có thể cụm nhiều node (master/worker)"],
        ["Wazuh indexer", "Lưu trữ alerts/archives (OpenSearch, cổng 9200)", "Chỉ mục wazuh-alerts-4.x-*, wazuh-archives-*"],
        ["Wazuh dashboard", "Giao diện web (443): tổng quan, MITRE ATT&CK, tuân thủ, quản lý agent, Security Configuration Assessment", "Dựa trên OpenSearch Dashboards"],
    ], widths=[1.4, 3.2, 1.9], size=9.5, caption="Thành phần Wazuh", part=P)
    h3("2.2.2. Cấu hình thu thập log trên agent")
    code("<!-- ossec.conf trên agent Windows -->\n<localfile>\n  <location>Security</location>\n  <log_format>eventchannel</log_format>\n  <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 4688]</query>\n</localfile>\n<localfile>\n  <location>Microsoft-Windows-Sysmon/Operational</location>\n  <log_format>eventchannel</log_format>\n</localfile>\n\n<!-- ossec.conf trên agent Linux -->\n<localfile>\n  <location>/var/log/auth.log</location>\n  <log_format>syslog</log_format>\n</localfile>\n<localfile>\n  <location>journald</location>\n  <log_format>journald</log_format>\n</localfile>")
    para("Wazuh dùng XPath để loại EventID nhiễu ngay tại agent - cùng cách SOC Agent lọc bằng danh sách `event_ids` trong XPath của `wevtutil`.")
    h3("2.2.3. Decoder và rule")
    para("Mỗi dòng log đi qua *pre-decoder* (tách thời gian, host, chương trình), rồi *decoder* đặc thù (regex tách `srcuser`, `srcip`, `dstuser`...), rồi được so với cây *rule*. "
         "Rule có `level` 0-15 (0 = bỏ qua, ≥ 3 sinh cảnh báo mặc định, 12+ nghiêm trọng), có thể kế thừa (`if_sid`), đếm tần suất (`frequency`, `timeframe`, `same_source_ip`) và gắn nhãn `mitre`. Ví dụ rút gọn từ ruleset sshd:")
    code("<decoder name=\"sshd-failed\">\n  <parent>sshd</parent>\n  <prematch>^Failed password for </prematch>\n  <regex>^Failed password for (invalid user )?(\\S+) from (\\S+) port (\\d+)</regex>\n  <order>srcuser, srcip, srcport</order>\n</decoder>\n\n<rule id=\"5716\" level=\"5\">\n  <if_sid>5700</if_sid>\n  <match>^Failed|^error: PAM: Authentication</match>\n  <description>sshd: authentication failed.</description>\n  <mitre><id>T1110.001</id></mitre>\n</rule>\n<rule id=\"5720\" level=\"10\" frequency=\"8\" timeframe=\"120\">\n  <if_matched_sid>5716</if_matched_sid>\n  <same_source_ip />\n  <description>sshd: Multiple authentication failures.</description>\n  <mitre><id>T1110.001</id></mitre>\n</rule>")
    para("Rule 5720 chính là luật *threshold* (≥ 8 lần 5716 cùng IP trong 120 giây) - tương đương R15 của đề tài (≥ 5 lần trong 120 giây). Cây rule của Wazuh có hơn 3.000 luật cho hàng trăm nguồn log.")
    table(["Khái niệm Wazuh", "Tương đương trong đề tài"], [
        ["decoder (regex tách trường)", "AUTH_PATTERNS trong parsers.py"],
        ["rule <match>, <regex>, <field>", "Luật match với conditions {action, event_id, regex, extra}"],
        ["frequency + timeframe + same_source_ip", "Luật threshold: threshold_count, window_seconds, group_by=src_ip"],
        ["if_matched_sid (luật phụ thuộc)", "Luật sequence: precondition → trigger"],
        ["level 0-15", "severity 5 mức"],
        ["<mitre><id>", "mitre_technique, mitre_tactic"],
        ["agent key + 1515/1514", "enrollment token + API key + /api/v1/logs"],
        ["active response", "Chưa có (AI chỉ khuyến nghị)"],
    ], widths=[3.0, 3.5], size=10, caption="Ánh xạ khái niệm Wazuh sang hệ thống đề tài", part=P)
    h3("2.2.4. Các năng lực khác của agent")
    bullets([
        "**FIM (File Integrity Monitoring):** phát hiện thay đổi tệp/registry theo thời gian thực hoặc theo lịch (syscheck) - bắt webshell, sửa /etc/passwd.",
        "**SCA (Security Configuration Assessment):** kiểm tra cấu hình theo CIS Benchmark, cho điểm.",
        "**Vulnerability Detection:** đối chiếu phần mềm cài đặt với CVE feed.",
        "**Active Response:** kịch bản phản ứng tự động (chặn IP bằng firewall-drop, vô hiệu tài khoản) khi rule đạt mức - tương ứng SOAR mini.",
        "**Command monitoring, Docker/cloud (AWS, Azure, GCP, Microsoft 365) integration.**",
    ])
    h3("2.2.5. Ưu nhược điểm và bài học")
    bullets([
        "**Ưu điểm:** miễn phí, đầy đủ năng lực XDR, cộng đồng lớn, ruleset phong phú, tuân thủ sẵn (PCI, GDPR, NIST 800-53), dashboard MITRE.",
        "**Nhược điểm:** viết decoder/rule bằng XML không trực quan, cần hiểu cây rule; indexer tốn tài nguyên; không có lớp AI phân loại/điều tra.",
        "**Bài học cho đề tài:** (1) ba loại luật tương ứng if_sid/frequency/if_matched_sid; (2) thang mức nghiêm trọng và gắn MITRE trên luật; (3) agent đăng ký bằng khóa rồi xác thực mọi gói tin; (4) lọc EventID nhiễu ngay tại agent.",
    ])
    link_line("Wazuh documentation - Architecture", "https://documentation.wazuh.com/current/getting-started/architecture.html")
    link_line("Wazuh - Ruleset (decoders & rules)", "https://documentation.wazuh.com/current/user-manual/ruleset/index.html")
    link_line("Wazuh - Log data collection", "https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html")
    link_line("Wazuh GitHub", "https://github.com/wazuh/wazuh")

    # ------------------------------------------------------------------ 2.3 Prometheus
    h2("2.3. Prometheus")
    h3("2.3.1. Tổng quan và kiến trúc")
    para("**Prometheus** (Apache 2.0, dự án tốt nghiệp thứ hai của CNCF sau Kubernetes) là hệ thống **giám sát chỉ số (metrics)** theo mô hình **pull**: máy chủ Prometheus định kỳ (mặc định 15 s) "
         "gọi HTTP tới các *exporter* để lấy số liệu dạng chuỗi thời gian, lưu vào TSDB cục bộ và cho phép truy vấn bằng **PromQL**. Prometheus không phải SIEM - nó không thu thập log an ninh - "
         "nhưng được khảo sát vì mô hình \"agent phơi dữ liệu - server thu định kỳ - cảnh báo theo luật - dashboard\" rất gần với yêu cầu của đề tài, và vì giám sát sức khỏe máy chủ là một phần của SOC hiện đại "
         "(sự cố an ninh thường biểu hiện qua CPU tăng vọt, đĩa đầy do log, dịch vụ chết).")
    figure("07_prometheus_architecture.png", "Kiến trúc Prometheus", P, 6.0)
    table(["Thành phần", "Vai trò", "Ví dụ"], [
        ["Exporter", "Phơi chỉ số qua HTTP /metrics (định dạng văn bản)", "node_exporter (Linux, :9100), windows_exporter (:9182), blackbox_exporter, mysqld_exporter"],
        ["Prometheus server", "Scrape, lưu TSDB, đánh giá recording/alerting rules", "Cổng 9090; lưu mặc định 15 ngày"],
        ["Alertmanager", "Gộp, ức chế, định tuyến cảnh báo", "Cổng 9093; gửi email/Slack/webhook"],
        ["Pushgateway", "Nhận số liệu đẩy từ job ngắn hạn", "Cron job, batch"],
        ["Grafana", "Dashboard (sản phẩm riêng, phổ biến đi kèm); Loki cho log", "Cổng 3000"],
    ], widths=[1.4, 2.6, 2.5], size=10, caption="Thành phần Prometheus", part=P)
    h3("2.3.2. Cấu hình, PromQL và luật cảnh báo")
    code("# prometheus.yml\nglobal: {scrape_interval: 15s}\nscrape_configs:\n  - job_name: node\n    static_configs: [{targets: ['web01:9100', 'db01:9100']}]\n  - job_name: windows\n    static_configs: [{targets: ['WIN-DC01:9182']}]\nrule_files: [alerts.yml]\n\n# alerts.yml\ngroups:\n  - name: host\n    rules:\n      - alert: HostDown\n        expr: up == 0\n        for: 5m\n        labels: {severity: critical}\n        annotations: {summary: \"{{ $labels.instance }} không phản hồi\"}\n      - alert: HighCPU\n        expr: 100 - avg by(instance)(rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100 > 90\n        for: 10m\n      - alert: SSHFailedLoginsSpike        # cần exporter đếm từ log (vd mtail, grok_exporter)\n        expr: increase(sshd_failed_logins_total[5m]) > 50")
    h3("2.3.3. So sánh pull và push; bài học")
    table(["Tiêu chí", "Pull (Prometheus)", "Push (SIEM, SOC Agent)"], [
        ["Phát hiện mục tiêu chết", "Tức thì (up == 0)", "Qua heartbeat / thời gian im lặng"],
        ["Xuyên NAT/firewall", "Server phải tới được mục tiêu", "Agent chỉ cần ra ngoài (HTTPS)"],
        ["Khối lượng dữ liệu", "Số liệu nhỏ, định kỳ", "Log lớn, theo lô, bùng nổ khi tấn công"],
        ["Bảo mật", "Phải mở cổng trên máy nguồn", "Không mở cổng; xác thực bằng khóa"],
        ["Thứ tự/mất mát", "Mẫu định kỳ, bỏ qua được", "Không được mất: cần hàng đợi, ACK, dedup"],
    ], widths=[1.8, 2.3, 2.4], size=10, caption="Pull và push", part=P)
    para("SOC Agent chọn mô hình đẩy (POST theo lô) nhưng mượn ý tưởng *heartbeat* của Prometheus để server phát hiện agent offline sau 180 giây và hiển thị CPU/RAM/đĩa (psutil) trên trang Máy trạm. "
         "Một hướng phát triển là xuất chỉ số của chính Web SOC (`/metrics`: số sự kiện/giây, cảnh báo mở, thời gian AI) để Prometheus/Grafana giám sát sức khỏe SOC.")
    link_line("Prometheus - Overview", "https://prometheus.io/docs/introduction/overview/")
    link_line("Prometheus - Querying basics (PromQL)", "https://prometheus.io/docs/prometheus/latest/querying/basics/")
    link_line("Alertmanager", "https://prometheus.io/docs/alerting/latest/alertmanager/")
    link_line("Grafana Loki (log) ", "https://grafana.com/oss/loki/")

    # ------------------------------------------------------------------ 2.4 khác
    h2("2.4. Một số nền tảng khác")
    table(["Nền tảng", "Loại", "Đặc điểm nổi bật", "Liên kết"], [
        ["Splunk Enterprise Security", "SIEM thương mại", "Ngôn ngữ SPL mạnh, Common Information Model, app ES; cấp phép theo GB/ngày; ASP hỗ trợ kết nối qua cổng 8089", "[splunk.com](https://www.splunk.com/en_us/products/enterprise-security.html)"],
        ["Microsoft Sentinel", "SIEM/SOAR cloud-native", "Trên Azure, KQL, kết nối sẵn Microsoft 365/Defender, playbook Logic Apps, Security Copilot", "[learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/overview)"],
        ["Google Chronicle (SecOps)", "SIEM cloud", "Lưu trữ 1 năm nóng, UDM schema, YARA-L rules, Gemini", "[cloud.google.com](https://cloud.google.com/chronicle)"],
        ["Graylog", "Log management / SIEM", "Mã nguồn mở, dựa trên OpenSearch + MongoDB, pipeline rules, Graylog Security", "[graylog.org](https://graylog.org/)"],
        ["Security Onion", "Bản phân phối NSM/SIEM", "Gói sẵn Suricata, Zeek, Elastic, Elastic Agent cho giám sát mạng", "[securityonion.net](https://securityonionsolutions.com/)"],
        ["OSSEC", "HIDS", "Tiền thân của Wazuh; FIM, rootkit, phân tích log", "[ossec.net](https://www.ossec.net/)"],
        ["TheHive + Cortex", "Quản lý vụ việc + phân tích IOC", "Case management mã nguồn mở, analyzers làm giàu IOC; mô hình Case/Observable giống ASP", "[strangebee.com](https://strangebee.com/thehive/)"],
        ["Shuffle / n8n", "SOAR mã nguồn mở", "Workflow tự động hóa phản ứng", "[shuffler.io](https://shuffler.io/)"],
        ["MISP", "Threat intelligence platform", "Chia sẻ IOC, STIX/TAXII", "[misp-project.org](https://www.misp-project.org/)"],
        ["Sigma", "Định dạng luật chung", "Luật YAML độc lập nền tảng, chuyển đổi sang Splunk/Elastic/Wazuh bằng sigma-cli", "[sigmahq.io](https://sigmahq.io/)"],
    ], widths=[1.5, 1.2, 2.9, 1.1], size=9.5, caption="Các nền tảng khác", part=P)
    h3("2.4.1. Ví dụ truy vấn tương đương trên nhiều nền tảng")
    para("Cùng một nhu cầu \"liệt kê IP có ≥ 5 lần đăng nhập SSH thất bại trong 2 phút\" được biểu diễn như sau:")
    code("# Splunk SPL\nindex=linux sourcetype=linux_secure \"Failed password\"\n| bin _time span=2m | stats count by _time, src_ip | where count >= 5\n\n# Microsoft Sentinel KQL\nSyslog | where ProcessName == \"sshd\" and SyslogMessage has \"Failed password\"\n| extend src_ip = extract(@\"from (\\S+) port\", 1, SyslogMessage)\n| summarize count() by src_ip, bin(TimeGenerated, 2m) | where count_ >= 5\n\n# Graylog pipeline rule\nrule \"ssh failed\"\nwhen has_field(\"message\") && contains(to_string($message.message), \"Failed password\")\nthen set_field(\"event_action\", \"logon_failed\"); end\n\n# Hệ thống đề tài (luật R15, JSON)\n{\"rule_type\": \"threshold\", \"conditions\": {\"action\": [\"logon_failed\"], \"source\": [\"linux.auth\", \"journald\"]},\n \"threshold_count\": 5, \"window_seconds\": 120, \"group_by\": \"src_ip\"}")
    h3("2.4.2. Sigma - ngôn ngữ luật chung và detection engineering")
    para("**Sigma** là định dạng YAML mô tả luật phát hiện độc lập với sản phẩm (giống Snort cho mạng, YARA cho tệp). Kho SigmaHQ có hơn 3.000 luật gắn ATT&CK; "
         "công cụ `sigma-cli`/pySigma chuyển luật sang truy vấn của từng SIEM. Quy trình *detection engineering* hiện đại coi luật là mã: viết, kiểm thử trên dữ liệu lịch sử, review, triển khai, đo lường.")
    figure("25_sigma_to_rule.png", "Từ luật Sigma tới luật JSON của Rule Engine và vòng đời luật", P, 6.5)
    code("title: SSH Brute Force Attempt\nid: 7b2c9c8a-...\nstatus: stable\nlogsource:\n  product: linux\n  service: auth\ndetection:\n  selection:\n    Message|contains: 'Failed password for'\n  timeframe: 2m\n  condition: selection | count() by SourceIp > 5\nlevel: high\ntags: [attack.credential_access, attack.t1110.001]")

    # ------------------------------------------------------------------ 2.5 so sánh
    h2("2.5. Bảng so sánh tổng hợp và bài học rút ra")
    table(["Tiêu chí", "ELK", "Wazuh", "Prometheus", "ASP (funnywolf)", "Web SOC (đề tài)"], [
        ["Trọng tâm", "Log analytics / SIEM", "XDR + SIEM", "Metrics", "Agentic SOC (lớp trên SIEM)", "SIEM thu nhỏ + 4 tác tử AI"],
        ["Thu thập", "Beats/Elastic Agent (push)", "Wazuh agent (push, AES)", "Exporter (pull)", "Nhận alert từ Splunk/ELK/webhook", "SOC Agent (push, REST, API key)"],
        ["Lưu trữ", "Elasticsearch", "OpenSearch", "TSDB", "PostgreSQL + Redis + S3", "SQLite (WAL)"],
        ["Chuẩn hóa", "ECS, Ingest Pipeline", "Decoder", "Nhãn (labels)", "Module Python", "parsers.py (17 trường)"],
        ["Phát hiện", "Rule/ML trong Security app", "Rule (level 0-15)", "PromQL alert rules", "Module Python, LLM", "Rule engine match/threshold/sequence"],
        ["AI", "Elastic AI Assistant (trả phí)", "Chưa tích hợp mặc định", "Không", "LLM Playbook, Harness Agent", "Enrichment/Triage/Investigation/Knowledge"],
        ["Quản lý vụ việc", "Cases", "Không (tích hợp TheHive)", "Không", "Case war room", "Alert + investigations + KB"],
        ["Triển khai", "Nặng (JVM, cluster)", "Trung bình (3 dịch vụ)", "Nhẹ", "Docker Compose, 6+ dịch vụ", "Rất nhẹ: 1 tiến trình Python"],
        ["Giấy phép", "Elastic/SSPL/AGPL", "GPLv2", "Apache 2.0", "MIT", "Mã đề tài"],
    ], widths=[1.0, 1.1, 1.1, 0.9, 1.2, 1.4], size=9, caption="So sánh tổng hợp các nền tảng", part=P)
    para("**Bài học rút ra:** (1) cần một lược đồ chuẩn hóa chung ngay từ agent; (2) agent phải nhớ con trỏ để không gửi lại và không bỏ sót; (3) luật phát hiện phải có ba cơ chế cơ bản và gắn MITRE; "
         "(4) cảnh báo cần được làm giàu trước khi tới người; (5) dashboard cần KPI, biểu đồ theo thời gian và top-N; (6) lớp Agentic AI nên đặt phía trên pipeline phát hiện, không thay thế nó; "
         "(7) coi luật là mã: kiểm thử, đo lường, có vòng đời.")
    page_break()
