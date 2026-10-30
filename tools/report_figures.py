# -*- coding: utf-8 -*-
"""
report_figures.py - Sinh sơ đồ và biểu đồ (PNG) cho báo cáo chi tiết (docs/figures/).

    python tools/report_figures.py

Sơ đồ khái niệm vẽ bằng matplotlib (hộp + mũi tên); biểu đồ số liệu lấy trực tiếp từ CSDL demo
soc_server/instance/soc.db nếu có. Bảng màu theo bộ màu dữ liệu đã kiểm định (categorical cố định,
ramp xanh cho mức độ thứ bậc, màu trạng thái dành riêng cho critical/high/medium).
"""
import os
import sqlite3
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "figures")
DB = os.path.join(ROOT, "soc_server", "instance", "soc_demo.db")      # CSDL demo tái tạo bằng mã mới
if not os.path.exists(DB):
    DB = os.path.join(ROOT, "soc_server", "instance", "soc.db")
os.makedirs(OUT, exist_ok=True)

# ---- bảng màu (references/palette.md) ----
CAT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SEQ = {"info": "#b7d3f6", "low": "#86b6ef", "medium": "#5598e7", "high": "#256abf", "critical": "#104281"}
INK, INK2, MUTED, GRID, SURF = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#fcfcfb"
BOX_FILL, BOX_EDGE, ACCENT_FILL, ACCENT_EDGE = "#f3f4f6", "#b8b7b0", "#e3eefb", "#2a78d6"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.edgecolor": MUTED,
                     "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
                     "figure.facecolor": "white", "axes.facecolor": SURF})


# =============================================================== tiện ích vẽ
def fig(w=10, h=5.6):
    f, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    return f, ax


def box(ax, x, y, w, h, title, sub=None, fill=BOX_FILL, edge=BOX_EDGE, fs=10.5, sfs=8.6, lw=1.3, bold=True,
        valign="center"):
    """Hộp bo góc có tiêu đề và mô tả nhiều dòng; khối chữ được canh giữa (hoặc sát trên) theo số dòng."""
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.6",
                                fc=fill, ec=edge, lw=lw))
    n_title = title.count("\n") + 1
    n_sub = (sub.count("\n") + 1) if sub else 0
    lh_t, lh_s = 3.9 * fs / 10.5, 3.3 * sfs / 8.6
    block = n_title * lh_t + (n_sub * lh_s + 0.8 if sub else 0)
    top = (y + h - 1.6) if valign == "top" else (y + h / 2 + block / 2)
    ax.text(x + w / 2, top, title, ha="center", va="top", fontsize=fs, color=INK,
            fontweight="bold" if bold else "normal", linespacing=1.15)
    if sub:
        ax.text(x + w / 2, top - n_title * lh_t - 0.8, sub, ha="center", va="top", fontsize=sfs, color=INK2,
                linespacing=1.25)


def arrow(ax, x1, y1, x2, y2, color=MUTED, lw=1.4, style="-|>", ls="-", shrink=2):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, color=color, lw=lw,
                                 mutation_scale=13, linestyle=ls, shrinkA=shrink, shrinkB=shrink))


def label(ax, x, y, text, fs=8.6, color=INK2, ha="center", **kw):
    ax.text(x, y, text, ha=ha, va="center", fontsize=fs, color=color, **kw)


def title(ax, text):
    ax.text(1, 97, text, fontsize=12.5, fontweight="bold", color=INK, va="top")


def save(f, name):
    path = os.path.join(OUT, name)
    f.savefig(path, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(f)
    print("  +", name)


def bar_style(ax, horizontal=False):
    ax.set_facecolor(SURF)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color(GRID)
    ax.spines["bottom"].set_color(GRID)
    ax.grid(axis="x" if horizontal else "y", color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)


# =============================================================== 1. SOC
def f_soc_components():
    f, ax = fig(10, 5.2)
    title(ax, "SOC = Con người + Quy trình + Công nghệ")
    box(ax, 36, 40, 28, 18, "SOC", "Giám sát 24/7, phát hiện,\nphản ứng, báo cáo", fill=ACCENT_FILL, edge=ACCENT_EDGE, fs=13)
    box(ax, 2, 66, 30, 22, "Con người", "Analyst Tier 1/2/3, Threat Hunter,\nIncident Responder, SOC Manager")
    box(ax, 68, 66, 30, 22, "Quy trình", "Giám sát → phân loại → điều tra →\nphản ứng → rút kinh nghiệm (NIST 800-61)")
    box(ax, 35, 6, 30, 22, "Công nghệ", "SIEM, EDR/XDR, SOAR, Threat Intel,\nTicketing, Agentic AI")
    for (x1, y1) in ((17, 66), (83, 66), (50, 28)):
        arrow(ax, x1, y1, 50, 49, style="<|-|>")
    save(f, "01_soc_components.png")


def f_soc_tiers():
    f, ax = fig(10, 5.4)
    title(ax, "Mô hình phân tầng xử lý cảnh báo trong SOC và vai trò của tác tử AI")
    tiers = [("Tier 1 - Giám sát & phân loại", "Nhận cảnh báo, loại dương tính giả,\nleo thang khi cần", 4, 72, 44, 16),
             ("Tier 2 - Điều tra sâu", "Dựng chuỗi tấn công, xác định phạm vi,\nkhuyến nghị khắc phục", 4, 50, 44, 16),
             ("Tier 3 - Threat Hunting / Ứng cứu", "Săn mối đe dọa, ứng cứu sự cố lớn,\nphân tích mã độc", 4, 28, 44, 16),
             ("Quản lý & tri thức", "Playbook, bài học, báo cáo tuân thủ", 4, 6, 44, 16)]
    for t, s, x, y, w, h in tiers:
        box(ax, x, y, w, h, t, s)
    for y in (72, 50, 28):
        arrow(ax, 26, y, 26, y - 6)
    ai = [("Enrichment + Triage Agent", "chấm điểm rủi ro, xếp ưu tiên,\ngiảm alert fatigue", 80),
          ("Investigation Agent", "dòng thời gian, MITRE ATT&CK,\nIOC, khuyến nghị", 58),
          ("(con người quyết định)", "AI chỉ đề xuất, không tự thi hành", 36),
          ("Knowledge Agent", "tự sinh playbook / bài học", 14)]
    for t, s, y in ai:
        box(ax, 56, y - 8, 42, 16, t, s, fill=ACCENT_FILL, edge=ACCENT_EDGE)
        arrow(ax, 48, y, 56, y, ls="--")
    save(f, "02_soc_tiers_ai.png")


def f_nist_lifecycle():
    f, ax = fig(10, 5)
    title(ax, "Vòng đời xử lý sự cố theo NIST SP 800-61 và ánh xạ vào hệ thống")
    steps = [("1. Chuẩn bị", "luật phát hiện, agent,\nplaybook, tài khoản", 2),
             ("2. Phát hiện & phân tích", "thu thập log, rule engine,\nEnrichment + Triage AI", 27),
             ("3. Ngăn chặn, loại bỏ,\nkhôi phục", "khuyến nghị của Investigation\nAgent, analyst thực hiện", 52),
             ("4. Hoạt động sau sự cố", "Knowledge Agent rút bài học,\nbáo cáo, cập nhật luật", 77)]
    for t, s, x in steps:
        box(ax, x, 40, 21, 30, t, s, fs=10)
    for x in (23, 48, 73):
        arrow(ax, x, 55, x + 4, 55)
    ax.add_patch(FancyArrowPatch((87, 40), (12, 40), arrowstyle="-|>", color=MUTED, lw=1.4, mutation_scale=13,
                                 connectionstyle="arc3,rad=0.35", linestyle="--"))
    label(ax, 50, 14, "phản hồi liên tục: bài học → cải thiện luật và quy trình", fs=9)
    save(f, "03_nist_lifecycle.png")


# =============================================================== 2. SIEM
def f_siem_pipeline():
    f, ax = fig(11, 5.2)
    title(ax, "Năm bước xử lý của một hệ thống SIEM")
    steps = [("1. Thu thập", "agent, syslog, API,\nbeats, webhook"),
             ("2. Chuẩn hóa", "parse, lược đồ chung\n(ECS / OCSF)"),
             ("3. Tương quan", "luật, ngưỡng, chuỗi,\nML / UEBA"),
             ("4. Cảnh báo", "ưu tiên, gộp trùng,\nenrichment"),
             ("5. Trình bày", "dashboard, tìm kiếm,\nbáo cáo, lưu trữ")]
    for i, (t, s) in enumerate(steps):
        x = 2 + i * 19.6
        box(ax, x, 48, 17.5, 26, t, s, fill=ACCENT_FILL if i in (1, 2) else BOX_FILL,
            edge=ACCENT_EDGE if i in (1, 2) else BOX_EDGE)
        if i < 4:
            arrow(ax, x + 17.5, 61, x + 19.6, 61)
    srcs = ["Windows Event Log", "Linux syslog / journald", "Web / ứng dụng", "Firewall, IDS, cloud"]
    for i, s in enumerate(srcs):
        box(ax, 2 + i * 24, 10, 22, 12, s, fs=9, bold=False)
        arrow(ax, 13 + i * 24, 22, 10.5, 48, ls=":")
    label(ax, 50, 86, "Web SOC trong đề tài tái hiện đủ 5 bước ở quy mô nhỏ: SOC Agent → parsers.py → RuleEngine → alerts + AI → dashboard", fs=9)
    save(f, "04_siem_pipeline.png")


def f_elk():
    f, ax = fig(10, 4.6)
    title(ax, "Kiến trúc Elastic Stack (ELK)")
    comps = [("Beats / Elastic Agent", "Filebeat, Winlogbeat,\nMetricbeat trên máy nguồn", 2),
             ("Logstash", "pipeline: input → filter\n(grok, mutate) → output", 27),
             ("Elasticsearch", "lưu trữ JSON, chỉ mục\nđảo ngược, tìm kiếm", 52),
             ("Kibana", "dashboard, Discover,\nSIEM app, cảnh báo", 77)]
    for t, s, x in comps:
        box(ax, x, 40, 21, 30, t, s, fill=ACCENT_FILL if t == "Elasticsearch" else BOX_FILL,
            edge=ACCENT_EDGE if t == "Elasticsearch" else BOX_EDGE)
    for x in (23, 48, 73):
        arrow(ax, x, 55, x + 4, 55)
    label(ax, 35.5, 78, "gửi trực tiếp (bỏ qua Logstash)", fs=8.5)
    ax.add_patch(FancyArrowPatch((12, 70), (62, 70), arrowstyle="-|>", color=MUTED, lw=1.2, mutation_scale=12,
                                 connectionstyle="arc3,rad=-0.25", linestyle="--"))
    label(ax, 50, 18, "Lược đồ dữ liệu chung: Elastic Common Schema (ECS) - nguồn cảm hứng cho lược đồ của parsers.py", fs=9)
    save(f, "05_elk_architecture.png")


def f_wazuh():
    f, ax = fig(10, 5.2)
    title(ax, "Kiến trúc Wazuh (XDR + SIEM mã nguồn mở)")
    for i, name in enumerate(("Windows agent", "Linux agent", "macOS agent")):
        box(ax, 2, 70 - i * 22, 20, 14, name, "thu thập log, FIM,\nvulnerability", fs=9.5)
        arrow(ax, 22, 77 - i * 22, 30, 60)
    box(ax, 30, 40, 24, 38, "Wazuh server", "Analysis engine:\ndecoder → rules → alerts\nTCP 1514 (dữ liệu, AES)\nTCP 1515 (đăng ký agent)",
        fill=ACCENT_FILL, edge=ACCENT_EDGE)
    box(ax, 62, 55, 20, 20, "Wazuh indexer", "OpenSearch\nlưu alerts, archives")
    box(ax, 62, 25, 20, 20, "Wazuh dashboard", "giao diện web,\nMITRE, compliance")
    arrow(ax, 54, 62, 62, 65)
    arrow(ax, 72, 55, 72, 45)
    arrow(ax, 82, 35, 92, 35)
    label(ax, 95, 35, "Analyst", fs=9, fontweight="bold")
    label(ax, 50, 12, "Mô hình agent → server → indexer → dashboard là hình mẫu trực tiếp của SOC Agent → Web SOC", fs=9)
    save(f, "06_wazuh_architecture.png")


def f_prometheus():
    f, ax = fig(10, 4.8)
    title(ax, "Kiến trúc Prometheus (giám sát chỉ số, mô hình pull)")
    for i, name in enumerate(("node_exporter", "windows_exporter", "ứng dụng /metrics")):
        box(ax, 2, 68 - i * 22, 22, 14, name, "phơi chỉ số HTTP", fs=9.5)
        arrow(ax, 36, 58, 24, 75 - i * 22, ls="-")
    box(ax, 36, 40, 26, 36, "Prometheus server", "scrape định kỳ (pull)\nTSDB chuỗi thời gian\nPromQL, rules",
        fill=ACCENT_FILL, edge=ACCENT_EDGE)
    box(ax, 70, 60, 26, 16, "Alertmanager", "gộp, định tuyến,\nemail / Slack / webhook")
    box(ax, 70, 32, 26, 16, "Grafana", "dashboard")
    box(ax, 36, 10, 26, 14, "Pushgateway", "cho job ngắn hạn", fs=9.5)
    arrow(ax, 62, 66, 70, 68)
    arrow(ax, 62, 50, 70, 40)
    arrow(ax, 49, 24, 49, 40)
    label(ax, 83, 12, "Mạnh về sức khỏe hệ thống (metrics),\nkhông phải log an ninh", fs=9)
    save(f, "07_prometheus_architecture.png")


def f_asp_pipeline():
    f, ax = fig(11, 5.8)
    title(ax, "Agentic SOC Platform (ASP): từ dòng cảnh báo tới tri thức")
    box(ax, 2, 70, 20, 20, "Nguồn cảnh báo", "Splunk / ELK Index Action /\nWebhook / EDR / cloud", fs=10)
    box(ax, 27, 70, 18, 20, "Redis Stream", "hàng đợi\ncảnh báo thô")
    box(ax, 50, 70, 22, 20, "Module (Python)", "ánh xạ trường, trích IOC,\ntương quan tín hiệu", fill=ACCENT_FILL, edge=ACCENT_EDGE)
    box(ax, 77, 70, 21, 20, "Case / Alert / Artifact", "hội tụ thành ít Case\nkhả thi", fill=ACCENT_FILL, edge=ACCENT_EDGE)
    arrow(ax, 22, 80, 27, 80); arrow(ax, 45, 80, 50, 80); arrow(ax, 72, 80, 77, 80)
    box(ax, 50, 36, 22, 22, "Playbook (Python)", "Investigation (LLM),\nKnowledge Extraction,\nThreat Intel / CMDB Enrichment")
    box(ax, 77, 36, 21, 22, "Knowledge", "bài học tái sử dụng,\ntrích từ Case đã có verdict")
    box(ax, 2, 36, 20, 22, "Harness Agent", "Claude Code / Codex qua\nasp-cli + Skills")
    box(ax, 27, 36, 18, 22, "Analyst", "xem bằng chứng, xác nhận\nbáo cáo AI, ra quyết định", fill="#fff7e6", edge="#eda100")
    arrow(ax, 87, 70, 87, 58, ls="--"); arrow(ax, 72, 47, 77, 47)
    arrow(ax, 61, 70, 61, 58); arrow(ax, 45, 47, 50, 47); arrow(ax, 22, 47, 27, 47, style="<|-|>")
    box(ax, 2, 6, 96, 18, "Nền tảng: Django (backend) + Vite/Ant Design (frontend) + PostgreSQL + Redis + RustFS (S3); LDAP, API Key, Audit Log, Inbox; MIT License",
        fs=9.5, bold=False)
    save(f, "08_asp_pipeline.png")


def f_asp_datamodel():
    f, ax = fig(10, 5.2)
    title(ax, "Mô hình dữ liệu cốt lõi của ASP và ánh xạ sang Web SOC của đề tài")
    rows = [("Case", "\"war room\" của sự cố: verdict, severity, assignee,\ncomments, timeline, báo cáo AI", "alerts (+ dedup_key, ai_*) & investigations"),
            ("Alert", "bản ghi cảnh báo từ SIEM/EDR: rule, product,\nMITRE, raw log", "alerts ↔ detection_rules"),
            ("Artifact", "thực thể / IOC: IP, domain, hash, tài khoản,\nhost, tiến trình", "log_events.src_ip / user_name / host, iocs"),
            ("Enrichment", "ngữ cảnh ngoài: threat intel, CMDB, danh tính,\nlịch sử", "enrichment.py + ip_reputation"),
            ("Playbook", "tác vụ tự động (Python) quanh Case:\nInvestigation, Knowledge, TI", "ai/agents.py + orchestrator"),
            ("Knowledge", "tri thức tái sử dụng rút từ Case đã kết luận", "knowledge_articles")]
    label(ax, 11, 90, "ASP", fs=10.5, fontweight="bold"); label(ax, 46, 90, "Ý nghĩa", fs=10.5, fontweight="bold")
    label(ax, 83, 90, "Web SOC (đề tài)", fs=10.5, fontweight="bold")
    for i, (n, d, m) in enumerate(rows):
        y = 76 - i * 14
        box(ax, 2, y - 5, 18, 11, n, fill=ACCENT_FILL, edge=ACCENT_EDGE, fs=10)
        label(ax, 24, y, d, fs=8.6, ha="left")
        box(ax, 68, y - 5, 30, 11, m, fs=8.6, bold=False)
        arrow(ax, 20, y, 24, y, lw=0.8); arrow(ax, 64, y, 68, y, ls="--")
    save(f, "09_asp_datamodel_mapping.png")


# =============================================================== 3. Log hệ điều hành
def f_windows_eventlog():
    f, ax = fig(11, 6)
    title(ax, "Cấu trúc một bản ghi Windows Event Log (XML, kênh Security)")
    box(ax, 2, 4, 46, 88, "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>", fill="white", fs=8.5, valign="top")
    box(ax, 5, 50, 40, 36, "<System>", "metadata do hệ thống ghi", fill=BOX_FILL, fs=10, valign="top")
    sysf = ["Provider Name='Microsoft-Windows-Security-Auditing'", "EventID 4625", "Level 0 (LogAlways) · Task · Opcode",
            "Keywords 0x8010... (Audit Failure)", "TimeCreated SystemTime='2026-10-26T03:30:00Z'",
            "EventRecordID 88123", "Channel Security · Computer WIN-SRV01"]
    for i, s in enumerate(sysf):
        label(ax, 8, 75 - i * 3.8, s, fs=8, ha="left", family="DejaVu Sans Mono")
    label(ax, 27, 75 - 5 * 3.8, "← con trỏ (cursor) của agent", fs=8, ha="left", color=ACCENT_EDGE)
    box(ax, 5, 10, 40, 36, "<EventData>", "các trường đặc thù theo EventID", fill=BOX_FILL, fs=10, valign="top")
    evf = ["Data Name='TargetUserName'  Administrator", "Data Name='LogonType'  10 (RemoteInteractive)",
           "Data Name='IpAddress'  203.0.113.66", "Data Name='IpPort'  50123",
           "Data Name='Status'  0xC000006D", "Data Name='SubStatus'  0xC000006A (bad password)"]
    for i, s in enumerate(evf):
        label(ax, 8, 35 - i * 3.8, s, fs=8, ha="left", family="DejaVu Sans Mono")
    box(ax, 54, 60, 44, 28, "Chuẩn hóa trong parsers.py", "EventID → (action, outcome, category,\nseverity, user_field, ip_field)\n4625 → logon_failed / failure / authentication / medium\nTargetUserName → user · IpAddress → src_ip\nIpPort → src_port · EventData → extra{}",
        fill=ACCENT_FILL, edge=ACCENT_EDGE, sfs=8.2)
    box(ax, 54, 22, 44, 30, "Các kênh và cách đọc", "Security: xác thực, tài khoản, đặc quyền, 1102\nSystem: dịch vụ 7045/7036, tắt máy 6008, 104\nApplication: crash 1000/1001\nĐọc: Event Viewer · wevtutil qe · Get-WinEvent\nTệp .evtx trong %SystemRoot%\\System32\\winevt\\Logs",
        sfs=8.2)
    arrow(ax, 48, 70, 54, 74)
    save(f, "10_windows_eventlog_structure.png")


def f_syslog_format():
    f, ax = fig(11, 5.6)
    title(ax, "Cấu trúc thông điệp syslog: BSD (RFC 3164) và RFC 5424")
    label(ax, 2, 88, "RFC 3164 (auth.log, syslog, messages):", fs=10, ha="left", fontweight="bold")
    parts = [("Oct 26 10:15:01", "TIMESTAMP\n(không năm, giờ địa phương)", CAT[0]),
             ("web01", "HOSTNAME", CAT[2]), ("sshd[2231]:", "TAG = process[PID]", CAT[1]),
             ("Failed password for root from 203.0.113.66 port 51234 ssh2", "MSG (nội dung tự do → regex AUTH_PATTERNS)", CAT[6])]
    x = 2
    widths = [16, 8, 13, 59]
    for (txt, desc, col), w in zip(parts, widths):
        ax.add_patch(FancyBboxPatch((x, 70), w - 1, 9, boxstyle="round,pad=0.3", fc="white", ec=col, lw=1.6))
        label(ax, x + (w - 1) / 2, 74.5, txt, fs=8.6, family="DejaVu Sans Mono", color=INK)
        label(ax, x + (w - 1) / 2, 63, desc, fs=8, color=col)
        x += w
    label(ax, 2, 48, "RFC 5424 (rsyslog hiện đại, journald xuất):", fs=10, ha="left", fontweight="bold")
    parts2 = [("<34>1", "PRI VERSION", CAT[7]), ("2026-10-26T03:20:00.000Z", "TIMESTAMP ISO-8601 + múi giờ", CAT[0]),
              ("db01", "HOSTNAME", CAT[2]), ("su", "APP-NAME", CAT[1]), ("2004", "PROCID", CAT[1]), ("ID47", "MSGID", CAT[3]),
              ("-", "STRUCTURED-DATA", CAT[4]), ("FAILED SU (to root) attacker on /dev/pts/2", "MSG", CAT[6])]
    widths2 = [7, 22, 6, 5, 6, 6, 5, 39]
    x = 2
    for i, ((txt, desc, col), w) in enumerate(zip(parts2, widths2)):
        ax.add_patch(FancyBboxPatch((x, 30), w - 0.8, 9, boxstyle="round,pad=0.3", fc="white", ec=col, lw=1.6))
        label(ax, x + (w - 0.8) / 2, 34.5, txt, fs=7.8, family="DejaVu Sans Mono", color=INK)
        label(ax, x + (w - 0.8) / 2, 25 if i % 2 == 0 else 20.5, desc, fs=7.4, color=col)   # so le để không chồng chữ
        x += w
    box(ax, 2, 2, 96, 14, "PRI = Facility × 8 + Severity   →   <34> = 4 × 8 + 2  ⇒  facility 4 (auth), severity 2 (Critical)",
        "Severity: 0 Emergency · 1 Alert · 2 Critical · 3 Error · 4 Warning · 5 Notice · 6 Informational · 7 Debug  —  ánh xạ SYSLOG_SEVERITY_MAP → critical/high/medium/low/info",
        fill=ACCENT_FILL, edge=ACCENT_EDGE, fs=9.5, sfs=8.2)
    save(f, "11_syslog_format.png")


def f_linux_log_map():
    f, ax = fig(11, 5.8)
    title(ax, "Bản đồ các tệp log quan trọng trên Linux và luồng ghi log")
    box(ax, 2, 62, 20, 24, "Ứng dụng / dịch vụ", "sshd, sudo, cron,\nkernel, systemd", fs=10)
    box(ax, 30, 62, 22, 24, "systemd-journald", "nhật ký nhị phân\n/var/log/journal\njournalctl -o json", fill=ACCENT_FILL, edge=ACCENT_EDGE)
    box(ax, 60, 62, 22, 24, "rsyslog / syslog-ng", "lọc theo facility.severity\n/etc/rsyslog.d/*.conf")
    arrow(ax, 22, 74, 30, 74); arrow(ax, 52, 74, 60, 74)
    label(ax, 41, 58, "logrotate: xoay vòng theo kích thước/ngày → auth.log.1, auth.log.2.gz", fs=8.5)
    files = [("/var/log/auth.log  (Debian/Ubuntu)\n/var/log/secure  (RHEL/CentOS)", "xác thực: sshd, sudo, su, PAM, useradd", CAT[0]),
             ("/var/log/syslog  (Debian)\n/var/log/messages  (RHEL)", "thông điệp hệ thống chung, kernel, cron", CAT[2]),
             ("/var/log/kern.log · dmesg", "nhân: OOM-killer, segfault, phần cứng", CAT[1]),
             ("/var/log/nginx/access.log\n/var/log/apache2/access.log", "web: Combined Log Format (IP, URL, status, UA)", CAT[6]),
             ("/var/log/wtmp · btmp · lastlog", "nhị phân: last, lastb (đăng nhập thất bại), lastlog", CAT[3]),
             ("/var/log/audit/audit.log", "auditd: syscall, thay đổi tệp (nếu bật)", CAT[4])]
    for i, (p, d, col) in enumerate(files):
        y = 46 - i * 8
        ax.add_patch(FancyBboxPatch((2, y - 3), 40, 6.5, boxstyle="round,pad=0.3", fc="white", ec=col, lw=1.4))
        label(ax, 4, y, p, fs=7.8, ha="left", family="DejaVu Sans Mono")
        label(ax, 46, y, d, fs=8.6, ha="left")
    box(ax, 86, 10, 12, 44, "SOC Agent", "FileCollector\n(offset)\n\nJournald\nCollector\n(cursor)", fill=ACCENT_FILL, edge=ACCENT_EDGE, fs=9.5, sfs=8)
    arrow(ax, 82, 72, 92, 54, ls="--")
    arrow(ax, 41, 74, 92, 54, ls="--")
    save(f, "12_linux_log_map.png")


def f_web_access_log():
    f, ax = fig(11, 3.6)
    title(ax, "Combined Log Format của Apache/Nginx và các trường rút trích")
    parts = [("198.51.100.23", "IP khách", CAT[0]), ("-", "ident", MUTED), ("alice", "user", CAT[2]),
             ("[26/Oct/2026:10:21:00 +0700]", "thời gian + múi giờ", CAT[0]), ('"GET /index.php?page=../../etc/passwd HTTP/1.1"', "method · URL · proto", CAT[6]),
             ("403", "status", CAT[7]), ("512", "bytes", MUTED), ('"-"', "referer", MUTED), ('"sqlmap/1.7"', "User-Agent", CAT[1])]
    widths = [10, 3, 5, 18, 32, 4, 4, 4, 11]
    x = 1
    for (txt, desc, col), w in zip(parts, widths):
        ax.add_patch(FancyBboxPatch((x, 56), w - 0.6, 12, boxstyle="round,pad=0.3", fc="white", ec=col, lw=1.6))
        label(ax, x + (w - 0.6) / 2, 62, txt, fs=7.4, family="DejaVu Sans Mono")
        label(ax, x + (w - 0.6) / 2, 46, desc, fs=7.6, color=col)
        x += w
    label(ax, 50, 22, "parse_access_log_line(): URL chứa ../ , <script, /etc/passwd → web_suspicious_request (high); "
                      "UA sqlmap/nikto/nmap... → web_scanner_detected (high); 401/403 → web_access_denied; 5xx → web_server_error", fs=8.6)
    save(f, "13_web_access_log.png")


# =============================================================== 4. Agent
def f_agent_internals():
    f, ax = fig(11, 6)
    title(ax, "Kiến trúc bên trong SOC Agent (soc_agent/agent.py + collectors.py + parsers.py)")
    box(ax, 2, 66, 24, 24, "WindowsEventLogCollector", "wevtutil qe <kênh> /f:RenderedXml\nXPath: EventID ∈ {…} and\nEventRecordID > last_record", fs=9.5, sfs=8)
    box(ax, 2, 38, 24, 24, "FileCollector", "auth.log, syslog, access.log\nbyte offset + inode\nphát hiện rotate/truncate", fs=9.5, sfs=8)
    box(ax, 2, 10, 24, 24, "JournaldCollector", "journalctl -o json\n--after-cursor <cursor>", fs=9.5, sfs=8)
    box(ax, 32, 38, 18, 24, "parsers.py", "chuẩn hóa về\nlược đồ chung\n(17 trường)", fill=ACCENT_FILL, edge=ACCENT_EDGE, fs=10)
    box(ax, 56, 38, 18, 24, "Hàng đợi (deque)", "max_queue 50 000\nlô 500 sự kiện\nspool ra đĩa khi dừng", fs=10, sfs=8)
    box(ax, 80, 56, 18, 20, "POST /api/v1/logs", "X-API-Key\nJSON {events:[...]}", fs=9.5, sfs=8)
    box(ax, 80, 30, 18, 20, "POST .../heartbeat", "CPU, RAM, đĩa,\nqueue_size, 60 s", fs=9.5, sfs=8)
    box(ax, 32, 6, 42, 20, "agent_state.json", "api_key · hostname · collector_states\n{offset, inode} · {last_record} · {cursor}", fs=9.5, sfs=8)
    for y in (78, 50, 22):
        arrow(ax, 26, y, 32, 50)
    arrow(ax, 50, 50, 56, 50); arrow(ax, 74, 52, 80, 64); arrow(ax, 74, 46, 80, 40)
    arrow(ax, 53, 26, 53, 38, ls="--", style="<|-|>")
    label(ax, 53, 2, "lưu mỗi 30 s và khi dừng", fs=8)
    label(ax, 89, 86, "Web SOC", fs=10, fontweight="bold")
    label(ax, 89, 81, "lỗi mạng / HTTP 5xx → trả lô về\nđầu hàng đợi, thử lại chu kỳ sau", fs=7.8)
    save(f, "14_agent_internals.png")


def f_agent_sequence():
    f, ax = fig(10, 6)
    title(ax, "Trình tự tương tác Agent ↔ Web SOC")
    for x, n in ((18, "SOC Agent"), (78, "Web SOC")):
        box(ax, x - 10, 84, 20, 8, n, fs=10.5)
        ax.plot([x, x], [8, 84], color=GRID, lw=1.5, ls="--")
    msgs = [(78, "1. POST /agents/register {enrollment_token, hostname, os, collectors}", True),
            (70, "2. 201 {api_key, agent_uid, config}", False),
            (60, "3. collect() mỗi 10 s → chuẩn hóa → hàng đợi", None),
            (52, "4. POST /logs {events[≤500]}  X-API-Key", True),
            (44, "5. 200 {accepted, duplicates, alerts_new, ai_started}", False),
            (36, "6. POST /agents/heartbeat {metrics} mỗi 60 s", True),
            (28, "7. 200 {ok, config}", False),
            (18, "8. 401 → cần đăng ký lại · lỗi mạng → giữ lô, spool khi dừng", None)]
    for y, t, direction in msgs:
        if direction is None:
            ax.add_patch(FancyBboxPatch((4, y - 3), 44 if y == 60 else 92, 6, boxstyle="round,pad=0.3", fc="#fffbe6", ec="#eda100", lw=1))
            label(ax, 26 if y == 60 else 50, y, t, fs=8.4)
        else:
            arrow(ax, 18 if direction else 78, y, 78 if direction else 18, y, color=ACCENT_EDGE if direction else MUTED)
            label(ax, 48, y + 2.8, t, fs=8.4)
    save(f, "15_agent_sequence.png")


# =============================================================== 5. Web SOC
def f_normalized_schema():
    f, ax = fig(11, 5.2)
    title(ax, "Lược đồ sự kiện chuẩn hóa dùng chung cho mọi nguồn log (bảng log_events)")
    groups = [("Thời gian", ["timestamp (ISO-8601 UTC)", "received_at"], CAT[0]),
              ("Định danh nguồn", ["source (linux.auth, windows.security, web.access, journald…)", "host · agent_id · process · pid", "event_id (4625, ssh_failed_password, http_403…)"], CAT[2]),
              ("Ngữ nghĩa an ninh", ["category (authentication, account, privilege, process, service, system,",
                                     "              network, web, policy, defense_evasion, persistence)",
                                     "action (logon_failed, user_created, audit_log_cleared…)", "outcome (success/failure/unknown) · severity (critical…info)"], CAT[1]),
              ("Thực thể (Artifact)", ["user · src_ip · src_port"], CAT[6]),
              ("Nội dung", ["message (người đọc) · raw (dòng/XML gốc) · extra (JSON: EventData, HTTP status, offset/cursor/record_id)", "event_hash = SHA1(agent|source|timestamp|event_id|định danh|raw) → chống trùng"], CAT[3])]
    y = 89
    for name, items, col in groups:
        h = 4.4 + 4.6 * len(items)
        ax.add_patch(FancyBboxPatch((2, y - h), 96, h, boxstyle="round,pad=0.3", fc="white", ec=col, lw=1.5))
        label(ax, 4, y - 3.2, name, fs=9.5, ha="left", color=col, fontweight="bold")
        for i, it in enumerate(items):
            label(ax, 24, y - 3.2 - i * 4.6, ("• " if not it.startswith(" ") else "") + it, fs=8.4, ha="left")
        y -= h + 2
    save(f, "16_normalized_schema.png")


def f_rule_types():
    f, ax = fig(11, 5.8)
    title(ax, "Ba loại luật của Rule Engine trên trục thời gian")
    def lane(y, name, desc):
        label(ax, 2, y + 8, name, fs=10, ha="left", fontweight="bold")
        ax.text(2, y + 4.5, desc, fontsize=7.9, color=INK2, ha="left", va="top", linespacing=1.2)
        ax.plot([44, 98], [y, y], color=GRID, lw=2)
    lane(80, "match", "1 sự kiện khớp điều kiện → cảnh báo ngay.\nVí dụ R01: EventID 1102 (xóa Security log).")
    ax.plot([68], [80], "o", ms=12, color="#d03b3b"); label(ax, 68, 74, "1102", fs=8)
    arrow(ax, 68, 82, 68, 89, color="#d03b3b"); label(ax, 68, 92, "cảnh báo critical", fs=8.4, color="#d03b3b")
    lane(50, "threshold", "≥ N sự kiện cùng nhóm (src_ip / user / host)\ntrong cửa sổ trượt W giây.\nR15: ≥ 5 logon_failed trong 120 s.\nR17: đếm số GIÁ TRỊ KHÁC NHAU của user\n(password spraying).")
    xs = [50, 54, 57, 62, 65, 68, 73]
    ax.plot(xs, [50] * len(xs), "o", ms=8, color=CAT[0])
    ax.add_patch(FancyBboxPatch((48, 45), 27, 10, boxstyle="round,pad=0.2", fc="none", ec=CAT[0], ls="--", lw=1.2))
    label(ax, 61.5, 41, "cửa sổ trượt W = 120 s, count = 7 ≥ 5", fs=8, color=CAT[0])
    arrow(ax, 73, 52, 73, 60, color=CAT[0]); label(ax, 73, 63, "cảnh báo high", fs=8.4, color=CAT[0])
    lane(18, "sequence", "Sự kiện B (trigger) xảy ra sau ≥ min_count\nsự kiện A (precondition) cùng nhóm trong W.\nR18: logon_success sau ≥ 3 logon_failed\ntrong 600 s (dò mật khẩu đã thành công).")
    xs = [50, 55, 59, 64, 68]
    ax.plot(xs, [18] * len(xs), "o", ms=8, color=CAT[0])
    ax.plot([80], [18], "s", ms=11, color="#0ca30c")
    label(ax, 59, 12, "A: logon_failed ×5", fs=8, color=CAT[0]); label(ax, 80, 12, "B: logon_success", fs=8, color="#0ca30c")
    arrow(ax, 80, 20, 80, 28, color="#d03b3b"); label(ax, 80, 31, "cảnh báo critical", fs=8.4, color="#d03b3b")
    label(ax, 50, 3, "dedup_key = rule | host | nhóm: lần kích hoạt tiếp theo trong cửa sổ \"nóng\" được gộp vào cảnh báo đang mở (không sinh cảnh báo trùng)", fs=8)
    save(f, "17_rule_types.png")


def f_triage_scoring():
    f, ax = fig(11, 5.6)
    title(ax, "Thuật toán chấm điểm rủi ro của Triage Agent (đường suy luận cục bộ)")
    box(ax, 2, 66, 22, 22, "Điểm cơ sở", "theo mức của luật:\ncritical 80 · high 60\nmedium 40 · low 20 · info 10", fs=10, sfs=8.3)
    plus = ["IP công cộng +15", "IP trong blocklist +25 / đáng ngờ +10", "IP đã có đăng nhập thành công +15",
            "IP nhắm > 1 máy +10", "tài khoản đặc quyền +10 · tài khoản mới +5", "luật sequence +20 · số sự kiện ≥ 2× ngưỡng +10",
            "ngoài giờ / cuối tuần +5 · ≥2 cảnh báo liên quan +10"]
    box(ax, 30, 40, 36, 50, "Chỉ dấu từ Enrichment (cộng)", "\n".join(plus), fs=10, sfs=8.2)
    box(ax, 30, 8, 36, 24, "Chỉ dấu giảm (trừ)", "nguồn nội bộ + số lần thấp\n+ trong giờ hành chính → −20\n(người dùng quên mật khẩu)", fs=10, sfs=8.3)
    arrow(ax, 24, 77, 30, 77); arrow(ax, 24, 70, 30, 24)
    box(ax, 72, 40, 26, 50, "Điểm 0-100 → kết luận", "≥ 85 → P1 true_positive (critical)\n65-84 → P2 likely_true_positive\n45-64 → P3 suspicious\n25-44 → P4 likely_false_positive\n< 25 → P5 false_positive\n\nconfidence = 0.5 + 0.06 × số chỉ dấu\nneeds_investigation nếu ≥ 45",
        fill=ACCENT_FILL, edge=ACCENT_EDGE, fs=10, sfs=8.3)
    arrow(ax, 66, 65, 72, 65); arrow(ax, 66, 20, 72, 50)
    label(ax, 85, 30, "Đường LLM: cùng đầu vào, Claude trả JSON theo\nTRIAGE_SCHEMA (structured outputs)", fs=8.2)
    save(f, "18_triage_scoring.png")


def f_agentic_loop():
    f, ax = fig(11, 5.4)
    title(ax, "Vòng lặp tác tử (agentic loop) của Investigation Agent với Claude API")
    box(ax, 2, 40, 22, 28, "Web SOC\n(orchestrator)", "system prompt + cảnh báo\n+ enrichment + sự kiện\n+ 6 định nghĩa công cụ", fs=10, sfs=8.2)
    box(ax, 38, 40, 24, 28, "Claude (claude-opus-5-5)", "adaptive thinking,\neffort medium,\noutput_config.format =\nINVESTIGATION_SCHEMA", fill=ACCENT_FILL, edge=ACCENT_EDGE, fs=10, sfs=8.2)
    box(ax, 76, 40, 22, 28, "ToolExecutor", "query_events · lookup_ip\nget_host_info · get_related_alerts\nsearch_knowledge · mitre_lookup\n(chỉ ĐỌC CSDL)", fs=10, sfs=7.8)
    arrow(ax, 24, 60, 38, 60, color=ACCENT_EDGE); label(ax, 31, 64, "messages", fs=8)
    arrow(ax, 62, 60, 76, 60, color=ACCENT_EDGE); label(ax, 69, 64, "stop_reason = tool_use\n{name, input}", fs=7.8)
    arrow(ax, 76, 48, 62, 48); label(ax, 69, 44, "tool_result (≤ 8 vòng)", fs=7.8)
    arrow(ax, 38, 48, 24, 48); label(ax, 31, 44, "stop_reason = end_turn\nJSON theo schema", fs=7.8)
    box(ax, 2, 8, 96, 22, "Không có ANTHROPIC_API_KEY / API lỗi / từ chối (refusal) → LLMUnavailable → run_local(): cùng công cụ, suy luận heuristic, kết quả cùng cấu trúc JSON",
        "Mọi lượt chạy ghi bảng ai_runs: mode (llm/local), model, tokens, tool_calls, thời gian, lỗi — phục vụ kiểm toán và đánh giá chi phí", fs=9.3, sfs=8.3, bold=False)
    save(f, "19_agentic_loop.png")


def f_security_layers():
    f, ax = fig(10, 4.8)
    title(ax, "Các lớp bảo vệ của chính Web SOC")
    layers = [("Agent → Server", "enrollment token · API key băm SHA-256 (chỉ hiển thị 1 lần) · HTTPS/TLS tùy chọn · giới hạn 16 MB & 2000 sự kiện/lô"),
              ("Phiên người dùng", "mật khẩu băm (Werkzeug scrypt/PBKDF2) · khóa 5 phút sau 5 lần sai · cookie HttpOnly + SameSite=Lax (+Secure) · token CSRF"),
              ("Phân quyền", "admin / analyst / viewer · role_required trên từng route · audit_logs ghi mọi thao tác"),
              ("Dữ liệu", "SQLite WAL, khóa ngoại ON · xóa log quá hạn lưu trữ · AI chỉ đọc, không thực thi lệnh trên máy trạm")]
    for i, (n, d) in enumerate(layers):
        y = 76 - i * 19
        ax.add_patch(FancyBboxPatch((2, y - 7), 96, 15, boxstyle="round,pad=0.3", fc=ACCENT_FILL if i % 2 == 0 else BOX_FILL, ec=BOX_EDGE, lw=1.2))
        label(ax, 4, y + 3, n, fs=10, ha="left", fontweight="bold")
        label(ax, 4, y - 3, d, fs=8.4, ha="left")
    save(f, "20_security_layers.png")


# =============================================================== 6. Biểu đồ số liệu từ CSDL demo
def q(sql):
    if not os.path.exists(DB):
        return []
    con = sqlite3.connect(DB)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def c_events_by_source():
    rows = q("select source, count(*) from log_events group by 1 order by 2 desc")
    if not rows:
        return
    f, ax = plt.subplots(figsize=(8, 3.6))
    bar_style(ax, horizontal=True)
    names = [r[0] for r in rows][::-1]
    vals = [r[1] for r in rows][::-1]
    bars = ax.barh(names, vals, color=[CAT[i % 8] for i in range(len(names))][::-1], height=0.55)
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + 2, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=9, color=INK2)
    ax.set_xlabel("Số sự kiện (dữ liệu trình diễn, 4 máy trạm)")
    ax.set_title("Sự kiện theo nguồn log", loc="left", fontsize=11, fontweight="bold", color=INK)
    save(f, "c1_events_by_source.png")


def c_events_by_severity():
    rows = dict(q("select severity, count(*) from log_events group by 1"))
    if not rows:
        return
    order = ["info", "low", "medium", "high", "critical"]
    lab = {"info": "Thông tin", "low": "Thấp", "medium": "Trung bình", "high": "Cao", "critical": "Nghiêm trọng"}
    f, ax = plt.subplots(figsize=(8, 3.6))
    bar_style(ax)
    vals = [rows.get(s, 0) for s in order]
    bars = ax.bar([lab[s] for s in order], vals, color=[SEQ[s] for s in order], width=0.55)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 3, str(v), ha="center", fontsize=9, color=INK2)
    ax.set_ylabel("Số sự kiện")
    ax.set_title("Sự kiện theo mức độ nghiêm trọng (sau chuẩn hóa)", loc="left", fontsize=11, fontweight="bold", color=INK)
    save(f, "c2_events_by_severity.png")


def c_alerts_by_rule():
    rows = q("select r.code, r.name, r.severity, count(*) from alerts a join detection_rules r on r.id=a.rule_id group by 1 order by 1")
    if not rows:
        return
    from matplotlib.ticker import MaxNLocator
    f, ax = plt.subplots(figsize=(10, 5))
    bar_style(ax, horizontal=True)
    names = ["%s %s" % (r[0], r[1][:50]) for r in rows][::-1]
    vals = [r[3] for r in rows][::-1]
    cols = [SEQ[r[2]] for r in rows][::-1]
    bars = ax.barh(names, vals, color=cols, height=0.6)
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + 0.05, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=9, color=INK2)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_xlabel("Số cảnh báo (màu = mức của luật: đậm = nghiêm trọng)")
    ax.set_title("Cảnh báo sinh ra theo luật phát hiện", loc="left", fontsize=11, fontweight="bold", color=INK)
    ax.tick_params(axis="y", labelsize=8.5)
    save(f, "c3_alerts_by_rule.png")


def c_ai_verdicts():
    rows = q("select ai_verdict, ai_priority, count(*) from alerts where ai_verdict is not null group by 1,2")
    if not rows:
        return
    order = ["true_positive", "likely_true_positive", "suspicious", "likely_false_positive", "false_positive"]
    lab = {"true_positive": "Tấn công thật\n(P1)", "likely_true_positive": "Nhiều khả năng\ntấn công (P2)", "suspicious": "Đáng ngờ\n(P3)",
           "likely_false_positive": "Khả năng DT giả\n(P4)", "false_positive": "Dương tính giả\n(P5)"}
    cnt = {r[0]: r[2] for r in rows}
    f, ax = plt.subplots(figsize=(8, 3.8))
    bar_style(ax)
    vals = [cnt.get(v, 0) for v in order]
    cols = ["#d03b3b", "#ec835a", "#fab219", SEQ["low"], SEQ["info"]]
    bars = ax.bar([lab[v] for v in order], vals, color=cols, width=0.55)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.1, str(v), ha="center", fontsize=9, color=INK2)
    ax.set_ylabel("Số cảnh báo")
    ax.set_title("Phân bố kết luận của Triage Agent (chế độ suy luận cục bộ)", loc="left", fontsize=11, fontweight="bold", color=INK)
    ax.tick_params(axis="x", labelsize=8.5)
    save(f, "c4_ai_verdicts.png")


def c_top_ips():
    rows = q("select src_ip, count(*) from log_events where outcome='failure' and src_ip is not null group by 1 order by 2 desc limit 8")
    if not rows:
        return
    f, ax = plt.subplots(figsize=(8, 3.6))
    bar_style(ax, horizontal=True)
    names = [r[0] for r in rows][::-1]
    vals = [r[1] for r in rows][::-1]
    bars = ax.barh(names, vals, color=[CAT[0]] * len(names), height=0.55)
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + 0.5, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=9, color=INK2)
    ax.set_xlabel("Số sự kiện thất bại (dải IP tài liệu RFC 5737 đóng vai kẻ tấn công)")
    ax.set_title("IP nguồn có nhiều sự kiện thất bại nhất", loc="left", fontsize=11, fontweight="bold", color=INK)
    ax.tick_params(axis="y", labelsize=9)
    for t in ax.get_yticklabels():
        t.set_family("DejaVu Sans Mono")
    save(f, "c5_top_failed_ips.png")


def c_ai_runs():
    rows = q("select agent_name, count(*), avg(duration_ms) from ai_runs group by 1")
    if not rows:
        return
    order = ["enrichment", "triage", "investigation", "knowledge"]
    cnt = {r[0]: (r[1], r[2]) for r in rows}
    f, (a1, a2) = plt.subplots(1, 2, figsize=(9, 3.4))
    for a in (a1, a2):
        bar_style(a)
    vals = [cnt.get(k, (0, 0))[0] for k in order]
    durs = [round(cnt.get(k, (0, 0))[1] or 0, 1) for k in order]
    b1 = a1.bar(order, vals, color=CAT[:4], width=0.55)
    b2 = a2.bar(order, durs, color=CAT[:4], width=0.55)
    for b, v in zip(b1, vals):
        a1.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.3, str(v), ha="center", fontsize=9, color=INK2)
    for b, v in zip(b2, durs):
        a2.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, "%.0f" % v, ha="center", fontsize=9, color=INK2)
    a1.set_title("Số lượt chạy tác tử", loc="left", fontsize=10.5, fontweight="bold", color=INK)
    a2.set_title("Thời gian trung bình (ms)", loc="left", fontsize=10.5, fontweight="bold", color=INK)
    f.tight_layout()
    save(f, "c6_ai_runs.png")


def c_events_by_host():
    rows = q("select host, count(*) from log_events group by 1 order by 2 desc")
    if not rows:
        return
    f, ax = plt.subplots(figsize=(8, 3.2))
    bar_style(ax)
    names = [r[0] for r in rows]
    vals = [r[1] for r in rows]
    bars = ax.bar(names, vals, color=[CAT[2] if "WIN" not in n else CAT[0] for n in names], width=0.55)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 2, str(v), ha="center", fontsize=9, color=INK2)
    ax.set_ylabel("Số sự kiện")
    ax.set_title("Sự kiện theo máy trạm (xanh dương = Windows, xanh lục = Linux)", loc="left", fontsize=11, fontweight="bold", color=INK)
    save(f, "c7_events_by_host.png")


def main():
    print("Sinh hình vào", OUT)
    for fn in (f_soc_components, f_soc_tiers, f_nist_lifecycle, f_siem_pipeline, f_elk, f_wazuh, f_prometheus,
               f_asp_pipeline, f_asp_datamodel, f_windows_eventlog, f_syslog_format, f_linux_log_map, f_web_access_log,
               f_agent_internals, f_agent_sequence, f_normalized_schema, f_rule_types, f_triage_scoring, f_agentic_loop,
               f_security_layers, c_events_by_source, c_events_by_severity, c_alerts_by_rule, c_ai_verdicts, c_top_ips,
               c_ai_runs, c_events_by_host):
        fn()
    print("Xong.")


if __name__ == "__main__":
    main()
