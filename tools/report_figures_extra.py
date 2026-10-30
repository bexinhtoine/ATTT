# -*- coding: utf-8 -*-
"""
report_figures_extra.py - Bộ hình bổ sung cho bản báo cáo chi tiết mở rộng (docs/figures/).

    python tools/report_figures_extra.py

Dùng lại tiện ích vẽ của report_figures.py (hộp, mũi tên, bảng màu, truy vấn CSDL demo).
"""
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from report_figures import (fig, box, arrow, label, title, save, bar_style, q, CAT, SEQ, INK, INK2, MUTED, GRID,  # noqa: E402
                            SURF, BOX_FILL, BOX_EDGE, ACCENT_FILL, ACCENT_EDGE, plt, FancyBboxPatch, FancyArrowPatch, OUT)

STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}


# ------------------------------------------------------------------ Phần 1 bổ sung
def f_kill_chain():
    f, ax = fig(11, 5.2)
    title(ax, "Cyber Kill Chain (Lockheed Martin) và các tactic MITRE ATT&CK tương ứng")
    steps = [("1. Reconnaissance", "Reconnaissance,\nResource Development"), ("2. Weaponization", "Resource\nDevelopment"),
             ("3. Delivery", "Initial Access"), ("4. Exploitation", "Execution"), ("5. Installation", "Persistence,\nPrivilege Escalation,\nDefense Evasion"),
             ("6. Command & Control", "Command and Control,\nCredential Access,\nDiscovery, Lateral Movement"), ("7. Actions on Objectives", "Collection,\nExfiltration, Impact")]
    for i, (s, t) in enumerate(steps):
        x = 1 + i * 14.1
        box(ax, x, 56, 13, 16, s, fs=8.8)
        box(ax, x, 22, 13, 28, "ATT&CK", t, fs=8.5, sfs=7.4, fill=ACCENT_FILL, edge=ACCENT_EDGE)
        arrow(ax, x + 6.5, 56, x + 6.5, 50, lw=1)
        if i < 6:
            arrow(ax, x + 13, 64, x + 14.1, 64)
    label(ax, 50, 10, "Luật của hệ thống phủ các bước 3-7: R11/R19 (Delivery/Recon web), R15-R18 (Credential Access), R03-R06/R08 (Installation/Persistence), R01/R02/R07 (Defense Evasion), R21 (Lateral Movement)", fs=8.2)
    save(f, "21_kill_chain.png")


def f_attack_tactics():
    tactics = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
               "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
               "Exfiltration", "Impact"]
    cover = {"Reconnaissance": ["R19"], "Initial Access": ["R10", "R11", "R21*"], "Execution": ["R06", "R14"],
             "Persistence": ["R03", "R04", "R05", "R06", "R08"], "Privilege Escalation": ["R04", "R09"],
             "Defense Evasion": ["R01", "R02", "R07"], "Credential Access": ["R13", "R15", "R16", "R17", "R18", "R20"],
             "Lateral Movement": ["R21"]}
    f, ax = plt.subplots(figsize=(10, 5.2))
    bar_style(ax, horizontal=True)
    names = tactics[::-1]
    vals = [len(cover.get(t, [])) for t in names]
    cols = [CAT[0] if v else GRID for v in vals]
    bars = ax.barh(names, [v if v else 0.08 for v in vals], color=cols, height=0.6)
    for b, t, v in zip(bars, names, vals):
        ax.text(b.get_width() + 0.1, b.get_y() + b.get_height() / 2, (", ".join(cover[t]) if v else "chưa có luật"),
                va="center", fontsize=8.5, color=INK2 if v else MUTED)
    ax.set_xlim(0, 8.5)
    ax.set_xlabel("Số luật mặc định phủ tactic (một luật có thể thuộc nhiều tactic; * = tactic phụ)")
    ax.set_title("Độ phủ 14 tactic MITRE ATT&CK Enterprise của 21 luật mặc định", loc="left", fontsize=11, fontweight="bold", color=INK)
    ax.tick_params(axis="y", labelsize=9)
    save(f, "22_attack_coverage.png")


def f_pyramid_of_pain():
    f, ax = fig(10, 5.4)
    title(ax, "Pyramid of Pain (David Bianco): chỉ dấu càng cao, kẻ tấn công càng khó thay đổi")
    levels = [("Hash values", "trivial", 44, "#cde2fb"), ("IP addresses", "easy", 38, "#b7d3f6"), ("Domain names", "simple", 32, "#9ec5f4"),
              ("Network / host artifacts", "annoying", 26, "#6da7ec"), ("Tools", "challenging", 20, "#3987e5"), ("TTPs (hành vi)", "tough!", 14, "#1c5cab")]
    y = 8
    for name, pain, w, col in levels[::-1]:
        ax.add_patch(FancyBboxPatch((50 - w, y), 2 * w, 11, boxstyle="square,pad=0", fc=col, ec="white", lw=1.5))
        label(ax, 50, y + 5.5, "%s  (%s)" % (name, pain), fs=9.5, color="white" if w < 30 else INK, fontweight="bold")
        y += 12
    label(ax, 88, 22, "Rule Engine + Triage:\nphát hiện theo HÀNH VI\n(brute force, tạo tài khoản,\nxóa log) = tầng TTP", fs=8.4, color=INK2)
    label(ax, 12, 70, "ip_reputation,\nlookup_ip:\ntầng IP (dễ đổi,\nchỉ làm giàu)", fs=8.4, color=INK2)
    save(f, "23_pyramid_of_pain.png")


def f_soc_maturity():
    f, ax = fig(11, 5.2)
    title(ax, "Các mức trưởng thành SOC (theo SOC-CMM) và vị trí của hệ thống đề tài")
    lv = [("1. Ban đầu", "log rải rác, xử lý\nthủ công khi có sự cố"), ("2. Quản lý", "SIEM cơ bản, luật tĩnh,\nquy trình chưa chuẩn"),
          ("3. Xác định", "quy trình chuẩn, playbook,\nphân tầng, KPI"), ("4. Định lượng", "đo MTTD/MTTR, tinh chỉnh\nluật theo dữ liệu, threat hunting"),
          ("5. Tối ưu", "tự động hóa, AI hỗ trợ,\ncải tiến liên tục")]
    for i, (n, d) in enumerate(lv):
        x = 1 + i * 19.8
        y = 14 + i * 9
        box(ax, x, y, 18, 26, n, d, fs=9.5, sfs=7.8, fill=ACCENT_FILL if i == 2 else BOX_FILL, edge=ACCENT_EDGE if i == 2 else BOX_EDGE)
        if i < 4:
            arrow(ax, x + 18, y + 13, x + 19.8, y + 22)
    label(ax, 41, 8, "Hệ thống đề tài cung cấp công cụ cho mức 3 (playbook, KPI, phân tầng) và một phần mức 4-5 (MTTR, tác tử AI)", fs=8.6)
    save(f, "24_soc_maturity.png")


def f_sigma_flow():
    f, ax = fig(11, 5.4)
    title(ax, "Detection engineering: từ luật Sigma chung tới luật JSON của Rule Engine")
    box(ax, 2, 44, 30, 44, "Luật Sigma (YAML)", "title: SSH Brute Force\nlogsource: product: linux, service: auth\ndetection:\n  selection: Message|contains: 'Failed password'\n  timeframe: 2m | count() by SourceIp > 5\nlevel: high\ntags: attack.t1110.001", fs=10, sfs=7.4)
    box(ax, 38, 54, 24, 24, "Chuyển đổi (sigma-cli, pySigma)", "backend: splunk / elastic /\nwazuh / tùy chỉnh", fs=9.5, sfs=8)
    box(ax, 68, 44, 30, 44, "Luật R15 của hệ thống", "rule_type: threshold\nconditions: {action: [logon_failed],\n             source: [linux.auth, journald]}\nthreshold_count: 5\nwindow_seconds: 120\ngroup_by: src_ip\nmitre_technique: T1110.001", fs=10, sfs=7.4, fill=ACCENT_FILL, edge=ACCENT_EDGE)
    arrow(ax, 32, 66, 38, 66); arrow(ax, 62, 66, 68, 66)
    box(ax, 2, 8, 96, 26, "Vòng đời một luật phát hiện", "Nhu cầu (ATT&CK gap, sự cố, threat intel) → viết luật → kiểm thử trên dữ liệu lịch sử (nút \"Chạy lại luật\") → đo dương tính giả → tinh chỉnh ngưỡng/cửa sổ/điều kiện loại trừ (not_regex, user_in) → triển khai → theo dõi hits → tri thức/playbook đi kèm", fs=10, sfs=8.2, bold=True)
    save(f, "25_sigma_to_rule.png")


# ------------------------------------------------------------------ Phần 3 bổ sung
def f_agent_safety():
    f, ax = fig(11, 5.2)
    title(ax, "Rủi ro khi dùng LLM trong SOC và các biện pháp kiểm soát của hệ thống")
    rows = [("Prompt injection qua nội dung log", "Log độc hại chứa chỉ thị giả cho mô hình", "Công cụ chỉ ĐỌC CSDL; không có công cụ hành động; kết quả ép theo JSON schema; con người quyết định"),
            ("Ảo giác (hallucination)", "Bịa IOC, kỹ thuật, kết luận", "System prompt yêu cầu dựa trên bằng chứng; evidence[] phải trích từ dữ liệu; đường cục bộ đối chiếu"),
            ("Rò rỉ dữ liệu nhạy cảm", "Log chứa tên người dùng, IP nội bộ gửi tới API", "Chỉ gửi bản rút gọn (compact) tối đa 40 sự kiện; có thể tắt LLM (chế độ cục bộ) hoặc tự host"),
            ("Chi phí và độ trễ", "Mỗi cảnh báo tốn token", "Tự động chỉ chạy enrich + triage; investigate/knowledge theo yêu cầu; ghi tokens vào ai_runs; timeout 180 s"),
            ("Từ chối / lỗi API", "Mô hình từ chối hoặc API gián đoạn", "LLMUnavailable → run_local() cùng cấu trúc; fallback phía máy chủ (fallbacks: default)")]
    label(ax, 2, 88, "Rủi ro", fs=10, ha="left", fontweight="bold"); label(ax, 27, 88, "Mô tả", fs=10, ha="left", fontweight="bold")
    label(ax, 56, 88, "Kiểm soát trong hệ thống", fs=10, ha="left", fontweight="bold")
    for i, (r, d, c) in enumerate(rows):
        y = 78 - i * 16
        ax.add_patch(FancyBboxPatch((1, y - 6), 98, 14, boxstyle="round,pad=0.3", fc=BOX_FILL if i % 2 else "white", ec=BOX_EDGE, lw=1))
        ax.text(2, y + 1, r, fontsize=8.8, fontweight="bold", va="center")
        ax.text(27, y + 1, d, fontsize=8.2, va="center", color=INK2, wrap=True)
        ax.text(56, y + 1, c, fontsize=7.8, va="center", color=INK2, wrap=True)
    save(f, "26_llm_risks.png")


def f_mode_selection():
    f, ax = fig(10, 5.2)
    title(ax, "Lựa chọn đường chạy của tác tử: LLM hay suy luận cục bộ")
    box(ax, 35, 80, 30, 12, "BaseAgent.run()", fs=10.5)
    box(ax, 30, 58, 40, 12, "Có ANTHROPIC_API_KEY và SDK anthropic?", fs=9.5, fill="#fff7e6", edge="#eda100")
    box(ax, 4, 34, 36, 14, "run_llm()", "complete_json / run_with_tools\nmodel claude-opus-5-5", fs=10, sfs=8, fill=ACCENT_FILL, edge=ACCENT_EDGE)
    box(ax, 60, 34, 36, 14, "run_local()", "heuristic, cùng công cụ,\ncùng cấu trúc JSON", fs=10, sfs=8)
    box(ax, 4, 8, 36, 14, "Thành công", "mode=llm, ghi tokens,\ntool_calls vào ai_runs", fs=9.5, sfs=8)
    box(ax, 40, 8, 20, 14, "LLMUnavailable", "lỗi API, từ chối,\nJSON sai, quá 8 vòng", fs=9, sfs=7.6, fill="#fdeaea", edge="#d03b3b")
    box(ax, 64, 8, 32, 14, "mode=local", "fallback_reason được\nghi lại để kiểm toán", fs=9.5, sfs=8)
    arrow(ax, 50, 80, 50, 70)
    arrow(ax, 38, 58, 22, 48); label(ax, 26, 56, "có", fs=9)
    arrow(ax, 62, 58, 78, 48); label(ax, 74, 56, "không", fs=9)
    arrow(ax, 22, 34, 22, 22); arrow(ax, 30, 34, 50, 22); arrow(ax, 60, 22, 78, 34, ls="--"); arrow(ax, 78, 34, 80, 22)
    save(f, "27_mode_selection.png")


# ------------------------------------------------------------------ Phần 4 bổ sung
def f_audit_policy():
    f, ax = fig(11, 5.6)
    title(ax, "Chính sách kiểm toán Windows (auditpol) quyết định EventID nào được ghi")
    cats = [("Logon /\nLogoff", "4624, 4625, 4634,\n4647, 4648, 4672", "Audit Logon, Logoff,\nSpecial Logon"),
            ("Account\nLogon", "4768, 4769, 4771,\n4776", "Kerberos, Credential\nValidation (DC)"),
            ("Account\nManagement", "4720-4726, 4728,\n4732, 4738, 4740", "User/Group\nManagement"),
            ("Detailed\nTracking", "4688, 4689, 4696", "Process Creation\n(+ CommandLine)"),
            ("Object\nAccess", "4663, 5140, 5145,\n5156, 5157", "File Share, Filtering\nPlatform (nhiễu)"),
            ("Policy\nChange", "4719, 4739, 4904", "Audit Policy\nChange"),
            ("System", "1102 (Security\nState), 4616", "Security State\nChange")]
    for i, (c, ids, sub) in enumerate(cats):
        x = 1 + i * 14.1
        box(ax, x, 46, 13, 26, c, sub, fs=8.3, sfs=6.8)
        box(ax, x, 16, 13, 22, "EventID", ids, fs=8.5, sfs=7.2, fill=ACCENT_FILL, edge=ACCENT_EDGE)
        arrow(ax, x + 6.5, 46, x + 6.5, 38, lw=1)
    box(ax, 1, 78, 98, 12, "auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable      (hoặc GPO: Advanced Audit Policy Configuration)", fs=9, bold=False)
    label(ax, 50, 7, "Không bật chính sách → không có sự kiện để thu thập. Máy trạm thường chỉ bật Logon/Logoff và Account Management mặc định; DC bật thêm Account Logon.", fs=8.4)
    save(f, "28_audit_policy.png")


def f_linux_auth_stack():
    f, ax = fig(11, 5.4)
    title(ax, "Ngăn xếp xác thực Linux và nơi log được sinh ra")
    box(ax, 2, 66, 20, 22, "Kết nối SSH", "sshd nhận\nmật khẩu / khóa", fs=10)
    box(ax, 30, 66, 20, 22, "PAM", "pam_unix, pam_faillock,\npam_tally2", fs=10, sfs=8)
    box(ax, 58, 66, 20, 22, "sudo / su / login", "kiểm tra sudoers,\nghi lệnh", fs=10, sfs=8)
    arrow(ax, 22, 77, 30, 77); arrow(ax, 50, 77, 58, 77)
    box(ax, 2, 30, 26, 22, "syslog (authpriv)", "/var/log/auth.log\n/var/log/secure", fs=10, sfs=8.5, fill=ACCENT_FILL, edge=ACCENT_EDGE)
    box(ax, 36, 30, 26, 22, "journald", "journalctl -u ssh\n_COMM=sudo", fs=10, sfs=8.5, fill=ACCENT_FILL, edge=ACCENT_EDGE)
    box(ax, 70, 30, 28, 22, "auditd (tùy chọn)", "/var/log/audit/audit.log\ntype=USER_AUTH, USER_CMD", fs=10, sfs=8)
    for x in (12, 40, 68):
        arrow(ax, x, 66, 15, 52, ls="--", lw=1); arrow(ax, x, 66, 49, 52, ls="--", lw=1)
    arrow(ax, 68, 66, 84, 52, ls=":", lw=1)
    box(ax, 2, 4, 96, 16, "Dòng log sinh ra: \"Failed password for root from 203.0.113.66 port 51234 ssh2\" (sshd) · \"pam_unix(sshd:auth): authentication failure; rhost=203.0.113.66 user=root\" (PAM) · \"student : TTY=pts/0 ; PWD=... ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow\" (sudo)",
        fs=8.6, bold=False)
    save(f, "29_linux_auth_stack.png")


def f_log_analysis_steps():
    f, ax = fig(11, 4.6)
    title(ax, "Quy trình phân tích log server (Lab 17) và phần được tự động hóa")
    steps = [("1. Xác định\nnguồn log", "auth.log, Security,\naccess.log"), ("2. Thu thập &\nchuẩn hóa", "đọc, tách trường,\nđổi múi giờ"),
             ("3. Lọc &\nthống kê", "grep/awk/uniq -c\ntop IP, top user"), ("4. Tương quan", "thất bại → thành công,\nnhiều máy, nhiều user"),
             ("5. Kết luận &\nphản ứng", "chặn IP, đổi mật khẩu,\nbáo cáo")]
    for i, (s, d) in enumerate(steps):
        x = 1 + i * 19.8
        auto = i in (1, 2, 3)
        box(ax, x, 40, 18, 34, s, d, fs=9.5, sfs=8, fill=ACCENT_FILL if auto else BOX_FILL, edge=ACCENT_EDGE if auto else BOX_EDGE)
        if i < 4:
            arrow(ax, x + 18, 57, x + 19.8, 57)
    label(ax, 50, 22, "Màu xanh = SOC Agent + parsers + Rule Engine + dashboard thực hiện tự động; bước 1 và 5 vẫn do con người quyết định (AI chỉ đề xuất)", fs=8.6)
    save(f, "30_log_analysis_steps.png")


# ------------------------------------------------------------------ Phần 5-6 bổ sung
def f_alert_lifecycle():
    f, ax = fig(11, 5)
    title(ax, "Vòng đời trạng thái của một cảnh báo và tác nhân chuyển trạng thái")
    st = [("new", 4, "Rule Engine\ntạo cảnh báo"), ("triaged", 26, "Triage Agent\n(tự động)"), ("investigating", 48, "Investigation Agent\nhoặc analyst"),
          ("resolved", 72, "analyst đóng,\nghi chú"), ("false_positive", 72, "analyst đánh dấu")]
    for name, x, who in st[:4]:
        y = 56
        box(ax, x, y, 18, 14, name, fs=10.5, fill=ACCENT_FILL if name in ("triaged", "investigating") else BOX_FILL,
            edge=ACCENT_EDGE if name in ("triaged", "investigating") else BOX_EDGE)
        label(ax, x + 9, 48, who, fs=8)
    box(ax, 72, 22, 18, 14, "false_positive", fs=10)
    label(ax, 81, 14, "analyst đánh dấu;\ntri thức \"dương tính giả\"", fs=8)
    arrow(ax, 22, 63, 26, 63); arrow(ax, 44, 63, 48, 63); arrow(ax, 66, 63, 72, 63)
    arrow(ax, 57, 56, 78, 36, ls="--"); arrow(ax, 35, 56, 74, 36, ls="--")
    label(ax, 52, 40, "analyst kết luận\ndương tính giả", fs=7.8, color=MUTED)
    label(ax, 47, 86, "Sự kiện mới cùng dedup_key khi cảnh báo còn \"nóng\" → gộp vào cảnh báo đang mở (new / triaged / investigating), không tạo cảnh báo mới", fs=8.4)
    label(ax, 50, 4, "Khi đóng (resolved / false_positive) với tùy chọn trích xuất → Knowledge Agent sinh bài học; resolved_at dùng để tính MTTR", fs=8.4)
    save(f, "31_alert_lifecycle.png")


def f_ingest_detail():
    f, ax = fig(11, 5.4)
    title(ax, "Pipeline tiếp nhận một lô log tại Web SOC (ingest.py)")
    steps = [("POST /api/v1/logs", "X-API-Key →\nagent_auth()"), ("Kiểm tra lô", "≤ 2000 sự kiện,\n≤ 16 MB, là list"),
             ("Phân tích raw\n(nếu có)", "parse_line(raw,\nsource, format)"), ("normalize_event()", "đủ 17 trường,\nđúng kiểu, cắt độ dài"),
             ("event_hash", "SHA1(agent|source|ts|\nevent_id|ident|raw)"), ("Loại trùng", "trong lô + truy vấn\nIN theo khối 500"),
             ("Ghi CSDL", "add_all + commit;\ncập nhật agent")]
    for i, (s, d) in enumerate(steps):
        x = 1 + i * 14.1
        box(ax, x, 56, 13, 26, s, d, fs=8.3, sfs=7)
        if i < 6:
            arrow(ax, x + 13, 69, x + 14.1, 69)
    box(ax, 8, 16, 26, 24, "RuleEngine.evaluate()", "21 luật × N sự kiện\n→ [(alert, is_new)]", fs=9.5, sfs=8, fill=ACCENT_FILL, edge=ACCENT_EDGE)
    box(ax, 40, 16, 26, 24, "_trigger_ai()", "cảnh báo MỚI →\norch.run_async(enrich, triage)", fs=9.5, sfs=8, fill=ACCENT_FILL, edge=ACCENT_EDGE)
    box(ax, 72, 16, 26, 24, "Phản hồi JSON", "received, accepted,\nduplicates, rejected,\nalerts_new, ai_started", fs=9.5, sfs=8)
    arrow(ax, 92, 56, 21, 40); arrow(ax, 34, 28, 40, 28); arrow(ax, 66, 28, 72, 28)
    save(f, "32_ingest_detail.png")


def f_dedup_example():
    f, ax = fig(11, 4.6)
    title(ax, "Ví dụ gộp cảnh báo: 18 lần Failed password từ 203.0.113.66 → 1 cảnh báo R15 với event_count = 18")
    xs = [4 + i * 3.6 for i in range(18)]
    for i, x in enumerate(xs):
        col = CAT[0] if i < 5 else "#9ec5f4"
        ax.add_patch(FancyBboxPatch((x, 62), 2.8, 10, boxstyle="round,pad=0.2", fc=col, ec="white", lw=0.8))
        label(ax, x + 1.4, 67, str(i + 1), fs=7, color="white")
    label(ax, 11, 56, "5 sự kiện đầu: chưa đủ ngưỡng (count < 5)... sự kiện thứ 5 đạt ngưỡng → tạo cảnh báo", fs=8, ha="left")
    arrow(ax, 20, 62, 20, 44, color=CAT[0]); label(ax, 20, 40, "raise(): Alert mới,\ndedup_key = R15|centos-db01|203.0.113.66\nevent_count = 5", fs=8, color=CAT[0])
    for i in (8, 12, 17):
        arrow(ax, xs[i] + 1.4, 62, xs[i] + 1.4, 48, color="#9ec5f4", lw=1)
    label(ax, 62, 44, "các sự kiện sau: cùng khóa, cảnh báo còn \"nóng\"\n→ gộp: event_count = max(count), last_event_time cập nhật,\nliên kết thêm bằng chứng vào alert_events", fs=8, color=INK2)
    box(ax, 70, 8, 28, 20, "Kết quả", "1 cảnh báo thay vì 14\n(dedup) · 18 bằng chứng\n· AI chỉ chạy 1 lần", fs=9.5, sfs=8, fill=ACCENT_FILL, edge=ACCENT_EDGE)
    save(f, "33_dedup_example.png")


def f_api_errors():
    f, ax = fig(10, 4.4)
    title(ax, "Xử lý lỗi phía agent theo mã trả về của Web SOC")
    rows = [("200 OK", "ghi nhận accepted/duplicates; log nếu có cảnh báo mới", STATUS["good"]),
            ("400 Bad Request", "body sai định dạng → bỏ lô (lỗi lập trình), ghi log", STATUS["warning"]),
            ("401 Unauthorized", "API key sai/bị thu hồi → giữ lô, dừng gửi, yêu cầu --register", STATUS["serious"]),
            ("403 Forbidden", "sai enrollment token khi đăng ký → thoát mã 2", STATUS["serious"]),
            ("413 / 5xx / timeout", "giữ lô ở đầu hàng đợi, thử lại chu kỳ sau; spool khi dừng", STATUS["critical"]),
            ("Không phải JSON", "proxy/HTML lỗi → trả chuỗi thô, không crash", STATUS["warning"])]
    for i, (c, d, col) in enumerate(rows):
        y = 80 - i * 13
        ax.add_patch(FancyBboxPatch((2, y - 4.5), 22, 10, boxstyle="round,pad=0.3", fc="white", ec=col, lw=1.8))
        label(ax, 13, y + 0.5, c, fs=9, fontweight="bold")
        label(ax, 27, y + 0.5, d, fs=8.6, ha="left")
    save(f, "34_agent_error_handling.png")


# ------------------------------------------------------------------ Biểu đồ số liệu bổ sung
def c_events_timeline():
    rows = q("select event_time, host, action, severity from log_events order by event_time")
    if not rows:
        return
    times = [datetime.strptime(r[0][:19], "%Y-%m-%d %H:%M:%S") for r in rows]
    t0 = times[0]
    minutes = [(t - t0).total_seconds() / 60 for t in times]
    hosts = sorted({r[1] for r in rows})
    f, ax = plt.subplots(figsize=(10, 4.2))
    bar_style(ax)
    ymap = {h: i for i, h in enumerate(hosts)}
    for (r, m) in zip(rows, minutes):
        attack = r[3] in ("critical", "high", "medium") or r[2] in ("logon_failed", "invalid_user", "web_not_found", "web_access_denied")
        ax.plot(m, ymap[r[1]], "o", ms=4 if attack else 2.5, color=CAT[7] if attack else "#9ec5f4", alpha=0.85 if attack else 0.6)
    ax.set_yticks(range(len(hosts))); ax.set_yticklabels(hosts, fontsize=9)
    ax.set_xlabel("Phút kể từ sự kiện đầu tiên (dữ liệu trình diễn trải trong 2 giờ)")
    ax.set_title("Dòng thời gian sự kiện theo máy trạm (đỏ = sự kiện thuộc kịch bản tấn công / thất bại, xanh = nền lành tính)",
                 loc="left", fontsize=10.5, fontweight="bold", color=INK)
    ax.grid(axis="x", color=GRID, lw=0.8)
    save(f, "c8_events_timeline.png")


def c_events_per_10min():
    rows = q("select strftime('%Y-%m-%d %H:%M', event_time, '-' || (strftime('%M', event_time) % 10) || ' minutes'), count(*) "
             "from log_events group by 1 order by 1")
    if not rows:
        return
    f, ax = plt.subplots(figsize=(9, 3.4))
    bar_style(ax)
    labels = [r[0][11:] for r in rows]
    vals = [r[1] for r in rows]
    ax.plot(labels, vals, "-o", color=CAT[0], lw=2, ms=5)
    ax.fill_between(range(len(vals)), vals, color=CAT[0], alpha=0.12)
    for i, v in enumerate(vals):
        if v >= max(vals) * 0.6:
            ax.text(i, v + 2, str(v), ha="center", fontsize=8.5, color=INK2)
    ax.set_ylabel("Sự kiện / 10 phút")
    ax.set_title("Mật độ sự kiện theo khung 10 phút (UTC) - đỉnh ứng với các kịch bản tấn công", loc="left", fontsize=11, fontweight="bold", color=INK)
    ax.tick_params(axis="x", labelsize=8, rotation=45)
    save(f, "c9_events_per_10min.png")


def c_sev_by_host():
    rows = q("select host, severity, count(*) from log_events group by 1,2")
    if not rows:
        return
    hosts = sorted({r[0] for r in rows})
    order = ["info", "low", "medium", "high", "critical"]
    lab = {"info": "Thông tin", "low": "Thấp", "medium": "Trung bình", "high": "Cao", "critical": "Nghiêm trọng"}
    data = {s: [sum(r[2] for r in rows if r[0] == h and r[1] == s) for h in hosts] for s in order}
    f, ax = plt.subplots(figsize=(8.5, 3.8))
    bar_style(ax)
    bottom = [0] * len(hosts)
    for s in order:
        ax.bar(hosts, data[s], bottom=bottom, color=SEQ[s], label=lab[s], width=0.55, edgecolor="white", linewidth=1.5)
        bottom = [b + v for b, v in zip(bottom, data[s])]
    for i, b in enumerate(bottom):
        ax.text(i, b + 2, str(b), ha="center", fontsize=9, color=INK2)
    ax.legend(frameon=False, fontsize=8.5, ncol=5, loc="upper center", bbox_to_anchor=(0.5, -0.12))
    ax.set_ylabel("Số sự kiện")
    ax.set_title("Phân bố mức độ sự kiện theo máy trạm", loc="left", fontsize=11, fontweight="bold", color=INK)
    save(f, "c10_sev_by_host.png")


def c_actions():
    rows = q("select action, count(*) from log_events group by 1 order by 2 desc limit 12")
    if not rows:
        return
    f, ax = plt.subplots(figsize=(8.5, 4.2))
    bar_style(ax, horizontal=True)
    names = [r[0] for r in rows][::-1]
    vals = [r[1] for r in rows][::-1]
    bars = ax.barh(names, vals, color=[CAT[7] if n in ("logon_failed", "invalid_user", "web_suspicious_request", "web_scanner_detected",
                                                      "audit_log_cleared", "user_added_to_privileged_group", "member_added_to_privileged_group")
                                       else CAT[0] for n in names], height=0.6)
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + 1, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=9, color=INK2)
    ax.set_xlabel("Số sự kiện (đỏ = hành động mang tính tấn công/thất bại)")
    ax.set_title("12 hành động (action) phổ biến nhất sau chuẩn hóa", loc="left", fontsize=11, fontweight="bold", color=INK)
    for t in ax.get_yticklabels():
        t.set_family("DejaVu Sans Mono"); t.set_fontsize(8.5)
    save(f, "c11_top_actions.png")


def c_risk_scores():
    rows = q("select a.id, r.code, a.ai_verdict, json_extract(a.ai_data, '$.triage.risk_score') from alerts a join detection_rules r on r.id=a.rule_id where a.ai_verdict is not null order by a.id")
    if not rows:
        return
    f, ax = plt.subplots(figsize=(9, 4))
    bar_style(ax)
    vcol = {"true_positive": "#d03b3b", "likely_true_positive": "#ec835a", "suspicious": "#fab219", "likely_false_positive": SEQ["low"], "false_positive": SEQ["info"]}
    xs = range(len(rows))
    ax.bar(xs, [r[3] or 0 for r in rows], color=[vcol.get(r[2], MUTED) for r in rows], width=0.6)
    for th, lab in ((85, "P1"), (65, "P2"), (45, "P3"), (25, "P4")):
        ax.axhline(th, color=MUTED, lw=0.8, ls="--"); ax.text(len(rows) - 0.4, th + 1, lab, fontsize=8, color=MUTED, ha="right")
    ax.set_xticks(list(xs)); ax.set_xticklabels(["#%d %s" % (r[0], r[1]) for r in rows], rotation=60, fontsize=7.5)
    ax.set_ylabel("Điểm rủi ro (0-100)"); ax.set_ylim(0, 105)
    ax.set_title("Điểm rủi ro Triage Agent của từng cảnh báo và ngưỡng ưu tiên P1-P4", loc="left", fontsize=11, fontweight="bold", color=INK)
    save(f, "c12_risk_scores.png")


def c_categories():
    rows = q("select category, count(*) from log_events group by 1 order by 2 desc")
    if not rows:
        return
    f, ax = plt.subplots(figsize=(8, 3.2))
    bar_style(ax)
    names = [r[0] for r in rows]; vals = [r[1] for r in rows]
    bars = ax.bar(names, vals, color=[CAT[i % 8] for i in range(len(names))], width=0.55)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 2, str(v), ha="center", fontsize=9, color=INK2)
    ax.set_ylabel("Số sự kiện")
    ax.set_title("Sự kiện theo category (nhóm ngữ nghĩa an ninh)", loc="left", fontsize=11, fontweight="bold", color=INK)
    ax.tick_params(axis="x", labelsize=9)
    save(f, "c13_categories.png")


def main():
    print("Sinh hình bổ sung vào", OUT)
    for fn in (f_kill_chain, f_attack_tactics, f_pyramid_of_pain, f_soc_maturity, f_sigma_flow, f_agent_safety, f_mode_selection,
               f_audit_policy, f_linux_auth_stack, f_log_analysis_steps, f_alert_lifecycle, f_ingest_detail, f_dedup_example,
               f_api_errors, c_events_timeline, c_events_per_10min, c_sev_by_host, c_actions, c_risk_scores, c_categories):
        fn()
    print("Xong.")


if __name__ == "__main__":
    main()
