# -*- coding: utf-8 -*-
"""
build_report.py - Sinh báo cáo Word (.docx) chi tiết cho đề tài Agentic SOC Platform.

Chạy: python tools/build_report.py
Kết quả: docs/BaoCao_Agentic_SOC_Platform.docx

Báo cáo theo đúng cấu trúc mục lục yêu cầu, kèm ảnh chụp màn hình và sơ đồ.
"""
import os
import re

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.path.join(ROOT, "docs", "screenshots")
OUT = os.path.join(ROOT, "docs", "BaoCao_Agentic_SOC_Platform.docx")

doc = Document()

# ------------------------------------------------------------- style co ban
style = doc.styles["Normal"]
style.font.name = "Times New Roman"
style.font.size = Pt(13)
style.element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")
style.paragraph_format.space_after = Pt(6)
style.paragraph_format.line_spacing = 1.4

for i, sz in ((1, 16), (2, 14), (3, 13)):
    h = doc.styles["Heading %d" % i]
    h.font.name = "Times New Roman"
    h.font.size = Pt(sz)
    h.font.color.rgb = RGBColor(0x0F, 0x2A, 0x4A)
    h.element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")


def _runs(p, text):
    """Them text vao paragraph, xu ly **in dam** va `code`."""
    for seg in re.split(r"(\*\*.+?\*\*|`.+?`)", text):
        if not seg:
            continue
        if seg.startswith("**") and seg.endswith("**"):
            r = p.add_run(seg[2:-2])
            r.bold = True
        elif seg.startswith("`") and seg.endswith("`"):
            r = p.add_run(seg[1:-1])
            r.font.name = "Consolas"
            r.font.size = Pt(11)
        else:
            p.add_run(seg)


def h1(text):
    doc.add_heading(text, level=1)


def h2(text):
    doc.add_heading(text, level=2)


def h3(text):
    doc.add_heading(text, level=3)


def para(text, align=None, italic=False):
    p = doc.add_paragraph()
    _runs(p, text)
    if italic:
        for r in p.runs:
            r.italic = True
    if align == "center":
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    elif align == "justify":
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    else:
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    return p


def bullets(items):
    for it in items:
        p = doc.add_paragraph(style="List Bullet")
        _runs(p, it)


def numbered(items):
    for it in items:
        p = doc.add_paragraph(style="List Number")
        _runs(p, it)


def code(text):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.font.name = "Consolas"
    r.font.size = Pt(10.5)
    p.paragraph_format.left_indent = Inches(0.2)
    p.paragraph_format.space_after = Pt(8)
    # nen xam nhe
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), "F2F4F7")
    p._p.get_or_add_pPr().append(shd)


def table(headers, rows):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Light Grid Accent 1"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, head in enumerate(headers):
        c = t.rows[0].cells[i]
        c.text = ""
        r = c.paragraphs[0].add_run(head)
        r.bold = True
        r.font.size = Pt(11.5)
    for row in rows:
        cells = t.add_row().cells
        for i, val in enumerate(row):
            cells[i].text = ""
            _runs(cells[i].paragraphs[0], str(val))
            for r in cells[i].paragraphs[0].runs:
                r.font.size = Pt(11)
    doc.add_paragraph()
    return t


def figure(filename, caption, width=6.3):
    path = os.path.join(SHOTS, filename)
    if not os.path.exists(path):
        para("[Thiếu ảnh: %s]" % filename)
        return
    doc.add_picture(path, width=Inches(width))
    doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = cap.add_run(caption)
    r.italic = True
    r.font.size = Pt(11)
    cap.paragraph_format.space_after = Pt(10)


def add_toc():
    p = doc.add_paragraph()
    run = p.add_run()
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), r'TOC \o "1-3" \h \z \u')
    t = OxmlElement("w:t")
    t.text = "Nhấn Ctrl+Click, sau đó 'Update Field' để cập nhật mục lục."
    r = OxmlElement("w:r")
    r.append(t)
    fld.append(r)
    p._p.append(fld)


def page_break():
    doc.add_page_break()


# ======================================================================
# TRANG BIA
# ======================================================================
for _ in range(2):
    doc.add_paragraph()
t = doc.add_paragraph(); t.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = t.add_run("BÁO CÁO ĐỀ TÀI"); r.bold = True; r.font.size = Pt(16)
t = doc.add_paragraph(); t.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = t.add_run("TRIỂN KHAI XÂY DỰNG HỆ THỐNG\nAGENTIC SOC PLATFORM"); r.bold = True; r.font.size = Pt(22)
r.font.color.rgb = RGBColor(0x0F, 0x2A, 0x4A)
for _ in range(2):
    doc.add_paragraph()
sub = doc.add_paragraph(); sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = sub.add_run("Nền tảng điều hành an ninh mã nguồn mở dựa trên Agentic AI:\nthu thập log Windows/Linux, phát hiện dựa trên luật và\ntác tử AI phân loại - điều tra - tích lũy tri thức")
r.italic = True; r.font.size = Pt(13)
for _ in range(6):
    doc.add_paragraph()
info = doc.add_paragraph(); info.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = info.add_run("Môn học: An toàn thông tin\nĐề tài: Agentic SOC Platform\n")
r.font.size = Pt(13)
page_break()

# ======================================================================
# MUC LUC
# ======================================================================
h1("MỤC LỤC")
add_toc()
page_break()

# ======================================================================
# LOI MO DAU
# ======================================================================
h1("LỜI MỞ ĐẦU")
para("Báo cáo này trình bày quá trình nghiên cứu và xây dựng một hệ thống Agentic SOC Platform thu nhỏ: client agent thu thập log từ các máy Windows/Linux, gửi tập trung về Web SOC để lưu trữ, phát hiện, hiển thị dashboard, và các tác tử AI hỗ trợ phân loại (triage), điều tra, làm giàu dữ liệu và tích lũy tri thức.")
para("**Bối cảnh.** Các cuộc tấn công mạng ngày càng nhiều và tinh vi, trong khi mỗi máy chủ sinh ra hàng nghìn dòng log mỗi giờ. Trung tâm điều hành an ninh (SOC) cùng công cụ SIEM là nơi tập trung và phân tích dữ liệu này, nhưng đội ngũ phân tích thường rơi vào tình trạng “mệt mỏi vì cảnh báo” (alert fatigue). Agentic AI mở ra hướng giải quyết: tác tử chủ động tham gia phân loại, điều tra và tổng hợp tri thức để con người tập trung vào ra quyết định.")
para("**Mục tiêu.** (1) Nắm khái niệm SOC, SIEM và khảo sát ELK, Wazuh, Prometheus, Agentic SOC Platform; (2) tìm hiểu cấu trúc log Windows/Linux; (3) xây dựng client agent; (4) xây dựng Web SOC có dashboard, luật, cảnh báo, báo cáo; (5) tích hợp bốn tác tử AI.")
para("**Phạm vi.** Triển khai trong phòng thí nghiệm, dùng Python 3, Flask và SQLite; tập trung vào log hệ điều hành và xác thực.")
para("**Bố cục.** Chương 1 - cơ sở lý thuyết; Chương 2 - phân tích thiết kế; Chương 3 - triển khai và đánh giá kết quả.")
page_break()

# ======================================================================
# CHUONG 1
# ======================================================================
h1("CHƯƠNG 1: CƠ SỞ LÝ THUYẾT")

h2("1.1. Tổng quan về Trung tâm điều hành an ninh (SOC)")
para("Trung tâm điều hành an ninh (Security Operations Center - SOC) là một bộ phận hoặc đội ngũ tập trung chịu trách nhiệm cải thiện tư thế an ninh mạng của tổ chức, đồng thời phòng ngừa, phát hiện và phản ứng với các mối đe dọa (theo Microsoft Security). Về bản chất, SOC là sự kết hợp của ba yếu tố: **con người** (chuyên viên phân tích, kỹ sư, thợ săn mối đe dọa), **quy trình** (giám sát, phân loại, điều tra, phản ứng) và **công nghệ** (SIEM, EDR, SOAR, threat intelligence). Mục tiêu là giám sát liên tục (24/7) để phát hiện sớm và ngăn chặn sự cố trước khi gây thiệt hại lớn.")
para("**Các chức năng chính của SOC:**")
numbered([
    "**Quản lý tài sản và khả năng quan sát:** duy trì danh mục tài sản và khả năng nhìn thấy toàn bộ bề mặt tấn công.",
    "**Giám sát và thu thập log:** tập trung nhật ký từ mọi nguồn để phân tích liên tục (vai trò của SIEM).",
    "**Phát hiện mối đe dọa:** lọc dương tính giả khỏi sự cố thật, xếp hạng theo mức độ và tác động.",
    "**Phản ứng sự cố:** cô lập điểm cuối, khóa tài khoản bị xâm phạm, ngăn lây lan.",
    "**Khôi phục và rút kinh nghiệm:** phục hồi về trạng thái an toàn và cập nhật quy trình.",
    "**Tuân thủ và báo cáo:** kiểm toán và lưu nhật ký cho ISO 27001, NIST CSF, GDPR.",
])
para("**Mô hình phân tầng đội ngũ SOC:**")
table(["Vai trò", "Trách nhiệm chính"], [
    ["Analyst Tier 1", "Người phản ứng đầu tiên: giám sát, phân loại nhanh, loại dương tính giả, leo thang"],
    ["Analyst Tier 2", "Điều tra sâu, dựng chuỗi tấn công, xác định phạm vi"],
    ["Threat Hunter", "Chủ động săn mối đe dọa nâng cao công cụ bỏ sót"],
    ["Incident Responder", "Quản lý sự cố từ phát hiện tới xử lý dứt điểm"],
    ["Security Engineer", "Thiết kế kiến trúc, duy trì công cụ giám sát"],
    ["SOC Manager", "Điều phối nguồn lực, quy trình và báo cáo"],
])
para("**Quy trình xử lý sự cố.** Theo khung NIST SP 800-61, vòng đời gồm bốn pha lặp: Chuẩn bị; Phát hiện và phân tích; Ngăn chặn, loại bỏ và khôi phục; Hoạt động sau sự cố. Hệ thống trong đề tài ánh xạ vào các pha phát hiện, phân tích và tích lũy bài học.")
para("**Thách thức cốt lõi - “mệt mỏi vì cảnh báo” (alert fatigue).** Các SOC hiện đại nhận hàng nghìn tới hàng chục nghìn cảnh báo mỗi ngày; chuyên viên dễ bỏ sót cảnh báo thật giữa biển dương tính giả, thời gian phát hiện và phản hồi kéo dài. Cùng với thiếu hụt nhân lực, đây là động lực chính thúc đẩy hướng Agentic AI.")

h2("1.2. Hệ thống SIEM và các nền tảng tham khảo")
para("**SIEM là gì.** Quản lý thông tin và sự kiện an ninh (Security Information and Event Management) giúp tổ chức nhận biết và xử lý mối đe dọa trước khi chúng gây gián đoạn (theo IBM). Thuật ngữ SIEM được Gartner đưa ra năm 2005, hợp nhất SIM (quản lý thông tin) và SEM (quản lý sự kiện). Nếu SOC là “con người và quy trình” thì SIEM là “bộ não công nghệ”.")
para("**Cách SIEM hoạt động** gồm năm bước: (1) thu thập log từ nhiều nguồn; (2) chuẩn hóa về lược đồ chung; (3) tương quan sự kiện; (4) cảnh báo theo luật; (5) dashboard và báo cáo. Đây chính là bộ khung mà Web SOC tái hiện ở quy mô nhỏ.")
para("**Các nền tảng tham khảo:**")
bullets([
    "**ELK Stack:** Elasticsearch (lưu trữ + tìm kiếm JSON), Logstash (biến đổi), Kibana (trực quan), Beats/Elastic Agent (thu thập). Nền tảng log analytics phổ biến nhất, có gói SIEM riêng.",
    "**Wazuh:** hợp nhất XDR và SIEM; gồm agent, server (decoder + rule), indexer và dashboard. Agent kết nối server qua TCP 1514 (đăng ký 1515), mã hóa AES. Kiến trúc “agent → server → indexer → dashboard” là hình mẫu trực tiếp cho đề tài.",
    "**Prometheus:** giám sát chỉ số dạng time series theo mô hình pull; gồm server, exporter, Alertmanager, Pushgateway. Mạnh về giám sát sức khỏe hệ thống hơn là log an ninh.",
])
table(["Tiêu chí", "ELK", "Wazuh", "Prometheus", "Web SOC (đề tài)"], [
    ["Trọng tâm", "Log/SIEM", "XDR + SIEM", "Metrics", "SIEM nhỏ + Agentic AI"],
    ["Agent", "Beats", "Wazuh agent", "Exporter", "SOC Agent (Python)"],
    ["Lưu trữ", "Elasticsearch", "Indexer", "TSDB", "SQLite"],
    ["Phát hiện", "Rule/ML", "Decoder+Rule", "PromQL alert", "Rule engine 3 loại"],
    ["Khác biệt", "-", "-", "-", "Tác tử AI triage/điều tra"],
])

h2("1.3. Cấu trúc log hệ điều hành và mô hình Agentic SOC Platform")
h3("Log trên Windows (Windows Event Log)")
para("Windows ghi sự kiện tập trung qua dịch vụ Event Log, lưu dạng .evtx, xem bằng Event Viewer hoặc `wevtutil`. Ba kênh quan trọng: Security, System, Application. Mỗi bản ghi có EventID, Provider, Level, TimeCreated, Computer, EventRecordID và EventData.")
table(["EventID", "Ý nghĩa", "Ghi chú an ninh"], [
    ["4624 / 4625", "Đăng nhập thành công / thất bại", "4625 lặp nhiều = dò mật khẩu"],
    ["4720 / 4726", "Tạo / xóa tài khoản", "Duy trì truy cập"],
    ["4728/4732/4756", "Thêm thành viên vào nhóm", "Vào Administrators = leo thang"],
    ["4672", "Gán đặc quyền phiên đăng nhập", "Tài khoản đặc quyền"],
    ["4688", "Tạo tiến trình mới", "Theo dõi lệnh thực thi"],
    ["4697 / 7045", "Cài dịch vụ mới", "Dịch vụ lạ = mã độc"],
    ["4698", "Tạo tác vụ định thời", "Chạy lại mã độc"],
    ["4719", "Thay đổi chính sách kiểm toán", "Làm mù giám sát"],
    ["1102", "Xóa nhật ký Security", "Che dấu vết - luôn nghiêm trọng"],
])
h3("Log trên Linux (syslog, auth.log, journald)")
para("Linux ghi log theo chuẩn syslog. Định dạng RFC 5424 gồm HEADER (PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID), STRUCTURED-DATA và MSG. Giá trị PRI = facility × 8 + severity. Thang severity 0 (Emergency) tới 7 (Debug). Các tệp quan trọng: `/var/log/auth.log` hoặc `/var/log/secure` (xác thực), `/var/log/syslog` hoặc `/var/log/messages` (hệ thống). Các bản mới dùng systemd-journald, đọc bằng `journalctl -o json`.")
h3("Mô hình Agentic SOC Platform")
para("Dự án tham khảo agentic-soc-platform định nghĩa: một nền tảng an ninh mã nguồn mở dựa trên Agentic AI, cho phép tác tử chủ động tham gia phân loại, điều tra, làm giàu dữ liệu và tích lũy tri thức. Các khái niệm: Alerts hội tụ thành Cases; Artifacts/IOC; Playbooks; Modules; Knowledge. Agentic AI khác SOAR truyền thống ở chỗ tác tử hình thành giả thuyết và chủ động gọi công cụ thay vì chạy bước cố định. Đề tài đặt AI ở vai trò hỗ trợ quyết định, không tự động thi hành phản ứng.")
figure("d1_pipeline.png", "Hình 1.1. Bốn tác tử AI tham gia vòng đời xử lý cảnh báo", 4.2)

h2("1.4. Kết chương")
para("Chương 1 đã làm rõ ba khối kiến thức: SOC và bài toán alert fatigue; SIEM và các nền tảng ELK/Wazuh/Prometheus với mô hình chung “agent → server → lưu trữ → dashboard”; cấu trúc log Windows/Linux và mô hình Agentic SOC Platform với bốn chức năng tác tử. Đây là cơ sở cho thiết kế ở Chương 2.")
page_break()

# ======================================================================
# CHUONG 2
# ======================================================================
h1("CHƯƠNG 2: PHÂN TÍCH THIẾT KẾ HỆ THỐNG")

h2("2.1. Phát biểu bài toán")
para("**Bài toán.** Xây dựng hệ thống Agentic SOC Platform cho phép: (1) thu thập tập trung log từ nhiều máy Windows/Linux về Web SOC; (2) phát hiện hành vi bất thường dựa trên luật; (3) dùng tác tử AI để phân loại, làm giàu, điều tra và tích lũy tri thức; (4) cung cấp dashboard, tìm kiếm, thống kê và báo cáo.")
para("**Đầu vào:** Windows Event Log, Linux syslog/journald, log ứng dụng dạng tệp. **Đầu ra:** log chuẩn hóa, cảnh báo kèm kết luận AI, báo cáo điều tra, tri thức, dashboard.")
para("**Ràng buộc:** agent chỉ dùng thư viện chuẩn Python; hệ thống chạy được kể cả khi không có LLM (tự chuyển sang suy luận cục bộ); dữ liệu lưu nội bộ. **Tiêu chí thành công:** gửi log ổn định không trùng; luật phát hiện đúng; AI xếp đúng ưu tiên; dashboard/báo cáo đúng số liệu.")

h2("2.2. Phân tích hiện trạng")
para("Ở nhiều tổ chức nhỏ, log nằm rải rác trên từng máy; quản trị viên phải đăng nhập từng máy, không tương quan được sự kiện, dễ mất log khi bị xâm nhập. Các SIEM lớn (ELK, Wazuh, Splunk) giải quyết tập trung hóa nhưng triển khai nặng, vẫn sinh nhiều cảnh báo và phần lớn chưa tích hợp tác tử AI chủ động. Đề tài lấp khoảng trống bằng một hệ thống gọn, tự chứa nhưng vẫn giữ đủ bốn tác tử AI.")
table(["Vấn đề hiện trạng", "Hướng giải quyết trong đề tài"], [
    ["Log rải rác", "SOC Agent gửi tập trung về Web SOC qua REST API"],
    ["Mất log khi bị xóa", "Log đã gửi về server lưu độc lập với máy nguồn"],
    ["Định dạng không đồng nhất", "Chuẩn hóa về một lược đồ chung"],
    ["Quá nhiều cảnh báo", "Tác tử AI chấm điểm rủi ro, xếp ưu tiên"],
    ["Điều tra thủ công chậm", "Tác tử Investigation dựng chuỗi tấn công, IOC"],
    ["Tri thức không được lưu", "Tác tử Knowledge tích lũy playbook"],
    ["Phụ thuộc dịch vụ ngoài", "Chạy được ở chế độ suy luận cục bộ"],
])

h2("2.3. Phân tích chức năng")
h3("2.3.1. Đối tượng sử dụng")
table(["Đối tượng", "Quyền hạn / vai trò"], [
    ["Quản trị viên (admin)", "Toàn quyền: người dùng, máy trạm, luật, cấu hình"],
    ["Chuyên viên (analyst)", "Xử lý cảnh báo, chạy AI, sửa luật, viết tri thức"],
    ["Người xem (viewer)", "Chỉ xem dashboard, cảnh báo, log, báo cáo"],
    ["SOC Agent", "Thu thập và gửi log; xác thực bằng API key"],
    ["Tác tử AI", "Phân tích cảnh báo, gọi công cụ truy vấn dữ liệu"],
])
h3("2.3.2. Chức năng 1: Thu thập và chuẩn hóa log")
para("SOC Agent dùng các collector đọc phần log mới (giữ con trỏ), chuẩn hóa rồi gửi theo lô. Linux dùng regex khớp RFC3164/ISO/RFC5424 rồi đối chiếu ~30 mẫu; Windows đọc XML từ `wevtutil` và tra bảng ~50 EventID; journald đọc JSON. Mỗi sự kiện được gán `event_hash` (SHA1) để chống trùng.")
h3("2.3.3. Chức năng 2: Phát hiện dựa trên luật (Rule Engine)")
para("Bộ máy luật hỗ trợ ba loại: **match** (một sự kiện khớp → cảnh báo), **threshold** (đếm trong cửa sổ trượt theo nhóm, có thể đếm giá trị khác nhau để bắt password spraying), **sequence** (trigger sau ≥ min_count precondition). Thuật toán rút gọn:")
code("for rule in rules_enabled:\n  for ev in new_events:\n    if match: raise(rule, ev, [ev])\n    elif threshold: count events same group in [t-W, t]; if count>=N: raise(...)\n    elif sequence: if >= min_count precondition in window: raise(...)\nraise(): dedup vao canh bao dang mo cung (rule|host|group), nguoc lai tao moi")
para("Điều kiện đơn giản được đẩy xuống SQL, phần regex/extra lọc bằng Python. Hệ thống có 21 luật mặc định gắn nhãn MITRE ATT&CK.")
h3("2.3.4. Chức năng 3: Làm giàu dữ liệu và phân loại AI")
para("**Enrichment** bổ sung ngữ cảnh: phân loại IP, uy tín IP, lịch sử 7 ngày, ngữ cảnh tài khoản/máy/thời gian, MITRE và cảnh báo liên quan. **Triage** cho điểm rủi ro: điểm cơ sở theo mức luật, cộng/trừ theo chỉ dấu (IP công cộng +15, blocklist +25, đã có đăng nhập thành công +15, tài khoản đặc quyền +10, ngoài giờ +5; nguồn nội bộ giờ hành chính -20). Thứ điểm → ≥ 85 P1 true_positive, 65-84 P2, 45-64 P3, 25-44 P4, <25 P5 false_positive.")
h3("2.3.5. Chức năng 4: Điều tra, tri thức, dashboard, báo cáo")
para("**Investigation** dựng dòng thời gian, chuỗi tấn công theo ATT&CK, trích IOC và khuyến nghị; ở đường LLM tác tử chủ động gọi công cụ. **Knowledge** rút bài học. **Dashboard** hiển thị KPI và biểu đồ cập nhật 30 giây. **Tìm kiếm log** đa tiêu chí, xuất CSV. **Báo cáo** theo khoảng thời gian có MTTR và in PDF.")
h3("2.3.6. Công nghệ sử dụng")
table(["Thành phần", "Công nghệ"], [
    ["Ngôn ngữ", "Python 3.12"],
    ["Web framework", "Flask 3, Jinja2"],
    ["ORM / CSDL", "SQLAlchemy 2 + SQLite (WAL)"],
    ["Xác thực", "Flask session, Werkzeug (băm mật khẩu)"],
    ["Giao diện", "Bootstrap 5, Chart.js 4"],
    ["AI", "Claude API (Anthropic SDK), claude-opus-5-5, structured outputs + tool use"],
    ["SOC Agent", "Thư viện chuẩn Python (urllib); psutil tuỳ chọn"],
])

h2("2.4. Thiết kế cơ sở dữ liệu")
h3("2.4.1. Sơ đồ tổng thể")
para("Cơ sở dữ liệu SQLite gồm 11 bảng. Một agent sinh nhiều log_events; detection_rules áp lên log_events sinh alerts; alerts liên kết log_events qua alert_events (N-N); mỗi alert có nhiều investigations, ai_runs và knowledge_articles.")
figure("d2_erd.png", "Hình 2.1. Sơ đồ thực thể - liên kết (ERD)", 6.3)
table(["Bảng", "Vai trò"], [
    ["users", "Tài khoản Web SOC (admin/analyst/viewer)"],
    ["agents", "Máy trạm đã đăng ký, kèm API key (băm)"],
    ["log_events", "Sự kiện log đã chuẩn hóa"],
    ["detection_rules", "Luật phát hiện (match/threshold/sequence)"],
    ["alerts", "Cảnh báo, kèm kết quả AI"],
    ["alert_events", "Bảng nối cảnh báo - sự kiện (N-N)"],
    ["investigations", "Báo cáo điều tra"],
    ["knowledge_articles", "Cơ sở tri thức"],
    ["ai_runs", "Nhật ký các lượt chạy tác tử AI"],
    ["audit_logs", "Nhật ký thao tác người dùng"],
    ["ip_reputation", "Uy tín IP (blocklist/allowlist)"],
])
h3("2.4.2. Bảng log_events")
para("Lưu mọi sự kiện đã chuẩn hóa: `event_time`, `received_at`, `source`, `category`, `action`, `outcome`, `severity`, `event_id`, `message`, `user_name`, `src_ip`, `src_port`, `process_name`, `pid`, `host`, `raw`, `extra` (JSON) và `event_hash` (duy nhất, chống trùng). Các cột tìm kiếm được đánh chỉ mục.")
h3("2.4.3. Bảng alerts")
para("Mỗi cảnh báo gắn một luật (`rule_id`) và một máy (`agent_id`). Nhóm cột do AI ghi: `ai_verdict`, `ai_confidence`, `ai_priority`, `ai_summary`, `ai_mode`, `ai_data` (JSON). `dedup_key` gom các lần kích hoạt của cùng cuộc tấn công. Trạng thái: new → triaged → investigating → resolved / false_positive.")

h2("2.5. Xây dựng chương trình")
h3("2.5.1. Kiến trúc tổng thể")
para("Hệ thống gồm SOC Agent trên máy trạm và Web SOC trên máy chủ, giao tiếp qua REST API.")
figure("d3_architecture.png", "Hình 2.2. Kiến trúc hệ thống và luồng xử lý dữ liệu", 6.3)
h3("2.5.2. Tổ chức thư mục")
code("atttprj/\n  soc_server/            # Web SOC\n    run.py, config.py\n    app/\n      __init__.py        # application factory\n      models.py          # 11 bang ORM\n      auth.py, api.py, views.py\n      ingest.py          # pipeline tiep nhan\n      detection.py       # rule engine\n      enrichment.py, stats.py, parsers.py\n      ai/                # module Agentic AI\n        llm.py, tools.py, agents.py, orchestrator.py\n      templates/, static/\n  soc_agent/             # SOC Agent\n    agent.py, collectors.py, parsers.py\n    config.example.json, install/\n  tools/                 # demo_attack.py, test_parsers.py\n  docs/screenshots/\n  requirements.txt")
h3("2.5.3. Các module chính")
bullets([
    "**parsers.py** (dùng chung): lược đồ chuẩn hóa; hàm phân tích syslog, access log, Windows Event XML với bảng ánh xạ ~50 EventID và ~30 mẫu Linux.",
    "**collectors.py**: FileCollector, WindowsEventLogCollector, JournaldCollector - mỗi loại tự giữ con trỏ, xử lý log xoay vòng.",
    "**agent.py**: đăng ký bằng enrollment token, thu thập theo chu kỳ, gửi theo lô có hàng đợi chống mất log; chỉ dùng urllib.",
    "**detection.py**: RuleEngine ba thuật toán match/threshold/sequence, dedup cảnh báo, chạy lại trên lịch sử.",
    "**ai/agents.py**: bốn tác tử, mỗi tác tử có run_llm() và run_local(); tự chuyển LOCAL khi không có LLM.",
    "**ai/orchestrator.py**: điều phối enrich → triage → investigate → knowledge, chạy nền khi tự động.",
    "**ai/llm.py**: bọc Claude API - complete_json() và run_with_tools(), bật fallback phía máy chủ.",
])

h2("2.6. Kết chương")
para("Chương 2 đã phát biểu bài toán, phân tích hiện trạng và thiết kế đầy đủ hệ thống: bốn khối chức năng, cơ sở dữ liệu 11 bảng, và kiến trúc SOC Agent + Web SOC. Điểm thiết kế quan trọng là tính bền bỉ: mọi tác tử AI đều có hai đường chạy (LLM và cục bộ).")
page_break()

# ======================================================================
# CHUONG 3
# ======================================================================
h1("CHƯƠNG 3: TRIỂN KHAI VÀ ĐÁNH GIÁ KẾT QUẢ")

h2("3.1. Mô hình triển khai")
h3("3.1.1. Môi trường triển khai")
table(["Thành phần", "Cấu hình"], [
    ["Máy chủ Web SOC", "Windows 11, Python 3.12, Flask, cổng 5000"],
    ["CSDL", "SQLite (WAL), instance/soc.db"],
    ["Máy trạm mô phỏng", "2 Windows Server, 2 Linux (Ubuntu, CentOS)"],
    ["Kết nối", "LAN, REST API HTTP"],
    ["Mô hình AI", "Suy luận cục bộ (không cấu hình khóa Claude trong lần thử này)"],
])
para("Bốn máy trạm được mô phỏng bằng `tools/demo_attack.py` - đóng vai nhiều agent, đăng ký qua API thật rồi gửi kịch bản tấn công xen log nền. Khi triển khai thật, mỗi máy cài agent (Windows: Scheduled Task; Linux: systemd service).")
h3("3.1.2. Các công cụ sử dụng")
bullets([
    "Phát triển: Python 3.12, Flask 3, SQLAlchemy 2, Anthropic SDK.",
    "Giao diện: Bootstrap 5, Chart.js 4, Bootstrap Icons.",
    "Kiểm thử: test_parsers.py, demo_attack.py.",
])
h3("3.1.3. Cấu hình hệ thống")
code("# Khoi dong Web SOC\ncd soc_server && python run.py --port 5000\n\n# Dang ky agent tren may tram\ncd soc_agent && python agent.py --server http://IP_SOC:5000 --token soc-enroll-2026 --register")
para("Lần đầu chạy, hệ thống tự tạo CSDL, 3 tài khoản mặc định (admin/analyst/viewer), 21 luật và các bài tri thức mẫu.")
figure("08_agents.jpg", "Hình 3.1. Danh sách máy trạm đã đăng ký (Windows và Linux)")

h2("3.2. Kết quả thực nghiệm")
para("Lần chạy thực nghiệm gửi **380 sự kiện** từ 4 máy trong 2 giờ, gồm 5 kịch bản tấn công xen log nền. Hệ thống sinh **18 cảnh báo** và chạy **36 lượt tác tử AI** (100% thành công).")
h3("3.2.1. Kịch bản 1: Đăng nhập hệ thống")
para("Đăng nhập bằng ba tài khoản mặc định để kiểm tra phân quyền.")
bullets([
    "Đăng nhập đúng → chuyển về dashboard; menu hiển thị theo vai trò (viewer không thấy Người dùng/Cài đặt).",
    "Sai 5 lần → khóa tài khoản 5 phút (chống dò mật khẩu chính Web SOC).",
    "Truy cập ngoài quyền → báo lỗi 403. Mọi đăng nhập/đăng xuất được ghi audit.",
])
figure("01_login.jpg", "Hình 3.2. Trang đăng nhập Web SOC", 3.6)
h3("3.2.2. Kịch bản 2: Nhập/xem dữ liệu (thu thập log và phát hiện)")
para("Bốn agent đăng ký thành công, gửi log đúng số lượng, không trùng. Năm kịch bản tấn công đã kích hoạt luật:")
table(["Kịch bản tấn công", "Máy", "Luật", "MITRE", "Verdict AI", "Ưu tiên"], [
    ["Xóa nhật ký (1102)", "WIN-DC01", "R01", "T1070.001", "Tấn công thật", "P1"],
    ["Dò SSH → thành công", "centos-db01", "R15,R18", "T1110.001", "Tấn công thật", "P1"],
    ["Dò RDP → thành công", "WIN-SRV02", "R16,R18", "T1110.001", "Tấn công thật", "P1"],
    ["Password spraying", "ubuntu-web01", "R17", "T1110.003", "Tấn công thật", "P1"],
    ["Tạo tk + thêm admin", "WIN-DC01", "R03,R04", "T1136/T1098", "Khả năng tấn công", "P2-P3"],
    ["Cài dịch vụ + tác vụ", "WIN-DC01", "R05,R06", "T1543/T1053", "Đáng ngờ", "P3"],
    ["Quét/tấn công web", "ubuntu-web01", "R11,R19", "T1190/T1595", "Đáng ngờ / DT giả", "P3-P5"],
])
figure("06_logs.jpg", "Hình 3.3. Tra cứu log tập trung (lọc mức Cao + Nghiêm trọng)")
h3("3.2.3. Kịch bản 3: Tìm kiếm, thống kê")
para("Trang Nhật ký log lọc đa tiêu chí và xuất CSV. Dashboard cập nhật mỗi 30 giây với KPI (380 sự kiện/24h, 18 cảnh báo mở, 4/4 agent), biểu đồ sự kiện theo giờ (thấy đỉnh khi tấn công), mức độ, cảnh báo theo ngày, nguồn log và IP/tài khoản bị thuật nhiều nhất.")
figure("02_dashboard.jpg", "Hình 3.4. Dashboard giám sát an ninh")
h3("3.2.4. Kịch bản 4: Truy vấn, báo cáo (phân loại và điều tra bằng AI)")
para("Tác tử AI tự động chấm điểm rủi ro và xếp ưu tiên đúng: 7 cảnh báo P1 (tấn công thật), trong khi quét web bị hạ xuống P5. Phân bố kết luận:")
table(["Kết luận AI", "Số cảnh báo", "Ưu tiên"], [
    ["Tấn công thật (true_positive)", "7", "P1"],
    ["Khả năng tấn công", "3", "P2"],
    ["Đáng ngờ (suspicious)", "7", "P3"],
    ["Dương tính giả", "1", "P5"],
])
para("Với cảnh báo “Đăng nhập thành công sau 18 lần thất bại”, tác tử Investigation dựng chuỗi tấn công đầy đủ: Initial Access (T1078) → Credential Access (T1110.001) → Persistence (T1136.001) → Privilege Escalation (T1098), kèm dòng thời gian 27 sự kiện, IOC và 14 khuyến nghị. Tác tử Knowledge tự sinh bài học đưa vào cơ sở tri thức.")
figure("04_alert_triage.jpg", "Hình 3.5. Chi tiết cảnh báo và kết quả phân loại (Triage Agent)")
figure("05_alert_investigation.jpg", "Hình 3.6. Báo cáo điều tra: chuỗi tấn công MITRE, IOC, dòng thời gian")
figure("03_alerts.jpg", "Hình 3.7. Danh sách cảnh báo xếp theo ưu tiên AI")
figure("07_reports.jpg", "Hình 3.8. Trang báo cáo và thống kê")
figure("09_kb.jpg", "Hình 3.9. Cơ sở tri thức (bài học AI sinh ra và playbook thủ công)")

h2("3.3. Nhận xét đánh giá kết quả")
para("**Ưu điểm đạt được:**")
bullets([
    "**Thu thập đa nền tảng:** agent chạy cả Windows và Linux, chuẩn hóa về lược đồ chung, có hàng đợi chống mất log và băm chống trùng.",
    "**Phát hiện hiệu quả:** 21 luật với ba cơ chế bắt đúng các kịch bản tấn công phổ biến, gắn nhãn MITRE.",
    "**AI giảm tải phân loại:** Triage xếp đúng ưu tiên - 7 vụ nghiêm trọng lên P1, hạ nhiễu quét web xuống P5.",
    "**Điều tra tự động:** Investigation dựng chuỗi tấn công, dòng thời gian và IOC.",
    "**Tính bền bỉ:** toàn bộ thực nghiệm chạy ở chế độ cục bộ không cần LLM mà vẫn hợp lý.",
])
table(["Tiêu chí", "Suy luận cục bộ", "Đường LLM (Claude)"], [
    ["Phụ thuộc mạng/khóa", "Không", "Có"],
    ["Chi phí", "Miễn phí", "Tính theo token"],
    ["Chất lượng lập luận", "Đủ dùng, theo mẫu", "Tự nhiên, sâu hơn"],
    ["Gọi công cụ linh hoạt", "Cố định", "Chủ động theo ngữ cảnh"],
    ["Độ ổn định đầu ra", "Tuyệt đối (JSON)", "Cao (structured outputs)"],
])
para("**Hạn chế:** dùng SQLite và Flask dev server (phù hợp quy mô nhỏ, nên chuyển PostgreSQL + WSGI production khi mở rộng); chấm điểm heuristic cần tinh chỉnh theo môi trường; thực nghiệm dùng dữ liệu mô phỏng, cần kiểm chứng thêm trên log thật; AI ở vai trò hỗ trợ quyết định, chưa tự động thi hành phản ứng.")

h2("3.4. Kết chương")
para("Chương 3 đã triển khai hệ thống và kiểm chứng qua bốn kịch bản. Kết quả cho thấy hệ thống hoạt động đúng từ đăng nhập phân quyền, thu thập - phát hiện, tìm kiếm - thống kê, đến phân loại - điều tra - báo cáo bằng AI. Lớp Agentic AI xếp đúng ưu tiên và dựng được chuỗi tấn công theo MITRE ATT&CK kể cả ở chế độ cục bộ. Hướng phát triển: tích hợp threat intelligence, hỗ trợ thêm nguồn log, chuyển sang CSDL production và phản ứng bán tự động có kiểm soát.")
page_break()

# ======================================================================
# TAI LIEU THAM KHAO
# ======================================================================
h1("TÀI LIỆU THAM KHẢO")
refs = [
    "Microsoft Security, What is a Security Operations Center (SOC)?",
    "IBM, What is SIEM? - ibm.com/think/topics/siem",
    "NIST, Computer Security Incident Handling Guide (SP 800-61).",
    "Elastic, Elastic (ELK) Stack - elastic.co/elastic-stack",
    "Wazuh, Wazuh architecture - documentation.wazuh.com",
    "Prometheus, Overview - prometheus.io",
    "MITRE, ATT&CK Knowledge Base - attack.mitre.org",
    "Microsoft Learn, Windows Event Logging & Appendix L: Events to Monitor.",
    "IETF, RFC 5424 - The Syslog Protocol.",
    "funnywolf, agentic-soc-platform - github.com/funnywolf/agentic-soc-platform",
    "Vectra AI, Agentic SOC explained - vectra.ai/topics/agentic-soc",
    "Anthropic, Claude API documentation - platform.claude.com/docs",
]
numbered(refs)

# ---------------------------------------------------------------- save
doc.save(OUT)
print("Da tao bao cao:", OUT)
print("So trang (uoc luong theo so page_break):", len([p for p in doc.paragraphs]))

