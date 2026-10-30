# -*- coding: utf-8 -*-
"""
report_lib.py - Thư viện dùng chung để sinh báo cáo Word (python-docx) cho các script tools/report_parts/*.

Cung cấp: doc (tài liệu), h1/h2/h3, para, bullets, numbered, code, table, figure, link_line, add_toc,
page_break, add_hyperlink. Mọi phần báo cáo chỉ cần `from report_lib import *`.
"""
import os
import re
import sys

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(ROOT, "docs", "figures")
SHOTS = os.path.join(ROOT, "docs", "screenshots")
DB_PATH = os.path.join(ROOT, "soc_server", "instance", "soc_demo.db")
if not os.path.exists(DB_PATH):
    DB_PATH = os.path.join(ROOT, "soc_server", "instance", "soc.db")

doc = Document()
for _section in doc.sections:
    _section.left_margin = _section.right_margin = Inches(1.0)
    _section.top_margin = _section.bottom_margin = Inches(0.9)

_style = doc.styles["Normal"]
_style.font.name = "Times New Roman"
_style.font.size = Pt(13)
_style.element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")
_style.paragraph_format.space_after = Pt(6)
_style.paragraph_format.line_spacing = 1.35
for _i, _sz in ((1, 16), (2, 14), (3, 13)):
    _h = doc.styles["Heading %d" % _i]
    _h.font.name = "Times New Roman"
    _h.font.size = Pt(_sz)
    _h.font.bold = True
    _h.font.color.rgb = RGBColor(0x0F, 0x2A, 0x4A)
    _h.element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")

_fig_no = {}
_tab_no = {}


def add_hyperlink(paragraph, url, text=None):
    part = paragraph.part
    r_id = part.relate_to(url, "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                          is_external=True)
    hl = OxmlElement("w:hyperlink")
    hl.set(qn("r:id"), r_id)
    r = OxmlElement("w:r")
    rpr = OxmlElement("w:rPr")
    c = OxmlElement("w:color"); c.set(qn("w:val"), "1155CC"); rpr.append(c)
    u = OxmlElement("w:u"); u.set(qn("w:val"), "single"); rpr.append(u)
    rf = OxmlElement("w:rFonts"); rf.set(qn("w:ascii"), "Times New Roman"); rf.set(qn("w:hAnsi"), "Times New Roman"); rpr.append(rf)
    r.append(rpr)
    t = OxmlElement("w:t"); t.text = text or url; t.set(qn("xml:space"), "preserve")
    r.append(t)
    hl.append(r)
    paragraph._p.append(hl)


def _runs(p, text):
    """Hỗ trợ **đậm**, *nghiêng*, `mã`, [nhãn](url)."""
    for seg in re.split(r"(\*\*.+?\*\*|`.+?`|\[[^\]]+\]\([^)]+\))", text):
        if not seg:
            continue
        if seg.startswith("**") and seg.endswith("**"):
            r = p.add_run(seg[2:-2]); r.bold = True
        elif seg.startswith("`") and seg.endswith("`"):
            r = p.add_run(seg[1:-1]); r.font.name = "Consolas"; r.font.size = Pt(11)
        elif seg.startswith("[") and "](" in seg:
            m = re.match(r"\[([^\]]+)\]\(([^)]+)\)", seg)
            add_hyperlink(p, m.group(2), m.group(1))
        else:
            p.add_run(seg)


def h1(t): doc.add_heading(t, level=1)
def h2(t): doc.add_heading(t, level=2)
def h3(t): doc.add_heading(t, level=3)


def h4(t):
    p = doc.add_paragraph()
    r = p.add_run(t); r.bold = True; r.italic = True
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.keep_with_next = True
    return p


def para(text, align="justify", italic=False, size=None):
    p = doc.add_paragraph()
    _runs(p, text)
    if italic or size:
        for r in p.runs:
            if italic:
                r.italic = True
            if size:
                r.font.size = Pt(size)
    p.alignment = {"center": WD_ALIGN_PARAGRAPH.CENTER, "left": WD_ALIGN_PARAGRAPH.LEFT}.get(align, WD_ALIGN_PARAGRAPH.JUSTIFY)
    return p


def note(text):
    """Ô ghi chú nền xanh nhạt."""
    p = doc.add_paragraph()
    _runs(p, text)
    p.paragraph_format.left_indent = Inches(0.15)
    shd = OxmlElement("w:shd"); shd.set(qn("w:fill"), "EAF2FB")
    p._p.get_or_add_pPr().append(shd)
    for r in p.runs:
        r.font.size = Pt(12)
    return p


def bullets(items):
    for it in items:
        _runs(doc.add_paragraph(style="List Bullet"), it)


def numbered(items):
    for it in items:
        _runs(doc.add_paragraph(style="List Number"), it)


def code(text, size=10):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.font.name = "Consolas"; r.font.size = Pt(size)
    p.paragraph_format.left_indent = Inches(0.2)
    p.paragraph_format.space_after = Pt(8)
    p.paragraph_format.line_spacing = 1.1
    shd = OxmlElement("w:shd"); shd.set(qn("w:fill"), "F2F4F7")
    p._p.get_or_add_pPr().append(shd)


def table(headers, rows, widths=None, size=10.5, caption=None, part=None):
    if caption and part:
        n = _tab_no.get(part, 0) + 1
        _tab_no[part] = n
        p = doc.add_paragraph()
        r = p.add_run("Bảng %s.%d. %s" % (part, n, caption)); r.bold = True; r.font.size = Pt(11.5)
        p.paragraph_format.keep_with_next = True
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Light Grid Accent 1"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, head in enumerate(headers):
        c = t.rows[0].cells[i]; c.text = ""
        r = c.paragraphs[0].add_run(head); r.bold = True; r.font.size = Pt(size + 0.5)
    for row in rows:
        cells = t.add_row().cells
        for i, val in enumerate(row):
            cells[i].text = ""
            _runs(cells[i].paragraphs[0], str(val))
            for r in cells[i].paragraphs[0].runs:
                r.font.size = Pt(size)
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Inches(w)
    doc.add_paragraph()
    return t


def figure(name, caption, part, width=6.3, folder=None):
    if folder is None:
        folder = SHOTS if name.endswith(".jpg") or name.startswith("d") else FIG
    path = os.path.join(folder, name)
    n = _fig_no.get(part, 0) + 1
    _fig_no[part] = n
    cap = "Hình %s.%d. %s" % (part, n, caption)
    if not os.path.exists(path):
        para("[Thiếu ảnh: %s] %s" % (name, cap), italic=True)
        return
    doc.add_picture(path, width=Inches(width))
    doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(cap); r.italic = True; r.font.size = Pt(11)
    p.paragraph_format.space_after = Pt(10)


def add_toc():
    p = doc.add_paragraph()
    fld = OxmlElement("w:fldSimple"); fld.set(qn("w:instr"), r'TOC \o "1-3" \h \z \u')
    r = OxmlElement("w:r"); t = OxmlElement("w:t")
    t.text = "Nhấn chuột phải vào đây và chọn 'Update Field' (hoặc F9) để cập nhật mục lục."
    r.append(t); fld.append(r); p._p.append(fld)


def page_break():
    doc.add_page_break()


def new_section(landscape=False):
    """Bắt đầu một section mới (trang mới) theo chiều ngang hoặc dọc - dùng cho bảng nhiều cột."""
    from docx.enum.section import WD_ORIENT, WD_SECTION
    sec = doc.add_section(WD_SECTION.NEW_PAGE)
    w, h = sec.page_width, sec.page_height
    if landscape != (w > h):
        sec.page_width, sec.page_height = h, w
    sec.orientation = WD_ORIENT.LANDSCAPE if landscape else WD_ORIENT.PORTRAIT
    sec.left_margin = sec.right_margin = Inches(0.8 if landscape else 1.0)
    sec.top_margin = sec.bottom_margin = Inches(0.8 if landscape else 0.9)
    return sec


def link_line(label_text, url):
    p = doc.add_paragraph(style="List Bullet")
    p.add_run(label_text + ": ")
    add_hyperlink(p, url)


def counts():
    return {"figures": sum(_fig_no.values()), "tables": len(doc.tables), "paragraphs": len(doc.paragraphs)}


def db_query(sql, params=()):
    """Truy vấn CSDL demo (trả về [] nếu không có)."""
    import sqlite3
    if not os.path.exists(DB_PATH):
        return []
    con = sqlite3.connect(DB_PATH)
    try:
        return con.execute(sql, params).fetchall()
    finally:
        con.close()
