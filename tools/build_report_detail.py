# -*- coding: utf-8 -*-
"""
build_report_detail.py - Sinh BÁO CÁO CHI TIẾT (bản mở rộng) dạng Word từ các phần trong tools/report_parts/.

Chạy:   python tools/report_figures.py && python tools/report_figures_extra.py   (sinh hình)
        python tools/build_report_detail.py                                       (sinh docs/BaoCao_ChiTiet_NenTang_AgenticSOC.docx)
"""
import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "report_parts"))

from report_lib import doc, counts, ROOT  # noqa: E402

OUT = os.path.join(ROOT, "docs", "BaoCao_ChiTiet_NenTang_AgenticSOC.docx")
PARTS = ["p0_front", "p1_soc_siem", "p2_platforms", "p3_asp", "p4_logs", "p5_agent", "p6_websoc",
         "p7_analysis", "p8_improvements", "p9_end"]


def main():
    for name in PARTS:
        mod = importlib.import_module(name)
        mod.build()
        print("  + %-16s (%d đoạn)" % (name, len(doc.paragraphs)))
    doc.save(OUT)
    c = counts()
    print("Đã tạo:", OUT)
    print("Số đoạn: %d | Số bảng: %d | Số hình: %d" % (c["paragraphs"], c["tables"], c["figures"]))


if __name__ == "__main__":
    main()
