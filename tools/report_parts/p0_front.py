# -*- coding: utf-8 -*-
"""Trang bìa, mục lục, lời mở đầu, hướng dẫn đọc."""
from report_lib import *  # noqa: F401,F403
from docx.shared import Pt, RGBColor


def build():
    for _ in range(3):
        doc.add_paragraph()
    p = para("BÁO CÁO CHI TIẾT", "center"); p.runs[0].bold = True; p.runs[0].font.size = Pt(16)
    p = para("NỀN TẢNG LÝ THUYẾT VÀ PHÂN TÍCH HỆ THỐNG\nAGENTIC SOC PLATFORM", "center")
    p.runs[0].bold = True; p.runs[0].font.size = Pt(22); p.runs[0].font.color.rgb = RGBColor(0x0F, 0x2A, 0x4A)
    doc.add_paragraph()
    para("SOC và SIEM · Khảo sát ELK / Wazuh / Prometheus · Agentic SOC Platform ·\nCấu trúc log Windows/Linux (Lab 17) · SOC Agent · Web SOC có dashboard ·\nPhân tích chức năng thu thập log · Cải tiến mã nguồn · Thuật ngữ · Phụ lục", "center", italic=True)
    for _ in range(6):
        doc.add_paragraph()
    para("Môn học: An toàn thông tin\nĐề tài: Agentic SOC Platform\nPhiên bản mã nguồn: 1.1 · Phiên bản báo cáo: 2 (mở rộng, tháng 10/2026)", "center")
    page_break()

    h1("MỤC LỤC")
    add_toc()
    page_break()

    h1("LỜI MỞ ĐẦU")
    para("Tài liệu này là bản báo cáo chi tiết về **nền tảng lý thuyết** và **phân tích hệ thống** của đề tài Agentic SOC Platform. "
         "Báo cáo đồ án (docs/BaoCao_Agentic_SOC_Platform.docx) được viết theo cấu trúc ba chương để nộp; tài liệu này đi sâu vào từng đề mục nền tảng "
         "mà người thực hiện cần nắm vững trước và trong khi xây dựng hệ thống, với sơ đồ, bảng tra cứu, trích mã nguồn có chú giải, ví dụ từ dữ liệu "
         "thực nghiệm và liên kết tham khảo để tiếp tục tự học.")
    para("**Bảy đề mục được bám sát:**")
    numbered([
        "Khái niệm Trung tâm điều hành an ninh (SOC) và Quản lý thông tin - sự kiện an ninh (SIEM).",
        "Tham khảo các hệ thống SOC/SIEM phổ biến: ELK Stack, Wazuh, Prometheus và một số nền tảng khác.",
        "Agentic SOC Platform - nền tảng điều hành an ninh mã nguồn mở dựa trên Agentic AI (github.com/funnywolf/agentic-soc-platform).",
        "Cấu trúc tệp log trên hệ điều hành Windows và Linux (nội dung Lab 17 - Phân tích log Server).",
        "Xây dựng chương trình client (SOC Agent) đọc và gửi log về Web SOC.",
        "Xây dựng ứng dụng Web SOC có dashboard quản lý dữ liệu log từ các máy chủ gửi về.",
        "Phân tích các chức năng của hệ thống SOC để thu thập log từ máy Windows và Linux.",
    ])
    para("Các phần cuối tổng hợp **cải tiến mã nguồn** đã thực hiện trong lần rà soát (kèm kết quả kiểm thử), **bảng thuật ngữ**, danh mục "
         "**tài liệu tham khảo có liên kết** và các **phụ lục** tra cứu nhanh (bộ luật đầy đủ, bảng ánh xạ EventID và mẫu regex, tham chiếu API, cấu hình, lệnh vận hành).")
    h3("Cách đọc tài liệu")
    table(["Bạn đọc là", "Nên đọc", "Có thể bỏ qua"], [
        ["Sinh viên cần nắm lý thuyết để bảo vệ", "Phần 1-4, Thuật ngữ", "Phụ lục mã nguồn"],
        ["Người sẽ triển khai hệ thống thật", "Phần 5-7, Phụ lục A/C/D", "Phần 2"],
        ["Người tiếp tục phát triển mã nguồn", "Phần 5, 6, 8 và Phụ lục B/E", "Phần 1"],
        ["Giảng viên chấm", "Lời mở đầu, Phần 7-8, Kết luận", "-"],
    ], widths=[2.0, 2.5, 2.0], size=10.5, caption="Gợi ý lộ trình đọc", part="0")
    para("**Quy ước trình bày:** từ khóa kỹ thuật giữ nguyên tiếng Anh kèm giải thích tiếng Việt ở lần xuất hiện đầu; tên tệp, hàm, trường dữ liệu được in "
         "bằng phông chữ đơn cách (ví dụ `soc_agent/agent.py`); trích mã nguồn được rút gọn để tập trung vào ý chính, bản đầy đủ nằm trong thư mục dự án. "
         "Hình và bảng đánh số theo phần (Hình 4.3 = hình thứ 3 của Phần 4). Số liệu thực nghiệm lấy từ cơ sở dữ liệu trình diễn được tạo lại bằng mã nguồn 1.1 "
         "(`tools/rebuild_demo.py`): 380 sự kiện, 19 cảnh báo, 49 lượt tác tử AI.")
    para("**Giới hạn:** tài liệu Lab 17 gốc không có trong tay người viết, nên Phần 4 trình bày theo nội dung phân tích log server điển hình và cách hệ thống tự động hóa từng bước; "
         "các con số về thị trường/khảo sát ngành là số công bố công khai tại thời điểm viết và được dẫn nguồn.")
    page_break()
