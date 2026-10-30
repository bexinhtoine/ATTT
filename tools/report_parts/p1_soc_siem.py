# -*- coding: utf-8 -*-
"""PHẦN 1. KHÁI NIỆM SOC VÀ SIEM (mở rộng)."""
from report_lib import *  # noqa: F401,F403

P = "1"


def build():
    h1("PHẦN 1. KHÁI NIỆM SOC VÀ SIEM")
    para("Phần này xây dựng nền tảng khái niệm: SOC là gì, làm những việc gì, được tổ chức ra sao và đo lường thế nào; SIEM là gì, hoạt động theo những bước nào, "
         "đã tiến hóa qua các thế hệ nào và vì sao mô hình SIEM truyền thống dẫn tới nhu cầu Agentic AI. Mỗi khái niệm đều được đối chiếu với thành phần tương ứng trong hệ thống của đề tài "
         "để người đọc thấy lý thuyết được hiện thực ở đâu.")

    # ------------------------------------------------------------------ 1.1
    h2("1.1. Trung tâm điều hành an ninh (SOC)")
    h3("1.1.1. Định nghĩa")
    para("**SOC (Security Operations Center)** là một đơn vị tập trung - gồm con người, quy trình và công nghệ - chịu trách nhiệm **giám sát liên tục**, "
         "**phát hiện**, **phân tích**, **phản ứng** và **báo cáo** về các sự cố an toàn thông tin của tổ chức. Microsoft định nghĩa SOC là \"a centralized "
         "function or team responsible for improving an organization's cybersecurity posture and preventing, detecting, and responding to threats\"; IBM nhấn mạnh "
         "SOC hoạt động 24/7 và là trung tâm điều phối mọi hoạt động an ninh. NIST không định nghĩa SOC như một thực thể cố định mà mô tả "
         "các năng lực của nó trong khung xử lý sự cố (NIST SP 800-61) và khung an ninh mạng (NIST CSF 2.0 với sáu chức năng Govern - Identify - Protect - Detect - Respond - Recover).")
    para("Nói ngắn gọn: nếu hệ thống CNTT là cơ thể thì SOC là \"phòng cấp cứu kết hợp phòng theo dõi\" - luôn có người trực, có thiết bị đo (SIEM/EDR), "
         "có phác đồ (playbook) và có hồ sơ bệnh án (tri thức tích lũy). SOC khác với **đội an ninh thông tin nói chung** ở tính chất *vận hành liên tục* "
         "và *hướng sự kiện*: SOC không thiết kế chính sách hay đánh giá rủi ro dài hạn, mà xử lý những gì đang xảy ra trên hệ thống ngay lúc này.")
    figure("01_soc_components.png", "Ba trụ cột của SOC: con người, quy trình, công nghệ", P, 5.6)
    h3("1.1.2. Lịch sử hình thành")
    table(["Giai đoạn", "Đặc điểm", "Công nghệ tiêu biểu"], [
        ["Thập niên 1990", "NOC (Network Operations Center) kiêm giám sát an ninh; IDS đầu tiên (Snort 1998); log xem thủ công", "Firewall, IDS, syslog"],
        ["2000-2010", "SOC tách khỏi NOC; SIEM thế hệ 1 (ArcSight, Q1 Labs) để tập trung log và đáp ứng tuân thủ (SOX 2002, PCI DSS 2004)", "SIEM, log management"],
        ["2010-2018", "Tấn công APT (Stuxnet 2010, Target 2013) thúc đẩy threat hunting, threat intelligence, EDR; MITRE ATT&CK công bố 2015", "EDR, TIP, big data SIEM"],
        ["2018-2023", "SOC cloud-native, SOAR tự động hóa, XDR hợp nhất, làm việc từ xa làm bề mặt tấn công mở rộng", "SOAR, XDR, cloud SIEM"],
        ["2024-nay", "LLM và tác tử AI tham gia triage/điều tra; \"AI SOC\", \"Agentic SOC\"; nền tảng mã nguồn mở như ASP", "LLM, agent, MCP"],
    ], widths=[1.2, 3.6, 1.7], size=10, caption="Các giai đoạn phát triển của SOC", part=P)
    h3("1.1.3. Các chức năng chính của SOC")
    table(["Chức năng", "Nội dung", "Thể hiện trong hệ thống của đề tài"], [
        ["Quản lý tài sản & khả năng quan sát", "Biết mình có gì (máy chủ, dịch vụ, tài khoản) và nhìn thấy chúng qua log/telemetry", "Trang Máy trạm (agents), heartbeat CPU/RAM/đĩa, trạng thái online/offline sau 180 s"],
        ["Thu thập và lưu trữ log tập trung", "Gom log từ mọi nguồn về một nơi, chuẩn hóa, lưu đủ lâu để điều tra", "SOC Agent → REST API → bảng log_events, lưu 30 ngày (RETENTION_DAYS)"],
        ["Giám sát và phát hiện", "Luật tương quan, ngưỡng, chữ ký, hành vi bất thường, threat intelligence", "RuleEngine 3 loại luật, 21 luật mặc định gắn MITRE ATT&CK, bảng uy tín IP"],
        ["Phân loại (triage) và ưu tiên", "Loại dương tính giả, xếp hạng theo mức độ và tác động", "Enrichment + Triage Agent: điểm rủi ro 0-100, ưu tiên P1-P5"],
        ["Điều tra và phản ứng sự cố", "Dựng lại chuỗi tấn công, xác định phạm vi, cô lập, khắc phục", "Investigation Agent: dòng thời gian, chuỗi ATT&CK, IOC, khuyến nghị"],
        ["Săn mối đe dọa (threat hunting)", "Chủ động tìm dấu hiệu xâm nhập chưa có luật", "Tìm kiếm log đa tiêu chí, xuất CSV, chạy lại luật mới trên dữ liệu lịch sử"],
        ["Quản lý tri thức và cải tiến", "Playbook, bài học sau sự cố, cập nhật luật", "Knowledge Agent + cơ sở tri thức; chỉnh luật và replay"],
        ["Tuân thủ và báo cáo", "Chứng minh với kiểm toán (ISO 27001, PCI DSS, Nghị định 85/2016)", "Trang Báo cáo & thống kê (MTTR, phân bố cảnh báo), xuất CSV, audit_logs"],
    ], widths=[1.6, 2.6, 2.3], size=10, caption="Chức năng của SOC và thành phần tương ứng trong hệ thống", part=P)

    h3("1.1.4. Tổ chức đội ngũ và mô hình phân tầng")
    para("SOC thường chia theo tầng (tier) để xử lý khối lượng cảnh báo lớn một cách hiệu quả. Tier 1 là tuyến đầu, tiếp nhận và phân loại; Tier 2 điều tra sâu; "
         "Tier 3 là chuyên gia săn mối đe dọa và ứng cứu; bên cạnh đó có kỹ sư SOC (vận hành công cụ), quản lý SOC và bộ phận threat intelligence. "
         "Điểm đáng chú ý của xu hướng **Agentic SOC** là các tác tử AI đảm nhận phần lớn công việc lặp lại của Tier 1 và hỗ trợ Tier 2, còn con người giữ vai trò ra quyết định.")
    figure("02_soc_tiers_ai.png", "Mô hình phân tầng SOC và vị trí của bốn tác tử AI trong hệ thống", P, 6.3)
    table(["Vai trò", "Trách nhiệm chính", "Kỹ năng điển hình", "Tỷ lệ thời gian (ước lượng)"], [
        ["Analyst Tier 1", "Giám sát bảng điều khiển, phân loại cảnh báo, đóng dương tính giả, leo thang", "Đọc log, hiểu luật, playbook cơ bản", "60-70% thời gian cho triage"],
        ["Analyst Tier 2", "Điều tra sự cố, tương quan nhiều nguồn, xác định phạm vi và tác động", "Forensics cơ bản, MITRE ATT&CK, scripting", "Điều tra 1-4 giờ/sự cố"],
        ["Analyst Tier 3 / Threat Hunter", "Săn mối đe dọa chưa có luật, phân tích mã độc, cải tiến phát hiện", "Reverse engineering, hunting hypothesis, detection engineering", "Dự án theo tuần"],
        ["Incident Responder", "Điều phối phản ứng, cô lập, khôi phục, giao tiếp với các bên", "Quy trình IR, quản lý khủng hoảng", "Theo sự cố"],
        ["SOC Engineer / Detection Engineer", "Vận hành SIEM/EDR/SOAR, tích hợp nguồn log, viết parser và luật", "Hệ thống, mạng, lập trình", "Liên tục"],
        ["Threat Intelligence Analyst", "Thu thập, đánh giá IOC/TTP, phổ biến tình báo", "OSINT, STIX/TAXII, phân tích", "Liên tục"],
        ["SOC Manager", "Nhân sự, KPI, báo cáo lãnh đạo, ngân sách", "Quản lý, tuân thủ", "-"],
    ], widths=[1.4, 2.4, 1.6, 1.1], size=9.5, caption="Các vai trò trong SOC", part=P)
    h4("Các mô hình vận hành SOC")
    table(["Mô hình", "Mô tả", "Ưu điểm", "Nhược điểm"], [
        ["Nội bộ (in-house)", "Tổ chức tự xây dựng và vận hành", "Kiểm soát dữ liệu, hiểu ngữ cảnh kinh doanh", "Chi phí cao, khó tuyển đủ nhân sự 24/7"],
        ["Thuê ngoài (MSSP / MDR)", "Nhà cung cấp dịch vụ giám sát", "Nhanh, chi phí dự đoán được, có chuyên gia", "Ít hiểu ngữ cảnh, dữ liệu ra ngoài"],
        ["Lai (hybrid / co-managed)", "Tier 1 thuê ngoài, Tier 2-3 nội bộ hoặc ngược lại", "Cân bằng", "Phối hợp phức tạp"],
        ["Ảo (virtual SOC)", "Đội phân tán, làm việc từ xa trên nền tảng cloud", "Linh hoạt", "Cần công cụ cộng tác tốt"],
        ["SOC hỗ trợ bởi AI (Agentic SOC)", "Tác tử AI làm Tier 1 và trợ lý Tier 2, người duyệt", "Giảm alert fatigue, 24/7 không mệt", "Rủi ro ảo giác, cần kiểm soát; chi phí token"],
    ], widths=[1.5, 2.2, 1.5, 1.4], size=9.5, caption="Các mô hình vận hành SOC", part=P)

    h3("1.1.5. Quy trình xử lý sự cố (NIST SP 800-61)")
    para("Khung NIST SP 800-61 (Computer Security Incident Handling Guide; bản Rev. 3 năm 2025 được tổ chức lại theo NIST CSF 2.0) mô tả vòng đời bốn pha: "
         "**Chuẩn bị** → **Phát hiện và phân tích** → **Ngăn chặn, loại bỏ và khôi phục** → **Hoạt động sau sự cố**. Vòng đời này lặp lại: bài học rút ra từ sự cố "
         "quay về cải thiện khâu chuẩn bị (luật, playbook, huấn luyện).")
    figure("03_nist_lifecycle.png", "Vòng đời xử lý sự cố NIST SP 800-61 và ánh xạ vào hệ thống", P, 6.3)
    table(["Pha", "Hoạt động tiêu biểu", "Công cụ/thành phần trong hệ thống"], [
        ["Chuẩn bị", "Chính sách, danh mục tài sản, công cụ giám sát, huấn luyện, playbook, kênh liên lạc", "Cài agent, bật audit policy, 21 luật mặc định, 3 playbook mẫu, tài khoản/vai trò"],
        ["Phát hiện và phân tích", "Thu thập dấu hiệu, xác nhận sự cố, xác định phạm vi, ưu tiên, ghi nhận", "Rule Engine, Enrichment, Triage Agent, trang Cảnh báo, Investigation Agent"],
        ["Ngăn chặn, loại bỏ, khôi phục", "Cô lập, chặn IP, khóa tài khoản, xóa mã độc, khôi phục từ sao lưu, xác minh", "Khuyến nghị (recommended_actions, recommendations) để analyst thực hiện; cập nhật trạng thái, ghi chú"],
        ["Hoạt động sau sự cố", "Họp rút kinh nghiệm, báo cáo, cập nhật luật/playbook, đo lường", "Knowledge Agent, cơ sở tri thức, báo cáo MTTR, chạy lại luật, audit_logs"],
    ], widths=[1.4, 2.6, 2.5], size=10, caption="Bốn pha NIST SP 800-61 và hiện thực trong hệ thống", part=P)
    h4("Phân loại sự cố và mức độ ưu tiên")
    para("NIST khuyến nghị phân loại sự cố theo **vectơ tấn công** (external/removable media, attrition - tức brute force/DoS, web, email, impersonation, improper usage, loss/theft, other) "
         "và xếp ưu tiên theo **tác động chức năng**, **tác động thông tin** và **khả năng khôi phục**. Hệ thống đề tài ánh xạ ý tưởng này thành ba trục: mức của luật (severity), "
         "verdict của AI (true_positive ... false_positive) và ưu tiên P1-P5, cùng bộ nhãn MITRE ATT&CK để nói chung ngôn ngữ với cộng đồng.")

    h3("1.1.6. Các khung tham chiếu kẻ tấn công: Kill Chain, ATT&CK, Pyramid of Pain")
    para("Để phát hiện có hệ thống, SOC cần mô hình hóa cách kẻ tấn công hành động. Ba khung phổ biến bổ sung cho nhau:")
    bullets([
        "**Cyber Kill Chain** (Lockheed Martin, 2011): bảy bước tuyến tính từ trinh sát tới hành động trên mục tiêu; giúp hình dung một cuộc xâm nhập là một chuỗi và cắt đứt ở bất kỳ mắt xích nào đều ngăn được thiệt hại.",
        "**MITRE ATT&CK** (2015-nay): ma trận 14 tactic (mục tiêu chiến thuật) × hơn 200 technique (kỹ thuật) được quan sát thực tế; mỗi luật phát hiện trong hệ thống gắn một technique để đo độ phủ và trao đổi với cộng đồng (Sigma, Elastic rules, Wazuh rules đều dùng nhãn này).",
        "**Pyramid of Pain** (David Bianco, 2013): phân cấp chỉ dấu theo mức \"đau\" gây ra cho kẻ tấn công khi bị phát hiện - hash và IP dễ đổi, còn TTP (hành vi) khó đổi nhất. Phát hiện theo hành vi (dò mật khẩu, tạo tài khoản, xóa log) có giá trị bền hơn danh sách IP đen.",
    ])
    figure("21_kill_chain.png", "Cyber Kill Chain và các tactic ATT&CK tương ứng", P, 6.5)
    table(["#", "Tactic ATT&CK", "Mục tiêu của kẻ tấn công", "Ví dụ technique", "Luật của hệ thống"], [
        ["1", "Reconnaissance", "Thu thập thông tin về mục tiêu", "T1595 Active Scanning", "R19"],
        ["2", "Resource Development", "Chuẩn bị hạ tầng, tài khoản, mã độc", "T1583 Acquire Infrastructure", "-"],
        ["3", "Initial Access", "Đặt chân vào mạng", "T1190 Exploit Public-Facing App, T1078 Valid Accounts", "R10, R11, R21"],
        ["4", "Execution", "Chạy mã độc", "T1059.001 PowerShell, T1053 Scheduled Task", "R06, R14"],
        ["5", "Persistence", "Duy trì truy cập qua khởi động lại", "T1136 Create Account, T1543.003 Windows Service", "R03, R04, R05, R06, R08"],
        ["6", "Privilege Escalation", "Lấy quyền cao hơn", "T1098 Account Manipulation, T1548.003 Sudo", "R04, R09"],
        ["7", "Defense Evasion", "Tránh bị phát hiện", "T1070.001 Clear Windows Event Logs, T1562.002", "R01, R02, R07"],
        ["8", "Credential Access", "Đánh cắp thông tin xác thực", "T1110 Brute Force (.001 guessing, .003 spraying)", "R13, R15, R16, R17, R18, R20"],
        ["9", "Discovery", "Tìm hiểu môi trường", "T1087 Account Discovery, T1018 Remote System Discovery", "-"],
        ["10", "Lateral Movement", "Di chuyển sang máy khác", "T1021.001 RDP, T1021.004 SSH", "R21"],
        ["11", "Collection", "Gom dữ liệu", "T1005 Data from Local System", "-"],
        ["12", "Command and Control", "Liên lạc với máy chủ điều khiển", "T1071 Application Layer Protocol", "-"],
        ["13", "Exfiltration", "Đưa dữ liệu ra ngoài", "T1041 Exfiltration Over C2 Channel", "-"],
        ["14", "Impact", "Phá hoại, tống tiền", "T1486 Data Encrypted for Impact, T1499 DoS", "(R12 gián tiếp)"],
    ], widths=[0.3, 1.5, 1.8, 2.0, 0.9], size=9, caption="14 tactic của MITRE ATT&CK Enterprise và độ phủ của 21 luật mặc định", part=P)
    figure("22_attack_coverage.png", "Độ phủ 14 tactic ATT&CK của bộ luật mặc định", P, 6.0)
    figure("23_pyramid_of_pain.png", "Pyramid of Pain và vị trí của các cơ chế phát hiện trong hệ thống", P, 5.6)

    h3("1.1.7. Các chỉ số đo hiệu quả SOC")
    table(["Chỉ số", "Ý nghĩa", "Cách hệ thống hỗ trợ"], [
        ["MTTD (Mean Time To Detect)", "Thời gian trung bình từ lúc sự kiện xảy ra đến khi phát hiện", "Luật chạy ngay khi lô log được tiếp nhận (độ trễ ≈ chu kỳ agent 10 s)"],
        ["MTTA (Mean Time To Acknowledge)", "Thời gian đến khi analyst nhận xử lý", "AI tự triage trong vài giây, xếp P1 lên đầu danh sách"],
        ["MTTR (Mean Time To Respond/Resolve)", "Thời gian đến khi xử lý xong", "Trang Báo cáo tính MTTR = trung bình (resolved_at − created_at)"],
        ["Dwell time", "Thời gian kẻ tấn công tồn tại trong hệ thống trước khi bị phát hiện (trung bình toàn cầu ~10 ngày theo Mandiant M-Trends 2024)", "Giảm bằng luật sequence (thành công sau thất bại) và bảo toàn log khi bị xóa"],
        ["Tỷ lệ dương tính giả", "Cảnh báo sai / tổng cảnh báo", "Verdict false_positive của AI + ghi chú của analyst, chạy lại luật sau khi tinh chỉnh"],
        ["Độ phủ (coverage)", "Số kỹ thuật ATT&CK có luật phát hiện", "21 luật gắn 17 kỹ thuật ATT&CK trên 8 tactic"],
        ["Số cảnh báo / analyst / ngày", "Khối lượng công việc", "Dedup theo dedup_key giảm số cảnh báo; AI hạ ưu tiên nhiễu"],
        ["Tỷ lệ cảnh báo được AI phân loại", "Mức độ tự động hóa", "KPI \"Cảnh báo AI đã phân loại\" trên dashboard"],
    ], widths=[1.9, 2.4, 2.2], size=10, caption="Chỉ số đo hiệu quả SOC", part=P)

    h3("1.1.8. Mức trưởng thành của SOC")
    para("SOC-CMM (Security Operations Center Capability & Maturity Model, Rob van Os) đánh giá SOC theo năm lĩnh vực (Business, People, Process, Technology, Services) "
         "trên thang trưởng thành 5 mức tương tự CMMI. Hệ thống của đề tài không làm cho một tổ chức \"trưởng thành\" hơn, nhưng cung cấp những công cụ cần có ở mức 3 "
         "(quy trình chuẩn, playbook, KPI) và mở đường cho mức 4-5 (đo lường, tự động hóa, AI).")
    figure("24_soc_maturity.png", "Các mức trưởng thành SOC và vị trí của hệ thống", P, 6.3)

    h3("1.1.9. Thách thức cốt lõi: \"mệt mỏi vì cảnh báo\" (alert fatigue)")
    para("Một SOC cỡ vừa có thể nhận hàng nghìn tới hàng chục nghìn cảnh báo mỗi ngày, trong đó phần lớn là nhiễu hoặc dương tính giả. Hệ quả là analyst bỏ sót cảnh "
         "báo thật, thời gian phản ứng kéo dài, nhân sự kiệt sức và nghỉ việc. Báo cáo IBM Cost of a Data Breach 2024 ghi nhận chi phí trung bình một vụ rò rỉ là 4,88 triệu USD và "
         "thời gian trung bình để nhận diện và khống chế là 258 ngày; các khảo sát SANS SOC Survey nhiều năm liền xếp alert fatigue và thiếu nhân lực là hai vấn đề hàng đầu. "
         "Nguyên nhân sâu xa gồm: luật tĩnh không có ngữ cảnh, nhiều công cụ rời rạc, thiếu tri thức tích lũy, và khối lượng dữ liệu tăng nhanh hơn số người.")
    para("Đây chính là động lực để chuyển từ \"xử lý từng cảnh báo\" sang \"**AI hỗ trợ ra quyết định**\": tác tử làm giàu dữ liệu, chấm điểm, điều tra sơ bộ; "
         "con người chỉ xem xét số ít trường hợp đã được tổng hợp. Trong thực nghiệm của đề tài, 380 sự kiện được rút về 19 cảnh báo, trong đó AI xếp 9 cảnh báo P1 cần xem ngay "
         "và hạ phần còn lại xuống P2-P3; analyst không cần đọc từng dòng log.")
    h4("Khung pháp lý và tuân thủ liên quan tới SOC/SIEM tại Việt Nam")
    bullets([
        "**Luật An toàn thông tin mạng 2015** (86/2015/QH13) và **Luật An ninh mạng 2018** (24/2018/QH14): nghĩa vụ giám sát, phát hiện, ứng cứu sự cố và lưu trữ nhật ký hệ thống.",
        "**Nghị định 85/2016/NĐ-CP** về bảo đảm an toàn hệ thống thông tin theo cấp độ và **Thông tư 12/2022/TT-BTTTT** hướng dẫn: yêu cầu ghi nhật ký, giám sát, quản lý sự cố theo từng cấp độ 1-5; **TCVN 11930:2017** quy định yêu cầu kỹ thuật cơ bản (nhật ký hệ thống, giám sát, phòng chống xâm nhập).",
        "**Nghị định 13/2023/NĐ-CP** về bảo vệ dữ liệu cá nhân: log chứa dữ liệu cá nhân (tên tài khoản, IP) phải được bảo vệ và lưu có thời hạn.",
        "**Quốc tế:** ISO/IEC 27001:2022 (kiểm soát A.8.15 Logging, A.8.16 Monitoring activities, A.5.24-A.5.28 quản lý sự cố), PCI DSS v4.0 (Requirement 10: ghi và giám sát mọi truy cập), NIST SP 800-92 (quản lý log).",
    ])

    # ------------------------------------------------------------------ 1.2
    h2("1.2. Quản lý thông tin và sự kiện an ninh (SIEM)")
    h3("1.2.1. Định nghĩa và lịch sử")
    para("**SIEM (Security Information and Event Management)** là giải pháp phần mềm thu thập, chuẩn hóa, lưu trữ và phân tích dữ liệu log/sự kiện từ toàn bộ hạ tầng để "
         "phát hiện mối đe dọa, hỗ trợ điều tra và đáp ứng tuân thủ. Thuật ngữ được Gartner đưa ra năm 2005 (Mark Nicolett và Amrit Williams), hợp nhất hai dòng sản phẩm trước đó: "
         "**SIM** (Security Information Management - lưu trữ, báo cáo, phân tích dài hạn) và **SEM** (Security Event Management - giám sát và tương quan thời gian thực). "
         "Nếu SOC là \"con người và quy trình\" thì SIEM là \"bộ não công nghệ\" trung tâm của SOC.")
    h3("1.2.2. Các chức năng của SIEM")
    figure("04_siem_pipeline.png", "Năm bước xử lý của SIEM và các nguồn log đầu vào", P, 6.5)
    numbered([
        "**Thu thập (collection):** qua agent cài trên máy (Beats, Wazuh agent, SOC Agent), giao thức đẩy (syslog UDP/TCP 514, Windows Event Forwarding), hoặc API/webhook của dịch vụ cloud (Microsoft 365, AWS CloudTrail).",
        "**Phân tích cú pháp và chuẩn hóa (parsing & normalization):** biến các định dạng khác nhau (XML của Windows, dòng văn bản syslog, JSON của ứng dụng) về một lược đồ chung như ECS (Elastic), OCSF (AWS/Splunk/IBM), CIM (Splunk) để có thể truy vấn và tương quan thống nhất.",
        "**Lưu trữ và chỉ mục (storage & indexing):** cơ sở dữ liệu tìm kiếm (Elasticsearch/OpenSearch), kho dữ liệu cột (ClickHouse), hoặc SQL; chính sách lưu trữ nóng/ấm/lạnh theo thời gian; nén và lưu trữ dài hạn cho tuân thủ (thường 90 ngày trực tuyến, 1 năm lưu trữ).",
        "**Tương quan và phát hiện (correlation & detection):** luật đơn sự kiện, luật ngưỡng theo cửa sổ thời gian, luật chuỗi, danh sách đen IP/hash, phân tích hành vi (UEBA), học máy.",
        "**Cảnh báo, làm giàu và ưu tiên (alerting & enrichment):** gộp trùng, bổ sung ngữ cảnh (tài sản, danh tính, threat intel, GeoIP), xếp hạng rủi ro.",
        "**Trình bày và điều tra (dashboard, search, case management):** bảng điều khiển thời gian thực, tìm kiếm toàn văn, dòng thời gian, quản lý vụ việc.",
        "**Báo cáo và tuân thủ (reporting & compliance):** báo cáo định kỳ, bằng chứng kiểm toán, lưu trữ dài hạn.",
        "**Tự động hóa phản ứng (SOAR):** playbook chặn IP, khóa tài khoản, tạo ticket - thường là module tích hợp hoặc sản phẩm riêng.",
    ])
    h3("1.2.3. Kiến trúc tham chiếu của một SIEM")
    table(["Lớp", "Thành phần", "Vấn đề thiết kế", "Trong Web SOC"], [
        ["Nguồn", "Máy chủ, thiết bị mạng, ứng dụng, cloud", "Bật đủ audit; tránh nhiễu", "Windows Event Log, syslog, journald, access log"],
        ["Thu thập", "Agent, collector, forwarder, syslog relay", "Con trỏ, hàng đợi, mã hóa, chữ ký", "SOC Agent (push JSON, API key)"],
        ["Tiếp nhận", "Message queue (Kafka, Redis Stream), load balancer", "Chịu tải đột biến, backpressure", "Flask endpoint + hàng đợi trên agent"],
        ["Xử lý", "Parser, normalizer, enricher", "Lược đồ chung, hiệu năng regex", "parsers.py, enrichment.py"],
        ["Lưu trữ", "Index engine, time-series, object storage", "Chi phí, thời gian lưu, tìm kiếm nhanh", "SQLite WAL có chỉ mục; xóa sau 30 ngày"],
        ["Phân tích", "Rule engine, correlation, ML, TI", "Dương tính giả, cửa sổ thời gian", "RuleEngine match/threshold/sequence"],
        ["Trình bày", "Dashboard, search UI, case, báo cáo", "Thời gian thực, phân quyền", "Flask + Bootstrap + Chart.js, 3 vai trò"],
        ["Phản ứng", "SOAR, ticketing, tích hợp firewall/AD", "An toàn khi tự động", "Khuyến nghị của AI, con người thực hiện"],
    ], widths=[0.9, 1.8, 1.8, 2.0], size=9.5, caption="Kiến trúc tham chiếu SIEM", part=P)
    h3("1.2.4. Các cơ chế phát hiện trong SIEM")
    table(["Cơ chế", "Nguyên lý", "Ưu điểm", "Hạn chế", "Trong hệ thống"], [
        ["Chữ ký / khớp mẫu", "Một sự kiện khớp điều kiện (EventID 1102, chuỗi \"sqlmap\")", "Chính xác, nhanh", "Chỉ bắt được cái đã biết", "Luật match (R01-R14, R21)"],
        ["Ngưỡng theo cửa sổ", "Đếm sự kiện cùng nhóm trong W giây", "Bắt brute force, quét", "Cần chỉnh ngưỡng theo môi trường", "Luật threshold (R15-R17, R19, R20)"],
        ["Chuỗi sự kiện", "B xảy ra sau ≥ N lần A", "Giảm dương tính giả, bắt giai đoạn thành công", "Phức tạp hơn", "Luật sequence (R18)"],
        ["Danh sách đen / threat intel", "IP, domain, hash trong feed", "Tận dụng tri thức cộng đồng", "Dễ cũ, tầng thấp Pyramid of Pain", "ip_reputation, enrichment"],
        ["Thống kê / baseline", "Lệch khỏi mức bình thường (số đăng nhập/giờ)", "Bắt bất thường chưa có chữ ký", "Nhiễu khi baseline chưa ổn", "Ngữ cảnh \"tài khoản mới\", \"ngoài giờ\" trong Triage"],
        ["UEBA / học máy", "Mô hình hành vi người dùng, thực thể", "Phát hiện nội gián, tài khoản bị chiếm", "Cần nhiều dữ liệu, khó giải thích", "Chưa có (hướng phát triển)"],
        ["LLM / tác tử", "Suy luận trên ngữ cảnh tổng hợp", "Giải thích được, linh hoạt", "Chi phí, ảo giác", "Triage/Investigation Agent"],
    ], widths=[1.1, 1.6, 1.2, 1.3, 1.3], size=9, caption="Các cơ chế phát hiện", part=P)
    h3("1.2.5. Các thế hệ SIEM")
    table(["Thế hệ", "Thời kỳ", "Đặc điểm", "Sản phẩm tiêu biểu"], [
        ["SIEM 1.0", "2005-2012", "Tập trung log, luật tĩnh, triển khai tại chỗ, nặng về tuân thủ (PCI DSS, SOX)", "ArcSight, QRadar, RSA enVision"],
        ["SIEM 2.0", "2012-2018", "Big data (Hadoop/Elasticsearch), tìm kiếm nhanh, UEBA, threat intelligence, bắt đầu có cloud", "Splunk ES, ELK, LogRhythm"],
        ["SIEM 3.0 / Next-gen", "2018-2023", "Cloud-native (Microsoft Sentinel, Chronicle), tích hợp SOAR, XDR, học máy, MITRE ATT&CK", "Sentinel, Chronicle, Elastic Security, Wazuh"],
        ["Agentic SOC / AI SOC", "2024-nay", "Tác tử LLM tham gia triage, điều tra, viết luật; con người giám sát; \"SOC copilot\"", "Agentic SOC Platform, Microsoft Security Copilot, Elastic AI Assistant"],
    ], widths=[1.3, 1.0, 3.0, 1.2], size=10, caption="Các thế hệ SIEM", part=P)
    h3("1.2.6. SIEM và các công nghệ liên quan")
    table(["Thuật ngữ", "Vai trò", "Khác biệt với SIEM"], [
        ["Log management", "Thu thập và lưu trữ log", "Không có tương quan/phát hiện; SIEM = log management + phân tích an ninh"],
        ["EDR (Endpoint Detection & Response)", "Giám sát chi tiết tiến trình, tệp, bộ nhớ trên máy trạm; cô lập máy", "Chuyên sâu điểm cuối, có phản ứng; SIEM bao quát mọi nguồn"],
        ["XDR", "Mở rộng EDR sang mạng, email, cloud, hợp nhất phát hiện", "Thường do một nhà cung cấp, dữ liệu đã chuẩn hóa sẵn"],
        ["SOAR", "Tự động hóa phản ứng theo playbook, quản lý vụ việc", "SIEM phát hiện, SOAR hành động; ngày càng hợp nhất"],
        ["UEBA", "Mô hình hành vi người dùng/thực thể, phát hiện bất thường", "Thường là module của SIEM"],
        ["Threat Intelligence Platform", "Quản lý IOC, nguồn tình báo (STIX/TAXII, MISP)", "Cung cấp dữ liệu làm giàu cho SIEM"],
        ["NDR", "Phân tích lưu lượng mạng (Zeek, Suricata)", "Nguồn dữ liệu cho SIEM"],
        ["HIDS / FIM", "Giám sát toàn vẹn tệp, rootkit trên máy chủ (OSSEC, Wazuh)", "Nguồn dữ liệu, một phần của XDR"],
    ], widths=[1.9, 2.5, 2.1], size=10, caption="SIEM và các công nghệ liên quan", part=P)
    h3("1.2.7. Lựa chọn và triển khai SIEM trong thực tế")
    bullets([
        "**Xác định phạm vi nguồn log:** ưu tiên log xác thực, máy chủ quan trọng, thiết bị biên; ước lượng EPS (events per second) và GB/ngày để tính lưu trữ và chi phí cấp phép.",
        "**Chuẩn hóa sớm:** chọn lược đồ (ECS/OCSF) ngay từ đầu; mỗi nguồn mới phải có parser và kiểm thử.",
        "**Bắt đầu với bộ luật nhỏ, chất lượng cao:** 20-30 luật phủ các kỹ thuật phổ biến (brute force, tạo tài khoản, xóa log, PowerShell) rồi mở rộng theo ATT&CK gap.",
        "**Đo và tinh chỉnh:** theo dõi tỷ lệ dương tính giả từng luật, thêm điều kiện loại trừ; chạy lại luật trên dữ liệu lịch sử trước khi bật.",
        "**Bảo vệ chính SIEM:** phân quyền, HTTPS, khóa API, chống CSRF, lưu log kiểm toán thao tác của analyst (hệ thống đề tài có đủ các lớp này, xem Phần 6).",
    ])
    h3("1.2.8. Hạn chế của SIEM truyền thống và nhu cầu Agentic AI")
    bullets([
        "**Chi phí và độ phức tạp:** cấp phép theo dung lượng (GB/ngày), hạ tầng lớn, cần đội ngũ viết parser và luật.",
        "**Nhiễu cảnh báo:** luật tĩnh sinh nhiều dương tính giả; mỗi cảnh báo thiếu ngữ cảnh, analyst phải tự tra cứu nhiều nguồn.",
        "**Điều tra thủ công:** dựng dòng thời gian, tra IOC, tìm sự kiện liên quan tốn hàng giờ.",
        "**Tri thức rời rạc:** kinh nghiệm xử lý nằm trong đầu analyst hoặc ticket, không được tái sử dụng có hệ thống.",
        "**Hướng giải quyết:** tác tử AI chủ động làm giàu, phân loại, điều tra và rút bài học - chính là bốn tác tử Enrichment, Triage, Investigation, Knowledge của đề tài; Phần 3 trình bày nền tảng Agentic AI và dự án tham khảo.",
    ])
    h3("1.2.9. Liên kết tham khảo cho Phần 1")
    link_line("Microsoft - What is a security operations center (SOC)?", "https://www.microsoft.com/en-us/security/business/security-101/what-is-a-security-operations-center-soc")
    link_line("IBM - What is SIEM?", "https://www.ibm.com/think/topics/siem")
    link_line("IBM - What is a Security Operations Center (SOC)?", "https://www.ibm.com/think/topics/security-operations-center")
    link_line("IBM - Cost of a Data Breach Report", "https://www.ibm.com/reports/data-breach")
    link_line("NIST SP 800-61 Rev. 3", "https://csrc.nist.gov/pubs/sp/800/61/r3/final")
    link_line("NIST SP 800-92 - Guide to Computer Security Log Management", "https://csrc.nist.gov/pubs/sp/800/92/final")
    link_line("NIST Cybersecurity Framework 2.0", "https://www.nist.gov/cyberframework")
    link_line("MITRE ATT&CK Enterprise", "https://attack.mitre.org/matrices/enterprise/")
    link_line("Lockheed Martin - Cyber Kill Chain", "https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html")
    link_line("David Bianco - The Pyramid of Pain", "https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html")
    link_line("SOC-CMM", "https://www.soc-cmm.com/")
    link_line("SANS - SOC Survey", "https://www.sans.org/white-papers/")
    link_line("Cổng thông tin pháp luật - Nghị định 85/2016/NĐ-CP", "https://vanban.chinhphu.vn/")
    page_break()
