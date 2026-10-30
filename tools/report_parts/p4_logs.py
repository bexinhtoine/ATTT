# -*- coding: utf-8 -*-
"""PHẦN 4. CẤU TRÚC TỆP LOG TRÊN HỆ ĐIỀU HÀNH (Lab 17) - mở rộng."""
from report_lib import *  # noqa: F401,F403

P = "4"


def build():
    h1("PHẦN 4. CẤU TRÚC TỆP LOG TRÊN HỆ ĐIỀU HÀNH (LAB 17 - PHÂN TÍCH LOG SERVER)")
    # ------------------------------------------------------------------ 4.1
    h2("4.1. Tổng quan về log")
    para("**Log (nhật ký)** là bản ghi theo thời gian về các sự kiện xảy ra trong hệ điều hành, dịch vụ hoặc ứng dụng. Với an ninh, log là **nguồn bằng chứng chính** để "
         "phát hiện xâm nhập, dựng lại diễn biến sự cố và chứng minh tuân thủ. Mọi bản ghi log, dù định dạng nào, đều có bốn thành phần: **thời điểm**, **nguồn phát sinh** "
         "(máy, tiến trình), **mức độ** và **nội dung**; log an ninh còn có **chủ thể** (tài khoản), **đối tượng** (tệp, dịch vụ), **kết quả** (thành công/thất bại) và **nguồn mạng** (IP, cổng). "
         "NIST SP 800-92 gọi quá trình tạo, truyền, lưu, phân tích và hủy log là *log management* và khuyến nghị tập trung hóa, đồng bộ thời gian (NTP), bảo vệ toàn vẹn và quy định thời hạn lưu.")
    table(["Loại log", "Nguồn", "Ví dụ", "Giá trị an ninh"], [
        ["Hệ điều hành", "Kernel, dịch vụ hệ thống, xác thực", "Windows Security/System, syslog, journald", "Đăng nhập, tài khoản, dịch vụ, đặc quyền"],
        ["Ứng dụng", "Web server, CSDL, mail", "access.log, error.log, mysql general log, maillog", "Tấn công ứng dụng, truy vấn lạ"],
        ["Mạng / bảo mật", "Firewall, IDS/IPS, proxy, VPN, DNS", "iptables LOG, Suricata eve.json, pfSense", "Kết nối, quét, C2"],
        ["Danh tính / cloud", "Active Directory, IdP, cloud", "DC Security log, Entra ID sign-in, CloudTrail", "Chiếm tài khoản, lạm dụng quyền"],
        ["Điểm cuối (EDR/Sysmon)", "Giám sát tiến trình", "Sysmon, osquery", "Thực thi mã độc, persistence"],
    ], widths=[1.3, 1.6, 2.0, 1.6], size=9.5, caption="Phân loại nguồn log", part=P)
    table(["Vấn đề chung", "Giải thích", "Cách xử lý trong hệ thống"], [
        ["Múi giờ và định dạng thời gian", "Windows ghi UTC ISO-8601; syslog BSD ghi giờ địa phương, không có năm; access log có offset +0700", "Mọi timestamp được đưa về UTC ISO-8601 (`to_iso`, `parse_bsd_timestamp`); giao diện hiển thị theo Asia/Ho_Chi_Minh"],
        ["Đồng bộ thời gian", "Lệch đồng hồ giữa các máy làm sai thứ tự sự kiện khi tương quan", "Yêu cầu NTP trên máy trạm; server ghi thêm received_at để đối chiếu"],
        ["Xoay vòng (rotation)", "logrotate/Windows tự cắt tệp khi đầy: auth.log → auth.log.1 → .gz; Event Log ghi đè khi đạt kích thước tối đa", "FileCollector phát hiện size < offset hoặc inode đổi → đọc lại từ đầu; Windows dùng EventRecordID tăng dần"],
        ["Khối lượng", "Một máy chủ bận có thể sinh hàng chục nghìn dòng/giờ (4688, 5156, access log)", "Chỉ thu EventID chọn lọc; lô ≤ 500; giữ lại 30 ngày; chỉ mục cột tìm kiếm"],
        ["Toàn vẹn và chống xóa dấu vết", "Kẻ tấn công xóa log cục bộ (EventID 1102) hoặc sửa auth.log", "Gửi về server ngay (10 s) nên bản sao tồn tại độc lập; luật R01/R02 báo ngay khi log bị xóa"],
        ["Quyền đọc", "Security log cần Administrator/SYSTEM; /var/log/auth.log thuộc root:adm", "Agent chạy bằng Scheduled Task (SYSTEM) hoặc systemd (root)"],
        ["Dữ liệu cá nhân", "Log chứa tên tài khoản, IP", "Phân quyền xem, lưu có thời hạn, HTTPS"],
    ], widths=[1.6, 2.5, 2.4], size=9.5, caption="Các vấn đề chung khi làm việc với log", part=P)

    # ------------------------------------------------------------------ 4.2 Windows
    h2("4.2. Windows Event Log")
    h3("4.2.1. Kiến trúc và cách truy cập")
    para("Windows ghi sự kiện qua dịch vụ **Windows Event Log** (nền tảng ETW - Event Tracing for Windows). Sự kiện được phân vào các **kênh (channel)**: ba kênh \"Windows Logs\" cổ điển là "
         "**Security**, **System**, **Application** (cùng Setup, Forwarded Events), và hàng trăm kênh \"Applications and Services Logs\" như Microsoft-Windows-PowerShell/Operational, "
         "Microsoft-Windows-Sysmon/Operational, Microsoft-Windows-TaskScheduler/Operational, Microsoft-Windows-TerminalServices-LocalSessionManager/Operational. "
         "Dữ liệu lưu dạng nhị phân **.evtx** trong `%SystemRoot%\\System32\\winevt\\Logs`, mỗi kênh có kích thước tối đa (Security mặc định 20 MB, nên tăng lên 1 GB trên máy chủ) và chính sách ghi đè.")
    table(["Công cụ", "Ví dụ", "Ghi chú"], [
        ["Event Viewer (eventvwr.msc)", "Lọc theo EventID, tạo Custom View, xuất .evtx/.xml/.csv", "Giao diện đồ họa; chậm với log lớn"],
        ["wevtutil", "`wevtutil qe Security /q:\"*[System[(EventID=4625)]]\" /f:RenderedXml /c:50 /rd:true`", "Dòng lệnh, xuất XML đầy đủ; SOC Agent dùng lệnh này với XPath `EventRecordID > N`"],
        ["PowerShell Get-WinEvent", "`Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-1)}`", "Lọc hiệu quả bằng FilterHashtable/FilterXPath; `.ToXml()` cho XML"],
        ["auditpol", "`auditpol /get /category:*`", "Xem/đặt chính sách kiểm toán quyết định sự kiện nào được ghi"],
        ["wevtutil sl / gl", "`wevtutil sl Security /ms:1073741824`", "Đặt kích thước tối đa của kênh"],
        ["Windows Event Forwarding (WEF)", "Thu thập tập trung bằng Subscription sang Collector (WinRM)", "Giải pháp có sẵn của Microsoft, không cần agent"],
    ], widths=[1.6, 3.0, 1.9], size=9.5, caption="Công cụ làm việc với Windows Event Log", part=P)
    h3("4.2.2. Chính sách kiểm toán (audit policy)")
    para("Windows chỉ ghi những sự kiện mà **chính sách kiểm toán** cho phép. Advanced Audit Policy Configuration có 10 nhóm (Account Logon, Account Management, Detailed Tracking, DS Access, "
         "Logon/Logoff, Object Access, Policy Change, Privilege Use, System, Global Object Access Auditing) với hơn 50 tiểu mục, mỗi tiểu mục bật riêng Success/Failure. "
         "Một máy chủ chưa bật *Audit Process Creation* sẽ không bao giờ có 4688; chưa bật *Audit Logon* thì không có 4624/4625. Đây là điều kiện tiên quyết thường bị bỏ qua khi triển khai SIEM.")
    figure("28_audit_policy.png", "Chính sách kiểm toán và EventID tương ứng", P, 6.5)
    code("# Bật các tiểu mục thiết yếu (chạy quyền Administrator)\nauditpol /set /subcategory:\"Logon\" /success:enable /failure:enable\nauditpol /set /subcategory:\"Account Lockout\" /failure:enable\nauditpol /set /subcategory:\"User Account Management\" /success:enable /failure:enable\nauditpol /set /subcategory:\"Security Group Management\" /success:enable\nauditpol /set /subcategory:\"Process Creation\" /success:enable\nauditpol /set /subcategory:\"Audit Policy Change\" /success:enable /failure:enable\nauditpol /set /subcategory:\"Security State Change\" /success:enable\n# Ghi dòng lệnh vào 4688 (GPO: Include command line in process creation events)\nreg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f\n# Bật PowerShell Script Block Logging (EventID 4104)\nreg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f")
    h3("4.2.3. Cấu trúc một bản ghi (XML)")
    figure("10_windows_eventlog_structure.png", "Cấu trúc XML của một sự kiện Windows (ví dụ 4625) và cách chuẩn hóa", P, 6.5)
    table(["Phần tử", "Ý nghĩa"], [
        ["System/Provider", "Nguồn phát sinh (Microsoft-Windows-Security-Auditing, Service Control Manager, Microsoft-Windows-Eventlog...)"],
        ["System/EventID", "Mã sự kiện - khóa chính để hiểu sự kiện; cùng EventID luôn có cùng cấu trúc EventData; thuộc tính Qualifiers với sự kiện cũ"],
        ["System/Version, Task, Opcode", "Phiên bản lược đồ EventData; Task = tiểu mục kiểm toán (12544 = Logon); Opcode = Info"],
        ["System/Level", "1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose, 0 LogAlways (kênh Security luôn 0)"],
        ["System/Keywords", "Bitmask; kênh Security: 0x8020000000000000 = Audit Success, 0x8010000000000000 = Audit Failure"],
        ["System/TimeCreated", "Thời điểm UTC chính xác tới 100 ns"],
        ["System/EventRecordID", "Số thứ tự tăng dần trong kênh - dùng làm con trỏ thu thập"],
        ["System/Correlation, Execution", "ActivityID để nối các sự kiện liên quan; ProcessID/ThreadID của tiến trình ghi"],
        ["System/Channel, Computer, Security", "Kênh, tên máy, SID người dùng ghi (thường trống với Security)"],
        ["EventData/Data Name=...", "Các trường đặc thù: TargetUserName, LogonType, IpAddress, ProcessName, ServiceName, ImagePath..."],
        ["UserData", "Một số sự kiện (1102 LogFileCleared, 104) dùng UserData thay EventData"],
        ["RenderingInfo/Message", "Thông điệp đã dịch sang ngôn ngữ hiển thị (chỉ có khi xuất RenderedXml)"],
    ], widths=[1.9, 4.6], size=10, caption="Các phần tử của bản ghi Windows Event", part=P)
    para("Ví dụ XML đầy đủ (rút gọn) của sự kiện 4624 đăng nhập RDP thành công:")
    code("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\n  <System>\n    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>\n    <EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>\n    <Keywords>0x8020000000000000</Keywords>\n    <TimeCreated SystemTime='2026-10-26T03:31:05.4471290Z'/>\n    <EventRecordID>88130</EventRecordID>\n    <Correlation ActivityID='{a1b2...}'/><Execution ProcessID='700' ThreadID='8120'/>\n    <Channel>Security</Channel><Computer>WIN-SRV02</Computer><Security/>\n  </System>\n  <EventData>\n    <Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data>\n    <Data Name='TargetUserSid'>S-1-5-21-...-500</Data>\n    <Data Name='TargetUserName'>Administrator</Data><Data Name='TargetDomainName'>WIN-SRV02</Data>\n    <Data Name='TargetLogonId'>0x3e7a2c1</Data>\n    <Data Name='LogonType'>10</Data>\n    <Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data>\n    <Data Name='WorkstationName'>WIN-SRV02</Data>\n    <Data Name='LogonGuid'>{...}</Data>\n    <Data Name='ProcessId'>0x1f4</Data><Data Name='ProcessName'>C:\\Windows\\System32\\svchost.exe</Data>\n    <Data Name='IpAddress'>198.51.100.23</Data><Data Name='IpPort'>51024</Data>\n    <Data Name='ElevatedToken'>%%1842</Data>\n  </EventData>\n</Event>", size=9)
    h3("4.2.4. Các EventID an ninh quan trọng")
    para("Bảng dưới tổng hợp các EventID được agent thu thập mặc định và ý nghĩa an ninh (theo Microsoft \"Appendix L: Events to Monitor\" và kinh nghiệm thực tế). Phụ lục B liệt kê toàn bộ ánh xạ của parser.")
    table(["EventID", "Kênh", "Ý nghĩa", "Dấu hiệu / kỹ thuật ATT&CK liên quan"], [
        ["4624", "Security", "Đăng nhập thành công (LogonType cho biết cách đăng nhập)", "Type 10 từ IP lạ: T1021.001 RDP; type 3 hàng loạt: lateral movement"],
        ["4625", "Security", "Đăng nhập thất bại (Status/SubStatus cho lý do)", "Lặp nhiều từ một IP: T1110 brute force; nhiều tài khoản: T1110.003 spraying"],
        ["4634 / 4647", "Security", "Đăng xuất", "Tính thời lượng phiên"],
        ["4648", "Security", "Đăng nhập bằng thông tin xác thực tường minh (runas)", "Pass-the-hash, lạm dụng tài khoản"],
        ["4672", "Security", "Gán đặc quyền đặc biệt cho phiên (SeDebugPrivilege...)", "Phiên quản trị"],
        ["4688 / 4689", "Security", "Tiến trình mới (có CommandLine nếu bật) / kết thúc", "T1059 thực thi; rất nhiều nhiễu"],
        ["4697 / 7045", "Security / System", "Cài đặt dịch vụ mới", "T1543.003 persistence (PsExec, mã độc)"],
        ["4698 / 4699 / 4702", "Security", "Tạo / xóa / sửa tác vụ định thời", "T1053.005 persistence"],
        ["4719", "Security", "Thay đổi chính sách kiểm toán", "T1562.002 làm mù giám sát"],
        ["4720 / 4722 / 4725 / 4726", "Security", "Tạo / bật / vô hiệu / xóa tài khoản", "T1136.001 tạo tài khoản cửa hậu"],
        ["4723 / 4724", "Security", "Đổi / đặt lại mật khẩu", "Chiếm tài khoản"],
        ["4728 / 4732 / 4756", "Security", "Thêm thành viên nhóm toàn cục / cục bộ / phổ quát", "Vào Administrators: T1098 leo thang"],
        ["4729 / 4733", "Security", "Gỡ thành viên nhóm", "Xóa dấu vết sau khi dùng"],
        ["4738", "Security", "Thay đổi thuộc tính tài khoản", "Đổi quyền, đổi script đăng nhập"],
        ["4740 / 4767", "Security", "Khóa / mở khóa tài khoản", "Hệ quả brute force"],
        ["4768 / 4769 / 4771", "Security (DC)", "Kerberos TGT / service ticket / pre-auth thất bại", "Kerberoasting, AS-REP roasting"],
        ["4776", "Security", "Xác thực NTLM", "Status ≠ 0x0 là thất bại"],
        ["4616", "Security", "Thay đổi giờ hệ thống", "Phá dòng thời gian"],
        ["1102", "Security", "Nhật ký Security bị xóa", "T1070.001 - luôn nghiêm trọng"],
        ["104", "System", "Một kênh nhật ký bị xóa", "T1070.001"],
        ["7034 / 7036 / 7040", "System", "Dịch vụ sập / đổi trạng thái / đổi kiểu khởi động", "Vô hiệu hóa AV, ổn định hệ thống"],
        ["6005 / 6006 / 6008 / 1074", "System", "Event Log khởi động / dừng / tắt máy bất thường / yêu cầu tắt máy", "Khoảng trống giám sát"],
        ["4104 / 4100", "PowerShell/Operational", "Script block logging / lỗi", "-enc, FromBase64String, DownloadString: T1059.001"],
        ["1000 / 1001", "Application", "Ứng dụng crash / báo lỗi", "Khai thác lỗ hổng gây crash"],
        ["5140 / 5145 / 5156 / 5157", "Security", "Truy cập share / đối tượng share / kết nối cho phép / bị chặn (Filtering Platform)", "Lateral movement, quét cổng; rất nhiều nhiễu"],
    ], widths=[1.1, 1.0, 2.2, 2.2], size=9, caption="EventID Windows quan trọng", part=P)
    h3("4.2.5. Giải mã sự kiện 4624/4625")
    table(["LogonType", "Tên", "Ý nghĩa", "Mức quan tâm"], [
        ["2", "Interactive", "Đăng nhập tại bàn phím/màn hình", "Bình thường trên máy trạm"],
        ["3", "Network", "Truy cập share, WMI, WinRM, SMB; phổ biến trong lateral movement", "Cao khi hàng loạt"],
        ["4", "Batch", "Scheduled task", "Theo dõi task lạ"],
        ["5", "Service", "Dịch vụ khởi động bằng tài khoản", "Theo dõi dịch vụ lạ"],
        ["7", "Unlock", "Mở khóa màn hình", "Thấp"],
        ["8", "NetworkCleartext", "Mật khẩu rõ (IIS basic auth)", "Trung bình"],
        ["9", "NewCredentials", "runas /netonly", "Trung bình"],
        ["10", "RemoteInteractive", "RDP / Terminal Services", "Cao nếu từ Internet (R21)"],
        ["11", "CachedInteractive", "Đăng nhập bằng thông tin đã cache (không liên lạc DC)", "Thấp"],
    ], widths=[0.9, 1.4, 2.8, 1.4], size=10, caption="LogonType của 4624/4625", part=P)
    table(["SubStatus (4625)", "Ý nghĩa", "Suy luận"], [
        ["0xC0000064", "Tài khoản không tồn tại", "Dò tên người dùng (user enumeration)"],
        ["0xC000006A", "Sai mật khẩu", "Dò mật khẩu nếu lặp"],
        ["0xC0000234", "Tài khoản đang bị khóa", "Brute force đã kích hoạt lockout"],
        ["0xC0000072", "Tài khoản bị vô hiệu hóa", "Thử tài khoản cũ"],
        ["0xC000006F / 0xC0000070", "Ngoài giờ / ngoài máy được phép", "Vi phạm chính sách"],
        ["0xC0000071", "Mật khẩu hết hạn", "Thường lành tính"],
        ["0xC000015B", "Không được cấp kiểu đăng nhập này", "Thử RDP bằng tài khoản không có quyền"],
        ["0xC0000133", "Lệch giờ với DC", "Vấn đề NTP"],
    ], widths=[1.6, 2.4, 2.5], size=10, caption="SubStatus của 4625", part=P)
    h3("4.2.6. Sysmon và các kênh nâng cao")
    para("Trong môi trường thực tế, **System Monitor (Sysmon)** của Sysinternals bổ sung kênh Microsoft-Windows-Sysmon/Operational với sự kiện chi tiết hơn nhiều so với 4688: "
         "1 tạo tiến trình (hash, dòng lệnh, tiến trình cha, chữ ký), 3 kết nối mạng, 7 nạp DLL, 8 CreateRemoteThread, 10 ProcessAccess (dump LSASS), 11 tạo tệp, 12/13 registry, 22 truy vấn DNS. "
         "Cấu hình bằng XML (cộng đồng SwiftOnSecurity, Olaf Hartong). Agent của đề tài thu kênh này bằng collector `winevt` với `channel: Microsoft-Windows-Sysmon/Operational`; "
         "parser hiện ánh xạ chung (provider, EventID, EventData vào extra) và có thể bổ sung ánh xạ riêng cho EventID 1/3/11.")

    # ------------------------------------------------------------------ 4.3 Linux
    h2("4.3. Log trên Linux")
    h3("4.3.1. Giao thức syslog")
    para("Linux ghi log theo chuẩn **syslog**: tiến trình gọi `syslog(3)` hoặc ghi vào socket `/dev/log`; daemon (**rsyslog**, syslog-ng, hoặc **systemd-journald**) nhận, gắn thời gian, phân loại theo "
         "**facility** (nguồn) và **severity** (mức) rồi ghi ra tệp hoặc chuyển tiếp qua mạng (UDP/TCP 514, TLS 6514). Hai định dạng dòng phổ biến: BSD (RFC 3164) và RFC 5424.")
    figure("11_syslog_format.png", "Cấu trúc thông điệp syslog RFC 3164 và RFC 5424, công thức PRI", P, 6.5)
    table(["Facility", "Mã", "Facility", "Mã"], [
        ["kern (nhân)", "0", "cron", "9"],
        ["user", "1", "authpriv (xác thực, riêng tư)", "10"],
        ["mail", "2", "ftp", "11"],
        ["daemon", "3", "ntp", "12"],
        ["auth (xác thực)", "4", "audit / alert", "13 / 14"],
        ["syslog", "5", "clock", "15"],
        ["lpr", "6", "local0 - local7 (ứng dụng tùy chọn)", "16 - 23"],
        ["news / uucp", "7 / 8", "", ""],
    ], widths=[2.0, 0.7, 2.6, 1.0], size=10, caption="Facility của syslog", part=P)
    table(["Severity", "Tên", "Ý nghĩa", "Mức chuẩn hóa trong hệ thống"], [
        ["0", "Emergency", "Hệ thống không dùng được", "critical"],
        ["1", "Alert", "Cần hành động ngay", "critical"],
        ["2", "Critical", "Tình trạng nghiêm trọng", "critical"],
        ["3", "Error", "Lỗi", "high"],
        ["4", "Warning", "Cảnh báo", "medium"],
        ["5", "Notice", "Bình thường nhưng đáng chú ý", "low"],
        ["6", "Informational", "Thông tin", "info"],
        ["7", "Debug", "Gỡ lỗi", "info"],
    ], widths=[0.8, 1.3, 2.4, 2.0], size=10, caption="Severity của syslog và ánh xạ", part=P)
    h3("4.3.2. Cấu hình rsyslog và logrotate")
    code("# /etc/rsyslog.d/50-default.conf (Debian/Ubuntu, rút gọn)\nauth,authpriv.*            /var/log/auth.log\n*.*;auth,authpriv.none     -/var/log/syslog\nkern.*                     -/var/log/kern.log\n# Chuyển tiếp mọi log tới máy chủ syslog tập trung (TCP, RFC 5424)\n*.* @@soc.example.local:514;RSYSLOG_SyslogProtocol23Format\n# Template thời gian ISO-8601 độ phân giải cao\n$ActionFileDefaultTemplate RSYSLOG_FileFormat\n\n# /etc/logrotate.d/rsyslog (rút gọn)\n/var/log/auth.log /var/log/syslog {\n    rotate 7\n    daily\n    missingok\n    compress\n    delaycompress\n    postrotate\n        /usr/lib/rsyslog/rsyslog-rotate\n    endscript\n}")
    para("`delaycompress` giữ tệp .1 chưa nén một chu kỳ, thuận tiện cho collector; `copytruncate` (nếu dùng) cắt tệp tại chỗ - chính là tình huống `size < offset` mà FileCollector xử lý.")
    h3("4.3.3. Các tệp log quan trọng trong /var/log")
    figure("12_linux_log_map.png", "Luồng ghi log trên Linux và các tệp quan trọng", P, 6.5)
    table(["Tệp", "Phân phối", "Nội dung", "Giá trị an ninh"], [
        ["/var/log/auth.log", "Debian, Ubuntu", "Xác thực: sshd, sudo, su, PAM, login, useradd/usermod, polkit", "Brute force, leo thang, tạo tài khoản - nguồn quan trọng nhất"],
        ["/var/log/secure", "RHEL, CentOS, Rocky, Fedora", "Tương đương auth.log", "Như trên"],
        ["/var/log/syslog", "Debian, Ubuntu", "Mọi thông điệp (trừ auth): kernel, cron, systemd, dịch vụ", "Dịch vụ lạ, OOM, lỗi phần cứng"],
        ["/var/log/messages", "RHEL", "Tương đương syslog", "Như trên"],
        ["/var/log/kern.log, dmesg", "Debian", "Thông điệp nhân", "Segfault, OOM-killer, rootkit module"],
        ["/var/log/wtmp, btmp, lastlog, utmp", "Tất cả", "Nhị phân: lịch sử đăng nhập (last), đăng nhập thất bại (lastb), lần cuối (lastlog), phiên hiện tại (who)", "Thống kê đăng nhập nhanh"],
        ["/var/log/audit/audit.log", "Khi cài auditd", "Syscall, thay đổi tệp, lệnh theo luật audit", "Forensics chi tiết"],
        ["/var/log/cron", "RHEL", "Lịch cron", "Persistence qua cron"],
        ["/var/log/nginx/, /var/log/apache2/ (httpd/)", "Khi cài web server", "access.log, error.log", "Tấn công web, quét lỗ hổng"],
        ["/var/log/journal/", "systemd", "Nhật ký nhị phân của journald", "Nguồn hợp nhất trên hệ hiện đại"],
        ["/var/log/dpkg.log, yum.log, dnf.log", "Debian / RHEL", "Cài/gỡ gói", "Cài công cụ tấn công"],
        ["~/.bash_history", "Mỗi user", "Lịch sử lệnh (dễ bị xóa)", "Dấu vết lệnh của kẻ tấn công"],
    ], widths=[1.7, 1.2, 2.2, 1.4], size=9, caption="Các tệp log Linux", part=P)
    h3("4.3.4. Ngăn xếp xác thực và nơi sinh log")
    figure("29_linux_auth_stack.png", "Ngăn xếp xác thực Linux: sshd, PAM, sudo và các đích ghi log", P, 6.5)
    para("Một lần đăng nhập SSH sai mật khẩu sinh **nhiều dòng** ở nhiều tầng: `sshd` ghi \"Failed password for ...\", PAM ghi \"pam_unix(sshd:auth): authentication failure; ... rhost=... user=...\", "
         "và khi ngắt kết nối sshd ghi \"Disconnected from authenticating user ...\" hoặc \"Connection closed by invalid user ...\". Parser của hệ thống nhận diện cả ba mẫu nhưng chỉ dòng sshd được gán action `logon_failed` "
         "(mức medium) để luật R15 đếm đúng một lần cho mỗi lần thử; dòng PAM được gán `pam_auth_failure` mức low.")
    h3("4.3.5. systemd-journald")
    para("Trên các bản phân phối hiện đại, **journald** thu toàn bộ log (kể cả stdout/stderr của dịch vụ) vào kho nhị phân có chỉ mục, mỗi bản ghi mang nhiều trường metadata đáng tin cậy do hệ thống gán "
         "(`_PID`, `_UID`, `_COMM`, `_EXE`, `_SYSTEMD_UNIT`, `_HOSTNAME`, `PRIORITY`, `SYSLOG_IDENTIFIER`, `__REALTIME_TIMESTAMP`, `__CURSOR`). Các trường bắt đầu bằng `_` do journald gán, không thể giả mạo bởi tiến trình ghi. "
         "rsyslog có thể đọc từ journald (module imjournal) để ghi ra tệp văn bản truyền thống; `/etc/systemd/journald.conf` quy định Storage=persistent, SystemMaxUse.")
    code("journalctl -u ssh.service --since \"1 hour ago\"      # log của một unit\njournalctl -p err -b                                 # mức error trở lên từ lần khởi động này\njournalctl -o json --after-cursor \"s=abc...;i=1f\"    # JSON, tiếp tục sau con trỏ (cách SOC Agent dùng)\njournalctl -f                                        # theo dõi thời gian thực\njournalctl _UID=1000 --since today                   # theo người dùng\njournalctl -o verbose -n 1                           # xem toàn bộ trường của bản ghi\n\n# Một bản ghi JSON (rút gọn)\n{\"__CURSOR\":\"s=4f3...;i=2a1c;b=...\",\"__REALTIME_TIMESTAMP\":\"1761472800123456\",\"PRIORITY\":\"6\",\n \"SYSLOG_IDENTIFIER\":\"sshd\",\"_PID\":\"812\",\"_COMM\":\"sshd\",\"_SYSTEMD_UNIT\":\"ssh.service\",\"_HOSTNAME\":\"db01\",\n \"MESSAGE\":\"Failed password for invalid user admin from 192.0.2.77 port 4000 ssh2\"}")
    h3("4.3.6. auditd")
    para("**auditd** là hệ thống kiểm toán ở mức nhân: ghi lại syscall, truy cập tệp, thực thi lệnh theo luật trong `/etc/audit/rules.d/`. Log có dạng cặp khóa=giá trị với nhiều bản ghi cùng `msg=audit(epoch:serial)`; "
         "công cụ `ausearch`, `aureport` để truy vấn. auditd là nguồn bổ sung chi tiết (ví dụ ai đã đọc /etc/shadow, lệnh nào được chạy bởi root) nhưng sinh rất nhiều dữ liệu; hệ thống đề tài có thể thu bằng FileCollector định dạng `plain` và luật regex.")
    code("# /etc/audit/rules.d/soc.rules\n-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p rwa -k identity\n-w /etc/sudoers -p wa -k sudoers\n-a always,exit -F arch=b64 -S execve -F euid=0 -k rootcmd\n\n# Bản ghi (rút gọn)\ntype=SYSCALL msg=audit(1761472801.123:4521): arch=c000003e syscall=59 success=yes exe=\"/usr/bin/cat\" key=\"rootcmd\"\ntype=EXECVE msg=audit(1761472801.123:4521): argc=2 a0=\"cat\" a1=\"/etc/shadow\"")
    h3("4.3.7. Đọc hiểu các dòng log xác thực tiêu biểu")
    table(["Dòng log (rút gọn)", "Ý nghĩa", "Chuẩn hóa (action / severity)"], [
        ["sshd[2231]: Failed password for root from 203.0.113.66 port 51234 ssh2", "Sai mật khẩu SSH cho tài khoản có tồn tại", "logon_failed / medium"],
        ["sshd[2250]: Invalid user oracle from 198.51.100.23 port 40022", "Thử tài khoản không tồn tại (dò tên)", "invalid_user / low"],
        ["sshd[2240]: Accepted password for root from 203.0.113.66 port 51240 ssh2", "Đăng nhập thành công bằng mật khẩu", "logon_success / info (R10 nếu là root)"],
        ["sshd[2241]: Accepted publickey for alice from 10.0.0.5 port 50001 ssh2: ED25519 SHA256:...", "Đăng nhập bằng khóa", "logon_success / info (extra.method=publickey)"],
        ["sshd: maximum authentication attempts exceeded for root from ...", "Vượt số lần thử của sshd (MaxAuthTries)", "ssh_max_auth_exceeded / high"],
        ["sshd[2260]: Did not receive identification string from 203.0.113.9", "Quét cổng SSH (kết nối không bắt tay)", "ssh_scan / low"],
        ["sudo: student : TTY=pts/0 ; PWD=/home/student ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", "Lệnh chạy bằng sudo", "sudo_command / low (extra.cmd)"],
        ["sudo: guest : user NOT in sudoers ; ...", "Người không có quyền dùng sudo", "sudo_failed / medium (R09)"],
        ["sudo: bob : 3 incorrect password attempts ; ...", "Sai mật khẩu sudo 3 lần", "sudo_failed / medium (R09)"],
        ["pam_unix(sudo:auth): authentication failure; ... user=bob", "Sai mật khẩu khi sudo (dòng PAM)", "sudo_auth_failure / medium"],
        ["su: FAILED SU (to root) attacker on /dev/pts/2", "su thất bại", "su_failed / medium (R09)"],
        ["su: Successful su for root by alice", "su thành công", "su_success / low"],
        ["useradd[3001]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash", "Tạo tài khoản", "user_created / medium (R08)"],
        ["usermod[3005]: add 'backdoor' to group 'sudo'", "Thêm vào nhóm đặc quyền", "user_added_to_privileged_group / high (R04)"],
        ["passwd[3010]: password changed for alice", "Đổi mật khẩu", "password_changed / low"],
        ["systemd-logind: New session 42 of user alice.", "Phiên đăng nhập mới", "session_opened / info"],
        ["CRON[412]: (root) CMD (/usr/bin/backup.sh)", "Cron chạy lệnh", "cron_command / info"],
        ["kernel: Out of memory: Killed process 1234 (java)", "OOM-killer", "oom_kill / high (R12)"],
        ["kernel: nginx[2345]: segfault at 0 ip ... error 4", "Tiến trình crash", "segfault / medium (R12)"],
        ["systemd[1]: Failed to start Apache HTTP Server.", "Dịch vụ không khởi động được", "service_failed / medium"],
    ], widths=[3.0, 1.9, 1.6], size=8.5, caption="Các dòng log Linux tiêu biểu và cách chuẩn hóa", part=P)
    h3("4.3.8. Các lệnh phân tích log server (thực hành Lab 17)")
    figure("30_log_analysis_steps.png", "Quy trình phân tích log server và phần được tự động hóa", P, 6.5)
    para("Các thao tác thủ công trong bài thực hành phân tích log server - và cách hệ thống tự động hóa chúng:")
    table(["Mục tiêu", "Lệnh thủ công", "Hệ thống tự động"], [
        ["Đếm số lần đăng nhập SSH thất bại theo IP", "`grep \"Failed password\" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head`", "Dashboard \"IP nguồn thất bại nhiều nhất\"; luật R15"],
        ["Liệt kê tài khoản bị thử", "`grep \"Failed password\" auth.log | grep -oP 'for (invalid user )?\\K\\S+' | sort | uniq -c`", "Bảng \"Tài khoản bị thử nhiều nhất\"; luật R17 (distinct user)"],
        ["Tìm đăng nhập thành công sau chuỗi thất bại", "`grep -E \"Failed|Accepted\" auth.log | grep 203.0.113.66`", "Luật sequence R18 → cảnh báo critical, AI điều tra"],
        ["Xem lệnh sudo", "`grep sudo auth.log | grep COMMAND`", "Lọc action=sudo_command trên trang Nhật ký log"],
        ["Tài khoản mới / nhóm", "`grep -E \"useradd|usermod|groupadd\" auth.log`", "Luật R08, R04"],
        ["Đăng nhập thất bại (nhị phân)", "`lastb | head`; `last -a`; `lastlog`", "Nguồn tương đương: sự kiện logon_failed/logon_success"],
        ["Theo dõi thời gian thực", "`tail -f /var/log/auth.log`; `journalctl -f`", "Agent gửi mỗi 10 s, dashboard tự làm mới 30 s"],
        ["Thống kê theo giờ", "`grep \"Failed password\" auth.log | awk '{print $3}' | cut -d: -f1 | sort | uniq -c`", "Biểu đồ sự kiện theo giờ"],
        ["Phân tích access log", "`awk '{print $1}' access.log | sort | uniq -c | sort -rn`; `grep -E \"\\.\\./|<script\" access.log`; `awk '$9>=400' access.log`", "Parser đánh dấu web_suspicious_request, web_scanner_detected; luật R11/R19"],
        ["Windows: đăng nhập thất bại", "`Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | Group-Object {$_.Properties[19].Value}`", "Luật R16; trường src_ip chuẩn hóa"],
        ["Windows: tài khoản mới", "`Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720,4732}`", "Luật R03, R04"],
        ["Windows: log bị xóa", "`Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102}`", "Luật R01"],
    ], widths=[1.7, 2.9, 1.9], size=8.5, caption="Lệnh phân tích log thủ công và chức năng tự động tương ứng", part=P)
    h4("Ví dụ phân tích một đoạn auth.log")
    para("Đoạn log dưới (rút từ dữ liệu trình diễn) minh họa quy trình: (1) nhận ra chuỗi thất bại từ cùng IP; (2) phát hiện lần thành công; (3) tìm hành động sau đăng nhập; (4) kết luận.")
    code("Oct 26 06:52:53 centos-db01 sshd[4312]: Failed password for root from 203.0.113.66 port 43718 ssh2\nOct 26 06:52:56 centos-db01 sshd[4313]: Failed password for root from 203.0.113.66 port 55926 ssh2\n... (16 dòng tương tự trong 74 giây) ...\nOct 26 06:54:07 centos-db01 sshd[4330]: Failed password for root from 203.0.113.66 port 41733 ssh2\nOct 26 06:54:16 centos-db01 sshd[4331]: Accepted password for root from 203.0.113.66 port 40999 ssh2\nOct 26 06:54:32 centos-db01 useradd[4340]: new user: name=backdoor, UID=1050, home=/home/backdoor\nOct 26 06:54:35 centos-db01 usermod[4342]: add 'backdoor' to group 'sudo'", size=9)
    numbered([
        "18 dòng `Failed password` cùng `203.0.113.66`, cách nhau 2-6 giây → không phải người gõ tay: **dò mật khẩu tự động** (T1110.001). Hệ thống: R15 kích hoạt ở dòng thứ 5.",
        "Dòng `Accepted password for root` từ cùng IP 9 giây sau lần thất bại cuối → **mật khẩu đã bị đoán đúng** (T1078). Hệ thống: R18 (sequence) kích hoạt, mức critical; R10 (root SSH) kích hoạt.",
        "16 giây sau: `useradd backdoor` rồi `usermod ... group 'sudo'` → kẻ tấn công **tạo cửa hậu có quyền sudo** (T1136.001, T1098). Hệ thống: R08, R04.",
        "Kết luận: máy centos-db01 đã bị xâm nhập; cần chặn IP, vô hiệu backdoor, đổi mật khẩu root, tắt PasswordAuthentication, rà soát thêm. Investigation Agent của hệ thống tự dựng đúng chuỗi 4 kỹ thuật này (xem Phần 7).",
    ])

    # ------------------------------------------------------------------ 4.4 web
    h2("4.4. Log của máy chủ web")
    figure("13_web_access_log.png", "Combined Log Format của Apache/Nginx và các trường rút trích", P, 6.5)
    para("Apache và Nginx ghi mỗi yêu cầu HTTP một dòng theo **Common Log Format** (`%h %l %u %t \"%r\" %>s %b`) hoặc **Combined Log Format** (thêm Referer và User-Agent). "
         "Nginx cho phép định nghĩa `log_format` tùy ý (kể cả JSON) trong nginx.conf. `error.log` ghi lỗi của web server và ứng dụng (PHP, upstream).")
    code("# nginx.conf\nlog_format combined_rt '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent '\n                       '\"$http_referer\" \"$http_user_agent\" $request_time';\naccess_log /var/log/nginx/access.log combined_rt;\n\n# Apache httpd.conf\nLogFormat \"%h %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\"\" combined\nCustomLog /var/log/apache2/access.log combined")
    table(["Dấu hiệu trong access log", "Kỹ thuật", "Ví dụ", "Xử lý của parser/luật"], [
        ["Hàng loạt 404/403/401 trong thời gian ngắn", "Dò quét thư mục (gobuster, dirb), T1595", "GET /admin, /.env, /wp-login.php, /backup.zip", "web_not_found/web_access_denied → R19 (≥ 30 trong 60 s)"],
        ["URL chứa ../ hoặc %2e%2e", "Path traversal / LFI", "GET /index.php?page=../../../../etc/passwd", "web_suspicious_request (high) → R11"],
        ["URL chứa <script hoặc %3cscript", "XSS", "GET /search?q=<script>alert(1)</script>", "web_suspicious_request → R11"],
        ["' OR 1=1, UNION SELECT, sleep(", "SQL injection (T1190)", "GET /item?id=1' OR '1'='1", "Luật regex tùy chỉnh trên extra.url"],
        ["User-Agent của công cụ", "Quét tự động", "sqlmap/1.7, Nikto, Nmap Scripting Engine, nuclei", "web_scanner_detected (high) → R11"],
        ["POST tới /login lặp lại 401", "Brute force web", "POST /login 401 ×50", "Luật threshold tùy chỉnh (category web, outcome failure, extra.url)"],
        ["Mã 5xx tăng vọt", "Khai thác lỗi, DoS", "500, 502, 503", "web_server_error (medium)"],
        ["Yêu cầu tới .php trong thư mục upload", "Webshell (T1505.003)", "GET /uploads/shell.php?cmd=id", "Luật regex tùy chỉnh"],
    ], widths=[1.8, 1.3, 1.9, 1.5], size=9, caption="Dấu hiệu tấn công trong access log", part=P)

    # ------------------------------------------------------------------ 4.5 lược đồ
    h2("4.5. Lược đồ chuẩn hóa chung của hệ thống")
    para("Để một bộ luật và một giao diện xử lý được cả Windows lẫn Linux, mọi bản ghi được quy về **một lược đồ 17 trường** (lấy cảm hứng từ ECS). Hình dưới mô tả nhóm trường; "
         "Phụ lục C có ví dụ JSON đầy đủ cho một sự kiện Windows và một sự kiện Linux.")
    figure("16_normalized_schema.png", "Lược đồ sự kiện chuẩn hóa (bảng log_events)", P, 6.5)
    table(["Trường", "Kiểu", "Nguồn Windows", "Nguồn Linux (syslog)", "Nguồn web"], [
        ["timestamp", "ISO-8601 UTC", "TimeCreated/@SystemTime", "BSD timestamp + năm hiện tại, đổi từ giờ địa phương", "[dd/Mon/yyyy:HH:MM:SS +zzzz]"],
        ["source", "chuỗi", "windows.security / system / application", "linux.auth (sshd, sudo...) / linux.syslog / journald", "web.access"],
        ["event_id", "chuỗi", "EventID", "mã do parser đặt: ssh_failed_password, useradd...", "http_<status> / web_suspicious / web_scanner"],
        ["category / action / outcome / severity", "enum", "Bảng WINDOWS_EVENT_MAP (≈ 50 EventID)", "Bảng AUTH_PATTERNS (≈ 30 regex) + Level syslog", "Theo status và dấu hiệu URL/UA"],
        ["user / src_ip / src_port", "chuỗi/int", "TargetUserName, IpAddress, IpPort", "nhóm regex user/ip/port", "%u, %h"],
        ["process / pid / host", "chuỗi/int", "Provider, Computer", "TAG process[PID], HOSTNAME", "httpd, host agent"],
        ["message / raw / extra", "text/JSON", "RenderingInfo hoặc mô tả tự sinh; XML gốc; EventData", "MSG; dòng gốc; facility, cmd, unit...", "\"IP METHOD URL -> status\"; dòng gốc; method, url, status, user_agent"],
    ], widths=[1.3, 0.8, 1.6, 1.6, 1.2], size=9, caption="Lược đồ 17 trường và nguồn của từng trường", part=P)
    h3("4.5.1. Tập giá trị của các trường phân loại")
    table(["Trường", "Giá trị", "Ý nghĩa"], [
        ["category", "authentication, account, privilege, process, service, system, network, web, policy, defense_evasion, persistence, other", "Nhóm ngữ nghĩa, gần với tactic ATT&CK"],
        ["outcome", "success, failure, unknown", "Kết quả hành động"],
        ["severity", "critical, high, medium, low, info", "Mức nghiêm trọng của riêng sự kiện (khác mức của cảnh báo)"],
        ["action (ví dụ)", "logon_success, logon_failed, invalid_user, logoff, user_created, user_deleted, member_added_to_group, member_added_to_privileged_group, password_reset, account_locked_out, service_installed, scheduled_task_created, audit_log_cleared, audit_policy_changed, process_created, powershell_suspicious_script, sudo_command, sudo_failed, su_failed, web_request, web_suspicious_request, web_scanner_detected, oom_kill, cron_command, log", "Hành động chuẩn hóa dùng trong điều kiện luật và trong ACTION_TACTIC của Investigation Agent"],
    ], widths=[1.1, 3.6, 1.8], size=9.5, caption="Tập giá trị của trường phân loại", part=P)
    h2("4.6. Liên kết tham khảo cho Phần 4")
    link_line("Microsoft Learn - Appendix L: Events to Monitor", "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor")
    link_line("Microsoft Learn - Advanced security audit policy settings", "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings")
    link_line("Microsoft Learn - Windows Event Log (ETW) overview", "https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log")
    link_line("Microsoft Learn - wevtutil", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil")
    link_line("Microsoft Learn - 4625(F): An account failed to log on", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625")
    link_line("Ultimate Windows Security - Event ID encyclopedia", "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/")
    link_line("Sysmon (Sysinternals) và cấu hình SwiftOnSecurity", "https://github.com/SwiftOnSecurity/sysmon-config")
    link_line("IETF RFC 5424 - The Syslog Protocol", "https://www.rfc-editor.org/rfc/rfc5424")
    link_line("IETF RFC 3164 - The BSD syslog Protocol", "https://www.rfc-editor.org/rfc/rfc3164")
    link_line("systemd - journalctl(1)", "https://www.freedesktop.org/software/systemd/man/latest/journalctl.html")
    link_line("rsyslog documentation", "https://www.rsyslog.com/doc/")
    link_line("Linux audit (auditd) documentation", "https://github.com/linux-audit/audit-documentation")
    link_line("Apache - Log Files", "https://httpd.apache.org/docs/2.4/logs.html")
    link_line("Nginx - log_format", "https://nginx.org/en/docs/http/ngx_http_log_module.html")
    link_line("NIST SP 800-92 - Guide to Computer Security Log Management", "https://csrc.nist.gov/pubs/sp/800/92/final")
    page_break()
