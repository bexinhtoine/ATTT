# -*- coding: utf-8 -*-
"""
seed.py - Dữ liệu khởi tạo: tài khoản mặc định, bộ luật phát hiện mặc định,
danh sách uy tín IP mẫu và một vài bài tri thức (playbook) ban đầu.
"""
from .extensions import db
from .models import User, DetectionRule, IpReputation, KnowledgeArticle, dumps

DEFAULT_USERS = [
    {"username": "admin", "password": "Admin@123", "full_name": "Quản trị hệ thống", "role": "admin"},
    {"username": "analyst", "password": "Analyst@123", "full_name": "Chuyên viên SOC Tier 1", "role": "analyst"},
    {"username": "viewer", "password": "Viewer@123", "full_name": "Người xem báo cáo", "role": "viewer"},
]

# code, name, type, severity, conditions, threshold, window, group_by, distinct, title, tactic, technique, description
DEFAULT_RULES = [
    ("R01", "Nhật ký kiểm toán Windows bị xóa", "match", "critical",
     {"source": "windows.security", "event_id": ["1102"]}, None, None, "host", None,
     "Nhật ký kiểm toán Security bị xóa trên {host} (bởi {user})",
     "Defense Evasion", "T1070.001",
     "Kẻ tấn công thường xóa Security log để che dấu vết. Một lần xuất hiện cũng cần điều tra ngay."),
    ("R02", "Nhật ký sự kiện Windows (System/Application) bị xóa", "match", "high",
     {"event_id": ["104"], "source": ["windows.system", "windows.application"]}, None, None, "host", None,
     "Nhật ký {extra.Channel} bị xóa trên {host}", "Defense Evasion", "T1070.001",
     "EventID 104 của provider Microsoft-Windows-Eventlog ghi nhận việc xóa một kênh nhật ký."),
    ("R03", "Tạo tài khoản người dùng Windows", "match", "medium",
     {"source": "windows.security", "event_id": ["4720"]}, None, None, "user_name", None,
     "Tài khoản mới '{user}' được tạo trên {host}", "Persistence", "T1136.001",
     "Tài khoản mới ngoài quy trình quản trị có thể là cửa hậu để duy trì truy cập."),
    ("R04", "Thêm thành viên vào nhóm đặc quyền", "match", "high",
     {"action": ["member_added_to_privileged_group", "user_added_to_privileged_group"]}, None, None, "user_name", None,
     "'{user}' được thêm vào nhóm đặc quyền {extra.group} trên {host}", "Persistence", "T1098",
     "Thêm vào Administrators / sudo / wheel... là bước leo thang và duy trì đặc quyền điển hình."),
    ("R05", "Cài đặt dịch vụ mới trên Windows", "match", "medium",
     {"event_id": ["7045", "4697"]}, None, None, "host", None,
     "Dịch vụ mới '{extra.ServiceName}' được cài trên {host}", "Persistence", "T1543.003",
     "Dịch vụ lạ có đường dẫn bất thường (thư mục Temp, AppData) là dấu hiệu mã độc cài cắm."),
    ("R06", "Tạo tác vụ định thời (Scheduled Task)", "match", "medium",
     {"source": "windows.security", "event_id": ["4698"]}, None, None, "host", None,
     "Tác vụ định thời mới '{extra.TaskName}' trên {host}", "Execution / Persistence", "T1053.005",
     "Scheduled Task thường được dùng để chạy lại mã độc sau khởi động."),
    ("R07", "Thay đổi chính sách kiểm toán", "match", "high",
     {"source": "windows.security", "event_id": ["4719"]}, None, None, "host", None,
     "Chính sách kiểm toán bị thay đổi trên {host} (bởi {user})", "Defense Evasion", "T1562.002",
     "Tắt/giảm kiểm toán làm mù hệ thống giám sát."),
    ("R08", "Tạo tài khoản mới trên Linux", "match", "medium",
     {"action": ["user_created"], "source": ["linux.auth", "linux.syslog", "journald"]}, None, None, "user_name", None,
     "Tài khoản Linux mới '{user}' được tạo trên {host}", "Persistence", "T1136.001",
     "Ghi nhận lệnh useradd / adduser qua log pam/sudo."),
    ("R09", "Lạm dụng sudo / su thất bại", "match", "medium",
     {"action": ["sudo_failed", "sudo_auth_failure", "su_failed"]}, None, None, "user_name", None,
     "Nỗ lực leo thang đặc quyền thất bại của '{user}' trên {host}", "Privilege Escalation", "T1548.003",
     "Người dùng không có quyền cố gắng dùng sudo/su."),
    ("R10", "Đăng nhập SSH trực tiếp bằng root", "match", "medium",
     {"event_id": ["ssh_accepted"], "user_in": ["root"]}, None, None, "src_ip", None,
     "Đăng nhập SSH trực tiếp bằng root trên {host} từ {src_ip}", "Initial Access", "T1078",
     "Chính sách an toàn khuyến nghị cấm đăng nhập root trực tiếp qua SSH."),
    ("R11", "Yêu cầu web đáng ngờ / máy quét web", "match", "high",
     {"action": ["web_suspicious_request", "web_scanner_detected"]}, None, None, "src_ip", None,
     "Yêu cầu web đáng ngờ từ {src_ip} tới {host}", "Initial Access", "T1190",
     "URL chứa dấu hiệu duyệt thư mục ngược/chèn script hoặc User-Agent của công cụ quét."),
    ("R12", "Sự cố ổn định hệ thống", "match", "low",
     {"action": ["oom_kill", "segfault", "service_crashed", "unexpected_shutdown", "application_crash"]},
     None, None, "host", None, "Sự cố hệ thống trên {host}: {action}", "", "",
     "Sự kiện vận hành (hết bộ nhớ, dịch vụ sập, tắt máy bất thường) - theo dõi sức khỏe máy chủ."),
    ("R13", "Tài khoản bị khóa do sai mật khẩu nhiều lần", "match", "medium",
     {"source": "windows.security", "event_id": ["4740"]}, None, None, "user_name", None,
     "Tài khoản '{user}' bị khóa trên {host}", "Credential Access", "T1110",
     "Khóa tài khoản thường là hệ quả của dò mật khẩu."),
    ("R14", "PowerShell đáng ngờ (mã hóa/tải từ xa)", "match", "high",
     {"action": ["powershell_suspicious_script"]}, None, None, "host", None,
     "Script PowerShell đáng ngờ trên {host}", "Execution", "T1059.001",
     "Lệnh PowerShell mã hóa base64 hoặc tải mã từ xa là kỹ thuật phổ biến của mã độc."),
    ("R15", "Dò mật khẩu SSH (brute force)", "threshold", "high",
     {"action": ["logon_failed"], "source": ["linux.auth", "journald"]}, 5, 120, "src_ip", None,
     "Dò mật khẩu SSH từ {src_ip} tới {host} ({count} lần thất bại)", "Credential Access", "T1110.001",
     "Từ 5 lần đăng nhập SSH thất bại trong 2 phút từ cùng một IP."),
    ("R16", "Dò mật khẩu Windows (brute force)", "threshold", "high",
     {"source": "windows.security", "event_id": ["4625"]}, 5, 120, "src_ip", None,
     "Dò mật khẩu Windows từ {src_ip} tới {host} ({count} lần thất bại)", "Credential Access", "T1110.001",
     "Từ 5 sự kiện 4625 trong 2 phút cùng IP nguồn (hoặc cùng tài khoản nếu đăng nhập cục bộ)."),
    ("R17", "Password spraying (nhiều tài khoản từ một IP)", "threshold", "high",
     {"action": ["logon_failed", "invalid_user"]}, 5, 300, "src_ip", "user_name",
     "Password spraying từ {src_ip}: {count} tài khoản khác nhau bị thử", "Credential Access", "T1110.003",
     "Đếm số tài khoản KHÁC NHAU bị thử từ cùng IP trong 5 phút."),
    ("R18", "Đăng nhập thành công sau nhiều lần thất bại", "sequence", "critical",
     {"precondition": {"action": ["logon_failed"]}, "trigger": {"action": ["logon_success"]}, "min_count": 3},
     None, 600, "src_ip", None,
     "Đăng nhập THÀNH CÔNG sau {count} lần thất bại: '{user}' từ {src_ip} vào {host}",
     "Credential Access", "T1110",
     "Dấu hiệu dò mật khẩu đã thành công - cần phản ứng ngay (khóa tài khoản, chặn IP)."),
    ("R19", "Dò quét ứng dụng web (nhiều lỗi 4xx)", "threshold", "medium",
     {"category": ["web"], "outcome": ["failure"]}, 30, 60, "src_ip", None,
     "Dò quét web từ {src_ip} ({count} yêu cầu lỗi trong 1 phút)", "Reconnaissance", "T1595",
     "Hơn 30 yêu cầu bị từ chối/không tồn tại trong 1 phút từ một IP."),
    ("R20", "Thử nhiều tài khoản không tồn tại qua SSH", "threshold", "medium",
     {"action": ["invalid_user"]}, 10, 300, "src_ip", None,
     "Thử {count} tài khoản không tồn tại qua SSH từ {src_ip}", "Credential Access", "T1110",
     "Dấu hiệu dò tên người dùng (user enumeration)."),
    ("R21", "Đăng nhập RDP từ Internet", "match", "medium",
     {"source": "windows.security", "event_id": ["4624"], "extra": {"LogonType": ["10"]}, "src_ip_public": True},
     None, None, "src_ip", None,
     "Đăng nhập RDP từ Internet ({src_ip}) vào {host} bằng '{user}'", "Lateral Movement", "T1021.001",
     "LogonType 10 (RemoteInteractive) từ địa chỉ công cộng."),
]

DEMO_IP_REPUTATION = [
    ("203.0.113.66", "malicious", "blocklist", "Máy quét SSH được ghi nhận trong danh sách chặn (dải tài liệu RFC 5737, dùng cho demo)"),
    ("198.51.100.23", "suspicious", "blocklist", "Nguồn dò quét web nhiều lần (dải tài liệu RFC 5737, dùng cho demo)"),
    ("192.0.2.77", "malicious", "analyst", "IP từng đứng sau chiến dịch password spraying (demo)"),
]

DEFAULT_KNOWLEDGE = [
    {"title": "Playbook: Xử lý cảnh báo dò mật khẩu SSH/RDP", "category": "playbook",
     "tags": "brute force,ssh,rdp,T1110", "mitre_technique": "T1110.001",
     "summary": "Các bước phân loại và phản ứng với tấn công dò mật khẩu.",
     "content": "## Phân loại\n1. Kiểm tra IP nguồn: nội bộ hay Internet, có trong blocklist không.\n"
                "2. Đếm số lần thất bại và số tài khoản bị thử; kiểm tra có lần đăng nhập THÀNH CÔNG nào sau đó không.\n"
                "3. Nếu có đăng nhập thành công -> nâng mức Nghiêm trọng, chuyển sang điều tra.\n\n"
                "## Phản ứng\n- Chặn IP tại firewall / fail2ban.\n- Đặt lại mật khẩu, bật MFA cho tài khoản bị nhắm.\n"
                "- Tắt đăng nhập root trực tiếp, chuyển SSH sang xác thực khóa.\n\n## Dương tính giả thường gặp\n"
                "- Script giám sát dùng sai mật khẩu cũ.\n- Người dùng quên mật khẩu (ít lần, giờ hành chính, IP nội bộ)."},
    {"title": "Playbook: Tài khoản mới / thêm vào nhóm quản trị", "category": "playbook",
     "tags": "account,persistence,T1136,T1098", "mitre_technique": "T1136.001",
     "summary": "Xác minh thay đổi tài khoản có nằm trong quy trình quản trị không.",
     "content": "## Phân loại\n1. Đối chiếu với ticket/yêu cầu thay đổi của bộ phận IT.\n"
                "2. Kiểm tra người thực hiện (SubjectUserName) và thời điểm (ngoài giờ?).\n"
                "3. Xem các sự kiện trước đó trên cùng máy: có dò mật khẩu, PowerShell lạ không.\n\n"
                "## Phản ứng\n- Vô hiệu hóa tài khoản lạ, gỡ khỏi nhóm đặc quyền.\n- Thu thập bằng chứng, rà soát dịch vụ/tác vụ định thời mới."},
    {"title": "Playbook: Nhật ký kiểm toán bị xóa (EventID 1102)", "category": "playbook",
     "tags": "defense evasion,1102,T1070", "mitre_technique": "T1070.001",
     "summary": "Xóa Security log là hành vi che dấu vết; luôn coi là nghiêm trọng.",
     "content": "## Phân loại\n- Xác định tài khoản thực hiện và phiên đăng nhập tương ứng (4624 trước đó).\n"
                "- Kiểm tra các sự kiện còn lưu trên Web SOC (log đã gửi về trước khi bị xóa).\n\n"
                "## Phản ứng\n- Cô lập máy, đổi mật khẩu tài khoản quản trị.\n- Khôi phục log từ SOC, điều tra toàn bộ chuỗi tấn công."},
]


def seed_all():
    created = {"users": 0, "rules": 0, "ips": 0, "kb": 0}
    if User.query.count() == 0:
        for u in DEFAULT_USERS:
            user = User(username=u["username"], full_name=u["full_name"], role=u["role"])
            user.set_password(u["password"])
            db.session.add(user)
            created["users"] += 1
    existing_codes = {r.code for r in DetectionRule.query.all()}
    for (code, name, rtype, sev, cond, thr, win, group_by, distinct, title, tactic, tech, desc) in DEFAULT_RULES:
        if code in existing_codes:
            continue
        db.session.add(DetectionRule(
            code=code, name=name, rule_type=rtype, severity=sev, conditions=dumps(cond),
            threshold_count=thr or 1, window_seconds=win or 600, group_by=group_by,
            distinct_field=distinct, title_template=title, mitre_tactic=tactic or None,
            mitre_technique=tech or None, description=desc, is_builtin=True, created_by="system"))
        created["rules"] += 1
    if IpReputation.query.count() == 0:
        for ip, verdict, source, note in DEMO_IP_REPUTATION:
            db.session.add(IpReputation(ip=ip, verdict=verdict, source=source, note=note, created_by="system"))
            created["ips"] += 1
    if KnowledgeArticle.query.count() == 0:
        for k in DEFAULT_KNOWLEDGE:
            db.session.add(KnowledgeArticle(source="manual", created_by="system", **k))
            created["kb"] += 1
    db.session.commit()
    return created
