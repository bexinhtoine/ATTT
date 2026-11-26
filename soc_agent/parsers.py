# -*- coding: utf-8 -*-
"""
parsers.py - Bộ phân tích (parser) và chuẩn hóa log dùng chung cho SOC Agent và Web SOC.

Mọi dòng log / sự kiện được đưa về MỘT lược đồ chung (lấy cảm hứng từ Elastic Common Schema):

    timestamp  : thời điểm sự kiện, ISO-8601 UTC (vd: 2026-10-26T03:12:00.000000Z)
    source     : nguồn log  (linux.auth, linux.syslog, windows.security, windows.system,
                              windows.application, web.access, journald, file.<tên>)
    category   : authentication | account | privilege | process | service | system |
                 network | web | policy | defense_evasion | persistence | other
    action     : hành động đã chuẩn hóa (logon_failed, logon_success, user_created, ...)
    outcome    : success | failure | unknown
    severity   : critical | high | medium | low | info
    event_id   : mã sự kiện (Windows EventID hoặc mã do parser đặt: ssh_failed_password, ...)
    message    : thông điệp dạng người đọc
    user       : tài khoản liên quan
    src_ip     : địa chỉ IP nguồn (nếu có)
    src_port   : cổng nguồn (nếu có)
    process    : tiến trình / provider sinh log
    pid        : PID (nếu có)
    host       : tên máy sinh log
    raw        : dòng log / XML gốc
    extra      : dict các trường bổ sung đặc thù (EventData của Windows, HTTP status, ...)

Module chỉ dùng thư viện chuẩn của Python để Agent có thể chạy trên mọi máy Windows/Linux.
"""
import re
import time
from datetime import datetime, timezone, timedelta
import xml.etree.ElementTree as ET

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# RFC 5424 severity (0-7) -> mức chuẩn hóa của hệ thống
SYSLOG_SEVERITY_MAP = {0: "critical", 1: "critical", 2: "critical", 3: "high",
                       4: "medium", 5: "low", 6: "info", 7: "info"}
SYSLOG_FACILITIES = {0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
                     6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
                     16: "local0", 17: "local1", 18: "local2", 19: "local3", 20: "local4",
                     21: "local5", 22: "local6", 23: "local7"}
# Windows Level: 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose, 0 LogAlways
WINDOWS_LEVEL_MAP = {1: "critical", 2: "high", 3: "medium", 4: "info", 5: "info", 0: "info"}
MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
PRIVILEGED_GROUPS = ("administrators", "domain admins", "enterprise admins", "sudo", "wheel",
                     "admin", "root", "adm", "schema admins", "remote desktop users")
PRIVILEGED_USERS = ("root", "administrator", "admin", "system", "sa")


# ----------------------------------------------------------------------------
# Tiện ích thời gian
# ----------------------------------------------------------------------------
def utcnow():
    return datetime.now(timezone.utc)


def to_iso(dt):
    """datetime (aware hoặc naive-UTC) -> chuỗi ISO-8601 UTC có hậu tố Z."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_RE_FRAC = re.compile(r"(\.\d{1,9})")


def parse_iso(ts):
    """Phân tích chuỗi ISO-8601 (chấp nhận Z, phần lẻ giây 1-9 chữ số, dấu cách thay T)."""
    if not ts:
        return None
    s = str(ts).strip()
    if s[-1:] in ("Z", "z"):
        s = s[:-1] + "+00:00"
    if "T" not in s and " " in s:
        s = s.replace(" ", "T", 1)
    s = _RE_FRAC.sub(lambda m: "." + (m.group(1)[1:] + "000000")[:6], s, count=1)
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def local_naive_to_utc(dt_naive):
    """datetime naive theo giờ máy cục bộ -> UTC (syslog BSD ghi giờ địa phương)."""
    return datetime.fromtimestamp(time.mktime(dt_naive.timetuple()), tz=timezone.utc)


def parse_bsd_timestamp(mon, day, hms, now=None):
    """'Oct 26 10:00:00' (không có năm) -> năm hiện tại, hoặc năm trước nếu vượt quá hiện tại."""
    now = now or datetime.now()
    try:
        h, m, s = (int(x) for x in hms.split(":"))
        dt = datetime(now.year, MONTHS[mon], int(day), h, m, s)
    except (KeyError, ValueError):
        return None
    if dt - now > timedelta(days=2):
        dt = dt.replace(year=now.year - 1)
    return local_naive_to_utc(dt)


# ----------------------------------------------------------------------------
# Biểu thức chính quy cho các định dạng dòng log
# ----------------------------------------------------------------------------
RE_SYSLOG_BSD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")
RE_SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")
RE_SYSLOG_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>-|(?:\[.*?\])+)\s*(?P<msg>.*)$")
RE_PRI_ONLY = re.compile(r"^<(?P<pri>\d{1,3})>(?P<rest>.*)$")
RE_ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+) '
    r'(?P<proto>[^"]+)" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')

# Chỉ dấu web bất thường ở mức tổng quát (duyệt thư mục ngược, chèn script, đọc tệp hệ thống).
# Các mẫu chi tiết hơn do quản trị viên tự định nghĩa bằng luật regex trong Web SOC.
WEB_SUSPECT_MARKERS = ("../", "%2e%2e", "<script", "%3cscript", "/etc/passwd")
WEB_SCANNER_AGENTS = ("sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
                      "wpscan", "nuclei", "zgrab")

# (regex, action, outcome, category, severity, event_id) - log xác thực / hệ thống Linux
AUTH_PATTERNS = [
    (re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
     "logon_failed", "failure", "authentication", "medium", "ssh_failed_password"),
    (re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
     "logon_failed", "failure", "authentication", "medium", "ssh_failed_password"),
    (re.compile(r"Failed (?:publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
     "logon_failed", "failure", "authentication", "low", "ssh_failed_auth"),
    (re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
     "logon_success", "success", "authentication", "info", "ssh_accepted"),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"),
     "invalid_user", "failure", "authentication", "low", "ssh_invalid_user"),
    (re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
     "ssh_max_auth_exceeded", "failure", "authentication", "high", "ssh_max_auth"),
    (re.compile(r"(?:Disconnected from|Connection closed by) (?:authenticating|invalid) user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)"),
     "ssh_disconnect", "unknown", "authentication", "info", "ssh_disconnect"),
    (re.compile(r"pam_unix\(sshd:auth\): authentication failure;.*?rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?"),
     "pam_auth_failure", "failure", "authentication", "low", "pam_auth_failure"),
    (re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*?user=(?P<user>\S+)"),
     "sudo_auth_failure", "failure", "privilege", "medium", "sudo_auth_failure"),
    (re.compile(r"^\s*(?P<user>\S+) : (?:\d+ incorrect password attempts?|user NOT in sudoers|command not allowed)"),
     "sudo_failed", "failure", "privilege", "medium", "sudo_failed"),
    (re.compile(r"^\s*(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$"),
     "sudo_command", "success", "privilege", "low", "sudo_command"),
    (re.compile(r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on"),
     "su_failed", "failure", "privilege", "medium", "su_failed"),
    (re.compile(r"Successful su for (?P<target>\S+) by (?P<user>\S+)"),
     "su_success", "success", "privilege", "low", "su_success"),
    (re.compile(r"new user: name=(?P<user>[^,]+)"),
     "user_created", "success", "account", "medium", "useradd"),
    (re.compile(r"delete user '(?P<user>[^']+)'"),
     "user_deleted", "success", "account", "medium", "userdel"),
    (re.compile(r"new group: name=(?P<group>[^,]+)"),
     "group_created", "success", "account", "low", "groupadd"),
    (re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'"),
     "user_added_to_group", "success", "account", "medium", "usermod_group"),
    (re.compile(r"password changed for (?P<user>\S+)"),
     "password_changed", "success", "account", "low", "passwd_changed"),
    (re.compile(r"session opened for user (?P<user>[^\s(]+)"),
     "session_opened", "success", "authentication", "info", "session_opened"),
    (re.compile(r"session closed for user (?P<user>\S+)"),
     "session_closed", "success", "authentication", "info", "session_closed"),
    (re.compile(r"Out of memory|oom-killer|Killed process"),
     "oom_kill", "failure", "system", "high", "kernel_oom"),
    (re.compile(r"segfault at"),
     "segfault", "failure", "system", "medium", "kernel_segfault"),
    (re.compile(r"Failed to start (?P<unit>.+)"),
     "service_failed", "failure", "service", "medium", "systemd_failed"),
    (re.compile(r"^Started (?P<unit>.+)"),
     "service_started", "success", "service", "info", "systemd_started"),
    (re.compile(r"^Stopped (?P<unit>.+)"),
     "service_stopped", "success", "service", "info", "systemd_stopped"),
    (re.compile(r"\((?P<user>\S+)\) CMD \((?P<cmd>.*)\)"),
     "cron_command", "success", "process", "info", "cron_cmd"),
    (re.compile(r"Did not receive identification string from (?P<ip>\S+)"),
     "ssh_scan", "unknown", "network", "low", "ssh_noident"),
]

# Windows EventID -> (action, outcome, category, severity, trường user, trường IP)
WINDOWS_EVENT_MAP = {
    "4624": ("logon_success", "success", "authentication", "info", "TargetUserName", "IpAddress"),
    "4625": ("logon_failed", "failure", "authentication", "medium", "TargetUserName", "IpAddress"),
    "4634": ("logoff", "success", "authentication", "info", "TargetUserName", None),
    "4647": ("logoff", "success", "authentication", "info", "TargetUserName", None),
    "4648": ("logon_explicit_credentials", "success", "authentication", "low", "TargetUserName", "IpAddress"),
    "4672": ("special_privileges_assigned", "success", "privilege", "low", "SubjectUserName", None),
    "4688": ("process_created", "success", "process", "info", "SubjectUserName", None),
    "4689": ("process_exited", "success", "process", "info", "SubjectUserName", None),
    "4697": ("service_installed", "success", "service", "medium", "SubjectUserName", None),
    "4698": ("scheduled_task_created", "success", "persistence", "medium", "SubjectUserName", None),
    "4699": ("scheduled_task_deleted", "success", "persistence", "low", "SubjectUserName", None),
    "4702": ("scheduled_task_updated", "success", "persistence", "low", "SubjectUserName", None),
    "4719": ("audit_policy_changed", "success", "policy", "high", "SubjectUserName", None),
    "4720": ("user_created", "success", "account", "medium", "TargetUserName", None),
    "4722": ("user_enabled", "success", "account", "low", "TargetUserName", None),
    "4723": ("password_change_attempt", "unknown", "account", "low", "TargetUserName", None),
    "4724": ("password_reset", "success", "account", "medium", "TargetUserName", None),
    "4725": ("user_disabled", "success", "account", "low", "TargetUserName", None),
    "4726": ("user_deleted", "success", "account", "medium", "TargetUserName", None),
    "4728": ("member_added_to_group", "success", "account", "medium", "MemberName", None),
    "4732": ("member_added_to_group", "success", "account", "medium", "MemberName", None),
    "4756": ("member_added_to_group", "success", "account", "medium", "MemberName", None),
    "4729": ("member_removed_from_group", "success", "account", "low", "MemberName", None),
    "4733": ("member_removed_from_group", "success", "account", "low", "MemberName", None),
    "4738": ("user_changed", "success", "account", "low", "TargetUserName", None),
    "4740": ("account_locked_out", "failure", "authentication", "medium", "TargetUserName", None),
    "4767": ("account_unlocked", "success", "account", "low", "TargetUserName", None),
    "4768": ("kerberos_tgt_requested", "success", "authentication", "info", "TargetUserName", "IpAddress"),
    "4769": ("kerberos_service_ticket", "success", "authentication", "info", "TargetUserName", "IpAddress"),
    "4771": ("kerberos_preauth_failed", "failure", "authentication", "medium", "TargetUserName", "IpAddress"),
    "4776": ("credential_validation", "unknown", "authentication", "info", "TargetUserName", "Workstation"),
    "4616": ("system_time_changed", "success", "system", "low", "SubjectUserName", None),
    "1102": ("audit_log_cleared", "success", "defense_evasion", "critical", "SubjectUserName", None),
    "104": ("event_log_cleared", "success", "defense_evasion", "high", "SubjectUserName", None),
    "7045": ("service_installed", "success", "service", "medium", "SubjectUserName", None),
    "7036": ("service_state_changed", "success", "service", "info", None, None),
    "7040": ("service_start_type_changed", "success", "service", "low", None, None),
    "7034": ("service_crashed", "failure", "service", "medium", None, None),
    "6005": ("eventlog_started", "success", "system", "info", None, None),
    "6006": ("eventlog_stopped", "success", "system", "info", None, None),
    "6008": ("unexpected_shutdown", "failure", "system", "medium", None, None),
    "1074": ("shutdown_initiated", "success", "system", "info", "SubjectUserName", None),
    "4104": ("powershell_scriptblock", "success", "process", "low", None, None),
    "4100": ("powershell_error", "failure", "process", "low", None, None),
    "5140": ("network_share_accessed", "success", "network", "info", "SubjectUserName", "IpAddress"),
    "5145": ("network_share_object_access", "success", "network", "info", "SubjectUserName", "IpAddress"),
    "5156": ("connection_allowed", "success", "network", "info", None, "SourceAddress"),
    "5157": ("connection_blocked", "failure", "network", "low", None, "SourceAddress"),
    "1000": ("application_crash", "failure", "process", "medium", None, None),
    "1001": ("error_report", "failure", "process", "low", None, None),
}
WINDOWS_EVENT_DESCRIPTIONS = {
    "4624": "Đăng nhập thành công", "4625": "Đăng nhập thất bại", "4634": "Đăng xuất",
    "4648": "Đăng nhập bằng thông tin xác thực tường minh", "4672": "Gán đặc quyền đặc biệt cho phiên đăng nhập",
    "4688": "Tiến trình mới được tạo", "4697": "Cài đặt dịch vụ mới", "4698": "Tạo tác vụ định thời",
    "4719": "Thay đổi chính sách kiểm toán", "4720": "Tạo tài khoản người dùng", "4722": "Kích hoạt tài khoản",
    "4724": "Đặt lại mật khẩu tài khoản", "4725": "Vô hiệu hóa tài khoản", "4726": "Xóa tài khoản người dùng",
    "4728": "Thêm thành viên vào nhóm bảo mật toàn cục", "4732": "Thêm thành viên vào nhóm bảo mật cục bộ",
    "4756": "Thêm thành viên vào nhóm bảo mật phổ quát", "4740": "Tài khoản bị khóa", "4767": "Mở khóa tài khoản",
    "4771": "Kerberos tiền xác thực thất bại", "4776": "Xác thực thông tin đăng nhập (NTLM)",
    "1102": "Nhật ký kiểm toán (Security) đã bị xóa", "104": "Nhật ký sự kiện đã bị xóa",
    "7045": "Dịch vụ mới được cài đặt trên hệ thống", "7036": "Dịch vụ thay đổi trạng thái",
    "7040": "Thay đổi kiểu khởi động dịch vụ", "6005": "Dịch vụ Event Log khởi động",
    "6006": "Dịch vụ Event Log dừng", "6008": "Tắt máy bất thường", "1074": "Yêu cầu tắt/khởi động lại máy",
    "4104": "PowerShell ghi script block", "1000": "Ứng dụng gặp lỗi (crash)",
}
WINDOWS_CHANNEL_SOURCE = {"security": "windows.security", "system": "windows.system",
                          "application": "windows.application"}


def empty_event(source="other", host=None):
    return {"timestamp": to_iso(utcnow()), "source": source, "category": "other", "action": "log",
            "outcome": "unknown", "severity": "info", "event_id": None, "message": "", "user": None,
            "src_ip": None, "src_port": None, "process": None, "pid": None, "host": host,
            "raw": None, "extra": {}}


def severity_from_keywords(text):
    t = (text or "").lower()
    if any(k in t for k in ("critical", "fatal", "panic", "emergency")):
        return "critical"
    if any(k in t for k in ("error", "fail", "denied", "refused", "invalid", "attack")):
        return "medium"
    if any(k in t for k in ("warn", "timeout", "retry")):
        return "low"
    return "info"


def classify_message(process, msg):
    """Áp các mẫu AUTH_PATTERNS lên nội dung thông điệp -> dict các trường chuẩn hóa."""
    out = {}
    for rx, action, outcome, category, severity, event_id in AUTH_PATTERNS:
        m = rx.search(msg)
        if not m:
            continue
        g = m.groupdict()
        out.update({"action": action, "outcome": outcome, "category": category,
                    "severity": severity, "event_id": event_id})
        if g.get("user"):
            out["user"] = g["user"].strip()
        if g.get("ip"):
            out["src_ip"] = g["ip"]
        if g.get("port"):
            try:
                out["src_port"] = int(g["port"])
            except ValueError:
                pass
        extra = {k: v for k, v in g.items() if k not in ("user", "ip", "port") and v}
        if extra:
            out["extra"] = extra
        if action == "user_added_to_group" and (g.get("group") or "").lower() in PRIVILEGED_GROUPS:
            out["severity"] = "high"
            out["action"] = "user_added_to_privileged_group"
        break
    if not out:
        out = {"action": "log", "outcome": "unknown", "category": "other",
               "severity": severity_from_keywords(msg), "event_id": None}
        p = (process or "").lower()
        if p in ("sshd", "sudo", "su", "login", "passwd", "useradd", "userdel", "usermod",
                 "groupadd", "pam_unix", "polkitd", "gdm-password"):
            out["category"] = "authentication"
        elif p == "kernel":
            out["category"] = "system"
        elif p in ("systemd", "cron", "crond"):
            out["category"] = "service"
    return out


def parse_syslog_line(line, source=None, default_host=None):
    """Phân tích một dòng syslog (BSD RFC3164, ISO-8601 của rsyslog mới, hoặc RFC5424)."""
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    ev = empty_event(source or "linux.syslog", default_host)
    ev["raw"] = line
    pri_sev = None
    body = line
    m = RE_PRI_ONLY.match(line)
    if m:
        try:
            pri = int(m.group("pri"))
            pri_sev = SYSLOG_SEVERITY_MAP.get(pri % 8)
            ev["extra"]["facility"] = SYSLOG_FACILITIES.get(pri // 8, str(pri // 8))
            ev["extra"]["syslog_severity"] = pri % 8
        except ValueError:
            pass
        body = m.group("rest")
    m5 = RE_SYSLOG_5424.match(line)
    if m5:
        dt = parse_iso(m5.group("ts"))
        if dt:
            ev["timestamp"] = to_iso(dt)
        ev["host"] = m5.group("host") if m5.group("host") != "-" else default_host
        ev["process"] = m5.group("app") if m5.group("app") != "-" else None
        ev["pid"] = int(m5.group("pid")) if m5.group("pid").isdigit() else None
        msg = m5.group("msg")
    else:
        m2 = RE_SYSLOG_ISO.match(body) or RE_SYSLOG_BSD.match(body)
        if not m2:
            ev["message"] = body.strip()
            info = classify_message(None, body)
            ev["extra"].update(info.pop("extra", {}))
            ev.update(info)
            if pri_sev:
                ev["severity"] = pri_sev
            return ev
        g = m2.groupdict()
        dt = parse_iso(g["ts"]) if g.get("ts") else parse_bsd_timestamp(g["mon"], g["day"], g["time"])
        if dt:
            ev["timestamp"] = to_iso(dt)
        ev["host"] = g.get("host") or default_host
        ev["process"] = g.get("proc")
        ev["pid"] = int(g["pid"]) if g.get("pid") else None
        msg = g.get("msg", "")
    ev["message"] = msg.strip()
    info = classify_message(ev["process"], msg)
    ev["extra"].update(info.pop("extra", {}))
    ev.update(info)
    if pri_sev and info.get("action") == "log":
        ev["severity"] = pri_sev
    if not source:
        p = (ev["process"] or "").lower()
        if ev["category"] in ("authentication", "privilege", "account") or p in ("sshd", "sudo", "su"):
            ev["source"] = "linux.auth"
        else:
            ev["source"] = "linux.syslog"
    return ev


def parse_access_log_line(line, source="web.access", default_host=None):
    """Phân tích dòng access log định dạng Common/Combined (Apache, Nginx)."""
    line = line.rstrip("\r\n")
    m = RE_ACCESS.match(line)
    if not m:
        return None
    g = m.groupdict()
    ev = empty_event(source, default_host)
    ev["raw"] = line
    try:
        ev["timestamp"] = to_iso(datetime.strptime(g["ts"], "%d/%b/%Y:%H:%M:%S %z"))
    except ValueError:
        pass
    status = int(g["status"])
    url = g["url"]
    ua = g.get("ua") or ""
    ev["src_ip"] = g["ip"]
    ev["user"] = None if g["user"] in ("-", "") else g["user"]
    ev["process"] = "httpd"
    ev["category"] = "web"
    ev["event_id"] = "http_%d" % status
    ev["extra"] = {"method": g["method"], "url": url, "status": status, "size": g["size"],
                   "user_agent": ua or None, "referer": g.get("ref")}
    low_url = url.lower()
    if any(k in low_url for k in WEB_SUSPECT_MARKERS):
        ev.update({"action": "web_suspicious_request", "outcome": "unknown", "severity": "high",
                   "event_id": "web_suspicious"})
    elif status >= 500:
        ev.update({"action": "web_server_error", "outcome": "failure", "severity": "medium"})
    elif status in (401, 403):
        ev.update({"action": "web_access_denied", "outcome": "failure", "severity": "low"})
    elif status == 404:
        ev.update({"action": "web_not_found", "outcome": "failure", "severity": "info"})
    else:
        ev.update({"action": "web_request", "outcome": "success", "severity": "info"})
    if any(k in ua.lower() for k in WEB_SCANNER_AGENTS):
        ev.update({"action": "web_scanner_detected", "severity": "high", "event_id": "web_scanner"})
    ev["message"] = "%s %s %s -> %d" % (g["ip"], g["method"], url[:200], status)
    return ev


def parse_line(line, source=None, default_host=None, fmt="syslog"):
    """Điểm vào chung cho log dạng tệp: fmt = syslog | access_log | plain."""
    if fmt == "access_log":
        return parse_access_log_line(line, source or "web.access", default_host)
    if fmt == "plain":
        ev = empty_event(source or "file", default_host)
        ev["raw"] = line.rstrip("\r\n")
        ev["message"] = ev["raw"][:2000]
        ev["severity"] = severity_from_keywords(ev["message"])
        return ev if ev["message"].strip() else None
    return parse_syslog_line(line, source, default_host)


# ----------------------------------------------------------------------------
# Windows Event Log (XML từ wevtutil /f:RenderedXml hoặc Get-WinEvent .ToXml())
# ----------------------------------------------------------------------------
WIN_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _txt(el):
    return (el.text or "").strip() if el is not None else ""


def parse_windows_event_xml(xml_text):
    """Chuỗi XML chứa một hoặc nhiều <Event> -> danh sách dict đã chuẩn hóa."""
    xml_text = (xml_text or "").strip()
    if not xml_text:
        return []
    try:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            root = ET.fromstring("<Events>" + xml_text + "</Events>")
        # wevtutil /e:Events returns a document wrapper; Get-WinEvent.ToXml()
        # returns a single Event. Do not treat the wrapper itself as an event.
        kind = root.tag.rsplit("}", 1)[-1]
        events = [root] if kind == "Event" else (
            [child for child in root if child.tag.rsplit("}", 1)[-1] == "Event"]
            if kind == "Events" else [])
    except ET.ParseError:
        events = []
        for chunk in re.findall(r"<Event[\s>].*?</Event>", xml_text, flags=re.S):
            try:
                events.append(ET.fromstring(chunk))
            except ET.ParseError:
                continue
    out = []
    for e in events:
        ev = normalize_windows_event_element(e)
        if ev:
            out.append(ev)
    return out


def normalize_windows_event_element(e):
    ns = WIN_NS if e.tag.startswith(WIN_NS) else ""
    system = e.find(ns + "System")
    if system is None:
        return None
    provider = system.find(ns + "Provider")
    tc = system.find(ns + "TimeCreated")
    data = {}
    ed = e.find(ns + "EventData")
    if ed is not None:
        for idx, d in enumerate(ed.findall(ns + "Data")):
            data[d.get("Name") or ("Data%d" % idx)] = _txt(d)
    ud = e.find(ns + "UserData")
    if ud is not None:
        for child in ud.iter():
            if child is not ud and child.text and child.text.strip() and len(list(child)) == 0:
                data[child.tag.split("}")[-1]] = child.text.strip()
    rendered = e.find(ns + "RenderingInfo")
    return normalize_windows_event({
        "provider": provider.get("Name") if provider is not None else None,
        "event_id": _txt(system.find(ns + "EventID")),
        "level": _txt(system.find(ns + "Level")),
        "time_created": tc.get("SystemTime") if tc is not None else None,
        "record_id": _txt(system.find(ns + "EventRecordID")),
        "channel": _txt(system.find(ns + "Channel")),
        "computer": _txt(system.find(ns + "Computer")),
        "keywords": _txt(system.find(ns + "Keywords")),
        "data": data,
        "message": _txt(rendered.find(ns + "Message")) if rendered is not None else "",
        "raw": ET.tostring(e, encoding="unicode")[:6000],
    })


def normalize_windows_event(w):
    """Chuẩn hóa dict sự kiện Windows (đã tách trường) về lược đồ chung."""
    channel = (w.get("channel") or "").lower()
    source = WINDOWS_CHANNEL_SOURCE.get(channel, "windows." + (channel.replace(" ", "_") or "other"))
    ev = empty_event(source, w.get("computer"))
    dt = parse_iso(w.get("time_created")) if w.get("time_created") else None
    if dt:
        ev["timestamp"] = to_iso(dt)
    eid = str(w.get("event_id") or "")
    data = w.get("data") or {}
    try:
        level = int(w.get("level") or 4)
    except ValueError:
        level = 4
    ev.update({"event_id": eid, "process": w.get("provider"), "raw": w.get("raw"),
               "severity": WINDOWS_LEVEL_MAP.get(level, "info")})
    ev["extra"] = {"channel": w.get("channel"), "record_id": w.get("record_id"),
                   "level": level, "keywords": w.get("keywords")}
    ev["extra"].update({k: v for k, v in data.items() if v not in (None, "", "-")})
    kw = (w.get("keywords") or "").lower()
    audit_failure = kw.startswith("0x8010")
    mapping = WINDOWS_EVENT_MAP.get(eid)
    if mapping:
        action, outcome, category, severity, user_field, ip_field = mapping
        ev.update({"action": action, "outcome": outcome, "category": category, "severity": severity})
        if user_field and data.get(user_field) and data.get(user_field) != "-":
            ev["user"] = data.get(user_field)
        ip = data.get(ip_field) if ip_field else None
        if ip and ip not in ("-", "::1", "127.0.0.1", "::"):
            ev["src_ip"] = ip
        if (data.get("IpPort") or "").isdigit():
            ev["src_port"] = int(data["IpPort"])
        if action == "member_added_to_group":
            group = (data.get("TargetUserName") or "").lower()
            ev["extra"]["group"] = data.get("TargetUserName")
            member = data.get("MemberName") or data.get("MemberSid") or ""
            if member:
                ev["user"] = member.split(",")[0].replace("CN=", "")
            if group in PRIVILEGED_GROUPS:
                ev["severity"] = "high"
                ev["action"] = "member_added_to_privileged_group"
        if eid == "4776":
            failed = data.get("Status") not in (None, "", "0x0")
            ev["outcome"] = "failure" if failed else "success"
            ev["action"] = "credential_validation_failed" if failed else "credential_validation"
            if failed:
                ev["severity"] = "medium"
        if eid == "4688":
            ev["extra"]["command_line"] = data.get("CommandLine")
        if eid == "4104":
            sb = (data.get("ScriptBlockText") or "").lower()
            if any(k in sb for k in ("-enc", "frombase64string", "downloadstring", "invoke-expression")):
                ev["severity"] = "high"
                ev["action"] = "powershell_suspicious_script"
    else:
        if audit_failure:
            ev["outcome"] = "failure"
            if ev["severity"] == "info":
                ev["severity"] = "medium"
        elif kw.startswith("0x8020"):
            ev["outcome"] = "success"
        if channel == "security":
            ev["category"] = "authentication" if audit_failure else "other"
    if not ev.get("user") and data.get("SubjectUserName") not in (None, "-", ""):
        ev["user"] = data.get("SubjectUserName")
    message = (w.get("message") or "").strip()
    if not message:
        message = WINDOWS_EVENT_DESCRIPTIONS.get(eid, "Windows event %s (%s)" % (eid, w.get("provider")))
        if eid == "4625":
            message += " - Tài khoản: %s, IP nguồn: %s" % (data.get("TargetUserName"), data.get("IpAddress"))
        elif eid == "4624":
            message += " - Tài khoản: %s, LogonType: %s, IP: %s" % (
                data.get("TargetUserName"), data.get("LogonType"), data.get("IpAddress"))
        elif eid in ("4720", "4726", "4740", "4724", "4722", "4725"):
            message += " - Tài khoản: %s (bởi %s)" % (data.get("TargetUserName"), data.get("SubjectUserName"))
        elif eid in ("4732", "4728", "4756"):
            message += " - Thành viên: %s -> nhóm %s" % (
                data.get("MemberName") or data.get("MemberSid"), data.get("TargetUserName"))
        elif eid == "7045":
            message += " - Dịch vụ: %s, Đường dẫn: %s" % (data.get("ServiceName"), data.get("ImagePath"))
        elif eid == "4698":
            message += " - Tác vụ: %s (bởi %s)" % (data.get("TaskName"), data.get("SubjectUserName"))
        elif eid == "1102":
            message += " - Bởi: %s" % data.get("SubjectUserName")
    ev["message"] = message[:4000]
    return ev


LEGACY_SECURITY_EVENTS = {
    **{str(n): ("logon_failed", "failure", "authentication", "medium", ["4625"])
       for n in (529, 530, 531, 532, 533, 534, 535, 536, 537, 539)},
    "528": ("logon_success", "success", "authentication", "info", ["4624"]),
    "540": ("logon_success", "success", "authentication", "info", ["4624"]),
    "538": ("logoff", "success", "authentication", "info", ["4634"]),
    "551": ("logoff", "success", "authentication", "info", ["4647"]),
    "517": ("audit_log_cleared", "success", "defense_evasion", "critical", ["1102"]),
    "624": ("user_created", "success", "account", "medium", ["4720"]),
    "630": ("user_deleted", "success", "account", "low", ["4726"]),
    "644": ("user_locked", "success", "account", "medium", ["4740"]),
    "612": ("audit_policy_changed", "success", "policy", "high", ["4719"]),
    "601": ("service_install_attempt", "unknown", "service", "medium", ["4697"]),
    "632": ("member_added_to_group", "success", "account", "medium", ["4728"]),
    "636": ("member_added_to_group", "success", "account", "medium", ["4732"]),
    "660": ("member_added_to_group", "success", "account", "medium", ["4756"]),
    "602": ("scheduled_task_changed", "unknown", "persistence", "medium",
            ["4698", "4699", "4700", "4701", "4702"]),
}


def normalize_legacy_windows(ev):
    """Classify classic Security events without changing their original ID or raw log.

    Microsoft Appendix L maps classic IDs to newer events. In particular, 602 is
    ambiguous; only a message explicitly describing creation is a created task.
    Named fields are extracted conservatively from the event's own message.
    """
    spec = LEGACY_SECURITY_EVENTS.get(str(ev.get("event_id")))
    if ev.get("source") != "windows.security" or spec is None:
        return ev
    action, outcome, category, severity, equivalents = spec
    raw = ev.get("raw") or ev.get("message") or ""
    fields = {}
    for key, value in re.findall(r"^[ \t]*([A-Za-z][A-Za-z 0-9()/ _-]{0,60}):[ \t]*(.*?)[ \t]*$", raw, re.M):
        value = value.strip()
        if value and value != "-":
            fields.setdefault(key.strip().casefold(), value)
    def field(*keys):
        return next((fields[k] for k in keys if fields.get(k)), None)
    extra = dict(ev.get("extra") or {})
    extra.update(legacy_event_id=str(ev["event_id"]), equivalent_modern_event_ids=equivalents,
                 legacy_normalizer="windows-classic-v1", legacy_message_fields=fields)
    target = field("new account name", "target account name", "target user name", "account name", "user name")
    if action == "member_added_to_group":
        group = field("target account name", "group name", "target group name")
        sid = field("target account id", "group id", "target sid")
        target = field("member name", "member account name", "member id")
        extra["group"] = group
        if ((group and group.casefold() in PRIVILEGED_GROUPS) or
                (sid and re.fullmatch(r"S-1-5-(?:32-(?:544|555)|21-(?:\d+-){3}(?:512|518|519))", sid, re.I))):
            action, severity = "member_added_to_privileged_group", "high"
    if action == "scheduled_task_changed":
        if re.search(r"scheduled\s+task\s+(?:was\s+)?created\b|created\s+(?:a\s+)?(?:new\s+)?scheduled\s+task", raw, re.I):
            action, outcome = "scheduled_task_created", "success"
        elif re.search(r"scheduled\s+task\s+(?:was\s+)?deleted\b", raw, re.I):
            action, outcome = "scheduled_task_deleted", "success"
        extra["TaskName"] = field("task name", "file name", "job name")
    if action == "service_install_attempt":
        extra["ServiceName"] = field("service name")
    if target:
        ev["user"] = target
    logon_type = field("logon type")
    if logon_type and logon_type.isdigit():
        extra["LogonType"] = logon_type
    address = field("source network address", "source ip address", "client address")
    if address:
        import ipaddress
        try:
            ev["src_ip"] = str(ipaddress.ip_address(address))
        except ValueError:
            pass
    port = field("source port", "client port")
    if port and port.isdigit() and int(port) <= 65535:
        ev["src_port"] = int(port)
    if outcome == "unknown" and ev.get("outcome") in ("success", "failure"):
        outcome = ev["outcome"]
    if extra.get("event_type") == 5:
        outcome = "failure"
    ev.update(action=action, outcome=outcome, category=category, severity=severity, extra=extra)
    return ev


def normalize_event(ev, default_host=None):
    """Làm sạch một dict sự kiện (dù do parser nào tạo) để chắc chắn đủ trường và đúng kiểu."""
    base = empty_event(ev.get("source") or "other", ev.get("host") or default_host)
    base.update({k: v for k, v in ev.items() if k in base})
    normalize_legacy_windows(base)
    if base["severity"] not in SEVERITIES:
        base["severity"] = "info"
    if base["outcome"] not in ("success", "failure", "unknown"):
        base["outcome"] = "unknown"
    if not parse_iso(base["timestamp"]):
        base["timestamp"] = to_iso(utcnow())
    if not isinstance(base["extra"], dict):
        base["extra"] = {"value": base["extra"]}
    if base.get("src_port") is not None:
        try:
            base["src_port"] = int(base["src_port"])
        except (TypeError, ValueError):
            base["src_port"] = None
    base["message"] = (base.get("message") or "")[:4000]
    if base.get("raw"):
        base["raw"] = str(base["raw"])[:8000]
    if not base.get("host"):
        base["host"] = default_host
    return base
