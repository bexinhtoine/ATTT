# -*- coding: utf-8 -*-
"""
demo_attack.py - Sinh dữ liệu trình diễn end-to-end cho Agentic SOC Platform.

Script đóng vai NHIỀU máy trạm: đăng ký agent qua API thật rồi gửi các kịch bản tấn công mô phỏng
(đã chuẩn hóa) về Web SOC, xen lẫn log nền lành tính. Qua đó kích hoạt luật phát hiện và tác tử AI,
tạo dữ liệu thực để chụp màn hình dashboard/cảnh báo/báo cáo và để kiểm thử toàn tuyến.

Cách dùng:
    python tools/demo_attack.py --server http://127.0.0.1:5000 --token soc-enroll-2026
    python tools/demo_attack.py --spread-hours 3     # trải sự kiện trong 3 giờ gần nhất

Mọi IP tấn công dùng dải tài liệu RFC 5737 (203.0.113.x, 198.51.100.x, 192.0.2.x) - không phải IP thật.
"""
import argparse
import json
import random
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ATTACKER_IPS = ["203.0.113.66", "198.51.100.23", "192.0.2.77", "203.0.113.150"]
INTERNAL_IPS = ["10.0.0.5", "10.0.0.12", "192.168.1.20", "192.168.1.45"]
COMMON_USERS = ["root", "admin", "administrator", "oracle", "postgres", "test", "ubuntu",
                "git", "user", "backup", "ftpuser", "guest", "dev"]
NORMAL_USERS = ["alice", "bob", "carol", "dnguyen", "ptran"]


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Sender:
    def __init__(self, server, token):
        self.server = server.rstrip("/")
        self.token = token

    def _post(self, path, payload, headers=None):
        req = urllib.request.Request(self.server + path, data=json.dumps(payload).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except urllib.error.URLError as e:
            print("Không kết nối được tới %s: %s" % (self.server, e))
            sys.exit(1)

    def register(self, hostname, os_type, os_version, ip):
        status, body = self._post("/api/v1/agents/register", {
            "enrollment_token": self.token, "hostname": hostname, "os_type": os_type,
            "os_version": os_version, "ip_address": ip, "agent_version": "1.0.0-demo",
            "collectors": [{"type": "winevt" if os_type == "windows" else "file", "name": "demo"}]})
        if status != 201:
            print("Đăng ký %s thất bại: %s %s" % (hostname, status, body))
            sys.exit(1)
        print("  + Đăng ký agent %-14s (%s)" % (hostname, os_type))
        return body["api_key"]

    def send(self, api_key, events):
        total = 0
        for i in range(0, len(events), 500):
            status, body = self._post("/api/v1/logs", {"events": events[i:i + 500]}, {"X-API-Key": api_key})
            if status != 200:
                print("  Gửi log lỗi: %s %s" % (status, body))
            elif isinstance(body, dict):
                total += body.get("accepted", 0)
        return total


# --------------------------------------------------------------------- Linux
def win_logon_fail(ts, host, user, ip):
    return {"timestamp": iso(ts), "source": "windows.security", "category": "authentication",
            "action": "logon_failed", "outcome": "failure", "severity": "medium", "event_id": "4625",
            "message": "Đăng nhập thất bại - Tài khoản: %s, IP nguồn: %s, LogonType: 10" % (user, ip),
            "user": user, "src_ip": ip, "src_port": random.randint(40000, 60000), "process": "Microsoft-Windows-Security-Auditing",
            "host": host, "raw": "EventID=4625 Target=%s Ip=%s" % (user, ip),
            "extra": {"LogonType": "10", "TargetUserName": user, "IpAddress": ip, "Status": "0xc000006d",
                      "SubStatus": "0xc000006a", "channel": "Security", "sim_id": random.random()}}


def win_logon_ok(ts, host, user, ip, logon_type="10"):
    return {"timestamp": iso(ts), "source": "windows.security", "category": "authentication",
            "action": "logon_success", "outcome": "success", "severity": "info", "event_id": "4624",
            "message": "Đăng nhập thành công - Tài khoản: %s, LogonType: %s, IP: %s" % (user, logon_type, ip),
            "user": user, "src_ip": ip, "host": host, "process": "Microsoft-Windows-Security-Auditing",
            "extra": {"LogonType": logon_type, "TargetUserName": user, "IpAddress": ip, "channel": "Security",
                      "sim_id": random.random()}}


def win_event(ts, host, eid, action, severity, message, user=None, extra=None):
    return {"timestamp": iso(ts), "source": "windows.security" if int(eid) < 5000 else "windows.system",
            "category": "account", "action": action, "outcome": "success", "severity": severity,
            "event_id": str(eid), "message": message, "user": user, "host": host,
            "process": "Microsoft-Windows-Security-Auditing",
            "extra": {**(extra or {}), "channel": "Security" if int(eid) < 5000 else "System", "sim_id": random.random()}}


def ssh_fail(ts, host, user, ip, invalid=False):
    msg = ("Failed password for invalid user %s from %s port %d ssh2" if invalid
           else "Failed password for %s from %s port %d ssh2") % (user, ip, random.randint(40000, 60000))
    return {"timestamp": iso(ts), "source": "linux.auth", "category": "authentication",
            "action": "invalid_user" if invalid else "logon_failed", "outcome": "failure",
            "severity": "low" if invalid else "medium",
            "event_id": "ssh_invalid_user" if invalid else "ssh_failed_password",
            "message": msg, "user": user, "src_ip": ip, "process": "sshd", "host": host,
            "raw": "%s sshd[%d]: %s" % (host, random.randint(1000, 9000), msg), "extra": {"sim_id": random.random()}}


def ssh_ok(ts, host, user, ip):
    msg = "Accepted password for %s from %s port %d ssh2" % (user, ip, random.randint(40000, 60000))
    return {"timestamp": iso(ts), "source": "linux.auth", "category": "authentication",
            "action": "logon_success", "outcome": "success", "severity": "info", "event_id": "ssh_accepted",
            "message": msg, "user": user, "src_ip": ip, "process": "sshd", "host": host,
            "raw": "%s sshd: %s" % (host, msg), "extra": {"sim_id": random.random()}}


def linux_event(ts, host, action, severity, message, user=None, process="sudo", category="privilege", eid=None):
    return {"timestamp": iso(ts), "source": "linux.auth", "category": category, "action": action,
            "outcome": "success", "severity": severity, "event_id": eid or action, "message": message,
            "user": user, "process": process, "host": host,
            "raw": "%s %s: %s" % (host, process, message), "extra": {"sim_id": random.random()}}


def web_event(ts, host, ip, method, url, status, ua="Mozilla/5.0", action=None, severity=None, eid=None):
    return {"timestamp": iso(ts), "source": "web.access", "category": "web",
            "action": action or ("web_request" if status < 400 else "web_not_found"),
            "outcome": "success" if status < 400 else "failure", "severity": severity or ("info" if status < 400 else "low"),
            "event_id": eid or ("http_%d" % status), "message": "%s %s %s -> %d" % (ip, method, url, status),
            "src_ip": ip, "process": "httpd", "host": host,
            "raw": '%s - - "%s %s HTTP/1.1" %d' % (ip, method, url, status),
            "extra": {"method": method, "url": url, "status": status, "user_agent": ua, "sim_id": random.random()}}


def benign_noise(host, os_type, start, end, n=60):
    """Log nền lành tính rải đều để dashboard/biểu đồ trông thực tế."""
    out = []
    span = (end - start).total_seconds()
    for _ in range(n):
        ts = start + timedelta(seconds=random.random() * span)
        if os_type == "windows":
            u = random.choice(NORMAL_USERS)
            out.append(win_logon_ok(ts, host, u, random.choice(INTERNAL_IPS), logon_type=random.choice(["2", "3", "7"])))
        elif os_type == "web":
            out.append(web_event(ts, host, random.choice(INTERNAL_IPS + ["203.0.113.9"]),
                                  random.choice(["GET", "GET", "GET", "POST"]),
                                  random.choice(["/", "/index.html", "/api/status", "/products", "/login", "/static/app.js"]),
                                  random.choice([200, 200, 200, 302, 404])))
        else:
            u = random.choice(NORMAL_USERS)
            if random.random() < 0.5:
                out.append(ssh_ok(ts, host, u, random.choice(INTERNAL_IPS)))
            else:
                out.append(linux_event(ts, host, "cron_command", "info",
                                        "(%s) CMD (/usr/bin/backup.sh)" % u, u, "CRON", "process", "cron_cmd"))
    return out


def scenario_ssh_bruteforce(host, t0):
    """Kịch bản 1: dò mật khẩu SSH từ IP độc hại, kết thúc bằng đăng nhập thành công."""
    ip, ev = ATTACKER_IPS[0], []
    t = t0
    for _ in range(18):
        ev.append(ssh_fail(t, host, "root", ip))
        t += timedelta(seconds=random.randint(2, 6))
    ev.append(ssh_ok(t + timedelta(seconds=4), host, "root", ip))              # thành công -> R18 (critical)
    t += timedelta(seconds=20)
    ev.append(linux_event(t, host, "user_created", "medium", "new user: name=backdoor, UID=1050, home=/home/backdoor",
                          "backdoor", "useradd", "account", "useradd"))         # R08
    ev.append(linux_event(t + timedelta(seconds=3), host, "user_added_to_privileged_group", "high",
                          "add 'backdoor' to group 'sudo'", "backdoor", "usermod", "account", "usermod_group"))  # R04
    ev[-1]["extra"]["group"] = "sudo"
    return ip, ev


def scenario_rdp_bruteforce(host, t0):
    """Kịch bản 2: dò mật khẩu RDP (Windows 4625) từ Internet rồi đăng nhập RDP thành công."""
    ip, ev = ATTACKER_IPS[1], []
    t = t0
    for _ in range(16):
        ev.append(win_logon_fail(t, host, random.choice(["administrator", "admin"]), ip))
        t += timedelta(seconds=random.randint(3, 8))
    ev.append(win_logon_ok(t + timedelta(seconds=5), host, "administrator", ip, "10"))    # R18 + R21
    return ip, ev


def scenario_password_spray(host, t0):
    """Kịch bản 3: một IP thử nhiều tài khoản khác nhau (password spraying)."""
    ip, ev = ATTACKER_IPS[2], []
    t = t0
    for u in COMMON_USERS:
        ev.append(ssh_fail(t, host, u, ip, invalid=u not in ("root", "admin", "test")))
        t += timedelta(seconds=random.randint(1, 4))
    return ip, ev


def scenario_windows_persistence(host, t0):
    """Kịch bản 4: sau khi xâm nhập, kẻ tấn công tạo tài khoản, thêm vào admin, cài dịch vụ, xóa log."""
    ev, t = [], t0
    ev.append(win_event(t, host, 4720, "user_created", "medium",
                        "Tạo tài khoản người dùng - Tài khoản: svc_update (bởi administrator)",
                        "svc_update", {"TargetUserName": "svc_update", "SubjectUserName": "administrator"}))  # R03
    t += timedelta(seconds=8)
    ev.append(win_event(t, host, 4732, "member_added_to_privileged_group", "high",
                        "Thêm thành viên vào nhóm bảo mật cục bộ - Thành viên: svc_update -> nhóm Administrators",
                        "svc_update", {"MemberName": "svc_update", "TargetUserName": "Administrators",
                                       "group": "Administrators", "SubjectUserName": "administrator"}))       # R04
    t += timedelta(seconds=12)
    ev.append({"timestamp": iso(t), "source": "windows.system", "category": "service", "action": "service_installed",
               "outcome": "success", "severity": "medium", "event_id": "7045",
               "message": "Dịch vụ mới 'WinUpdateSvc' được cài - Đường dẫn: C:\\Users\\Public\\upd.exe",
               "host": host, "process": "Service Control Manager",
               "extra": {"ServiceName": "WinUpdateSvc", "ImagePath": "C:\\Users\\Public\\upd.exe", "channel": "System", "sim_id": random.random()}})  # R05
    t += timedelta(seconds=15)
    ev.append({"timestamp": iso(t), "source": "windows.security", "category": "persistence", "action": "scheduled_task_created",
               "outcome": "success", "severity": "medium", "event_id": "4698",
               "message": "Tác vụ định thời mới '\\UpdateCheck' trên %s" % host, "user": "administrator", "host": host,
               "extra": {"TaskName": "\\UpdateCheck", "SubjectUserName": "administrator", "channel": "Security", "sim_id": random.random()}})  # R06
    t += timedelta(seconds=20)
    ev.append({"timestamp": iso(t), "source": "windows.security", "category": "defense_evasion", "action": "audit_log_cleared",
               "outcome": "success", "severity": "critical", "event_id": "1102",
               "message": "Nhật ký kiểm toán Security bị xóa trên %s (bởi administrator)" % host, "user": "administrator",
               "host": host, "extra": {"SubjectUserName": "administrator", "channel": "Security", "sim_id": random.random()}})  # R01
    return ev


def scenario_web_attack(host, t0):
    """Kịch bản 5: quét và tấn công ứng dụng web."""
    ip, ev = ATTACKER_IPS[3], []
    t = t0
    for _ in range(40):          # quét nhiều URL -> R19
        url = random.choice(["/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/backup.zip",
                             "/config.php", "/.git/config", "/api/v1/users", "/server-status"])
        ev.append(web_event(t, host, ip, "GET", url, random.choice([404, 403, 404, 401]), ua="Mozilla/5.0 zgrab/0.x"))
        t += timedelta(seconds=random.randint(1, 3))
    # Yêu cầu đáng ngờ (duyệt thư mục ngược, chèn script) + User-Agent của công cụ quét -> R11
    ev.append(web_event(t, host, ip, "GET", "/index.php?page=../../../../etc/passwd", 403,
                        ua="Mozilla/5.0", action="web_suspicious_request", severity="high", eid="web_suspicious"))
    ev.append(web_event(t + timedelta(seconds=5), host, ip, "GET", "/search?q=<script>alert(1)</script>", 200,
                        ua="sqlmap/1.7", action="web_scanner_detected", severity="high", eid="web_scanner"))
    return ip, ev


def main():
    parser = argparse.ArgumentParser(description="Sinh dữ liệu trình diễn tấn công cho Agentic SOC Platform")
    parser.add_argument("--server", default="http://127.0.0.1:5000")
    parser.add_argument("--token", default="soc-enroll-2026")
    parser.add_argument("--spread-hours", type=float, default=2.0, help="Trải sự kiện trong N giờ gần nhất")
    parser.add_argument("--no-noise", action="store_true", help="Không sinh log nền lành tính")
    args = parser.parse_args()

    random.seed(20261026)
    sender = Sender(args.server, args.token)
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=args.spread_hours)

    print("Đăng ký các máy trạm trình diễn...")
    hosts = {
        "WIN-DC01": sender.register("WIN-DC01", "windows", "Windows Server 2022", "192.168.1.10"),
        "WIN-SRV02": sender.register("WIN-SRV02", "windows", "Windows Server 2019", "192.168.1.11"),
        "ubuntu-web01": sender.register("ubuntu-web01", "linux", "Ubuntu 22.04.3 LTS", "192.168.1.20"),
        "centos-db01": sender.register("centos-db01", "linux", "CentOS Stream 9", "192.168.1.21"),
    }

    print("Sinh các kịch bản tấn công và log nền...")
    bundles = {h: [] for h in hosts}

    # Rải 5 kịch bản tại các mốc thời gian khác nhau trong cửa sổ
    def at(frac):
        return start + timedelta(seconds=(now - start).total_seconds() * frac)

    _, ev = scenario_ssh_bruteforce("centos-db01", at(0.25)); bundles["centos-db01"] += ev
    _, ev = scenario_rdp_bruteforce("WIN-SRV02", at(0.45)); bundles["WIN-SRV02"] += ev
    _, ev = scenario_password_spray("ubuntu-web01", at(0.60)); bundles["ubuntu-web01"] += ev
    ev = scenario_windows_persistence("WIN-DC01", at(0.75)); bundles["WIN-DC01"] += ev
    _, ev = scenario_web_attack("ubuntu-web01", at(0.85)); bundles["ubuntu-web01"] += ev

    # Thêm vài sự kiện lẻ: SSH root trực tiếp, tài khoản Windows bị khóa
    bundles["ubuntu-web01"].append(ssh_ok(at(0.35), "ubuntu-web01", "root", INTERNAL_IPS[0]))   # R10
    bundles["WIN-DC01"].append(win_event(at(0.5), "WIN-DC01", 4740, "account_locked_out", "medium",
                                         "Tài khoản 'jdoe' bị khóa trên WIN-DC01", "jdoe",
                                         {"TargetUserName": "jdoe"}))                             # R13

    if not args.no_noise:
        os_map = {"WIN-DC01": "windows", "WIN-SRV02": "windows", "ubuntu-web01": "web", "centos-db01": "linux"}
        for h, otype in os_map.items():
            bundles[h] += benign_noise(h, otype, start, now, n=70)

    total = 0
    for h, events in bundles.items():
        events.sort(key=lambda e: e["timestamp"])
        n = sender.send(hosts[h], events)
        total += n
        print("  -> %-14s gửi %d sự kiện" % (h, n))

    print("\nHoàn tất. Tổng %d sự kiện đã gửi tới %s" % (total, args.server))
    print("Server đang chạy luật phát hiện và tác tử AI. Mở dashboard để xem cảnh báo.")


if __name__ == "__main__":
    main()
