# -*- coding: utf-8 -*-
"""Kiểm thử nhanh bộ parser dùng chung (chạy: python tools/test_parsers.py)."""
import os
import sys
import json

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "soc_agent"))

import parsers  # noqa: E402

SAMPLES = [
    ("syslog", "Oct 26 10:15:01 web01 sshd[2231]: Failed password for root from 203.0.113.66 port 51234 ssh2"),
    ("syslog", "Oct 26 10:15:09 web01 sshd[2240]: Accepted password for root from 203.0.113.66 port 51240 ssh2"),
    ("syslog", "Oct 26 10:16:00 web01 sshd[2250]: Invalid user oracle from 198.51.100.23 port 40022"),
    ("syslog", "Oct 26 10:17:00 web01 sudo:   student : TTY=pts/0 ; PWD=/home/student ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"),
    ("syslog", "Oct 26 10:17:30 web01 sudo:   guest : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/guest ; USER=root ; COMMAND=/bin/bash"),
    ("syslog", "Oct 26 10:18:00 web01 useradd[3001]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash"),
    ("syslog", "Oct 26 10:18:05 web01 usermod[3005]: add 'backdoor' to group 'sudo'"),
    ("syslog", "2026-10-26T10:19:00.123456+07:00 web01 kernel: Out of memory: Killed process 1234 (java) total-vm:4096kB"),
    ("syslog", "<34>1 2026-10-26T03:20:00.000Z db01 su 2004 ID47 - FAILED SU (to root) attacker on /dev/pts/2"),
    ("access_log", '198.51.100.23 - - [26/Oct/2026:10:21:00 +0700] "GET /index.php?page=../../../../etc/passwd HTTP/1.1" 403 512 "-" "Mozilla/5.0"'),
    ("access_log", '198.51.100.23 - - [26/Oct/2026:10:21:05 +0700] "GET /admin/ HTTP/1.1" 404 210 "-" "sqlmap/1.7"'),
    ("access_log", '10.0.0.5 - alice [26/Oct/2026:10:22:00 +0700] "POST /login HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'),
]

WIN_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
<EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>
<Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2026-10-26T03:30:00.1234567Z'/>
<EventRecordID>88123</EventRecordID><Correlation/><Execution ProcessID='700' ThreadID='800'/>
<Channel>Security</Channel><Computer>WIN-SRV01</Computer><Security/></System>
<EventData><Data Name='SubjectUserName'>-</Data><Data Name='TargetUserName'>Administrator</Data>
<Data Name='TargetDomainName'>WIN-SRV01</Data><Data Name='Status'>0xc000006d</Data>
<Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>10</Data>
<Data Name='IpAddress'>203.0.113.66</Data><Data Name='IpPort'>50123</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><Level>4</Level>
<Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2026-10-26T03:31:00Z'/>
<EventRecordID>88124</EventRecordID><Channel>Security</Channel><Computer>WIN-SRV01</Computer></System>
<UserData><LogFileCleared><SubjectUserName>attacker</SubjectUserName><SubjectDomainName>WIN-SRV01</SubjectDomainName></LogFileCleared></UserData></Event>"""


def main():
    ok = 0
    for fmt, line in SAMPLES:
        ev = parsers.parse_line(line, fmt=fmt, default_host="test-host")
        assert ev is not None, line
        print("[%-10s] %-28s user=%-12s ip=%-15s sev=%-8s %s" % (
            fmt, ev["action"], ev["user"], ev["src_ip"], ev["severity"], ev["timestamp"]))
        ok += 1
    wins = parsers.parse_windows_event_xml(WIN_XML)
    assert len(wins) == 2, len(wins)
    for ev in wins:
        print("[windows   ] %-28s id=%s user=%-12s ip=%-15s sev=%-8s outcome=%s" % (
            ev["action"], ev["event_id"], ev["user"], ev["src_ip"], ev["severity"], ev["outcome"]))
        ok += 1
    assert wins[0]["action"] == "logon_failed" and wins[0]["src_ip"] == "203.0.113.66"
    assert wins[1]["action"] == "audit_log_cleared" and wins[1]["user"] == "attacker"
    print("\nTất cả %d mẫu được phân tích đúng." % ok)
    print(json.dumps(wins[0], ensure_ascii=False, indent=1)[:600])


if __name__ == "__main__":
    main()
