# -*- coding: utf-8 -*-
"""
Kiểm thử các collector của SOC Agent (chạy: python tools/test_collectors.py).

Kiểm tra FileCollector: lần đầu chỉ ghi nhận mốc, đọc đúng phần mới, giữ lại dòng chưa ghi xong,
xử lý tệp bị xoay vòng (truncate), và JournaldCollector chuẩn hóa bản ghi JSON của journalctl.
"""
import os
import sys
import json
import tempfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "soc_agent"))

import collectors  # noqa: E402

LINE_FAIL = "Oct 26 10:15:01 web01 sshd[2231]: Failed password for root from 203.0.113.66 port 51234 ssh2\n"
LINE_OK = "Oct 26 10:15:09 web01 sshd[2240]: Accepted password for alice from 10.0.0.5 port 51240 ssh2\n"


def test_file_collector():
    tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8")
    tmp.write("Oct 26 09:00:00 web01 cron[1]: (root) CMD (/bin/true)\n" * 5)   # lịch sử cũ
    tmp.close()
    path = tmp.name
    try:
        c = collectors.FileCollector("t", path, "syslog", "linux.auth", state={}, host="web01")
        assert c.collect() == [], "lần đầu phải bỏ qua lịch sử cũ"
        assert c.state["offset"] == os.path.getsize(path)

        with open(path, "a", encoding="utf-8") as f:
            f.write(LINE_FAIL + LINE_OK)
        ev = c.collect()
        assert [e["action"] for e in ev] == ["logon_failed", "logon_success"], ev
        assert ev[0]["src_ip"] == "203.0.113.66" and ev[0]["user"] == "root"
        assert ev[1]["extra"]["offset"] == os.path.getsize(path)
        print("  [file] đọc phần mới: 2 sự kiện, action =", [e["action"] for e in ev])

        with open(path, "a", encoding="utf-8") as f:
            f.write("Oct 26 10:16:00 web01 sshd[2250]: Invalid user oracle from 198.51")  # chưa có \n
        assert c.collect() == [], "dòng chưa ghi xong phải được giữ lại"
        with open(path, "a", encoding="utf-8") as f:
            f.write(".100.23 port 40022\n")
        ev = c.collect()
        assert len(ev) == 1 and ev[0]["action"] == "invalid_user" and ev[0]["src_ip"] == "198.51.100.23", ev
        print("  [file] dòng ghi dở được ghép lại đúng:", ev[0]["message"])

        # Xoay vòng: tệp bị cắt về rỗng rồi ghi dòng mới -> đọc lại từ đầu
        with open(path, "w", encoding="utf-8") as f:
            f.write(LINE_OK)
        ev = c.collect()
        assert len(ev) == 1 and ev[0]["action"] == "logon_success", ev
        print("  [file] xử lý xoay vòng (truncate) đúng")
        assert c.collect() == []
    finally:
        os.remove(path)


def test_journald_normalize():
    c = collectors.JournaldCollector("j", host="db01")
    rec = {"SYSLOG_IDENTIFIER": "sshd", "_PID": "812", "_HOSTNAME": "db01", "PRIORITY": "6",
           "__REALTIME_TIMESTAMP": "1761472800000000", "__CURSOR": "s=abc;i=1",
           "MESSAGE": "Failed password for invalid user admin from 192.0.2.77 port 4000 ssh2",
           "_SYSTEMD_UNIT": "ssh.service"}
    ev = c._normalize_journal(rec)
    assert ev["action"] == "logon_failed" and ev["user"] == "admin" and ev["src_ip"] == "192.0.2.77", ev
    assert ev["source"] == "journald" or ev["source"] == "linux.auth"
    assert ev["extra"]["cursor"] == "s=abc;i=1" and ev["extra"]["unit"] == "ssh.service"
    assert ev["timestamp"].startswith("2025-10-26")
    print("  [journald] chuẩn hóa bản ghi JSON đúng:", json.dumps(
        {k: ev[k] for k in ("timestamp", "action", "user", "src_ip", "severity")}, ensure_ascii=False))


def main():
    test_file_collector()
    test_journald_normalize()
    print("\nTất cả kiểm thử collector đạt.")


if __name__ == "__main__":
    main()
