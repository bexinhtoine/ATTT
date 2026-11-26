# -*- coding: utf-8 -*-
"""
collectors.py - Các bộ thu thập log của SOC Agent.

Mỗi collector có phương thức collect() trả về danh sách sự kiện đã CHUẨN HÓA (cùng lược đồ với
parsers.py). Collector lưu "con trỏ" (cursor/offset) để chỉ gửi phần log MỚI so với lần trước:

  FileCollector            đọc tệp log văn bản (syslog, auth.log, access log...), nhớ vị trí byte +
                           inode/kích thước để xử lý log xoay vòng (rotate).
  WindowsEventLogCollector đọc Windows Event Log bằng wevtutil (/f:RenderedXml), nhớ EventRecordID lớn nhất.
  JournaldCollector        đọc systemd journal bằng journalctl -o json, nhớ con trỏ (cursor).

State (con trỏ) được orchestrator trong agent.py lưu ra tệp JSON để bền vững qua các lần khởi động.
"""
import os
import re
import json
import subprocess
import sys

import parsers

IS_WINDOWS = sys.platform.startswith("win")


class BaseCollector:
    type = "base"

    def __init__(self, name, state=None, host=None):
        self.name = name
        self.state = state if state is not None else {}
        self.host = host

    def collect(self):
        return []

    def describe(self):
        return {"type": self.type, "name": self.name}


# ---------------------------------------------------------------------------
class FileCollector(BaseCollector):
    """Đọc phần mới của một tệp log văn bản. fmt: syslog | access_log | plain."""
    type = "file"

    def __init__(self, name, path, fmt="syslog", source=None, state=None, host=None, max_lines=5000):
        super().__init__(name, state, host)
        self.path = path
        self.fmt = fmt
        self.source = source
        self.max_lines = max_lines

    def describe(self):
        return {"type": self.type, "name": self.name, "path": self.path, "format": self.fmt}

    def collect(self):
        if not os.path.exists(self.path):
            raise FileNotFoundError(self.path)
        try:
            size = os.path.getsize(self.path)
            inode = getattr(os.stat(self.path), "st_ino", 0)
        except OSError:
            raise
        offset = self.state.get("offset", None)
        prev_inode = self.state.get("inode")
        # Lần đầu: bắt đầu từ cuối tệp để không gửi ồ ạt toàn bộ lịch sử
        if offset is None:
            self.state.update({"offset": size, "inode": inode})
            return []
        # Tệp bị cắt/xoay vòng -> đọc lại từ đầu
        if size < offset or (prev_inode and inode and prev_inode != inode):
            offset = 0
        events, lines_read = [], 0
        try:
            # Mở ở chế độ nhị phân: ở chế độ văn bản Python cấm gọi tell() trong vòng lặp
            # `for line in f` (OSError "telling position disabled by next() call"), nên con trỏ
            # byte phải được lấy bằng readline() từng dòng.
            with open(self.path, "rb") as f:
                actual = os.fstat(f.fileno())
                inode = getattr(actual, "st_ino", 0)
                if actual.st_size < offset or (prev_inode and inode and prev_inode != inode):
                    offset = 0
                f.seek(offset)
                while lines_read < self.max_lines:
                    pos = f.tell()
                    raw = f.readline()
                    if not raw:
                        break
                    if not raw.endswith(b"\n"):
                        f.seek(pos)          # dòng cuối chưa ghi xong -> để lần sau đọc lại
                        break
                    lines_read += 1
                    line = raw.decode("utf-8", "replace")
                    ev = parsers.parse_line(line, self.source, self.host, self.fmt)
                    if ev:
                        ev.setdefault("extra", {})["offset"] = f.tell()
                        events.append(ev)
                offset = f.tell()
        except OSError:
            raise
        self.state.update({"offset": offset, "inode": inode})
        return events


# ---------------------------------------------------------------------------
class WindowsEventLogCollector(BaseCollector):
    """Đọc Windows Event Log qua wevtutil. channel: Security | System | Application ..."""
    type = "winevt"

    def __init__(self, name, channel, event_ids=None, state=None, host=None, max_events=800):
        super().__init__(name, state, host)
        self.channel = channel
        self.event_ids = event_ids or []
        self.max_events = max_events

    def describe(self):
        return {"type": self.type, "name": self.name, "channels": [self.channel]}

    def _query(self, xpath, count, newest_first=True):
        """Gọi wevtutil. newest_first=True đọc từ bản ghi mới nhất (dùng để lấy mốc ban đầu);
        False đọc theo thứ tự cũ -> mới để không bỏ sót khi số sự kiện mới vượt quá max_events."""
        cmd = ["wevtutil", "qe", self.channel, "/q:%s" % xpath, "/f:RenderedXml",
               "/c:%d" % count, "/rd:%s" % ("true" if newest_first else "false"), "/e:Events"]
        out = subprocess.run(cmd, capture_output=True, timeout=60,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if out.returncode != 0:
            raise RuntimeError(out.stderr.decode("utf-8", "replace")[:300])
        return out.stdout.decode("utf-8", "replace")

    def collect(self):
        if not IS_WINDOWS:
            return []
        last_record = int(self.state.get("last_record", 0))
        # Lọc theo EventRecordID > last_record; nếu có danh sách EventID thì lọc luôn
        id_filter = ""
        if self.event_ids:
            id_filter = "(" + " or ".join("EventID=%s" % e for e in self.event_ids) + ")"
        # Lần đầu (last_record = 0): chỉ lấy bản ghi MỚI NHẤT của kênh để ghi nhận mốc,
        # không gửi lịch sử ồ ạt về server
        if not last_record and not self.state.get("initialized"):
            try:
                xml = self._query("*", 1, newest_first=True)
            except Exception as exc:
                raise RuntimeError("Không đọc được kênh %s: %s" % (self.channel, exc)) from exc
            events = parsers.parse_windows_event_xml(xml)
            if events:
                self.state["last_record"] = max(int((e.get("extra") or {}).get("record_id") or 0) for e in events)
            self.state["initialized"] = True
            return []
        xpath = "*[System[%sEventRecordID>%d]]" % (id_filter + " and " if id_filter else "", last_record)
        try:
            # Đọc theo thứ tự cũ -> mới: nếu có nhiều hơn max_events sự kiện mới thì lấy phần đầu,
            # phần còn lại sẽ được lấy ở chu kỳ sau (không bị "nhảy cóc" như khi đọc ngược)
            xml = self._query(xpath, self.max_events, newest_first=False)
        except Exception as exc:
            # Reading only the newest 200 records here could silently skip backlog.
            raise RuntimeError("Không đọc được kênh %s: %s" % (self.channel, exc)) from exc
        events = parsers.parse_windows_event_xml(xml)
        if not events and last_record:
            newest = parsers.parse_windows_event_xml(self._query("*", 1, newest_first=True))
            newest_record = max((int((e.get("extra") or {}).get("record_id") or 0) for e in newest), default=0)
            if 0 < newest_record < last_record:
                # Channel was cleared/reset. Read forward from its current beginning.
                xml = self._query("*[System[%s]]" % id_filter if id_filter else "*",
                                  self.max_events, newest_first=False)
                events = parsers.parse_windows_event_xml(xml)
                last_record = 0
        fresh, max_rec = [], last_record
        for ev in events:
            rec = int((ev.get("extra") or {}).get("record_id") or 0)
            if rec <= last_record:
                continue
            max_rec = max(max_rec, rec)
            fresh.append(ev)
        self.state["last_record"] = max_rec
        fresh.sort(key=lambda e: int((e.get("extra") or {}).get("record_id") or 0))
        return fresh


# ---------------------------------------------------------------------------
class JournaldCollector(BaseCollector):
    """Đọc systemd journal qua journalctl -o json, dùng con trỏ (cursor)."""
    type = "journald"

    def __init__(self, name, units=None, state=None, host=None, max_events=2000):
        super().__init__(name, state, host)
        self.units = units or []
        self.max_events = max_events

    def describe(self):
        return {"type": self.type, "name": self.name, "units": self.units}

    def collect(self):
        if IS_WINDOWS:
            return []
        cursor = self.state.get("cursor")
        cmd = ["journalctl", "-o", "json", "--no-pager", "-q"]
        for u in self.units:
            cmd += ["-u", u]
        if cursor:
            cmd += ["--after-cursor", cursor]
        else:
            cmd += ["-n", "0", "--show-cursor"]      # lần đầu chỉ lấy con trỏ hiện tại
        try:
            out = subprocess.run(cmd, capture_output=True, timeout=60)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            raise
        if out.returncode != 0:
            raise RuntimeError("journalctl thất bại: %s" % out.stderr.decode("utf-8", "replace")[:300])
        text = out.stdout.decode("utf-8", "replace")
        events, last_cursor, n = [], cursor, 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("-- cursor:"):
                last_cursor = line.split("-- cursor:", 1)[1].strip()
                continue
            if n >= self.max_events:
                break
            try:
                j = json.loads(line)
            except ValueError:
                continue
            last_cursor = j.get("__CURSOR", last_cursor)
            if cursor is None:
                continue
            ev = self._normalize_journal(j)
            if ev:
                events.append(ev)
            n += 1
        if last_cursor:
            self.state["cursor"] = last_cursor
        return events

    def _normalize_journal(self, j):
        ident = j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or "journald"
        msg = j.get("MESSAGE")
        if isinstance(msg, list):
            msg = "".join(chr(b) if isinstance(b, int) else str(b) for b in msg)
        line = "%s[%s]: %s" % (ident, j.get("_PID", ""), msg or "")
        ev = parsers.parse_syslog_line(line, None, j.get("_HOSTNAME") or self.host)
        ev["source"] = "journald" if ev["source"] == "linux.syslog" else ev["source"]
        rt = j.get("__REALTIME_TIMESTAMP")
        if rt:
            try:
                from datetime import datetime, timezone
                ev["timestamp"] = parsers.to_iso(datetime.fromtimestamp(int(rt) / 1_000_000, tz=timezone.utc))
            except (ValueError, OSError):
                pass
        pr = j.get("PRIORITY")
        if pr is not None and ev.get("action") == "log":
            try:
                ev["severity"] = parsers.SYSLOG_SEVERITY_MAP.get(int(pr), ev["severity"])
            except (ValueError, TypeError):
                pass
        ev.setdefault("extra", {})["cursor"] = j.get("__CURSOR")
        ev["extra"]["unit"] = j.get("_SYSTEMD_UNIT")
        return ev


# ---------------------------------------------------------------------------
DEFAULT_LINUX_AUTH = ["/var/log/auth.log", "/var/log/secure"]
DEFAULT_LINUX_SYS = ["/var/log/syslog", "/var/log/messages"]


def build_default_collectors(host):
    """Tạo bộ collector mặc định theo hệ điều hành."""
    collectors = []
    if IS_WINDOWS:
        collectors.append(WindowsEventLogCollector("windows-security", "Security",
                          event_ids=[4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4699, 4719,
                                     4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733,
                                     4738, 4740, 4756, 4767, 4768, 4769, 4771, 4776, 1102], host=host))
        collectors.append(WindowsEventLogCollector("windows-system", "System",
                          event_ids=[7045, 7034, 7036, 7040, 104, 6005, 6006, 6008, 1074], host=host))
        collectors.append(WindowsEventLogCollector("windows-application", "Application",
                          event_ids=[1000, 1001, 1002], host=host))
    else:
        for p in DEFAULT_LINUX_AUTH:
            if os.path.exists(p):
                collectors.append(FileCollector("linux-auth", p, "syslog", "linux.auth", host=host))
                break
        for p in DEFAULT_LINUX_SYS:
            if os.path.exists(p):
                collectors.append(FileCollector("linux-syslog", p, "syslog", "linux.syslog", host=host))
                break
        # Nếu không có tệp log truyền thống (hệ chỉ dùng journald) thì dùng journald
        if not collectors:
            collectors.append(JournaldCollector("journald", host=host))
    return collectors


def build_collector(spec, state, host):
    """Tạo collector từ cấu hình trong config.json."""
    t = spec.get("type")
    name = spec.get("name") or t
    if t == "file":
        return FileCollector(name, spec["path"], spec.get("format", "syslog"), spec.get("source"), state, host)
    if t == "winevt":
        return WindowsEventLogCollector(name, spec.get("channel", "Security"), spec.get("event_ids"), state, host)
    if t == "journald":
        return JournaldCollector(name, spec.get("units"), state, host)
    raise ValueError("Loại collector không hỗ trợ: %s" % t)
