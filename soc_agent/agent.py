# -*- coding: utf-8 -*-
"""
agent.py - Chương trình client (SOC Agent) chạy trên máy Windows/Linux.

Nhiệm vụ:
  1. Đăng ký với Web SOC bằng enrollment token (nhận API key riêng, lưu vào agent_state.json).
  2. Định kỳ (mặc định 10 giây) gọi các collector để lấy log MỚI, chuẩn hóa, đưa vào hàng đợi.
  3. Gửi log theo lô về endpoint /api/v1/logs kèm header X-API-Key. Lô gửi lỗi được giữ lại
     (có giới hạn) để gửi lại, nên mất mạng tạm thời không làm mất log.
  4. Định kỳ (mặc định 60 giây) gửi heartbeat kèm số liệu CPU/RAM/đĩa (nếu có psutil).

Chỉ dùng thư viện chuẩn Python (urllib) nên chạy được trên mọi máy có Python 3.8+ mà không cần
cài thêm gói. psutil là tùy chọn để bổ sung số liệu tài nguyên.

Cách dùng:
    python agent.py --server http://IP_SOC:5000 --token soc-enroll-2026 --register
    python agent.py                         # chạy liên tục theo config.json
    python agent.py --once                  # thu thập và gửi một lần rồi thoát (dùng để kiểm thử)
"""
import argparse
import json
import os
import platform
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error
from collections import deque
from datetime import datetime, timezone

import collectors as collectors_mod

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "agent_state.json")
SPOOL_FILE = os.path.join(BASE_DIR, "agent_spool.json")     # hàng đợi chưa gửi, lưu khi dừng agent
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
AGENT_VERSION = "1.1.0"


def log(msg):
    print("[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg), flush=True)


def load_json(path, default=None):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (ValueError, OSError):
            pass
    return default if default is not None else {}


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def detect_os():
    system = platform.system().lower()
    if system == "windows":
        return "windows", "%s %s" % (platform.system(), platform.release())
    if system == "linux":
        name = "Linux"
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        name = line.split("=", 1)[1].strip().strip('"')
                        break
        except OSError:
            pass
        return "linux", name
    return "other", platform.platform()


def primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


def get_metrics():
    try:
        import psutil
        return {"cpu_percent": round(psutil.cpu_percent(interval=0.3), 1),
                "memory_percent": round(psutil.virtual_memory().percent, 1),
                "disk_percent": round(psutil.disk_usage(os.path.abspath(os.sep)).percent, 1),
                "uptime_hours": round((time.time() - psutil.boot_time()) / 3600, 1)}
    except Exception:
        try:
            load = os.getloadavg()[0] if hasattr(os, "getloadavg") else None
            return {"load_avg": round(load, 2) if load is not None else None}
        except OSError:
            return {}


class SOCAgent:
    def __init__(self, config):
        self.config = config
        self.server = config["server"].rstrip("/")
        self.verify_tls = config.get("verify_tls", True)
        self.state = load_json(STATE_FILE, {})
        self.api_key = self.state.get("api_key") or config.get("api_key")
        self.hostname = config.get("hostname") or socket.gethostname()
        self.interval = config.get("interval_seconds", 10)
        self.heartbeat_interval = config.get("heartbeat_seconds", 60)
        self.batch_size = config.get("batch_size", 500)
        self.queue = deque(maxlen=config.get("max_queue", 50000))
        self._load_spool()
        self.collectors = self._build_collectors()
        self._ssl_ctx = None
        if not self.verify_tls:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------- collectors
    def _build_collectors(self):
        states = self.state.setdefault("collector_states", {})
        specs = self.config.get("collectors")
        result = []
        if specs:
            for spec in specs:
                name = spec.get("name") or spec.get("type")
                try:
                    result.append(collectors_mod.build_collector(spec, states.setdefault(name, {}), self.hostname))
                except Exception as exc:
                    log("Bỏ qua collector %s: %s" % (name, exc))
        else:
            for c in collectors_mod.build_default_collectors(self.hostname):
                c.state = states.setdefault(c.name, {})
                result.append(c)
        log("Đã nạp %d collector: %s" % (len(result), ", ".join(c.name for c in result)))
        return result

    def _save_state(self):
        self.state["collector_states"] = {c.name: c.state for c in self.collectors}
        self.state["api_key"] = self.api_key
        self.state["hostname"] = self.hostname
        save_json(STATE_FILE, self.state)

    # ------------------------------------------------------------------ spool
    def _load_spool(self):
        """Nạp lại các sự kiện chưa gửi được từ lần chạy trước (nếu có) rồi xóa tệp spool."""
        spool = load_json(SPOOL_FILE, {})
        events = spool.get("events") if isinstance(spool, dict) else None
        if events:
            self.queue.extend(e for e in events if isinstance(e, dict))
            log("Nạp lại %d sự kiện chưa gửi từ lần chạy trước (%s)" % (len(events), SPOOL_FILE))
        if os.path.exists(SPOOL_FILE):
            try:
                os.remove(SPOOL_FILE)
            except OSError:
                pass

    def _save_spool(self):
        """Ghi hàng đợi chưa gửi ra đĩa khi agent dừng, để log không mất khi server đang offline."""
        if not self.queue:
            return
        save_json(SPOOL_FILE, {"saved_at": datetime.now(timezone.utc).isoformat(),
                               "hostname": self.hostname, "events": list(self.queue)})
        log("Đã lưu %d sự kiện chưa gửi vào %s (sẽ gửi lại khi khởi động)" % (len(self.queue), SPOOL_FILE))

    def _apply_server_config(self, cfg):
        """Áp dụng cấu hình tập trung do Web SOC gửi xuống (chu kỳ, heartbeat, kích thước lô)
        khi config.json đặt follow_server_config = true."""
        if not isinstance(cfg, dict) or not self.config.get("follow_server_config", False):
            return
        changed = []
        for key, attr in (("interval_seconds", "interval"), ("heartbeat_seconds", "heartbeat_interval"),
                          ("batch_size", "batch_size")):
            val = cfg.get(key)
            if isinstance(val, int) and val > 0 and getattr(self, attr) != val:
                setattr(self, attr, val)
                changed.append("%s=%d" % (key, val))
        if changed:
            log("Áp dụng cấu hình từ server: %s" % ", ".join(changed))

    # ---------------------------------------------------------------- network
    def _request(self, path, payload, headers=None, timeout=30):
        url = self.server + path
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "SOC-Agent/%s" % AGENT_VERSION)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ssl_ctx) as resp:
                text = resp.read().decode("utf-8", "replace")
                try:
                    return resp.status, json.loads(text)
                except ValueError:          # proxy/máy chủ trả HTML thay vì JSON
                    return resp.status, text
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            try:
                body = json.loads(body)
            except ValueError:
                pass
            return e.code, body
        except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
            return None, str(e)

    def register(self, token):
        os_type, os_version = detect_os()
        payload = {"enrollment_token": token, "hostname": self.hostname, "os_type": os_type,
                   "os_version": os_version, "ip_address": primary_ip(), "agent_version": AGENT_VERSION,
                   "collectors": [c.describe() for c in self.collectors]}
        status, body = self._request("/api/v1/agents/register", payload)
        if status == 201 and isinstance(body, dict):
            self.api_key = body["api_key"]
            self.state["api_key"] = self.api_key
            self.state["agent_uid"] = body.get("agent_uid")
            self._save_state()
            self._apply_server_config(body.get("config"))
            log("Đăng ký thành công. Hostname=%s, agent_uid=%s" % (self.hostname, body.get("agent_uid")))
            log("Đã lưu API key vào %s" % STATE_FILE)
            return True
        log("Đăng ký THẤT BẠI (HTTP %s): %s" % (status, body))
        return False

    def send_heartbeat(self):
        if not self.api_key:
            return
        payload = {"metrics": {**get_metrics(), "queue_size": len(self.queue)},
                   "collectors": [c.describe() for c in self.collectors],
                   "agent_version": AGENT_VERSION, "ip_address": primary_ip()}
        status, body = self._request("/api/v1/agents/heartbeat", payload, {"X-API-Key": self.api_key})
        if status == 401:
            log("Heartbeat bị từ chối (API key không hợp lệ). Hãy đăng ký lại bằng --register.")
        elif status == 200 and isinstance(body, dict):
            self._apply_server_config(body.get("config"))

    def flush_queue(self):
        """Gửi các sự kiện trong hàng đợi theo lô. Giữ lại lô gửi lỗi để thử lần sau."""
        sent = 0
        while self.queue:
            batch = [self.queue.popleft() for _ in range(min(self.batch_size, len(self.queue)))]
            status, body = self._request("/api/v1/logs", {"events": batch}, {"X-API-Key": self.api_key})
            if status == 200 and isinstance(body, dict):
                sent += body.get("accepted", 0)
                if body.get("alerts_new"):
                    log("Server phát sinh %d cảnh báo mới (AI đã khởi chạy: %s)" %
                        (body["alerts_new"], body.get("ai_started", 0)))
            elif status == 401:
                log("API key không hợp lệ - cần đăng ký lại. Giữ lại %d sự kiện." % len(batch))
                self.queue.extendleft(reversed(batch))
                return sent
            else:
                # Lỗi mạng/máy chủ: trả sự kiện về đầu hàng đợi, thử lại sau
                self.queue.extendleft(reversed(batch))
                log("Gửi lô thất bại (HTTP %s). Sẽ thử lại. Hàng đợi: %d" % (status, len(self.queue)))
                return sent
        return sent

    # -------------------------------------------------------------------- run
    def collect_once(self):
        total = 0
        for c in self.collectors:
            try:
                events = c.collect()
            except Exception as exc:
                log("Collector %s lỗi: %s" % (c.name, exc))
                continue
            for ev in events:
                self.queue.append(ev)
            total += len(events)
        if total:
            log("Thu thập %d sự kiện mới (hàng đợi: %d)" % (total, len(self.queue)))
        return total

    def run_once(self):
        if not self.api_key:
            log("Chưa có API key. Chạy với --register trước.")
            return
        self.collect_once()
        sent = self.flush_queue()
        self.send_heartbeat()
        self._save_state()
        log("Đã gửi %d sự kiện." % sent)

    def run_forever(self):
        if not self.api_key:
            log("Chưa có API key. Chạy với --register trước.")
            return
        log("SOC Agent khởi động. Server=%s, chu kỳ %ds, heartbeat %ds" %
            (self.server, self.interval, self.heartbeat_interval))
        self.send_heartbeat()
        last_hb = last_save = time.time()
        try:
            while True:
                try:
                    self.collect_once()
                    self.flush_queue()
                    now = time.time()
                    if now - last_hb >= self.heartbeat_interval:
                        self.send_heartbeat()
                        last_hb = now
                    if now - last_save >= 30:
                        self._save_state()
                        last_save = now
                except Exception as exc:      # một chu kỳ lỗi không được làm chết agent
                    log("Lỗi trong chu kỳ thu thập/gửi: %s: %s" % (type(exc).__name__, exc))
                time.sleep(self.interval)
        except KeyboardInterrupt:
            log("Dừng agent (Ctrl+C). Lưu trạng thái...")
        finally:
            self._save_state()
            self._save_spool()


def load_config(args):
    config = load_json(CONFIG_FILE, {})
    if args.server:
        config["server"] = args.server
    if args.hostname:
        config["hostname"] = args.hostname
    if not config.get("server"):
        config["server"] = "http://127.0.0.1:5000"
    return config


def main():
    parser = argparse.ArgumentParser(description="Agentic SOC Platform - SOC Agent (client thu thập log)")
    parser.add_argument("--server", help="URL Web SOC, vd http://192.168.1.10:5000")
    parser.add_argument("--token", help="Enrollment token để đăng ký")
    parser.add_argument("--hostname", help="Ghi đè hostname")
    parser.add_argument("--register", action="store_true", help="Đăng ký với server rồi tiếp tục chạy")
    parser.add_argument("--once", action="store_true", help="Thu thập và gửi một lần rồi thoát")
    parser.add_argument("--no-verify-tls", action="store_true", help="Bỏ qua kiểm tra chứng chỉ TLS (chỉ dùng trong LAB)")
    args = parser.parse_args()

    config = load_config(args)
    if args.no_verify_tls:
        config["verify_tls"] = False
    agent = SOCAgent(config)

    if args.register:
        token = args.token or config.get("enrollment_token")
        if not token:
            log("Thiếu enrollment token (dùng --token hoặc đặt trong config.json).")
            sys.exit(1)
        if not agent.register(token):
            sys.exit(2)
        if args.once:
            agent.run_once()
            return
        agent.run_forever()
    elif args.once:
        agent.run_once()
    else:
        agent.run_forever()


if __name__ == "__main__":
    main()
