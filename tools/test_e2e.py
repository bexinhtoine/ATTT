# -*- coding: utf-8 -*-
"""
Kiểm thử toàn tuyến Web SOC bằng Flask test client (không cần chạy server, dùng CSDL tạm).

    python tools/test_e2e.py

Kịch bản: đăng ký agent -> gửi lô log dò mật khẩu SSH rồi đăng nhập thành công -> luật R15/R18
sinh cảnh báo -> gửi lại lô cũ không tạo bản ghi trùng -> đăng nhập web (CSRF) -> chạy tác tử
Triage/Investigation/Knowledge ở chế độ cục bộ qua API -> kiểm tra dashboard/stats/CSV.
"""
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "soc_server"))

from config import Config  # noqa: E402
from app import create_app  # noqa: E402

TMP_DB = os.path.join(tempfile.mkdtemp(prefix="soc_test_"), "test.db")


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + TMP_DB.replace("\\", "/")
    AI_AUTO_TRIAGE = False          # không chạy luồng nền để kết quả kiểm thử xác định
    ANTHROPIC_API_KEY = None        # ép chế độ suy luận cục bộ


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ssh_fail(ts, host, user, ip, i):
    msg = "Failed password for %s from %s port %d ssh2" % (user, ip, 40000 + i)
    return {"timestamp": iso(ts), "source": "linux.auth", "category": "authentication", "action": "logon_failed",
            "outcome": "failure", "severity": "medium", "event_id": "ssh_failed_password", "message": msg,
            "user": user, "src_ip": ip, "process": "sshd", "host": host, "raw": "%s sshd[%d]: %s" % (host, 100 + i, msg)}


def main():
    app = create_app(TestConfig, start_background=False)
    client = app.test_client()
    passed = 0

    # 1) Đăng ký agent sai token -> 403; đúng token -> 201 + api_key
    r = client.post("/api/v1/agents/register", json={"enrollment_token": "sai", "hostname": "db01"})
    assert r.status_code == 403, r.data
    r = client.post("/api/v1/agents/register", json={"enrollment_token": Config.ENROLLMENT_TOKEN, "hostname": "db01",
                                                      "os_type": "linux", "os_version": "Ubuntu 22.04"})
    assert r.status_code == 201, r.data
    key = r.get_json()["api_key"]
    assert r.get_json()["config"]["interval_seconds"] == Config.AGENT_INTERVAL_SECONDS
    print("1. Đăng ký agent: OK (api_key %s...)" % key[:8]); passed += 1

    # 2) Gửi log không có API key -> 401; có key -> 200
    now = datetime.now(timezone.utc)
    events = [ssh_fail(now - timedelta(seconds=60 - 3 * i), "db01", "root", "203.0.113.66", i) for i in range(8)]
    ok_msg = "Accepted password for root from 203.0.113.66 port 40999 ssh2"
    events.append({"timestamp": iso(now), "source": "linux.auth", "category": "authentication", "action": "logon_success",
                   "outcome": "success", "severity": "info", "event_id": "ssh_accepted", "message": ok_msg,
                   "user": "root", "src_ip": "203.0.113.66", "process": "sshd", "host": "db01", "raw": "db01 sshd: " + ok_msg})
    # Một dòng log THÔ để server tự phân tích
    events.append({"raw": "Oct 26 10:18:00 db01 useradd[3001]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor",
                   "source": "linux.auth", "format": "syslog"})
    assert client.post("/api/v1/logs", json={"events": events}).status_code == 401
    r = client.post("/api/v1/logs", json={"events": events}, headers={"X-API-Key": key})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["accepted"] == 10 and body["rejected"] == 0, body
    assert body["alerts_new"] >= 3, body          # R15 (brute force), R18 (thành công sau thất bại), R08 (useradd), R10 (root ssh)
    print("2. Gửi 10 sự kiện -> %d cảnh báo mới (R15/R18/R08/R10): OK" % body["alerts_new"]); passed += 1

    # 3) Gửi lại đúng lô cũ -> toàn bộ là bản trùng
    r = client.post("/api/v1/logs", json={"events": events}, headers={"X-API-Key": key}).get_json()
    assert r["accepted"] == 0 and r["duplicates"] == 10, r
    print("3. Chống trùng khi gửi lại lô: OK (duplicates=%d)" % r["duplicates"]); passed += 1

    # 4) Heartbeat
    r = client.post("/api/v1/agents/heartbeat", json={"metrics": {"cpu_percent": 12.5}}, headers={"X-API-Key": key})
    assert r.status_code == 200 and r.get_json()["ok"]
    print("4. Heartbeat: OK"); passed += 1

    # 5) Đăng nhập web: thiếu CSRF -> 403; có CSRF -> chuyển hướng dashboard
    r = client.post("/login", data={"username": "admin", "password": "Admin@123"})
    assert r.status_code == 403, r.status_code
    page = client.get("/login").get_data(as_text=True)
    token = re.search(r'name="_csrf_token" value="([^"]+)"', page).group(1)
    r = client.post("/login", data={"username": "admin", "password": "sai", "_csrf_token": token})
    assert r.status_code == 200 and "không đúng" in r.get_data(as_text=True)
    r = client.post("/login", data={"username": "admin", "password": "Admin@123", "_csrf_token": token})
    assert r.status_code == 302 and r.headers["Location"].endswith("/"), (r.status_code, r.headers.get("Location"))
    # Đăng nhập thành công làm mới phiên (chống session fixation) -> token CSRF mới nằm trong thẻ meta
    page = client.get("/").get_data(as_text=True)
    new_token = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    assert new_token != token
    token = new_token
    print("5. Đăng nhập web + chống CSRF (token đổi sau đăng nhập): OK"); passed += 1

    # 6) Dashboard, stats, trang log, xuất CSV
    assert client.get("/").status_code == 200
    stats = client.get("/api/v1/stats").get_json()
    assert stats["kpi"]["events_total"] == 10 and stats["kpi"]["alerts_open"] >= 3, stats["kpi"]
    assert client.get("/logs?src_ip=203.0.113.66&severity=medium,info").status_code == 200
    assert client.get("/logs?agent_id=abc").status_code == 200       # tham số sai không gây 500
    assert client.get("/api/v1/events?limit=xyz&offset=-5").status_code == 200
    csv_text = client.get("/logs/export.csv").get_data(as_text=True)
    assert csv_text.count("\n") >= 11, csv_text[:200]
    print("6. Dashboard/stats/log/CSV: OK (%d sự kiện, %d cảnh báo mở)" % (
        stats["kpi"]["events_total"], stats["kpi"]["alerts_open"])); passed += 1

    # 7) Chạy tác tử AI (cục bộ) cho cảnh báo R18 qua API JSON với header CSRF
    seq_alert = next(a for a in stats["latest_alerts"] if "THÀNH CÔNG" in a["title"])
    headers = {"X-CSRF-Token": token}
    assert client.post("/api/v1/alerts/%d/ai/triage" % seq_alert["id"]).status_code == 403   # thiếu CSRF header
    r = client.post("/api/v1/alerts/%d/ai/full" % seq_alert["id"], headers=headers)
    assert r.status_code == 200, r.data
    out = r.get_json()
    tri = out["ai_data"]["triage"]
    assert tri["verdict"] in ("true_positive", "likely_true_positive") and tri["priority"] <= 2, tri
    inv = out["ai_data"]["investigation"]
    assert inv["attack_chain"] and inv["iocs"]["ips"] == ["203.0.113.66"], inv
    assert out["alert"]["status"] == "investigating"
    print("7. Tác tử Triage/Investigation cục bộ: verdict=%s, P%d, điểm %d, %d kỹ thuật ATT&CK: OK" % (
        tri["verdict"], tri["priority"], tri["risk_score"], len(inv["attack_chain"]))); passed += 1

    # 8) Đóng cảnh báo + trích xuất tri thức qua form
    r = client.post("/alerts/%d/update" % seq_alert["id"], data={"status": "resolved", "note": "Đã chặn IP",
                                                                  "extract_knowledge": "1", "_csrf_token": token})
    assert r.status_code == 302
    page = client.get("/kb").get_data(as_text=True)
    assert "Bài học" in page
    print("8. Đóng cảnh báo + Knowledge Agent sinh bài học: OK"); passed += 1

    # 9) Trang chi tiết cảnh báo và báo cáo
    assert client.get("/alerts/%d" % seq_alert["id"]).status_code == 200
    assert client.get("/reports").status_code == 200
    assert client.get("/rules").status_code == 200
    print("9. Các trang chi tiết/báo cáo/luật: OK"); passed += 1

    print("\nTất cả %d bước kiểm thử toàn tuyến đạt. CSDL tạm: %s" % (passed, TMP_DB))


if __name__ == "__main__":
    main()
