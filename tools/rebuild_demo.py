# -*- coding: utf-8 -*-
"""
rebuild_demo.py - Tạo lại cơ sở dữ liệu trình diễn bằng mã nguồn hiện tại.

    python tools/rebuild_demo.py [--port 5055]

Các bước: sao lưu soc_server/instance/soc.db -> soc.db.bak (nếu chưa có), xóa CSDL cũ, khởi động Web SOC
tạm trên cổng riêng, chạy tools/demo_attack.py, chờ tác tử tự động phân loại, tắt server, rồi chạy thêm
Investigation/Knowledge cho các cảnh báo tiêu biểu và đóng một vài cảnh báo để có số liệu MTTR.
"""
import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_DIR = os.path.join(ROOT, "soc_server")
# CSDL trình diễn riêng (soc_demo.db) để không đụng tới soc.db đang được Web SOC của người dùng mở
DB = os.path.join(SERVER_DIR, "instance", "soc_demo.db")
DB_URI = "sqlite:///" + DB.replace("\\", "/")


def wait_http(url, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            urllib.request.urlopen(url, timeout=3)
            return True
        except Exception:
            time.sleep(1)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5055)
    args = ap.parse_args()
    url = "http://127.0.0.1:%d" % args.port

    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(DB + suffix):
            os.remove(DB + suffix)

    env = dict(os.environ, SOC_AI_AUTO_TRIAGE="1", PYTHONIOENCODING="utf-8", SOC_DATABASE_URI=DB_URI)
    os.environ["SOC_DATABASE_URI"] = DB_URI
    env.pop("ANTHROPIC_API_KEY", None)          # chế độ cục bộ để kết quả tái lập được
    server = subprocess.Popen([sys.executable, "run.py", "--port", str(args.port)], cwd=SERVER_DIR, env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_http(url + "/login"):
            raise SystemExit("Web SOC không khởi động được")
        print("Web SOC tạm đang chạy tại", url)
        subprocess.run([sys.executable, os.path.join(ROOT, "tools", "demo_attack.py"), "--server", url], check=True, env=env)
        print("Chờ tác tử tự động phân loại...")
        time.sleep(20)
    finally:
        server.terminate()
        try:
            server.wait(10)
        except subprocess.TimeoutExpired:
            server.kill()
    time.sleep(2)

    sys.path.insert(0, SERVER_DIR)
    from app import create_app
    from app.extensions import db
    from app.models import Alert, AIRun, LogEvent, utcnow

    app = create_app(start_background=False)
    with app.app_context():
        orch = app.extensions["soc_orchestrator"]
        # Bảo đảm mọi cảnh báo đều đã enrich + triage (phòng khi luồng nền chưa kịp)
        for a in Alert.query.all():
            if not a.ai_verdict:
                orch.run(a.id, ("enrich", "triage"), trigger="auto")
        # Điều tra sâu các cảnh báo tiêu biểu
        picks = []
        for code in ("R18", "R01", "R17", "R21"):
            for a in Alert.query.join(Alert.rule).filter_by(code=code).all():
                picks.append(a.id)
        for aid in picks:
            orch.run(aid, ("investigate",), trigger="manual", username="analyst")
        # Đóng cảnh báo R18 đầu tiên và trích tri thức, đóng một cảnh báo R19 là dương tính giả
        first = Alert.query.join(Alert.rule).filter_by(code="R18").order_by(Alert.id).first()
        if first:
            first.status, first.resolution_note = "resolved", "Đã chặn IP tại firewall, đặt lại mật khẩu root, tắt PasswordAuthentication."
            first.resolved_at = utcnow()
            db.session.commit()
            orch.run(first.id, ("knowledge",), trigger="manual", username="analyst")
        fp = Alert.query.join(Alert.rule).filter_by(code="R19").first()
        if fp:
            fp.status, fp.resolution_note, fp.resolved_at = "false_positive", "Máy quét lỗ hổng nội bộ theo lịch.", utcnow()
            db.session.commit()
        print("Sự kiện:", LogEvent.query.count(), "| Cảnh báo:", Alert.query.count(), "| Lượt AI:", AIRun.query.count())
        for a in Alert.query.order_by(Alert.id).all():
            print("  #%-2d %s %-8s P%s %-22s %s" % (a.id, a.rule.code if a.rule else "?", a.severity, a.ai_priority, a.ai_verdict, a.title[:70]))


if __name__ == "__main__":
    main()
