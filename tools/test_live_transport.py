"""Real HTTP/agent/worker/restart smoke test, isolated from project runtime DB."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from http.cookiejar import CookieJar
from urllib.request import build_opener, HTTPCookieProcessor, Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "soc_server"))
sys.path.insert(0, str(ROOT / "soc_agent"))
from agent import SOCAgent
from app import create_app
from app.extensions import db
from app.models import Agent, LogEvent, WorkJob, dumps, utcnow
from app.ingest import ingest
from app.work import enqueue
from config import Config

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


class LiveTransportTest(unittest.TestCase):
    def test_agent_http_worker_and_restart(self):
        with tempfile.TemporaryDirectory(prefix="soc_live_") as directory:
            root = Path(directory)
            database = root / "server.db"
            class C(Config):
                SQLALCHEMY_DATABASE_URI = "sqlite:///" + database.as_posix()
                AI_AUTO_TRIAGE = False
                ANTHROPIC_API_KEY = None
                SECRET_KEY = "live-test-secret"
                ENROLLMENT_TOKEN = "live-test-token"
            app = create_app(C, start_background=False)
            with app.app_context():
                agent = Agent(hostname="recovery-source", events_count=0)
                db.session.add(agent)
                db.session.commit()
                result = ingest(agent, [{"event_uid": "before-restart", "action": "health_check",
                                         "message": "persisted before worker startup"}], run_rules=False)
                job = enqueue("detection", {"event_ids": result["event_ids"]})
                job.status, job.lease_until = "running", utcnow() - timedelta(minutes=1)
                db.session.commit()
                db.session.remove()
                db.engine.dispose()

            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            base = "http://127.0.0.1:%d" % port
            child = """
import os,sys
sys.path.insert(0,sys.argv[1])
from config import Config
from app import create_app
class C(Config):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + sys.argv[2]
    SECRET_KEY = 'live-test-secret'
    ENROLLMENT_TOKEN = 'live-test-token'
    ANTHROPIC_API_KEY = None
app = create_app(C, start_background=True)
app.run(host='127.0.0.1', port=int(sys.argv[3]), threaded=True, use_reloader=False)
"""
            proc = None
            logfile = open(root / "server-output.log", "w", encoding="utf-8")
            def start():
                process = subprocess.Popen([sys.executable, "-c", child, str(ROOT / "soc_server"),
                                            database.as_posix(), str(port)], stdout=logfile, stderr=logfile,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                deadline = time.monotonic() + 30
                last_error = None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail("Server exited; " + (root / "server-output.log").read_text(encoding="utf-8"))
                    try:
                        with urlopen(base + "/login", timeout=1) as response:
                            if response.status == 200:
                                return process
                    except OSError as exc:
                        last_error = repr(exc)
                        time.sleep(.1)
                process.terminate()
                process.wait(timeout=10)
                logfile.flush()
                self.fail("Server startup timeout: %s\n%s" % (last_error, (root / "server-output.log").read_text(encoding="utf-8")))
            try:
                proc = start()
                source = root / "auth.log"
                source.write_text("", encoding="utf-8")
                cfg = {"server": base, "data_dir": str(root / "agent"), "hostname": "live-linux",
                       "collectors": [{"type": "file", "name": "auth", "path": str(source),
                                       "format": "syslog", "source": "linux.auth"}]}
                a = SOCAgent(cfg)
                self.assertTrue(a.register("live-test-token"))
                a.collect_once()
                now = datetime.now()
                lines = ["%s live-linux sshd[%d]: Failed password for root from 203.0.113.66 port %d ssh2\n" % (
                    (now - timedelta(seconds=60 - 3 * i)).strftime("%b %d %H:%M:%S"), 100 + i, 40000 + i)
                         for i in range(8)]
                lines.append("%s live-linux sshd[999]: Accepted password for root from 203.0.113.66 port 40999 ssh2\n" % now.strftime("%b %d %H:%M:%S"))
                source.write_text("".join(lines), encoding="utf-8")
                self.assertEqual(a.collect_once(), 9)
                original = list(a.queue)
                self.assertEqual(a.flush_queue(), 9)
                self.assertFalse(a.queue)

                browser = build_opener(HTTPCookieProcessor(CookieJar()))
                html = browser.open(base + "/login").read().decode()
                token = re.search(r'name="_csrf_token" value="([^"]+)"', html).group(1)
                from urllib.parse import urlencode
                browser.open(Request(base + "/login", data=urlencode({"username": "admin", "password": "Admin@123",
                                                                       "_csrf_token": token}).encode())).read()
                deadline = time.monotonic() + 30
                while True:
                    health = json.loads(browser.open(base + "/api/v1/health").read())
                    if not health["jobs"].get("queued", 0) and not health["jobs"].get("running", 0):
                        break
                    self.assertLess(time.monotonic(), deadline, health)
                    time.sleep(.1)
                self.assertTrue(health["worker_alive"])
                self.assertEqual(health["jobs"].get("failed", 0), 0)
                stats = json.loads(browser.open(base + "/api/v1/stats").read())
                self.assertEqual(stats["kpi"]["events_total"], 10)
                self.assertGreaterEqual(stats["kpi"]["alerts_open"], 2)
                for path in ("/operations", "/kb", "/reports", "/alerts/%d" % stats["latest_alerts"][0]["id"]):
                    self.assertEqual(browser.open(base + path).status, 200)

                proc.terminate()
                proc.wait(timeout=10)
                proc = start()
                b = SOCAgent(cfg)
                self.assertEqual(b.collect_once(), 0)
                b.queue.extend(original)  # Emulate ACK loss and retransmit after server restart.
                b._save_spool()
                self.assertEqual(b.flush_queue(), 0)
                self.assertFalse(b.queue)
                with app.app_context():
                    self.assertEqual(LogEvent.query.count(), 10)
                    self.assertEqual(WorkJob.query.filter_by(status="failed").count(), 0)
                    self.assertEqual(WorkJob.query.filter_by(kind="detection", status="succeeded").count(), 2)
                    db.session.remove()
                    db.engine.dispose()
                print("HTTP thật: collector -> agent -> ingest -> luật -> AI worker -> UI -> restart/gửi lại: đạt.")
            finally:
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=10)
                logfile.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
