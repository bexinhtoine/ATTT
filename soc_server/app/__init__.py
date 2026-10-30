# -*- coding: utf-8 -*-
"""
Khởi tạo ứng dụng Web SOC (application factory).

    create_app() -> cấu hình, CSDL (SQLite WAL), seed dữ liệu, blueprint (auth, api, main),
                    bộ lọc Jinja, orchestrator AI, luồng bảo trì nền.
"""
import hmac
import json
import secrets
import threading
import time
import traceback
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

from flask import Flask, g, render_template, request, session, jsonify
from flask.json.provider import DefaultJSONProvider
from markupsafe import Markup
from sqlalchemy import event

from .extensions import db
from .models import (SEVERITY_LABELS, ALERT_STATUS_LABELS, ROLE_LABELS, RULE_TYPE_LABELS, utcnow)

APP_VERSION = "1.0.0"


class SOCJSONProvider(DefaultJSONProvider):
    ensure_ascii = False

    @staticmethod
    def default(o):
        if isinstance(o, datetime):
            return o.isoformat() + ("Z" if o.tzinfo is None else "")
        return DefaultJSONProvider.default(o)


def create_app(config_object=None, start_background=True):
    if config_object is None:
        from config import Config
        config_object = Config
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(config_object)
    app.json = SOCJSONProvider(app)
    db.init_app(app)

    with app.app_context():
        @event.listens_for(db.engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
        db.create_all()
        from .seed import seed_all
        created = seed_all()
        app.logger.info("Khởi tạo dữ liệu: %s", created)

    from .auth import bp as auth_bp, load_current_user
    from .api import bp as api_bp
    from .views import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(main_bp)
    app.before_request(load_current_user)
    _register_csrf(app)
    _warn_insecure_defaults(app)

    from .ai import SOCOrchestrator
    app.extensions["soc_orchestrator"] = SOCOrchestrator(app)
    from .ai.llm import LLMClient
    app.extensions["soc_llm_status"] = lambda: LLMClient.from_app(app)

    _register_template_helpers(app)
    _register_error_handlers(app)
    if start_background:
        _start_maintenance(app)
    return app


# ------------------------------------------------------------------- bảo mật
# Các endpoint dành cho agent xác thực bằng X-API-Key (không có phiên trình duyệt) nên miễn CSRF
CSRF_EXEMPT_PREFIXES = ("/api/v1/agents/register", "/api/v1/agents/heartbeat", "/api/v1/logs")


def _register_csrf(app):
    """Chống CSRF kiểu "synchronizer token": token sinh ngẫu nhiên gắn với phiên, mọi POST từ
    trình duyệt phải gửi kèm (trường ẩn _csrf_token trong form hoặc header X-CSRF-Token)."""
    def csrf_token():
        tok = session.get("_csrf_token")
        if not tok:
            tok = session["_csrf_token"] = secrets.token_urlsafe(32)
        return tok

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["csrf_field"] = lambda: Markup(
        '<input type="hidden" name="_csrf_token" value="%s">' % csrf_token())

    @app.before_request
    def csrf_protect():
        if not app.config.get("CSRF_ENABLED", True):
            return None
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        if request.path.startswith(CSRF_EXEMPT_PREFIXES):
            return None
        expected = session.get("_csrf_token") or ""
        sent = request.headers.get("X-CSRF-Token") or request.form.get("_csrf_token") or ""
        if not expected or not sent or not hmac.compare_digest(expected, sent):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Thiếu hoặc sai CSRF token"}), 403
            return render_template("error.html", code=403,
                                   message="Phiên làm việc không hợp lệ (CSRF). Hãy tải lại trang rồi thử lại."), 403
        return None


def _warn_insecure_defaults(app):
    """Cảnh báo khi còn dùng khóa bí mật / enrollment token mặc định của bản demo."""
    try:
        from config import DEFAULT_SECRET_KEY, DEFAULT_ENROLLMENT_TOKEN
    except ImportError:
        return
    if app.config.get("SECRET_KEY") == DEFAULT_SECRET_KEY:
        app.logger.warning("SECRET_KEY đang là giá trị mặc định - đặt biến môi trường SOC_SECRET_KEY khi triển khai thật.")
    if app.config.get("ENROLLMENT_TOKEN") == DEFAULT_ENROLLMENT_TOKEN:
        app.logger.warning("ENROLLMENT_TOKEN đang là giá trị mặc định - đặt SOC_ENROLLMENT_TOKEN để tránh agent lạ đăng ký.")


# ---------------------------------------------------------------- Jinja helpers
def _register_template_helpers(app):
    tz = ZoneInfo(app.config.get("TIMEZONE", "Asia/Ho_Chi_Minh"))

    def localtime(dt, fmt="%d/%m/%Y %H:%M:%S"):
        if not dt:
            return "-"
        if isinstance(dt, str):
            return dt
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(tz).strftime(fmt)

    def timeago(dt):
        if not dt:
            return "-"
        delta = utcnow() - dt
        s = int(delta.total_seconds())
        if s < 60:
            return "%d giây trước" % s
        if s < 3600:
            return "%d phút trước" % (s // 60)
        if s < 86400:
            return "%d giờ trước" % (s // 3600)
        return "%d ngày trước" % (s // 86400)

    sev_class = {"critical": "bg-danger", "high": "bg-warning text-dark", "medium": "bg-info text-dark",
                 "low": "bg-secondary", "info": "bg-light text-dark border"}
    status_class = {"new": "bg-primary", "triaged": "bg-info text-dark", "investigating": "bg-warning text-dark",
                    "resolved": "bg-success", "false_positive": "bg-secondary"}
    verdict_labels = {"true_positive": "Tấn công thật", "likely_true_positive": "Nhiều khả năng tấn công",
                      "suspicious": "Đáng ngờ", "likely_false_positive": "Khả năng dương tính giả",
                      "false_positive": "Dương tính giả"}
    verdict_class = {"true_positive": "bg-danger", "likely_true_positive": "bg-warning text-dark",
                     "suspicious": "bg-info text-dark", "likely_false_positive": "bg-secondary",
                     "false_positive": "bg-light text-dark border"}

    try:
        import markdown as _md

        def md(text):
            return _md.markdown(text or "", extensions=["tables", "fenced_code"])
    except ImportError:  # không có gói markdown -> hiển thị dạng văn bản thô
        from markupsafe import escape

        def md(text):
            return "<pre class='small'>%s</pre>" % escape(text or "")

    app.jinja_env.filters.update({
        "localtime": localtime, "timeago": timeago,
        "sev_label": lambda s: SEVERITY_LABELS.get(s, s or "-"),
        "sev_class": lambda s: sev_class.get(s, "bg-secondary"),
        "status_label": lambda s: ALERT_STATUS_LABELS.get(s, s or "-"),
        "status_class": lambda s: status_class.get(s, "bg-secondary"),
        "role_label": lambda r: ROLE_LABELS.get(r, r),
        "rule_type_label": lambda t: RULE_TYPE_LABELS.get(t, t),
        "verdict_label": lambda v: verdict_labels.get(v, v or "-"),
        "verdict_class": lambda v: verdict_class.get(v, "bg-secondary"),
        "pretty_json": lambda o: json.dumps(o, ensure_ascii=False, indent=2, default=str),
        "md": md,
    })

    @app.context_processor
    def inject_globals():
        llm = app.extensions["soc_llm_status"]()
        return {"current_user": g.get("user"), "app_version": APP_VERSION,
                "ai_available": llm.available, "ai_model": llm.model,
                "ai_reason": llm.unavailable_reason, "now": utcnow(),
                "SEVERITY_LABELS": SEVERITY_LABELS, "ALERT_STATUS_LABELS": ALERT_STATUS_LABELS}


def _register_error_handlers(app):
    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403, message="Bạn không có quyền truy cập chức năng này."), 403

    @app.errorhandler(404)
    def not_found(_e):
        if request.path.startswith("/api/"):
            return {"error": "Không tìm thấy"}, 404
        return render_template("error.html", code=404, message="Không tìm thấy trang yêu cầu."), 404

    @app.errorhandler(500)
    def server_error(_e):
        db.session.rollback()
        return render_template("error.html", code=500, message="Lỗi máy chủ nội bộ."), 500


# ------------------------------------------------------------ background jobs
def _start_maintenance(app):
    """Luồng nền: đánh dấu agent offline, dọn dữ liệu quá hạn lưu trữ."""
    def loop():
        from .models import Agent, LogEvent
        last_cleanup = 0
        while True:
            time.sleep(30)
            with app.app_context():
                try:
                    limit = utcnow() - timedelta(seconds=app.config.get("AGENT_OFFLINE_AFTER", 180))
                    for a in Agent.query.filter(Agent.status == "online").all():
                        if a.last_seen is None or a.last_seen < limit:
                            a.status = "offline"
                    db.session.commit()
                    if time.time() - last_cleanup > 3600:
                        keep = utcnow() - timedelta(days=app.config.get("RETENTION_DAYS", 30))
                        LogEvent.query.filter(LogEvent.event_time < keep).delete(synchronize_session=False)
                        db.session.commit()
                        last_cleanup = time.time()
                except Exception:
                    db.session.rollback()
                    app.logger.error("Lỗi luồng bảo trì:\n%s", traceback.format_exc())
                finally:
                    db.session.remove()
    threading.Thread(target=loop, daemon=True, name="soc-maintenance").start()
