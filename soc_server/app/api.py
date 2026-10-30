# -*- coding: utf-8 -*-
"""
api.py - REST API của Web SOC.

Dành cho AGENT (xác thực bằng header X-API-Key):
    POST /api/v1/agents/register   đăng ký máy trạm bằng enrollment token -> nhận API key
    POST /api/v1/logs              gửi lô sự kiện đã chuẩn hóa {"events": [...]}
    POST /api/v1/agents/heartbeat  báo còn sống + số liệu CPU/RAM/disk
Dành cho GIAO DIỆN (xác thực bằng phiên đăng nhập):
    GET  /api/v1/stats             số liệu dashboard (JSON)
    GET  /api/v1/events            truy vấn sự kiện có bộ lọc (JSON) - dùng cho tìm kiếm/xuất dữ liệu
    POST /api/v1/alerts/<id>/ai/<stage>   chạy một giai đoạn AI (enrich|triage|investigate|knowledge|full)
    POST /api/v1/alerts/<id>/status       đổi trạng thái cảnh báo
"""
import platform
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, request, jsonify, g, current_app

from .extensions import db
from .models import Agent, Alert, LogEvent, AuditLog, dumps, utcnow, ALERT_STATUSES
from .ingest import ingest
from .auth import login_required, role_required, audit
from . import stats as stats_mod
from .parsers import parse_iso

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def _int(value, default=None):
    """Ép kiểu số nguyên an toàn cho tham số truy vấn (tránh lỗi 500 khi người dùng nhập sai)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _agent_config():
    """Cấu hình tập trung gửi xuống agent trong phản hồi register/heartbeat."""
    cfg = current_app.config
    return {"interval_seconds": cfg.get("AGENT_INTERVAL_SECONDS", 10),
            "batch_size": cfg.get("AGENT_BATCH_SIZE", 500),
            "heartbeat_seconds": cfg.get("AGENT_HEARTBEAT_SECONDS", 60),
            "max_events_per_batch": cfg.get("MAX_EVENTS_PER_BATCH", 2000)}


def agent_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        key = request.headers.get("X-API-Key") or ""
        agent = Agent.query.filter_by(api_key_hash=Agent.hash_key(key)).first() if key else None
        if agent is None:
            return jsonify({"error": "API key không hợp lệ"}), 401
        g.agent = agent
        return view(*args, **kwargs)
    return wrapped


def _trigger_ai(alerts):
    """Tự động phân loại các cảnh báo MỚI bằng tác tử AI (luồng nền)."""
    if not current_app.config.get("AI_AUTO_TRIAGE", True):
        return 0
    orch = current_app.extensions.get("soc_orchestrator")
    n = 0
    for alert, is_new in alerts:
        if is_new and orch is not None:
            orch.run_async(alert.id, ("enrich", "triage"), trigger="auto")
            n += 1
    return n


# ------------------------------------------------------------------ agent API
@bp.post("/agents/register")
def register_agent():
    data = request.get_json(silent=True) or {}
    if data.get("enrollment_token") != current_app.config["ENROLLMENT_TOKEN"]:
        audit("agent_register_denied", data.get("hostname"), "Sai enrollment token", success=False)
        return jsonify({"error": "Enrollment token không đúng"}), 403
    hostname = (data.get("hostname") or "").strip()[:128]
    if not hostname:
        return jsonify({"error": "Thiếu hostname"}), 400
    agent = Agent.query.filter_by(hostname=hostname).first()
    created = agent is None
    if created:
        agent = Agent(hostname=hostname)
        db.session.add(agent)
    agent.os_type = (data.get("os_type") or "other")[:32]
    agent.os_version = (data.get("os_version") or "")[:128]
    agent.ip_address = (data.get("ip_address") or request.remote_addr or "")[:64]
    agent.agent_version = (data.get("agent_version") or "")[:32]
    agent.collectors = dumps(data.get("collectors") or [])
    agent.status = "online"
    agent.last_seen = utcnow()
    api_key = agent.issue_api_key()
    db.session.commit()
    audit("agent_registered" if created else "agent_rekeyed", hostname,
          "OS=%s, IP=%s" % (agent.os_type, agent.ip_address))
    return jsonify({"agent_uid": agent.agent_uid, "agent_id": agent.id, "api_key": api_key,
                    "server_time": utcnow().isoformat() + "Z", "config": _agent_config()}), 201


@bp.post("/logs")
@agent_auth
def post_logs():
    data = request.get_json(silent=True)
    events = data.get("events") if isinstance(data, dict) else data
    if not isinstance(events, list):
        return jsonify({"error": "Body phải là {\"events\": [...]}"}), 400
    result = ingest(g.agent, events)
    ai_started = _trigger_ai(result["alerts"])
    return jsonify({"received": result["received"], "accepted": result["accepted"],
                    "duplicates": result["duplicates"], "rejected": result["rejected"],
                    "alerts_new": sum(1 for _, n in result["alerts"] if n),
                    "alerts_updated": sum(1 for _, n in result["alerts"] if not n),
                    "ai_started": ai_started, "server_time": utcnow().isoformat() + "Z"})


@bp.post("/agents/heartbeat")
@agent_auth
def heartbeat():
    data = request.get_json(silent=True) or {}
    g.agent.last_seen = utcnow()
    g.agent.status = "online"
    if data.get("metrics"):
        g.agent.metrics = dumps(data["metrics"])
    if data.get("collectors"):
        g.agent.collectors = dumps(data["collectors"])
    if data.get("agent_version"):
        g.agent.agent_version = str(data["agent_version"])[:32]
    if data.get("ip_address"):
        g.agent.ip_address = str(data["ip_address"])[:64]
    db.session.commit()
    return jsonify({"ok": True, "server_time": utcnow().isoformat() + "Z", "config": _agent_config()})


# --------------------------------------------------------------- UI JSON API
@bp.get("/stats")
@login_required
def get_stats():
    return jsonify(stats_mod.dashboard_stats())


def apply_event_filters(q, args):
    """Áp các tham số lọc chung cho trang log và API events."""
    if _int(args.get("agent_id")) is not None:
        q = q.filter(LogEvent.agent_id == _int(args["agent_id"]))
    if args.get("host"):
        q = q.filter(LogEvent.host == args["host"])
    if args.get("source"):
        q = q.filter(LogEvent.source == args["source"])
    if args.get("severity"):
        q = q.filter(LogEvent.severity.in_(args.get("severity").split(",")))
    if args.get("category"):
        q = q.filter(LogEvent.category == args["category"])
    if args.get("action"):
        q = q.filter(LogEvent.action == args["action"])
    if args.get("outcome"):
        q = q.filter(LogEvent.outcome == args["outcome"])
    if args.get("event_id"):
        q = q.filter(LogEvent.event_id == args["event_id"])
    if args.get("user"):
        q = q.filter(LogEvent.user_name.ilike("%%%s%%" % args["user"]))
    if args.get("src_ip"):
        q = q.filter(LogEvent.src_ip.like("%s%%" % args["src_ip"]))
    if args.get("q"):
        like = "%%%s%%" % args["q"]
        q = q.filter(db.or_(LogEvent.message.ilike(like), LogEvent.raw.ilike(like),
                            LogEvent.process_name.ilike(like), LogEvent.user_name.ilike(like)))
    for key, op in (("from", "ge"), ("to", "le")):
        if args.get(key):
            dt = parse_iso(args[key])
            if dt:
                dt = dt.replace(tzinfo=None)
                q = q.filter(LogEvent.event_time >= dt if op == "ge" else LogEvent.event_time <= dt)
    return q


@bp.get("/events")
@login_required
def get_events():
    q = apply_event_filters(LogEvent.query, request.args)
    limit = max(1, min(_int(request.args.get("limit"), 100), 5000))
    offset = max(0, _int(request.args.get("offset"), 0))
    total = q.count()
    rows = q.order_by(LogEvent.event_time.desc()).offset(offset).limit(limit).all()
    return jsonify({"total": total, "limit": limit, "offset": offset,
                    "events": [e.to_dict(with_raw=request.args.get("raw") == "1") for e in rows]})


@bp.post("/alerts/<int:alert_id>/ai/<stage>")
@role_required("admin", "analyst")
def run_ai(alert_id, stage):
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        return jsonify({"error": "Không tìm thấy cảnh báo"}), 404
    stages = {"enrich": ("enrich",), "triage": ("enrich", "triage"), "investigate": ("investigate",),
              "knowledge": ("knowledge",), "full": ("enrich", "triage", "investigate")}.get(stage)
    if stages is None:
        return jsonify({"error": "Giai đoạn không hợp lệ"}), 400
    orch = current_app.extensions["soc_orchestrator"]
    results = orch.run(alert_id, stages, trigger="manual", username=g.user.username)
    audit("ai_run", "alert:%d" % alert_id, "stage=%s" % stage)
    alert = db.session.get(Alert, alert_id)
    return jsonify({"alert": alert.to_dict(), "results": results, "ai_data": alert.ai})


@bp.post("/alerts/<int:alert_id>/status")
@role_required("admin", "analyst")
def set_alert_status(alert_id):
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        return jsonify({"error": "Không tìm thấy cảnh báo"}), 404
    data = request.get_json(silent=True) or request.form
    status = data.get("status")
    if status not in ALERT_STATUSES:
        return jsonify({"error": "Trạng thái không hợp lệ"}), 400
    alert.status = status
    if data.get("note"):
        alert.resolution_note = data.get("note")
    if status in ("resolved", "false_positive"):
        alert.resolved_at = utcnow()
        alert.resolved_by = g.user.id
    alert.updated_at = utcnow()
    db.session.commit()
    audit("alert_status", "alert:%d" % alert_id, status)
    return jsonify({"ok": True, "alert": alert.to_dict()})
