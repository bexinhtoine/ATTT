# -*- coding: utf-8 -*-
"""
views.py - Các trang giao diện Web SOC (blueprint "main").

Dashboard, Máy trạm, Nhật ký log, Cảnh báo, Luật phát hiện, Cơ sở tri thức, Báo cáo,
Uy tín IP, Người dùng, Nhật ký thao tác, Cài đặt.
"""
import csv
import io
import json
from datetime import timedelta

from flask import (Blueprint, render_template, request, redirect, url_for, flash, g, abort,
                   Response, current_app)
from sqlalchemy import func

from .extensions import db
from .models import (User, Agent, LogEvent, DetectionRule, Alert, Investigation, KnowledgeArticle,
                     AIRun, AuditLog, IpReputation, ALERT_STATUSES, SEVERITIES, RULE_TYPES, ROLES,
                     OPEN_STATUSES, dumps, loads, utcnow)
from .auth import login_required, role_required, audit
from .api import apply_event_filters
from .detection import RuleEngine
from .parsers import parse_iso
from . import stats as stats_mod

bp = Blueprint("main", __name__)


def _page():
    try:
        return max(1, int(request.args.get("page", 1)))
    except ValueError:
        return 1


def _csv_response(filename, header, rows):
    buf = io.StringIO()
    buf.write("﻿")                         # BOM để Excel đọc đúng UTF-8
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow(r)
    return Response(buf.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=%s" % filename})


def _parse_range(default_hours=24):
    until = parse_iso(request.args.get("to")) if request.args.get("to") else None
    since = parse_iso(request.args.get("from")) if request.args.get("from") else None
    until = until.replace(tzinfo=None) if until else utcnow()
    since = since.replace(tzinfo=None) if since else until - timedelta(hours=default_hours)
    return since, until


# ------------------------------------------------------------------ Dashboard
@bp.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", stats=stats_mod.dashboard_stats())


# -------------------------------------------------------------------- Agents
@bp.route("/agents")
@login_required
def agents():
    rows = Agent.query.order_by(Agent.status.desc(), Agent.hostname).all()
    return render_template("agents.html", agents=rows,
                           enrollment_token=current_app.config["ENROLLMENT_TOKEN"],
                           server_url=request.host_url.rstrip("/"))


@bp.route("/agents/<int:agent_id>")
@login_required
def agent_detail(agent_id):
    agent = db.session.get(Agent, agent_id) or abort(404)
    events = agent.events.order_by(LogEvent.event_time.desc()).limit(50).all()
    alerts = agent.alerts.order_by(Alert.created_at.desc()).limit(20).all()
    since = utcnow() - timedelta(hours=24)
    by_source = db.session.query(LogEvent.source, func.count(LogEvent.id)).filter(
        LogEvent.agent_id == agent.id, LogEvent.event_time >= since).group_by(LogEvent.source).all()
    by_sev = db.session.query(LogEvent.severity, func.count(LogEvent.id)).filter(
        LogEvent.agent_id == agent.id, LogEvent.event_time >= since).group_by(LogEvent.severity).all()
    return render_template("agent_detail.html", agent=agent, events=events, alerts=alerts,
                           by_source=by_source, by_sev=by_sev)


@bp.post("/agents/<int:agent_id>/rekey")
@role_required("admin")
def agent_rekey(agent_id):
    agent = db.session.get(Agent, agent_id) or abort(404)
    key = agent.issue_api_key()
    db.session.commit()
    audit("agent_rekey", agent.hostname)
    flash("API key mới cho %s (chỉ hiển thị một lần): %s" % (agent.hostname, key), "warning")
    return redirect(url_for("main.agent_detail", agent_id=agent.id))


@bp.post("/agents/<int:agent_id>/delete")
@role_required("admin")
def agent_delete(agent_id):
    agent = db.session.get(Agent, agent_id) or abort(404)
    name = agent.hostname
    LogEvent.query.filter_by(agent_id=agent.id).update({LogEvent.agent_id: None})
    Alert.query.filter_by(agent_id=agent.id).update({Alert.agent_id: None})
    db.session.delete(agent)
    db.session.commit()
    audit("agent_delete", name)
    flash("Đã xóa máy trạm %s." % name, "success")
    return redirect(url_for("main.agents"))


# ---------------------------------------------------------------------- Logs
@bp.route("/logs")
@login_required
def logs():
    q = apply_event_filters(LogEvent.query, request.args)
    pagination = q.order_by(LogEvent.event_time.desc()).paginate(
        page=_page(), per_page=current_app.config["PAGE_SIZE"], error_out=False)
    sources = [r[0] for r in db.session.query(LogEvent.source).distinct().order_by(LogEvent.source).all() if r[0]]
    categories = [r[0] for r in db.session.query(LogEvent.category).distinct().order_by(LogEvent.category).all() if r[0]]
    hosts = [r[0] for r in db.session.query(LogEvent.host).distinct().order_by(LogEvent.host).all() if r[0]]
    return render_template("logs.html", pagination=pagination, events=pagination.items,
                           sources=sources, categories=categories, hosts=hosts, severities=SEVERITIES,
                           args=request.args)


@bp.route("/logs/export.csv")
@login_required
def logs_export():
    q = apply_event_filters(LogEvent.query, request.args).order_by(LogEvent.event_time.desc()).limit(20000)
    rows = ((e.id, e.event_time, e.host, e.source, e.category, e.action, e.outcome, e.severity, e.event_id,
             e.user_name, e.src_ip, e.src_port, e.process_name, (e.message or "").replace("\n", " ")) for e in q)
    audit("export_logs", detail=json.dumps(request.args.to_dict(), ensure_ascii=False))
    return _csv_response("soc_events.csv", ["id", "event_time_utc", "host", "source", "category", "action",
                                            "outcome", "severity", "event_id", "user", "src_ip", "src_port",
                                            "process", "message"], rows)


@bp.route("/logs/<int:event_id>")
@login_required
def log_detail(event_id):
    ev = db.session.get(LogEvent, event_id) or abort(404)
    alerts = Alert.query.join(Alert.events).filter(LogEvent.id == ev.id).all()
    return render_template("log_detail.html", ev=ev, alerts=alerts)


# -------------------------------------------------------------------- Alerts
@bp.route("/alerts")
@login_required
def alerts():
    q = Alert.query
    a = request.args
    if a.get("status"):
        q = q.filter(Alert.status.in_(a["status"].split(",")))
    elif a.get("open") == "1":
        q = q.filter(Alert.status.in_(OPEN_STATUSES))
    if a.get("severity"):
        q = q.filter(Alert.severity.in_(a["severity"].split(",")))
    if a.get("host"):
        q = q.filter(Alert.host == a["host"])
    if a.get("rule_id", "").isdigit():
        q = q.filter(Alert.rule_id == int(a["rule_id"]))
    if a.get("verdict"):
        q = q.filter(Alert.ai_verdict == a["verdict"])
    if a.get("q"):
        like = "%%%s%%" % a["q"]
        q = q.filter(db.or_(Alert.title.ilike(like), Alert.src_ip.ilike(like), Alert.user_name.ilike(like),
                            Alert.description.ilike(like)))
    for key, cmp in (("from", "ge"), ("to", "le")):
        if a.get(key) and parse_iso(a[key]):
            dt = parse_iso(a[key]).replace(tzinfo=None)
            q = q.filter(Alert.created_at >= dt if cmp == "ge" else Alert.created_at <= dt)
    order = a.get("sort", "created")
    if order == "priority":
        q = q.order_by(Alert.priority.asc().nullslast(), Alert.created_at.desc())
    elif order == "severity":
        sev_case = db.case({"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}, value=Alert.severity, else_=0)
        q = q.order_by(sev_case.desc(), Alert.created_at.desc())
    else:
        q = q.order_by(Alert.created_at.desc())
    pagination = q.paginate(page=_page(), per_page=current_app.config["PAGE_SIZE"], error_out=False)
    hosts = [r[0] for r in db.session.query(Alert.host).distinct().order_by(Alert.host).all() if r[0]]
    rules = DetectionRule.query.order_by(DetectionRule.code).all()
    status_counts = dict(db.session.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all())
    return render_template("alerts.html", pagination=pagination, alerts=pagination.items, hosts=hosts,
                           rules=rules, args=a, statuses=ALERT_STATUSES, severities=SEVERITIES,
                           status_counts=status_counts)


@bp.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    alert = db.session.get(Alert, alert_id) or abort(404)
    events = alert.events.order_by(LogEvent.event_time).limit(200).all()
    users = User.query.filter_by(is_active=True).order_by(User.username).all()
    return render_template("alert_detail.html", alert=alert, events=events, ai=alert.ai, users=users,
                           investigations=alert.investigations.all(), runs=alert.ai_runs.limit(20).all(),
                           articles=alert.knowledge_articles.all(), statuses=ALERT_STATUSES)


@bp.post("/alerts/<int:alert_id>/update")
@role_required("admin", "analyst")
def alert_update(alert_id):
    alert = db.session.get(Alert, alert_id) or abort(404)
    status = request.form.get("status")
    if status in ALERT_STATUSES:
        alert.status = status
        if status in ("resolved", "false_positive"):
            alert.resolved_at = utcnow()
            alert.resolved_by = g.user.id
    if request.form.get("assigned_to"):
        try:
            alert.assigned_to = int(request.form["assigned_to"]) or None
        except ValueError:
            pass
    if request.form.get("severity") in SEVERITIES:
        alert.severity = request.form["severity"]
    if request.form.get("note") is not None:
        alert.resolution_note = request.form.get("note") or alert.resolution_note
    alert.updated_at = utcnow()
    db.session.commit()
    audit("alert_update", "alert:%d" % alert.id, "status=%s" % alert.status)
    if status in ("resolved", "false_positive") and request.form.get("extract_knowledge") == "1":
        current_app.extensions["soc_orchestrator"].run(alert.id, ("knowledge",), "manual", g.user.username)
        flash("Đã cập nhật cảnh báo và trích xuất bài học vào cơ sở tri thức.", "success")
    else:
        flash("Đã cập nhật cảnh báo.", "success")
    return redirect(url_for("main.alert_detail", alert_id=alert.id))


@bp.route("/alerts/export.csv")
@login_required
def alerts_export():
    q = Alert.query.order_by(Alert.created_at.desc()).limit(10000)
    rows = ((al.id, al.created_at, al.title, al.severity, al.status, al.priority, al.host, al.src_ip, al.user_name,
             al.event_count, al.mitre_tactic, al.mitre_technique, al.ai_verdict, al.ai_confidence,
             (al.ai_summary or "").replace("\n", " ")) for al in q)
    audit("export_alerts")
    return _csv_response("soc_alerts.csv", ["id", "created_at_utc", "title", "severity", "status", "priority", "host",
                                            "src_ip", "user", "event_count", "mitre_tactic", "mitre_technique",
                                            "ai_verdict", "ai_confidence", "ai_summary"], rows)


# --------------------------------------------------------------------- Rules
@bp.route("/rules")
@login_required
def rules():
    rows = DetectionRule.query.order_by(DetectionRule.code).all()
    return render_template("rules.html", rules=rows)


def _rule_from_form(rule):
    f = request.form
    try:
        cond = json.loads(f.get("conditions") or "{}")
        if not isinstance(cond, dict):
            raise ValueError("Điều kiện phải là một đối tượng JSON")
    except ValueError as exc:
        raise ValueError("Điều kiện JSON không hợp lệ: %s" % exc)
    rule.code = (f.get("code") or rule.code or "").strip()[:16] or None
    rule.name = (f.get("name") or "").strip()[:160]
    if not rule.name:
        raise ValueError("Tên luật không được để trống")
    rule.description = f.get("description")
    rule.rule_type = f.get("rule_type") if f.get("rule_type") in RULE_TYPES else "match"
    rule.severity = f.get("severity") if f.get("severity") in SEVERITIES else "medium"
    rule.enabled = f.get("enabled") == "1"
    rule.conditions = dumps(cond)
    rule.threshold_count = int(f.get("threshold_count") or 1)
    rule.window_seconds = int(f.get("window_seconds") or 300)
    rule.group_by = f.get("group_by") or "src_ip"
    rule.distinct_field = (f.get("distinct_field") or "").strip() or None
    rule.title_template = (f.get("title_template") or "").strip() or None
    rule.mitre_tactic = (f.get("mitre_tactic") or "").strip() or None
    rule.mitre_technique = (f.get("mitre_technique") or "").strip() or None
    return rule


@bp.route("/rules/new", methods=["GET", "POST"])
@role_required("admin", "analyst")
def rule_new():
    rule = DetectionRule(rule_type="match", severity="medium", enabled=True, threshold_count=5,
                         window_seconds=300, group_by="src_ip", conditions="{}")
    if request.method == "POST":
        try:
            _rule_from_form(rule)
            rule.created_by = g.user.username
            db.session.add(rule)
            db.session.commit()
            audit("rule_create", rule.code or rule.name)
            flash("Đã tạo luật %s." % rule.name, "success")
            return redirect(url_for("main.rules"))
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("rule_form.html", rule=rule, is_new=True)


@bp.route("/rules/<int:rule_id>/edit", methods=["GET", "POST"])
@role_required("admin", "analyst")
def rule_edit(rule_id):
    rule = db.session.get(DetectionRule, rule_id) or abort(404)
    if request.method == "POST":
        try:
            _rule_from_form(rule)
            db.session.commit()
            audit("rule_update", rule.code or rule.name)
            flash("Đã lưu luật %s." % rule.name, "success")
            return redirect(url_for("main.rules"))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
    return render_template("rule_form.html", rule=rule, is_new=False)


@bp.post("/rules/<int:rule_id>/toggle")
@role_required("admin", "analyst")
def rule_toggle(rule_id):
    rule = db.session.get(DetectionRule, rule_id) or abort(404)
    rule.enabled = not rule.enabled
    db.session.commit()
    audit("rule_toggle", rule.code, "enabled=%s" % rule.enabled)
    return redirect(url_for("main.rules"))


@bp.post("/rules/<int:rule_id>/delete")
@role_required("admin")
def rule_delete(rule_id):
    rule = db.session.get(DetectionRule, rule_id) or abort(404)
    Alert.query.filter_by(rule_id=rule.id).update({Alert.rule_id: None})
    db.session.delete(rule)
    db.session.commit()
    audit("rule_delete", rule.code)
    flash("Đã xóa luật.", "success")
    return redirect(url_for("main.rules"))


@bp.post("/rules/replay")
@role_required("admin", "analyst")
def rules_replay():
    hours = int(request.form.get("hours") or 24)
    since = utcnow() - timedelta(hours=hours)
    results = RuleEngine().evaluate_range(since, utcnow())
    new = sum(1 for _, n in results if n)
    audit("rules_replay", detail="hours=%d, alerts_new=%d" % (hours, new))
    flash("Đã chạy lại luật trên dữ liệu %d giờ qua: %d cảnh báo mới, %d cảnh báo cập nhật."
          % (hours, new, len(results) - new), "info")
    return redirect(url_for("main.rules"))


# ---------------------------------------------------------- Knowledge base
@bp.route("/kb")
@login_required
def kb():
    q = KnowledgeArticle.query
    if request.args.get("q"):
        like = "%%%s%%" % request.args["q"]
        q = q.filter(db.or_(KnowledgeArticle.title.ilike(like), KnowledgeArticle.tags.ilike(like),
                            KnowledgeArticle.content.ilike(like), KnowledgeArticle.summary.ilike(like)))
    if request.args.get("category"):
        q = q.filter(KnowledgeArticle.category == request.args["category"])
    if request.args.get("source"):
        q = q.filter(KnowledgeArticle.source == request.args["source"])
    pagination = q.order_by(KnowledgeArticle.updated_at.desc()).paginate(page=_page(), per_page=20, error_out=False)
    return render_template("kb.html", pagination=pagination, articles=pagination.items, args=request.args)


@bp.route("/kb/<int:article_id>")
@login_required
def kb_detail(article_id):
    art = db.session.get(KnowledgeArticle, article_id) or abort(404)
    return render_template("kb_detail.html", art=art)


@bp.route("/kb/new", methods=["GET", "POST"])
@bp.route("/kb/<int:article_id>/edit", methods=["GET", "POST"])
@role_required("admin", "analyst")
def kb_edit(article_id=None):
    art = db.session.get(KnowledgeArticle, article_id) if article_id else KnowledgeArticle(category="playbook", source="manual")
    if art is None:
        abort(404)
    if request.method == "POST":
        f = request.form
        art.title = (f.get("title") or "").strip()[:255]
        art.category = f.get("category") or "playbook"
        art.tags = (f.get("tags") or "").strip()
        art.summary = f.get("summary")
        art.content = f.get("content")
        art.mitre_technique = (f.get("mitre_technique") or "").strip() or None
        if not art.title:
            flash("Tiêu đề không được để trống.", "danger")
        else:
            if article_id is None:
                art.created_by = g.user.username
                db.session.add(art)
            art.updated_at = utcnow()
            db.session.commit()
            audit("kb_save", art.title)
            flash("Đã lưu bài tri thức.", "success")
            return redirect(url_for("main.kb_detail", article_id=art.id))
    return render_template("kb_form.html", art=art, is_new=article_id is None)


@bp.post("/kb/<int:article_id>/delete")
@role_required("admin", "analyst")
def kb_delete(article_id):
    art = db.session.get(KnowledgeArticle, article_id) or abort(404)
    db.session.delete(art)
    db.session.commit()
    audit("kb_delete", art.title)
    flash("Đã xóa bài tri thức.", "success")
    return redirect(url_for("main.kb"))


# ------------------------------------------------------------------- Reports
@bp.route("/reports")
@login_required
def reports():
    since, until = _parse_range(24)
    data = stats_mod.report_stats(since, until)
    audit("report_view", detail="%s -> %s" % (since, until))
    return render_template("reports.html", r=data, args=request.args, printable=request.args.get("print") == "1")


# -------------------------------------------------------------- IP reputation
@bp.route("/ip-reputation", methods=["GET", "POST"])
@login_required
def ip_reputation():
    if request.method == "POST":
        if g.user.role not in ("admin", "analyst"):
            abort(403)
        ip = (request.form.get("ip") or "").strip()
        verdict = request.form.get("verdict") or "suspicious"
        if ip:
            rec = IpReputation.query.filter_by(ip=ip).first() or IpReputation(ip=ip)
            rec.verdict, rec.source, rec.note, rec.created_by = verdict, "analyst", request.form.get("note"), g.user.username
            db.session.add(rec)
            db.session.commit()
            audit("ip_reputation_set", ip, verdict)
            flash("Đã cập nhật uy tín IP %s." % ip, "success")
        return redirect(url_for("main.ip_reputation"))
    rows = IpReputation.query.order_by(IpReputation.created_at.desc()).all()
    return render_template("ip_reputation.html", rows=rows)


@bp.post("/ip-reputation/<int:rec_id>/delete")
@role_required("admin", "analyst")
def ip_reputation_delete(rec_id):
    rec = db.session.get(IpReputation, rec_id) or abort(404)
    db.session.delete(rec)
    db.session.commit()
    audit("ip_reputation_delete", rec.ip)
    return redirect(url_for("main.ip_reputation"))


# --------------------------------------------------------------------- Users
@bp.route("/users")
@role_required("admin")
def users():
    return render_template("users.html", users=User.query.order_by(User.username).all(), roles=ROLES)


@bp.route("/users/new", methods=["GET", "POST"])
@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def user_edit(user_id=None):
    user = db.session.get(User, user_id) if user_id else User(role="analyst", is_active=True)
    if user is None:
        abort(404)
    if request.method == "POST":
        f = request.form
        username = (f.get("username") or "").strip()
        if not username:
            flash("Tên đăng nhập không được để trống.", "danger")
        elif User.query.filter(User.username == username, User.id != (user.id or 0)).first():
            flash("Tên đăng nhập đã tồn tại.", "danger")
        else:
            user.username = username
            user.full_name = f.get("full_name")
            user.email = f.get("email")
            user.role = f.get("role") if f.get("role") in ROLES else "analyst"
            user.is_active = f.get("is_active") == "1"
            if f.get("password"):
                if len(f["password"]) < 8:
                    flash("Mật khẩu phải có ít nhất 8 ký tự.", "danger")
                    return render_template("user_form.html", user=user, roles=ROLES, is_new=user_id is None)
                user.set_password(f["password"])
            elif user_id is None:
                flash("Cần đặt mật khẩu cho người dùng mới.", "danger")
                return render_template("user_form.html", user=user, roles=ROLES, is_new=True)
            if user_id is None:
                db.session.add(user)
            db.session.commit()
            audit("user_save", user.username, "role=%s active=%s" % (user.role, user.is_active))
            flash("Đã lưu người dùng %s." % user.username, "success")
            return redirect(url_for("main.users"))
    return render_template("user_form.html", user=user, roles=ROLES, is_new=user_id is None)


@bp.post("/users/<int:user_id>/delete")
@role_required("admin")
def user_delete(user_id):
    user = db.session.get(User, user_id) or abort(404)
    if user.id == g.user.id:
        flash("Không thể tự xóa tài khoản đang đăng nhập.", "danger")
        return redirect(url_for("main.users"))
    db.session.delete(user)
    db.session.commit()
    audit("user_delete", user.username)
    flash("Đã xóa người dùng.", "success")
    return redirect(url_for("main.users"))


@bp.route("/profile/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        if not g.user.check_password(request.form.get("current") or ""):
            flash("Mật khẩu hiện tại không đúng.", "danger")
        elif len(request.form.get("new") or "") < 8:
            flash("Mật khẩu mới phải có ít nhất 8 ký tự.", "danger")
        elif request.form.get("new") != request.form.get("confirm"):
            flash("Xác nhận mật khẩu không khớp.", "danger")
        else:
            g.user.set_password(request.form["new"])
            db.session.commit()
            audit("password_change", g.user.username)
            flash("Đã đổi mật khẩu.", "success")
            return redirect(url_for("main.dashboard"))
    return render_template("change_password.html")


# ------------------------------------------------------------- Audit & settings
@bp.route("/audit")
@role_required("admin", "analyst")
def audit_logs():
    q = AuditLog.query
    if request.args.get("action"):
        q = q.filter(AuditLog.action == request.args["action"])
    if request.args.get("username"):
        q = q.filter(AuditLog.username.ilike("%%%s%%" % request.args["username"]))
    pagination = q.order_by(AuditLog.created_at.desc()).paginate(page=_page(), per_page=50, error_out=False)
    actions = [r[0] for r in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()]
    return render_template("audit.html", pagination=pagination, rows=pagination.items, actions=actions, args=request.args)


@bp.route("/settings")
@role_required("admin")
def settings():
    cfg = current_app.config
    llm = current_app.extensions["soc_llm_status"]()
    ai_runs = db.session.query(AIRun.agent_name, AIRun.mode, func.count(AIRun.id), func.avg(AIRun.duration_ms),
                               func.sum(AIRun.input_tokens), func.sum(AIRun.output_tokens)).group_by(
        AIRun.agent_name, AIRun.mode).all()
    db_path = cfg["SQLALCHEMY_DATABASE_URI"]
    counts = {"events": db.session.query(func.count(LogEvent.id)).scalar(),
              "alerts": db.session.query(func.count(Alert.id)).scalar(),
              "agents": db.session.query(func.count(Agent.id)).scalar(),
              "rules": db.session.query(func.count(DetectionRule.id)).scalar(),
              "kb": db.session.query(func.count(KnowledgeArticle.id)).scalar(),
              "ai_runs": db.session.query(func.count(AIRun.id)).scalar()}
    return render_template("settings.html", cfg=cfg, llm=llm, ai_runs=ai_runs, db_path=db_path, counts=counts)
