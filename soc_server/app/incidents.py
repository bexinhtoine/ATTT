"""Incident workflow. Correlation proposes links; analysts explicitly accept them.

Only additive tables; alert status and AI decisions are never changed by this module.
"""
from datetime import timedelta

from flask import Blueprint, abort, g, redirect, render_template, request, url_for
from sqlalchemy.exc import IntegrityError

from .auth import login_required, role_required
from .extensions import db
from .platforms import platform_view
from .models import (Alert, AlertEvent, AuditLog, Incident, IncidentActivity, IncidentAlert,
                     INCIDENT_STATUSES, LogEvent, SEVERITIES, SEVERITY_ORDER, User, dumps, utcnow)

bp = Blueprint("incidents", __name__)


def correlation_reason(left, right):
    """Conservative proposal: exact host/user, compatible IP, <=30 minute total span.

    Missing account/host is insufficient. Never infer a link from shared IP alone.
    """
    missing = (None, "", "-", "unknown")
    if left.host in missing or left.user_name in missing:
        return None
    if left.host != right.host or left.user_name != right.user_name:
        return None
    if left.src_ip and right.src_ip and left.src_ip != right.src_ip:
        return None
    times = [a.first_event_time or a.created_at for a in (left, right)]
    times += [a.last_event_time or a.created_at for a in (left, right)]
    if max(times) - min(times) > timedelta(minutes=30):
        return None
    return "Cùng máy %s, tài khoản %s, IP không mâu thuẫn; cửa sổ sự kiện ≤30 phút (cần analyst xác minh)." % (left.host, left.user_name)


def activity(incident, action, detail):
    db.session.add(IncidentActivity(incident=incident, username=g.user.username, action=action, detail=detail))
    db.session.add(AuditLog(user_id=g.user.id, username=g.user.username, action="incident_" + action,
                            target="incident:%s" % incident.id, detail=detail[:2000], ip=request.remote_addr, success=True))


def text_field(name, limit, required=False):
    value = request.form.get(name, "").strip()
    if len(value) > limit or (required and not value):
        abort(400, description="Trường %s trống hoặc quá dài." % name)
    return value


def selected_ids():
    try:
        values = sorted({int(v) for v in request.form.getlist("alert_ids")})
    except ValueError:
        abort(400)
    if not values or len(values) > 100 or min(values) < 1:
        abort(400, description="Chọn từ 1 đến 100 cảnh báo.")
    return values


def claim(incident, field="version"):
    """Optimistic lock held in the same transaction as all membership mutations."""
    try:
        expected = int(request.form.get(field, ""))
    except ValueError:
        abort(400)
    changed = Incident.query.filter_by(id=incident.id, version=expected).update(
        {"version": Incident.version + 1, "updated_at": utcnow()}, synchronize_session=False)
    if not changed:
        db.session.rollback()
        abort(409, description="Incident đã thay đổi. Hãy tải lại trang.")
    db.session.refresh(incident)


def editable(incident):
    if incident.merged_into_id or incident.status in ("resolved", "closed"):
        abort(409, description="Mở lại incident trước khi thay đổi liên kết.")


def commit():
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        abort(409, description="Cảnh báo đã được liên kết bởi một thao tác khác. Hãy tải lại.")


@bp.get("/incidents")
@login_required
@platform_view("incidents", listing=True)
def index():
    query = Incident.query
    status = request.args.get("status", "")
    if status in INCIDENT_STATUSES:
        query = query.filter_by(status=status)
    page = query.order_by(Incident.updated_at.desc()).paginate(per_page=30, error_out=False)
    unlinked = Alert.query.filter(~Alert.id.in_(db.session.query(IncidentAlert.alert_id))).order_by(Alert.id.desc()).limit(100).all()
    return render_template("incidents.html", page=page, unlinked=unlinked, statuses=INCIDENT_STATUSES)


@bp.post("/incidents/create")
@role_required("admin", "analyst")
@platform_view("incidents")
def create():
    ids = selected_ids()
    alerts = Alert.query.filter(Alert.id.in_(ids)).all()
    if len(alerts) != len(ids):
        abort(400)
    if IncidentAlert.query.filter(IncidentAlert.alert_id.in_(ids)).first():
        abort(409, description="Có cảnh báo đã thuộc incident khác.")
    title = text_field("title", 255) or alerts[0].title
    reason = text_field("reason", 2000, True)
    incident = Incident(title=title, severity=max(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 0)).severity)
    db.session.add(incident)
    db.session.flush()
    for alert in alerts:
        db.session.add(IncidentAlert(incident=incident, alert=alert, reason=reason, linked_by=g.user.username))
    activity(incident, "create", dumps({"alerts": ids, "reason": reason}))
    commit()
    return redirect(url_for("incidents.detail", incident_id=incident.id))


@bp.get("/incidents/<int:incident_id>")
@login_required
@platform_view("incidents")
def detail(incident_id):
    incident = db.get_or_404(Incident, incident_id)
    ids = [link.alert_id for link in incident.links]
    timeline = LogEvent.query.join(AlertEvent, AlertEvent.event_id == LogEvent.id).filter(
        AlertEvent.alert_id.in_(ids)).distinct().order_by(LogEvent.event_time, LogEvent.id).limit(1001).all()
    candidates = []
    # Restrict by exact entities and time before examining candidates, never scan every alert.
    from sqlalchemy import or_, and_
    anchors = [link.alert for link in incident.links]
    clauses = [and_(Alert.host == a.host, Alert.user_name == a.user_name,
                    Alert.last_event_time >= (a.first_event_time or a.created_at) - timedelta(minutes=30),
                    Alert.first_event_time <= (a.last_event_time or a.created_at) + timedelta(minutes=30))
               for a in anchors if a.host and a.user_name]
    rows = Alert.query.filter(~Alert.id.in_(db.session.query(IncidentAlert.alert_id)), or_(*clauses)).order_by(Alert.id.desc()).limit(101).all() if clauses else []
    for alert in rows[:100]:
        reasons = [correlation_reason(a, alert) for a in anchors]
        if reasons and all(reasons):
            candidates.append((alert, reasons[0]))
    return render_template("incident_detail.html", incident=incident, timeline=timeline[:1000],
                           truncated=len(timeline) > 1000, candidates=candidates, candidates_limited=len(rows) > 100,
                           users=User.query.filter(User.is_active.is_(True), User.role.in_(("admin", "analyst"))).all(),
                           statuses=INCIDENT_STATUSES, severities=SEVERITIES)


@bp.post("/incidents/<int:incident_id>/update")
@role_required("admin", "analyst")
@platform_view("incidents")
def update(incident_id):
    incident = db.get_or_404(Incident, incident_id)
    if incident.merged_into_id:
        abort(409)
    title = text_field("title", 255, True)
    summary = text_field("summary", 20000)
    status, severity = request.form.get("status"), request.form.get("severity")
    if status not in INCIDENT_STATUSES or severity not in SEVERITIES:
        abort(400)
    try:
        owner = int(request.form.get("assigned_to") or 0)
    except ValueError:
        abort(400)
    user = db.session.get(User, owner) if owner else None
    if owner and (not user or not user.is_active or user.role not in ("admin", "analyst")):
        abort(400)
    claim(incident)
    incident.title, incident.summary = title, summary
    incident.status, incident.severity, incident.assigned_to = status, severity, owner or None
    activity(incident, "update", dumps({"title": title, "status": status, "severity": severity, "assigned_to": owner, "summary": summary}))
    commit()
    return redirect(url_for("incidents.detail", incident_id=incident.id))


@bp.post("/incidents/<int:incident_id>/link")
@role_required("admin", "analyst")
@platform_view("incidents")
def link(incident_id):
    incident = db.get_or_404(Incident, incident_id)
    ids, reason = selected_ids(), text_field("reason", 2000, True)
    alerts = Alert.query.filter(Alert.id.in_(ids)).all()
    if len(alerts) != len(ids):
        abort(400)
    claim(incident)
    editable(incident)
    if IncidentAlert.query.filter(IncidentAlert.alert_id.in_(ids)).first():
        abort(409)
    for alert in alerts:
        db.session.add(IncidentAlert(incident=incident, alert=alert, reason=reason, linked_by=g.user.username))
    activity(incident, "link", dumps({"alerts": ids, "reason": reason}))
    commit()
    return redirect(url_for("incidents.detail", incident_id=incident.id))


@bp.post("/incidents/<int:incident_id>/split")
@role_required("admin", "analyst")
@platform_view("incidents")
def split(incident_id):
    incident = db.get_or_404(Incident, incident_id)
    ids, reason = selected_ids(), text_field("reason", 2000, True)
    title = text_field("title", 255, True)
    claim(incident)
    editable(incident)
    links = IncidentAlert.query.filter_by(incident_id=incident.id).filter(IncidentAlert.alert_id.in_(ids)).all()
    if len(links) != len(ids) or len(links) == len(incident.links):
        abort(400, description="Tách một phần cảnh báo; phải giữ lại ít nhất một cảnh báo.")
    target = Incident(title=title, severity=incident.severity)
    db.session.add(target)
    db.session.flush()
    for item in links:
        item.incident = target
        item.reason, item.linked_by, item.linked_at = reason, g.user.username, utcnow()
    detail = dumps({"source": incident.id, "target": target.id, "alerts": ids, "reason": reason})
    activity(incident, "split", detail)
    activity(target, "split", detail)
    commit()
    return redirect(url_for("incidents.detail", incident_id=target.id))


@bp.post("/incidents/<int:incident_id>/merge")
@role_required("admin", "analyst")
@platform_view("incidents")
def merge(incident_id):
    source = db.get_or_404(Incident, incident_id)
    try:
        target_id = int(request.form.get("target_id", ""))
    except ValueError:
        abort(400)
    target = db.get_or_404(Incident, target_id)
    if target.id == source.id:
        abort(400)
    reason = text_field("reason", 2000, True)
    claim(source)
    claim(target, "target_version")
    editable(source)
    editable(target)
    ids = [item.alert_id for item in source.links]
    for item in list(source.links):
        item.incident = target
        item.reason, item.linked_by, item.linked_at = reason, g.user.username, utcnow()
    source.status, source.merged_into_id = "closed", target.id
    detail = dumps({"source": source.id, "target": target.id, "alerts": ids, "reason": reason})
    activity(source, "merge", detail)
    activity(target, "merge", detail)
    commit()
    return redirect(url_for("incidents.detail", incident_id=target.id))


@bp.post("/incidents/<int:incident_id>/note")
@role_required("admin", "analyst")
@platform_view("incidents")
def note(incident_id):
    incident = db.get_or_404(Incident, incident_id)
    content = text_field("note", 10000, True)
    claim(incident)
    if incident.merged_into_id:
        abort(409)
    activity(incident, "note", content)
    commit()
    return redirect(url_for("incidents.detail", incident_id=incident.id))
