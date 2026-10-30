# -*- coding: utf-8 -*-
"""stats.py - Các truy vấn thống kê phục vụ dashboard và báo cáo."""
from datetime import timedelta, timezone, datetime
from zoneinfo import ZoneInfo

from flask import current_app
from sqlalchemy import func

from .extensions import db
from .models import LogEvent, Alert, Agent, AIRun, OPEN_STATUSES, utcnow


def _tz():
    return ZoneInfo(current_app.config.get("TIMEZONE", "Asia/Ho_Chi_Minh"))


def to_local(dt):
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc).astimezone(_tz())


def events_per_hour(hours=24, since=None, until=None):
    """Số sự kiện theo từng giờ (nhãn theo giờ địa phương)."""
    until = until or utcnow()
    since = since or (until - timedelta(hours=hours))
    rows = (db.session.query(func.strftime("%Y-%m-%d %H", LogEvent.event_time), func.count(LogEvent.id))
            .filter(LogEvent.event_time >= since, LogEvent.event_time <= until)
            .group_by(func.strftime("%Y-%m-%d %H", LogEvent.event_time)).all())
    counts = {r[0]: r[1] for r in rows}
    out = []
    cur = since.replace(minute=0, second=0, microsecond=0)
    while cur <= until:
        key = cur.strftime("%Y-%m-%d %H")
        out.append({"label": to_local(cur).strftime("%d/%m %Hh"), "count": counts.get(key, 0)})
        cur += timedelta(hours=1)
    return out


def alerts_per_day(days=7):
    since = (utcnow() - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    rows = (db.session.query(func.strftime("%Y-%m-%d", Alert.created_at), Alert.severity, func.count(Alert.id))
            .filter(Alert.created_at >= since).group_by(func.strftime("%Y-%m-%d", Alert.created_at), Alert.severity).all())
    by_day = {}
    for day, sev, n in rows:
        by_day.setdefault(day, {})[sev] = n
    out = []
    cur = since
    while cur <= utcnow():
        key = cur.strftime("%Y-%m-%d")
        out.append({"label": cur.strftime("%d/%m"), **{s: by_day.get(key, {}).get(s, 0)
                                                     for s in ("critical", "high", "medium", "low", "info")}})
        cur += timedelta(days=1)
    return out


def group_count(column, since=None, until=None, limit=10, where=None):
    q = db.session.query(column, func.count(LogEvent.id).label("n"))
    if since is not None:
        q = q.filter(LogEvent.event_time >= since)
    if until is not None:
        q = q.filter(LogEvent.event_time <= until)
    if where is not None:
        q = q.filter(where)
    q = q.filter(column.isnot(None)).group_by(column).order_by(func.count(LogEvent.id).desc()).limit(limit)
    return [{"key": r[0], "count": r[1]} for r in q.all()]


def dashboard_stats():
    now = utcnow()
    since24 = now - timedelta(hours=24)
    since7d = now - timedelta(days=7)
    offline_after = current_app.config.get("AGENT_OFFLINE_AFTER", 180)
    agents = Agent.query.all()
    online = sum(1 for a in agents if a.last_seen and (now - a.last_seen).total_seconds() <= offline_after)
    sev_rows = db.session.query(LogEvent.severity, func.count(LogEvent.id)).filter(
        LogEvent.event_time >= since24).group_by(LogEvent.severity).all()
    alert_sev_rows = db.session.query(Alert.severity, func.count(Alert.id)).filter(
        Alert.status.in_(OPEN_STATUSES)).group_by(Alert.severity).all()
    status_rows = db.session.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
    ai_rows = db.session.query(AIRun.mode, func.count(AIRun.id)).group_by(AIRun.mode).all()
    latest_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()
    return {
        "generated_at": now,
        "kpi": {
            "events_24h": LogEvent.query.filter(LogEvent.event_time >= since24).count(),
            "events_total": db.session.query(func.count(LogEvent.id)).scalar() or 0,
            "alerts_open": Alert.query.filter(Alert.status.in_(OPEN_STATUSES)).count(),
            "alerts_critical_open": Alert.query.filter(Alert.status.in_(OPEN_STATUSES),
                                                       Alert.severity.in_(("critical", "high"))).count(),
            "alerts_24h": Alert.query.filter(Alert.created_at >= since24).count(),
            "agents_total": len(agents), "agents_online": online,
            "ai_triaged": Alert.query.filter(Alert.ai_verdict.isnot(None)).count(),
            "ai_runs": sum(n for _, n in ai_rows),
        },
        "events_per_hour": events_per_hour(24),
        "alerts_per_day": alerts_per_day(7),
        "events_by_severity": {s: n for s, n in sev_rows},
        "open_alerts_by_severity": {s: n for s, n in alert_sev_rows},
        "alerts_by_status": {s: n for s, n in status_rows},
        "ai_runs_by_mode": {m or "local": n for m, n in ai_rows},
        "top_sources": group_count(LogEvent.source, since24),
        "top_hosts": group_count(LogEvent.host, since24),
        "top_src_ips": group_count(LogEvent.src_ip, since24, where=LogEvent.outcome == "failure"),
        "top_failed_users": group_count(LogEvent.user_name, since24, where=LogEvent.outcome == "failure"),
        "top_actions": group_count(LogEvent.action, since24),
        "latest_alerts": [a.to_dict() for a in latest_alerts],
        "agents": [a.to_dict() for a in agents],
        "alerts_7d": Alert.query.filter(Alert.created_at >= since7d).count(),
    }


def report_stats(since, until):
    """Thống kê cho trang báo cáo trong một khoảng thời gian tùy chọn."""
    ev_q = LogEvent.query.filter(LogEvent.event_time >= since, LogEvent.event_time <= until)
    al_q = Alert.query.filter(Alert.created_at >= since, Alert.created_at <= until)
    hours = max(1, int((until - since).total_seconds() // 3600))
    sev = db.session.query(LogEvent.severity, func.count(LogEvent.id)).filter(
        LogEvent.event_time >= since, LogEvent.event_time <= until).group_by(LogEvent.severity).all()
    cat = db.session.query(LogEvent.category, func.count(LogEvent.id)).filter(
        LogEvent.event_time >= since, LogEvent.event_time <= until).group_by(LogEvent.category).all()
    al_sev = db.session.query(Alert.severity, func.count(Alert.id)).filter(
        Alert.created_at >= since, Alert.created_at <= until).group_by(Alert.severity).all()
    al_status = db.session.query(Alert.status, func.count(Alert.id)).filter(
        Alert.created_at >= since, Alert.created_at <= until).group_by(Alert.status).all()
    al_rule = (db.session.query(Alert.rule_id, func.count(Alert.id)).filter(
        Alert.created_at >= since, Alert.created_at <= until).group_by(Alert.rule_id)
        .order_by(func.count(Alert.id).desc()).limit(10).all())
    from .models import DetectionRule
    rules = {r.id: r for r in DetectionRule.query.filter(DetectionRule.id.in_([r[0] for r in al_rule] or [0])).all()}
    verdicts = db.session.query(Alert.ai_verdict, func.count(Alert.id)).filter(
        Alert.created_at >= since, Alert.created_at <= until, Alert.ai_verdict.isnot(None)).group_by(Alert.ai_verdict).all()
    resolved = al_q.filter(Alert.resolved_at.isnot(None)).all()
    mttr = None
    if resolved:
        mttr = sum((a.resolved_at - a.created_at).total_seconds() for a in resolved) / len(resolved) / 60
    return {
        "since": since, "until": until, "events_total": ev_q.count(), "alerts_total": al_q.count(),
        "events_by_severity": dict(sev), "events_by_category": dict(cat),
        "alerts_by_severity": dict(al_sev), "alerts_by_status": dict(al_status),
        "alerts_by_rule": [{"rule": rules[r[0]].name if r[0] in rules else "?", "code": rules[r[0]].code if r[0] in rules else "", "count": r[1]} for r in al_rule],
        "ai_verdicts": dict(verdicts), "mttr_minutes": round(mttr, 1) if mttr is not None else None,
        "events_per_hour": events_per_hour(hours, since, until) if hours <= 72 else [],
        "top_hosts": group_count(LogEvent.host, since, until), "top_sources": group_count(LogEvent.source, since, until),
        "top_src_ips": group_count(LogEvent.src_ip, since, until, where=LogEvent.outcome == "failure"),
        "top_failed_users": group_count(LogEvent.user_name, since, until, where=LogEvent.outcome == "failure"),
        "top_actions": group_count(LogEvent.action, since, until, limit=15),
    }
