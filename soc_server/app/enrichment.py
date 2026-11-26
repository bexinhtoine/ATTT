# -*- coding: utf-8 -*-
"""
enrichment.py - Làm giàu dữ liệu (enrichment) cho cảnh báo.

Bổ sung ngữ cảnh cho một cảnh báo từ chính dữ liệu trong hệ thống:
  * IP nguồn   : phân loại (nội bộ/công cộng/loopback...), uy tín (bảng ip_reputation),
                 lịch sử 7 ngày (số sự kiện, số lần thất bại/thành công, số host bị nhắm, số tài khoản bị thử)
  * Tài khoản  : lần đầu xuất hiện, hoạt động 24h, số host đã đăng nhập, có phải tài khoản đặc quyền
  * Máy trạm   : thông tin agent, số sự kiện 24h, số cảnh báo đang mở
  * MITRE ATT&CK: tactic/technique của luật
  * Cảnh báo liên quan: cùng IP / cùng tài khoản trên cùng host trong 7 ngày
  * Ngữ cảnh thời gian: giờ địa phương, ngoài giờ hành chính, cuối tuần
"""
import ipaddress
from datetime import timedelta, timezone
from zoneinfo import ZoneInfo

from flask import current_app
from sqlalchemy import func

from .extensions import db
from .models import LogEvent, Alert, Agent, IpReputation, OPEN_STATUSES, utcnow

PRIVILEGED_USERS = ("root", "administrator", "admin", "system", "sa", "domain admin")

# Ánh xạ kỹ thuật MITRE ATT&CK dùng trong các luật mặc định: id -> (tactic, tên kỹ thuật)
MITRE_TECHNIQUES = {
    "T1110": ("Credential Access", "Brute Force"),
    "T1110.001": ("Credential Access", "Brute Force: Password Guessing"),
    "T1110.003": ("Credential Access", "Brute Force: Password Spraying"),
    "T1078": ("Initial Access / Persistence", "Valid Accounts"),
    "T1136.001": ("Persistence", "Create Account: Local Account"),
    "T1098": ("Persistence", "Account Manipulation"),
    "T1543.003": ("Persistence", "Create or Modify System Process: Windows Service"),
    "T1053.005": ("Execution / Persistence", "Scheduled Task/Job: Scheduled Task"),
    "T1070.001": ("Defense Evasion", "Indicator Removal: Clear Windows Event Logs"),
    "T1562.002": ("Defense Evasion", "Impair Defenses: Disable Windows Event Logging"),
    "T1548.003": ("Privilege Escalation", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"),
    "T1190": ("Initial Access", "Exploit Public-Facing Application"),
    "T1595": ("Reconnaissance", "Active Scanning"),
    "T1059.001": ("Execution", "Command and Scripting Interpreter: PowerShell"),
    "T1021.001": ("Lateral Movement", "Remote Services: Remote Desktop Protocol"),
    "T1021.004": ("Lateral Movement", "Remote Services: SSH"),
    "T1499": ("Impact", "Endpoint Denial of Service"),
}


def mitre_info(technique_id):
    if not technique_id:
        return {}
    tactic, name = MITRE_TECHNIQUES.get(technique_id, ("", ""))
    return {"technique_id": technique_id, "technique": name, "tactic": tactic,
            "url": "https://attack.mitre.org/techniques/%s/" % technique_id.replace(".", "/")}


# Dải địa chỉ "tài liệu" (RFC 5737 / RFC 3849) được dùng trong lab và dữ liệu trình diễn để đóng vai
# IP Internet. Python xếp chúng vào is_private nên phải tách riêng để coi như địa chỉ bên ngoài.
DOCUMENTATION_NETS = [ipaddress.ip_network(n) for n in
                      ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def classify_ip(ip):
    """Phân loại địa chỉ IP (không cần mạng)."""
    if not ip or ip in ("-", "?"):
        return {"ip": ip, "type": "none", "is_public": False, "is_internal": False}
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return {"ip": ip, "type": "hostname", "is_public": False, "is_internal": False}
    if addr.is_loopback:
        t = "loopback"
    elif any(addr in net for net in DOCUMENTATION_NETS):
        t = "public"                      # dải tài liệu: xem như địa chỉ ngoài Internet
    elif addr.is_private:
        t = "private"
    elif addr.is_link_local:
        t = "link-local"
    elif addr.is_multicast:
        t = "multicast"
    elif addr.is_reserved or addr.is_unspecified:
        t = "reserved"
    else:
        t = "public"
    return {"ip": ip, "type": t, "version": addr.version, "is_public": t == "public",
            "is_internal": t in ("private", "loopback", "link-local")}


def ip_reputation(ip):
    """Tra cứu bảng uy tín IP cục bộ (blocklist/allowlist do analyst hoặc AI bổ sung)."""
    if not ip:
        return {"verdict": "unknown", "source": None, "note": None}
    rec = IpReputation.query.filter_by(ip=ip).first()
    if rec:
        return rec.to_dict()
    return {"ip": ip, "verdict": "unknown", "source": None, "note": None}


def ip_history(ip, days=7, cutoff=None):
    if not ip:
        return {}
    cutoff = cutoff or utcnow()
    since = cutoff - timedelta(days=days)
    base = LogEvent.query.filter(LogEvent.src_ip == ip, LogEvent.event_time <= cutoff,
                                 LogEvent.received_at <= cutoff)
    q = base.filter(LogEvent.event_time >= since)
    total = q.count()
    if not total:
        return {"total_events": 0, "days": days}
    failed = q.filter(LogEvent.outcome == "failure", LogEvent.category == "authentication").count()
    success = q.filter(LogEvent.outcome == "success", LogEvent.category == "authentication").count()
    hosts = [r[0] for r in q.with_entities(LogEvent.host).distinct().limit(20)]
    users = [r[0] for r in q.with_entities(LogEvent.user_name).filter(LogEvent.user_name.isnot(None)).distinct().limit(30)]
    first_seen = base.with_entities(func.min(LogEvent.event_time)).scalar()
    last_seen = base.with_entities(func.max(LogEvent.event_time)).scalar()
    return {"days": days, "total_events": total, "failed_auth": failed, "success_auth": success,
            "hosts_targeted": hosts, "users_tried": users, "first_seen": first_seen, "last_seen": last_seen}


def user_context(user_name, host=None, cutoff=None):
    if not user_name:
        return {}
    cutoff = cutoff or utcnow()
    since = cutoff - timedelta(hours=24)
    base = LogEvent.query.filter(LogEvent.user_name == user_name, LogEvent.event_time <= cutoff,
                                 LogEvent.received_at <= cutoff)
    if host:
        base = base.filter(LogEvent.host == host)
    first_seen = base.with_entities(func.min(LogEvent.event_time)).scalar()
    q24 = base.filter(LogEvent.event_time >= since)
    hosts = [r[0] for r in q24.with_entities(LogEvent.host).distinct().limit(20)]
    return {"user": user_name, "is_privileged": user_name.lower() in PRIVILEGED_USERS,
            "first_seen": first_seen, "events_24h": q24.count(),
            "failed_24h": q24.filter(LogEvent.outcome == "failure").count(),
            "success_24h": q24.filter(LogEvent.outcome == "success",
                                      LogEvent.category == "authentication").count(),
            "hosts_24h": hosts,
            "is_new_account": bool(first_seen and first_seen >= cutoff - timedelta(days=1))}


def host_context(agent, host=None, cutoff=None):
    cutoff = cutoff or utcnow()
    since = cutoff - timedelta(hours=24)
    name = agent.hostname if agent else host
    ctx = {"host": name}
    if agent:
        ctx.update({"agent_id": agent.id, "os_type": agent.os_type, "os_version": agent.os_version,
                    "ip_address": agent.ip_address, "status": agent.status, "last_seen": agent.last_seen,
                    "metrics": agent.metrics_dict})
    ctx["inventory_is_live"] = True
    ctx["events_24h"] = LogEvent.query.filter(LogEvent.host == name, LogEvent.event_time >= since,
                                             LogEvent.event_time <= cutoff, LogEvent.received_at <= cutoff).count()
    ctx["open_alerts"] = Alert.query.filter(Alert.host == name, Alert.status.in_(OPEN_STATUSES),
                                            Alert.created_at <= cutoff).count()
    ctx["alerts_7d"] = Alert.query.filter(Alert.host == name, Alert.created_at <= cutoff,
                                          Alert.created_at >= cutoff - timedelta(days=7)).count()
    return ctx


def related_alerts(alert, days=7, limit=10, cutoff=None):
    cutoff = cutoff or utcnow()
    since = cutoff - timedelta(days=days)
    q = Alert.query.filter(Alert.id != alert.id, Alert.created_at >= since, Alert.created_at <= cutoff)
    conds = []
    if alert.src_ip:
        conds.append(Alert.src_ip == alert.src_ip)
    if alert.user_name and alert.host:
        conds.append(db.and_(Alert.user_name == alert.user_name, Alert.host == alert.host))
    if not conds:
        conds.append(Alert.host == alert.host)
    q = q.filter(db.or_(*conds)).order_by(Alert.created_at.desc()).limit(limit)
    return [{"id": a.id, "title": a.title, "severity": a.severity, "status": a.status,
             "created_at": a.created_at, "host": a.host, "src_ip": a.src_ip,
             "mitre_technique": a.mitre_technique} for a in q]


def time_context(dt_utc):
    tz = ZoneInfo(current_app.config.get("TIMEZONE", "Asia/Ho_Chi_Minh"))
    if dt_utc is None:
        dt_utc = utcnow()
    local = dt_utc.replace(tzinfo=timezone.utc).astimezone(tz)
    return {"local_time": local.strftime("%Y-%m-%d %H:%M:%S %Z"), "hour": local.hour,
            "weekday": local.strftime("%A"), "off_hours": local.hour < 7 or local.hour >= 19,
            "weekend": local.weekday() >= 5}


def enrich_alert(alert, cutoff=None):
    """Tổng hợp toàn bộ ngữ cảnh cho một cảnh báo -> dict (có thể lưu JSON)."""
    ip = alert.src_ip
    cutoff = cutoff or utcnow()
    enrichment = {
        "cutoff": cutoff.isoformat() + "Z", "mutable_context_is_live": True,
        "ip": {**classify_ip(ip), "reputation": ip_reputation(ip), "history": ip_history(ip, cutoff=cutoff)} if ip else None,
        "user": user_context(alert.user_name, alert.host, cutoff=cutoff) if alert.user_name else None,
        "host": host_context(alert.agent, alert.host, cutoff=cutoff),
        "mitre": mitre_info(alert.mitre_technique),
        "related_alerts": related_alerts(alert, cutoff=cutoff),
        "time": time_context(alert.last_event_time or alert.created_at),
        "rule": {"code": alert.rule.code, "name": alert.rule.name, "type": alert.rule.rule_type,
                 "severity": alert.rule.severity} if alert.rule else None,
    }
    # Những "chỉ dấu rủi ro" rút gọn giúp tác tử Triage (và người đọc) nắm nhanh
    flags = []
    if enrichment["ip"]:
        if enrichment["ip"].get("is_public"):
            flags.append("IP nguồn là địa chỉ công cộng (từ Internet)")
        if enrichment["ip"]["reputation"].get("verdict") in ("malicious", "suspicious"):
            flags.append("IP nguồn nằm trong danh sách uy tín xấu (%s)" % enrichment["ip"]["reputation"]["verdict"])
        h = enrichment["ip"].get("history") or {}
        if len(h.get("hosts_targeted") or []) > 1:
            flags.append("IP này đã nhắm tới %d máy khác nhau trong 7 ngày" % len(h["hosts_targeted"]))
        if len(h.get("users_tried") or []) >= 5:
            flags.append("IP này đã thử %d tài khoản khác nhau" % len(h["users_tried"]))
        if h.get("success_auth"):
            flags.append("IP này đã có %d lần xác thực THÀNH CÔNG" % h["success_auth"])
    if enrichment["user"]:
        if enrichment["user"].get("is_privileged"):
            flags.append("Tài khoản mục tiêu là tài khoản đặc quyền")
        if enrichment["user"].get("is_new_account"):
            flags.append("Tài khoản mới xuất hiện lần đầu trong 24 giờ")
    if enrichment["time"].get("off_hours") or enrichment["time"].get("weekend"):
        flags.append("Xảy ra ngoài giờ hành chính / cuối tuần")
    if enrichment["host"].get("open_alerts", 0) > 1:
        flags.append("Máy trạm đang có %d cảnh báo mở khác" % (enrichment["host"]["open_alerts"] - 1))
    if enrichment["related_alerts"]:
        flags.append("Có %d cảnh báo liên quan trong 7 ngày" % len(enrichment["related_alerts"]))
    enrichment["risk_flags"] = flags
    return enrichment
