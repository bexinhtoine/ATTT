# -*- coding: utf-8 -*-
"""
ingest.py - Pipeline tiếp nhận log từ agent.

    Agent --POST /api/v1/logs--> validate -> chuẩn hóa -> băm chống trùng -> lưu CSDL
          -> RuleEngine.evaluate() -> cảnh báo -> (API) kích hoạt tác tử AI

Mỗi sự kiện được gán event_hash = SHA1(agent_id | source | timestamp | event_id | định danh gốc | raw)
để một lô gửi lại (do mất ACK) không tạo bản ghi trùng.
"""
import hashlib
from datetime import timezone

from flask import current_app

from . import parsers
from .extensions import db
from .models import LogEvent, dumps, utcnow
from .detection import RuleEngine


def _naive_utc(dt_aware):
    return dt_aware.astimezone(timezone.utc).replace(tzinfo=None)


def compute_hash(agent_id, ev):
    extra = ev.get("extra") or {}
    ident = extra.get("record_id") or extra.get("cursor") or extra.get("offset") or extra.get("sim_id") or ""
    base = "|".join(str(x) for x in (agent_id, ev.get("source"), ev.get("timestamp"), ev.get("event_id"),
                                     ident, (ev.get("raw") or ev.get("message") or "")[:500]))
    return hashlib.sha1(base.encode("utf-8", "replace")).hexdigest()


def build_event(ev, agent):
    """dict đã chuẩn hóa -> đối tượng LogEvent (chưa add vào session)."""
    ev = parsers.normalize_event(ev, default_host=agent.hostname)
    dt = parsers.parse_iso(ev["timestamp"]) or parsers.utcnow()
    return LogEvent(
        agent_id=agent.id, event_time=_naive_utc(dt), source=ev["source"][:64], category=ev["category"][:32],
        action=(ev["action"] or "log")[:64], outcome=ev["outcome"], severity=ev["severity"],
        event_id=str(ev["event_id"])[:32] if ev.get("event_id") is not None else None,
        message=ev["message"], user_name=(ev.get("user") or None) and str(ev["user"])[:128],
        src_ip=(ev.get("src_ip") or None) and str(ev["src_ip"])[:64], src_port=ev.get("src_port"),
        process_name=(ev.get("process") or None) and str(ev["process"])[:128], pid=ev.get("pid"),
        host=(ev.get("host") or agent.hostname)[:128], raw=ev.get("raw"),
        extra=dumps(ev.get("extra") or {}), event_hash=compute_hash(agent.id, ev))


def ingest(agent, payload_events, run_rules=True):
    """Tiếp nhận một lô sự kiện. Trả về thống kê + danh sách (alert, is_new)."""
    max_batch = current_app.config.get("MAX_EVENTS_PER_BATCH", 2000)
    stats = {"received": len(payload_events), "accepted": 0, "duplicates": 0, "rejected": 0,
             "alerts": [], "event_ids": []}
    candidates, seen = [], set()
    for raw in payload_events[:max_batch]:
        if not isinstance(raw, dict):
            stats["rejected"] += 1
            continue
        try:
            # Agent có thể gửi dòng log thô {"raw": "...", "source": ..., "format": ...} để server tự phân tích
            if raw.get("raw") and not raw.get("message") and not raw.get("action"):
                parsed = parsers.parse_line(raw["raw"], raw.get("source"), agent.hostname, raw.get("format", "syslog"))
                if not parsed:
                    stats["rejected"] += 1
                    continue
                raw = parsed
            ev = build_event(raw, agent)
        except Exception:
            current_app.logger.exception("Sự kiện không hợp lệ")
            stats["rejected"] += 1
            continue
        if ev.event_hash in seen:
            stats["duplicates"] += 1
            continue
        seen.add(ev.event_hash)
        candidates.append(ev)
    stats["rejected"] += max(0, len(payload_events) - max_batch)

    # Loại các sự kiện đã tồn tại (theo hash) - truy vấn theo khối 500
    existing = set()
    hashes = [c.event_hash for c in candidates]
    for i in range(0, len(hashes), 500):
        rows = db.session.query(LogEvent.event_hash).filter(LogEvent.event_hash.in_(hashes[i:i + 500])).all()
        existing.update(r[0] for r in rows)
    new_events = [c for c in candidates if c.event_hash not in existing]
    stats["duplicates"] += len(candidates) - len(new_events)

    if new_events:
        db.session.add_all(new_events)
    agent.last_seen = utcnow()
    agent.status = "online"
    agent.events_count = (agent.events_count or 0) + len(new_events)
    db.session.commit()
    stats["accepted"] = len(new_events)
    stats["event_ids"] = [e.id for e in new_events]

    if run_rules and new_events:
        stats["alerts"] = RuleEngine().evaluate(new_events)
    return stats
