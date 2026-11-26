"""Validated ingest with per-item receipts and a transactional detection outbox."""
import hashlib
import json
from datetime import timezone

from flask import current_app
from sqlalchemy.exc import IntegrityError

from . import parsers
from .extensions import db
from .models import Agent, Alert, LogEvent, WorkJob, dumps, loads, utcnow


def _legacy_hash(agent_id, ev):
    extra = ev.get("extra") or {}
    ident = extra.get("record_id") or extra.get("cursor") or extra.get("offset") or extra.get("sim_id") or ""
    base = "|".join(str(x) for x in (agent_id, ev.get("source"), ev.get("timestamp"), ev.get("event_id"),
                                     ident, (ev.get("raw") or ev.get("message") or "")[:500]))
    return hashlib.sha1(base.encode("utf-8", "replace")).hexdigest()


def compute_hash(agent_id, ev):
    uid = ev.get("event_uid") or (ev.get("extra") or {}).get("event_uid")
    if uid:
        base = json.dumps([agent_id, "event_uid", uid], ensure_ascii=False)
    else:
        extra = ev.get("extra") or {}
        ident = [extra.get(k) for k in ("channel", "record_id", "cursor", "offset", "sim_id")]
        base = json.dumps([agent_id, ev.get("source"), ev.get("timestamp"), ev.get("event_id"),
                           ident, ev.get("raw") or ev.get("message") or ""], ensure_ascii=False)
    return hashlib.sha1(base.encode("utf-8", "replace")).hexdigest()


def _validate(ev):
    for field in ("source", "host", "message", "raw", "action", "user", "process", "timestamp", "event_uid",
                  "category", "severity", "outcome", "src_ip", "format"):
        if field in ev and ev[field] is not None and not isinstance(ev[field], str):
            raise ValueError("%s phải là chuỗi" % field)
    if "extra" in ev and not isinstance(ev["extra"], dict):
        raise ValueError("extra phải là object")
    for field in ("pid", "src_port"):
        if ev.get(field) is not None:
            if isinstance(ev[field], bool) or not isinstance(ev[field], (int, str)):
                raise ValueError("%s phải là số nguyên" % field)
            number = int(ev[field])
            if number < 0 or number > (65535 if field == "src_port" else 2147483647):
                raise ValueError("%s ngoài giới hạn" % field)
    if ev.get("event_id") is not None and type(ev["event_id"]) not in (str, int):
        raise ValueError("event_id phải là chuỗi hoặc số nguyên")
    if ev.get("timestamp") and parsers.parse_iso(ev["timestamp"]) is None:
        raise ValueError("timestamp không hợp lệ")
    uid = ev.get("event_uid", (ev.get("extra") or {}).get("event_uid"))
    if uid is not None and (not isinstance(uid, str) or not uid.strip() or len(uid) > 128):
        raise ValueError("event_uid không hợp lệ")
    if not (ev.get("raw") or ev.get("message") or ev.get("action")):
        raise ValueError("Sự kiện không có nội dung")


def build_event(ev, agent):
    original = dict(ev)
    uid = ev.get("event_uid") or (ev.get("extra") or {}).get("event_uid")
    fingerprint = hashlib.sha256(json.dumps(ev, sort_keys=True, ensure_ascii=False,
                                           separators=(",", ":")).encode("utf-8")).hexdigest()
    if ev.get("raw") and not ev.get("message") and not ev.get("action"):
        parsed = parsers.parse_line(ev["raw"], ev.get("source"), agent.hostname, ev.get("format", "syslog"))
        if not parsed:
            raise ValueError("Không phân tích được log thô")
        ev = parsed
        if original.get("timestamp"):
            ev["timestamp"] = original["timestamp"]
    full_payload = dict(ev)
    ev = parsers.normalize_event(ev, default_host=agent.hostname)
    if uid:
        full_payload["event_uid"] = uid
    identity = compute_hash(agent.id, full_payload if original.get("timestamp") or uid else original)
    extra = dict(ev.get("extra") or {})
    extra["_transport_hash"] = fingerprint
    if uid:
        extra["event_uid"] = uid
    if not original.get("timestamp"):
        extra["timestamp_inferred"] = True
    extra["raw_truncated"] = len(str(full_payload.get("raw") or "")) > 8000
    extra["message_truncated"] = len(str(full_payload.get("message") or "")) > 4000
    if extra["raw_truncated"]:
        extra["original_raw_sha256"] = hashlib.sha256(full_payload["raw"].encode("utf-8")).hexdigest()
    dt = parsers.parse_iso(ev["timestamp"]).astimezone(timezone.utc).replace(tzinfo=None)
    return LogEvent(
        agent_id=agent.id, event_time=dt, source=ev["source"][:64], category=ev["category"][:32],
        action=(ev["action"] or "log")[:64], outcome=ev["outcome"], severity=ev["severity"],
        event_id=str(ev["event_id"])[:32] if ev.get("event_id") is not None else None,
        message=ev["message"], user_name=(ev.get("user") or None) and str(ev["user"])[:128],
        src_ip=(ev.get("src_ip") or None) and str(ev["src_ip"])[:64], src_port=ev.get("src_port"),
        process_name=(ev.get("process") or None) and str(ev["process"])[:128],
        pid=int(ev["pid"]) if ev.get("pid") is not None else None,
        host=(ev.get("host") or agent.hostname)[:128], raw=ev.get("raw"), extra=dumps(extra), event_hash=identity)


def ingest(agent, payload_events, run_rules=True):
    from .work import enqueue, process_job
    max_batch = current_app.config.get("MAX_EVENTS_PER_BATCH", 2000)
    stats = {"received": len(payload_events), "accepted": 0, "duplicates": 0, "rejected": 0,
             "deferred": 0, "alerts": [], "event_ids": [], "receipts": [], "ai_started": 0}
    # Start the outer write transaction before releasing any SQLite savepoint.
    agent.last_seen, agent.status = utcnow(), "online"
    db.session.flush()
    for index, raw in enumerate(payload_events):
        receipt = {"index": index}
        stats["receipts"].append(receipt)
        if index >= max_batch:
            receipt.update(status="retry", reason="batch_limit")
            stats["deferred"] += 1
            continue
        try:
            if not isinstance(raw, dict):
                raise ValueError("Sự kiện phải là object")
            _validate(raw)
            ev = build_event(raw, agent)
            existing = LogEvent.query.filter_by(event_hash=ev.event_hash).first()
            if existing is None and not ev.extra_dict.get("event_uid"):
                legacy = raw
                if raw.get("raw") and not raw.get("message") and not raw.get("action"):
                    legacy = parsers.parse_line(raw["raw"], raw.get("source"), agent.hostname, raw.get("format", "syslog"))
                legacy = parsers.normalize_event(legacy, default_host=agent.hostname)
                existing = LogEvent.query.filter_by(event_hash=_legacy_hash(agent.id, legacy)).first()
            if existing is None:
                try:
                    with db.session.begin_nested():
                        db.session.add(ev)
                        db.session.flush()
                except IntegrityError:
                    existing = LogEvent.query.filter_by(event_hash=ev.event_hash).first()
                    if existing is None:
                        raise
            if existing is not None:
                if (ev.extra_dict.get("event_uid") and existing.extra_dict.get("_transport_hash")
                        != ev.extra_dict.get("_transport_hash")):
                    receipt.update(status="rejected", reason="event_uid_conflict")
                    stats["rejected"] += 1
                else:
                    receipt.update(status="duplicate", event_id=existing.id)
                    stats["duplicates"] += 1
            else:
                receipt.update(status="accepted", event_id=ev.id)
                stats["accepted"] += 1
                stats["event_ids"].append(ev.id)
        except (ValueError, TypeError, AttributeError, OverflowError) as exc:
            receipt.update(status="rejected", reason=str(exc)[:300])
            stats["rejected"] += 1
    Agent.query.filter_by(id=agent.id).update(
        {Agent.events_count: db.func.coalesce(Agent.events_count, 0) + stats["accepted"]},
        synchronize_session=False)
    db.session.expire(agent, ["events_count"])
    job = enqueue("detection", {"event_ids": stats["event_ids"]}) if run_rules and stats["event_ids"] else None
    db.session.commit()  # Events and their detection job become durable together.
    if job is not None:
        stats["detection_job_id"] = job.id
        result = process_job(current_app._get_current_object(), job.id)
        if result:
            stats["alerts"], stats["ai_started"] = result["alerts"], result["ai_started"]
            if result.get("error"):
                stats["detection_pending"] = True
        else:
            current_job = db.session.get(WorkJob, job.id, populate_existing=True)
            stats["detection_pending"] = current_job.status != "succeeded"
            if current_job.status == "succeeded":
                saved = loads(current_job.result, {})
                stats["ai_started"] = saved.get("ai_started", 0)
                stats["alerts"] = [(alert, row["is_new"]) for row in saved.get("alerts", [])
                                   if (alert := db.session.get(Alert, row["id"])) is not None]
    return stats
