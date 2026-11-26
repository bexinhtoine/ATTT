"""Transactional detection outbox and bounded background AI worker.

Jobs survive restarts. Detection results, AI enqueue and job completion commit
together. A lease heartbeat prevents a healthy slow worker from being reclaimed.
"""
import threading
import uuid
from datetime import timedelta

from sqlalchemy import and_, or_

from .extensions import db
from .models import WorkJob, Alert, LogEvent, dumps, loads, utcnow


def enqueue(kind, payload, object_id=None):
    job = WorkJob(kind=kind, object_id=object_id, payload=dumps(payload))
    db.session.add(job)
    db.session.flush()
    return job


def _eligible(now):
    return or_(and_(WorkJob.status == "queued", WorkJob.available_at <= now),
               and_(WorkJob.status == "running", WorkJob.lease_until < now))


def process_job(app, job_id):
    """Claim atomically; callers must have an app context. Return None if owned."""
    now, token = utcnow(), str(uuid.uuid4())
    lease_seconds = max(30, app.config.get("WORK_LEASE_SECONDS", 120))
    claimed = WorkJob.query.filter(WorkJob.id == job_id, _eligible(now)).update({
        WorkJob.status: "running", WorkJob.lease_token: token,
        WorkJob.lease_until: now + timedelta(seconds=lease_seconds),
        WorkJob.started_at: now, WorkJob.attempts: WorkJob.attempts + 1}, synchronize_session=False)
    db.session.commit()
    if not claimed:
        return None
    stop = threading.Event()

    def renew():
        while not stop.wait(lease_seconds / 3):
            with app.app_context():
                try:
                    WorkJob.query.filter_by(id=job_id, status="running", lease_token=token).update({
                        "lease_until": utcnow() + timedelta(seconds=lease_seconds)})
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                finally:
                    db.session.remove()

    lease_thread = threading.Thread(target=renew, daemon=True, name="soc-job-lease")
    lease_thread.start()
    try:
        job = db.session.get(WorkJob, job_id, populate_existing=True)
        payload = loads(job.payload, {})
        result = {"alerts": [], "ai_started": 0}
        if job.kind == "detection":
            from .detection import RuleEngine
            events = db.session.query(LogEvent).filter(LogEvent.id.in_(payload["event_ids"])).all()
            result["alerts"] = RuleEngine().evaluate(events, commit=False, strict=True)
            if app.config.get("AI_AUTO_TRIAGE", True):
                for alert, is_new in result["alerts"]:
                    if is_new:
                        enqueue("ai", {"stages": ["enrich", "triage"], "trigger": "auto"}, alert.id)
                        result["ai_started"] += 1
            serial_result = {"alert_ids": [a.id for a, _ in result["alerts"]],
                             "alerts": [{"id": a.id, "is_new": is_new} for a, is_new in result["alerts"]],
                             "ai_started": result["ai_started"]}
        elif job.kind == "ai":
            if db.session.get(Alert, job.object_id) is None:
                raise ValueError("Cảnh báo đã bị xóa")
            output = app.extensions["soc_orchestrator"].run(
                job.object_id, tuple(payload.get("stages", ["enrich", "triage"])),
                trigger=payload.get("trigger", "auto"), username=payload.get("username"))
            if any(isinstance(v, dict) and "error" in v for v in output.values()):
                raise RuntimeError("Một giai đoạn AI thất bại; xem ai_runs")
            serial_result = {"stages": list(output)}
        else:
            raise ValueError("Loại tác vụ không hợp lệ")
        changed = WorkJob.query.filter_by(id=job_id, status="running", lease_token=token).update({
            "status": "succeeded", "finished_at": utcnow(), "lease_until": None,
            "error": None, "result": dumps(serial_result)}, synchronize_session=False)
        if not changed:
            raise RuntimeError("Đã mất lease của tác vụ")
        db.session.commit()
        return result
    except Exception as exc:
        db.session.rollback()
        job = db.session.get(WorkJob, job_id, populate_existing=True)
        if job and job.lease_token == token:
            retry = job.attempts < app.config.get("WORK_MAX_ATTEMPTS", 3)
            job.status = "queued" if retry else "failed"
            job.available_at = utcnow() + timedelta(seconds=min(60, 2 ** job.attempts))
            job.finished_at = None if retry else utcnow()
            job.lease_until = None
            job.error = "%s: %s" % (type(exc).__name__, exc)
            db.session.commit()
        app.logger.exception("Tác vụ %s thất bại", job_id)
        return {"alerts": [], "ai_started": 0, "error": str(exc)}
    finally:
        stop.set()
        lease_thread.join(timeout=2)


def start_worker(app):
    def loop(kind):
        while True:
            with app.app_context():
                try:
                    ids = [r.id for r in WorkJob.query.filter(WorkJob.kind == kind, _eligible(utcnow())).order_by(WorkJob.id).limit(10)]
                    for job_id in ids:
                        process_job(app, job_id)
                except Exception:
                    db.session.rollback()
                    app.logger.exception("Lỗi worker")
                finally:
                    db.session.remove()
            threading.Event().wait(1)
    workers = []
    for kind in ("detection", "ai"):
        worker = threading.Thread(target=loop, args=(kind,), daemon=True, name="soc-worker-" + kind)
        worker.start()
        workers.append(worker)
    app.extensions["soc_workers"] = workers
    app.extensions["soc_worker"] = workers[-1]
