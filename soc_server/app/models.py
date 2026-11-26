# -*- coding: utf-8 -*-
"""
models.py - Mô hình dữ liệu (SQLAlchemy) của Web SOC.

Các bảng:
    users              Tài khoản người dùng Web SOC (admin / analyst / viewer)
    agents             Máy trạm (host) đã đăng ký gửi log, kèm API key
    log_events         Sự kiện log đã chuẩn hóa nhận từ agent
    detection_rules    Luật phát hiện (match / threshold / sequence)
    alerts             Cảnh báo do luật sinh ra, kèm kết quả phân tích AI
    alert_events       Bảng liên kết cảnh báo <-> sự kiện
    investigations     Báo cáo điều tra (do AI hoặc analyst tạo)
    knowledge_articles Cơ sở tri thức tích lũy
    ai_runs            Nhật ký các lần chạy tác tử AI
    audit_logs         Nhật ký thao tác người dùng trên Web SOC
    ip_reputation      Danh sách uy tín IP (blocklist/allowlist cục bộ) phục vụ làm giàu dữ liệu
"""
import json
import hashlib
import secrets
import uuid
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash

from .extensions import db


def utcnow():
    """Thời điểm hiện tại UTC, dạng naive (SQLite không lưu múi giờ)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, default=str)


def loads(text, default=None):
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


ROLES = ("admin", "analyst", "viewer")
ROLE_LABELS = {"admin": "Quản trị viên", "analyst": "Chuyên viên phân tích", "viewer": "Người xem"}
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_LABELS = {"critical": "Nghiêm trọng", "high": "Cao", "medium": "Trung bình",
                   "low": "Thấp", "info": "Thông tin"}
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
ALERT_STATUSES = ("new", "triaged", "investigating", "resolved", "false_positive")
ALERT_STATUS_LABELS = {"new": "Mới", "triaged": "Đã phân loại", "investigating": "Đang điều tra",
                       "resolved": "Đã xử lý", "false_positive": "Dương tính giả"}
OPEN_STATUSES = ("new", "triaged", "investigating")
RULE_TYPES = ("match", "threshold", "sequence")
RULE_TYPE_LABELS = {"match": "Khớp mẫu (1 sự kiện)", "threshold": "Ngưỡng theo cửa sổ thời gian",
                    "sequence": "Chuỗi sự kiện (A rồi B)"}
AGENT_STATUSES = ("online", "offline", "pending")


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(128))
    email = db.Column(db.String(128))
    role = db.Column(db.String(16), nullable=False, default="analyst")
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    failed_logins = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def role_label(self):
        return ROLE_LABELS.get(self.role, self.role)

    def to_dict(self):
        return {"id": self.id, "username": self.username, "full_name": self.full_name,
                "email": self.email, "role": self.role, "is_active": self.is_active,
                "created_at": self.created_at, "last_login": self.last_login}


class Agent(db.Model):
    __tablename__ = "agents"
    id = db.Column(db.Integer, primary_key=True)
    agent_uid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    hostname = db.Column(db.String(128), nullable=False, index=True)
    os_type = db.Column(db.String(32))            # windows | linux | other
    os_version = db.Column(db.String(128))
    ip_address = db.Column(db.String(64))
    agent_version = db.Column(db.String(32))
    api_key_hash = db.Column(db.String(64), unique=True, index=True)
    api_key_prefix = db.Column(db.String(12))
    status = db.Column(db.String(16), default="pending", nullable=False)
    registered_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen = db.Column(db.DateTime)
    events_count = db.Column(db.Integer, default=0, nullable=False)
    collectors = db.Column(db.Text)               # JSON: danh sách collector agent đang chạy
    metrics = db.Column(db.Text)                  # JSON: CPU/RAM/disk từ heartbeat gần nhất
    tags = db.Column(db.String(255))
    notes = db.Column(db.Text)

    @staticmethod
    def hash_key(plain):
        return hashlib.sha256(plain.encode("utf-8")).hexdigest()

    def issue_api_key(self):
        """Sinh API key mới, lưu hash và trả về bản rõ (chỉ hiển thị một lần)."""
        plain = "soc_" + secrets.token_urlsafe(32)
        self.api_key_hash = self.hash_key(plain)
        self.api_key_prefix = plain[:10]
        return plain

    @property
    def collectors_list(self):
        return loads(self.collectors, [])

    @property
    def metrics_dict(self):
        return loads(self.metrics, {})

    def to_dict(self):
        return {"id": self.id, "agent_uid": self.agent_uid, "hostname": self.hostname,
                "os_type": self.os_type, "os_version": self.os_version, "ip_address": self.ip_address,
                "agent_version": self.agent_version, "status": self.status,
                "registered_at": self.registered_at, "last_seen": self.last_seen,
                "events_count": self.events_count, "collectors": self.collectors_list,
                "metrics": self.metrics_dict, "tags": self.tags}


class LogEvent(db.Model):
    __tablename__ = "log_events"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey("agents.id"), index=True)
    received_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    event_time = db.Column(db.DateTime, nullable=False, index=True)
    source = db.Column(db.String(64), index=True)
    category = db.Column(db.String(32), index=True)
    action = db.Column(db.String(64), index=True)
    outcome = db.Column(db.String(16))
    severity = db.Column(db.String(16), index=True)
    event_id = db.Column(db.String(32), index=True)
    message = db.Column(db.Text)
    user_name = db.Column(db.String(128), index=True)
    src_ip = db.Column(db.String(64), index=True)
    src_port = db.Column(db.Integer)
    process_name = db.Column(db.String(128))
    pid = db.Column(db.Integer)
    host = db.Column(db.String(128), index=True)
    raw = db.Column(db.Text)
    extra = db.Column(db.Text)                    # JSON
    event_hash = db.Column(db.String(40), unique=True)

    agent = db.relationship("Agent", backref=db.backref("events", lazy="dynamic"))

    @property
    def extra_dict(self):
        return loads(self.extra, {})

    def to_dict(self, with_raw=False):
        d = {"id": self.id, "agent_id": self.agent_id, "received_at": self.received_at,
             "event_time": self.event_time, "source": self.source, "category": self.category,
             "action": self.action, "outcome": self.outcome, "severity": self.severity,
             "event_id": self.event_id, "message": self.message, "user": self.user_name,
             "src_ip": self.src_ip, "src_port": self.src_port, "process": self.process_name,
             "pid": self.pid, "host": self.host, "extra": self.extra_dict}
        if with_raw:
            d["raw"] = self.raw
        return d

    def compact(self):
        """Bản rút gọn dùng làm ngữ cảnh cho tác tử AI."""
        return {"id": self.id, "time": self.event_time.strftime("%Y-%m-%d %H:%M:%S") if self.event_time else None,
                "host": self.host, "source": self.source, "event_id": self.event_id, "action": self.action,
                "outcome": self.outcome, "severity": self.severity, "user": self.user_name,
                "src_ip": self.src_ip, "message": (self.message or "")[:300]}


class DetectionRule(db.Model):
    __tablename__ = "detection_rules"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(16), unique=True)                 # R01, R02 ...
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text)
    rule_type = db.Column(db.String(16), nullable=False, default="match")
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    severity = db.Column(db.String(16), default="medium", nullable=False)
    conditions = db.Column(db.Text, nullable=False, default="{}")  # JSON điều kiện khớp
    threshold_count = db.Column(db.Integer, default=5)
    window_seconds = db.Column(db.Integer, default=300)
    group_by = db.Column(db.String(32), default="src_ip")         # src_ip | user_name | host
    distinct_field = db.Column(db.String(32))                     # đếm số giá trị khác nhau (password spraying)
    title_template = db.Column(db.String(255))
    mitre_tactic = db.Column(db.String(64))
    mitre_technique = db.Column(db.String(32))
    is_builtin = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    hits = db.Column(db.Integer, default=0)

    @property
    def conditions_dict(self):
        return loads(self.conditions, {})

    @property
    def type_label(self):
        return RULE_TYPE_LABELS.get(self.rule_type, self.rule_type)

    def to_dict(self):
        return {"id": self.id, "code": self.code, "name": self.name, "description": self.description,
                "rule_type": self.rule_type, "enabled": self.enabled, "severity": self.severity,
                "conditions": self.conditions_dict, "threshold_count": self.threshold_count,
                "window_seconds": self.window_seconds, "group_by": self.group_by,
                "distinct_field": self.distinct_field, "title_template": self.title_template,
                "mitre_tactic": self.mitre_tactic, "mitre_technique": self.mitre_technique,
                "is_builtin": self.is_builtin, "hits": self.hits}


class AlertEvent(db.Model):
    __tablename__ = "alert_events"
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("log_events.id", ondelete="CASCADE"), primary_key=True)


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("detection_rules.id"), index=True)
    agent_id = db.Column(db.Integer, db.ForeignKey("agents.id"), index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(16), nullable=False, default="medium", index=True)
    status = db.Column(db.String(24), nullable=False, default="new", index=True)
    priority = db.Column(db.Integer)                    # 1 (cao nhất) .. 5
    event_count = db.Column(db.Integer, default=1)
    first_event_time = db.Column(db.DateTime)
    last_event_time = db.Column(db.DateTime)
    src_ip = db.Column(db.String(64), index=True)
    user_name = db.Column(db.String(128), index=True)
    host = db.Column(db.String(128), index=True)
    mitre_tactic = db.Column(db.String(64))
    mitre_technique = db.Column(db.String(32))
    dedup_key = db.Column(db.String(255), index=True)
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Kết quả do tác tử AI tạo
    ai_verdict = db.Column(db.String(32))               # true_positive | suspicious | false_positive ...
    ai_confidence = db.Column(db.Float)
    ai_priority = db.Column(db.Integer)
    ai_summary = db.Column(db.Text)
    ai_data = db.Column(db.Text)                        # JSON: triage + enrichment đầy đủ
    ai_mode = db.Column(db.String(16))                  # llm | local
    ai_updated_at = db.Column(db.DateTime)
    resolution_note = db.Column(db.Text)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    rule = db.relationship("DetectionRule", backref=db.backref("alerts", lazy="dynamic"))
    agent = db.relationship("Agent", backref=db.backref("alerts", lazy="dynamic"))
    assignee = db.relationship("User", foreign_keys=[assigned_to])
    resolver = db.relationship("User", foreign_keys=[resolved_by])
    events = db.relationship("LogEvent", secondary="alert_events", lazy="dynamic",
                             order_by="LogEvent.event_time")

    @property
    def status_label(self):
        return ALERT_STATUS_LABELS.get(self.status, self.status)

    @property
    def severity_label(self):
        return SEVERITY_LABELS.get(self.severity, self.severity)

    @property
    def ai(self):
        return loads(self.ai_data, {})

    @property
    def is_open(self):
        return self.status in OPEN_STATUSES

    def to_dict(self):
        return {"id": self.id, "rule_id": self.rule_id, "rule": self.rule.name if self.rule else None,
                "agent_id": self.agent_id, "host": self.host, "created_at": self.created_at,
                "updated_at": self.updated_at, "title": self.title, "description": self.description,
                "severity": self.severity, "status": self.status, "priority": self.priority,
                "event_count": self.event_count, "first_event_time": self.first_event_time,
                "last_event_time": self.last_event_time, "src_ip": self.src_ip,
                "user": self.user_name, "mitre_tactic": self.mitre_tactic,
                "mitre_technique": self.mitre_technique, "ai_verdict": self.ai_verdict,
                "ai_confidence": self.ai_confidence, "ai_priority": self.ai_priority,
                "ai_summary": self.ai_summary, "ai_mode": self.ai_mode,
                "assigned_to": self.assignee.username if self.assignee else None,
                "resolution_note": self.resolution_note}


INCIDENT_STATUSES = {"new": "Mới", "investigating": "Đang điều tra", "resolved": "Đã xử lý", "closed": "Đã đóng"}


class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text, default="")
    status = db.Column(db.String(24), default="new", nullable=False, index=True)
    severity = db.Column(db.String(16), default="medium", nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    version = db.Column(db.Integer, default=1, nullable=False)
    merged_into_id = db.Column(db.Integer, db.ForeignKey("incidents.id"))
    assignee = db.relationship("User")
    links = db.relationship("IncidentAlert", back_populates="incident", cascade="all, delete-orphan")
    activities = db.relationship("IncidentActivity", back_populates="incident", order_by="IncidentActivity.id.desc()")

    @property
    def status_label(self):
        return INCIDENT_STATUSES.get(self.status, self.status)


class IncidentAlert(db.Model):
    __tablename__ = "incident_alerts"
    # Each alert belongs to at most one incident. Moving it requires an explicit merge/split.
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False, index=True)
    reason = db.Column(db.Text, nullable=False)
    linked_by = db.Column(db.String(64), nullable=False)
    linked_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    incident = db.relationship("Incident", back_populates="links")
    alert = db.relationship("Alert", backref=db.backref("incident_link", uselist=False))


class IncidentActivity(db.Model):
    __tablename__ = "incident_activities"
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    username = db.Column(db.String(64), nullable=False)
    action = db.Column(db.String(32), nullable=False)
    detail = db.Column(db.Text, nullable=False)
    incident = db.relationship("Incident", back_populates="activities")


class Investigation(db.Model):
    __tablename__ = "investigations"
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    created_by = db.Column(db.String(64))               # tên analyst hoặc "ai:investigation"
    mode = db.Column(db.String(16))                     # llm | local | manual
    status = db.Column(db.String(16), default="done")
    hypothesis = db.Column(db.Text)
    summary = db.Column(db.Text)
    timeline = db.Column(db.Text)                       # JSON [{time, host, event, note}]
    attack_chain = db.Column(db.Text)                   # JSON [{tactic, technique, evidence}]
    iocs = db.Column(db.Text)                           # JSON {ips:[], users:[], processes:[], files:[]}
    impact = db.Column(db.Text)
    root_cause = db.Column(db.Text)
    recommendations = db.Column(db.Text)                # JSON [str]
    raw = db.Column(db.Text)                            # JSON toàn bộ kết quả

    alert = db.relationship("Alert", backref=db.backref("investigations", lazy="dynamic",
                                                        order_by="Investigation.created_at.desc()"))

    @property
    def timeline_list(self):
        return loads(self.timeline, [])

    @property
    def attack_chain_list(self):
        return loads(self.attack_chain, [])

    @property
    def iocs_dict(self):
        return loads(self.iocs, {})

    @property
    def recommendations_list(self):
        return loads(self.recommendations, [])


class KnowledgeArticle(db.Model):
    __tablename__ = "knowledge_articles"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text)
    content = db.Column(db.Text)                        # Markdown
    category = db.Column(db.String(64))                 # playbook | lesson | indicator | reference
    tags = db.Column(db.String(255))                    # phân tách bằng dấu phẩy
    source = db.Column(db.String(16), default="manual") # manual | ai
    related_alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"))
    related_rule_id = db.Column(db.Integer, db.ForeignKey("detection_rules.id"))
    mitre_technique = db.Column(db.String(32))
    created_by = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    times_used = db.Column(db.Integer, default=0)

    related_alert = db.relationship("Alert", backref=db.backref("knowledge_articles", lazy="dynamic"))
    review = db.relationship("KnowledgeReview", uselist=False, cascade="all, delete-orphan", back_populates="article")

    @property
    def review_status(self):
        return self.review.status if self.review else ("approved" if self.source == "manual" else "draft")

    @property
    def tag_list(self):
        return [t.strip() for t in (self.tags or "").split(",") if t.strip()]

    def to_dict(self):
        return {"id": self.id, "title": self.title, "summary": self.summary, "category": self.category,
                "tags": self.tag_list, "source": self.source, "mitre_technique": self.mitre_technique,
                "created_at": self.created_at, "times_used": self.times_used}


class AIRun(db.Model):
    __tablename__ = "ai_runs"
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    agent_name = db.Column(db.String(32), nullable=False)     # enrichment | triage | investigation | knowledge
    mode = db.Column(db.String(16))                           # llm | local
    model = db.Column(db.String(64))
    trigger = db.Column(db.String(16))                        # auto | manual
    started_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    finished_at = db.Column(db.DateTime)
    duration_ms = db.Column(db.Integer)
    input_tokens = db.Column(db.Integer, default=0)
    output_tokens = db.Column(db.Integer, default=0)
    tool_calls = db.Column(db.Text)                           # JSON [{tool, input, output_preview}]
    output = db.Column(db.Text)                               # JSON kết quả
    status = db.Column(db.String(16), default="ok")           # ok | error
    error = db.Column(db.Text)

    alert = db.relationship("Alert", backref=db.backref("ai_runs", lazy="dynamic",
                                                        order_by="AIRun.started_at.desc()"))

    @property
    def tool_calls_list(self):
        return loads(self.tool_calls, [])

    @property
    def output_dict(self):
        return loads(self.output, {})


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    username = db.Column(db.String(64))
    action = db.Column(db.String(64), nullable=False, index=True)
    target = db.Column(db.String(128))
    detail = db.Column(db.Text)
    ip = db.Column(db.String(64))
    success = db.Column(db.Boolean, default=True)


class IpReputation(db.Model):
    __tablename__ = "ip_reputation"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), unique=True, nullable=False, index=True)
    verdict = db.Column(db.String(16), nullable=False)        # malicious | suspicious | clean
    source = db.Column(db.String(64))                         # blocklist | analyst | ai
    note = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utcnow)
    created_by = db.Column(db.String(64))

    def to_dict(self):
        return {"ip": self.ip, "verdict": self.verdict, "source": self.source, "note": self.note}


class AlertReview(db.Model):
    """Separate analyst decisions from AI suggestions without altering legacy tables."""
    __tablename__ = "alert_reviews"
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    revision = db.Column(db.Integer, nullable=False, default=1)
    reviewed_by = db.Column(db.String(64), nullable=False)
    reviewed_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    decision = db.Column(db.Text, nullable=False)


class KnowledgeReview(db.Model):
    __tablename__ = "knowledge_reviews"
    article_id = db.Column(db.Integer, db.ForeignKey("knowledge_articles.id", ondelete="CASCADE"), primary_key=True)
    status = db.Column(db.String(16), nullable=False, default="draft")
    revision = db.Column(db.Integer, nullable=False, default=1)
    reviewed_by = db.Column(db.String(64))
    reviewed_at = db.Column(db.DateTime)
    article = db.relationship("KnowledgeArticle", back_populates="review")


class WorkJob(db.Model):
    """Durable ingest/detection and background AI work, with recoverable leases."""
    __tablename__ = "work_jobs"
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(24), nullable=False, index=True)
    object_id = db.Column(db.Integer, index=True)
    payload = db.Column(db.Text, nullable=False, default="{}")
    status = db.Column(db.String(16), nullable=False, default="queued", index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    available_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    lease_until = db.Column(db.DateTime)
    lease_token = db.Column(db.String(36))
    error = db.Column(db.Text)
    result = db.Column(db.Text)
