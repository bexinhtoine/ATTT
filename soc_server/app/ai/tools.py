# -*- coding: utf-8 -*-
"""
tools.py - Bộ công cụ (tools) mà các tác tử AI được phép sử dụng.

Cùng một bộ hàm phục vụ hai đường chạy:
  * Đường LLM : mô tả bằng JSON schema (TOOL_DEFINITIONS) để mô hình tự quyết định gọi công cụ nào.
  * Đường LOCAL: các tác tử heuristic gọi trực tiếp ToolExecutor.<hàm>().
Mọi công cụ chỉ ĐỌC dữ liệu trong CSDL của SOC (không thực thi lệnh trên máy trạm).
"""
from datetime import timedelta

from sqlalchemy import or_

from ..extensions import db
from ..models import LogEvent, Alert, Agent, KnowledgeArticle, utcnow
from .. import enrichment

TOOL_DEFINITIONS = [
    {
        "name": "query_events",
        "description": ("Truy vấn các sự kiện log đã lưu trong SOC quanh thời điểm cảnh báo. "
                        "Các bộ lọc là chuỗi; để chuỗi rỗng nếu không lọc theo trường đó. "
                        "Trả về danh sách sự kiện rút gọn sắp xếp theo thời gian."),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Tên máy trạm (rỗng = mọi máy)"},
                "src_ip": {"type": "string", "description": "IP nguồn (rỗng = mọi IP)"},
                "user": {"type": "string", "description": "Tên tài khoản (rỗng = mọi tài khoản)"},
                "source": {"type": "string", "description": "Nguồn log, vd linux.auth, windows.security (rỗng = tất cả)"},
                "keyword": {"type": "string", "description": "Từ khóa tìm trong thông điệp (rỗng = không lọc)"},
                "minutes_before": {"type": "integer", "description": "Số phút trước thời điểm cảnh báo (vd 30)"},
                "minutes_after": {"type": "integer", "description": "Số phút sau thời điểm cảnh báo (vd 10)"},
                "limit": {"type": "integer", "description": "Số sự kiện tối đa (<= 100)"},
            },
            "required": ["host", "src_ip", "user", "source", "keyword", "minutes_before", "minutes_after", "limit"],
            "additionalProperties": False,
        },
    },
    {
        "name": "lookup_ip",
        "description": "Tra cứu một địa chỉ IP: phân loại (nội bộ/công cộng), uy tín trong blocklist cục bộ, lịch sử 7 ngày.",
        "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}},
                         "required": ["ip"], "additionalProperties": False},
    },
    {
        "name": "get_host_info",
        "description": "Thông tin máy trạm: hệ điều hành, trạng thái agent, số sự kiện 24h, số cảnh báo đang mở.",
        "input_schema": {"type": "object", "properties": {"host": {"type": "string"}},
                         "required": ["host"], "additionalProperties": False},
    },
    {
        "name": "get_related_alerts",
        "description": "Các cảnh báo khác liên quan (cùng IP, cùng tài khoản hoặc cùng máy) trong N ngày gần đây.",
        "input_schema": {"type": "object",
                         "properties": {"host": {"type": "string"}, "src_ip": {"type": "string"},
                                        "user": {"type": "string"}, "days": {"type": "integer"}},
                         "required": ["host", "src_ip", "user", "days"], "additionalProperties": False},
    },
    {
        "name": "search_knowledge",
        "description": "Tìm trong cơ sở tri thức SOC (playbook, bài học, chỉ dấu) theo từ khóa.",
        "input_schema": {"type": "object",
                         "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
                         "required": ["query", "limit"], "additionalProperties": False},
    },
    {
        "name": "mitre_lookup",
        "description": "Tra cứu tên tactic/kỹ thuật MITRE ATT&CK theo mã, vd T1110.001.",
        "input_schema": {"type": "object", "properties": {"technique_id": {"type": "string"}},
                         "required": ["technique_id"], "additionalProperties": False},
    },
]


def _dt(d):
    return d.strftime("%Y-%m-%d %H:%M:%S") if d else None


class ToolExecutor:
    """Thực thi công cụ trong ngữ cảnh một cảnh báo (để biết tâm cửa sổ thời gian)."""

    def __init__(self, alert):
        self.alert = alert
        self.center = alert.last_event_time or alert.created_at or utcnow()

    def __call__(self, name, args):
        fn = getattr(self, name, None)
        if fn is None or name.startswith("_"):
            raise ValueError("Không có công cụ tên '%s'" % name)
        return fn(**(args or {}))

    # ---------------------------------------------------------------- tools
    def query_events(self, host="", src_ip="", user="", source="", keyword="",
                     minutes_before=30, minutes_after=10, limit=50):
        start = self.center - timedelta(minutes=int(minutes_before or 30))
        end = self.center + timedelta(minutes=int(minutes_after or 10))
        q = LogEvent.query.filter(LogEvent.event_time >= start, LogEvent.event_time <= end)
        if host:
            q = q.filter(LogEvent.host == host)
        if src_ip:
            q = q.filter(LogEvent.src_ip == src_ip)
        if user:
            q = q.filter(LogEvent.user_name == user)
        if source:
            q = q.filter(LogEvent.source == source)
        if keyword:
            q = q.filter(LogEvent.message.ilike("%%%s%%" % keyword))
        limit = max(1, min(int(limit or 50), 100))
        rows = q.order_by(LogEvent.event_time.desc()).limit(limit).all()
        rows.reverse()
        return {"count": len(rows), "window": [_dt(start), _dt(end)], "events": [e.compact() for e in rows]}

    def lookup_ip(self, ip=""):
        if not ip:
            return {"error": "Thiếu địa chỉ IP"}
        return {**enrichment.classify_ip(ip), "reputation": enrichment.ip_reputation(ip),
                "history": enrichment.ip_history(ip)}

    def get_host_info(self, host=""):
        host = host or self.alert.host
        agent = Agent.query.filter_by(hostname=host).first()
        return enrichment.host_context(agent, host)

    def get_related_alerts(self, host="", src_ip="", user="", days=7):
        since = utcnow() - timedelta(days=int(days or 7))
        q = Alert.query.filter(Alert.id != self.alert.id, Alert.created_at >= since)
        conds = []
        if host:
            conds.append(Alert.host == host)
        if src_ip:
            conds.append(Alert.src_ip == src_ip)
        if user:
            conds.append(Alert.user_name == user)
        if conds:
            q = q.filter(or_(*conds))
        rows = q.order_by(Alert.created_at.desc()).limit(20).all()
        return [{"id": a.id, "title": a.title, "severity": a.severity, "status": a.status,
                 "created_at": _dt(a.created_at), "host": a.host, "src_ip": a.src_ip, "user": a.user_name,
                 "technique": a.mitre_technique, "ai_verdict": a.ai_verdict} for a in rows]

    def search_knowledge(self, query="", limit=5):
        words = [w for w in (query or "").replace(",", " ").split() if len(w) >= 3][:8]
        if not words:
            return []
        conds = []
        for w in words:
            like = "%%%s%%" % w
            conds.append(or_(KnowledgeArticle.title.ilike(like), KnowledgeArticle.tags.ilike(like),
                             KnowledgeArticle.summary.ilike(like), KnowledgeArticle.mitre_technique.ilike(like)))
        rows = KnowledgeArticle.query.filter(or_(*conds)).order_by(
            KnowledgeArticle.times_used.desc(), KnowledgeArticle.updated_at.desc()).limit(max(1, min(int(limit or 5), 10))).all()
        for r in rows:
            r.times_used = (r.times_used or 0) + 1
        db.session.commit()
        return [{"id": r.id, "title": r.title, "category": r.category, "tags": r.tag_list,
                 "summary": r.summary, "content": (r.content or "")[:1500]} for r in rows]

    def mitre_lookup(self, technique_id=""):
        return enrichment.mitre_info(technique_id) or {"error": "Không tìm thấy kỹ thuật"}
