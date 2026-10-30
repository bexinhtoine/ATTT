# -*- coding: utf-8 -*-
"""
detection.py - Bộ máy luật phát hiện (Rule Engine) của Web SOC.

Ba loại luật được hỗ trợ:
  * match     : MỘT sự kiện khớp điều kiện -> sinh cảnh báo
                (vd: EventID 1102 - nhật ký kiểm toán bị xóa).
  * threshold : đếm số sự kiện khớp điều kiện trong CỬA SỔ TRƯỢT window_seconds, gom nhóm theo
                group_by (src_ip / user_name / host). Đạt threshold_count -> cảnh báo.
                Nếu đặt distinct_field thì đếm số GIÁ TRỊ KHÁC NHAU của trường đó
                (vd: số tài khoản bị thử từ cùng một IP -> password spraying).
  * sequence  : sự kiện B (trigger) xảy ra sau ít nhất min_count sự kiện A (precondition)
                cùng nhóm trong cửa sổ (vd: đăng nhập THÀNH CÔNG sau nhiều lần THẤT BẠI).

Điều kiện (JSON). Mọi khóa có mặt phải thỏa (AND); giá trị là chuỗi hoặc danh sách (OR):
  {"source": "linux.auth", "event_id": ["4625"], "action": "logon_failed",
   "category": "authentication", "outcome": "failure", "severity_min": "high",
   "regex": "Failed password", "field": "message", "not_regex": "...",
   "extra": {"LogonType": ["10", "3"]}, "user_in": ["root", "administrator"],
   "src_ip_public": true}
Luật sequence: {"precondition": {...}, "trigger": {...}, "min_count": 3}

Thuật toán tổng quát khi nhận một lô sự kiện mới E (đã lưu vào CSDL, sắp theo thời gian):
  for rule in các luật đang bật:
      for ev in E:
          match     : nếu khớp -> raise(rule, ev, [ev])
          threshold : nếu khớp -> lấy các sự kiện cùng nhóm trong [t_ev - W, t_ev] khớp điều kiện
                      -> nếu count (hoặc distinct) >= N -> raise(rule, ev, các sự kiện đó)
          sequence  : nếu ev khớp trigger -> đếm precondition cùng nhóm trong cửa sổ
                      -> nếu >= min_count -> raise(rule, ev, precondition + [ev])
  raise(): gộp (dedup) vào cảnh báo đang mở cùng khóa rule|host|nhóm nếu còn "nóng",
           ngược lại tạo cảnh báo mới; liên kết các sự kiện bằng chứng vào cảnh báo.
"""
import re
from datetime import timedelta

from flask import current_app

from .extensions import db
from .models import (DetectionRule, Alert, AlertEvent, LogEvent, SEVERITY_ORDER, OPEN_STATUSES,
                     utcnow)

FIELD_MAP = {"user": "user_name", "process": "process_name", "ip": "src_ip"}
SQL_SIMPLE_KEYS = {"source": LogEvent.source, "event_id": LogEvent.event_id, "action": LogEvent.action,
                   "category": LogEvent.category, "outcome": LogEvent.outcome, "host": LogEvent.host}
_regex_cache = {}


def _as_list(v):
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def _rx(pattern):
    rx = _regex_cache.get(pattern)
    if rx is None:
        rx = _regex_cache[pattern] = re.compile(pattern, re.IGNORECASE)
    return rx


def event_field(ev, name):
    """Đọc một trường của sự kiện theo tên; hỗ trợ 'extra.<key>'."""
    name = FIELD_MAP.get(name, name)
    if name.startswith("extra."):
        return (ev.extra_dict or {}).get(name[6:])
    return getattr(ev, name, None)


def match_conditions(cond, ev):
    """Kiểm tra một sự kiện có thỏa toàn bộ điều kiện của luật hay không."""
    if not cond:
        return False
    for key in ("source", "event_id", "action", "category", "outcome", "host", "process"):
        if key in cond and cond[key] not in (None, "", []):
            val = event_field(ev, key)
            allowed = [str(x).lower() for x in _as_list(cond[key])]
            if str(val).lower() not in allowed:
                return False
    if cond.get("severity_min"):
        if SEVERITY_ORDER.get(ev.severity, 0) < SEVERITY_ORDER.get(cond["severity_min"], 0):
            return False
    if cond.get("user_in"):
        if (ev.user_name or "").lower() not in [str(u).lower() for u in _as_list(cond["user_in"])]:
            return False
    field = cond.get("field", "message")
    if cond.get("regex"):
        if not _rx(cond["regex"]).search(str(event_field(ev, field) or "")):
            return False
    if cond.get("not_regex"):
        if _rx(cond["not_regex"]).search(str(event_field(ev, field) or "")):
            return False
    if cond.get("extra"):
        ex = ev.extra_dict or {}
        for k, v in cond["extra"].items():
            if str(ex.get(k, "")).lower() not in [str(x).lower() for x in _as_list(v)]:
                return False
    if cond.get("src_ip_public") is True:
        from .enrichment import classify_ip
        if not classify_ip(ev.src_ip).get("is_public"):
            return False
    return True


class _SafeCtx(dict):
    def __missing__(self, key):
        return "?"


def render_template_text(template, rule, ev, count):
    """Điền {host} {src_ip} {user} {count} {event_id} {action} {extra.X} ... vào tiêu đề."""
    if not template:
        template = "%s trên {host}" % rule.name
    ctx = _SafeCtx(host=ev.host or "?", src_ip=ev.src_ip or "?", user=ev.user_name or "?",
                   count=count, rule=rule.name, event_id=ev.event_id or "?", action=ev.action or "?",
                   message=(ev.message or "")[:80], source=ev.source or "?")
    for k, v in (ev.extra_dict or {}).items():
        ctx["extra." + k] = v if v not in (None, "") else "?"
    return re.sub(r"\{([\w\.]+)\}", lambda m: str(ctx[m.group(1)]), template)[:255]


class RuleEngine:
    MATCH_DEDUP_SECONDS = 600       # gộp các cảnh báo match cùng khóa trong 10 phút

    def __init__(self, rules=None):
        self.rules = rules if rules is not None else (
            DetectionRule.query.filter_by(enabled=True).order_by(DetectionRule.id).all())

    # ------------------------------------------------------------------ public
    def evaluate(self, events):
        """events: danh sách LogEvent ĐÃ được commit. Trả về list (alert, is_new)."""
        results = {}
        events = sorted(events, key=lambda e: (e.event_time, e.id))
        for rule in self.rules:
            cond = rule.conditions_dict
            for ev in events:
                try:
                    if rule.rule_type == "match":
                        if match_conditions(cond, ev):
                            self._raise(rule, ev, [ev], 1, results)
                    elif rule.rule_type == "threshold":
                        if match_conditions(cond, ev):
                            self._eval_threshold(rule, cond, ev, results)
                    elif rule.rule_type == "sequence":
                        if match_conditions(cond.get("trigger", {}), ev):
                            self._eval_sequence(rule, cond, ev, results)
                except Exception:            # một luật lỗi không được làm hỏng cả lô
                    current_app.logger.exception("Lỗi khi đánh giá luật %s", rule.code)
                    db.session.rollback()
        db.session.commit()
        return list(results.values())

    def evaluate_range(self, start, end, batch=500):
        """Chạy lại toàn bộ luật trên dữ liệu lịch sử trong [start, end] (dùng khi sửa luật)."""
        q = LogEvent.query.filter(LogEvent.event_time >= start, LogEvent.event_time <= end)
        total = []
        offset = 0
        while True:
            chunk = q.order_by(LogEvent.event_time, LogEvent.id).offset(offset).limit(batch).all()
            if not chunk:
                break
            total.extend(self.evaluate(chunk))
            offset += batch
        return total

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _group(rule, ev):
        """Trường gom nhóm; nếu sự kiện không có giá trị (vd: đăng nhập cục bộ không có IP)
        thì lùi dần: group_by -> user_name -> host."""
        for field in (rule.group_by or "src_ip", "user_name", "host"):
            val = event_field(ev, field)
            if val not in (None, "", "-"):
                return field, val
        return "host", ev.host

    @staticmethod
    def _candidates(cond, group_field, group_value, start, end):
        q = LogEvent.query.filter(LogEvent.event_time >= start, LogEvent.event_time <= end)
        col = getattr(LogEvent, FIELD_MAP.get(group_field, group_field), None)
        if col is not None:
            q = q.filter(col == group_value)
        for key, column in SQL_SIMPLE_KEYS.items():          # đẩy các điều kiện đơn giản xuống SQL
            if key in cond and cond[key] not in (None, "", []):
                q = q.filter(column.in_([str(x) for x in _as_list(cond[key])]))
        cands = q.order_by(LogEvent.event_time, LogEvent.id).limit(5000).all()
        return [c for c in cands if match_conditions(cond, c)]   # phần còn lại (regex, extra) lọc bằng Python

    def _eval_threshold(self, rule, cond, ev, results):
        gfield, gval = self._group(rule, ev)
        start = ev.event_time - timedelta(seconds=rule.window_seconds or 300)
        cands = self._candidates(cond, gfield, gval, start, ev.event_time)
        if rule.distinct_field:
            values = {event_field(c, rule.distinct_field) for c in cands}
            values.discard(None)
            count = len(values)
        else:
            count = len(cands)
        if count >= (rule.threshold_count or 1):
            self._raise(rule, ev, cands, count, results)

    def _eval_sequence(self, rule, cond, ev, results):
        pre = cond.get("precondition", {})
        min_count = int(cond.get("min_count", 3))
        gfield, gval = self._group(rule, ev)
        start = ev.event_time - timedelta(seconds=rule.window_seconds or 600)
        cands = self._candidates(pre, gfield, gval, start, ev.event_time)
        cands = [c for c in cands if c.id != ev.id]
        if len(cands) >= min_count:
            self._raise(rule, ev, cands + [ev], len(cands), results)

    def _raise(self, rule, ev, evidence, count, results):
        """Tạo mới hoặc gộp vào cảnh báo đang mở (dedup)."""
        gfield, gval = self._group(rule, ev)
        dedup_key = "%s|%s|%s" % (rule.id, ev.host, gval)
        hot_window = max(rule.window_seconds or 0, self.MATCH_DEDUP_SECONDS) * 2
        existing = (Alert.query
                    .filter(Alert.dedup_key == dedup_key, Alert.status.in_(OPEN_STATUSES),
                            Alert.last_event_time >= ev.event_time - timedelta(seconds=hot_window))
                    .order_by(Alert.id.desc()).first())
        if existing:
            alert, is_new = existing, False
            if rule.rule_type == "match":
                alert.event_count = (alert.event_count or 0) + 1
            else:
                alert.event_count = max(alert.event_count or 0, count)
            if ev.event_time and (alert.last_event_time is None or ev.event_time > alert.last_event_time):
                alert.last_event_time = ev.event_time
            alert.updated_at = utcnow()
            if SEVERITY_ORDER.get(rule.severity, 0) > SEVERITY_ORDER.get(alert.severity, 0):
                alert.severity = rule.severity
        else:
            alert = Alert(
                rule_id=rule.id, agent_id=ev.agent_id, host=ev.host, src_ip=ev.src_ip,
                user_name=ev.user_name, severity=rule.severity, status="new",
                title=render_template_text(rule.title_template, rule, ev, count),
                description=self._describe(rule, ev, count),
                event_count=count if rule.rule_type != "match" else 1,
                first_event_time=min((e.event_time for e in evidence if e.event_time), default=ev.event_time),
                last_event_time=ev.event_time, mitre_tactic=rule.mitre_tactic,
                mitre_technique=rule.mitre_technique, dedup_key=dedup_key)
            db.session.add(alert)
            db.session.flush()
            rule.hits = (rule.hits or 0) + 1
            is_new = True
        # liên kết bằng chứng (bỏ qua những sự kiện đã liên kết)
        linked = {r.event_id for r in AlertEvent.query.filter_by(alert_id=alert.id).all()}
        for e in evidence:
            if e.id not in linked:
                db.session.add(AlertEvent(alert_id=alert.id, event_id=e.id))
                linked.add(e.id)
        db.session.flush()
        if alert.id not in results:
            results[alert.id] = (alert, is_new)
        return alert

    @staticmethod
    def _describe(rule, ev, count):
        parts = ["Luật %s - %s." % (rule.code or rule.id, rule.name)]
        if rule.description:
            parts.append(rule.description)
        if rule.rule_type == "threshold":
            parts.append("Ghi nhận %d sự kiện khớp trong cửa sổ %d giây (ngưỡng %d), gom nhóm theo %s."
                         % (count, rule.window_seconds or 0, rule.threshold_count or 0, rule.group_by))
        elif rule.rule_type == "sequence":
            parts.append("Sự kiện kích hoạt xảy ra sau %d sự kiện tiền đề trong %d giây."
                         % (count, rule.window_seconds or 0))
        parts.append("Sự kiện kích hoạt: [%s] %s" % (ev.event_id or ev.action, (ev.message or "")[:300]))
        return " ".join(parts)
