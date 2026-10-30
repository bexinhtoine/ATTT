# -*- coding: utf-8 -*-
"""
orchestrator.py - Điều phối chuỗi tác tử cho một cảnh báo.

    enrich -> triage -> investigate -> knowledge

* run()       : chạy đồng bộ các giai đoạn được yêu cầu, ghi bảng ai_runs, cập nhật cảnh báo.
* run_async() : chạy trong luồng nền (dùng khi tự động phân loại ngay lúc cảnh báo được tạo).
Kết quả từng giai đoạn được lưu vào alert.ai_data (JSON) và các bảng investigations / knowledge_articles.
"""
import threading
import time
import traceback

from ..extensions import db
from ..models import Alert, AIRun, Investigation, KnowledgeArticle, dumps, loads, utcnow
from .llm import LLMClient
from .tools import ToolExecutor
from .agents import EnrichmentAgent, TriageAgent, InvestigationAgent, KnowledgeAgent

STAGES = ("enrich", "triage", "investigate", "knowledge")
AGENT_BY_STAGE = {"enrich": EnrichmentAgent, "triage": TriageAgent,
                  "investigate": InvestigationAgent, "knowledge": KnowledgeAgent}


class SOCOrchestrator:
    def __init__(self, app):
        self.app = app

    # ------------------------------------------------------------------ public
    def run_async(self, alert_id, stages=("enrich", "triage"), trigger="auto", username=None):
        t = threading.Thread(target=self._run_in_context, args=(alert_id, tuple(stages), trigger, username),
                             daemon=True, name="soc-ai-%s" % alert_id)
        t.start()
        return t

    def run(self, alert_id, stages=("enrich", "triage"), trigger="manual", username=None):
        """Phải được gọi trong app context. Trả về dict {stage: kết quả}."""
        alert = db.session.get(Alert, alert_id)
        if alert is None:
            return {"error": "Không tìm thấy cảnh báo"}
        llm = LLMClient.from_app(self.app)
        executor = ToolExecutor(alert)
        ai_data = alert.ai or {}
        context = {"enrichment": ai_data.get("enrichment"), "triage": ai_data.get("triage"),
                   "investigation": ai_data.get("investigation")}
        results = {}
        for stage in stages:
            if stage not in AGENT_BY_STAGE:
                continue
            if stage != "enrich" and not context.get("enrichment"):
                context["enrichment"] = self._execute(alert, "enrich", llm, executor, context, trigger, username, ai_data)
            results[stage] = self._execute(alert, stage, llm, executor, context, trigger, username, ai_data)
        return results

    # ----------------------------------------------------------------- internal
    def _run_in_context(self, alert_id, stages, trigger, username):
        with self.app.app_context():
            try:
                self.run(alert_id, stages, trigger, username)
            except Exception:
                self.app.logger.error("Lỗi luồng AI cho cảnh báo %s:\n%s", alert_id, traceback.format_exc())
                db.session.rollback()
            finally:
                db.session.remove()

    def _execute(self, alert, stage, llm, executor, context, trigger, username, ai_data):
        agent_cls = AGENT_BY_STAGE[stage]
        run = AIRun(alert_id=alert.id, agent_name=agent_cls.name, trigger=trigger,
                    model=llm.model if llm.available else None, mode="local")
        db.session.add(run)
        db.session.flush()
        t0 = time.time()
        try:
            agent = agent_cls(llm, executor, alert, context)
            result = agent.run()
            run.mode = result.get("_mode", "local")
            run.model = llm.model if run.mode == "llm" else None
            usage = result.get("_usage") or {}
            run.input_tokens = usage.get("input_tokens", 0)
            run.output_tokens = usage.get("output_tokens", 0)
            run.tool_calls = dumps(result.get("_tool_calls") or [])
            clean = {k: v for k, v in result.items() if not k.startswith("_")}
            if result.get("_fallback_reason"):
                clean["fallback_reason"] = result["_fallback_reason"]
            run.output = dumps(clean)
            run.status = "ok"
            self._apply(alert, stage, clean, run.mode, context, ai_data, username)
        except Exception as exc:
            db.session.rollback()
            run = db.session.merge(run)
            run.status, run.error = "error", "%s: %s" % (type(exc).__name__, exc)
            self.app.logger.error("Tác tử %s lỗi: %s", stage, traceback.format_exc())
            clean = {"error": run.error}
        run.finished_at = utcnow()
        run.duration_ms = int((time.time() - t0) * 1000)
        db.session.commit()
        return clean

    def _apply(self, alert, stage, result, mode, context, ai_data, username):
        """Ghi kết quả của một giai đoạn vào cảnh báo / các bảng liên quan."""
        now = utcnow()
        if stage == "enrich":
            ai_data["enrichment"] = result
            context["enrichment"] = result
        elif stage == "triage":
            ai_data["triage"] = result
            context["triage"] = result
            alert.ai_verdict = result.get("verdict")
            alert.ai_confidence = result.get("confidence")
            alert.ai_priority = result.get("priority")
            alert.priority = result.get("priority")
            alert.ai_summary = result.get("summary")
            alert.ai_mode = mode
            alert.ai_updated_at = now
            if alert.status == "new":
                alert.status = "triaged"
        elif stage == "investigate":
            ai_data["investigation"] = result
            context["investigation"] = result
            inv = Investigation(alert_id=alert.id, created_by="ai:investigation", mode=mode,
                                hypothesis=result.get("hypothesis"), summary=result.get("summary"),
                                timeline=dumps(result.get("timeline") or []),
                                attack_chain=dumps(result.get("attack_chain") or []),
                                iocs=dumps(result.get("iocs") or {}), impact=result.get("impact"),
                                root_cause=result.get("root_cause"),
                                recommendations=dumps(result.get("recommendations") or []), raw=dumps(result))
            db.session.add(inv)
            db.session.flush()
            ai_data["investigation_id"] = inv.id
            if alert.status in ("new", "triaged"):
                alert.status = "investigating"
        elif stage == "knowledge":
            art = KnowledgeArticle(title=(result.get("title") or "Bài học từ cảnh báo #%d" % alert.id)[:255],
                                   summary=result.get("summary"), content=result.get("content"),
                                   category=result.get("category") or "lesson",
                                   tags=",".join(result.get("tags") or []), source="ai",
                                   related_alert_id=alert.id, related_rule_id=alert.rule_id,
                                   mitre_technique=alert.mitre_technique,
                                   created_by=username or "ai:knowledge")
            db.session.add(art)
            db.session.flush()
            ai_data["knowledge_article_id"] = art.id
        ai_data["last_stage"] = stage
        ai_data["last_mode"] = mode
        ai_data["updated_at"] = now
        alert.ai_data = dumps(ai_data)
        alert.updated_at = now
        db.session.commit()
