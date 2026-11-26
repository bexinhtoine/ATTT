# -*- coding: utf-8 -*-
"""
orchestrator.py - Điều phối chuỗi tác tử cho một cảnh báo.

    enrich -> triage -> investigate -> knowledge

* run()       : chạy đồng bộ các giai đoạn được yêu cầu, ghi bảng ai_runs, cập nhật cảnh báo.
* run_async() : lưu tác vụ bền vững, worker nền thực thi và phục hồi qua restart.
Kết quả từng giai đoạn được lưu vào alert.ai_data (JSON) và các bảng investigations / knowledge_articles.
"""
import threading
import math
import time
import traceback

from ..extensions import db
from ..models import Alert, AlertReview, AIRun, Investigation, KnowledgeArticle, dumps, utcnow
from .llm import LLMClient
from .tools import ToolExecutor
from .agents import EnrichmentAgent, TriageAgent, InvestigationAgent, KnowledgeAgent

STAGES = ("enrich", "triage", "investigate", "knowledge")
AGENT_BY_STAGE = {"enrich": EnrichmentAgent, "triage": TriageAgent,
                  "investigate": InvestigationAgent, "knowledge": KnowledgeAgent}


class SOCOrchestrator:
    def __init__(self, app):
        self.app = app
        self._locks = [threading.RLock() for _ in range(64)]

    # ------------------------------------------------------------------ public
    def run_async(self, alert_id, stages=("enrich", "triage"), trigger="auto", username=None):
        from ..work import enqueue
        job = enqueue("ai", {"stages": list(stages), "trigger": trigger, "username": username}, alert_id)
        db.session.commit()
        return job

    def run(self, alert_id, stages=("enrich", "triage"), trigger="manual", username=None):
        with self._locks[alert_id % len(self._locks)]:
            return self._run(alert_id, stages, trigger, username)

    def _run(self, alert_id, stages, trigger, username):
        """Phải được gọi trong app context. Trả về dict {stage: kết quả}."""
        alert = db.session.get(Alert, alert_id)
        if alert is None:
            return {"error": "Không tìm thấy cảnh báo"}
        llm = LLMClient.from_app(self.app)
        executor = ToolExecutor(alert)
        ai_data = alert.ai or {}
        context = {"enrichment": None, "triage": ai_data.get("triage"),
                   "investigation": ai_data.get("investigation")}
        results = {}
        for stage in stages:
            if stage not in AGENT_BY_STAGE:
                continue
            if stage != "enrich" and not context.get("enrichment"):
                context["enrichment"] = self._execute(alert, "enrich", llm, executor, context, trigger, username, ai_data)
                if context["enrichment"].get("error") or context["enrichment"].get("analysis", {}).get("stale"):
                    results["enrich"] = context["enrichment"]
                    break
            results[stage] = self._execute(alert, stage, llm, executor, context, trigger, username, ai_data)
            if results[stage].get("error") or results[stage].get("analysis", {}).get("stale"):
                break
        return results

    # ----------------------------------------------------------------- internal
    def _execute(self, alert, stage, llm, executor, context, trigger, username, ai_data):
        agent_cls = AGENT_BY_STAGE[stage]
        run = AIRun(alert_id=alert.id, agent_name=agent_cls.name, trigger=trigger,
                    model=llm.model if llm.available else None, mode="local", status="running")
        db.session.add(run)
        db.session.flush()
        run_id = run.id
        baseline = alert.updated_at
        input_state = {"status": alert.status, "severity": alert.severity,
                       "event_count": alert.event_count, "last_event_time": alert.last_event_time,
                       "rule_conditions": alert.rule.conditions if alert.rule else None}
        db.session.commit()  # Never hold a write transaction while waiting for the LLM.
        t0 = time.time()
        try:
            agent = agent_cls(llm, executor, alert, context)
            result = agent.run()
            self._validate_result(stage, result)
            refs = result.get("evidence_refs", [])
            if any(type(ref) is not int or ref not in executor.examined_event_ids for ref in refs):
                raise ValueError("AI tham chiếu sự kiện chưa được truy xuất")
            # Discard stale ORM snapshots before applying an external computation.
            db.session.rollback()
            run = db.session.get(AIRun, run_id)
            alert = db.session.get(Alert, alert.id, populate_existing=True)
            run.mode = result.get("_mode", "local")
            run.model = llm.model if run.mode == "llm" else None
            usage = result.get("_usage") or {}
            run.input_tokens = usage.get("input_tokens", 0)
            run.output_tokens = usage.get("output_tokens", 0)
            run.tool_calls = dumps(result.get("_tool_calls") or [])
            clean = {k: v for k, v in result.items() if not k.startswith("_")}
            if result.get("_fallback_reason"):
                clean["fallback_reason"] = result["_fallback_reason"]
            clean["analysis"] = {"run_id": run_id, "cutoff": executor.cutoff.isoformat() + "Z",
                                 "pipeline_version": "soc-evidence-v1",
                                 "mutable_inventory_and_reputation": "live",
                                 "input_updated_at": str(baseline), "input_state": input_state,
                                 "examined_event_ids": sorted(executor.examined_event_ids),
                                 "confidence_calibrated": False, "stale": alert.updated_at != baseline}
            run.output = dumps(clean)
            run.status = "ok"
            if not clean["analysis"]["stale"]:
                if not self._apply(alert, stage, clean, run.mode, context, ai_data, username, baseline):
                    clean["analysis"]["stale"] = True
            run.output = dumps(clean)
        except Exception as exc:
            db.session.rollback()
            run = db.session.get(AIRun, run_id)
            run.status, run.error = "error", "%s: %s" % (type(exc).__name__, exc)
            self.app.logger.error("Tác tử %s lỗi: %s", stage, traceback.format_exc())
            clean = {"error": run.error}
        run.finished_at = utcnow()
        run.duration_ms = int((time.time() - t0) * 1000)
        db.session.commit()
        return clean

    @staticmethod
    def _validate_result(stage, result):
        if not isinstance(result, dict):
            raise ValueError("Kết quả AI phải là object")
        if not isinstance(result.get("evidence_refs", []), list):
            raise ValueError("evidence_refs phải là danh sách")
        if stage == "triage":
            if result.get("verdict") not in ("true_positive", "likely_true_positive", "suspicious",
                                              "likely_false_positive", "false_positive"):
                raise ValueError("verdict không hợp lệ")
            if type(result.get("priority")) is not int or not 1 <= result["priority"] <= 5:
                raise ValueError("priority không hợp lệ")
            confidence = result.get("confidence")
            if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
                raise ValueError("confidence không hợp lệ")
        if stage == "investigate":
            if not isinstance(result.get("timeline"), list) or not isinstance(result.get("iocs"), dict):
                raise ValueError("Kết quả điều tra không đúng cấu trúc")

    def _apply(self, alert, stage, result, mode, context, ai_data, username, baseline):
        """Ghi kết quả của một giai đoạn vào cảnh báo / các bảng liên quan."""
        now = utcnow()
        # Claim this revision before touching either workflow state or derived rows.
        changed = Alert.query.filter(Alert.id == alert.id, Alert.updated_at == baseline).update(
            {"updated_at": now}, synchronize_session=False)
        if not changed:
            return False
        db.session.refresh(alert)
        review = db.session.get(AlertReview, alert.id)
        if stage == "enrich":
            ai_data["enrichment"] = result
            context["enrichment"] = result
        elif stage == "triage":
            ai_data["triage"] = result
            context["triage"] = result
            alert.ai_verdict = result.get("verdict")
            alert.ai_confidence = result.get("confidence")
            alert.ai_priority = result.get("priority")
            if review is None and alert.status not in ("resolved", "false_positive"):
                alert.priority = result.get("priority")
            alert.ai_summary = result.get("summary")
            alert.ai_mode = mode
            alert.ai_updated_at = now
            if review is None and alert.status == "new":
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
            if review is None and alert.status in ("new", "triaged"):
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
            from ..reviews import edit_knowledge_review
            edit_knowledge_review(art, username or "ai:knowledge", approve=False)
            ai_data["knowledge_article_id"] = art.id
        ai_data["last_stage"] = stage
        ai_data["last_mode"] = mode
        ai_data["updated_at"] = now
        alert.ai_data = dumps(ai_data)
        alert.updated_at = now
        db.session.flush()
        return True
