"""Regression tests for durable delivery, work recovery and analyst/AI boundaries.

Run: python tools/test_reliability.py. Uses temporary data and no external LLM.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from collections import deque
from datetime import timedelta
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "soc_agent"))
import agent as agent_module
import collectors as collectors_module
from collectors import FileCollector
sys.path.insert(0, str(ROOT / "soc_server"))
from app import create_app
from config import Config
from app.extensions import db
from app.models import (Agent, Alert, AlertEvent, AlertReview, AIRun, DetectionRule,
                        KnowledgeArticle, KnowledgeReview, LogEvent, WorkJob, dumps, utcnow)
from app.ai.agents import TriageAgent, InvestigationAgent
from app.ai.tools import ToolExecutor
from app.ai.validation import validate_json
from app.ai.llm import LLMClient, LLMUnavailable
from app.detection import RuleEngine, validate_conditions
from app.ingest import ingest
from app.reviews import record_alert_review, edit_knowledge_review
from app.work import enqueue, process_job
from app.safe_html import sanitize_html

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def event(uid="test", action="logon_failed", at=None, user="alice", host="test-host"):
    return {"event_uid": uid, "timestamp": (at or utcnow()).isoformat() + "Z",
            "source": "linux.auth", "action": action, "message": action, "host": host,
            "user": user, "src_ip": "203.0.113.5", "severity": "medium"}


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="soc_agent_regression_")
        self.logfile = Path(self.tmp.name) / "source.log"
        self.logfile.write_text("", encoding="utf-8")
        self.cfg = {"server": "http://127.0.0.1:1", "data_dir": self.tmp.name, "hostname": "test-host",
                    "api_key": "test", "max_queue": 2,
                    "collectors": [{"name": "file", "type": "file", "path": str(self.logfile),
                                    "format": "plain", "source": "test"}]}

    def tearDown(self):
        self.tmp.cleanup()

    def test_checkpoint_and_queue_survive_without_clean_shutdown(self):
        a = agent_module.SOCAgent(self.cfg)
        a.collect_once()  # initial offset
        self.logfile.write_text("first\nsecond\n", encoding="utf-8")
        self.assertEqual(a.collect_once(), 2)
        uid = [e["event_uid"] for e in a.queue]
        b = agent_module.SOCAgent(self.cfg)  # no _save_state(), no finally
        self.assertEqual([e["event_uid"] for e in b.queue], uid)
        self.assertEqual(b.collect_once(), 0)

    def test_full_queue_does_not_advance_source(self):
        a = agent_module.SOCAgent(self.cfg)
        a.collect_once()
        self.logfile.write_text("first\nsecond\nthird\n", encoding="utf-8")
        self.assertEqual(a.collect_once(), 2)
        offset = a.collectors[0].state["offset"]
        self.assertEqual(a.collect_once(), 0)
        self.assertEqual(a.collectors[0].state["offset"], offset)
        a._request = lambda *args: (200, {"accepted": 2, "duplicates": 0})
        self.assertEqual(a.flush_queue(), 2)
        self.assertEqual(a.collect_once(), 1)
        self.assertEqual(len(a.queue), 1)

    def test_partial_ack_quarantines_rejection_and_keeps_retry(self):
        a = agent_module.SOCAgent(self.cfg)
        a.queue.extend([event("a"), event("b"), event("c")])
        a._save_spool()
        a._request = lambda *args: (200, {"accepted": 1, "receipts": [
            {"index": 0, "status": "accepted"}, {"index": 1, "status": "rejected", "reason": "invalid"},
            {"index": 2, "status": "retry"}]})
        self.assertEqual(a.flush_queue(), 1)
        restored = agent_module.SOCAgent(self.cfg)
        self.assertEqual([e["event_uid"] for e in restored.queue], ["c"])
        self.assertEqual(restored.quarantine[0]["event"]["event_uid"], "b")

    def test_invalid_ack_keeps_batch(self):
        a = agent_module.SOCAgent(self.cfg)
        a.queue.append(event())
        a._request = lambda *args: (200, {"accepted": 1, "receipts": [{"index": 9, "status": "accepted"}]})
        self.assertEqual(a.flush_queue(), 0)
        self.assertEqual(len(a.queue), 1)

    def test_ack_snapshot_failure_keeps_memory_and_disk(self):
        a = agent_module.SOCAgent(self.cfg)
        a.queue.append(event())
        a._save_spool()
        a._request = lambda *args: (200, {"accepted": 1})
        with patch.object(a, "_save_spool", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                a.flush_queue()
        self.assertEqual(len(a.queue), 1)
        self.assertEqual(len(agent_module.SOCAgent(self.cfg).queue), 1)

    def test_clean_ack_is_not_resurrected(self):
        a = agent_module.SOCAgent(self.cfg)
        a.queue.append(event())
        a._save_spool()
        a._request = lambda *args: (200, {"accepted": 1})
        a.flush_queue()
        self.assertEqual(len(agent_module.SOCAgent(self.cfg).queue), 0)

    def test_corrupt_spool_fails_closed(self):
        (Path(self.tmp.name) / "agent_spool.json").write_text("broken", encoding="utf-8")
        with self.assertRaises(ValueError):
            agent_module.SOCAgent(self.cfg)

    def test_single_instance_lock_rejects_second_writer(self):
        with agent_module.agent_lock(self.tmp.name):
            with self.assertRaises(RuntimeError):
                with agent_module.agent_lock(self.tmp.name):
                    self.fail("Second writer acquired the spool lock")
        with agent_module.agent_lock(self.tmp.name):
            pass

    def test_failed_snapshot_rolls_back_checkpoint_before_retry(self):
        a = agent_module.SOCAgent(self.cfg)
        a.collect_once()
        before = dict(a.collectors[0].state)
        self.logfile.write_text("one\n", encoding="utf-8")
        with patch.object(a, "_save_spool", side_effect=OSError("disk full")):
            self.assertEqual(a.collect_once(), 0)
        self.assertEqual(a.collectors[0].state, before)
        self.assertFalse(a.queue)
        self.assertEqual(a.collect_once(), 1)

    def test_missing_source_is_reported_by_collector_health(self):
        a = agent_module.SOCAgent(self.cfg)
        self.logfile.unlink()
        self.assertEqual(a.collect_once(), 0)
        self.assertEqual(a.collector_health["file"]["status"], "error")

    def test_real_process_abrupt_exit_recovers_snapshot(self):
        script = ("import sys,os; sys.path.insert(0,sys.argv[1]); from agent import SOCAgent; "
                  "import json; a=SOCAgent(json.loads(sys.argv[2])); a.collect_once(); "
                  "open(sys.argv[3],'a').write('after-checkpoint\\n'); a.collect_once(); os._exit(17)")
        out = subprocess.run([sys.executable, "-c", script, str(ROOT / "soc_agent"),
                              json.dumps(self.cfg), str(self.logfile)], capture_output=True, timeout=30)
        self.assertEqual(out.returncode, 17, out.stderr)
        restored = agent_module.SOCAgent(self.cfg)
        self.assertEqual(len(restored.queue), 1)
        self.assertEqual(restored.collect_once(), 0)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="soc_server_regression_")
        class TestConfig(Config):
            TESTING = True
            CSRF_ENABLED = False
            AI_AUTO_TRIAGE = False
            ANTHROPIC_API_KEY = None
            SECRET_KEY = "regression-secret"
            ENROLLMENT_TOKEN = "regression-token"
            SQLALCHEMY_DATABASE_URI = "sqlite:///" + (Path(cls.tmp.name) / "server.db").as_posix()
        cls.cfg = TestConfig
        cls.app = create_app(TestConfig, start_background=False)
        cls.app.logger.setLevel("CRITICAL")

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.session.remove()
            db.engine.dispose()
        cls.tmp.cleanup()

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        for model in (WorkJob, AlertReview, AIRun, AlertEvent):
            model.query.delete()
        # References are cleared explicitly only in this temporary test database.
        from app.models import Investigation
        Investigation.query.delete()
        KnowledgeReview.query.delete()
        KnowledgeArticle.query.filter(KnowledgeArticle.related_alert_id.is_not(None)).delete()
        Alert.query.delete()
        LogEvent.query.delete()
        Agent.query.delete()
        DetectionRule.query.update({"enabled": False})
        db.session.commit()
        self.agent = Agent(hostname="test-host", events_count=0)
        self.key = self.agent.issue_api_key()
        db.session.add(self.agent)
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            from app.models import User
            session["user_id"] = User.query.filter_by(username="admin").first().id

    def tearDown(self):
        db.session.rollback()
        db.session.remove()
        self.ctx.pop()

    def post(self, events):
        return self.client.post("/api/v1/logs", json={"events": events}, headers={"X-API-Key": self.key})

    def make_alert(self):
        result = ingest(self.agent, [event()], run_rules=False)
        ev = db.session.get(LogEvent, result["event_ids"][0])
        alert = Alert(title="test", host=ev.host, user_name=ev.user_name, src_ip=ev.src_ip,
                      severity="high", status="new", priority=2, first_event_time=ev.event_time,
                      last_event_time=ev.event_time, event_count=1)
        db.session.add(alert)
        db.session.flush()
        db.session.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
        db.session.commit()
        return alert

    def test_uid_replay_without_timestamp_and_conflict(self):
        payload = event()
        payload.pop("timestamp")
        self.assertEqual(self.post([payload]).json["accepted"], 1)
        self.assertEqual(self.post([payload]).json["duplicates"], 1)
        payload["message"] = "different"
        result = self.post([payload]).json
        self.assertEqual(result["receipts"][0]["reason"], "event_uid_conflict")
        self.assertEqual(LogEvent.query.count(), 1)

    def test_distinct_tail_after_500_characters_is_preserved(self):
        a = event()
        a.pop("event_uid")
        a["raw"] = "x" * 9000 + "A"
        b = {**a, "raw": "x" * 9000 + "B"}
        self.assertEqual(self.post([a, b]).json["accepted"], 2)

    def test_partial_batch_and_schema_rejection(self):
        with patch.dict(self.app.config, MAX_EVENTS_PER_BATCH=2):
            result = self.post([event(), {"message": 123}, event("later")]).json
        self.assertEqual([r["status"] for r in result["receipts"]], ["accepted", "rejected", "retry"])
        self.assertEqual(result["deferred"], 1)

    def test_invalid_timestamp_is_not_silently_replaced(self):
        result = self.post([{**event(), "timestamp": "not a date"}]).json
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(LogEvent.query.count(), 0)

    def test_invalid_sql_field_is_quarantined_without_losing_good_items(self):
        result = self.post([{**event("bad"), "pid": [1, 2]}, event("good")]).json
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(result["accepted"], 1)

    def test_legacy_event_without_timestamp_replays_stably(self):
        payload = {"message": "legacy log without timestamp", "action": "health_check"}
        self.assertEqual(self.post([payload]).json["accepted"], 1)
        self.assertEqual(self.post([payload]).json["duplicates"], 1)

    def test_concurrent_uid_delivery_keeps_one_record_and_counter(self):
        payload = event("concurrent")
        barrier, results, errors = threading.Barrier(2), [], []
        def send():
            try:
                with self.app.test_client() as client:
                    barrier.wait(timeout=5)
                    response = client.post("/api/v1/logs", json={"events": [payload]},
                                           headers={"X-API-Key": self.key})
                    results.append(response)
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=send) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertFalse(errors, errors)
        self.assertEqual([response.status_code for response in results], [200, 200])
        self.assertEqual(sum(response.json["accepted"] for response in results), 1)
        db.session.expire_all()
        self.assertEqual(LogEvent.query.count(), 1)
        self.assertEqual(db.session.get(Agent, self.agent.id).events_count, 1)

    def test_host_registration_cannot_rotate_key_without_old_key(self):
        payload = {"hostname": self.agent.hostname, "enrollment_token": self.cfg.ENROLLMENT_TOKEN}
        self.assertEqual(self.client.post("/api/v1/agents/register", json=payload).status_code, 409)
        result = self.client.post("/api/v1/agents/register", json=payload, headers={"X-API-Key": self.key})
        self.assertEqual(result.status_code, 201)
        self.assertNotEqual(result.json["api_key"], self.key)

    def test_detection_failure_is_durable_and_can_be_retried(self):
        with patch.object(RuleEngine, "evaluate", side_effect=RuntimeError("temporary")):
            result = self.post([event()]).json
        self.assertTrue(result["detection_pending"])
        self.assertEqual(result["accepted"], 1)
        job = db.session.get(WorkJob, result["detection_job_id"])
        self.assertEqual(job.status, "queued")
        job.available_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
        process_job(self.app, job.id)
        db.session.refresh(job)
        self.assertEqual(job.status, "succeeded")

    def test_expired_job_lease_can_be_recovered(self):
        job = enqueue("detection", {"event_ids": []})
        job.status, job.lease_until = "running", utcnow() - timedelta(seconds=1)
        db.session.commit()
        process_job(self.app, job.id)
        db.session.refresh(job)
        self.assertEqual(job.status, "succeeded")

    def test_active_lease_cannot_be_claimed(self):
        job = enqueue("detection", {"event_ids": []})
        job.status, job.lease_until = "running", utcnow() + timedelta(minutes=1)
        db.session.commit()
        self.assertIsNone(process_job(self.app, job.id))

    def test_ai_enqueue_commits_with_detection(self):
        rule = DetectionRule(code="REG_MATCH", name="match", rule_type="match", enabled=True,
                             severity="high", conditions=dumps({"action": "logon_failed"}))
        db.session.add(rule)
        db.session.commit()
        with patch.dict(self.app.config, AI_AUTO_TRIAGE=True):
            result = self.post([event()]).json
        self.assertEqual(result["ai_started"], 1)
        job = WorkJob.query.filter_by(kind="ai").one()
        process_job(self.app, job.id)
        db.session.refresh(job)
        self.assertEqual(job.status, "succeeded")

    def test_replay_does_not_inflate_match_count(self):
        rule = DetectionRule(name="idempotent", rule_type="match", enabled=True, severity="medium",
                             conditions=dumps({"action": "logon_failed"}))
        db.session.add(rule)
        db.session.commit()
        self.post([event()])
        RuleEngine([rule]).evaluate(LogEvent.query.all())
        self.assertEqual(Alert.query.one().event_count, 1)

    def test_late_preconditions_trigger_sequence_for_same_account(self):
        rule = DetectionRule(name="sequence", rule_type="sequence", enabled=True, severity="high",
                             window_seconds=300, group_by="src_ip", conditions=dumps({
                                 "precondition": {"action": "logon_failed"},
                                 "trigger": {"action": "logon_success"}, "min_count": 2}))
        db.session.add(rule)
        db.session.commit()
        now = utcnow()
        self.post([event("success", "logon_success", now)])
        self.post([event("bob-1", at=now - timedelta(seconds=30), user="bob"),
                   event("bob-2", at=now - timedelta(seconds=20), user="bob")])
        self.assertEqual(Alert.query.count(), 0)
        self.post([event("alice-1", at=now - timedelta(seconds=30)),
                   event("alice-2", at=now - timedelta(seconds=20))])
        self.assertEqual(Alert.query.count(), 1)

    def test_analyst_priority_and_closed_state_survive_ai(self):
        alert = self.make_alert()
        alert.status, alert.priority = "resolved", 5
        record_alert_review(alert, "admin")
        db.session.commit()
        output = self.app.extensions["soc_orchestrator"].run(alert.id, ("triage", "investigate"))
        self.assertNotIn("error", output["triage"])
        db.session.refresh(alert)
        self.assertEqual((alert.status, alert.priority), ("resolved", 5))
        self.assertIsNotNone(alert.ai_priority)

    def test_change_while_ai_runs_is_not_overwritten(self):
        alert = self.make_alert()
        self.app.extensions["soc_orchestrator"].run(alert.id, ("enrich",))
        original = TriageAgent.run
        def modify_then_return(instance):
            result = original(instance)
            instance.alert.status = "resolved"
            instance.alert.updated_at = utcnow()
            db.session.commit()
            return result
        with patch.object(TriageAgent, "run", modify_then_return):
            output = self.app.extensions["soc_orchestrator"].run(alert.id, ("triage",))
        self.assertTrue(output["triage"]["analysis"]["stale"])
        self.assertEqual(db.session.get(Alert, alert.id).status, "resolved")

    def test_unknown_evidence_id_is_rejected(self):
        alert = self.make_alert()
        original = TriageAgent.run
        def bad_ref(instance):
            result = original(instance)
            result["evidence_refs"] = [9999999]
            return result
        with patch.object(TriageAgent, "run", bad_ref):
            output = self.app.extensions["soc_orchestrator"].run(alert.id, ("triage",))
        self.assertIn("error", output["triage"])

    def test_ai_knowledge_requires_approval_and_edit_revokes_it(self):
        alert = self.make_alert()
        self.app.extensions["soc_orchestrator"].run(alert.id, ("knowledge",), username="admin")
        article = KnowledgeArticle.query.filter_by(related_alert_id=alert.id).one()
        article.title = "unique-regression-knowledge"
        db.session.commit()
        executor = ToolExecutor(alert)
        self.assertEqual(executor.search_knowledge("unique-regression-knowledge"), [])
        edit_knowledge_review(article, "admin", approve=True)
        db.session.commit()
        executor = ToolExecutor(alert)
        self.assertEqual(executor.search_knowledge("unique-regression-knowledge")[0]["id"], article.id)
        edit_knowledge_review(article, "admin", approve=False)
        db.session.commit()
        self.assertEqual(executor.search_knowledge("unique-regression-knowledge"), [])

    def test_tool_allowlist_and_ingest_cutoff(self):
        alert = self.make_alert()
        executor = ToolExecutor(alert)
        with self.assertRaises(ValueError):
            executor("sample_events", {})
        late = event("new-data", at=alert.last_event_time)
        ingest(self.agent, [late], run_rules=False)
        result = executor.query_events(host=alert.host)
        self.assertEqual(result["count"], 1)

    def test_status_api_checks_revision_and_preserves_review(self):
        alert = self.make_alert()
        result = self.client.post("/api/v1/alerts/%d/status" % alert.id,
                                  json={"status": "resolved", "expected_updated_at": "outdated"})
        self.assertEqual(result.status_code, 409)
        result = self.client.post("/api/v1/alerts/%d/status" % alert.id,
                                  json={"status": "resolved", "priority": 5})
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(db.session.get(AlertReview, alert.id))

    def test_operations_and_viewer_permissions(self):
        self.assertEqual(self.client.get("/operations").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/health").status_code, 200)
        alert = self.make_alert()
        from app.models import User
        with self.client.session_transaction() as session:
            session["user_id"] = User.query.filter_by(username="viewer").first().id
        self.assertEqual(self.client.get("/operations").status_code, 403)
        self.assertEqual(self.client.post("/api/v1/alerts/%d/status" % alert.id,
                                          json={"status": "resolved"}).status_code, 403)

    def test_candidate_limit_is_visible_and_retryable(self):
        rule = DetectionRule(name="bounded", enabled=True, rule_type="threshold", severity="high",
                             group_by="src_ip", threshold_count=2, window_seconds=300,
                             conditions=dumps({"action": "logon_failed"}))
        db.session.add(rule)
        db.session.commit()
        with patch.dict(self.app.config, DETECTION_CANDIDATE_LIMIT=1):
            result = self.post([event("one"), event("two")]).json
        self.assertTrue(result["detection_pending"])
        self.assertEqual(Alert.query.count(), 0)


class ValidationTests(unittest.TestCase):
    def test_unknown_rule_condition_fails_explicitly(self):
        with self.assertRaises(ValueError):
            validate_conditions({"actoin": "logon_failed"})

    def test_windows_empty_channel_collects_first_new_record(self):
        c = collectors_module.WindowsEventLogCollector("win", "Security", state={})
        first = {"extra": {"record_id": 1}}
        with patch.object(collectors_module, "IS_WINDOWS", True), patch.object(c, "_query", side_effect=["empty", "new"]), patch.object(
                collectors_module.parsers, "parse_windows_event_xml", side_effect=[[], [first]]):
            self.assertEqual(c.collect(), [])
            self.assertEqual(c.collect(), [first])

    def test_windows_record_reset_reads_from_beginning(self):
        c = collectors_module.WindowsEventLogCollector("win", "Security", state={"last_record": 100})
        newest, first = {"extra": {"record_id": 3}}, {"extra": {"record_id": 1}}
        with patch.object(collectors_module, "IS_WINDOWS", True), patch.object(c, "_query", side_effect=["empty", "newest", "all"]), patch.object(
                collectors_module.parsers, "parse_windows_event_xml", side_effect=[[], [newest], [first, newest]]):
            self.assertEqual(c.collect(), [first, newest])
        self.assertEqual(c.state["last_record"], 3)

    def test_windows_read_error_does_not_jump_over_backlog(self):
        c = collectors_module.WindowsEventLogCollector("win", "Security", state={"last_record": 100})
        with patch.object(collectors_module, "IS_WINDOWS", True), patch.object(c, "_query", side_effect=RuntimeError("permission")):
            with self.assertRaises(RuntimeError):
                c.collect()
        self.assertEqual(c.state["last_record"], 100)
    def test_provider_invalid_json_schema_preserves_usage(self):
        llm = LLMClient()
        llm._client = object()
        response = SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text='{"score":true}')],
                                   usage=SimpleNamespace(input_tokens=10, output_tokens=5))
        with patch.object(llm, "_create", return_value=response):
            with self.assertRaises(LLMUnavailable) as raised:
                llm.complete_json("system", "data", {"type": "object", "properties": {"score": {"type": "number"}}})
        self.assertEqual(raised.exception.usage["input_tokens"], 10)

    def test_tool_budget_blocks_extra_execution_and_preserves_usage(self):
        llm = LLMClient(max_tool_iterations=0)
        llm._client = object()
        response = SimpleNamespace(stop_reason="tool_use", content=[SimpleNamespace(type="tool_use", name="query_events", input={}, id="x")],
                                   usage=SimpleNamespace(input_tokens=10, output_tokens=5))
        calls = []
        with patch.object(llm, "_create", return_value=response):
            with self.assertRaises(LLMUnavailable) as raised:
                llm.run_with_tools("system", "data", [], lambda *args: calls.append(args))
        self.assertFalse(calls)
        self.assertEqual(raised.exception.usage["output_tokens"], 5)

    def test_json_schema_rejects_bool_as_number_and_nan(self):
        for value in (True, float("nan"), -1, 2):
            with self.assertRaises(ValueError):
                validate_json(value, {"type": "number", "minimum": 0, "maximum": 1})

    def test_html_sanitizer_drops_executable_content(self):
        unsafe = '<script>alert(1)</script><img src=x onerror=alert(1)><a href="java&#x73;cript:alert(1)">bad</a><p onclick="x">safe</p>'
        safe = sanitize_html(unsafe)
        self.assertNotIn("script", safe)
        self.assertNotIn("onerror", safe)
        self.assertNotIn("onclick", safe)
        self.assertIn("<p>safe</p>", safe)


if __name__ == "__main__":
    unittest.main(verbosity=2)
