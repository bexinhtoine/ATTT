"""Platform UI/data integration tests. All vendor examples below are test fixtures only."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "soc_server"))
from config import Config
from app import create_app
from app.extensions import db
from app.models import Alert, AuditLog, User
from app.platforms import FEATURES, SCHEMA, external_result, save_snapshot, validate_snapshot
from tools.sync_platform_results import collect


def fixture(platform="wazuh"):
    return {"schema": SCHEMA, "platform": platform, "source": "TEST FIXTURE ONLY",
            "scope": "isolated unit test", "collected_at": "2026-11-25T08:00:00Z",
            "features": {"alerts": {"status": "available", "total": 1,
                "summary": {"Tổng bản ghi": 1}, "records": [{"id": "vendor-unique-001", "title": "Fixture vendor alert",
                "host": "fixture-host", "severity": "high", "status": "open", "message": "<script>bad()</script>"}]}}}


class PlatformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="soc_platform_tests_")
        class C(Config):
            TESTING = True
            SECRET_KEY = "test-only-platforms"
            ENROLLMENT_TOKEN = "test-only"
            ANTHROPIC_API_KEY = None
            OPENAI_API_KEY = None
            SQLALCHEMY_DATABASE_URI = "sqlite:///" + (Path(cls.temp.name) / "test.db").as_posix()
            PLATFORM_RESULTS_DIR = str(Path(cls.temp.name) / "platform_results")
        cls.app = create_app(C, start_background=False)

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.session.remove()
            db.engine.dispose()
        cls.temp.cleanup()

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.directory = Path(self.app.config["PLATFORM_RESULTS_DIR"])
        self.directory.mkdir(exist_ok=True)
        for platform in ("elastic", "wazuh"):
            (self.directory / (platform + ".json")).unlink(missing_ok=True)
        self.local = Alert(title="LOCAL-ONLY-MUST-NOT-LEAK", severity="high", status="new")
        db.session.add(self.local)
        db.session.commit()
        self.client = self.as_role("admin")

    def tearDown(self):
        db.session.delete(self.local)
        db.session.commit()
        db.session.remove()
        self.ctx.pop()

    def as_role(self, role):
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = User.query.filter_by(role=role).first().id
        return client

    def token(self, client=None):
        client = client or self.client
        client.get("/alerts")
        with client.session_transaction() as session:
            return session["_csrf_token"]

    def test_all_features_render_with_each_platform_and_selector(self):
        for feature, (_, endpoint, _) in FEATURES.items():
            from flask import url_for
            with self.app.test_request_context():
                path = url_for(endpoint)
            for platform in ("soc", "elastic", "wazuh", "all"):
                with self.subTest(feature=feature, platform=platform):
                    response = self.client.get(path, query_string={"platform": platform})
                    self.assertEqual(response.status_code, 200)
                    self.assertIn('id="result-platform"', response.get_data(as_text=True))
                    if platform in ("elastic", "wazuh"):
                        self.assertNotIn("LOCAL-ONLY-MUST-NOT-LEAK", response.get_data(as_text=True))

    def test_selection_persists_navigation_and_native_view_can_be_restored(self):
        self.client.get("/alerts?platform=wazuh")
        self.assertIn('data-result-platform="wazuh"', self.client.get("/logs").get_data(as_text=True))
        self.assertIn("LOCAL-ONLY-MUST-NOT-LEAK", self.client.get("/alerts?platform=soc").get_data(as_text=True))
        self.assertEqual(self.client.get("/alerts?platform=../../soc").status_code, 400)

    def test_imported_vendor_records_are_isolated_and_escaped(self):
        save_snapshot(fixture())
        page = self.client.get("/alerts?platform=wazuh").get_data(as_text=True)
        self.assertIn("vendor-unique-001", page)
        self.assertNotIn("LOCAL-ONLY-MUST-NOT-LEAK", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>bad()", page)
        page = self.client.get("/alerts?platform=all").get_data(as_text=True)
        self.assertIn("vendor-unique-001", page)
        self.assertIn("LOCAL-ONLY-MUST-NOT-LEAK", page)
        self.assertEqual(page.count('data-result-platform="'), 3)
        self.assertEqual(external_result("wazuh", "rules")["status"], "not_integrated")

    def test_filters_pagination_and_csv_use_vendor_source(self):
        data = fixture()
        data["features"]["alerts"]["records"] = [{"id": str(i), "title": "=EVIL()" if i == 0 else "fixture", "severity": "high"} for i in range(61)]
        data["features"]["alerts"]["total"] = 100
        data["features"]["alerts"]["status"] = "partial"
        save_snapshot(data)
        page = self.client.get("/alerts?platform=wazuh&page=2").get_data(as_text=True)
        self.assertIn("Trang 2/2", page)
        csv = self.client.get("/alerts/export.csv?platform=wazuh&q=EVIL").get_data(as_text=True)
        self.assertIn("'=EVIL()", csv)
        self.assertNotIn("LOCAL-ONLY", csv)
        self.assertNotIn("fixture", csv)
        page = self.client.get("/alerts?platform=wazuh&severity=low").get_data(as_text=True)
        self.assertNotIn("=EVIL()", page)

    def test_read_only_guards_native_mutations_and_details(self):
        token = self.token()
        self.client.get("/alerts?platform=wazuh")
        for path in ("/rules/replay", "/alerts/%s/update" % self.local.id, "/incidents/create"):
            self.assertEqual(self.client.post(path, data={"_csrf_token": token}).status_code, 409)
        for path in ("/api/v1/alerts/%s/status" % self.local.id, "/api/v1/alerts/%s/ai/full" % self.local.id):
            response = self.client.post(path, json={"status": "resolved"}, headers={"X-CSRF-Token": token})
            self.assertEqual(response.status_code, 409)
        self.assertEqual(db.session.get(Alert, self.local.id).status, "new")
        self.assertEqual(self.client.get("/alerts/%s" % self.local.id).status_code, 302)

    def test_rbac_and_login_still_apply_to_comparison_and_import(self):
        self.assertEqual(self.app.test_client().get("/alerts?platform=all").status_code, 302)
        for role in ("viewer", "analyst"):
            client = self.as_role(role)
            self.assertEqual(client.get("/platform-results/import").status_code, 403)
            if role == "viewer":
                self.assertEqual(client.get("/operations?platform=all").status_code, 403)
                token = self.token(client)
                self.assertEqual(client.post("/rules/replay?platform=all", data={"_csrf_token": token}).status_code, 403)

    def test_import_requires_csrf_and_admin_and_records_audit(self):
        content = json.dumps(fixture()).encode()
        self.assertEqual(self.client.post("/platform-results/import", data={"results": (io.BytesIO(content), "a.json")}).status_code, 403)
        token = self.token()
        response = self.client.post("/platform-results/import", data={"_csrf_token": token, "results": (io.BytesIO(content), "../../elsewhere.json")})
        self.assertEqual(response.status_code, 302)
        self.assertTrue((self.directory / "wazuh.json").exists())
        self.assertTrue(AuditLog.query.filter_by(action="platform_results_import", target="wazuh").first())
        self.assertIn("vendor-unique-001", self.client.get(response.location).get_data(as_text=True))

    def test_invalid_import_preserves_previous_valid_data(self):
        save_snapshot(fixture())
        token = self.token()
        self.client.post("/platform-results/import", data={"_csrf_token": token, "results": (io.BytesIO(b'{"platform":"../bad"}'), "bad.json")})
        self.assertEqual(external_result("wazuh", "alerts")["records"][0]["id"], "vendor-unique-001")
        (self.directory / "wazuh.json").write_text("[]", encoding="utf-8")
        self.assertEqual(external_result("wazuh", "alerts")["status"], "error")
        self.assertEqual(self.client.get("/alerts?platform=wazuh").status_code, 200)

    def test_unknown_platform_and_schema_cannot_be_saved(self):
        for key, value in (("platform", "../soc"), ("schema", "wrong"), ("collected_at", "yesterday")):
            data = fixture()
            data[key] = value
            with self.assertRaises(ValueError):
                validate_snapshot(data)
        data = fixture()
        data["features"]["alerts"]["status"] = "not_measured"
        with self.assertRaises(ValueError):
            validate_snapshot(data)

    def test_default_comparison_never_substitutes_synthetic_pilot(self):
        with patch.object(self.app, "instance_path", self.temp.name):
            text = self.client.get("/comparison?platform=all").get_data(as_text=True)
            self.assertIn("Chưa xuất bản lượt đối chiếu máy thật mới", text)
            self.assertNotIn("96 kịch bản", text)
            current = {"schema": "real-vm-comparison-v1", "run_id": "native-fixture", "generated_at_local": "25/11/2026 19:10 +07:00", "events": 1, "hosts": ["lab"], "sha256": "fixture", "source_event_ids": [1], "limitations": "fixture", "rules": [], "platforms": {}}
            for key in ("soc", "elastic", "wazuh"):
                current["platforms"][key] = {"logs": 1, "missing_ids": 0, "raw_mismatches": 0, "alerts": 1, "collected_at_local": "fixture", "rule_scope": "fixture"}
            (Path(self.temp.name) / "real_comparison.json").write_text(json.dumps(current), encoding="utf-8")
            text = self.client.get("/comparison?platform=all").get_data(as_text=True)
            self.assertIn("native-fixture", text)
            self.assertNotIn("Precision hành vi", text)

    def test_benchmark_filters_platform_and_renders_episode_evidence(self):
        # Isolate this UI check from any real lab results the user may regenerate.
        measured = {"status": "measured", "run_id": "fixture", "started_at": "2026-11-25T00:00:00Z", "metrics": {
            "counts": {"tp": 1, "fp": 0, "fn": 0, "tn": 3}, "markers_seen": 1, "markers_expected": 1,
            "precision": 1.0, "recall": 1.0, "f1": 1.0,
            "per_rule": {"M01": {"tp": 1, "fp": 0, "fn": 0, "tn": 0}},
            "episodes": [{"episode_id": "fixture-episode", "expected": ["M01"], "observed": ["M01"], "marker_seen": True, "exact_match": True}]}}
        report = {"schema": "threeway-report-v1", "comparison_ready": False, "conclusion": "TEST FIXTURE ONLY",
                  "manifest": {"episodes": 1, "events": 2, "events_sha256": "fixture-only"},
                  "platforms": {"soc": measured, "elastic": {"status": "unavailable", "metrics": None}, "wazuh": {"status": "unavailable", "metrics": None}}}
        path = Path(self.temp.name) / "fixture-comparison.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        with patch.dict(self.app.config, {"COMPARISON_REPORT_PATH": str(path)}):
            text = self.client.get("/comparison?mode=benchmark&platform=soc").get_data(as_text=True)
            self.assertIn("fixture-episode", text)
            text = self.client.get("/comparison?mode=benchmark&platform=wazuh").get_data(as_text=True)
            self.assertNotIn("fixture-episode", text)
            self.assertIn("Chưa đo", text)


class CollectorTests(unittest.TestCase):
    def test_collector_queries_only_search_and_marks_truncated_results(self):
        client = Mock(url="https://fixture.invalid")
        client.request.return_value = {"hits": {"total": {"value": 99, "relation": "eq"}, "hits": [{"_id": "e1", "_source": {"@timestamp": "2026-11-25T01:00:00Z", "host": {"name": "lab"}, "kibana.alert.rule.name": "Fixture rule"}}]}}
        result = collect("elastic", client, "now-1h", "now", {"alerts": ".alerts-fixture"})
        self.assertEqual(result["features"]["alerts"]["status"], "partial")
        self.assertEqual(result["features"]["alerts"]["records"][0]["title"], "Fixture rule")
        for args in client.request.call_args_list:
            self.assertEqual(args.args[0], "POST")
            self.assertTrue(args.args[1].endswith("/_search"))
        self.assertNotIn("rules", result["features"])

    def test_collector_failure_is_unmeasured_not_zero(self):
        client = Mock(url="https://fixture.invalid")
        client.request.side_effect = RuntimeError("HTTP 404 test fixture")
        result = collect("wazuh", client, "now-1h", "now", {"logs": "wazuh-archives-*", "alerts": "wazuh-alerts-*"})
        self.assertEqual(result["features"]["logs"]["status"], "not_measured")
        self.assertNotIn("total", result["features"]["logs"])
        self.assertEqual(result["features"]["dashboard"]["summary"], {})

    def test_wazuh_native_level_is_preserved(self):
        client = Mock(url="https://fixture.invalid")
        client.request.return_value = {"hits": {"total": 1, "hits": [{"_id": "w1", "_source": {"rule": {"level": 12, "description": "Fixture rule"}, "agent": {"name": "host1"}}}]}}
        result = collect("wazuh", client, "now-1h", "now", {"alerts": "wazuh-alerts-*"})
        self.assertEqual(result["features"]["alerts"]["records"][0]["severity"], 12)
        self.assertIsNone(result["features"]["alerts"]["records"][0]["status"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
