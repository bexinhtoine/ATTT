"""Unit/integration checks for comparison tooling, not measured vendor results."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.three_way.core import (generate, write_bundle, read_bundle, score, RULES, MARKER,
                                       elastic_rules, wazuh_rules_xml, parse_native_hits)
from benchmarks.three_way.adapters import JsonHTTP, PrerequisiteError, _search_all
from benchmarks.three_way.adapters import run_elastic, run_wazuh
from benchmarks.three_way.core import elastic_document, wazuh_document, timestamp
from datetime import datetime, timezone, timedelta
from benchmarks.three_way.cli import run_platform
from benchmarks.three_way.report import write_report, load_results
from tools.prepare_threeway_lab import init_secrets, prepare_wazuh

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def oracle_observations(bundle):
    """Scoring fixture ONLY. Never used by any platform adapter."""
    rows = []
    for label in bundle["labels"]:
        rows.append({"rule": "B99", "event_uid": label["marker_uid"], "episode_id": label["episode_id"]})
        for rule in label["expected_rules"]:
            rows.append({"rule": rule, "event_uid": label["event_uid"], "episode_id": label["episode_id"]})
    return rows


class DatasetTests(unittest.TestCase):
    def test_deterministic_and_ground_truth_separate(self):
        a, b = generate(), generate()
        self.assertEqual(a, b)
        self.assertEqual(len(a["labels"]), 96)
        self.assertEqual(len(a["events"]), 192)
        text = json.dumps(a["events"])
        self.assertNotIn("expected_rules", text)
        self.assertNotIn("ground_truth_attack", text)
        self.assertEqual(len({e["event_uid"] for e in a["events"]}), 192)

    def test_invalid_run_id_rejected(self):
        for name in ("../elsewhere", "RUN WITH SPACE", "", "a" * 49):
            with self.assertRaises(ValueError):
                generate(name)

    def test_checksum_detects_dataset_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            write_bundle(directory, variants=1)
            path = Path(directory) / "events.jsonl"
            path.write_text(path.read_text(encoding="utf-8").replace("audit_log_cleared", "audit_log_requested"), encoding="utf-8")
            with self.assertRaises(ValueError):
                read_bundle(directory)

    def test_existing_bundle_cannot_be_replaced_by_other_dataset(self):
        with tempfile.TemporaryDirectory() as directory:
            write_bundle(directory, variants=1)
            with self.assertRaises(ValueError):
                write_bundle(directory, variants=2)

    def test_generated_rules_include_separate_marker(self):
        bundle = generate(variants=1)
        rules = elastic_rules(bundle["manifest"])
        self.assertEqual(len(rules), 5)
        self.assertTrue(all(rule["timestamp_override"] == "event.ingested" for rule in rules))
        self.assertEqual(len(ET.fromstring(wazuh_rules_xml()).findall("rule")), 6)


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.bundle = generate(variants=1)

    def test_correct_fixture_scores_exactly(self):
        result = score(self.bundle, oracle_observations(self.bundle))
        self.assertEqual(result["counts"], {"tp": 4, "fp": 0, "fn": 0, "tn": 28})
        self.assertEqual(result["f1"], 1.0)
        self.assertFalse(result["attack_verdict_evaluated"])
        self.assertTrue(result["complete"])

    def test_wrong_rule_is_both_false_positive_and_false_negative(self):
        rows = oracle_observations(self.bundle)
        item = next(row for row in rows if row["rule"] == "M01")
        item["rule"] = "M02"
        result = score(self.bundle, rows)
        self.assertEqual((result["counts"]["tp"], result["counts"]["fp"], result["counts"]["fn"]), (3, 1, 1))

    def test_missing_telemetry_cannot_be_called_complete(self):
        result = score(self.bundle, [])
        self.assertFalse(result["complete"])
        self.assertIsNone(result["precision"])
        self.assertEqual(result["recall"], 0)

    def test_duplicate_alerts_are_counted_separately(self):
        rows = oracle_observations(self.bundle)
        rows.append(copy.deepcopy(next(row for row in rows if row["rule"] == "M01")))
        result = score(self.bundle, rows)
        self.assertEqual(result["duplicate_observations"], 1)
        self.assertEqual(result["counts"]["tp"], 4)

    def test_forged_episode_and_marker_rejected(self):
        rows = oracle_observations(self.bundle)
        rows[0]["event_uid"] = "invented"
        result = score(self.bundle, rows)
        self.assertFalse(result["complete"])
        self.assertTrue(result["invalid_observations"])

    def test_false_alert_on_negative_counts_fp(self):
        rows = oracle_observations(self.bundle)
        label = next(label for label in self.bundle["labels"] if not label["expected_rules"])
        rows.append({"rule": "M01", "episode_id": label["episode_id"], "event_uid": label["event_uid"]})
        self.assertEqual(score(self.bundle, rows)["counts"]["fp"], 1)


class NativeParserTests(unittest.TestCase):
    def setUp(self):
        self.bundle = generate(variants=1)
        self.event = self.bundle["events"][0]
        self.meta = self.event["extra"]["socbench"]

    def test_wazuh_native_alert_fields(self):
        hits = [{"_id": "native", "_source": {"data": {"socbench": self.meta}, "rule": {"id": "100511"}}}]
        rows, ignored = parse_native_hits("wazuh", hits, self.bundle)
        self.assertEqual(rows[0]["rule"], "M01")
        self.assertEqual(rows[0]["event_uid"], self.event["event_uid"])
        self.assertEqual(ignored, 0)

    def test_elastic_flattened_and_nested_rule_fields(self):
        for rule in ({"kibana.alert.rule.rule_id": "socbench-pilot-v1-M01"},
                     {"kibana": {"alert": {"rule": {"rule_id": "socbench-pilot-v1-M01"}}}}):
            rows, _ = parse_native_hits("elastic", [{"_source": {**rule, "socbench": self.meta}}], self.bundle)
            self.assertEqual(rows[0]["rule"], "M01")

    def test_other_run_cannot_contaminate_measurement(self):
        meta = {**self.meta, "run_id": "another-run"}
        rows, ignored = parse_native_hits("wazuh", [{"_source": {"data": {"socbench": meta}, "rule": {"id": "100511"}}}], self.bundle)
        self.assertEqual(rows, [])
        self.assertEqual(ignored, 1)

    def test_search_refuses_truncated_results(self):
        class Fake:
            def request(self, *args):
                return {"hits": {"total": {"value": 2, "relation": "eq"}, "hits": [{}]}}
        with self.assertRaises(RuntimeError):
            _search_all(Fake(), "index", {"match_all": {}})

    def test_missing_config_and_remote_http_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(PrerequisiteError):
                JsonHTTP("ELASTIC")

    def test_insecure_tls_opt_in_is_limited_to_loopback(self):
        with patch.dict(os.environ, {"ELASTIC_URL": "https://example.com", "ELASTIC_API_KEY": "fixture",
                                     "SOCBENCH_LAB_INSECURE_TLS": "1"}, clear=True):
            with self.assertRaises(PrerequisiteError):
                JsonHTTP("ELASTIC")
        with patch.dict(os.environ, {"ELASTIC_URL": "http://example.com", "ELASTIC_API_KEY": "fixture"}, clear=True):
            with self.assertRaises(PrerequisiteError):
                JsonHTTP("ELASTIC")


class ReportTests(unittest.TestCase):
    def test_comparison_page_renders_report_and_missing_report(self):
        sys.path.insert(0, str(ROOT / "soc_server"))
        from config import Config
        from app import create_app
        from app.extensions import db
        from app.models import User
        with tempfile.TemporaryDirectory() as directory:
            bundle = write_bundle(directory, variants=1)
            write_report(directory, bundle)
            class C(Config):
                TESTING = True
                SECRET_KEY = "comparison-test"
                ANTHROPIC_API_KEY = None
                SQLALCHEMY_DATABASE_URI = "sqlite:///" + (Path(directory) / "ui.db").as_posix()
                COMPARISON_REPORT_PATH = str(Path(directory) / "comparison.json")
            app = create_app(C, start_background=False)
            with app.app_context():
                client = app.test_client()
                with client.session_transaction() as session:
                    session["user_id"] = User.query.filter_by(username="viewer").one().id
                response = client.get("/comparison?mode=benchmark")
                self.assertEqual(response.status_code, 200)
                self.assertIn("Wazuh", response.get_data(as_text=True))
                self.assertIn("Chưa đo", response.get_data(as_text=True))
                Path(C.COMPARISON_REPORT_PATH).unlink()
                self.assertIn("Chưa có báo cáo", client.get("/comparison?mode=benchmark").get_data(as_text=True))
                db.session.remove()
                db.engine.dispose()
    def test_missing_platforms_are_not_zero_or_ranked(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = write_bundle(directory, variants=1)
            report = write_report(directory, bundle)
            self.assertFalse(report["comparison_ready"])
            self.assertIsNone(report["platforms"]["elastic"]["metrics"])
            self.assertIn("Chưa đo", (Path(directory) / "comparison.html").read_text(encoding="utf-8"))

    def test_real_soc_adapter_and_raw_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = write_bundle(directory, variants=1)
            result = run_platform(directory, bundle, "soc")
            self.assertEqual(result["status"], "measured", result.get("reason"))
            self.assertEqual(result["metrics"]["counts"]["tp"], 4)
            self.assertEqual(result["metrics"]["markers_seen"], 8)
            self.assertFalse(write_report(directory, bundle)["comparison_ready"])
            path = Path(directory) / result["raw_file"]
            path.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_results(directory, bundle)

    def test_missing_vendor_is_explicitly_unavailable(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            bundle = write_bundle(directory, variants=1)
            result = run_platform(directory, bundle, "elastic")
            self.assertEqual(result["status"], "unavailable")
            self.assertIsNone(result["metrics"])


class AdapterContractTests(unittest.TestCase):
    """Fixtures test client logic, never count as vendor benchmark observations."""
    def test_elastic_adapter_reads_alerts_and_rule_execution(self):
        bundle = generate(variants=1)
        class FakeHTTP:
            tls_mode = "fixture"
            def __init__(self, *args):
                pass
            def request(self, method, path, value=None, ndjson=None):
                if path == "/":
                    return {"version": {"number": "fixture-only"}}
                if path.startswith("/api/detection_engine/rules?"):
                    return {"execution_summary": {"last_execution": {"status": "succeeded",
                            "date": timestamp(datetime.now(timezone.utc) + timedelta(seconds=1))}}}
                return {}
        hits = []
        for row in oracle_observations(bundle):
            ev = next(e for e in bundle["events"] if e["event_uid"] == row["event_uid"])
            hits.append({"_id": ev["event_uid"], "_source": {**elastic_document(ev, ev["timestamp"]),
                         "kibana.alert.rule.rule_id": "socbench-pilot-v1-" + row["rule"]}})
        with patch("benchmarks.three_way.adapters.JsonHTTP", FakeHTTP), patch(
                "benchmarks.three_way.adapters._search_all", return_value=hits):
            result = run_elastic(bundle, timeout=1)
        self.assertTrue(result["execution_gate"])
        self.assertTrue(score(bundle, result["observations"])["complete"])

    def test_wazuh_preflight_replay_and_attempt_filter(self):
        bundle = generate(variants=1)
        action_rules = {spec["action"]: spec["wazuh_id"] for spec in list(RULES.values()) + [MARKER]}
        seen_queries = []
        class FakeHTTP:
            tls_mode = "fixture"
            def __init__(self, *args):
                pass
            def request(self, method, path, value=None, raw_response=False):
                if raw_response:
                    return "fixture-token"
                if path == "/logtest":
                    action = json.loads(value["event"])["socbench"]["action"]
                    return {"error": 0, "data": {"token": "fixture-session",
                            "output": {"rule": {"id": action_rules.get(action, "100510")}}}}
                return {"version": {"number": "fixture"}, "data": {"api_version": "fixture-only"}}
        def search(client, index, query):
            seen_queries.append(query)
            hits = []
            for row in oracle_observations(bundle):
                ev = next(e for e in bundle["events"] if e["event_uid"] == row["event_uid"])
                hits.append({"_id": ev["event_uid"], "_source": {
                    "data": wazuh_document(ev), "rule": {"id": action_rules[ev["action"]]}}})
            return hits
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.jsonl"
            path.touch()
            with patch.dict(os.environ, {"WAZUH_INPUT_FILE": str(path)}), patch(
                    "benchmarks.three_way.adapters.JsonHTTP", FakeHTTP), patch(
                    "benchmarks.three_way.adapters._search_all", side_effect=search):
                result = run_wazuh(bundle, timeout=1)
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), len(bundle["events"]))
        self.assertEqual(len(result["native"]["rule_preflight"]), 9)
        self.assertIn(result["attempt_id"], json.dumps(seen_queries))
        self.assertTrue(score(bundle, result["observations"])["complete"])


class LabTests(unittest.TestCase):
    def test_secret_generation_does_not_overwrite_existing_values(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(init_secrets(directory))
            path = Path(directory) / ".env"
            original = path.read_bytes()
            self.assertFalse(init_secrets(directory))
            self.assertEqual(path.read_bytes(), original)

    def test_official_compose_transform_is_loopback_only_and_idempotent(self):
        import yaml
        with tempfile.TemporaryDirectory() as directory:
            single = Path(directory) / "single-node"
            config = single / "config" / "wazuh_cluster"
            config.mkdir(parents=True)
            (config / "wazuh_manager.conf").write_text("<ossec_config></ossec_config>", encoding="utf-8")
            services = {name: {"image": "wazuh/" + name.replace(".", "-") + ":4.14.10", "volumes": []}
                        for name in ("wazuh.manager", "wazuh.indexer", "wazuh.dashboard")}
            (single / "docker-compose.yml").write_text(yaml.safe_dump({"services": services}), encoding="utf-8")
            target = prepare_wazuh(directory)
            content = json.loads(target.read_text())
            for service in content["services"].values():
                self.assertTrue(all(port.startswith("127.0.0.1:") for port in service["ports"]))
            prepare_wazuh(directory)
            self.assertEqual((config / "wazuh_manager.conf").read_text().count("<localfile>"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
