"""Offline checks only: provider protocol and honest evaluation failure handling."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "soc_server"))
from app.ai.openai_client import OpenAILLMClient
from app.ai.llm import LLMUnavailable, LLMClient
from app.ai.agents import InvestigationAgent
from benchmarks.ai_eval.runner import run, measure, seed_case, DATASET, create_app, Config, db

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False}


def response(text='{"ok": true}', output=None, status="completed"):
    return SimpleNamespace(status=status, output=output or [], output_text=text,
                           usage=SimpleNamespace(input_tokens=10, output_tokens=3,
                                                 input_tokens_details=SimpleNamespace(cached_tokens=2)))


class OpenAIProtocolTests(unittest.TestCase):
    def client(self, **kwargs):
        client = OpenAILLMClient(api_key=None, **kwargs)
        client._client = MagicMock()
        return client

    def test_missing_key_never_sends_request(self):
        client = OpenAILLMClient()
        self.assertFalse(client.available)
        with self.assertRaises(LLMUnavailable):
            client.complete_json("system", "user", SCHEMA)

    def test_structured_output_and_usage(self):
        client = self.client()
        client._client.responses.create.return_value = response()
        result, usage = client.complete_json("system", "user", SCHEMA)
        self.assertTrue(result["ok"])
        self.assertEqual(usage["cached_input_tokens"], 2)
        sent = client._client.responses.create.call_args.kwargs
        self.assertFalse(sent["store"])
        self.assertEqual(sent["text"]["format"]["schema"], SCHEMA)

    def test_tool_results_return_to_model(self):
        client = self.client()
        call = SimpleNamespace(type="function_call", name="lookup", arguments='{"key":"value"}', call_id="call1")
        call.model_dump = lambda **kwargs: {"type": "function_call", "name": "lookup", "arguments": call.arguments, "call_id": "call1", "id": "fc_1"}
        client._client.responses.create.side_effect = [response(output=[call]), response()]
        definitions = [{"name": "lookup", "description": "Read only", "input_schema": {"type": "object"}}]
        executor = MagicMock(return_value={"observed": 42})
        result, calls, usage = client.run_with_tools("sys", "user", definitions, executor, SCHEMA)
        executor.assert_called_once_with("lookup", {"key": "value"})
        sent = client._client.responses.create.call_args.kwargs["input"]
        self.assertEqual(sent[-1]["type"], "function_call_output")
        self.assertEqual(sent[-1]["call_id"], "call1")
        self.assertEqual(len(calls), 1)
        self.assertEqual(usage["input_tokens"], 20)

    def test_budget_schema_refusal_and_incomplete(self):
        for item in (response(text='{"wrong":true}'), response(text=""), response(status="incomplete")):
            client = self.client()
            client._client.responses.create.return_value = item
            with self.assertRaises(LLMUnavailable) as raised:
                client.complete_json("sys", "user", SCHEMA)
            self.assertEqual(raised.exception.usage["input_tokens"], 10)
        client = self.client(tool_budget_seconds=0)
        with self.assertRaises(LLMUnavailable):
            client.complete_json("sys", "user", SCHEMA)
        client._client.responses.create.assert_not_called()

    def test_provider_selection(self):
        app = SimpleNamespace(config={"AI_PROVIDER": "openai", "OPENAI_API_KEY": None, "AI_MODEL": "gpt-4.1-mini"})
        self.assertIsInstance(LLMClient.from_app(app), OpenAILLMClient)


class EvaluationTests(unittest.TestCase):
    def test_offline_run_keeps_llm_unavailable_and_outputs_review_sheet(self):
        with tempfile.TemporaryDirectory(prefix="soc_eval_check_") as directory:
            out = Path(directory) / "result"
            args = argparse.Namespace(provider="openai", model="gpt-4.1-mini", arms=["heuristic", "single_turn", "agentic"], limit=1,
                                      repeats=1, output=out, input_usd_per_million=None, output_usd_per_million=None)
            unavailable = SimpleNamespace(model="gpt-4.1-mini", available=False, unavailable_reason="No API key")
            with patch.object(LLMClient, "from_app", return_value=unavailable):
                self.assertEqual(run(args), 2)
            report = json.loads((out / "results.json").read_text(encoding="utf-8"))
            self.assertFalse(report["complete"])
            self.assertEqual([r["status"] for r in report["records"]], ["measured", "unavailable", "unavailable"])
            self.assertTrue((out / "human_review.csv").is_file())
            self.assertTrue((out / "failed_only.db").is_file())
            with self.assertRaises(FileExistsError):
                run(args)

    def test_llm_error_is_not_replaced_with_local_result(self):
        with tempfile.TemporaryDirectory(prefix="soc_eval_failure_") as directory:
            class C(Config):
                TESTING = True
                ANTHROPIC_API_KEY = None
                OPENAI_API_KEY = None
                SQLALCHEMY_DATABASE_URI = "sqlite:///" + (Path(directory) / "case.db").as_posix()
            app = create_app(C, start_background=False)
            with app.app_context():
                case = json.loads(DATASET.read_text(encoding="utf-8"))["cases"][0]
                aid, ids, cutoff = seed_case(case)
                llm = SimpleNamespace(model="test", available=True)
                with patch.object(InvestigationAgent, "run_llm", side_effect=LLMUnavailable("timeout", {"input_tokens": 21})), patch.object(InvestigationAgent, "run_local") as local:
                    record = measure(app, aid, "agentic", llm, cutoff, ids)
                local.assert_not_called()
                self.assertEqual(record["status"], "error")
                self.assertIsNone(record["output"])
                self.assertEqual(record["usage"]["input_tokens"], 21)
                db.session.remove()
                db.engine.dispose()


if __name__ == "__main__":
    unittest.main(verbosity=2)
