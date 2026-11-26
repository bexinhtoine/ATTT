"""OpenAI Responses adapter with the same interface as the Claude client."""
import json
import time

try:
    import openai
except ImportError:
    openai = None

from .llm import LLMUnavailable
from .validation import validate_json


class OpenAILLMClient:
    provider = "openai"

    def __init__(self, api_key=None, model="gpt-4.1-mini", max_tool_iterations=8,
                 max_tool_calls=24, tool_budget_seconds=240):
        self.model = model
        self.max_tool_iterations = max_tool_iterations
        self.max_tool_calls = max_tool_calls
        self.tool_budget_seconds = tool_budget_seconds
        self._client = openai.OpenAI(api_key=api_key, timeout=120, max_retries=0) if openai and api_key else None
        self.unavailable_reason = None if self._client else "Chưa cài openai hoặc chưa cấu hình OPENAI_API_KEY"

    @property
    def available(self):
        return self._client is not None

    def _run(self, system, user_content, tools, executor, schema, max_tokens):
        if not self.available:
            raise LLMUnavailable(self.unavailable_reason)
        messages = [{"role": "user", "content": user_content}]
        definitions = [{"type": "function", "name": t["name"], "description": t["description"],
                        "parameters": t["input_schema"], "strict": True} for t in tools]
        usage = {"input_tokens": 0, "output_tokens": 0, "cached_input_tokens": 0}
        calls = []
        deadline = time.monotonic() + self.tool_budget_seconds
        for turn in range(self.max_tool_iterations + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LLMUnavailable("Hết ngân sách thời gian gọi công cụ", usage, calls)
            kwargs = dict(model=self.model, instructions=system, input=messages, store=False,
                          max_output_tokens=max_tokens, timeout=min(120, remaining))
            if definitions:
                kwargs["tools"] = definitions
            if schema:
                kwargs["text"] = {"format": {"type": "json_schema", "name": "soc_result", "schema": schema, "strict": True}}
            try:
                response = self._client.responses.create(**kwargs)
            except openai.APIError as exc:
                # Do not persist exception strings that might contain HTTP request details/secrets.
                raise LLMUnavailable("OpenAI API: %s (HTTP %s)" % (type(exc).__name__, getattr(exc, "status_code", "unknown")), usage, calls) from exc
            u = getattr(response, "usage", None)
            for key in ("input_tokens", "output_tokens"):
                usage[key] += getattr(u, key, 0) or 0
            usage["cached_input_tokens"] += getattr(getattr(u, "input_tokens_details", None), "cached_tokens", 0) or 0
            if response.status != "completed":
                raise LLMUnavailable("OpenAI trả về trạng thái %s" % response.status, usage, calls)
            requested = [item for item in response.output if item.type == "function_call"]
            if not requested:
                try:
                    result = json.loads(response.output_text) if schema else response.output_text
                    if schema:
                        validate_json(result, schema)
                    return result, calls, usage
                except ValueError as exc:
                    raise LLMUnavailable("Kết quả OpenAI không đúng schema hoặc bị từ chối", usage, calls) from exc
            if turn >= self.max_tool_iterations or len(calls) + len(requested) > self.max_tool_calls:
                raise LLMUnavailable("Vượt giới hạn gọi công cụ", usage, calls)
            messages.extend(item.model_dump(exclude_none=True) for item in response.output)
            for item in requested:
                if time.monotonic() >= deadline:
                    raise LLMUnavailable("Hết ngân sách thời gian gọi công cụ", usage, calls)
                failed = False
                try:
                    args = json.loads(item.arguments)
                    result = executor(item.name, args)
                except Exception as exc:
                    args, result, failed = {}, "Lỗi công cụ: %s" % type(exc).__name__, True
                rendered = json.dumps(result, ensure_ascii=False, default=str)
                calls.append({"tool": item.name, "input": args, "error": failed, "output_preview": rendered[:600]})
                messages.append({"type": "function_call_output", "call_id": item.call_id, "output": rendered[:20000]})
        raise LLMUnavailable("Vượt giới hạn vòng gọi công cụ", usage, calls)

    def complete_json(self, system, user_content, schema, max_tokens=8000):
        result, _, usage = self._run(system, user_content, [], None, schema, max_tokens)
        return result, usage

    def run_with_tools(self, system, user_content, tools, executor, schema=None, max_tokens=8000):
        return self._run(system, user_content, tools, executor, schema, max_tokens)
