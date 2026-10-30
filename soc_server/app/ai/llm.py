# -*- coding: utf-8 -*-
"""
llm.py - Lớp bọc Claude API (Anthropic Python SDK).

* Không có SDK hoặc không có khóa API -> `available = False`, orchestrator dùng đường LOCAL.
* complete_json()   : một lượt gọi, ép kết quả theo JSON schema (structured outputs, output_config.format).
* run_with_tools()  : vòng lặp tác tử (agentic loop) - mô hình gọi công cụ, server thực thi, trả kết quả,
                      lặp đến khi mô hình kết thúc lượt (stop_reason = end_turn).
* Mặc định dùng mô hình claude-opus-5-5 với adaptive thinking (mặc định của mô hình),
  điều chỉnh độ sâu suy luận bằng output_config.effort, bật fallback phía máy chủ khi bị từ chối.
"""
import json
import logging

from flask import current_app

try:
    import anthropic
except ImportError:  # SDK là tùy chọn
    anthropic = None

log = logging.getLogger(__name__)


class LLMUnavailable(Exception):
    """Ném ra khi không thể dùng LLM (không khóa, lỗi API, từ chối...) -> chuyển sang đường LOCAL."""


class LLMClient:
    def __init__(self, api_key=None, model="claude-opus-5-5", effort="medium", max_tool_iterations=8):
        self.model = model or "claude-opus-5-5"
        self.effort = effort or "medium"
        self.max_tool_iterations = max_tool_iterations
        # timeout 180 giây để luồng AI nền không treo quá lâu khi mạng lỗi; SDK tự thử lại 2 lần (429/5xx)
        self._client = (anthropic.Anthropic(api_key=api_key, timeout=180.0, max_retries=2)
                        if (anthropic and api_key) else None)
        self.unavailable_reason = None
        if anthropic is None:
            self.unavailable_reason = "Chưa cài gói anthropic"
        elif not api_key:
            self.unavailable_reason = "Chưa cấu hình ANTHROPIC_API_KEY"

    @classmethod
    def from_app(cls, app=None):
        cfg = (app or current_app).config
        return cls(api_key=cfg.get("ANTHROPIC_API_KEY"), model=cfg.get("AI_MODEL"),
                   effort=cfg.get("AI_EFFORT", "medium"),
                   max_tool_iterations=cfg.get("AI_MAX_TOOL_ITERATIONS", 8))

    @property
    def available(self):
        return self._client is not None

    # ------------------------------------------------------------------ core
    def _create(self, **kwargs):
        """Gọi Messages API, ưu tiên bật fallback phía máy chủ (beta); nếu máy chủ không chấp nhận
        tham số beta thì gọi lại dạng thường."""
        try:
            return self._client.beta.messages.create(
                betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
        except anthropic.BadRequestError as exc:
            msg = str(exc).lower()
            if "fallback" in msg or "beta" in msg:
                return self._client.messages.create(**kwargs)
            raise

    @staticmethod
    def _usage(resp):
        u = getattr(resp, "usage", None)
        return {"input_tokens": getattr(u, "input_tokens", 0) or 0,
                "output_tokens": getattr(u, "output_tokens", 0) or 0}

    def complete_json(self, system, user_content, schema, max_tokens=8000):
        """Một lượt gọi -> (dict theo schema, usage)."""
        if not self.available:
            raise LLMUnavailable(self.unavailable_reason)
        try:
            resp = self._create(
                model=self.model, max_tokens=max_tokens, system=system,
                messages=[{"role": "user", "content": user_content}],
                output_config={"effort": self.effort,
                               "format": {"type": "json_schema", "schema": schema}})
        except anthropic.APIError as exc:
            raise LLMUnavailable("Lỗi Claude API: %s" % exc) from exc
        if resp.stop_reason == "refusal":
            raise LLMUnavailable("Mô hình từ chối yêu cầu (%s)" % getattr(resp, "stop_details", ""))
        text = "".join(b.text for b in resp.content if b.type == "text")
        try:
            return json.loads(text), self._usage(resp)
        except ValueError as exc:
            raise LLMUnavailable("Kết quả không phải JSON hợp lệ") from exc

    def run_with_tools(self, system, user_content, tools, executor, schema=None, max_tokens=8000):
        """Vòng lặp tác tử. executor(name, input_dict) -> str|dict. Trả về (kết quả, nhật ký tool, usage)."""
        if not self.available:
            raise LLMUnavailable(self.unavailable_reason)
        messages = [{"role": "user", "content": user_content}]
        tool_defs = [{**t, "strict": True} for t in tools]
        output_config = {"effort": self.effort}
        if schema:
            output_config["format"] = {"type": "json_schema", "schema": schema}
        tool_log, usage = [], {"input_tokens": 0, "output_tokens": 0}
        for _ in range(self.max_tool_iterations + 1):
            try:
                resp = self._create(model=self.model, max_tokens=max_tokens, system=system,
                                    messages=messages, tools=tool_defs, output_config=output_config)
            except anthropic.APIError as exc:
                raise LLMUnavailable("Lỗi Claude API: %s" % exc) from exc
            u = self._usage(resp)
            usage["input_tokens"] += u["input_tokens"]
            usage["output_tokens"] += u["output_tokens"]
            if resp.stop_reason == "refusal":
                raise LLMUnavailable("Mô hình từ chối yêu cầu")
            if resp.stop_reason == "pause_turn":
                messages.append({"role": "assistant", "content": resp.content})
                continue
            tool_uses = [b for b in resp.content if b.type == "tool_use"]
            if resp.stop_reason != "tool_use" or not tool_uses:
                text = "".join(b.text for b in resp.content if b.type == "text")
                if schema:
                    try:
                        return json.loads(text), tool_log, usage
                    except ValueError as exc:
                        raise LLMUnavailable("Kết quả không phải JSON hợp lệ") from exc
                return text, tool_log, usage
            messages.append({"role": "assistant", "content": resp.content})
            results = []
            for tu in tool_uses:          # thực thi mọi tool_use rồi trả về trong MỘT message
                is_error = False
                try:
                    out = executor(tu.name, tu.input or {})
                except Exception as exc:  # lỗi công cụ được báo lại cho mô hình, không dừng vòng lặp
                    out, is_error = "Lỗi khi thực thi công cụ: %s" % exc, True
                out_str = out if isinstance(out, str) else json.dumps(out, ensure_ascii=False, default=str)
                tool_log.append({"tool": tu.name, "input": tu.input, "error": is_error,
                                 "output_preview": out_str[:600]})
                block = {"type": "tool_result", "tool_use_id": tu.id, "content": out_str[:20000]}
                if is_error:
                    block["is_error"] = True
                results.append(block)
            messages.append({"role": "user", "content": results})
        raise LLMUnavailable("Vượt quá %d vòng gọi công cụ" % self.max_tool_iterations)
