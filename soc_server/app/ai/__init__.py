# -*- coding: utf-8 -*-
"""
Module Agentic AI của Web SOC.

    llm.py          - Bọc Claude API (Anthropic SDK): gọi một lượt có JSON schema, vòng lặp tool-use
    tools.py        - Các "công cụ" tác tử được phép gọi (truy vấn log, tra IP, tri thức, MITRE ...)
    agents.py       - Bốn tác tử: Enrichment, Triage, Investigation, Knowledge
    orchestrator.py - Điều phối chuỗi tác tử cho một cảnh báo, ghi nhật ký ai_runs

Mọi tác tử đều có hai đường chạy: LLM (khi có ANTHROPIC_API_KEY) và LOCAL (suy luận
heuristic/quy tắc) để hệ thống luôn hoạt động kể cả khi không có mô hình ngôn ngữ.
"""
from .orchestrator import SOCOrchestrator  # noqa: F401
