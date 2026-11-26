# -*- coding: utf-8 -*-
"""Cấu hình Web SOC. Có thể ghi đè bằng biến môi trường (tiền tố SOC_)."""
import os
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)


DEFAULT_SECRET_KEY = "doi-khoa-bi-mat-nay-khi-trien-khai-that"
DEFAULT_ENROLLMENT_TOKEN = "soc-enroll-2026"


class Config:
    # Bảo mật phiên làm việc
    SECRET_KEY = os.environ.get("SOC_SECRET_KEY", DEFAULT_SECRET_KEY)
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get("SOC_HTTPS", "0") == "1"   # bật khi chạy sau HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024          # tối đa 16 MB mỗi lô log gửi lên
    CSRF_ENABLED = True                            # chống CSRF cho mọi form/POST của giao diện web

    # Cơ sở dữ liệu (mặc định SQLite trong thư mục instance/)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "SOC_DATABASE_URI",
        "sqlite:///" + os.path.join(INSTANCE_DIR, "soc.db").replace("\\", "/"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {"check_same_thread": False, "timeout": 30},
        "pool_pre_ping": True,
    }

    # Thu thập log từ agent
    ENROLLMENT_TOKEN = os.environ.get("SOC_ENROLLMENT_TOKEN", DEFAULT_ENROLLMENT_TOKEN)
    AGENT_OFFLINE_AFTER = int(os.environ.get("SOC_AGENT_OFFLINE_AFTER", "180"))   # giây
    MAX_EVENTS_PER_BATCH = 2000
    RETENTION_DAYS = int(os.environ.get("SOC_RETENTION_DAYS", "30"))
    # Cấu hình tập trung gửi xuống agent (agent chỉ áp dụng khi config.json có follow_server_config = true)
    AGENT_INTERVAL_SECONDS = int(os.environ.get("SOC_AGENT_INTERVAL", "10"))
    AGENT_HEARTBEAT_SECONDS = int(os.environ.get("SOC_AGENT_HEARTBEAT", "60"))
    AGENT_BATCH_SIZE = int(os.environ.get("SOC_AGENT_BATCH_SIZE", "500"))

    # Giao diện
    PAGE_SIZE = 50
    TIMEZONE = os.environ.get("SOC_TIMEZONE", "Asia/Ho_Chi_Minh")
    LOGIN_MAX_FAILURES = 5
    LOGIN_LOCK_SECONDS = 300

    # Module Agentic AI (Claude API). Không có khóa -> tự chuyển sang chế độ suy luận cục bộ.
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
    AI_PROVIDER = os.environ.get("SOC_AI_PROVIDER", "anthropic")
    AI_MODEL = os.environ.get("SOC_AI_MODEL", "gpt-4.1-mini" if AI_PROVIDER == "openai" else "claude-opus-5-5")
    AI_AUTO_TRIAGE = os.environ.get("SOC_AI_AUTO_TRIAGE", "1") == "1"
    AI_MAX_TOOL_ITERATIONS = 8
    AI_MAX_TOOL_CALLS = 24
    AI_TOOL_BUDGET_SECONDS = 240
    AI_EFFORT = os.environ.get("SOC_AI_EFFORT", "medium")
    WORK_LEASE_SECONDS = 120
    WORK_MAX_ATTEMPTS = 3
    DETECTION_CANDIDATE_LIMIT = 5000
    COMPARISON_REPORT_PATH = os.environ.get("SOC_COMPARISON_REPORT_PATH")
    PLATFORM_RESULTS_DIR = os.environ.get("SOC_PLATFORM_RESULTS_DIR")
