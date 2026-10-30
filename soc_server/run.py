# -*- coding: utf-8 -*-
"""
run.py - Điểm khởi chạy Web SOC.

    python run.py                 # chạy tại http://0.0.0.0:5000
    python run.py --port 8080     # đổi cổng
    python run.py --init-only     # chỉ khởi tạo CSDL + dữ liệu mẫu rồi thoát

Tài khoản mặc định: admin / Admin@123, analyst / Analyst@123, viewer / Viewer@123
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if hasattr(sys.stdout, "reconfigure"):            # console Windows in được tiếng Việt
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from app import create_app  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Agentic SOC Platform - Web SOC server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.environ.get("SOC_PORT", "5000")))
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--init-only", action="store_true", help="Khởi tạo CSDL rồi thoát")
    args = parser.parse_args()
    app = create_app(start_background=not args.init_only)
    if args.init_only:
        print("Đã khởi tạo cơ sở dữ liệu tại", app.config["SQLALCHEMY_DATABASE_URI"])
        return
    print("Web SOC đang chạy tại http://%s:%d  (AI: %s)" % (
        args.host, args.port, "Claude API" if app.extensions["soc_llm_status"]().available else "chế độ cục bộ"))
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
