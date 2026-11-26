"""Run the supported verification suite and keep logs plus a machine-readable report."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="Include real localhost HTTP/restart test")
    args = parser.parse_args()
    output = ROOT / "docs" / "verification"
    output.mkdir(parents=True, exist_ok=True)
    scripts = ["test_parsers.py", "test_collectors.py", "test_e2e.py", "test_reliability.py",
               "test_upgrade_compatibility.py", "test_threeway.py", "test_incidents.py", "test_ai_evaluation.py"]
    if args.live:
        scripts.append("test_live_transport.py")
    report = {"started_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
              "platform": platform.platform(), "live_included": args.live, "checks": [], "source_sha256": {}}
    for folder in ("soc_agent", "soc_server", "benchmarks/three_way"):
        for path in sorted((ROOT / folder).rglob("*")):
            if "vendor" not in path.parts and "artifacts" not in path.parts and path.suffix in (".py", ".html", ".js", ".css"):
                report["source_sha256"][path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for script in scripts:
        started = time.monotonic()
        logfile = output / (Path(script).stem + ".log")
        with logfile.open("w", encoding="utf-8") as stream:
            try:
                result = subprocess.run([sys.executable, str(ROOT / "tools" / script)], cwd=ROOT,
                                        stdout=stream, stderr=subprocess.STDOUT, timeout=180,
                                        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
                code = result.returncode
            except subprocess.TimeoutExpired:
                stream.write("\nVerification timed out after 180 seconds.\n")
                code = 124
        entry = {"script": script, "exit_code": code, "passed": code == 0,
                 "seconds": round(time.monotonic() - started, 3), "log": logfile.relative_to(ROOT).as_posix()}
        report["checks"].append(entry)
        print("%s %s (%.2fs)" % ("PASS" if code == 0 else "FAIL", script, entry["seconds"]), flush=True)
    report["passed"] = all(item["passed"] for item in report["checks"])
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    target = output / "latest.json"
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Report:", target)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
