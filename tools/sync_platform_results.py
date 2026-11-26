"""Read operational log/alert indexes into the platform viewer; never install or run rules."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "soc_server"))
from benchmarks.three_way.adapters import JsonHTTP, PrerequisiteError
from app.platforms import SCHEMA, validate_snapshot


def path_value(data, path, default=None):
    # Elasticsearch may return dotted field names or nested _source objects.
    if path in data:
        return data[path]
    value = data
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def normalize_hit(platform, feature, hit):
    source = hit.get("_source", {})
    get = lambda path, default=None: path_value(source, path, default)
    row = {"id": hit.get("_id"), "timestamp": get("@timestamp", get("timestamp")),
           "host": get("host.name") if platform == "elastic" else get("agent.name"),
           "src_ip": get("source.ip") if platform == "elastic" else get("data.srcip")}
    if platform == "elastic":
        row.update({"severity": get("kibana.alert.severity", get("event.severity")),
                    "source": get("event.dataset", get("event.module")),
                    "action": get("event.action"), "message": get("message")})
        if feature == "alerts":
            row.update({"title": get("kibana.alert.rule.name", get("kibana.alert.reason")),
                        "status": get("kibana.alert.workflow_status"), "rule": get("kibana.alert.rule.rule_id")})
    else:
        # Keep the native numeric rule level; do not invent cross-vendor severity equivalence.
        row.update({"severity": get("rule.level"), "source": get("decoder.name", get("location")),
                    "action": get("data.action"), "message": get("full_log"),
                    "title": get("rule.description"), "rule": get("rule.id"), "status": None})
    row["native_index"] = hit.get("_index")
    return row


def collect(platform, client, since, until, indexes, limit=500):
    features = {}
    for feature, index in indexes.items():
        if not re.fullmatch(r"[a-zA-Z0-9_.*,-]+", index):
            raise ValueError("Tên index không hợp lệ")
        time_field = "timestamp" if platform == "wazuh" else "@timestamp"
        try:
            response = client.request("POST", "/" + index + "/_search", {
                "size": limit, "track_total_hits": True,
                "sort": [{time_field: {"order": "desc", "unmapped_type": "date"}}],
                "query": {"range": {time_field: {"gte": since, "lte": until}}}})
            if response.get("timed_out") or response.get("_shards", {}).get("failed", 0):
                raise RuntimeError("Truy vấn timeout hoặc có shard thất bại")
            hits = response["hits"]
            total = hits["total"]
            if isinstance(total, dict):
                if total.get("relation") != "eq":
                    raise RuntimeError("Chưa xác định được tổng kết quả")
                total = total["value"]
            rows = [normalize_hit(platform, feature, hit) for hit in hits["hits"]]
            features[feature] = {"status": "partial" if total > len(rows) else "available", "total": total,
                                 "records": rows, "summary": {"Tổng bản ghi": total},
                                 "reason": "Chỉ lấy các bản ghi mới nhất, chưa xuất toàn bộ index." if total > len(rows) else ""}
        except (RuntimeError, PrerequisiteError, KeyError, TypeError, ValueError) as exc:
            features[feature] = {"status": "not_measured", "reason": str(exc), "records": []}
    summary = {"Log trong khoảng đo" if key == "logs" else "Cảnh báo trong khoảng đo": value["total"]
               for key, value in features.items() if "total" in value}
    for feature in ("dashboard", "reports"):
        features[feature] = {"status": "partial" if summary else "not_measured", "summary": summary,
                             "records": [], "reason": "Chỉ thống kê log/cảnh báo đã truy vấn; chưa thu thập agent, luật, điều tra hoặc tài nguyên."}
    return validate_snapshot({"schema": SCHEMA, "platform": platform,
                              "collected_at": datetime.now(timezone.utc).isoformat(),
                              "source": "%s index API (%s)" % (platform, urlsplit(client.url).hostname),
                              "scope": "%s → %s; indexes=%s; tối đa %s dòng/index; mức độ giữ nguyên từ nguồn" % (since, until, ", ".join(indexes.values()), limit),
                              "features": features})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("elastic", "wazuh"), required=True)
    parser.add_argument("--since", default="now-24h")
    parser.add_argument("--until", default="now")
    parser.add_argument("--logs-index", help="Elastic: logs-*; Wazuh: wazuh-archives-* (cần bật lưu archive)")
    parser.add_argument("--alerts-index")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--output", type=Path, help="Tệp JSON để nhập từ giao diện admin")
    args = parser.parse_args()
    if not 1 <= args.limit <= 10000:
        parser.error("limit phải trong 1..10000")
    try:
        client = JsonHTTP("ELASTIC" if args.platform == "elastic" else "WAZUH_INDEXER")
        indexes = {"logs": args.logs_index or ("logs-*" if args.platform == "elastic" else "wazuh-archives-*"),
                   "alerts": args.alerts_index or (".alerts-security.alerts-default" if args.platform == "elastic" else "wazuh-alerts-*")}
        data = collect(args.platform, client, args.since, args.until, indexes, args.limit)
        successful = any(data["features"][key]["status"] in ("available", "partial") for key in indexes)
        if not successful:
            for key in indexes:
                print(key + ": " + data["features"][key]["reason"], file=sys.stderr)
            return 1
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            print("Đã xuất: " + str(args.output))
        else:
            # Same default directory as the Flask app; no database creation or seeding.
            from flask import Flask
            from app.platforms import save_snapshot
            app = Flask("app", root_path=str(ROOT / "soc_server" / "app"), instance_path=str(ROOT / "soc_server" / "instance"))
            app.config["PLATFORM_RESULTS_DIR"] = os.environ.get("SOC_PLATFORM_RESULTS_DIR")
            with app.app_context():
                save_snapshot(data)
            print("Đã cập nhật kết quả " + args.platform + "; tải lại trang Web SOC.")
        return 0
    except (RuntimeError, PrerequisiteError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
