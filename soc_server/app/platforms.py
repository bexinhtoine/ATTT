"""Platform-scoped, read-only results. Operational snapshots never stand in for benchmarks."""
import csv
import io
import json
import math
import os
import tempfile
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect,
                   render_template, request, session, url_for)

from .auth import audit, role_required
from .models import (Agent, Alert, DetectionRule, Incident, IpReputation,
                     KnowledgeArticle, LogEvent, WorkJob, utcnow)

bp = Blueprint("platforms", __name__)
PLATFORMS = {"soc": "Agentic SOC", "elastic": "Elastic Security", "wazuh": "Wazuh", "all": "So sánh cả 3"}
# Only operational features belong here. Accounts/settings/audit manage this web app.
FEATURES = {
    "dashboard": ("Dashboard", "main.dashboard", []),
    "alerts": ("Cảnh báo an ninh", "main.alerts", [("id", "ID"), ("timestamp", "Thời gian"), ("title", "Tiêu đề"), ("severity", "Mức độ"), ("status", "Trạng thái"), ("host", "Máy"), ("rule", "Luật"), ("src_ip", "IP nguồn")]),
    "logs": ("Nhật ký log", "main.logs", [("id", "ID"), ("timestamp", "Thời gian"), ("host", "Máy"), ("source", "Nguồn log"), ("action", "Hành vi"), ("severity", "Mức độ"), ("message", "Nội dung")]),
    "agents": ("Máy trạm", "main.agents", [("id", "ID"), ("host", "Máy"), ("ip", "IP"), ("status", "Trạng thái"), ("os", "Hệ điều hành"), ("timestamp", "Lần cuối")]),
    "rules": ("Luật phát hiện", "main.rules", [("id", "Mã luật"), ("title", "Tên luật"), ("type", "Loại"), ("severity", "Mức độ"), ("enabled", "Bật")]),
    "incidents": ("Hồ sơ sự cố", "incidents.index", [("id", "ID"), ("title", "Tiêu đề"), ("status", "Trạng thái"), ("severity", "Mức độ"), ("timestamp", "Cập nhật"), ("summary", "Kết quả điều tra")]),
    "kb": ("Cơ sở tri thức", "main.kb", [("id", "ID"), ("title", "Tiêu đề"), ("category", "Danh mục"), ("source", "Nguồn"), ("summary", "Tóm tắt")]),
    "reports": ("Báo cáo & thống kê", "main.reports", []),
    "ip_reputation": ("Uy tín IP", "main.ip_reputation", [("ip", "IP"), ("verdict", "Kết luận"), ("source", "Nguồn"), ("note", "Ghi chú")]),
    "operations": ("Vận hành hệ thống", "main.operations", [("id", "ID"), ("kind", "Tác vụ"), ("status", "Trạng thái"), ("timestamp", "Thời gian"), ("error", "Lỗi")]),
}
STATUS_LABELS = {"available": "Có dữ liệu", "partial": "Dữ liệu một phần", "not_integrated": "Chưa tích hợp", "not_measured": "Chưa đo", "not_applicable": "Không áp dụng", "error": "Không đọc được dữ liệu"}
SCHEMA = "soc-platform-results-v1"
MAX_BYTES = 16 * 1024 * 1024


def selected_platform():
    value = request.args.get("platform", session.get("result_platform", "soc"))
    if value not in PLATFORMS:
        abort(400, description="Nền tảng không hợp lệ")
    if g.get("user") and "platform" in request.args:
        session["result_platform"] = value
    return value


def results_dir():
    return Path(current_app.config.get("PLATFORM_RESULTS_DIR") or Path(current_app.instance_path) / "platform_results")


def validate_snapshot(data, expected_platform=None):
    """Small explicit interchange format; absent capabilities stay absent, never become zero."""
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError("Sai schema; cần soc-platform-results-v1")
    if data.get("platform") not in ("elastic", "wazuh") or (expected_platform and data["platform"] != expected_platform):
        raise ValueError("Nền tảng của tệp không khớp")
    for key in ("collected_at", "source", "scope"):
        if not isinstance(data.get(key), str) or not data[key].strip() or len(data[key]) > 1000:
            raise ValueError("Thiếu hoặc sai trường " + key)
    try:
        moment = datetime.fromisoformat(data["collected_at"].replace("Z", "+00:00"))
        if moment.tzinfo is None:
            raise ValueError()
    except ValueError:
        raise ValueError("collected_at cần là thời gian ISO-8601 có múi giờ") from None
    features = data.get("features")
    if not isinstance(features, dict) or not features or set(features) - set(FEATURES):
        raise ValueError("features phải chứa các chức năng hợp lệ")
    for feature, result in features.items():
        if not isinstance(result, dict) or result.get("status") not in set(STATUS_LABELS) - {"error"}:
            raise ValueError("Trạng thái không hợp lệ: " + feature)
        records, summary = result.get("records", []), result.get("summary", {})
        if not isinstance(records, list) or len(records) > 50000 or any(not isinstance(row, dict) for row in records):
            raise ValueError("records phải là danh sách đối tượng, tối đa 50000 dòng")
        if not isinstance(summary, dict) or len(summary) > 50:
            raise ValueError("summary phải là đối tượng, tối đa 50 chỉ số")
        if any(not isinstance(k, str) or len(k) > 100 or not isinstance(v, (str, int, float, bool, type(None))) or (isinstance(v, float) and not math.isfinite(v)) for k, v in summary.items()):
            raise ValueError("summary chỉ nhận giá trị đơn, hữu hạn")
        if not isinstance(result.get("reason", ""), str):
            raise ValueError("reason phải là chuỗi")
        if result["status"] not in ("available", "partial") and (records or summary):
            raise ValueError("Chức năng chưa đo/không áp dụng không được mang kết quả")
        total = result.get("total", len(records))
        if type(total) is not int or total < len(records):
            raise ValueError("total phải là số nguyên >= số dòng")
    return data


def save_snapshot(data):
    validate_snapshot(data)
    directory = results_dir()
    directory.mkdir(parents=True, exist_ok=True)
    # Atomic replacement: readers see either the previous complete export or the new one.
    fd, name = tempfile.mkstemp(prefix="import-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, allow_nan=False)
        os.replace(name, directory / (data["platform"] + ".json"))
    finally:
        if os.path.exists(name):
            os.unlink(name)


def external_result(platform, feature):
    empty = {"status": "not_integrated", "reason": "Chưa nhập kết quả cho chức năng này từ " + PLATFORMS[platform], "records": [], "summary": {}, "total": None}
    path = results_dir() / (platform + ".json")
    try:
        if not path.exists():
            return empty
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("Tệp quá lớn")
        data = validate_snapshot(json.loads(path.read_text(encoding="utf-8")), platform)
        result = dict(data["features"].get(feature, empty))
        result.setdefault("records", [])
        result.setdefault("summary", {})
        result.setdefault("reason", "")
        result.setdefault("total", len(result["records"]) if result["status"] in ("available", "partial") else None)
        result.update({key: data[key] for key in ("source", "scope", "collected_at")})
        return result
    except (OSError, ValueError, TypeError, RecursionError):
        return {**empty, "status": "error", "reason": "Tệp kết quả không hợp lệ hoặc đang không đọc được; hãy nhập lại."}


def _value(value):
    return value.isoformat() + "Z" if isinstance(value, datetime) else value


def soc_result(feature):
    if feature in ("dashboard", "reports"):
        return {"status": "available", "records": [], "total": None, "summary": {
            "Log đã lưu": LogEvent.query.count(), "Cảnh báo": Alert.query.count(),
            "Máy trạm": Agent.query.count(), "Luật": DetectionRule.query.count(),
            "Hồ sơ sự cố": Incident.query.count()}, "source": "CSDL Agentic SOC", "scope": "Toàn bộ dữ liệu đang lưu; thời điểm hiện tại", "collected_at": utcnow().isoformat() + "Z"}
    specs = {
        "alerts": (Alert, "created_at", {"timestamp": "created_at", "rule": "rule_id"}),
        "logs": (LogEvent, "event_time", {"timestamp": "event_time"}),
        "agents": (Agent, "last_seen", {"host": "hostname", "ip": "ip_address", "os": "os_type", "timestamp": "last_seen"}),
        "rules": (DetectionRule, "id", {"id": "code", "title": "name", "type": "rule_type"}),
        "incidents": (Incident, "updated_at", {"timestamp": "updated_at"}),
        "kb": (KnowledgeArticle, "updated_at", {}),
        "ip_reputation": (IpReputation, "created_at", {}),
        "operations": (WorkJob, "created_at", {"timestamp": "created_at"}),
    }
    model, order, aliases = specs[feature]
    query = model.query
    total = query.count()
    records = [{key: _value(getattr(obj, aliases.get(key, key), None)) for key, _ in FEATURES[feature][2]}
               for obj in query.order_by(getattr(model, order).desc()).limit(500).all()]
    return {"status": "available", "records": records, "total": total, "summary": {"Tổng bản ghi": total},
            "source": "CSDL Agentic SOC", "scope": "Toàn bộ dữ liệu đang lưu; hiển thị tối đa 500 bản ghi mới nhất", "collected_at": utcnow().isoformat() + "Z"}


def feature_result(platform, feature):
    return soc_result(feature) if platform == "soc" else external_result(platform, feature)


def _filtered(records):
    q = request.args.get("q", "").strip().casefold()
    severity = request.args.get("severity", "")
    statuses = request.args.get("status", "").split(",") if request.args.get("status") else []
    if not statuses and request.args.get("open") == "1":
        statuses = ["new", "triaged", "investigating", "open", "acknowledged"]
    host = request.args.get("host", "")
    return [row for row in records if (not q or q in json.dumps(row, ensure_ascii=False).casefold())
            and (not severity or str(row.get("severity")) in severity.split(","))
            and (not host or row.get("host") == host)
            and (not statuses or row.get("status") in statuses)]


def render_results(feature, export=False):
    selected = selected_platform()
    keys = ["soc", "elastic", "wazuh"] if selected == "all" else [selected]
    results = {}
    for key in keys:
        result = feature_result(key, feature)
        filtered = _filtered(result["records"])
        result["matched"] = len(filtered)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        result["page"] = page
        result["pages"] = max(1, (len(filtered) + 49) // 50)
        result["rows"] = filtered if export else filtered[(page - 1) * 50:page * 50]
        results[key] = result
    if export:
        buf = io.StringIO()
        buf.write("\ufeff")
        writer = csv.writer(buf)
        fields = [key for key, _ in FEATURES[feature][2]]
        writer.writerow(["platform", "source", "scope", "collected_at"] + fields)
        def safe(value):
            value = "" if value is None else str(value)
            return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value
        for platform, result in results.items():
            for row in result["rows"]:
                writer.writerow([safe(platform), safe(result.get("source")), safe(result.get("scope")), safe(result.get("collected_at"))] + [safe(row.get(f)) for f in fields])
        return Response(buf.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="%s_%s.csv"' % (feature, selected)})
    from .comparison_explanations import feature_guide, rule_definitions, display_value
    for result in results.values():
        result['display_summary'] = {
            label.replace('Cảnh báo native', 'Cảnh báo do nền tảng tạo').replace('Host trong log', 'Máy xuất hiện trong log')
                 .replace('Trạng thái native', 'Trạng thái dịch vụ'): value
            for label, value in result['summary'].items()}
    definitions = rule_definitions(DetectionRule.query.filter(DetectionRule.code.in_(
        ["R%02d" % n for n in range(1, 22)])).all()) if feature == 'rules' else {}
    return render_template("platform_results.html", feature=feature, feature_spec=FEATURES[feature], results=results,
                           comparison_guide=feature_guide(feature, results), rule_definitions=definitions,
                           result_value=display_value)


def platform_view(feature, listing=False, export=False):
    """Placed inside the existing login/role decorators so RBAC remains authoritative."""
    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if selected_platform() == "soc":
                return view(*args, **kwargs)
            if request.method not in ("GET", "HEAD"):
                if request.path.startswith("/api/"):
                    return {"error": "Chọn Agentic SOC trước khi thay đổi dữ liệu nội bộ."}, 409
                return render_template("error.html", code=409, message="Kết quả nền tảng ngoài và chế độ so sánh chỉ đọc. Chọn Agentic SOC để thao tác dữ liệu nội bộ."), 409
            if listing or export:
                return render_results(feature, export)
            return redirect(url_for(FEATURES[feature][1]))
        wrapped.platform_feature = feature
        return wrapped
    return decorate


def register_platforms(app):
    app.register_blueprint(bp)

    @app.context_processor
    def platform_context():
        endpoint = request.endpoint or ""
        view = app.view_functions.get(endpoint)
        feature = getattr(view, "platform_feature", None)
        selected = selected_platform() if g.get("user") else "soc"
        # Retain only filters supported by both native and external list views.
        args = {key: request.args.getlist(key) for key in ("q", "severity") if key in request.args}
        return {"platform_choices": PLATFORMS, "selected_platform": selected, "platform_feature": feature,
                "platform_features": FEATURES, "platform_status_labels": STATUS_LABELS,
                "platform_switch_endpoint": FEATURES[feature][1] if feature else ("main.comparison" if endpoint == "main.comparison" else "main.dashboard"),
                "platform_switch_args": args if feature and endpoint == FEATURES[feature][1] else {}}


@bp.post("/platform-results/import")
@role_required("admin")
def import_results():
    upload = request.files.get("results")
    try:
        if upload is None:
            raise ValueError("Chưa chọn tệp JSON")
        content = upload.read(MAX_BYTES + 1)
        if len(content) > MAX_BYTES:
            raise ValueError("Tệp vượt quá 16 MB")
        data = validate_snapshot(json.loads(content.decode("utf-8-sig")))
        save_snapshot(data)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        flash("Không nhập được kết quả: " + str(exc), "danger")
        return redirect(url_for("platforms.import_page"))
    audit("platform_results_import", data["platform"], "source=%s; collected_at=%s" % (data["source"], data["collected_at"]))
    session["result_platform"] = data["platform"]
    flash("Đã nhập kết quả " + PLATFORMS[data["platform"]], "success")
    return redirect(url_for(FEATURES[next(iter(data["features"]))][1]))


@bp.get("/platform-results/import")
@role_required("admin")
def import_page():
    return render_template("platform_import.html")
