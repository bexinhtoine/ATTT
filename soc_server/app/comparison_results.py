"""Present recorded comparisons without inventing absent totals."""
import re


def comparison_rows(report, events=None):
    events = events or {}
    rows = []
    for original in report.get("rules", []):
        row = dict(original)
        ref = re.search(r"#(\d+).*?event\s*#(\d+)", str(row.get("soc", "")), re.I)
        alert_id, event_id = (int(ref[1]), int(ref[2])) if ref else (None, None)
        event = events.get(event_id)
        cells = {}
        for key in ("soc", "elastic", "wazuh"):
            text = str(row.get(key, ""))
            match = re.match(r"(\d+)\s+cảnh báo", text)
            count = int(match[1]) if match else None
            present = count > 0 if count is not None else (True if key == "soc" and ref else None)
            builtin = re.search(r"luật có sẵn\s*(\d+)", text)
            cells[key] = dict(present=present, count=count, builtin=builtin[1] if builtin else None,
                              alert_id=alert_id if key == "soc" else None,
                              event_id=event_id if key == "soc" else None)
        elastic, wazuh = cells["elastic"], cells["wazuh"]
        known = [c["present"] for c in cells.values() if c["present"] is not None]
        differs = (True in known and False in known) or (
            elastic["count"] is not None and wazuh["count"] is not None
            and elastic["count"] != wazuh["count"])
        if cells["soc"]["present"] and elastic["present"] and wazuh["present"] is False:
            note = "SOC và Elastic có cảnh báo; Wazuh chưa có cảnh báo tương ứng trong bản xuất này. Cần kiểm tra luật và cách tính thời gian trên Wazuh."
        elif elastic["count"] is not None and wazuh["count"] is not None:
            if elastic["count"] != wazuh["count"]:
                note = (f"Elastic ghi {elastic['count']} cảnh báo, Wazuh ghi {wazuh['count']}. "
                        "Khác số lượng; cần xem cách đếm và gộp trước khi đánh giá bỏ sót hoặc báo nhầm.")
            elif elastic["present"] and cells["soc"]["present"]:
                note = "Cả ba có cảnh báo. Elastic và Wazuh ghi cùng số lượng trong bản xuất."
            else:
                note = "Elastic và Wazuh ghi cùng số lượng; xem trạng thái SOC ở cột bên cạnh."
        else:
            note = "Chưa đủ số liệu để so sánh số cảnh báo giữa hai nền tảng ngoài."
        if wazuh["builtin"]:
            note += f" Wazuh dùng luật có sẵn số {wazuh['builtin']}."
        row.update(cells=cells, alert_id=alert_id, event_id=event_id,
                   evidence_host=event.host if event else None,
                   differs=differs, difference=note)
        rows.append(row)
    return rows


def comparison_summary(rows):
    return {key: {"detected": sum(r["cells"][key]["present"] is True for r in rows),
                  "not_seen": sum(r["cells"][key]["present"] is False for r in rows),
                  "unknown": sum(r["cells"][key]["present"] is None for r in rows)}
            for key in ("soc", "elastic", "wazuh")}
