/* soc.js - tiện ích giao diện Web SOC */
const SEV_COLORS = { critical: "#dc3545", high: "#fd7e14", medium: "#0dcaf0", low: "#6c757d", info: "#adb5bd" };
const SEV_LABELS = { critical: "Nghiêm trọng", high: "Cao", medium: "Trung bình", low: "Thấp", info: "Thông tin" };
const STATUS_LABELS = { new: "Mới", triaged: "Đã phân loại", investigating: "Đang điều tra", resolved: "Đã xử lý", false_positive: "Dương tính giả" };

function fmtLocal(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleString("vi-VN", { hour12: false });
}

function csrfToken() {
  const m = document.querySelector('meta[name="csrf-token"]');
  return m ? m.content : "";
}

async function postJSON(url, body) {
  const resp = await fetch(url, { method: "POST",
                                   headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
                                   body: JSON.stringify(body || {}) });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || ("HTTP " + resp.status));
  return data;
}

/* Nút chạy tác tử AI trên trang chi tiết cảnh báo */
async function runAI(alertId, stage, btn) {
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Đang chạy...';
  try {
    await postJSON(`/api/v1/alerts/${alertId}/ai/${stage}`);
    window.location.reload();
  } catch (e) {
    alert("Lỗi khi chạy tác tử AI: " + e.message);
    btn.disabled = false;
    btn.innerHTML = original;
  }
}

/* Dashboard: vẽ biểu đồ và tự làm mới */
let charts = {};
function makeChart(id, config) {
  const el = document.getElementById(id);
  if (!el) return;
  if (charts[id]) { charts[id].destroy(); }
  charts[id] = new Chart(el.getContext("2d"), config);
}

function renderDashboard(s) {
  const k = s.kpi;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set("kpi-events-24h", k.events_24h.toLocaleString("vi-VN"));
  set("kpi-events-total", "Tổng: " + k.events_total.toLocaleString("vi-VN"));
  set("kpi-alerts-open", k.alerts_open);
  set("kpi-alerts-critical", k.alerts_critical_open + " mức cao/nghiêm trọng");
  set("kpi-agents", k.agents_online + "/" + k.agents_total);
  set("kpi-ai", k.ai_triaged);
  set("kpi-ai-runs", k.ai_runs + " lượt tác tử");
  set("dash-updated", "Cập nhật: " + fmtLocal(s.generated_at));

  makeChart("chartEventsHour", { type: "line",
    data: { labels: s.events_per_hour.map(x => x.label),
            datasets: [{ label: "Sự kiện/giờ", data: s.events_per_hour.map(x => x.count), borderColor: "#0d6efd",
                         backgroundColor: "rgba(13,110,253,.15)", fill: true, tension: .3, pointRadius: 2 }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
               scales: { y: { beginAtZero: true } } } });

  const sev = ["critical", "high", "medium", "low", "info"];
  makeChart("chartSeverity", { type: "doughnut",
    data: { labels: sev.map(x => SEV_LABELS[x]), datasets: [{ data: sev.map(x => s.events_by_severity[x] || 0),
            backgroundColor: sev.map(x => SEV_COLORS[x]) }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "right" } } } });

  makeChart("chartSources", { type: "bar",
    data: { labels: s.top_sources.map(x => x.key), datasets: [{ label: "Sự kiện 24h", data: s.top_sources.map(x => x.count),
            backgroundColor: "#20c997" }] },
    options: { indexAxis: "y", responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } } });

  makeChart("chartAlertsDay", { type: "bar",
    data: { labels: s.alerts_per_day.map(x => x.label),
            datasets: sev.map(sv => ({ label: SEV_LABELS[sv], data: s.alerts_per_day.map(x => x[sv] || 0),
                                       backgroundColor: SEV_COLORS[sv], stack: "a" })) },
    options: { responsive: true, maintainAspectRatio: false, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } } } });

  const fillTable = (id, rows, fn) => { const tb = document.getElementById(id); if (!tb) return;
    tb.innerHTML = rows.length ? rows.map(fn).join("") : '<tr><td colspan="9" class="text-muted text-center">Chưa có dữ liệu</td></tr>'; };
  fillTable("tbl-top-ips", s.top_src_ips, r => `<tr><td class="mono"><a href="/logs?src_ip=${encodeURIComponent(r.key)}">${r.key}</a></td><td class="text-end">${r.count}</td></tr>`);
  fillTable("tbl-top-users", s.top_failed_users, r => `<tr><td>${r.key}</td><td class="text-end">${r.count}</td></tr>`);
  fillTable("tbl-top-hosts", s.top_hosts, r => `<tr><td>${r.key}</td><td class="text-end">${r.count}</td></tr>`);
  fillTable("tbl-latest-alerts", s.latest_alerts, a => `<tr>
      <td>${fmtLocal(a.created_at)}</td>
      <td><a href="/alerts/${a.id}">${a.title}</a></td>
      <td><span class="badge sev-${a.severity}">${SEV_LABELS[a.severity] || a.severity}</span></td>
      <td><span class="badge status-${a.status}">${STATUS_LABELS[a.status] || a.status}</span></td>
      <td>${a.ai_priority ? "P" + a.ai_priority : "-"}</td>
      <td>${a.host || "-"}</td></tr>`);
  fillTable("tbl-agents", s.agents, a => `<tr>
      <td><span class="status-dot ${a.status}"></span><a href="/agents/${a.id}">${a.hostname}</a></td>
      <td>${a.os_type || "-"}</td><td class="mono">${a.ip_address || "-"}</td>
      <td>${a.events_count.toLocaleString("vi-VN")}</td><td>${fmtLocal(a.last_seen)}</td></tr>`);
}

async function refreshDashboard() {
  try {
    const resp = await fetch("/api/v1/stats");
    if (resp.ok) renderDashboard(await resp.json());
  } catch (e) { console.error(e); }
}

document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("chartEventsHour")) {
    refreshDashboard();
    setInterval(refreshDashboard, 30000);
  }
  document.querySelectorAll("[data-confirm]").forEach(f => f.addEventListener("submit", e => {
    if (!confirm(f.dataset.confirm)) e.preventDefault();
  }));
});
