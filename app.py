"""
Mini SIEM Dashboard
--------------------
Author: Ujjwal Dhakal
Description: A Security Information and Event Management (SIEM) system that
             ingests security logs, detects threats using rule-based analysis,
             generates alerts, and visualizes security events in real time.
"""

from flask import Flask, jsonify, render_template_string, request
import sqlite3, datetime, json
from log_generator import generate_logs
from threat_detector import run_detection

app = Flask(__name__)
DB = 'siem.db'

# ── DB helper ────────────────────────────────────────────────────────────────
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

# ── Seed DB on startup ───────────────────────────────────────────────────────
generate_logs(DB, count=200)
run_detection(DB)

# ════════════════════════════════════════════════════════════════════════════
#  DASHBOARD HTML
# ════════════════════════════════════════════════════════════════════════════
DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Mini SIEM — Security Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3}
header{background:#161b22;border-bottom:1px solid #30363d;padding:16px 28px;
       display:flex;align-items:center;justify-content:space-between}
header h1{font-size:1.2rem;color:#58a6ff}
header p{font-size:0.8rem;color:#8b949e}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;
       font-size:0.72rem;font-weight:bold}
.CRITICAL{background:#3d1f1f;color:#f85149}
.HIGH{background:#3d2b1f;color:#f0883e}
.MEDIUM{background:#2e2a18;color:#e3b341}
.LOW{background:#1a2b1a;color:#3fb950}
.OPEN{background:#1a2b3d;color:#58a6ff}
.RESOLVED{background:#1a2b1a;color:#3fb950}
.container{max-width:1300px;margin:24px auto;padding:0 20px}
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.kpi{background:#161b22;border:1px solid #30363d;border-radius:8px;
     padding:20px;text-align:center}
.kpi .num{font-size:2.2rem;font-weight:bold;margin-bottom:4px}
.kpi .label{font-size:0.8rem;color:#8b949e}
.kpi.critical .num{color:#f85149}
.kpi.high .num{color:#f0883e}
.kpi.medium .num{color:#e3b341}
.kpi.total .num{color:#58a6ff}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px}
.card h2{font-size:0.95rem;color:#58a6ff;margin-bottom:14px;
         border-bottom:1px solid #30363d;padding-bottom:8px}
.full{grid-column:1/-1}
table{width:100%;border-collapse:collapse;font-size:0.82rem}
th{background:#0d1117;color:#8b949e;padding:8px 10px;text-align:left;
   border-bottom:1px solid #30363d}
td{padding:7px 10px;border-bottom:1px solid #21262d;color:#e6edf3}
tr:hover td{background:#1c2128}
.bar-wrap{background:#21262d;border-radius:4px;height:14px;margin:3px 0}
.bar{height:14px;border-radius:4px;transition:width 0.5s}
.bar.CRITICAL{background:#f85149}
.bar.HIGH{background:#f0883e}
.bar.MEDIUM{background:#e3b341}
.bar.LOW{background:#3fb950}
button{background:#238636;color:#fff;border:none;padding:7px 16px;
       border-radius:6px;cursor:pointer;font-size:0.85rem}
button:hover{background:#2ea043}
.btn-red{background:#da3633}
.btn-red:hover{background:#f85149}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot-ok{background:#3fb950}
.dot-warn{background:#e3b341}
.dot-critical{background:#f85149}
canvas{width:100%!important}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>

<header>
  <div>
    <h1>🛡️ Mini SIEM — Security Information & Event Management</h1>
    <p>Real-time threat detection · Alert management · Log analysis · Built with Python & Flask</p>
  </div>
  <div style="display:flex;gap:10px">
    <button onclick="refreshAll()">🔄 Refresh</button>
    <button class="btn-red" onclick="regenerateLogs()">⚡ Generate New Logs</button>
  </div>
</header>

<div class="container">

  <!-- KPI CARDS -->
  <div class="kpi-row" id="kpis">
    <div class="kpi critical"><div class="num" id="k-critical">—</div><div class="label">🔴 Critical Alerts</div></div>
    <div class="kpi high"><div class="num" id="k-high">—</div><div class="label">🟠 High Severity</div></div>
    <div class="kpi medium"><div class="num" id="k-medium">—</div><div class="label">🟡 Medium Severity</div></div>
    <div class="kpi total"><div class="num" id="k-total">—</div><div class="label">📋 Total Events (24h)</div></div>
  </div>

  <div class="grid2">

    <!-- SEVERITY CHART -->
    <div class="card">
      <h2>📊 Events by Severity</h2>
      <canvas id="sevChart" height="200"></canvas>
    </div>

    <!-- EVENT TYPE CHART -->
    <div class="card">
      <h2>🔍 Top Event Types</h2>
      <canvas id="typeChart" height="200"></canvas>
    </div>

    <!-- TIMELINE CHART -->
    <div class="card full">
      <h2>📈 Event Timeline (Last 24 Hours)</h2>
      <canvas id="timeChart" height="100"></canvas>
    </div>

    <!-- TOP ATTACKERS -->
    <div class="card">
      <h2>🌐 Top Source IPs</h2>
      <table id="ip-table">
        <thead><tr><th>IP Address</th><th>Events</th><th>Threat Level</th><th>Bar</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>

    <!-- OPEN ALERTS -->
    <div class="card">
      <h2>🚨 Active Alerts</h2>
      <table id="alert-table">
        <thead><tr><th>Time</th><th>Severity</th><th>Title</th><th>Action</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>

    <!-- LIVE LOG FEED -->
    <div class="card full">
      <h2>📋 Live Security Log Feed</h2>
      <table id="log-table">
        <thead><tr><th>Timestamp</th><th>Severity</th><th>Event Type</th><th>User</th><th>Source IP</th><th>Host</th><th>Message</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>

  </div>
</div>

<script>
let sevChart, typeChart, timeChart;

async function api(url, method='GET') {
  const r = await fetch(url, {method});
  return r.json();
}

async function loadKPIs() {
  const d = await api('/api/summary');
  document.getElementById('k-critical').textContent = d.critical;
  document.getElementById('k-high').textContent     = d.high;
  document.getElementById('k-medium').textContent   = d.medium;
  document.getElementById('k-total').textContent    = d.total;
}

async function loadCharts() {
  const d = await api('/api/charts');

  // Severity donut
  if (sevChart) sevChart.destroy();
  sevChart = new Chart(document.getElementById('sevChart'), {
    type: 'doughnut',
    data: {
      labels: d.severity.labels,
      datasets: [{
        data: d.severity.values,
        backgroundColor: ['#f85149','#f0883e','#e3b341','#3fb950'],
        borderWidth: 0
      }]
    },
    options: { plugins: { legend: { labels: { color: '#e6edf3' } } } }
  });

  // Event type bar
  if (typeChart) typeChart.destroy();
  typeChart = new Chart(document.getElementById('typeChart'), {
    type: 'bar',
    data: {
      labels: d.types.labels,
      datasets: [{
        data: d.types.values,
        backgroundColor: '#58a6ff',
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#e6edf3' }, grid: { color: '#21262d' } }
      }
    }
  });

  // Timeline
  if (timeChart) timeChart.destroy();
  timeChart = new Chart(document.getElementById('timeChart'), {
    type: 'line',
    data: {
      labels: d.timeline.labels,
      datasets: [{
        label: 'Events',
        data: d.timeline.values,
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88,166,255,0.1)',
        fill: true,
        tension: 0.4,
        pointRadius: 3
      }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8b949e', maxTicksLimit: 12 }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }
      }
    }
  });
}

async function loadIPs() {
  const d = await api('/api/top-ips');
  const max = d.ips[0]?.count || 1;
  const tbody = document.querySelector('#ip-table tbody');
  tbody.innerHTML = d.ips.map(ip => {
    const pct = Math.round((ip.count / max) * 100);
    const sev = ip.count > 20 ? 'CRITICAL' : ip.count > 10 ? 'HIGH' : 'MEDIUM';
    return `<tr>
      <td><code style="color:#58a6ff">${ip.source_ip}</code></td>
      <td>${ip.count}</td>
      <td><span class="badge ${sev}">${sev}</span></td>
      <td><div class="bar-wrap"><div class="bar ${sev}" style="width:${pct}%"></div></div></td>
    </tr>`;
  }).join('');
}

async function loadAlerts() {
  const d = await api('/api/alerts');
  const tbody = document.querySelector('#alert-table tbody');
  tbody.innerHTML = d.alerts.map(a => `
    <tr>
      <td style="color:#8b949e;font-size:0.78rem">${a.timestamp.slice(11,16)}</td>
      <td><span class="badge ${a.severity}">${a.severity}</span></td>
      <td>${a.title}</td>
      <td><button onclick="resolveAlert(${a.id})" style="padding:3px 10px;font-size:0.75rem">✓ Resolve</button></td>
    </tr>`).join('') || '<tr><td colspan="4" style="color:#3fb950;text-align:center">✅ No open alerts</td></tr>';
}

async function loadLogs() {
  const d = await api('/api/logs');
  const tbody = document.querySelector('#log-table tbody');
  tbody.innerHTML = d.logs.map(l => `
    <tr>
      <td style="color:#8b949e;font-size:0.78rem">${l.timestamp}</td>
      <td><span class="badge ${l.severity}">${l.severity}</span></td>
      <td style="color:#e3b341">${l.event_type}</td>
      <td>${l.user || '—'}</td>
      <td><code style="color:#58a6ff">${l.source_ip || '—'}</code></td>
      <td>${l.host || '—'}</td>
      <td style="color:#8b949e;font-size:0.8rem">${l.message}</td>
    </tr>`).join('');
}

async function resolveAlert(id) {
  await api(`/api/alerts/${id}/resolve`, 'POST');
  loadAlerts();
}

async function regenerateLogs() {
  await api('/api/regenerate', 'POST');
  refreshAll();
}

async function refreshAll() {
  await Promise.all([loadKPIs(), loadCharts(), loadIPs(), loadAlerts(), loadLogs()]);
}

// Auto-refresh every 30 seconds
refreshAll();
setInterval(refreshAll, 30000);
</script>
</body>
</html>
"""

# ════════════════════════════════════════════════════════════════════════════
#  API ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD)


@app.route('/api/summary')
def summary():
    c = db()
    total    = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    critical = c.execute("SELECT COUNT(*) FROM logs WHERE severity='CRITICAL'").fetchone()[0]
    high     = c.execute("SELECT COUNT(*) FROM logs WHERE severity='HIGH'").fetchone()[0]
    medium   = c.execute("SELECT COUNT(*) FROM logs WHERE severity='MEDIUM'").fetchone()[0]
    return jsonify({'total': total, 'critical': critical, 'high': high, 'medium': medium})


@app.route('/api/charts')
def charts():
    c = db()

    # Severity distribution
    sev_rows = c.execute(
        "SELECT severity, COUNT(*) as cnt FROM logs GROUP BY severity ORDER BY cnt DESC"
    ).fetchall()
    sev_order = ['CRITICAL','HIGH','MEDIUM','LOW']
    sev_dict  = {r['severity']: r['cnt'] for r in sev_rows}
    severity  = {'labels': sev_order, 'values': [sev_dict.get(s, 0) for s in sev_order]}

    # Top event types
    type_rows = c.execute(
        "SELECT event_type, COUNT(*) as cnt FROM logs GROUP BY event_type ORDER BY cnt DESC LIMIT 8"
    ).fetchall()
    types = {'labels': [r['event_type'].replace('_',' ') for r in type_rows],
             'values': [r['cnt'] for r in type_rows]}

    # Timeline — events per hour
    tl_rows = c.execute("""
        SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as cnt
        FROM logs GROUP BY hour ORDER BY hour
    """).fetchall()
    timeline = {'labels': [r['hour'] for r in tl_rows],
                'values': [r['cnt'] for r in tl_rows]}

    return jsonify({'severity': severity, 'types': types, 'timeline': timeline})


@app.route('/api/top-ips')
def top_ips():
    c  = db()
    rows = c.execute(
        "SELECT source_ip, COUNT(*) as count FROM logs WHERE source_ip IS NOT NULL "
        "GROUP BY source_ip ORDER BY count DESC LIMIT 8"
    ).fetchall()
    return jsonify({'ips': [dict(r) for r in rows]})


@app.route('/api/alerts')
def alerts():
    c = db()
    rows = c.execute(
        "SELECT * FROM alerts WHERE status='OPEN' ORDER BY severity DESC, timestamp DESC LIMIT 20"
    ).fetchall()
    return jsonify({'alerts': [dict(r) for r in rows]})


@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    c = db()
    c.execute("UPDATE alerts SET status='RESOLVED' WHERE id=?", (alert_id,))
    c.commit()
    return jsonify({'success': True})


@app.route('/api/logs')
def logs():
    c = db()
    rows = c.execute(
        "SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    return jsonify({'logs': [dict(r) for r in rows]})


@app.route('/api/regenerate', methods=['POST'])
def regenerate():
    generate_logs(DB, count=200)
    run_detection(DB)
    return jsonify({'success': True, 'message': 'New logs generated'})


if __name__ == '__main__':
    app.run(debug=True, port=5001)
