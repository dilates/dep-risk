from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dep_risk.scorers.base import PackageResult

VERSION = "1.0.0"
GITHUB_URL = "https://github.com/dilates"


def generate_html(
    results: list[PackageResult],
    directory: Path,
    duration: float,
    scan_time: datetime,
) -> str:
    data = [r.to_dict() for r in results]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        counts[r.risk_level] = counts.get(r.risk_level, 0) + 1

    json_blob = json.dumps(data, indent=None, separators=(",", ":"))
    scan_ts = scan_time.strftime("%Y-%m-%d %H:%M:%S UTC")

    return _HTML_TEMPLATE.format(
        version=VERSION,
        github_url=GITHUB_URL,
        directory=str(directory),
        scan_time=scan_ts,
        duration=f"{duration:.1f}s",
        total=len(results),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        json_blob=json_blob,
    )


class HtmlReporter:
    def write(
        self,
        path: Path,
        results: list[PackageResult],
        directory: Path,
        duration: float,
    ) -> None:
        html = generate_html(results, directory, duration, datetime.now(timezone.utc))
        path.write_text(html, encoding="utf-8")


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>dep-risk Report — {directory}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{display:flex;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f1923;color:#e2e8f0;font-size:14px}}
a{{color:#60a5fa;text-decoration:none}}
a:hover{{text-decoration:underline}}

/* Sidebar */
#sidebar{{width:240px;min-height:100vh;background:#0a1118;border-right:1px solid #1e3a5f;padding:20px;display:flex;flex-direction:column;gap:16px;position:sticky;top:0;max-height:100vh;overflow-y:auto}}
.logo{{font-size:18px;font-weight:700;color:#60a5fa;letter-spacing:-.5px}}
.logo span{{color:#e2e8f0;font-weight:400}}
.meta{{font-size:12px;color:#94a3b8;line-height:1.7}}
.meta strong{{color:#e2e8f0;display:block}}

/* Donut chart */
.donut-wrap{{text-align:center;padding:8px 0}}
.donut{{position:relative;display:inline-block}}
.donut svg{{transform:rotate(-90deg)}}
.donut-label{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:20px;font-weight:700;color:#e2e8f0}}

/* Filters */
.filter-section h4{{font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}}
.checkbox-group{{display:flex;flex-direction:column;gap:4px}}
.checkbox-group label{{display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;padding:2px 0}}
.checkbox-group input{{accent-color:#60a5fa}}

.sidebar-footer{{margin-top:auto;padding-top:12px;border-top:1px solid #1e3a5f;font-size:11px;color:#64748b}}

/* Main */
#main{{flex:1;padding:24px;overflow:hidden}}

/* Stat cards */
.stat-cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}}
.stat-card{{background:#111d2a;border:1px solid #1e3a5f;border-radius:8px;padding:16px;text-align:center}}
.stat-card .num{{font-size:28px;font-weight:700}}
.stat-card .lbl{{font-size:12px;color:#94a3b8;margin-top:4px}}
.c-critical{{color:#ef4444}}
.c-high{{color:#f97316}}
.c-medium{{color:#eab308}}
.c-low{{color:#22c55e}}
.c-total{{color:#60a5fa}}

/* Search + export bar */
.toolbar{{display:flex;gap:10px;margin-bottom:14px;align-items:center}}
#search{{flex:1;background:#111d2a;border:1px solid #1e3a5f;color:#e2e8f0;padding:8px 12px;border-radius:6px;font-size:13px;outline:none}}
#search:focus{{border-color:#3b82f6}}
#export-btn{{background:#1e3a5f;color:#e2e8f0;border:1px solid #2d5a8e;padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px;white-space:nowrap}}
#export-btn:hover{{background:#2d5a8e}}

/* Table */
#pkg-table{{width:100%;border-collapse:collapse;font-size:13px}}
#pkg-table thead th{{background:#111d2a;color:#94a3b8;text-align:left;padding:10px 12px;border-bottom:2px solid #1e3a5f;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;cursor:pointer;user-select:none;white-space:nowrap}}
#pkg-table thead th:hover{{color:#e2e8f0}}
#pkg-table thead th.sorted-asc::after{{content:' ↑'}}
#pkg-table thead th.sorted-desc::after{{content:' ↓'}}
#pkg-table tbody tr{{border-bottom:1px solid #1a2d3e;transition:background .1s}}
#pkg-table tbody tr.data-row:hover{{background:#111d2a}}
#pkg-table tbody td{{padding:10px 12px;vertical-align:middle}}
.detail-row td{{padding:0;background:#0d1923}}
.detail-content{{padding:16px 20px;border-left:3px solid #1e3a5f}}
.score-bar-wrap{{display:flex;align-items:center;gap:8px}}
.score-bar{{height:6px;border-radius:3px;min-width:2px}}
.score-num{{font-weight:700;font-size:13px}}
.risk-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.05em}}
.risk-critical{{background:#450a0a;color:#ef4444;border:1px solid #ef4444}}
.risk-high{{background:#431407;color:#f97316;border:1px solid #f97316}}
.risk-medium{{background:#422006;color:#eab308;border:1px solid #eab308}}
.risk-low{{background:#052e16;color:#22c55e;border:1px solid #22c55e}}
.expand-btn{{background:none;border:1px solid #1e3a5f;color:#94a3b8;padding:2px 8px;border-radius:4px;cursor:pointer;font-size:11px}}
.expand-btn:hover{{border-color:#3b82f6;color:#60a5fa}}

/* Detail panel */
.scorer-grid{{display:grid;grid-template-columns:130px 1fr 60px auto;gap:6px 10px;align-items:center;margin-bottom:12px}}
.scorer-name{{color:#94a3b8;font-size:12px}}
.scorer-bar-wrap{{background:#1a2d3e;border-radius:3px;height:8px;overflow:hidden}}
.scorer-bar-fill{{height:100%;border-radius:3px;transition:width .3s}}
.scorer-pts{{font-size:12px;font-weight:700;text-align:right}}
.scorer-finding{{font-size:12px;color:#94a3b8;grid-column:2 / -1}}
.detail-links{{display:flex;gap:16px;margin:10px 0;font-size:12px}}
.flags-list{{margin-top:8px}}
.flags-list li{{font-size:12px;color:#94a3b8;margin-left:16px;list-style:disc;line-height:1.7}}
.errors-list{{color:#f97316;font-size:11px;margin-top:6px}}

/* Footer */
footer{{margin-top:40px;padding-top:16px;border-top:1px solid #1a2d3e;font-size:12px;color:#64748b;text-align:center}}

/* Responsive */
@media(max-width:900px){{
  body{{flex-direction:column}}
  #sidebar{{width:100%;min-height:auto;position:static;flex-direction:row;flex-wrap:wrap}}
  .stat-cards{{grid-template-columns:repeat(2,1fr)}}
}}
</style>
</head>
<body>

<nav id="sidebar">
  <div>
    <div class="logo">dep-<span>risk</span></div>
    <div style="font-size:11px;color:#64748b">v{version}</div>
  </div>
  <div class="meta">
    <strong>Directory</strong>{directory}
    <strong style="margin-top:8px">Scan time</strong>{scan_time}
    <strong style="margin-top:8px">Duration</strong>{duration}
    <strong style="margin-top:8px">Packages</strong>{total} total
  </div>

  <div class="donut-wrap">
    <div class="donut">
      <svg id="donut-svg" width="100" height="100" viewBox="0 0 100 100"></svg>
      <div class="donut-label" id="donut-label">{total}</div>
    </div>
  </div>

  <div class="filter-section">
    <h4>Risk Level</h4>
    <div class="checkbox-group" id="risk-filters">
      <label><input type="checkbox" value="critical" checked> <span class="c-critical">Critical ({critical})</span></label>
      <label><input type="checkbox" value="high" checked> <span class="c-high">High ({high})</span></label>
      <label><input type="checkbox" value="medium" checked> <span class="c-medium">Medium ({medium})</span></label>
      <label><input type="checkbox" value="low" checked> <span class="c-low">Low ({low})</span></label>
    </div>
  </div>

  <div class="filter-section">
    <h4>Ecosystem</h4>
    <div class="checkbox-group" id="eco-filters"></div>
  </div>

  <div class="sidebar-footer">
    <a href="{github_url}" target="_blank">{github_url}</a>
  </div>
</nav>

<main id="main">
  <div class="stat-cards">
    <div class="stat-card"><div class="num c-total">{total}</div><div class="lbl">Total Packages</div></div>
    <div class="stat-card"><div class="num c-critical">{critical}</div><div class="lbl">Critical</div></div>
    <div class="stat-card"><div class="num c-high">{high}</div><div class="lbl">High</div></div>
    <div class="stat-card"><div class="num c-medium">{medium}</div><div class="lbl">Medium</div></div>
  </div>

  <div class="toolbar">
    <input id="search" type="text" placeholder="Filter packages..." oninput="applyFilters()">
    <button id="export-btn" onclick="exportCsv()">Export CSV</button>
  </div>

  <table id="pkg-table">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Package</th>
        <th onclick="sortTable(1)">Version</th>
        <th onclick="sortTable(2)">Ecosystem</th>
        <th onclick="sortTable(3)">Score</th>
        <th onclick="sortTable(4)">Risk</th>
        <th onclick="sortTable(5)">Top Finding</th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody id="table-body"></tbody>
  </table>

  <footer>
    Generated by dep-risk v{version} &mdash; <a href="{github_url}" target="_blank">{github_url}</a> &mdash; {scan_time}
  </footer>
</main>

<script>
const DATA = {json_blob};

const RISK_ORDER = {{critical:3,high:2,medium:1,low:0}};
const RISK_COLORS_HEX = {{critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e'}};
const SCORER_ORDER = ['maintainer','install_script','activity','typosquat','version','github','entropy'];

let sortCol = 3, sortAsc = false;

function initEcoFilters() {{
  const ecos = [...new Set(DATA.map(d => d.ecosystem))].sort();
  const wrap = document.getElementById('eco-filters');
  ecos.forEach(eco => {{
    const lbl = document.createElement('label');
    lbl.innerHTML = `<input type="checkbox" value="${{eco}}" checked> ${{eco}}`;
    lbl.querySelector('input').addEventListener('change', applyFilters);
    wrap.appendChild(lbl);
  }});
  document.querySelectorAll('#risk-filters input').forEach(cb => cb.addEventListener('change', applyFilters));
}}

function getFilters() {{
  const risk = [...document.querySelectorAll('#risk-filters input:checked')].map(i => i.value);
  const eco = [...document.querySelectorAll('#eco-filters input:checked')].map(i => i.value);
  const search = document.getElementById('search').value.toLowerCase();
  return {{risk, eco, search}};
}}

function filteredData() {{
  const {{risk, eco, search}} = getFilters();
  return DATA.filter(d =>
    risk.includes(d.risk_level) &&
    eco.includes(d.ecosystem) &&
    (d.name.toLowerCase().includes(search) || (d.flags[0]||'').toLowerCase().includes(search))
  );
}}

function scoreBarColor(score) {{
  if (score > 70) return '#ef4444';
  if (score > 45) return '#f97316';
  if (score > 20) return '#eab308';
  return '#22c55e';
}}

function renderTable() {{
  const rows = filteredData();
  rows.sort((a,b) => {{
    let av, bv;
    if (sortCol === 3) {{ av = a.total_score; bv = b.total_score; }}
    else if (sortCol === 4) {{ av = RISK_ORDER[a.risk_level]; bv = RISK_ORDER[b.risk_level]; }}
    else {{
      const keys = ['name','version','ecosystem','total_score','risk_level','flags'];
      av = (a[keys[sortCol]]||'').toString().toLowerCase();
      bv = (b[keys[sortCol]]||'').toString().toLowerCase();
      if (sortCol === 5) {{ av = (a.flags[0]||'').toLowerCase(); bv = (b.flags[0]||'').toLowerCase(); }}
    }}
    if (av < bv) return sortAsc ? -1 : 1;
    if (av > bv) return sortAsc ? 1 : -1;
    return 0;
  }});

  const tbody = document.getElementById('table-body');
  tbody.innerHTML = '';
  rows.forEach((pkg, idx) => {{
    const color = RISK_COLORS_HEX[pkg.risk_level];
    const barW = Math.max(2, Math.round(pkg.total_score));
    const tr = document.createElement('tr');
    tr.className = 'data-row';
    tr.dataset.idx = idx;
    tr.innerHTML = `
      <td><strong>${{pkg.name}}</strong></td>
      <td>${{pkg.version||'—'}}</td>
      <td>${{pkg.ecosystem}}</td>
      <td>
        <div class="score-bar-wrap">
          <div class="score-bar" style="width:${{barW}}px;background:${{color}}"></div>
          <span class="score-num" style="color:${{color}}">${{Math.round(pkg.total_score)}}</span>
        </div>
      </td>
      <td><span class="risk-badge risk-${{pkg.risk_level}}">${{pkg.risk_level.toUpperCase()}}</span></td>
      <td>${{pkg.flags[0]||'—'}}</td>
      <td><button class="expand-btn" onclick="toggleDetail(this, ${{idx}})">▶ Show</button></td>
    `;
    tbody.appendChild(tr);

    const detailTr = document.createElement('tr');
    detailTr.className = 'detail-row';
    detailTr.id = `detail-${{idx}}`;
    detailTr.style.display = 'none';
    detailTr.innerHTML = `<td colspan="7"><div class="detail-content" id="detail-content-${{idx}}"></div></td>`;
    tbody.appendChild(detailTr);
  }});

  updateHeaders();
  updateDonut();
}}

function toggleDetail(btn, idx) {{
  const row = document.getElementById(`detail-${{idx}}`);
  const content = document.getElementById(`detail-content-${{idx}}`);
  if (row.style.display === 'none') {{
    row.style.display = '';
    btn.textContent = '▼ Hide';
    if (!content.dataset.rendered) {{
      const pkg = filteredData()[idx];
      content.innerHTML = renderDetail(pkg);
      content.dataset.rendered = '1';
    }}
  }} else {{
    row.style.display = 'none';
    btn.textContent = '▶ Show';
  }}
}}

function renderDetail(pkg) {{
  let html = '<div class="scorer-grid">';
  SCORER_ORDER.forEach(name => {{
    const s = pkg.scores[name];
    if (!s) return;
    const color = scoreBarColor(s.score);
    const w = Math.round(s.score);
    html += `
      <div class="scorer-name">${{name}}</div>
      <div class="scorer-bar-wrap"><div class="scorer-bar-fill" style="width:${{w}}%;background:${{color}}"></div></div>
      <div class="scorer-pts" style="color:${{color}}">${{Math.round(s.score)}}pts</div>
      <div></div>
      <div class="scorer-finding" style="grid-column:2/-1">${{s.finding}}</div>
    `;
  }});
  html += '</div>';
  html += '<div class="detail-links">';
  if (pkg.registry_url) html += `<a href="${{pkg.registry_url}}" target="_blank">Registry ↗</a>`;
  if (pkg.github_url) html += `<a href="${{pkg.github_url}}" target="_blank">GitHub ↗</a>`;
  html += '</div>';
  if (pkg.flags.length > 0) {{
    html += '<ul class="flags-list">' + pkg.flags.map(f => `<li>${{f}}</li>`).join('') + '</ul>';
  }}
  if (pkg.fetch_errors.length > 0) {{
    html += '<div class="errors-list">⚠ ' + pkg.fetch_errors.join(' | ') + '</div>';
  }}
  return html;
}}

function sortTable(col) {{
  if (sortCol === col) sortAsc = !sortAsc;
  else {{ sortCol = col; sortAsc = col !== 3 && col !== 4; }}
  renderTable();
}}

function updateHeaders() {{
  document.querySelectorAll('#pkg-table thead th').forEach((th, i) => {{
    th.classList.remove('sorted-asc','sorted-desc');
    if (i === sortCol) th.classList.add(sortAsc ? 'sorted-asc' : 'sorted-desc');
  }});
}}

function applyFilters() {{ renderTable(); }}

function updateDonut() {{
  const rows = filteredData();
  const counts = {{critical:0,high:0,medium:0,low:0}};
  rows.forEach(r => counts[r.risk_level]++);
  const total = rows.length;
  document.getElementById('donut-label').textContent = total;

  const svg = document.getElementById('donut-svg');
  const cx=50,cy=50,r=38,strokeW=12;
  const circ = 2*Math.PI*r;
  const colors = {{critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e'}};
  const order = ['critical','high','medium','low'];
  let offset = 0;
  let svgContent = '';
  order.forEach(lvl => {{
    const frac = total > 0 ? counts[lvl]/total : 0;
    const dash = frac * circ;
    if (dash > 0) {{
      svgContent += `<circle cx="${{cx}}" cy="${{cy}}" r="${{r}}" fill="none" stroke="${{colors[lvl]}}" stroke-width="${{strokeW}}" stroke-dasharray="${{dash}} ${{circ-dash}}" stroke-dashoffset="${{-offset}}" />`;
      offset += dash;
    }}
  }});
  if (total === 0) svgContent = `<circle cx="${{cx}}" cy="${{cy}}" r="${{r}}" fill="none" stroke="#1e3a5f" stroke-width="${{strokeW}}" />`;
  svg.innerHTML = svgContent;
}}

function exportCsv() {{
  const rows = filteredData();
  const header = ['name','version','ecosystem','score','risk_level','top_finding','registry_url','github_url'];
  const lines = [header.join(',')];
  rows.forEach(r => {{
    const row = [
      r.name, r.version||'', r.ecosystem,
      Math.round(r.total_score), r.risk_level,
      (r.flags[0]||'').replace(/,/g,' '),
      r.registry_url||'', r.github_url||''
    ];
    lines.push(row.map(v => `"${{v}}"`).join(','));
  }});
  const blob = new Blob([lines.join('\\n')], {{type:'text/csv'}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'dep-risk-report.csv'; a.click();
  URL.revokeObjectURL(url);
}}

initEcoFilters();
renderTable();
</script>
</body>
</html>
"""
