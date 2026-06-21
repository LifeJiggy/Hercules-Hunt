const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const args = process.argv.slice(2);
if (args.length < 2) { console.log('Usage: node html-report-generator.js <findings.json> <output.html> [--title "Scan Report"]'); process.exit(1); }

const inputJson = args[0];
const outputHtml = args[1];
const titleFlag = args.indexOf('--title');
const reportTitle = titleFlag > -1 && args[titleFlag + 1] ? args[titleFlag + 1] : 'JS Chunk Analysis Report';

const loaded = harden.safeLoadFile(inputJson);
if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }

let data;
try { data = JSON.parse(loaded.content); }
catch (e) { console.error(`Invalid JSON: ${e.message}`); process.exit(1); }

const findings = data.findings || data.finalFindings || data.raw_findings || [];
const metadata = data.metadata || {};
const summary = data.summary || {};

const severityColors = { CRITICAL: '#dc3545', HIGH: '#fd7e14', MEDIUM: '#ffc107', LOW: '#28a745', INFO: '#6c757d' };
const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

function sevColor(s) { return severityColors[s] || '#6c757d'; }

const sorted = [...findings].sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0));
const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] };
for (const f of sorted) { if (bySeverity[f.severity]) bySeverity[f.severity].push(f); }

const totalCrit = bySeverity.CRITICAL.length;
const totalHigh = bySeverity.HIGH.length;
const totalMed = bySeverity.MEDIUM.length;
const totalLow = bySeverity.LOW.length;

function escapeHtml(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

let findingsRows = '';
let idx = 0;
for (const f of sorted) {
  idx++;
  const filePath = f.filePath || f.file || '';
  const code = (f.code || f.name || '').substring(0, 200);
  findingsRows += `<tr class="sev-${f.severity}" onclick="toggleDetail(${idx})">
    <td><span class="sev-badge" style="background:${sevColor(f.severity)}">${f.severity}</span></td>
    <td>${escapeHtml(f.category || f.type || 'Unknown')}</td>
    <td>${escapeHtml(f.name || '')}</td>
    <td>${escapeHtml(f.file || '')}</td>
    <td>${f.line || '-'}</td>
    <td><code>${escapeHtml(code.substring(0, 80))}</code></td>
  </tr>
  <tr id="detail-${idx}" class="detail-row" style="display:none">
    <td colspan="6">
      <pre>File: ${escapeHtml(filePath)}<br>Line: ${f.line || '?'}<br>CVSS: ${f.cvss || f.cvss_score || 'N/A'}<br><br><code>${escapeHtml(code)}</code>${f.context ? '<br><br><b>Context:</b><br><code>' + escapeHtml(f.context.substring(0, 300)) + '</code>' : ''}${f.risk ? '<br><br><b>Risk:</b> ' + escapeHtml(f.risk) : ''}</pre>
    </td>
  </tr>`;
}

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(reportTitle)}</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background:#0d1117; color:#c9d1d9; padding:20px; }
h1 { color:#58a6ff; margin-bottom:5px; }
h2 { color:#c9d1d9; margin:20px 0 10px; font-size:1.2em; }
.meta { color:#8b949e; font-size:0.9em; margin-bottom:20px; }
.summary-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(140px,1fr)); gap:12px; margin:20px 0; }
.stat-card { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px; text-align:center; }
.stat-card .num { font-size:2em; font-weight:700; }
.stat-card .label { color:#8b949e; font-size:0.85em; margin-top:4px; }
table { width:100%; border-collapse:collapse; margin:10px 0; }
th { background:#161b22; color:#8b949e; text-align:left; padding:10px 12px; border-bottom:2px solid #30363d; font-size:0.85em; text-transform:uppercase; }
td { padding:10px 12px; border-bottom:1px solid #21262d; font-size:0.9em; vertical-align:top; }
tr:hover { background:#161b22; }
tr.detail-row:hover { background:transparent; }
tr.detail-row td { padding:0; }
tr.detail-row pre { background:#0d1117; border:1px solid #30363d; border-radius:6px; padding:16px; margin:4px 12px 12px; font-size:0.85em; overflow-x:auto; white-space:pre-wrap; word-break:break-all; }
tr.detail-row code { background:#1c2128; padding:2px 6px; border-radius:3px; font-size:0.95em; }
.sev-badge { display:inline-block; padding:2px 8px; border-radius:4px; color:#fff; font-size:0.8em; font-weight:600; }
.sev-CRITICAL td:first-child { border-left:3px solid #dc3545; }
.sev-HIGH td:first-child { border-left:3px solid #fd7e14; }
.sev-MEDIUM td:first-child { border-left:3px solid #ffc107; }
.sev-LOW td:first-child { border-left:3px solid #28a745; }
code { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size:0.9em; }
.footer { margin-top:30px; padding-top:15px; border-top:1px solid #30363d; color:#8b949e; font-size:0.85em; }
.search-box { width:100%; padding:10px 14px; background:#0d1117; border:1px solid #30363d; border-radius:6px; color:#c9d1d9; font-size:1em; margin:10px 0; }
.search-box:focus { outline:none; border-color:#58a6ff; }
</style>
</head>
<body>
<h1>${escapeHtml(reportTitle)}</h1>
<div class="meta">${metadata.date || new Date().toISOString().split('T')[0]} &middot; Target: ${escapeHtml(metadata.target || metadata.filesAnalyzed ? metadata.filesAnalyzed + ' files' : 'N/A')} &middot; ${findings.length} findings</div>

<div class="summary-grid">
<div class="stat-card"><div class="num" style="color:#dc3545">${totalCrit}</div><div class="label">CRITICAL</div></div>
<div class="stat-card"><div class="num" style="color:#fd7e14">${totalHigh}</div><div class="label">HIGH</div></div>
<div class="stat-card"><div class="num" style="color:#ffc107">${totalMed}</div><div class="label">MEDIUM</div></div>
<div class="stat-card"><div class="num" style="color:#28a745">${totalLow}</div><div class="label">LOW</div></div>
<div class="stat-card"><div class="num" style="color:#8b949e">${findings.length}</div><div class="label">TOTAL</div></div>
</div>

<input type="text" class="search-box" id="search" placeholder="Search findings..." onkeyup="filterTable()">

<h2>All Findings</h2>
<table id="findings-table">
<thead><tr><th>Severity</th><th>Category</th><th>Pattern</th><th>File</th><th>Line</th><th>Code</th></tr></thead>
<tbody>${findingsRows}</tbody>
</table>

<div class="footer">
Generated by JS Chunk Analysis Toolkit &middot; ${new Date().toISOString()}
</div>

<script>
function toggleDetail(id) {
  const row = document.getElementById('detail-' + id);
  if (row) row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}
function filterTable() {
  const q = document.getElementById('search').value.toLowerCase();
  const rows = document.querySelectorAll('#findings-table tbody tr:not(.detail-row)');
  for (const row of rows) {
    const text = row.textContent.toLowerCase();
    const detail = row.nextElementSibling;
    const match = text.includes(q);
    row.style.display = match ? '' : 'none';
    if (detail && detail.classList.contains('detail-row')) {
      detail.style.display = 'none';
    }
  }
}
</script>
</body>
</html>`;

fs.mkdirSync(path.dirname(path.resolve(outputHtml)), { recursive: true });
fs.writeFileSync(outputHtml, html, 'utf-8');
console.log(`\n[OK] HTML report written to ${path.resolve(outputHtml)} (${(html.length / 1024).toFixed(1)} KB)`);
