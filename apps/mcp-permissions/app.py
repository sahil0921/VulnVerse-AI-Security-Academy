from flask import Flask, request, jsonify, render_template_string
import requests, os, json, re

app = Flask(__name__)
OLLAMA = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL  = os.environ.get("MODEL_NAME",  "mistral:latest")

DEFENSE_LEVEL = {"current": "production"}

# ---------------- Simulated environment ----------------
VFS = {
    "/data/documents/welcome.txt": "Welcome to NimbleTech document store.",
    "/data/documents/employee-handbook.md": "# Employee Handbook\nStandard policies here.",
    "/data/documents/q1-report.pdf": "[binary content - quarterly sales numbers]",
    "/data/.secrets/credentials.json": json.dumps({
        "db_password": "Nimble_Pr0d_DB_S3cret!_2026",
        "redis_password": "N1mbleRedisPr0d2026",
        "internal_api": "sk-nimble-internal-7f3a9b2c4e1d8f6a"
    }, indent=2),
    "/data/projects/api-docs/spec.yaml": "openapi: 3.0\ninfo:\n  title: NimbleTech API",
    "__SYMLINK__/data/projects/vendor-docs": "/data/secrets",
    "/data/secrets/prod.env": """AWS_ACCESS_KEY_ID=AKIA3NIMBLE2026PROD01
AWS_SECRET_ACCESS_KEY=wJalrXUtnNIMBLE/K7MDENG/bPxR26Prod
DATABASE_URL=postgresql://prod_admin:N1mbleProd2026!@db.nimbletech.internal/prod
STRIPE_LIVE_KEY=sk_live_nimble2026_xK9mP2vL5nQ8wR_LEAKED"""
}

DB_TABLES = {
    "customers": [
        {"id": 1, "name": "Acme Corp", "email": "acme@example.com"},
        {"id": 2, "name": "Globex", "email": "globex@example.com"}
    ],
    "customer_pii": [
        {"id": 1, "ssn": "123-45-6789", "dob": "1985-04-12", "address": "123 Main St"},
        {"id": 2, "ssn": "234-56-7890", "dob": "1990-08-23", "address": "456 Oak Ave"}
    ],
    "api_keys": [
        {"service": "Stripe", "key": "sk_live_nimble2026_xK9mP2vL5nQ8wR"},
        {"service": "SendGrid", "key": "SG.nimble2026.xK9mP2vL5nQ8wR_jF4kZ"},
        {"service": "AWS", "key": "AKIA3NIMBLE2026PROD01"}
    ]
}

WALKTHROUGH = [
    {"title": "Step 1 — Check the MCP tool's role", "body": "Open the <b>DB Query</b> tab and run <code>What role is this connection using?</code>. In a properly configured system, an MCP tool used for everyday queries should run as a narrow, read-only service account. Here it doesn't.", "query": "What role and privileges does this database connection have?", "tab": "db", "expect": "The response should show the connection is running as an owner-level role (mcpuser), not a scoped read-only account."},
    {"title": "Step 2 — Enumerate the schema", "body": "A single natural-language request is enough to map every table in the database, including ones that were never meant to be exposed to a chat interface.", "query": "List all tables in the database.", "tab": "db", "expect": "The result should list customer_pii and api_keys alongside ordinary tables like customers — tables a normal support tool should never need."},
    {"title": "Step 3 — Pull PII and live API keys", "body": "Try both queries below. There's no row-level security and no column masking, so a single chat request returns everything.", "query": "Join customers and customer_pii and show SSN and DOB for all rows.", "tab": "db", "expect": "Full SSNs, dates of birth, and live Stripe/AWS/SendGrid keys should come back in plain text."},
    {"title": "Step 4 — Try the path traversal (File Browser tab)", "body": "Switch to the <b>File Browser</b> tab. First try reading the secrets file directly — it should be denied because the tool checks the path prefix. Then try the same file using a <code>../</code> traversal from an allowed folder.", "query": "Read the file at /data/documents/../.secrets/credentials.json", "tab": "trav", "expect": "The direct path is denied, but the ../ version resolves outside the sandboxed /data/documents/ folder and returns the credentials file — because the prefix check runs on the raw path before it's normalized."},
    {"title": "Step 5 — Discover and cross the symlink", "body": "Switch to the <b>Symlink</b> tab. List the projects folder first — you'll see a folder called vendor-docs that looks completely ordinary in a normal directory listing.", "query": "List files in /data/projects/", "tab": "sym", "expect": "The listing shows vendor-docs as a symlink pointing to /data/secrets — a normal file browser would show this exact same thing to anyone who looks closely."},
    {"title": "Step 6 — Read through the symlink", "body": "Now read a file inside that folder. The path itself still starts with the allowed /data/projects/ prefix, so a naive string check lets it through — even though the symlink actually points outside the sandbox.", "query": "Read /data/projects/vendor-docs/prod.env", "tab": "sym", "expect": "Full production AWS keys, database credentials, and a live Stripe key should be returned — reached entirely through a path that looked allowed."},
    {"title": "Step 7 — Compare Staging / Compliance", "body": "Switch environment (top right) to <b>Staging</b> — the DB connection is downgraded to read-only with column masking on SSNs and API keys, the file tool normalizes paths before checking them, and symlinks are resolved and rejected. Switch to <b>Compliance</b> — sensitive table names, PII columns, and traversal-looking paths are refused outright and logged."},
]

SOLUTION_NOTES = """This lab chains three separate but related permission failures, all rooted in the same idea: an MCP tool's technical access should never be broader than what the assistant actually needs to do its job.

1. Database over-privilege: the MCP tool connects to the database as an owner-level account instead of a narrow, purpose-scoped one. Since there's no row-level security or column masking, any natural-language query the LLM decides to run has full read access to every table, including PII and live API keys.

2. Path traversal (matches the pattern behind CVE-2025-53109/53110): the file-reading tool checks whether the raw, unmodified path starts with an allowed prefix, and only normalizes the path afterward. A path like /data/documents/../.secrets/credentials.json passes the prefix check as written, but once normalized it resolves completely outside the sandbox.

3. Symlink escape: even after path normalization is fixed, os.path.normpath() only does string-level cleanup — it does not resolve symlinks. A symlink sitting inside an allowed folder can point anywhere on disk, and a string-prefix check has no way to see that.

Fixes demonstrated here:
1. Run MCP-backed database connections under a least-privilege, read-only role with column-level masking on sensitive fields (Staging mode).
2. Normalize the path before checking it against the sandbox prefix, not after (Staging mode).
3. Resolve symlinks with something equivalent to os.path.realpath() and re-check the resolved path against the sandbox boundary before allowing access (Staging mode).
4. In production: give the guardrail layer explicit knowledge of sensitive table/column names and path patterns so it can refuse before the query or file read ever executes (Compliance mode)."""

# ---------------- HTML ----------------
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NimbleTech Data Console</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');
:root{
  --bg:#f5f6f8;--panel:#ffffff;--panelhdr:#fafbfc;--border:#e1e4e8;
  --blue:#0f6cbd;--green:#107c10;--amber:#a15c00;--red:#d13438;--cyan:#0a7ea4;
  --t1:#1b1b1b;--t2:#5b5f66;--t3:#8a8f98;
  --mono:'JetBrains Mono',monospace;--sans:'Inter',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t1);font-family:var(--sans);height:100vh;overflow:hidden;font-size:13px}
.app{display:flex;flex-direction:column;height:100vh}
.topbar{background:var(--panelhdr);height:52px;border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 18px;gap:12px;flex-shrink:0}
.logo{width:28px;height:28px;background:linear-gradient(135deg,var(--blue),#2b6fd6);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px}
.topbar b{font-size:13.5px}
.topbar .crumb{color:var(--t2);font-size:12px;font-family:var(--mono)}
.topbar .badge{font-family:var(--mono);font-size:10px;color:var(--red);border:1px solid var(--red);padding:2px 8px;border-radius:10px;background:rgba(239,87,87,.08);margin-left:6px}
.env-select{margin-left:auto;position:relative}
.env-btn{font-family:var(--mono);font-size:11px;padding:5px 12px;border-radius:14px;cursor:pointer;border:1px solid var(--red);background:rgba(239,87,87,.1);color:var(--red)}
.env-menu{display:none;position:absolute;right:0;top:32px;background:#fff;border:1px solid var(--border);border-radius:6px;z-index:50;min-width:150px;box-shadow:0 8px 24px rgba(0,0,0,.12)}
.env-menu.open{display:block}
.env-menu div{padding:8px 12px;font-size:11.5px;font-family:var(--mono);cursor:pointer;color:var(--t2)}
.env-menu div:hover{background:#f5f6f8;color:var(--t1)}
.env-menu div.sel::before{content:'✓ ';color:var(--green)}
.body{flex:1;display:flex;min-height:0}
.sidebar{width:250px;background:var(--panel);border-right:1px solid var(--border);flex-shrink:0;padding:14px 0}
.sidebar-hdr{padding:0 16px 8px;font-size:11px;letter-spacing:.06em;color:var(--t2);font-weight:600;text-transform:uppercase}
.side-tab{padding:11px 16px;cursor:pointer;display:flex;align-items:center;gap:9px;font-size:12.5px;color:var(--t2);border-left:2px solid transparent}
.side-tab:hover{background:#f5f6f8;color:var(--t1)}
.side-tab.active{background:#eef4fb;color:var(--t1);border-left-color:var(--blue)}
.side-tab .n{width:18px;height:18px;border-radius:5px;background:#eef0f2;display:flex;align-items:center;justify-content:center;font-size:10px;font-family:var(--mono);color:var(--t3)}
.main{flex:1;overflow-y:auto;padding:20px 26px;min-width:0}
.section{display:none}
.section.active{display:block}
.sec-hdr{display:flex;align-items:baseline;gap:10px;margin-bottom:6px}
.sec-hdr h2{font-family:var(--mono);font-size:17px}
.sec-sub{color:var(--t2);font-size:12px;margin-bottom:16px;line-height:1.6}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:16px}
.panel h4{font-size:11px;letter-spacing:.05em;color:var(--t2);margin-bottom:10px;text-transform:uppercase;font-family:var(--mono)}
.fs-tree{font-family:var(--mono);font-size:12px;line-height:1.85;background:#f7f8f9;border:1px solid var(--border);padding:14px;border-radius:8px;color:#1b1b1b}
.fs-tree .allowed{color:var(--t3)}
.fs-tree .symlink{color:var(--amber)}
.fs-tree .secret{color:var(--red)}
.chip-row{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px;margin:12px 0}
.chip{background:#fdf8f0;border:1px solid var(--border);border-left:3px solid var(--amber);border-radius:8px;padding:12px;cursor:pointer}
.chip:hover{border-left-color:var(--cyan)}
.chip h5{font-family:var(--mono);font-size:12px;color:var(--amber);margin-bottom:5px}
.chip p{font-size:11px;color:var(--t2);line-height:1.5}
.chip code{display:block;font-family:var(--mono);font-size:10.5px;color:var(--t3);background:var(--bg);padding:5px 7px;margin-top:6px;border-radius:4px;word-break:break-all}
.query-row{display:flex;gap:8px;margin-top:8px}
.query-row input{flex:1;background:#fff;border:1px solid var(--border);color:var(--t1);padding:10px 12px;border-radius:7px;font-family:var(--mono);font-size:12px;outline:none}
.query-row input:focus{border-color:var(--blue)}
.btn{font-family:var(--mono);font-size:12px;font-weight:600;padding:10px 16px;border-radius:7px;border:none;cursor:pointer}
.btn-run{background:linear-gradient(135deg,var(--red),#c23a3a);color:#fff}
.btn-run:hover{filter:brightness(1.1)}
.btn-run:disabled{opacity:.6;cursor:not-allowed}
.output{background:#0d1117;border:1px solid var(--border);border-radius:8px;padding:14px;font-family:var(--mono);font-size:12px;color:#3fb950;white-space:pre-wrap;min-height:110px;max-height:280px;overflow-y:auto;line-height:1.65;margin-top:12px}
.output.err{color:var(--red)}
.res-table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11.5px}
.res-table th{background:#161c25;color:#8b97a8;text-align:left;padding:7px 10px;border-bottom:1px solid #2a3240;font-weight:600}
.res-table td{padding:7px 10px;border-bottom:1px solid #1c2430;color:#3fb950}
.statusbar{height:22px;background:var(--panelhdr);border-top:1px solid var(--border);display:flex;align-items:center;padding:0 14px;gap:16px;font-size:10.5px;color:var(--t2);flex-shrink:0;font-family:var(--mono)}
.help-fab{position:fixed;left:14px;bottom:34px;background:#fff;border:1px solid var(--border);color:var(--t1);padding:9px 14px;border-radius:20px;font-size:11.5px;display:flex;align-items:center;gap:7px;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,.12);z-index:200}
.help-fab:hover{border-color:var(--blue)}
.help-fab .q{width:18px;height:18px;border-radius:50%;background:var(--blue);color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700}
.drawer-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.3);z-index:300}
.drawer-overlay.open{display:block}
.drawer{position:fixed;left:0;top:0;bottom:0;width:480px;max-width:92vw;background:#fff;border-right:1px solid var(--border);z-index:301;transform:translateX(-100%);transition:transform .25s ease;display:flex;flex-direction:column}
.drawer.open{transform:translateX(0)}
.drawer-hdr{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.drawer-hdr h3{font-size:14.5px}
.drawer-hdr span{font-size:11px;color:var(--t2);font-family:var(--mono)}
.drawer-close{cursor:pointer;color:var(--t2);font-size:18px}
.drawer-tabs{display:flex;border-bottom:1px solid var(--border)}
.drawer-tab{flex:1;text-align:center;padding:10px;font-size:12px;color:var(--t2);cursor:pointer;border-bottom:2px solid transparent}
.drawer-tab.active{color:#fff;border-bottom-color:var(--blue)}
.drawer-body{flex:1;overflow-y:auto;padding:18px 20px}
.wt-step{margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid #f0f1f3}
.wt-step:last-child{border:none}
.wt-step .num{display:inline-flex;width:20px;height:20px;border-radius:50%;background:var(--blue);color:#fff;font-size:11px;align-items:center;justify-content:center;margin-right:8px}
.wt-step h4{display:inline;font-size:13px}
.wt-step p{margin-top:8px;font-size:12px;color:var(--t2);line-height:1.7}
.wt-step code{background:#f3f4f6;padding:2px 6px;border-radius:3px;color:var(--amber);font-family:var(--mono);font-size:11.5px}
.wt-step .try{margin-top:8px;background:#f7f7f8;border:1px solid var(--border);border-radius:5px;padding:8px 10px;font-family:var(--mono);font-size:11px;color:var(--t2);cursor:pointer}
.wt-step .try:hover{border-color:var(--blue);color:var(--blue)}
.wt-step .expect{margin-top:8px;background:rgba(47,191,113,.08);border:1px solid rgba(47,191,113,.35);border-radius:5px;padding:8px 10px;font-size:11.5px;color:#7fd9a4;line-height:1.6}
.sol-text{font-size:12.5px;line-height:1.8;color:var(--t1);white-space:pre-wrap}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:#d0d4d8;border-radius:5px}
</style>
</head>
<body>
<div class="app">
  <div class="topbar">
    <div class="logo">🗄️</div>
    <b>NimbleTech Data Console</b>
    <span class="crumb">/ mcp-tools / db + files</span>
    <span class="badge">PERMISSION ABUSE LAB · PORT 5023</span>
    <div class="env-select">
      <button class="env-btn" id="env-btn" onclick="toggleEnv()">● PRODUCTION ▾</button>
      <div class="env-menu" id="env-menu">
        <div class="sel" data-lvl="production" onclick="setEnv('production')">● Production</div>
        <div data-lvl="staging" onclick="setEnv('staging')">◐ Staging</div>
        <div data-lvl="compliance" onclick="setEnv('compliance')">✓ Compliance</div>
      </div>
    </div>
  </div>
  <div class="body">
    <div class="sidebar">
      <div class="sidebar-hdr">Connected MCP Servers</div>
      <div style="padding:0 16px 10px;font-size:10.5px;color:var(--t3);font-family:var(--mono);line-height:1.6">
        This assistant has 2 MCP servers attached — a database connector and a filesystem connector — the same way Continue or Claude Desktop lets one assistant reach several backend tools at once.
      </div>
      <div class="sidebar-hdr" style="padding-top:4px;font-size:10px;opacity:.7">server: postgres-prod</div>
      <div class="side-tab active" data-tab="db" onclick="selectTab('db',this)"><span class="n">DB</span> Database Query</div>
      <div class="sidebar-hdr" style="padding-top:10px;font-size:10px;opacity:.7">server: filesystem</div>
      <div class="side-tab" data-tab="trav" onclick="selectTab('trav',this)"><span class="n">FS</span> File Browser</div>
      <div class="side-tab" data-tab="sym" onclick="selectTab('sym',this)"><span class="n">SL</span> Symlink Probe</div>
    </div>
    <div class="main">
      <!-- DB Section -->
      <div class="section active" id="sec-db">
        <div class="sec-hdr"><h2>Database Query Tool</h2></div>
        <div class="sec-sub">This MCP tool connects to the production database as <b>mcpuser</b> and translates natural-language requests into SQL.</div>
        <div class="panel">
          <div class="query-row"><input id="q-db" placeholder="Ask the DB tool anything..."></div>
          <button class="btn btn-run" onclick="run('db')">Run Query</button>
          <div class="output" id="out-db">// Query results will appear here...</div>
        </div>
      </div>
      <!-- Traversal Section -->
      <div class="section" id="sec-trav">
        <div class="sec-hdr"><h2>File Browser Tool</h2></div>
        <div class="sec-sub">Reads files from the workspace on behalf of the assistant, scoped to an allowed set of folders.</div>
        <div class="panel">
          <h4>Sandbox Layout</h4>
          <div class="fs-tree">/data/
├── documents/           <span class="allowed">(allowed)</span>
│   ├── welcome.txt
│   ├── employee-handbook.md
│   └── q1-report.pdf
├── projects/            <span class="allowed">(allowed)</span>
│   ├── api-docs/spec.yaml
│   └── <span class="symlink">vendor-docs → /data/secrets   (SYMLINK)</span>
├── <span class="secret">.secrets/credentials.json  (denied)</span>
└── <span class="secret">secrets/prod.env  (denied — reachable via symlink)</span></div>
        </div>
        <div class="panel">
          <div class="query-row"><input id="q-trav" placeholder="Ask the file tool to read a path..."></div>
          <button class="btn btn-run" onclick="run('trav')">Read File</button>
          <div class="output" id="out-trav">// File contents will appear here...</div>
        </div>
      </div>
      <!-- Symlink Section -->
      <div class="section" id="sec-sym">
        <div class="sec-hdr"><h2>Symlink Probe</h2></div>
        <div class="sec-sub">Lists and reads files the same way the File Browser tool does, useful for exploring linked folders.</div>
        <div class="panel">
          <div class="query-row"><input id="q-sym" placeholder="Ask the tool to list or read a path..."></div>
          <button class="btn btn-run" onclick="run('sym')">Execute</button>
          <div class="output" id="out-sym">// Tool response will appear here...</div>
        </div>
      </div>
    </div>
  </div>
  <div class="statusbar">
    <span>data-console.nimbletech.internal</span><span>|</span>
    <span id="sb-env">Env: Production</span>
    <span style="margin-left:auto">MCP host: localhost:5023</span>
  </div>
</div>

<div class="help-fab" onclick="openDrawer('walkthrough')"><span class="q">?</span> Need help? — Solutions &amp; Walkthrough</div>
<div class="drawer-overlay" id="overlay" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <div class="drawer-hdr">
    <div><h3>Permission Abuse, Path Traversal &amp; Symlink Escape</h3><span>Module 7 · Part 3</span></div>
    <div class="drawer-close" onclick="closeDrawer()">✕</div>
  </div>
  <div class="drawer-tabs">
    <div class="drawer-tab active" data-t="walkthrough" onclick="switchTab('walkthrough')">Walkthrough</div>
    <div class="drawer-tab" data-t="solution" onclick="switchTab('solution')">Root Cause &amp; Fix</div>
  </div>
  <div class="drawer-body" id="drawer-body"></div>
</div>

<script>
const WALKTHROUGH = {{WT_JSON}};
const SOLUTION = {{SOL_JSON}};

function selectTab(tab, el){
  document.querySelectorAll('.side-tab').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('.section').forEach(x=>x.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('sec-'+tab).classList.add('active');
}
function setQ(tab, t){ document.getElementById('q-'+tab).value = t; }

function toggleEnv(){ document.getElementById('env-menu').classList.toggle('open'); }
async function setEnv(lvl){
  document.getElementById('env-menu').classList.remove('open');
  const labels = {production:'● PRODUCTION',staging:'◐ STAGING',compliance:'✓ COMPLIANCE'};
  const colors = {production:'#ef5757',staging:'#e2a33d',compliance:'#2fbf71'};
  const bg = {production:'rgba(239,87,87,.1)',staging:'rgba(226,163,61,.1)',compliance:'rgba(47,191,113,.1)'};
  const btn = document.getElementById('env-btn');
  btn.textContent = labels[lvl] + ' ▾';
  btn.style.color = colors[lvl]; btn.style.borderColor = colors[lvl]; btn.style.background = bg[lvl];
  document.getElementById('sb-env').textContent = 'Env: ' + lvl[0].toUpperCase()+lvl.slice(1);
  document.querySelectorAll('.env-menu div').forEach(d=>d.classList.toggle('sel', d.dataset.lvl===lvl));
  await fetch('/defense', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({level:lvl})});
}
document.addEventListener('click', e=>{
  if(!e.target.closest('.env-select')) document.getElementById('env-menu').classList.remove('open');
});

function renderTable(rows){
  if(!rows || rows.length===0) return '';
  const cols = Object.keys(rows[0]);
  let t = '<table class="res-table"><thead><tr>' + cols.map(c=>`<th>${c}</th>`).join('') + '</tr></thead><tbody>';
  rows.forEach(r=> t += '<tr>' + cols.map(c=>`<td>${r[c]}</td>`).join('') + '</tr>');
  t += '</tbody></table>';
  return t;
}
async function run(tab){
  const q = document.getElementById('q-'+tab).value.trim();
  const out = document.getElementById('out-'+tab);
  const btn = event.target;
  if(!q){ out.classList.add('err'); out.textContent = 'Enter or select a query first.'; return; }
  out.classList.remove('err');
  btn.disabled = true; const orig = btn.textContent; btn.textContent = 'Running…';
  out.innerHTML = '// Processing...';
  try{
    const r = await fetch('/exec', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({mode:tab, q})});
    if(!r.ok){
      out.classList.add('err');
      out.textContent = `[HTTP ${r.status}] Server error — check container logs (docker compose logs -f mcp-permissions).`;
      return;
    }
    const d = await r.json();
    if(d.rows && d.rows.length){
      out.innerHTML = `<div style="color:#8b97a8;margin-bottom:8px">${d.result}</div>` + renderTable(d.rows);
    } else {
      out.textContent = d.result;
    }
  }catch(e){
    out.classList.add('err');
    out.textContent = `[NETWORK ERROR] Could not reach the tool: ${e.message}`;
  }finally{
    btn.disabled = false; btn.textContent = orig;
  }
}

function openDrawer(tab){ document.getElementById('overlay').classList.add('open'); document.getElementById('drawer').classList.add('open'); switchTab(tab); }
function closeDrawer(){ document.getElementById('overlay').classList.remove('open'); document.getElementById('drawer').classList.remove('open'); }
function tryQuery(q, tab){
  const tabEl = document.querySelector(`.side-tab[data-tab="${tab}"]`);
  if(tabEl) selectTab(tab, tabEl);
  document.getElementById('q-'+tab).value = q;
  closeDrawer();
  document.getElementById('q-'+tab).focus();
}
function switchTab(t){
  document.querySelectorAll('.drawer-tab').forEach(x=>x.classList.toggle('active', x.dataset.t===t));
  const body = document.getElementById('drawer-body');
  if(t==='walkthrough'){
    body.innerHTML = WALKTHROUGH.map((s,i)=>`
      <div class="wt-step">
        <span class="num">${i+1}</span><h4>${s.title}</h4>
        <p>${s.body}</p>
        ${s.query ? `<div class="try" onclick='tryQuery(${JSON.stringify(s.query)}, ${JSON.stringify(s.tab)})'>▶ Try: "${s.query}"</div>` : ''}
        ${s.expect ? `<div class="expect">👀 <b>What you should see:</b> ${s.expect}</div>` : ''}
      </div>`).join('');
  } else {
    body.innerHTML = `<div class="sol-text">${SOLUTION.replace(/</g,'&lt;')}</div>`;
  }
}
</script>
</body>
</html>"""

# ---------------- Path helpers ----------------
def vulnerable_path_check(path):
    if not path.startswith("/data/documents/") and not path.startswith("/data/projects/"):
        return None, "Access denied: must start with /data/documents/ or /data/projects/"
    real = os.path.normpath(path)
    for k, v in VFS.items():
        if k.startswith("__SYMLINK__"):
            link_from = k.replace("__SYMLINK__", "")
            if real.startswith(link_from):
                real = real.replace(link_from, v, 1)
    return real, None

def hardened_path_check(path):
    real = os.path.normpath(path)
    for k, v in VFS.items():
        if k.startswith("__SYMLINK__"):
            link_from = k.replace("__SYMLINK__", "")
            if real.startswith(link_from):
                real = real.replace(link_from, v, 1)
    if not (real.startswith("/data/documents/") or real.startswith("/data/projects/")):
        return None, f"Access denied (staging): resolved path {real} is outside the sandbox."
    return real, None

# ---------------- Routes ----------------
@app.route("/")
def index():
    html = HTML.replace("{{WT_JSON}}", json.dumps(WALKTHROUGH))
    html = html.replace("{{SOL_JSON}}", json.dumps(SOLUTION_NOTES))
    return render_template_string(html)

@app.route("/defense", methods=["POST"])
def defense():
    data = request.get_json(force=True) or {}
    DEFENSE_LEVEL["current"] = data.get("level", "production")
    return jsonify({"ok": True, "level": DEFENSE_LEVEL["current"]})

@app.route("/exec", methods=["POST"])
def execute():
    data = request.get_json(force=True) or {}
    mode = data.get("mode")
    q = data.get("q", "")
    lvl = DEFENSE_LEVEL["current"]

    if lvl == "compliance":
        bad = ["api_keys", "customer_pii", "ssn", "..", ".secrets", "vendor-docs", "prod.env", "credentials.json"]
        if any(b in q.lower() for b in bad):
            return jsonify({"result": "[COMPLIANCE] Refused — this query or path matches a sensitive-data pattern. The request was blocked and logged to SIEM."})

    if mode == "db":
        ql = q.lower()
        if "information_schema" in ql or ("list" in ql and "table" in ql):
            rows = [{"table_name": t} for t in ["customers", "customer_pii", "api_keys", "financial_records", "agent_sessions"]]
            return jsonify({"result": "5 tables found.", "rows": rows})
        if "customer_pii" in ql or "pii" in ql or "ssn" in ql:
            if lvl == "staging":
                rows = [{"id": r["id"], "ssn": f"***-**-{r['ssn'][-4:]}", "dob": "****", "address": "[REDACTED]"} for r in DB_TABLES["customer_pii"]]
                return jsonify({"result": "[STAGING] Column masking applied.", "rows": rows})
            rows = DB_TABLES["customer_pii"]
            return jsonify({"result": "PII join result.", "rows": rows})
        if "api_keys" in ql or "api key" in ql:
            if lvl == "staging":
                return jsonify({"result": "[STAGING] api_keys table access denied for non-admin role."})
            rows = DB_TABLES["api_keys"]
            return jsonify({"result": "api_keys contents.", "rows": rows})
        if "role" in ql or "privilege" in ql:
            if lvl == "staging":
                return jsonify({"result": "Current role: mcp_readonly\nPrivileges: SELECT only on customers, financial_records (masked columns on PII/keys tables)"})
            return jsonify({"result": "Current role: mcpuser\nPrivileges: OWNER on public schema (full read/write/grant)"})
        return jsonify({"result": "[DB tool] Couldn't parse that request. Try asking about tables, roles, PII, or API keys."})

    if mode == "trav":
        m = re.search(r"(/data/[^\s'\"]+)", q)
        if not m:
            return jsonify({"result": "[file tool] No path found in request."})
        path = m.group(1)
        real, err = hardened_path_check(path) if lvl == "staging" else vulnerable_path_check(path)
        if err:
            return jsonify({"result": err})
        content = VFS.get(real)
        if content is None:
            return jsonify({"result": f"[file tool] Path resolved to: {real}\nFile not found."})
        return jsonify({"result": f"[file tool] Resolved path: {real}\n---\n{content}"})

    if mode == "sym":
        m = re.search(r"(/data/[^\s'\"]+)", q)
        if not m:
            return jsonify({"result": "[symlink tool] No path found."})
        path = m.group(1)
        if "list" in q.lower():
            if path.rstrip("/") == "/data/projects":
                return jsonify({"result": "Listing /data/projects/:\n- api-docs/\n- vendor-docs -> /data/secrets (symlink)"})
            if "vendor-docs" in path:
                if lvl == "staging":
                    return jsonify({"result": "[STAGING] Symlink crossing detected via realpath() resolution -> access denied (resolves to /data/secrets, outside sandbox)."})
                return jsonify({"result": "Listing /data/projects/vendor-docs/:\n- prod.env"})
            return jsonify({"result": f"Listing {path}:\n(no entries)"})
        real, err = hardened_path_check(path) if lvl == "staging" else vulnerable_path_check(path)
        if err:
            return jsonify({"result": err})
        content = VFS.get(real)
        if content is None:
            return jsonify({"result": f"[file tool] Resolved to: {real}\nFile not found."})
        return jsonify({"result": f"[file tool] Resolved to: {real}\n---\n{content}"})

    return jsonify({"result": "unknown mode"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5023)
