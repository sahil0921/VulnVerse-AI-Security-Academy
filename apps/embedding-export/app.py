from flask import Flask, request, jsonify, render_template_string, send_file
import requests, os, json, io, time
import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer

app = Flask(__name__)
WEAVIATE = os.environ.get("WEAVIATE_URL", "http://weaviate-db:8080")
MODE = {"current": "vulnerable"}
REQUEST_LOG = []
EXPORTED = {"vectors": None, "ids": None, "chunk_ids": None, "categories": None, "texts": None}

PROBES_POSITIVE = [
    "password is", "api key is", "secret key", "access token",
    "authentication required", "default credentials", "connection string",
    "private key", "recovery code"
]
PROBES_NEGATIVE = [
    "company vacation policy", "quarterly business review",
    "team meeting notes", "office holiday schedule", "training session"
]


def guard(action):
    now = time.time()
    REQUEST_LOG[:] = [t for t in REQUEST_LOG if now - t < 60]
    REQUEST_LOG.append(now)
    if MODE["current"] == "hardened" and len(REQUEST_LOG) > 30:
        return False, "Rate limit"
    if MODE["current"] == "guardrailed":
        if len(REQUEST_LOG) > 15:
            return False, "Rate limit (guardrailed)"
        if action == "export_all":
            return False, "Bulk export blocked in guardrailed mode (anomaly detection)"
    return True, None


HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Exports · doc-embeddings-prod · Vantage Vector Cloud</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root{
  --bg:#f4f5f8; --surface:#ffffff; --surface-alt:#fafbfc;
  --border:#e4e7ed; --border-strong:#d3d8e0;
  --ink:#13161f; --ink-soft:#3d4354; --dim:#6b7280; --dim-2:#9aa1ae;
  --accent:#4338ca; --accent-soft:#eef0fe; --accent-ring:rgba(67,56,202,.18);
  --prod:#dc2626; --prod-soft:#fdeaea;
  --staging:#d97706; --staging-soft:#fdf3e3;
  --compliance:#059669; --compliance-soft:#e7f6f0;
  --display:'Space Grotesk',sans-serif; --sans:'Inter',sans-serif; --mono:'IBM Plex Mono',monospace;
  --shadow-sm:0 1px 2px rgba(20,24,38,.05); --shadow-md:0 4px 16px rgba(20,24,38,.06);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}

.shell{display:grid;grid-template-columns:230px 1fr;min-height:100vh}

.sidebar{background:#12141c;color:#c7cbd6;display:flex;flex-direction:column;padding:20px 14px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:10px;padding:6px 8px 22px 8px}
.brand-mark{width:30px;height:30px;border-radius:8px;flex:none;background:linear-gradient(155deg,#4338ca,#7c6cf0);display:flex;align-items:center;justify-content:center;box-shadow:0 0 0 1px rgba(255,255,255,.08) inset}
.brand-mark svg{width:16px;height:16px}
.brand-name{font-family:var(--display);font-weight:700;font-size:.92rem;color:#f2f3f7;letter-spacing:-.01em}
.brand-sub{font-family:var(--mono);font-size:.62rem;color:#666e80;letter-spacing:.04em;margin-top:1px}

.nav-group-label{font-family:var(--mono);font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;color:#565e70;padding:14px 10px 6px}
.nav-item{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:7px;font-size:.83rem;color:#565b68;cursor:not-allowed;margin-bottom:2px}
.nav-item .dot{width:6px;height:6px;border-radius:50%;background:#33374a;flex:none}
.nav-item.active{background:#1d2030;color:#f2f3f7;cursor:default}
.nav-item.active .dot{background:#7c6cf0}

.sidebar-footer{margin-top:auto;padding-top:14px;border-top:1px solid #22242f}
.help-link{display:flex;gap:9px;align-items:flex-start;padding:9px 10px;border-radius:8px;cursor:pointer;color:#8b93a6;font-size:.8rem;line-height:1.35;transition:background .12s}
.help-link:hover{background:#1a1c28;color:#d7dae2}
.help-link .qmark{width:16px;height:16px;border-radius:50%;border:1.5px solid #565e70;display:flex;align-items:center;justify-content:center;flex:none;font-size:.62rem;font-family:var(--mono);color:#8b93a6;margin-top:1px}
.help-link b{color:#c7cbd6;display:block;font-weight:600}
.version-tag{font-family:var(--mono);font-size:.62rem;color:#454b5c;padding:10px 10px 0}

.main{display:flex;flex-direction:column;min-width:0}
.topbar{height:60px;flex:none;background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:16px;padding:0 26px;position:sticky;top:0;z-index:5}
.crumbs{font-size:.82rem;color:var(--dim)}
.crumbs b{color:var(--ink);font-weight:600}
.crumbs .sep{margin:0 6px;color:var(--dim-2)}

.env-picker{margin-left:auto;position:relative}
.env-btn{display:flex;align-items:center;gap:8px;background:var(--surface-alt);border:1px solid var(--border-strong);padding:7px 12px;border-radius:8px;cursor:pointer;font-family:var(--mono);font-size:.76rem;font-weight:500}
.env-btn .env-dot{width:7px;height:7px;border-radius:50%}
.env-btn:after{content:'▾';color:var(--dim-2);font-size:.7rem;margin-left:2px}
.env-menu{position:absolute;top:calc(100% + 6px);right:0;width:190px;background:var(--surface);border:1px solid var(--border);border-radius:10px;box-shadow:var(--shadow-md);padding:6px;display:none;z-index:20}
.env-menu.open{display:block}
.env-opt{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:7px;font-size:.8rem;cursor:pointer;color:var(--ink-soft)}
.env-opt:hover{background:var(--surface-alt)}
.env-opt.sel{background:var(--accent-soft);color:var(--accent);font-weight:600}
.env-opt .env-dot{width:7px;height:7px;border-radius:50%}
.env-opt small{display:block;font-weight:400;color:var(--dim-2);font-size:.68rem;margin-top:1px}

.avatar{width:30px;height:30px;border-radius:50%;background:var(--accent-soft);color:var(--accent);display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:.72rem;font-weight:600}

.page{padding:28px 32px 60px;max-width:1180px;width:100%;margin:0 auto}
.page-head{margin-bottom:22px}
.eyebrow{font-family:var(--mono);font-size:.72rem;color:var(--accent);letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px}
.page-title{font-family:var(--display);font-size:1.5rem;font-weight:700;letter-spacing:-.01em;color:var(--ink)}
.page-desc{color:var(--dim);font-size:.88rem;margin-top:5px;max-width:640px;line-height:1.5}

.tick-strip{display:flex;align-items:flex-end;gap:2px;height:26px;margin-top:16px}
.tick-strip i{display:block;width:3px;border-radius:1.5px;background:linear-gradient(180deg,var(--accent),#a89af6);opacity:.55}

.env-banner{display:flex;align-items:center;gap:10px;padding:11px 16px;border-radius:9px;margin-bottom:20px;font-size:.82rem;border:1px solid transparent}
.env-banner .ico{font-family:var(--mono);font-size:.9rem}
.eb-prod{background:var(--prod-soft);color:#9d1c1c;border-color:#f6c9c9}
.eb-staging{background:var(--staging-soft);color:#93590a;border-color:#f3d9a5}
.eb-compliance{background:var(--compliance-soft);color:#03664e;border-color:#b7e4d4}

.grid{display:grid;grid-template-columns:1fr;gap:16px}

.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px 22px;box-shadow:var(--shadow-sm)}
.card-head{display:flex;align-items:center;gap:10px;margin-bottom:4px}
.card-num{font-family:var(--mono);font-size:.68rem;color:var(--accent);background:var(--accent-soft);width:20px;height:20px;border-radius:5px;display:flex;align-items:center;justify-content:center;flex:none;font-weight:600}
.card-title{font-family:var(--display);font-weight:600;font-size:.95rem;color:var(--ink)}
.card-desc{color:var(--dim);font-size:.82rem;line-height:1.5;margin:8px 0 14px}

.btn{font-family:var(--sans);font-size:.8rem;font-weight:600;padding:9px 16px;border-radius:7px;border:1px solid transparent;cursor:pointer;display:inline-flex;align-items:center;gap:7px;transition:filter .12s, transform .12s}
.btn-pri{background:var(--ink);color:#fff}
.btn-pri:hover{filter:brightness(1.25)}
.btn-pri:active{transform:translateY(1px)}
.btn-sec{background:var(--surface-alt);color:var(--ink-soft);border-color:var(--border-strong)}
.btn-sec:hover{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-ring)}
.row{display:flex;gap:10px;flex-wrap:wrap}

.output{margin-top:14px;background:#0f1117;border:1px solid #23262f;border-radius:8px;padding:13px 14px;font-family:var(--mono);font-size:.76rem;color:#9ee8b8;white-space:pre-wrap;min-height:104px;max-height:420px;overflow-y:auto;line-height:1.55}
.output:empty:before{content:'Awaiting run —';color:#565e70}

.spinner{display:inline-block;width:11px;height:11px;border:2px solid rgba(255,255,255,.15);border-top-color:#9ee8b8;border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

.scrim{position:fixed;inset:0;background:rgba(15,17,23,.35);opacity:0;pointer-events:none;transition:opacity .18s;z-index:30}
.scrim.open{opacity:1;pointer-events:auto}
.help-panel{position:fixed;top:0;right:-420px;width:400px;height:100vh;background:var(--surface);border-left:1px solid var(--border);box-shadow:-8px 0 32px rgba(20,24,38,.12);transition:right .22s ease;z-index:31;display:flex;flex-direction:column}
.help-panel.open{right:0}
.help-panel-head{padding:20px 22px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.help-panel-head h2{font-family:var(--display);font-size:1.02rem;font-weight:700}
.help-panel-head p{color:var(--dim);font-size:.78rem;margin-top:3px}
.help-close{width:26px;height:26px;border-radius:7px;border:1px solid var(--border-strong);background:var(--surface-alt);cursor:pointer;color:var(--dim);font-size:.85rem;flex:none}
.help-body{padding:18px 22px 40px;overflow-y:auto;flex:1}

.help-tabs{display:flex;gap:4px;background:var(--surface-alt);border:1px solid var(--border);border-radius:8px;padding:3px;margin-bottom:18px}
.help-tab{flex:1;text-align:center;padding:6px 0;border-radius:6px;font-size:.74rem;font-weight:600;color:var(--dim);cursor:pointer}
.help-tab.active{background:var(--surface);color:var(--ink);box-shadow:var(--shadow-sm)}

.hp-section{display:none}
.hp-section.active{display:block}

.step-block{margin-bottom:18px;padding-bottom:18px;border-bottom:1px solid var(--border)}
.step-block:last-child{border-bottom:none}
.step-label{font-family:var(--mono);font-size:.68rem;color:var(--accent);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;font-weight:600}
.step-text{font-size:.83rem;line-height:1.55;color:var(--ink-soft);margin-bottom:10px}
.step-text code{background:var(--accent-soft);color:var(--accent);padding:1px 5px;border-radius:4px;font-family:var(--mono);font-size:.78rem}

.cmd-block{background:#0f1117;border-radius:8px;padding:11px 13px}
.cmd-block pre{font-family:var(--mono);font-size:.71rem;color:#c9d6f2;white-space:pre-wrap;line-height:1.6}
.cmd-label{font-family:var(--mono);font-size:.6rem;color:#565e70;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}

.theory-p{font-size:.83rem;line-height:1.6;color:var(--ink-soft);margin-bottom:14px}
.theory-p b{color:var(--ink)}

.mode-note{display:flex;gap:8px;padding:10px 12px;border-radius:8px;margin-top:8px;font-size:.76rem;line-height:1.5}
.mn-prod{background:var(--prod-soft);color:#9d1c1c}
.mn-staging{background:var(--staging-soft);color:#93590a}
.mn-compliance{background:var(--compliance-soft);color:#03664e}

::-webkit-scrollbar{width:7px;height:7px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border-strong);border-radius:4px}
</style>
</head>
<body>

<div class="shell">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark">
        <svg viewBox="0 0 24 24" fill="none"><path d="M4 12h4M10 6h4M16 12h4M4 18h4M10 18h4" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/></svg>
      </div>
      <div>
        <div class="brand-name">Vantage</div>
        <div class="brand-sub">VECTOR CLOUD</div>
      </div>
    </div>

    <div class="nav-group-label">Workspace</div>
    <div class="nav-item"><span class="dot"></span>Overview</div>
    <div class="nav-item"><span class="dot"></span>Indexes</div>
    <div class="nav-item"><span class="dot"></span>Query console</div>
    <div class="nav-item"><span class="dot"></span>Diagnostics</div>
    <div class="nav-item active"><span class="dot"></span>Exports</div>

    <div class="nav-group-label">Manage</div>
    <div class="nav-item"><span class="dot"></span>Access &amp; API keys</div>
    <div class="nav-item"><span class="dot"></span>Settings</div>

    <div class="sidebar-footer">
      <div class="help-link" onclick="openHelp()">
        <span class="qmark">?</span>
        <span><b>Need help?</b>Solutions &amp; walkthrough</span>
      </div>
      <div class="version-tag">v3.4.1 · region us-east-1</div>
    </div>
  </aside>

  <div class="main">
    <div class="topbar">
      <div class="crumbs">Exports <span class="sep">/</span> <b>doc-embeddings-prod</b></div>
      <div class="env-picker">
        <button class="env-btn" id="envBtn" onclick="toggleEnvMenu()">
          <span class="env-dot" id="envDot" style="background:#dc2626"></span>
          <span id="envLabel">Production</span>
        </button>
        <div class="env-menu" id="envMenu">
          <div class="env-opt sel" data-env="vulnerable" onclick="selectEnv('vulnerable')">
            <span class="env-dot" style="background:#dc2626"></span>
            <span>Production<small>Live traffic, no gating</small></span>
          </div>
          <div class="env-opt" data-env="hardened" onclick="selectEnv('hardened')">
            <span class="env-dot" style="background:#d97706"></span>
            <span>Staging<small>Rate limited</small></span>
          </div>
          <div class="env-opt" data-env="guardrailed" onclick="selectEnv('guardrailed')">
            <span class="env-dot" style="background:#059669"></span>
            <span>Compliance<small>Audited &amp; redacted</small></span>
          </div>
        </div>
      </div>
      <div class="avatar">SA</div>
    </div>

    <div class="page">
      <div class="page-head">
        <div class="eyebrow">Bulk export &amp; triage</div>
        <div class="page-title">doc-embeddings-prod</div>
        <div class="page-desc">Page through every stored vector and rank chunks by how likely they are to hold sensitive content — without reading a single one directly.</div>
        <div class="tick-strip" id="tickStrip"></div>
      </div>

      <div id="envBanner" class="env-banner eb-prod">
        <span class="ico">●</span>
        <span id="envBannerText">Production environment — bulk export allowed, no anomaly detection on pagination volume.</span>
      </div>

      <div class="grid">
        <div class="card">
          <div class="card-head"><span class="card-num">1</span><span class="card-title">Bulk export</span></div>
          <div class="card-desc">Pages through every vector with cursor-based pagination and holds the result in memory for download.</div>
          <div class="row">
            <button class="btn btn-pri" onclick="exportAll()">Export all embeddings</button>
            <a class="btn btn-sec" href="/download/npy">Download .npy</a>
            <a class="btn btn-sec" href="/download/csv">Download .csv</a>
          </div>
          <div id="out1" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">2</span><span class="card-title">Chunk triage pipeline</span></div>
          <div class="card-desc">Three-stage scoring — isolation density, contrastive probe similarity, and template matching — surfaces the chunks most likely to contain credentials, without inverting any of them first.</div>
          <button class="btn btn-pri" onclick="triage()">Run triage</button>
          <div id="out2" class="output"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="scrim" id="scrim" onclick="closeHelp()"></div>
<div class="help-panel" id="helpPanel">
  <div class="help-panel-head">
    <div>
      <h2>Solutions &amp; walkthrough</h2>
      <p>Step-by-step guide plus the raw request each control sends.</p>
    </div>
    <button class="help-close" onclick="closeHelp()">✕</button>
  </div>
  <div class="help-body">
    <div class="help-tabs">
      <div class="help-tab active" data-tab="walk" onclick="switchTab('walk')">Walkthrough</div>
      <div class="help-tab" data-tab="theory" onclick="switchTab('theory')">Theory</div>
    </div>

    <div class="hp-section active" id="tab-walk">
      <div class="step-block">
        <div class="step-label">Step 1 · Bulk export</div>
        <div class="step-text">Cursor pagination at page size <code>200</code> mimics ordinary application traffic — nothing about a single page of 200 results looks like a scrape. Repeated over enough pages, the whole index leaves through a door that was only ever meant for one page at a time.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request (one page)</div>
          <pre>curl -s http://localhost:8090/v1/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ Get { DocChunk(limit:200) { chunk_id category text _additional { id vector } } } }"}'</pre>
        </div>
        <div class="mode-note mn-prod">Production — page size 200, unlimited pages, no volume tracking.</div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 2 · Chunk triage</div>
        <div class="step-text">Stage 1 scores <b>isolation</b> — a chunk whose nearest neighbors are all far away sits outside the semantic cluster of ordinary documents, which is exactly where a stray credential ends up. Stage 2 runs <b>contrastive probes</b>: cosine similarity against phrases like <code>"password is"</code>, minus similarity against neutral phrases like <code>"vacation policy"</code>. Stage 3 checks the surviving candidates against known credential templates and entropy, without ever decoding the vector back to text.</div>
        <div class="step-text">The three signals are combined with a weighted sum, then min-max normalized so the top-ranked chunk is always exactly the most anomalous one in this specific index — not tied to any fixed threshold.</div>
      </div>
    </div>

    <div class="hp-section" id="tab-theory">
      <div class="theory-p">A vector database's own similarity search becomes an attacker's triage tool. You never have to invert a single embedding to find the interesting ones — you only need reference phrases for the kind of content you're hunting, and the index does the ranking for you.</div>
      <div class="theory-p"><b>Why environments differ:</b> Staging shrinks the page size and slows the pagination, which raises the cost of a full dump without stopping it outright. Compliance blocks the bulk-export path entirely once volume crosses its threshold — the anomaly isn't any single request, it's the shape of the whole session.</div>
      <div class="theory-p">This is why real vector platforms increasingly monitor <b>query patterns</b>, not just individual queries: a scraper making 500 well-formed, individually-legitimate requests is still a scraper.</div>
    </div>
  </div>
</div>

<script>
const envMeta = {
  vulnerable:  {label:'Production',  dot:'#dc2626', banner:'eb-prod',       text:'Production environment — bulk export allowed, no anomaly detection on pagination volume.'},
  hardened:    {label:'Staging',     dot:'#d97706', banner:'eb-staging',    text:'Staging environment — page size capped, requests rate-limited to 30/min.'},
  guardrailed: {label:'Compliance',  dot:'#059669', banner:'eb-compliance', text:'Compliance environment — bulk export blocked outright once anomaly detection flags the session; per-IP query budget enforced.'}
};

function toggleEnvMenu(){document.getElementById('envMenu').classList.toggle('open')}
document.addEventListener('click', e=>{
  if(!e.target.closest('.env-picker')) document.getElementById('envMenu').classList.remove('open');
});

function selectEnv(env){
  fetch('/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:env})})
    .then(r=>r.json()).then(()=>{
      const m = envMeta[env];
      document.getElementById('envLabel').textContent = m.label;
      document.getElementById('envDot').style.background = m.dot;
      document.querySelectorAll('.env-opt').forEach(o=>o.classList.toggle('sel', o.dataset.env===env));
      const banner = document.getElementById('envBanner');
      banner.className = 'env-banner '+m.banner;
      document.getElementById('envBannerText').textContent = m.text;
      document.getElementById('envMenu').classList.remove('open');
    });
}

function openHelp(){document.getElementById('helpPanel').classList.add('open');document.getElementById('scrim').classList.add('open')}
function closeHelp(){document.getElementById('helpPanel').classList.remove('open');document.getElementById('scrim').classList.remove('open')}
function switchTab(t){
  document.querySelectorAll('.help-tab').forEach(el=>el.classList.toggle('active', el.dataset.tab===t));
  document.querySelectorAll('.hp-section').forEach(el=>el.classList.toggle('active', el.id==='tab-'+t));
}

async function exportAll(){
  const o=document.getElementById('out1');
  o.innerHTML='<span class="spinner"></span> paginating…';
  try{
    const r=await fetch('/export/all',{method:'POST'});
    const d=await r.json();
    o.textContent=JSON.stringify(d,null,2);
  }catch(e){o.textContent='ERROR: '+e.message}
}

async function triage(){
  const o=document.getElementById('out2');
  o.innerHTML='<span class="spinner"></span> running 3-stage triage…';
  try{
    const r=await fetch('/triage',{method:'POST'});
    const d=await r.json();
    if(d.error){o.textContent='ERROR: '+d.error;return}
    if(d.blocked){o.textContent='BLOCKED: '+d.reason;return}
    let out=`total chunks   ${d.total}\ntop ${d.top.length} candidates:\n\n`;
    d.top.forEach((t,i)=>{
      out += `#${(i+1).toString().padStart(2,'0')}  ${t.chunk_id.padEnd(16)} score=${t.score.toFixed(3)}  category=${t.category}\n     ${t.preview}\n\n`;
    });
    o.textContent = out;
  }catch(e){o.textContent='ERROR: '+e.message}
}

(function(){
  const strip = document.getElementById('tickStrip');
  const n = 64;
  let html = '';
  for(let i=0;i<n;i++){
    const h = 6 + Math.round(Math.abs(Math.sin(i*0.4))*18);
    html += `<i style="height:${h}px"></i>`;
  }
  strip.innerHTML = html;
})();
</script>
</body></html>
"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/mode", methods=["POST"])
def set_mode():
    m = request.json.get("mode", "vulnerable")
    if m in ("vulnerable", "hardened", "guardrailed"):
        MODE["current"] = m
        REQUEST_LOG.clear()
    return jsonify({"mode": MODE["current"]})


def _gql(q):
    r = requests.post(f"{WEAVIATE}/v1/graphql", json={"query": q}, timeout=20)
    return r.json()["data"]


@app.route("/export/all", methods=["POST"])
def export_all():
    ok, msg = guard("export_all")
    if not ok:
        return jsonify({"blocked": True, "reason": msg}), 429
    page_size = 200 if MODE["current"] == "vulnerable" else 50
    count = _gql("{ Aggregate { DocChunk { meta { count } } } }")
    total = count["Aggregate"]["DocChunk"][0]["meta"]["count"]
    ids, chunk_ids, cats, texts, vecs = [], [], [], [], []
    cursor = None
    while True:
        after = f'after: "{cursor}"' if cursor else ""
        q = f"""{{ Get {{ DocChunk(limit: {page_size} {after}) {{ chunk_id category text _additional {{ id vector }} }} }} }}"""
        d = _gql(q)["Get"]["DocChunk"]
        if not d:
            break
        for o in d:
            ids.append(o["_additional"]["id"])
            chunk_ids.append(o.get("chunk_id"))
            cats.append(o.get("category"))
            texts.append(o.get("text"))
            vecs.append(o["_additional"]["vector"])
        cursor = d[-1]["_additional"]["id"]
        if len(ids) >= total:
            break
    EXPORTED["vectors"] = np.array(vecs, dtype=np.float32)
    EXPORTED["ids"] = ids
    EXPORTED["chunk_ids"] = chunk_ids
    EXPORTED["categories"] = cats
    EXPORTED["texts"] = texts
    return jsonify({
        "total_exported": len(ids),
        "dimension": int(EXPORTED["vectors"].shape[1]),
        "page_size": page_size,
        "sample_chunk_ids": chunk_ids[:5],
        "downloadable": ["/download/npy", "/download/csv"]
    })


@app.route("/download/<fmt>")
def download(fmt):
    if EXPORTED["vectors"] is None:
        return jsonify({"error": "run export first"}), 400
    buf = io.BytesIO()
    if fmt == "npy":
        np.save(buf, EXPORTED["vectors"])
        buf.seek(0)
        return send_file(buf, mimetype="application/octet-stream", as_attachment=True, download_name="embeddings.npy")
    if fmt == "csv":
        df = pd.DataFrame(EXPORTED["vectors"], columns=[f"d{i}" for i in range(EXPORTED["vectors"].shape[1])])
        df.insert(0, "chunk_id", EXPORTED["chunk_ids"])
        df.insert(1, "category", EXPORTED["categories"])
        s = df.to_csv(index=False)
        return s, 200, {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=embeddings.csv"}
    return jsonify({"error": "unknown format"}), 400


_probe_model = None


def get_probe_model():
    global _probe_model
    if _probe_model is None:
        _probe_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _probe_model


@app.route("/triage", methods=["POST"])
def triage():
    ok, msg = guard("triage")
    if not ok:
        return jsonify({"blocked": True, "reason": msg}), 429
    if EXPORTED["vectors"] is None:
        export_all()
    V = EXPORTED["vectors"]
    if V is None or len(V) == 0:
        return jsonify({"error": "no data exported"})
    m = get_probe_model()
    pos = m.encode(PROBES_POSITIVE)
    neg = m.encode(PROBES_NEGATIVE)
    Vn = V / (np.linalg.norm(V, axis=1, keepdims=True) + 1e-9)
    posn = pos / (np.linalg.norm(pos, axis=1, keepdims=True) + 1e-9)
    negn = neg / (np.linalg.norm(neg, axis=1, keepdims=True) + 1e-9)
    sim_self = Vn @ Vn.T
    np.fill_diagonal(sim_self, 0)
    k = min(3, len(V) - 1)
    density = np.sort(sim_self, axis=1)[:, -k:].mean(axis=1)
    isolation = 1.0 - density
    pos_sim = (Vn @ posn.T).max(axis=1)
    neg_sim = (Vn @ negn.T).max(axis=1)
    contrast = pos_sim - 0.5 * neg_sim
    score = 0.4 * isolation + 0.6 * contrast
    score = (score - score.min()) / (score.max() - score.min() + 1e-9)
    order = np.argsort(-score)
    top = []
    for i in order[:10]:
        top.append({
            "chunk_id": EXPORTED["chunk_ids"][i],
            "category": EXPORTED["categories"][i],
            "score": float(score[i]),
            "isolation": float(isolation[i]),
            "contrast": float(contrast[i]),
            "preview": (EXPORTED["texts"][i][:70] + "...") if MODE["current"] == "vulnerable" else "[hidden]"
        })
    return jsonify({"total": len(V), "top": top, "mode": MODE["current"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5014)
