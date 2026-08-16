from flask import Flask, request, jsonify, render_template_string
import requests, os, time, hashlib
from sentence_transformers import SentenceTransformer
import numpy as np

app = Flask(__name__)
WEAVIATE = os.environ.get("WEAVIATE_URL", "http://weaviate-db:8080")
MODE = {"current": "vulnerable"}  # vulnerable | hardened | guardrailed
REQUEST_LOG = []  # rate limit tracker

# Candidate embedding models for fingerprinting
CANDIDATES = {
    "all-MiniLM-L6-v2": 384,
    "all-MiniLM-L12-v2": 384,
    "paraphrase-MiniLM-L6-v2": 384,
    "multi-qa-MiniLM-L6-cos-v1": 384,
    "all-mpnet-base-v2": 768,
    "all-distilroberta-v1": 768,
    "bge-small-en-v1.5": 384,
    "bge-base-en-v1.5": 768,
}
_models = {}


def get_model(name):
    if name not in _models:
        try:
            _models[name] = SentenceTransformer(f"sentence-transformers/{name}")
        except Exception:
            try:
                _models[name] = SentenceTransformer(f"BAAI/{name}")
            except Exception:
                return None
    return _models[name]


def check_mode_guard(action):
    """Apply mode-specific guards. Returns (allowed, message)."""
    now = time.time()
    REQUEST_LOG[:] = [t for t in REQUEST_LOG if now - t < 60]
    REQUEST_LOG.append(now)
    if MODE["current"] == "vulnerable":
        return True, None
    if MODE["current"] == "hardened":
        if len(REQUEST_LOG) > 20:
            return False, "Rate limit exceeded (hardened mode: 20 req/min)"
        return True, None
    if MODE["current"] == "guardrailed":
        if len(REQUEST_LOG) > 10:
            return False, "Rate limit exceeded (guardrailed mode: 10 req/min)"
        if action in ("fingerprint", "probe") and len(REQUEST_LOG) > 5:
            return False, "Recon pattern detected — request blocked by guardrail"
        return True, None
    return True, None


HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Diagnostics · doc-embeddings-prod · Vantage Vector Cloud</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root{
  --bg:#f4f5f8;
  --surface:#ffffff;
  --surface-alt:#fafbfc;
  --border:#e4e7ed;
  --border-strong:#d3d8e0;
  --ink:#13161f;
  --ink-soft:#3d4354;
  --dim:#6b7280;
  --dim-2:#9aa1ae;
  --accent:#4338ca;
  --accent-soft:#eef0fe;
  --accent-ring:rgba(67,56,202,.18);
  --prod:#dc2626;
  --prod-soft:#fdeaea;
  --staging:#d97706;
  --staging-soft:#fdf3e3;
  --compliance:#059669;
  --compliance-soft:#e7f6f0;
  --display:'Space Grotesk',sans-serif;
  --sans:'Inter',sans-serif;
  --mono:'IBM Plex Mono',monospace;
  --shadow-sm:0 1px 2px rgba(20,24,38,.05);
  --shadow-md:0 4px 16px rgba(20,24,38,.06);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  background:var(--bg);
  color:var(--ink);
  font-family:var(--sans);
  font-size:14px;
  -webkit-font-smoothing:antialiased;
}
a{color:inherit}

/* ---------- shell layout ---------- */
.shell{display:grid;grid-template-columns:230px 1fr;min-height:100vh}

/* ---------- sidebar ---------- */
.sidebar{
  background:#12141c;
  color:#c7cbd6;
  display:flex;
  flex-direction:column;
  padding:20px 14px;
  position:sticky;top:0;height:100vh;
}
.brand{display:flex;align-items:center;gap:10px;padding:6px 8px 22px 8px}
.brand-mark{
  width:30px;height:30px;border-radius:8px;flex:none;
  background:linear-gradient(155deg,#4338ca,#7c6cf0);
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 0 0 1px rgba(255,255,255,.08) inset;
}
.brand-mark svg{width:16px;height:16px}
.brand-name{font-family:var(--display);font-weight:700;font-size:.92rem;color:#f2f3f7;letter-spacing:-.01em}
.brand-sub{font-family:var(--mono);font-size:.62rem;color:#666e80;letter-spacing:.04em;margin-top:1px}

.nav-group-label{font-family:var(--mono);font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;color:#565e70;padding:14px 10px 6px}
.nav-item{
  display:flex;align-items:center;gap:10px;
  padding:8px 10px;border-radius:7px;
  font-size:.83rem;color:#a6acba;
  cursor:default;
  margin-bottom:2px;
}
.nav-item .dot{width:6px;height:6px;border-radius:50%;background:#454b5c;flex:none}
.nav-item.active{background:#1d2030;color:#f2f3f7}
.nav-item.active .dot{background:#7c6cf0}

.sidebar-footer{margin-top:auto;padding-top:14px;border-top:1px solid #22242f}
.help-link{
  display:flex;gap:9px;align-items:flex-start;
  padding:9px 10px;border-radius:8px;cursor:pointer;
  color:#8b93a6;font-size:.8rem;line-height:1.35;
  transition:background .12s;
}
.help-link:hover{background:#1a1c28;color:#d7dae2}
.help-link .qmark{
  width:16px;height:16px;border-radius:50%;border:1.5px solid #565e70;
  display:flex;align-items:center;justify-content:center;flex:none;
  font-size:.62rem;font-family:var(--mono);color:#8b93a6;margin-top:1px;
}
.help-link b{color:#c7cbd6;display:block;font-weight:600}
.version-tag{font-family:var(--mono);font-size:.62rem;color:#454b5c;padding:10px 10px 0}

/* ---------- main ---------- */
.main{display:flex;flex-direction:column;min-width:0}
.topbar{
  height:60px;flex:none;
  background:var(--surface);border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:16px;padding:0 26px;
  position:sticky;top:0;z-index:5;
}
.crumbs{font-size:.82rem;color:var(--dim)}
.crumbs b{color:var(--ink);font-weight:600}
.crumbs .sep{margin:0 6px;color:var(--dim-2)}

.env-picker{margin-left:auto;position:relative}
.env-btn{
  display:flex;align-items:center;gap:8px;
  background:var(--surface-alt);border:1px solid var(--border-strong);
  padding:7px 12px;border-radius:8px;cursor:pointer;
  font-family:var(--mono);font-size:.76rem;font-weight:500;
}
.env-btn .env-dot{width:7px;height:7px;border-radius:50%}
.env-btn:after{content:'▾';color:var(--dim-2);font-size:.7rem;margin-left:2px}
.env-menu{
  position:absolute;top:calc(100% + 6px);right:0;width:190px;
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  box-shadow:var(--shadow-md);padding:6px;display:none;z-index:20;
}
.env-menu.open{display:block}
.env-opt{
  display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:7px;
  font-size:.8rem;cursor:pointer;color:var(--ink-soft);
}
.env-opt:hover{background:var(--surface-alt)}
.env-opt.sel{background:var(--accent-soft);color:var(--accent);font-weight:600}
.env-opt .env-dot{width:7px;height:7px;border-radius:50%}
.env-opt small{display:block;font-weight:400;color:var(--dim-2);font-size:.68rem;margin-top:1px}

.avatar{
  width:30px;height:30px;border-radius:50%;background:var(--accent-soft);
  color:var(--accent);display:flex;align-items:center;justify-content:center;
  font-family:var(--mono);font-size:.72rem;font-weight:600;
}

.page{padding:28px 32px 60px;max-width:1180px;width:100%;margin:0 auto}
.page-head{margin-bottom:22px}
.eyebrow{font-family:var(--mono);font-size:.72rem;color:var(--accent);letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.page-title{font-family:var(--display);font-size:1.5rem;font-weight:700;letter-spacing:-.01em;color:var(--ink)}
.page-desc{color:var(--dim);font-size:.88rem;margin-top:5px;max-width:640px;line-height:1.5}

/* signature: dimension-tick strip */
.tick-strip{display:flex;align-items:flex-end;gap:2px;height:26px;margin-top:16px}
.tick-strip i{
  display:block;width:3px;border-radius:1.5px;background:linear-gradient(180deg,var(--accent),#a89af6);
  opacity:.55;
}

.env-banner{
  display:flex;align-items:center;gap:10px;
  padding:11px 16px;border-radius:9px;margin-bottom:20px;
  font-size:.82rem;border:1px solid transparent;
}
.env-banner .ico{font-family:var(--mono);font-size:.9rem}
.eb-prod{background:var(--prod-soft);color:#9d1c1c;border-color:#f6c9c9}
.eb-staging{background:var(--staging-soft);color:#93590a;border-color:#f3d9a5}
.eb-compliance{background:var(--compliance-soft);color:#03664e;border-color:#b7e4d4}

.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:880px){.grid{grid-template-columns:1fr}}

.card{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:20px 22px;box-shadow:var(--shadow-sm);
}
.card-head{display:flex;align-items:center;gap:10px;margin-bottom:4px}
.card-num{
  font-family:var(--mono);font-size:.68rem;color:var(--accent);
  background:var(--accent-soft);width:20px;height:20px;border-radius:5px;
  display:flex;align-items:center;justify-content:center;flex:none;font-weight:600;
}
.card-title{font-family:var(--display);font-weight:600;font-size:.95rem;color:var(--ink)}
.card-desc{color:var(--dim);font-size:.82rem;line-height:1.5;margin:8px 0 14px}

.field{width:100%;background:var(--surface-alt);border:1px solid var(--border-strong);color:var(--ink);
  padding:9px 11px;border-radius:7px;font-family:var(--mono);font-size:.79rem;margin-bottom:10px}
.field:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-ring)}

.btn{
  font-family:var(--sans);font-size:.8rem;font-weight:600;
  padding:9px 16px;border-radius:7px;border:1px solid transparent;cursor:pointer;
  display:inline-flex;align-items:center;gap:7px;transition:filter .12s, transform .12s;
}
.btn-pri{background:var(--ink);color:#fff}
.btn-pri:hover{filter:brightness(1.25)}
.btn-pri:active{transform:translateY(1px)}
.btn:disabled{opacity:.45;cursor:not-allowed}

.output{
  margin-top:14px;background:#0f1117;border:1px solid #23262f;border-radius:8px;
  padding:13px 14px;font-family:var(--mono);font-size:.76rem;color:#9ee8b8;
  white-space:pre-wrap;min-height:104px;max-height:340px;overflow-y:auto;line-height:1.55;
}
.output:empty:before{content:'Awaiting run —';color:#565e70}
.output .k{color:#7c9cf0}

.spinner{display:inline-block;width:11px;height:11px;border:2px solid rgba(255,255,255,.15);
  border-top-color:#9ee8b8;border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* ---------- slide-over help panel ---------- */
.scrim{position:fixed;inset:0;background:rgba(15,17,23,.35);opacity:0;pointer-events:none;transition:opacity .18s;z-index:30}
.scrim.open{opacity:1;pointer-events:auto}
.help-panel{
  position:fixed;top:0;right:-420px;width:400px;height:100vh;background:var(--surface);
  border-left:1px solid var(--border);box-shadow:-8px 0 32px rgba(20,24,38,.12);
  transition:right .22s ease;z-index:31;display:flex;flex-direction:column;
}
.help-panel.open{right:0}
.help-panel-head{
  padding:20px 22px 16px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
}
.help-panel-head h2{font-family:var(--display);font-size:1.02rem;font-weight:700}
.help-panel-head p{color:var(--dim);font-size:.78rem;margin-top:3px}
.help-close{width:26px;height:26px;border-radius:7px;border:1px solid var(--border-strong);
  background:var(--surface-alt);cursor:pointer;color:var(--dim);font-size:.85rem;flex:none}
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

.cmd-block{background:#0f1117;border-radius:8px;padding:11px 13px;position:relative}
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
  <!-- sidebar -->
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
    <div class="nav-item active"><span class="dot"></span>Diagnostics</div>

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

  <!-- main -->
  <div class="main">
    <div class="topbar">
      <div class="crumbs">Diagnostics <span class="sep">/</span> <b>doc-embeddings-prod</b></div>
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
        <div class="eyebrow">Index diagnostics</div>
        <div class="page-title">doc-embeddings-prod</div>
        <div class="page-desc">Connectivity, dimensionality and schema checks for this index. Read-only — these calls do not modify stored vectors.</div>
        <div class="tick-strip" id="tickStrip"></div>
      </div>

      <div id="envBanner" class="env-banner eb-prod">
        <span class="ico">●</span>
        <span id="envBannerText">Production environment — no authentication gate, full schema and dimension exposed to any caller on the index endpoint.</span>
      </div>

      <div class="grid">
        <div class="card">
          <div class="card-head"><span class="card-num">1</span><span class="card-title">Connectivity check</span></div>
          <div class="card-desc">Confirms the index endpoint is reachable and lists every collection it serves.</div>
          <button class="btn btn-pri" onclick="probe('/recon/discover','out1')">Run connectivity check</button>
          <div id="out1" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">2</span><span class="card-title">Dimension inspector</span></div>
          <div class="card-desc">Pulls one stored vector and reports its dimensionality, narrowing down which embedding model produced it.</div>
          <button class="btn btn-pri" onclick="probe('/recon/fingerprint','out2')">Inspect dimension</button>
          <div id="out2" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">3</span><span class="card-title">Model identification</span></div>
          <div class="card-desc">Sends sample text, retrieves the nearest stored vector, and scores it against known model candidates.</div>
          <input id="probe-text" class="field" value="Please navigate to login and reset your password" />
          <button class="btn btn-pri" onclick="inferenceProbe()">Run identification</button>
          <div id="out3" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">4</span><span class="card-title">Schema export</span></div>
          <div class="card-desc">Exports the full index schema — property names, types, and index configuration.</div>
          <button class="btn btn-pri" onclick="probe('/recon/schema','out4')">Export schema</button>
          <div id="out4" class="output"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- slide-over help panel -->
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
        <div class="step-label">Step 1 · Connectivity</div>
        <div class="step-text">The index endpoint answers on port <code>8090</code> without an API key. In a correctly configured environment this route should require a signed token — its absence means anyone on the network path can enumerate every collection the cluster serves.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s http://localhost:8090/v1/schema | jq '.classes[].class'</pre>
        </div>
        <div class="mode-note mn-prod">Production — returns full collection list and version string.</div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 2 · Dimension</div>
        <div class="step-text">A stored vector's length narrows the search space immediately. A <code>384</code>-dim vector rules out every 768-dim model in one call — dimension alone doesn't name the model, but it cuts the candidate list in half or more.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s http://localhost:8090/v1/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ Get { DocChunk(limit:1) { _additional { vector } } } }"}'</pre>
        </div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 3 · Model identification</div>
        <div class="step-text">Every dimension-matching candidate model re-encodes the retrieved chunk locally. Whichever candidate's output has the highest cosine similarity to the stored vector is almost certainly the model in production — embeddings from the same model on the same text are near-identical, embeddings from different models diverge even on identical input.</div>
        <div class="step-text">A separation above <code>0.15</code> between the top two candidates counts as high confidence.</div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 4 · Schema export</div>
        <div class="step-text">Property names in the schema often describe what's inside without needing to read a single vector — fields like <code>chunk_id</code> or <code>category</code> hint at how sensitive documents are partitioned internally.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s http://localhost:8090/v1/schema</pre>
        </div>
      </div>
    </div>

    <div class="hp-section" id="tab-theory">
      <div class="theory-p">Embeddings preserve <b>semantic meaning</b> as geometry, not as a one-way hash. Two pieces of text that mean similar things produce vectors that sit close together under cosine similarity — that closeness is measurable by anyone who can query the index, authenticated or not.</div>
      <div class="theory-p">This is what makes model identification possible without ever touching production infrastructure again: once you know which open-source model generated the vectors, you can download it and run every further step — inversion, membership inference, canary extraction — entirely offline, against your own local copy.</div>
      <div class="theory-p"><b>Why environments differ:</b> Staging rate-limits before it blocks — a slow analyst still gets through, a script doesn't. Compliance goes further and pattern-matches the request sequence itself, not just its volume, then redacts identifying fields in the response rather than refusing outright — the call succeeds, but the payload is shaped to disclose nothing sensitive.</div>
    </div>
  </div>
</div>

<script>
const envMeta = {
  vulnerable:  {label:'Production',  dot:'#dc2626', banner:'eb-prod',       text:'Production environment — no authentication gate, full schema and dimension exposed to any caller on the index endpoint.'},
  hardened:    {label:'Staging',     dot:'#d97706', banner:'eb-staging',    text:'Staging environment — requests are rate-limited to 20/min; schema responses omit internal index configuration.'},
  guardrailed: {label:'Compliance',  dot:'#059669', banner:'eb-compliance', text:'Compliance environment — 10 req/min ceiling, recon-pattern detection, and sensitive fields are redacted before the response leaves the cluster.'}
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

async function probe(endpoint,outId){
  const o=document.getElementById(outId);
  o.innerHTML='<span class="spinner"></span> running…';
  try{
    const r=await fetch(endpoint);
    const d=await r.json();
    o.textContent=JSON.stringify(d,null,2);
  }catch(e){o.textContent='ERROR: '+e.message}
}

async function inferenceProbe(){
  const o=document.getElementById('out3');
  const txt=document.getElementById('probe-text').value;
  o.innerHTML='<span class="spinner"></span> scoring candidate models…';
  try{
    const r=await fetch('/recon/inference_probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:txt})});
    const d=await r.json();
    if(d.error){o.textContent='ERROR: '+d.error;return}
    let out=`top candidate   ${d.top_candidate}\nconfidence      ${d.confidence}\nseparation      ${d.separation.toFixed(4)}\n\nranking:\n`;
    d.ranking.forEach(r=>{ out += `  ${r.model.padEnd(30)} cos=${r.cosine.toFixed(4)}\n`; });
    o.textContent = out;
  }catch(e){o.textContent='ERROR: '+e.message}
}

// signature: render dimension-tick strip
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


@app.route("/recon/discover")
def discover():
    ok, msg = check_mode_guard("discover")
    if not ok:
        return jsonify({"blocked": True, "reason": msg}), 429
    try:
        r = requests.get(f"{WEAVIATE}/v1/.well-known/ready", timeout=5)
        meta = requests.get(f"{WEAVIATE}/v1/meta", timeout=5).json()
        schema = requests.get(f"{WEAVIATE}/v1/schema", timeout=5).json()
        collections = [c["class"] for c in schema.get("classes", [])]
        result = {
            "endpoint": WEAVIATE,
            "ready": r.status_code == 200,
            "auth_required": False,
            "version": meta.get("version", "unknown"),
            "collections": collections,
            "mode": MODE["current"]
        }
        if MODE["current"] == "guardrailed":
            result["version"] = "[REDACTED]"
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/recon/fingerprint")
def fingerprint():
    ok, msg = check_mode_guard("fingerprint")
    if not ok:
        return jsonify({"blocked": True, "reason": msg}), 429
    query = {"query": "{ Get { DocChunk(limit: 1) { _additional { vector } } } }"}
    r = requests.post(f"{WEAVIATE}/v1/graphql", json=query, timeout=10)
    data = r.json()
    try:
        vec = data["data"]["Get"]["DocChunk"][0]["_additional"]["vector"]
        dim = len(vec)
        candidates = [m for m, d in CANDIDATES.items() if d == dim]
        result = {
            "dimension": dim,
            "candidate_models": candidates,
            "first_10_values": vec[:10],
            "interpretation": f"Dimension {dim} matches {len(candidates)} candidate model(s). Run model identification to confirm."
        }
        if MODE["current"] == "guardrailed":
            result.pop("first_10_values", None)
            result["interpretation"] = "Dimension hidden in Compliance environment."
            result["dimension"] = "[REDACTED]"
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "raw": data})


@app.route("/recon/schema")
def schema_dump():
    ok, msg = check_mode_guard("schema")
    if not ok:
        return jsonify({"blocked": True, "reason": msg}), 429
    r = requests.get(f"{WEAVIATE}/v1/schema", timeout=5).json()
    if MODE["current"] == "hardened":
        for c in r.get("classes", []):
            c.pop("invertedIndexConfig", None)
            c.pop("moduleConfig", None)
    if MODE["current"] == "guardrailed":
        return jsonify({"classes": [{"class": c["class"]} for c in r.get("classes", [])]})
    return jsonify(r)


@app.route("/recon/inference_probe", methods=["POST"])
def inference_probe():
    ok, msg = check_mode_guard("probe")
    if not ok:
        return jsonify({"blocked": True, "reason": msg}), 429
    text = request.json.get("text", "")
    if not text:
        return jsonify({"error": "text required"})
    try:
        target_model = get_model("all-MiniLM-L6-v2")
        if target_model is None:
            return jsonify({"error": "target model not available"})
        query_vec = target_model.encode(text).tolist()
        gql = {
            "query": f"""{{ Get {{ DocChunk(nearVector: {{vector: {query_vec}}}, limit: 1) {{ text _additional {{ vector }} }} }} }}"""
        }
        r = requests.post(f"{WEAVIATE}/v1/graphql", json=gql, timeout=15).json()
        retrieved = r["data"]["Get"]["DocChunk"][0]
        stored_vec = np.array(retrieved["_additional"]["vector"])
        retrieved_text = retrieved["text"]
    except Exception as e:
        return jsonify({"error": f"retrieval failed: {e}"})

    dim = len(stored_vec)
    ranking = []
    for name, d in CANDIDATES.items():
        if d != dim:
            continue
        m = get_model(name)
        if m is None:
            continue
        candidate_vec = m.encode(retrieved_text)
        cos = float(np.dot(candidate_vec, stored_vec) / (np.linalg.norm(candidate_vec) * np.linalg.norm(stored_vec)))
        ranking.append({"model": name, "cosine": cos})
    ranking.sort(key=lambda x: -x["cosine"])
    if not ranking:
        return jsonify({"error": "no candidates of matching dimension"})
    top = ranking[0]
    separation = ranking[0]["cosine"] - (ranking[1]["cosine"] if len(ranking) > 1 else 0)
    confidence = "HIGH" if separation > 0.15 else "MEDIUM" if separation > 0.05 else "LOW"
    result = {
        "top_candidate": top["model"],
        "confidence": confidence,
        "separation": separation,
        "ranking": ranking,
        "retrieved_chunk_preview": retrieved_text[:80] + "..."
    }
    if MODE["current"] == "guardrailed":
        result["top_candidate"] = "[REDACTED]"
        result["ranking"] = [{"model": "[REDACTED]", "cosine": r["cosine"]} for r in ranking]
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5013)
