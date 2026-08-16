from flask import Flask, request, jsonify, render_template_string
import requests, os, itertools, re, math
import numpy as np
from sentence_transformers import SentenceTransformer

app = Flask(__name__)
WEAVIATE = os.environ.get("WEAVIATE_URL", "http://weaviate-db:8080")
MODE = {"current": "vulnerable"}

WORDLIST = [
    "Password123", "Admin@123", "Welcome2026", "ChangeMe!", "N0=Acc3ss",
    "Nimble2026", "Spring2024!", "Summer@2026", "Test1234", "Letmein!",
    "Qwerty@123", "P@ssw0rd", "Default123", "FirstLogin1", "Reset@2026",
    "Nimble@Login", "Corporate1!", "Secure@2026", "Welcome123!", "Hello@2026"
]
TEMPLATES_BASE = {
    "credential_reset": [
        "Please navigate to {URL} and reset your password. Default password is {PASSWORD} for first-time users.",
        "Go to {URL} to change your password. Initial credential: {PASSWORD}.",
        "Visit {URL} and enter your credentials. Temporary password: {PASSWORD}.",
        "Reset your account at {URL}. The default password is {PASSWORD} change it after first login.",
        "To activate your account visit {URL} default password {PASSWORD} must be updated.",
    ],
    "api_credential": [
        "Production API key: {PASSWORD}. Used by the analytics pipeline.",
        "OpenAI API key for production environment: {PASSWORD}.",
        "API key {PASSWORD} for service integration.",
    ],
    "vpn_credential": [
        "VPN endpoint {URL} pre-shared key {PASSWORD} MFA required.",
        "Connect to {URL} using PSK {PASSWORD}.",
    ]
}
CATEGORY_SEEDS = {
    "credential_reset": "Please navigate to login and reset your password",
    "api_credential": "Production OpenAI API key for the pipeline",
    "vpn_credential": "VPN endpoint pre-shared key MFA",
}

_model = None


def model():
    global _model
    if _model is None:
        _model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _model


def cos(a, b):
    a = np.asarray(a); b = np.asarray(b)
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))


HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Query console · doc-embeddings-prod · Vantage Vector Cloud</title>
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
.page-desc{color:var(--dim);font-size:.88rem;margin-top:5px;max-width:660px;line-height:1.5}

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

.field,select.field{width:100%;background:var(--surface-alt);border:1px solid var(--border-strong);color:var(--ink);padding:9px 11px;border-radius:7px;font-family:var(--mono);font-size:.79rem;margin-bottom:10px}
.field:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-ring)}
.row{display:flex;gap:10px}
.row .field{flex:1;margin-bottom:0}

.btn{font-family:var(--sans);font-size:.8rem;font-weight:600;padding:9px 16px;border-radius:7px;border:1px solid transparent;cursor:pointer;display:inline-flex;align-items:center;gap:7px;white-space:nowrap}
.btn-pri{background:var(--ink);color:#fff}
.btn-pri:hover{filter:brightness(1.25)}
.btn-pri:active{transform:translateY(1px)}

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
    <div class="nav-item active"><span class="dot"></span>Query console</div>
    <div class="nav-item"><span class="dot"></span>Diagnostics</div>
    <div class="nav-item"><span class="dot"></span>Exports</div>

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
      <div class="crumbs">Query console <span class="sep">/</span> <b>doc-embeddings-prod</b></div>
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
            <span>Staging<small>Noised vectors</small></span>
          </div>
          <div class="env-opt" data-env="guardrailed" onclick="selectEnv('guardrailed')">
            <span class="env-dot" style="background:#059669"></span>
            <span>Compliance<small>Raw vectors blocked</small></span>
          </div>
        </div>
      </div>
      <div class="avatar">SA</div>
    </div>

    <div class="page">
      <div class="page-head">
        <div class="eyebrow">Zero-shot text recovery</div>
        <div class="page-title">doc-embeddings-prod</div>
        <div class="page-desc">Recover a chunk's structure by scoring a template bank against its stored vector, then brute-force the variable slot against a candidate wordlist.</div>
        <div class="tick-strip" id="tickStrip"></div>
      </div>

      <div id="envBanner" class="env-banner eb-prod">
        <span class="ico">●</span>
        <span id="envBannerText">Production environment — raw vectors returned as-is, no perturbation applied.</span>
      </div>

      <div class="grid">
        <div class="card">
          <div class="card-head"><span class="card-num">1</span><span class="card-title">Select target chunk</span></div>
          <div class="card-desc">Pull a target embedding from the index by chunk ID.</div>
          <div class="row">
            <select id="chunk-select" class="field"></select>
            <button class="btn btn-pri" onclick="loadChunk()">Load target</button>
          </div>
          <div id="target-info" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">2</span><span class="card-title">Template matching</span></div>
          <div class="card-desc">Scores a bank of common document templates against the target vector. The highest-similarity template recovers the chunk's structure — without decoding a single number.</div>
          <button class="btn btn-pri" onclick="matchTemplate()">Match templates</button>
          <div id="out-tpl" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">3</span><span class="card-title">Slot inference</span></div>
          <div class="card-desc">Fills the variable slot in the matched template with each wordlist candidate, re-embeds, and scores the uplift against target — margin-aware, so common tokens don't dominate.</div>
          <div class="row">
            <input id="url-hint" class="field" placeholder="URL hint (optional)" value="https://login.nimbletech.ai" />
            <button class="btn btn-pri" onclick="invertPassword()">Run slot inference</button>
          </div>
          <div id="out-inv" class="output"></div>
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
        <div class="step-label">Why two stages</div>
        <div class="step-text">A direct attempt to recover a password from a 384-dim vector fails, because the embedding encodes <b>"this text is a password-reset instruction"</b> as a concept — not the literal string. Recovering the sentence's structure first, then narrowing the one variable part of it, is a far smaller search than inverting the whole thing at once.</div>
      </div>
      <div class="step-block">
        <div class="step-label">Stage A · Template matching</div>
        <div class="step-text">Each candidate template — e.g. <code>"Default password is {PASSWORD}"</code> — is rendered with a placeholder and embedded. Whichever template's embedding sits closest to the target vector is almost certainly the sentence shape the original chunk used.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s 'http://localhost:5015/match_template?chunk_id=PWD-RESET-001'</pre>
        </div>
      </div>
      <div class="step-block">
        <div class="step-label">Stage B · Slot inference</div>
        <div class="step-text">For every wordlist candidate, the matched template is filled in and re-embedded. The uplift over a neutral placeholder baseline is measured per-template, then converted to a z-score — this is what keeps generic words like <code>"Password123"</code> from winning purely on being semantically unremarkable.</div>
        <div class="step-text">Agreement across multiple templates on the same winning word is the strongest confidence signal: independent structures converging on one answer is far less likely by chance than a single template doing so.</div>
      </div>
    </div>

    <div class="hp-section" id="tab-theory">
      <div class="theory-p">This is <b>zero-shot inversion</b> — no fine-tuned inverter model, no training data from this specific index. Just a template bank, a public sentence-embedding model, and cosine similarity.</div>
      <div class="theory-p">It works because embedding models are deterministic and public. Anyone can download <code>all-MiniLM-L6-v2</code> and encode candidate sentences locally, then compare against a leaked vector entirely offline.</div>
      <div class="theory-p"><b>Why environments differ:</b> Staging adds small Gaussian noise to every returned vector — enough to blur exact structure recovery without breaking legitimate nearest-neighbor search. Compliance withholds raw vectors entirely, or returns them heavily quantized, which destroys the fine-grained similarity signal this whole attack depends on.</div>
    </div>
  </div>
</div>

<script>
async function init(){
  const r=await fetch('/chunks'); const d=await r.json();
  const s=document.getElementById('chunk-select');
  d.forEach(c=>{const o=document.createElement('option');o.value=c.chunk_id;o.textContent=`${c.chunk_id} (${c.category})`;s.appendChild(o)});
}
init();

const envMeta = {
  vulnerable:  {label:'Production',  dot:'#dc2626', banner:'eb-prod',       text:'Production environment — raw vectors returned as-is, no perturbation applied.'},
  hardened:    {label:'Staging',     dot:'#d97706', banner:'eb-staging',    text:'Staging environment — small Gaussian noise added to every returned vector.'},
  guardrailed: {label:'Compliance',  dot:'#059669', banner:'eb-compliance', text:'Compliance environment — raw vectors withheld or returned heavily quantized; only nearest-neighbor lookups are served.'}
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

async function loadChunk(){
  const id=document.getElementById('chunk-select').value;
  const o=document.getElementById('target-info');
  o.innerHTML='<span class="spinner"></span> loading…';
  const r=await fetch('/target?chunk_id='+encodeURIComponent(id));
  const d=await r.json();
  o.textContent=JSON.stringify(d,null,2);
}

async function matchTemplate(){
  const id=document.getElementById('chunk-select').value;
  const o=document.getElementById('out-tpl');
  o.innerHTML='<span class="spinner"></span> scoring templates…';
  const r=await fetch('/match_template?chunk_id='+encodeURIComponent(id));
  const d=await r.json();
  if(d.error){o.textContent=d.error;return}
  let out=`detected category   ${d.detected_category}\nbest similarity     ${d.best_similarity.toFixed(4)}\n\ntop 5 templates:\n`;
  d.top.forEach((t,i)=>{ out += `  #${i+1} cos=${t.cosine.toFixed(4)}  cat=${t.category}\n      "${t.template}"\n\n`; });
  o.textContent=out;
}

async function invertPassword(){
  const id=document.getElementById('chunk-select').value;
  const url=document.getElementById('url-hint').value;
  const o=document.getElementById('out-inv');
  o.innerHTML='<span class="spinner"></span> brute-forcing slot…';
  const r=await fetch('/invert',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chunk_id:id,url_hint:url})});
  const d=await r.json();
  if(d.error){o.textContent=d.error;return}
  let out=`top candidates (margin-aware):\n\n`;
  d.candidates.forEach((c,i)=>{ out += `  #${i+1} ${c.password.padEnd(18)} score=${c.score.toFixed(4)}  z=${c.z.toFixed(2)}\n`; });
  out += `\n=== result ===\nrecovered password   ${d.recovered}\nconfidence            ${d.confidence}\nagreement             ${d.agreement}/${d.total_templates} templates\n`;
  if(d.recovered_actual){ out += `\n[ground truth] actual chunk text:\n  ${d.recovered_actual}`; }
  o.textContent=out;
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
    return jsonify({"mode": MODE["current"]})


def _all_templates():
    out = []
    for cat, lst in TEMPLATES_BASE.items():
        for t in lst:
            out.append({"category": cat, "template": t})
    expanded = []
    swaps = [("navigate to", "go to"), ("reset your password", "change your password"), ("Default password is", "Initial password is")]
    for item in out:
        for a, b in swaps:
            if a in item["template"]:
                expanded.append({"category": item["category"], "template": item["template"].replace(a, b)})
    return out + expanded


@app.route("/chunks")
def chunks():
    q = "{ Get { DocChunk(limit: 100) { chunk_id category } } }"
    d = requests.post(f"{WEAVIATE}/v1/graphql", json={"query": q}, timeout=10).json()
    return jsonify(d["data"]["Get"]["DocChunk"])


@app.route("/target")
def target():
    chunk_id = request.args.get("chunk_id")
    q = f"""{{ Get {{ DocChunk(where: {{path: ["chunk_id"], operator: Equal, valueString: "{chunk_id}"}}) {{ chunk_id category text _additional {{ vector }} }} }} }}"""
    d = requests.post(f"{WEAVIATE}/v1/graphql", json={"query": q}, timeout=10).json()
    obj = d["data"]["Get"]["DocChunk"][0]
    vec = obj["_additional"]["vector"]
    if MODE["current"] == "hardened":
        v = np.array(vec); v = v + np.random.normal(0, 0.01, v.shape); vec = v.tolist()
    if MODE["current"] == "guardrailed":
        return jsonify({"chunk_id": chunk_id, "category": obj.get("category"), "note": "raw vector hidden in guardrailed mode", "vector_preview": "[REDACTED]"})
    return jsonify({"chunk_id": chunk_id, "category": obj.get("category"), "dimension": len(vec), "vector_preview": vec[:8]})


def _get_vec(chunk_id):
    q = f"""{{ Get {{ DocChunk(where: {{path: ["chunk_id"], operator: Equal, valueString: "{chunk_id}"}}) {{ text category _additional {{ vector }} }} }} }}"""
    d = requests.post(f"{WEAVIATE}/v1/graphql", json={"query": q}, timeout=10).json()
    obj = d["data"]["Get"]["DocChunk"][0]
    v = np.array(obj["_additional"]["vector"])
    if MODE["current"] == "hardened":
        v = v + np.random.normal(0, 0.01, v.shape)
    if MODE["current"] == "guardrailed":
        v = np.round(v * 8) / 8
    return v, obj.get("text"), obj.get("category")


@app.route("/match_template")
def match_template():
    chunk_id = request.args.get("chunk_id")
    target_v, actual_text, actual_cat = _get_vec(chunk_id)
    m = model()
    seed_embs = {c: m.encode(s) for c, s in CATEGORY_SEEDS.items()}
    cat_scores = {c: cos(v, target_v) for c, v in seed_embs.items()}
    detected = max(cat_scores, key=cat_scores.get)
    all_t = _all_templates()
    scored = []
    for t in all_t:
        rendered = t["template"].replace("{URL}", "https://login.nimbletech.ai").replace("{PASSWORD}", "PLACEHOLDER")
        emb = m.encode(rendered)
        scored.append({"category": t["category"], "template": t["template"], "cosine": cos(emb, target_v)})
    scored.sort(key=lambda x: -x["cosine"])
    return jsonify({
        "detected_category": detected,
        "best_similarity": scored[0]["cosine"],
        "top": scored[:5]
    })


@app.route("/invert", methods=["POST"])
def invert():
    chunk_id = request.json["chunk_id"]
    url_hint = request.json.get("url_hint", "https://login.nimbletech.ai")
    target_v, actual_text, actual_cat = _get_vec(chunk_id)
    m = model()
    seed_embs = {c: m.encode(s) for c, s in CATEGORY_SEEDS.items()}
    cat_scores = {c: cos(v, target_v) for c, v in seed_embs.items()}
    detected = max(cat_scores, key=cat_scores.get)
    templates = TEMPLATES_BASE.get(detected, TEMPLATES_BASE["credential_reset"])
    baseline_embs = [m.encode(t.replace("{URL}", url_hint).replace("{PASSWORD}", "PLACEHOLDER")) for t in templates]
    baseline_sims = [cos(b, target_v) for b in baseline_embs]
    word_scores = {}
    for w in WORDLIST:
        sims = []
        for ti, t in enumerate(templates):
            filled = t.replace("{URL}", url_hint).replace("{PASSWORD}", w)
            emb = m.encode(filled)
            uplift = cos(emb, target_v) - baseline_sims[ti]
            sims.append(uplift)
        sims = np.array(sims)
        word_scores[w] = float(sims.mean())
    template_winners = []
    for ti, t in enumerate(templates):
        best_w, best_s = None, -1e9
        for w in WORDLIST:
            filled = t.replace("{URL}", url_hint).replace("{PASSWORD}", w)
            s = cos(m.encode(filled), target_v) - baseline_sims[ti]
            if s > best_s:
                best_s = s; best_w = w
        template_winners.append(best_w)
    from collections import Counter
    votes = Counter(template_winners)
    top_word, agreement = votes.most_common(1)[0]
    scores_list = np.array(list(word_scores.values()))
    mean_s = scores_list.mean(); std_s = scores_list.std() + 1e-9
    top_z = (word_scores[top_word] - mean_s) / std_s
    ranked = sorted(word_scores.items(), key=lambda x: -x[1])[:8]
    candidates = [{"password": w, "score": s, "z": (s - mean_s) / std_s} for w, s in ranked]
    confidence = "HIGH" if (agreement >= len(templates) * 0.6 and top_z > 2.0) else "MEDIUM" if top_z > 1.0 else "LOW"
    return jsonify({
        "candidates": candidates,
        "recovered": top_word,
        "confidence": confidence,
        "agreement": agreement,
        "total_templates": len(templates),
        "recovered_actual": actual_text if MODE["current"] == "vulnerable" else None
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5015)
