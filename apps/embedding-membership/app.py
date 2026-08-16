from flask import Flask, request, jsonify, render_template_string
import requests, os
import numpy as np
from sentence_transformers import SentenceTransformer

app = Flask(__name__)
WEAVIATE = os.environ.get("WEAVIATE_URL", "http://weaviate-db:8080")
MODE = {"current": "vulnerable"}

ATTRIBUTE_PROBES = {
    "credential": "password api key secret token authentication credential",
    "financial": "revenue salary compensation budget invoice financial",
    "hr_policy": "employee PTO vacation onboarding policy benefits",
    "network_infra": "VPN endpoint server IP address network configuration",
    "meeting_notes": "meeting agenda action items discussion summary",
    "audit_finding": "security audit vulnerability critical finding compliance",
    "cloud_credential": "AWS Azure GCP cloud access key bucket",
    "code_secret": "github token CI deployment build pipeline",
}

_model = None


def model():
    global _model
    if _model is None:
        _model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _model


def cos(a, b):
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))


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

.field,textarea.field{width:100%;background:var(--surface-alt);border:1px solid var(--border-strong);color:var(--ink);padding:9px 11px;border-radius:7px;font-family:var(--mono);font-size:.79rem;margin-bottom:10px}
.field:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-ring)}
textarea.field{min-height:64px;resize:vertical}

.btn{font-family:var(--sans);font-size:.8rem;font-weight:600;padding:9px 16px;border-radius:7px;border:1px solid transparent;cursor:pointer;display:inline-flex;align-items:center;gap:7px;white-space:nowrap}
.btn-pri{background:var(--ink);color:#fff}
.btn-pri:hover{filter:brightness(1.25)}
.btn-pri:active{transform:translateY(1px)}

.output{margin-top:14px;background:#0f1117;border:1px solid #23262f;border-radius:8px;padding:13px 14px;font-family:var(--mono);font-size:.76rem;color:#9ee8b8;white-space:pre-wrap;min-height:104px;max-height:420px;overflow-y:auto;line-height:1.55}
.output:empty:before{content:'Awaiting run —';color:#565e70}
.output .yes{color:#34d399;font-weight:700}
.output .no{color:#f87171;font-weight:700}

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
.step-btn{display:inline-block;background:var(--ink);color:#fff;font-family:var(--sans);font-size:.74rem;font-weight:600;padding:3px 9px;border-radius:5px;margin:0 2px}

.cmd-block{background:#0f1117;border-radius:8px;padding:11px 13px}
.cmd-block pre{font-family:var(--mono);font-size:.71rem;color:#c9d6f2;white-space:pre-wrap;line-height:1.6}
.cmd-label{font-family:var(--mono);font-size:.6rem;color:#565e70;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}

.theory-p{font-size:.83rem;line-height:1.6;color:var(--ink-soft);margin-bottom:14px}
.theory-p b{color:var(--ink)}

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
    <div class="nav-item active"><span class="dot"></span>Diagnostics</div>
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
      <div class="crumbs">Diagnostics <span class="sep">/</span> <b>doc-embeddings-prod</b></div>
      <div class="env-picker">
        <button class="env-btn" id="envBtn" onclick="toggleEnvMenu()">
          <span class="env-dot" id="envDot" style="background:#dc2626"></span>
          <span id="envLabel">Production</span>
        </button>
        <div class="env-menu" id="envMenu">
          <div class="env-opt sel" data-env="vulnerable" onclick="selectEnv('vulnerable')">
            <span class="env-dot" style="background:#dc2626"></span>
            <span>Production<small>Exact cosines</small></span>
          </div>
          <div class="env-opt" data-env="hardened" onclick="selectEnv('hardened')">
            <span class="env-dot" style="background:#d97706"></span>
            <span>Staging<small>Rounded scores</small></span>
          </div>
          <div class="env-opt" data-env="guardrailed" onclick="selectEnv('guardrailed')">
            <span class="env-dot" style="background:#059669"></span>
            <span>Compliance<small>DP noise added</small></span>
          </div>
        </div>
      </div>
      <div class="avatar">SA</div>
    </div>

    <div class="page">
      <div class="page-head">
        <div class="eyebrow">Membership &amp; attribute inference</div>
        <div class="page-title">doc-embeddings-prod</div>
        <div class="page-desc">Two lighter-weight attacks that don't require recovering any text: confirm whether a specific string is stored, and classify every chunk by data type — both from nearest-neighbor similarity alone.</div>
        <div class="tick-strip" id="tickStrip"></div>
      </div>

      <div id="envBanner" class="env-banner eb-prod">
        <span class="ico">●</span>
        <span id="envBannerText">Production environment — k-NN queries return exact cosine similarities.</span>
      </div>

      <div class="grid">
        <div class="card">
          <div class="card-head"><span class="card-num">1</span><span class="card-title">Membership inference</span></div>
          <div class="card-desc">Embeds a candidate string and checks whether any stored vector matches it closely enough to conclude the exact string is already in the index.</div>
          <textarea id="member-text" class="field">Default password is N0=Acc3ss for first-time users</textarea>
          <button class="btn btn-pri" onclick="member()">Test membership</button>
          <div id="out-mem" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">2</span><span class="card-title">Attribute inference</span></div>
          <div class="card-desc">Scores every stored chunk against a bank of category probes — credential, financial, HR policy, and so on — without decoding a single one. Use it to triage which chunks are worth the cost of full inversion.</div>
          <button class="btn btn-pri" onclick="attribute()">Classify all chunks</button>
          <div id="out-attr" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">3</span><span class="card-title">Wordlist membership sweep</span></div>
          <div class="card-desc">Runs membership inference across a whole list at once — useful for confirming which candidate credentials from a wordlist actually appear in this index.</div>
          <textarea id="sweep-list" class="field" style="min-height:120px">N0=Acc3ss
Password123
Admin@123
Welcome2026
ChangeMe!
sk-nimble-prod-2026-jF4kZmP2vL5nQ8
ghp_NimbleX9mP2vL5nQ8wRjF4kZ
NimbleVPN2026!Secure</textarea>
          <button class="btn btn-pri" onclick="sweep()">Run sweep</button>
          <div id="out-sw" class="output"></div>
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
        <div class="step-label">Step 1 · Membership inference — <span class="step-btn">Test membership</span></div>
        <div class="step-text">The candidate string is embedded and compared against its nearest stored neighbors. A top similarity above <code>0.85</code> is treated as YES — that's simplest attack in the whole module: no reconstruction needed, just a yes/no answer about whether a known string already exists somewhere in the index.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s -X POST http://localhost:5019/member \
  -H 'Content-Type: application/json' \
  -d '{"text": "Default password is N0=Acc3ss for first-time users"}'</pre>
        </div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 2 · Attribute inference — <span class="step-btn">Classify all chunks</span></div>
        <div class="step-text">Every chunk's stored vector is scored against a fixed bank of category probes — short phrases like <code>"password api key secret token"</code> for credentials, or <code>"employee PTO vacation onboarding"</code> for HR policy. The highest-scoring probe becomes that chunk's predicted category, with no text ever decoded.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s http://localhost:5019/attribute</pre>
        </div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 3 · Wordlist sweep — <span class="step-btn">Run sweep</span></div>
        <div class="step-text">The same membership test as Step 1, run across an entire list in one pass — a practical way to confirm which entries from a leaked or guessed credential list actually match something stored in this index, using a slightly looser threshold of <code>0.7</code>.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s -X POST http://localhost:5019/sweep \
  -H 'Content-Type: application/json' \
  -d '{"list": ["N0=Acc3ss", "Password123", "Admin@123"]}'</pre>
        </div>
      </div>
    </div>

    <div class="hp-section" id="tab-theory">
      <div class="theory-p">Membership and attribute inference are the <b>cheapest, lowest-risk</b> attacks in this module — they never touch the text-reconstruction machinery, so they're usually run first, to decide where the expensive attacks (Vec2Text, beam search, template slot-filling) are actually worth aiming.</div>
      <div class="theory-p"><b>Why environments differ:</b> Staging rounds returned similarity scores to two decimal places — coarse enough that the confident/uncertain boundary blurs slightly, but membership verdicts near the threshold become noisier. Compliance adds calibrated differential-privacy noise directly to the similarity signal, which is a much stronger defense: it doesn't just hide precision, it statistically obscures whether any single query result reflects a real match at all.</div>
      <div class="theory-p">Attribute inference in particular scales: 10,000 chunks reduced to 50 "credential"-scored candidates turns an infeasible full-index inversion sweep into a focused one.</div>
    </div>
  </div>
</div>

<script>
const envMeta = {
  vulnerable:  {label:'Production',  dot:'#dc2626', banner:'eb-prod',       text:'Production environment — k-NN queries return exact cosine similarities.'},
  hardened:    {label:'Staging',     dot:'#d97706', banner:'eb-staging',    text:'Staging environment — similarity scores rounded to 2 decimal places.'},
  guardrailed: {label:'Compliance',  dot:'#059669', banner:'eb-compliance', text:'Compliance environment — calibrated differential-privacy noise applied to similarity scores.'}
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

async function member(){
  const txt=document.getElementById('member-text').value;
  const o=document.getElementById('out-mem');
  o.innerHTML='<span class="spinner"></span> testing…';
  const r=await fetch('/member',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:txt})});
  const d=await r.json();
  if(d.error){o.textContent=d.error;return}
  let out=`verdict         ${d.verdict}\ntop similarity  ${d.top_sim.toFixed(4)}\nthreshold       ${d.threshold}\n\ntop matches:\n`;
  d.matches.forEach((m,i)=>{ out += `  #${i+1} cos=${m.cosine.toFixed(4)} chunk_id=${m.chunk_id}\n      ${m.text}\n\n`; });
  o.innerHTML = out.replace(/verdict         YES/,'verdict         <span class="yes">YES</span>').replace(/verdict         NO/,'verdict         <span class="no">NO</span>');
}

async function attribute(){
  const o=document.getElementById('out-attr');
  o.innerHTML='<span class="spinner"></span> classifying…';
  const r=await fetch('/attribute');
  const d=await r.json();
  if(d.error){o.textContent=d.error;return}
  let out=`classified ${d.results.length} chunks:\n\n`;
  d.results.forEach(r=>{ out += `  ${r.chunk_id.padEnd(20)} \u2192 ${r.attribute.padEnd(18)} (score ${r.score.toFixed(3)})\n`; });
  o.textContent=out;
}

async function sweep(){
  const list=document.getElementById('sweep-list').value.split('\n').filter(Boolean);
  const o=document.getElementById('out-sw');
  o.innerHTML='<span class="spinner"></span> sweeping…';
  const r=await fetch('/sweep',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({list})});
  const d=await r.json();
  if(d.error){o.textContent=d.error;return}
  let out=`sweep results:\n\n`;
  d.results.forEach(x=>{
    const flag = x.in_db ? '\u2713 IN_DB' : '\u2717      ';
    out += `  ${flag}  cos=${x.top_sim.toFixed(4)}  ${x.text}\n`;
  });
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


def _knn(vec, k=5):
    gql = {"query": f"""{{ Get {{ DocChunk(nearVector: {{vector: {list(vec)}}}, limit: {k}) {{ chunk_id text _additional {{ vector distance }} }} }} }}"""}
    d = requests.post(f"{WEAVIATE}/v1/graphql", json=gql, timeout=15).json()
    return d["data"]["Get"]["DocChunk"]


@app.route("/member", methods=["POST"])
def member():
    txt = request.json["text"]
    m = model()
    v = m.encode(txt)
    matches = _knn(v, k=3)
    sims = []
    for x in matches:
        sv = np.array(x["_additional"]["vector"])
        c = cos(sv, v)
        if MODE["current"] == "guardrailed":
            c = c + np.random.normal(0, 0.05)
        sims.append({"chunk_id": x.get("chunk_id"), "text": x.get("text") if MODE["current"] == "vulnerable" else "[hidden]", "cosine": c})
    top = sims[0]["cosine"] if sims else 0
    threshold = 0.85
    verdict = "YES" if top > threshold else "NO"
    if MODE["current"] == "hardened":
        for s in sims:
            s["cosine"] = round(s["cosine"], 2)
    return jsonify({"verdict": verdict, "top_sim": top, "threshold": threshold, "matches": sims})


@app.route("/attribute")
def attribute():
    q = "{ Get { DocChunk(limit: 100) { chunk_id _additional { vector } } } }"
    d = requests.post(f"{WEAVIATE}/v1/graphql", json={"query": q}, timeout=15).json()
    chunks = d["data"]["Get"]["DocChunk"]
    m = model()
    probe_vecs = {k: m.encode(v) for k, v in ATTRIBUTE_PROBES.items()}
    results = []
    for c in chunks:
        if c.get("chunk_id", "").startswith("CANARY"):
            continue
        v = np.array(c["_additional"]["vector"])
        scores = {k: cos(v, pv) for k, pv in probe_vecs.items()}
        best = max(scores, key=scores.get)
        results.append({"chunk_id": c["chunk_id"], "attribute": best, "score": scores[best]})
    results.sort(key=lambda x: -x["score"])
    return jsonify({"results": results})


@app.route("/sweep", methods=["POST"])
def sweep():
    items = request.json["list"]
    m = model()
    out = []
    for txt in items:
        v = m.encode(txt)
        matches = _knn(v, k=1)
        if matches:
            sv = np.array(matches[0]["_additional"]["vector"])
            c = cos(sv, v)
        else:
            c = 0
        out.append({"text": txt, "top_sim": float(c), "in_db": c > 0.7})
    return jsonify({"results": out})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5019)
