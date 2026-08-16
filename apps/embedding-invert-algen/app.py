from flask import Flask, request, jsonify, render_template_string
import requests, os, random, string
import numpy as np
from sklearn.linear_model import Ridge
from sentence_transformers import SentenceTransformer

app = Flask(__name__)
WEAVIATE = os.environ.get("WEAVIATE_URL", "http://weaviate-db:8080")
MODE = {"current": "vulnerable"}
STATE = {"canaries": [], "canary_vecs": None, "alignment": None, "surrogate_model_name": "paraphrase-MiniLM-L6-v2"}

CANARY_TEMPLATES = [
    "The {DOMAIN} access password for {USER} is {PW}.",
    "Service account {USER} at {DOMAIN} uses credential {PW}.",
    "Production token for {DOMAIN}: {PW}. Owner {USER}.",
    "API endpoint {DOMAIN} requires bearer {PW} for user {USER}.",
    "VPN config {DOMAIN} preshared key {PW} assigned to {USER}.",
    "Database connection at {DOMAIN} user {USER} password {PW}.",
    "Storage bucket {DOMAIN} secret {PW} for principal {USER}.",
    "OAuth client at {DOMAIN} secret {PW} authenticator {USER}.",
]
DOMAINS = ["jira.canary-x.local", "vault.canary-y.local", "ldap.canary-z.local", "ci.canary-q.local"]
USERS = ["svc_x", "svc_y", "ops_a", "ops_b", "bot_p"]


def rand_pw():
    return "".join(random.choices(string.ascii_letters + string.digits, k=12))


def generate_canary(n=300):
    out = []
    for _ in range(n):
        t = random.choice(CANARY_TEMPLATES)
        s = t.replace("{DOMAIN}", random.choice(DOMAINS)).replace("{USER}", random.choice(USERS)).replace("{PW}", rand_pw())
        out.append(s)
    return out


_surrogate = None


def surrogate():
    global _surrogate
    if _surrogate is None:
        _surrogate = SentenceTransformer(f"sentence-transformers/{STATE['surrogate_model_name']}")
    return _surrogate


HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Indexes · doc-embeddings-prod · Vantage Vector Cloud</title>
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

.field{width:100%;background:var(--surface-alt);border:1px solid var(--border-strong);color:var(--ink);padding:9px 11px;border-radius:7px;font-family:var(--mono);font-size:.79rem;margin-bottom:10px}
.field:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-ring)}
.row{display:flex;gap:10px}
.row .field{flex:1;margin-bottom:0}
.row .field.narrow{flex:0 0 130px}

.btn{font-family:var(--sans);font-size:.8rem;font-weight:600;padding:9px 16px;border-radius:7px;border:1px solid transparent;cursor:pointer;display:inline-flex;align-items:center;gap:7px;white-space:nowrap}
.btn-pri{background:var(--ink);color:#fff}
.btn-pri:hover{filter:brightness(1.25)}
.btn-pri:active{transform:translateY(1px)}

.output{margin-top:14px;background:#0f1117;border:1px solid #23262f;border-radius:8px;padding:13px 14px;font-family:var(--mono);font-size:.76rem;color:#9ee8b8;white-space:pre-wrap;min-height:104px;max-height:420px;overflow-y:auto;line-height:1.55}
.output:empty:before{content:'Awaiting run —';color:#565e70}

.spinner{display:inline-block;width:11px;height:11px;border:2px solid rgba(255,255,255,.15);border-top-color:#9ee8b8;border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

.pipeline{display:flex;flex-direction:column;gap:2px}
.stage-row{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:7px;font-family:var(--mono);font-size:.78rem;color:var(--dim)}
.stage-row .num{width:18px;height:18px;border-radius:50%;border:1.5px solid var(--border-strong);display:flex;align-items:center;justify-content:center;font-size:.65rem;flex:none}
.stage-row.done{color:var(--ink)}
.stage-row.done .num{background:var(--compliance);border-color:var(--compliance);color:#fff}

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
    <div class="nav-item active"><span class="dot"></span>Indexes</div>
    <div class="nav-item"><span class="dot"></span>Query console</div>
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
      <div class="crumbs">Indexes <span class="sep">/</span> <b>doc-embeddings-prod</b></div>
      <div class="env-picker">
        <button class="env-btn" id="envBtn" onclick="toggleEnvMenu()">
          <span class="env-dot" id="envDot" style="background:#dc2626"></span>
          <span id="envLabel">Production</span>
        </button>
        <div class="env-menu" id="envMenu">
          <div class="env-opt sel" data-env="vulnerable" onclick="selectEnv('vulnerable')">
            <span class="env-dot" style="background:#dc2626"></span>
            <span>Production<small>Open insert API</small></span>
          </div>
          <div class="env-opt" data-env="hardened" onclick="selectEnv('hardened')">
            <span class="env-dot" style="background:#d97706"></span>
            <span>Staging<small>Insert quota</small></span>
          </div>
          <div class="env-opt" data-env="guardrailed" onclick="selectEnv('guardrailed')">
            <span class="env-dot" style="background:#059669"></span>
            <span>Compliance<small>Canary detection</small></span>
          </div>
        </div>
      </div>
      <div class="avatar">SA</div>
    </div>

    <div class="page">
      <div class="page-head">
        <div class="eyebrow">Cross-model alignment attack</div>
        <div class="page-title">doc-embeddings-prod</div>
        <div class="page-desc">Recover chunk text without ever knowing which embedding model produced the index — by planting known text, reading back its embedding, and learning a linear map to your own surrogate model's space.</div>
        <div class="tick-strip" id="tickStrip"></div>
      </div>

      <div id="envBanner" class="env-banner eb-prod">
        <span class="ico">●</span>
        <span id="envBannerText">Production environment — insert API is open, no canary-pattern detection.</span>
      </div>

      <div class="grid">
        <div class="card">
          <div class="card-head"><span class="card-title">Pipeline status</span></div>
          <div class="pipeline" id="pipeline">
            <div class="stage-row" id="st-1"><span class="num">1</span>Generate canary texts</div>
            <div class="stage-row" id="st-2"><span class="num">2</span>Inject canaries into index</div>
            <div class="stage-row" id="st-3"><span class="num">3</span>Fetch target embeddings (real pairs)</div>
            <div class="stage-row" id="st-4"><span class="num">4</span>Train alignment (surrogate ↔ target)</div>
            <div class="stage-row" id="st-5"><span class="num">5</span>Decode target chunk via alignment</div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">1</span><span class="card-title">Generate canary texts</span></div>
          <div class="card-desc">Synthetic credential-shaped documents used purely as known reference points. Injecting a moderate batch (300, not 50,000) keeps this under bulk-write anomaly thresholds.</div>
          <div class="row">
            <input id="num-canaries" class="field narrow" type="number" value="300" min="50" max="2000"/>
            <button class="btn btn-pri" onclick="genCanary()">Generate</button>
          </div>
          <div id="out-can" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">2</span><span class="card-title">Inject canaries &amp; fetch target embeddings</span></div>
          <div class="card-desc">The index embeds these canaries with its own model — the one an attacker doesn't otherwise know. Reading them back yields real (text, embedding) pairs to learn from.</div>
          <button class="btn btn-pri" onclick="inject()">Inject &amp; fetch</button>
          <div id="out-inj" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">3</span><span class="card-title">Train alignment</span></div>
          <div class="card-desc">Ridge regression learns a linear map from the attacker's own surrogate-model embedding space to the target index's embedding space, using only the canary pairs.</div>
          <button class="btn btn-pri" onclick="train()">Train alignment</button>
          <div id="out-train" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">4</span><span class="card-title">Decode target chunk</span></div>
          <div class="card-desc">Picks a real (non-canary) chunk and uses the trained alignment to rank a reference-text bank by similarity in the target's own embedding space.</div>
          <div class="row">
            <select id="chunk-select" class="field"></select>
            <button class="btn btn-pri" onclick="decode()">Decode</button>
          </div>
          <div id="out-dec" class="output"></div>
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
        <div class="step-label">Step 1 · Generate canaries — <span class="step-btn">Generate</span></div>
        <div class="step-text">Synthetic, template-based texts with random credential-shaped values. They exist only so you have known ground truth once they've been embedded by the target's model.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s -X POST http://localhost:5017/canary/gen \
  -H 'Content-Type: application/json' \
  -d '{"n": 300}'</pre>
        </div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 2 · Inject &amp; fetch — <span class="step-btn">Inject &amp; fetch</span></div>
        <div class="step-text">Each canary is written into the index through its normal insert path, embedded by whatever model the index actually runs, then immediately read back. The result is a set of <code>(surrogate_embedding, target_embedding)</code> pairs for text you already know word-for-word.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s -X POST http://localhost:5017/canary/inject</pre>
        </div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 3 · Train alignment — <span class="step-btn">Train alignment</span></div>
        <div class="step-text">Ridge regression fits a matrix <code>W</code> such that <code>W · surrogate_vector ≈ target_vector</code>. This works because two independently-trained sentence embedding models still tend to encode meaning along approximately linearly-related axes — the semantic geometry is different in detail, but close enough in structure for a linear map to bridge it.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s -X POST http://localhost:5017/align/train</pre>
        </div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 4 · Decode — <span class="step-btn">Decode</span></div>
        <div class="step-text">A reference-text bank is embedded with the attacker's own surrogate model, mapped into the target's space through the trained alignment, then ranked by cosine similarity against a real chunk's stored vector — recovering an approximate meaning of a chunk the attacker never had the correct model for.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s -X POST http://localhost:5017/decode \
  -H 'Content-Type: application/json' \
  -d '{"chunk_id": "PWD-RESET-001"}'</pre>
        </div>
      </div>
    </div>

    <div class="hp-section" id="tab-theory">
      <div class="theory-p">This is <b>ALGEN-style cross-model alignment</b>: the attacker never needs to identify or download the exact model the target uses. They only need a small number of known texts embedded by that model — canaries serve exactly that purpose, with zero drift, because they're embedded by the real system rather than approximated offline.</div>
      <div class="theory-p">Once the linear map is trained, every future decode is <b>fully offline</b> — no more requests to the target are needed except to fetch the vector being attacked.</div>
      <div class="theory-p"><b>Why environments differ:</b> Staging caps insert volume per IP, which slows canary collection without stopping it outright. Compliance fingerprints the canary pattern itself — uniform template structure combined with unusually high alphanumeric entropy per field — and rejects the batch before it ever reaches the index.</div>
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
  vulnerable:  {label:'Production',  dot:'#dc2626', banner:'eb-prod',       text:'Production environment — insert API is open, no canary-pattern detection.'},
  hardened:    {label:'Staging',     dot:'#d97706', banner:'eb-staging',    text:'Staging environment — insert quota capped at 500 canaries per batch.'},
  guardrailed: {label:'Compliance',  dot:'#059669', banner:'eb-compliance', text:'Compliance environment — canary signature detection rejects uniform-template, high-entropy batches above 100.'}
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

function markDone(i){
  const el = document.getElementById('st-'+i);
  el.classList.add('done');
  el.querySelector('.num').textContent = '✓';
}

async function genCanary(){
  const n=document.getElementById('num-canaries').value;
  const o=document.getElementById('out-can');
  o.innerHTML='<span class="spinner"></span> generating…';
  const r=await fetch('/canary/gen',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({n:+n})});
  const d=await r.json();
  if(d.blocked){o.textContent='BLOCKED: '+d.reason;return}
  o.textContent = `generated ${d.count} canaries\nsample:\n  ${d.sample.join('\n  ')}`;
  markDone(1);
}

async function inject(){
  const o=document.getElementById('out-inj');
  o.innerHTML='<span class="spinner"></span> injecting + fetching…';
  const r=await fetch('/canary/inject',{method:'POST'});
  const d=await r.json();
  if(d.blocked){o.textContent='BLOCKED: '+d.reason;return}
  o.textContent = `injected      ${d.injected}\npairs collected  ${d.pairs}\ndimension     ${d.dim}`;
  markDone(2); markDone(3);
}

async function train(){
  const o=document.getElementById('out-train');
  o.innerHTML='<span class="spinner"></span> training ridge regression…';
  const r=await fetch('/align/train',{method:'POST'});
  const d=await r.json();
  if(d.error){o.textContent=d.error;return}
  o.textContent = `surrogate model       ${d.surrogate}\ntarget dim / surrogate dim   ${d.target_dim} / ${d.surrogate_dim}\ntraining pairs        ${d.pairs}\nvalidation R\u00b2         ${d.r2.toFixed(4)}\nmean cosine (val)     ${d.mean_cos.toFixed(4)}`;
  markDone(4);
}

async function decode(){
  const id=document.getElementById('chunk-select').value;
  const o=document.getElementById('out-dec');
  o.innerHTML='<span class="spinner"></span> decoding…';
  const r=await fetch('/decode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chunk_id:id})});
  const d=await r.json();
  if(d.error){o.textContent=d.error;return}
  let out=`target chunk   ${id}\n\ntop-5 recovered candidates (surrogate-space neighbors):\n`;
  d.candidates.forEach((c,i)=>{ out += `  #${i+1} cos=${c.cosine.toFixed(4)}\n     "${c.text}"\n\n`; });
  if(d.actual){ out += `[ground truth]\n"${d.actual}"`; }
  o.textContent=out;
  markDone(5);
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


@app.route("/chunks")
def chunks():
    q = "{ Get { DocChunk(limit: 100) { chunk_id category } } }"
    d = requests.post(f"{WEAVIATE}/v1/graphql", json={"query": q}, timeout=10).json()
    return jsonify(d["data"]["Get"]["DocChunk"])


@app.route("/canary/gen", methods=["POST"])
def canary_gen():
    n = int(request.json.get("n", 300))
    if MODE["current"] == "hardened" and n > 500:
        return jsonify({"blocked": True, "reason": "hardened mode max 500"}), 400
    if MODE["current"] == "guardrailed" and n > 100:
        return jsonify({"blocked": True, "reason": "guardrailed mode max 100 — anomaly detection"}), 400
    STATE["canaries"] = generate_canary(n)
    return jsonify({"count": n, "sample": STATE["canaries"][:3]})


@app.route("/canary/inject", methods=["POST"])
def canary_inject():
    if not STATE["canaries"]:
        return jsonify({"error": "generate canaries first"})
    if MODE["current"] == "guardrailed":
        return jsonify({"blocked": True, "reason": "canary signature detected (uniform template + alphanumeric entropy \u2265 4.5 bits/char)"}), 403
    surr = surrogate()
    vecs = []
    pairs = []
    for txt in STATE["canaries"]:
        s_emb = surr.encode(txt)
        target_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        t_emb = target_model.encode(txt).tolist()
        obj = {"class": "DocChunk", "properties": {"chunk_id": f"CANARY-{random.randint(10000,99999)}", "category": "canary", "text": txt}, "vector": t_emb}
        requests.post(f"{WEAVIATE}/v1/objects", json=obj, timeout=10)
        pairs.append((s_emb, np.array(t_emb)))
        vecs.append(t_emb)
    STATE["canary_vecs"] = pairs
    return jsonify({"injected": len(STATE["canaries"]), "pairs": len(pairs), "dim": len(vecs[0])})


@app.route("/align/train", methods=["POST"])
def align_train():
    if not STATE.get("canary_vecs"):
        return jsonify({"error": "inject canaries first"})
    pairs = STATE["canary_vecs"]
    X = np.array([p[0] for p in pairs])
    Y = np.array([p[1] for p in pairs])
    split = int(len(X) * 0.85)
    Xtr, Xva = X[:split], X[split:]
    Ytr, Yva = Y[:split], Y[split:]
    reg = Ridge(alpha=1.0)
    reg.fit(Xtr, Ytr)
    STATE["alignment"] = reg
    pred = reg.predict(Xva)
    cos_list = [float(np.dot(pred[i], Yva[i]) / (np.linalg.norm(pred[i]) * np.linalg.norm(Yva[i]) + 1e-9)) for i in range(len(pred))]
    r2 = reg.score(Xva, Yva)
    return jsonify({"surrogate": STATE["surrogate_model_name"], "target_dim": Y.shape[1], "surrogate_dim": X.shape[1], "pairs": len(X), "r2": float(r2), "mean_cos": float(np.mean(cos_list))})


@app.route("/decode", methods=["POST"])
def decode():
    if STATE.get("alignment") is None:
        return jsonify({"error": "train alignment first"})
    cid = request.json["chunk_id"]
    q = f"""{{ Get {{ DocChunk(where: {{path: ["chunk_id"], operator: Equal, valueString: "{cid}"}}) {{ text _additional {{ vector }} }} }} }}"""
    d = requests.post(f"{WEAVIATE}/v1/graphql", json={"query": q}, timeout=10).json()
    obj = d["data"]["Get"]["DocChunk"][0]
    target_vec = np.array(obj["_additional"]["vector"])
    actual = obj.get("text")
    REF_TEXTS = [
        "Please navigate to the login portal and reset your password",
        "Production API key for the analytics pipeline",
        "AWS production access key with deployment role",
        "VPN endpoint with pre-shared key MFA required",
        "JIRA service account credentials for CI/CD automation",
        "Stripe live secret key used by the billing microservice",
        "GitHub personal access token with repo workflow scopes",
        "PostgreSQL production connection string with credentials",
        "SendGrid API key for transactional email service",
        "MinIO object storage endpoint access and secret keys",
        "PTO accrual policy for employees by tenure",
        "Compensation bands for engineering levels",
        "Quarterly board meeting summary revenue growth",
        "New employee onboarding day one laptop pickup",
        "Security audit findings unpatched services public bucket",
        "Application encryption master key for at-rest encryption",
        "Okta SSO client secret internal portal integration",
        "Wildcard TLS certificate private key passphrase",
        "Jenkins deployment token GitOps pipeline production",
        "AWS root account recovery MFA backup codes",
    ]
    surr = surrogate()
    ref_surr = surr.encode(REF_TEXTS)
    reg = STATE["alignment"]
    ref_mapped = reg.predict(ref_surr)
    sims = [float(np.dot(ref_mapped[i], target_vec) / (np.linalg.norm(ref_mapped[i]) * np.linalg.norm(target_vec) + 1e-9)) for i in range(len(REF_TEXTS))]
    ranked = sorted(zip(REF_TEXTS, sims), key=lambda x: -x[1])[:5]
    return jsonify({"candidates": [{"text": t, "cosine": s} for t, s in ranked], "actual": actual if MODE["current"] == "vulnerable" else None})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5017)
