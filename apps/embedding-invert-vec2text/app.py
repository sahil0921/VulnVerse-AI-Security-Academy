from flask import Flask, request, jsonify, render_template_string
import requests, os, math, random
import numpy as np
from sentence_transformers import SentenceTransformer

app = Flask(__name__)
WEAVIATE = os.environ.get("WEAVIATE_URL", "http://weaviate-db:8080")
MODE = {"current": "vulnerable"}

CORPUS = [
    "Please navigate to https://login.nimbletech.ai and reset your password",
    "Default password is {PW} for first-time users",
    "Change immediately after first login",
    "Production OpenAI API key for the analytics pipeline",
    "Rotate quarterly per security policy",
    "AWS production access key with secret used by deployment role",
    "GlobalProtect VPN endpoint MFA via Duo required",
    "JIRA service account credentials for CI CD integration",
    "Stripe live secret key used by the billing microservice",
    "Do not commit to git",
    "GitHub personal access token with repo and workflow scopes",
    "Belongs to deployment bot",
    "PostgreSQL production connection string read-write access",
    "SendGrid API key for transactional email service",
    "Rate limit 100 emails per second",
    "MinIO object storage endpoint buckets nimble-documents nimble-archive",
    "Paid Time Off Policy 2026 employees accrue PTO per year",
    "Submit requests via Workday at least 2 weeks in advance",
    "Compensation bands L3 engineer L4 senior L5 staff L6 principal",
    "Annual review in Q1",
    "Q1 2026 board meeting summary revenue up year over year",
    "Product roadmap approved new office Bangalore Q3",
    "New employee onboarding day one pick up laptop from IT",
    "Default Wi-Fi password connect to AD using temporary credentials",
    "Q1 2026 security audit findings critical unpatched services",
    "Default Jenkins credentials public S3 bucket no MFA on AWS root",
    "Application encryption master key used by all services for at-rest encryption",
    "Stored in HSM and Vault",
    "Okta SSO client secret for the internal portal integration",
    "Wildcard TLS certificate expires private key passphrase",
    "Jenkins deployment token used by GitOps pipeline",
    "Permits production deploys to all clusters",
    "AWS root account recovery MFA backup codes store in physical safe",
]

_emb = None
_corpus_vecs = None


def emb():
    global _emb, _corpus_vecs
    if _emb is None:
        _emb = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        _corpus_vecs = _emb.encode(CORPUS)
    return _emb


def inverter_stage(target_vec, top_k=3):
    emb()
    sims = [float(np.dot(_corpus_vecs[i], target_vec) / (np.linalg.norm(_corpus_vecs[i]) * np.linalg.norm(target_vec) + 1e-9)) for i in range(len(CORPUS))]
    ranked = sorted(range(len(CORPUS)), key=lambda i: -sims[i])
    return [CORPUS[i] for i in ranked[:top_k]], [sims[i] for i in ranked[:top_k]]


def corrector_stage(target_vec, hypothesis, max_iter=8):
    emb()
    current = hypothesis
    trajectory = []
    for it in range(max_iter):
        cur_emb = _emb.encode(current)
        cur_sim = float(np.dot(cur_emb, target_vec) / (np.linalg.norm(cur_emb) * np.linalg.norm(target_vec) + 1e-9))
        residual = target_vec - cur_emb
        best_i, best_align = None, -1
        for i, frag in enumerate(CORPUS):
            if frag in current:
                continue
            align = float(np.dot(_corpus_vecs[i], residual) / (np.linalg.norm(_corpus_vecs[i]) * np.linalg.norm(residual) + 1e-9))
            if align > best_align:
                best_align = align; best_i = i
        if best_i is None or best_align < 0.05:
            trajectory.append({"iter": it + 1, "sim": cur_sim, "action": "converged"})
            break
        candidate = current + " " + CORPUS[best_i]
        cand_emb = _emb.encode(candidate)
        cand_sim = float(np.dot(cand_emb, target_vec) / (np.linalg.norm(cand_emb) * np.linalg.norm(target_vec) + 1e-9))
        if cand_sim > cur_sim:
            current = candidate
            trajectory.append({"iter": it + 1, "sim": cand_sim, "action": f"added: {CORPUS[best_i][:40]}..."})
        else:
            trajectory.append({"iter": it + 1, "sim": cur_sim, "action": "no improvement, stop"})
            break
    final_emb = _emb.encode(current)
    final_sim = float(np.dot(final_emb, target_vec) / (np.linalg.norm(final_emb) * np.linalg.norm(target_vec) + 1e-9))
    return current, final_sim, trajectory


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

.pipeline-strip{display:flex;align-items:center;gap:6px;margin-bottom:18px;flex-wrap:wrap}
.stage-box{flex:1;min-width:130px;background:var(--surface-alt);border:1px solid var(--border-strong);border-radius:8px;padding:11px 12px;text-align:center;font-family:var(--mono);font-size:.68rem;color:var(--dim);transition:all .15s}
.stage-box.active{border-color:var(--accent);color:var(--accent);background:var(--accent-soft);font-weight:600}
.stage-arrow{color:var(--dim-2);font-size:.9rem}

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
            <span>Production<small>Clean target vector</small></span>
          </div>
          <div class="env-opt" data-env="hardened" onclick="selectEnv('hardened')">
            <span class="env-dot" style="background:#d97706"></span>
            <span>Staging<small>PCA-reduced</small></span>
          </div>
          <div class="env-opt" data-env="guardrailed" onclick="selectEnv('guardrailed')">
            <span class="env-dot" style="background:#059669"></span>
            <span>Compliance<small>Quantized</small></span>
          </div>
        </div>
      </div>
      <div class="avatar">SA</div>
    </div>

    <div class="page">
      <div class="page-head">
        <div class="eyebrow">Supervised inversion</div>
        <div class="page-title">doc-embeddings-prod</div>
        <div class="page-desc">Two-stage reconstruction: an inverter proposes an initial guess from a corpus of known fragments, then a corrector iteratively appends the fragment that best closes the gap to the target vector.</div>
        <div class="tick-strip" id="tickStrip"></div>
      </div>

      <div id="envBanner" class="env-banner eb-prod">
        <span class="ico">●</span>
        <span id="envBannerText">Production environment — full corpus visible, target vector returned clean.</span>
      </div>

      <div class="grid">
        <div class="card">
          <div class="card-head"><span class="card-title">Two-stage architecture</span></div>
          <div class="pipeline-strip">
            <div class="stage-box" id="sb1">Target embedding<br/>(384-dim)</div>
            <span class="stage-arrow">→</span>
            <div class="stage-box" id="sb2">Inverter<br/>(initial guess)</div>
            <span class="stage-arrow">→</span>
            <div class="stage-box" id="sb3">Corrector<br/>(N iterations)</div>
            <span class="stage-arrow">→</span>
            <div class="stage-box" id="sb4">Recovered text</div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">1</span><span class="card-title">Select target &amp; run inverter</span></div>
          <div class="card-desc">Scores a reference corpus against the target vector and returns the closest fragment as an initial hypothesis.</div>
          <div class="row">
            <select id="chunk-select" class="field"></select>
            <button class="btn btn-pri" onclick="runInverter()">Run inverter</button>
          </div>
          <div id="out-inv" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">2</span><span class="card-title">Run corrector</span></div>
          <div class="card-desc">Each iteration measures the residual between the current hypothesis and the target, finds the corpus fragment most aligned with that residual, and appends it — only if doing so actually improves similarity.</div>
          <div class="row">
            <input id="iters" class="field narrow" type="number" value="6" min="1" max="15"/>
            <button class="btn btn-pri" onclick="runCorrector()">Run corrector</button>
          </div>
          <div id="out-cor" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">3</span><span class="card-title">Final recovered text</span></div>
          <div class="card-desc">Recovered text alongside ground truth (in Production) for comparison.</div>
          <div id="out-final" class="output"></div>
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
        <div class="step-label">Step 1 · Inverter — <span class="step-btn">Run inverter</span></div>
        <div class="step-text">A reference corpus of known enterprise-style fragments is pre-embedded once. The target vector is scored by cosine similarity against every fragment, and the closest one becomes the starting hypothesis — this is the "initial guess" stage of a real Vec2Text pipeline, simplified to corpus lookup instead of a trained T5 decoder.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s -X POST http://localhost:5018/invert \
  -H 'Content-Type: application/json' \
  -d '{"chunk_id": "PWD-RESET-001"}'</pre>
        </div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 2 · Corrector — <span class="step-btn">Run corrector</span></div>
        <div class="step-text">At every iteration the algorithm computes the <code>residual</code> — the direction the hypothesis's embedding still needs to move to reach the target — then searches the corpus for whichever fragment's own embedding points most in that same direction. If appending it actually raises similarity, it's kept; otherwise the search halts. This is the same "residual-driven refinement" idea a trained corrector network does, just against a fixed fragment bank instead of free-form generation.</div>
        <div class="cmd-block">
          <div class="cmd-label">Equivalent request</div>
          <pre>curl -s -X POST http://localhost:5018/correct \
  -H 'Content-Type: application/json' \
  -d '{"chunk_id": "PWD-RESET-001", "hypothesis": "...", "iters": 6}'</pre>
        </div>
      </div>

      <div class="step-block">
        <div class="step-label">Step 3 · Match quality — <span class="step-btn">Run corrector</span> (result panel)</div>
        <div class="step-text">Final cosine similarity above <code>0.9</code> counts as excellent, <code>0.75–0.9</code> good, <code>0.5–0.75</code> partial — below that the corrector likely ran out of useful corpus fragments before converging.</div>
      </div>
    </div>

    <div class="hp-section" id="tab-theory">
      <div class="theory-p">Real Vec2Text trains a T5-based inverter and corrector on hundreds of thousands of (text, embedding) pairs, reporting up to <b>92% exact match</b> on short inputs in the original paper. This lab swaps the trained networks for a lightweight corpus-fragment simulator so the same iterative-refinement principle is visible without hours of GPU training — the mechanism is identical, only the model size differs.</div>
      <div class="theory-p"><b>Why environments differ:</b> Staging simulates PCA dimensionality reduction by zeroing the tail dimensions of the returned vector — enough information survives for ordinary nearest-neighbor search, but the fine-grained residual signal this technique depends on gets noticeably weaker. Compliance applies coarse quantization, which destroys that signal almost entirely.</div>
      <div class="theory-p">This technique pairs naturally with beam search's high-entropy detection: the corrector reliably reconstructs surrounding sentence structure but rarely recovers a genuinely random credential — that gap is exactly where a slot-filling brute-force picks up.</div>
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
  vulnerable:  {label:'Production',  dot:'#dc2626', banner:'eb-prod',       text:'Production environment — full corpus visible, target vector returned clean.'},
  hardened:    {label:'Staging',     dot:'#d97706', banner:'eb-staging',    text:'Staging environment — target vector simulates PCA reduction to 128 dimensions.'},
  guardrailed: {label:'Compliance',  dot:'#059669', banner:'eb-compliance', text:'Compliance environment — target vector coarsely quantized before being returned.'}
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

let hypothesis = "";

async function runInverter(){
  document.getElementById('sb1').classList.add('active');
  document.getElementById('sb2').classList.add('active');
  const id=document.getElementById('chunk-select').value;
  const o=document.getElementById('out-inv');
  o.innerHTML='<span class="spinner"></span> scoring corpus…';
  const r=await fetch('/invert',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chunk_id:id})});
  const d=await r.json();
  if(d.error){o.textContent=d.error;return}
  hypothesis = d.hypothesis;
  let out=`initial hypotheses (top 3 corpus matches):\n`;
  d.candidates.forEach((c,i)=>{ out += `  #${i+1} cos=${c.cosine.toFixed(4)}\n     "${c.text}"\n\n`; });
  out += `\nselected hypothesis: "${hypothesis}"`;
  o.textContent=out;
}

async function runCorrector(){
  if(!hypothesis){document.getElementById('out-cor').textContent='Run inverter first.';return}
  document.getElementById('sb3').classList.add('active');
  const id=document.getElementById('chunk-select').value;
  const it=document.getElementById('iters').value;
  const o=document.getElementById('out-cor');
  o.innerHTML='<span class="spinner"></span> iterative refinement…';
  const r=await fetch('/correct',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chunk_id:id,hypothesis,iters:+it})});
  const d=await r.json();
  if(d.error){o.textContent=d.error;return}
  let out=`correction trajectory:\n`;
  d.trajectory.forEach(t=>{ out += `  iter ${t.iter}: sim=${t.sim.toFixed(4)} | ${t.action}\n`; });
  out += `\nfinal similarity: ${d.final_sim.toFixed(4)}`;
  o.textContent=out;
  document.getElementById('sb4').classList.add('active');
  let f=`recovered:\n"${d.recovered}"\n`;
  if(d.actual) f += `\nground truth:\n"${d.actual}"\n\nmatch quality: ${d.final_sim>0.9?'EXCELLENT':d.final_sim>0.75?'GOOD':d.final_sim>0.5?'PARTIAL':'POOR'}`;
  document.getElementById('out-final').textContent=f;
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


def _get_vec(chunk_id):
    q = f"""{{ Get {{ DocChunk(where: {{path: ["chunk_id"], operator: Equal, valueString: "{chunk_id}"}}) {{ text _additional {{ vector }} }} }} }}"""
    d = requests.post(f"{WEAVIATE}/v1/graphql", json={"query": q}, timeout=10).json()
    obj = d["data"]["Get"]["DocChunk"][0]
    v = np.array(obj["_additional"]["vector"])
    if MODE["current"] == "hardened":
        v = v.copy(); v[128:] = 0
    if MODE["current"] == "guardrailed":
        v = np.round(v * 4) / 4
    return v, obj.get("text")


@app.route("/invert", methods=["POST"])
def invert_endpoint():
    cid = request.json["chunk_id"]
    v, actual = _get_vec(cid)
    cands, sims = inverter_stage(v, top_k=3)
    return jsonify({"hypothesis": cands[0], "candidates": [{"text": c, "cosine": s} for c, s in zip(cands, sims)]})


@app.route("/correct", methods=["POST"])
def correct_endpoint():
    cid = request.json["chunk_id"]
    h = request.json["hypothesis"]
    iters = int(request.json.get("iters", 6))
    v, actual = _get_vec(cid)
    recovered, sim, traj = corrector_stage(v, h, max_iter=iters)
    return jsonify({"recovered": recovered, "final_sim": sim, "trajectory": traj, "actual": actual if MODE["current"] == "vulnerable" else None})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5018)
