from flask import Flask, request, jsonify, render_template_string
import requests, os, re, math
import numpy as np
from sentence_transformers import SentenceTransformer
from transformers import GPT2LMHeadModel, GPT2Tokenizer
import torch

app = Flask(__name__)
WEAVIATE = os.environ.get("WEAVIATE_URL", "http://weaviate-db:8080")
MODE = {"current": "vulnerable"}

_emb_model = None
_gpt2 = None
_tok = None


def emb_model():
    global _emb_model
    if _emb_model is None:
        _emb_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _emb_model


def gpt2():
    global _gpt2, _tok
    if _gpt2 is None:
        _tok = GPT2Tokenizer.from_pretrained("gpt2")
        _gpt2 = GPT2LMHeadModel.from_pretrained("gpt2")
        _gpt2.eval()
    return _gpt2, _tok


def cos(a, b):
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))


def beam_search_inversion(target_vec, max_steps=18, beam_width=6, candidates_per_step=30, seed_text=""):
    em = emb_model()
    model, tok = gpt2()
    beams = [(seed_text, -1.0)]
    history = []
    target = np.asarray(target_vec, dtype=np.float32)
    for step in range(max_steps):
        new_beams = []
        for text, _ in beams:
            ids = tok.encode(text, return_tensors="pt") if text else tok.encode(tok.bos_token, return_tensors="pt")
            with torch.no_grad():
                logits = model(ids).logits[0, -1]
            top_ids = torch.topk(logits, candidates_per_step).indices.tolist()
            for tid in top_ids:
                tok_text = tok.decode([tid])
                if not tok_text.strip() and text == "":
                    continue
                cand_text = text + tok_text
                if len(cand_text.strip()) < 1:
                    continue
                emb = em.encode(cand_text)
                score = cos(emb, target)
                new_beams.append((cand_text, score))
        new_beams.sort(key=lambda x: -x[1])
        beams = new_beams[:beam_width]
        history.append({"step": step + 1, "best_text": beams[0][0][:60], "best_score": beams[0][1]})
    return beams[0][0], beams[0][1], history


def detect_high_entropy_regions(text):
    tokens = text.split()
    masked = []
    for t in tokens:
        clean = t.strip(".,!?;:")
        if len(clean) < 6:
            masked.append(t); continue
        classes = sum([
            any(c.isupper() for c in clean),
            any(c.islower() for c in clean),
            any(c.isdigit() for c in clean),
            any(not c.isalnum() for c in clean),
        ])
        if len(clean) > 0:
            p = {c: clean.count(c) / len(clean) for c in set(clean)}
            ent = -sum(v * math.log2(v) for v in p.values())
        else:
            ent = 0
        is_alphanum_mix = re.search(r"[A-Za-z]", clean) and re.search(r"\d", clean)
        if (classes >= 3 and ent > 2.8) or (is_alphanum_mix and len(clean) >= 8 and ent > 2.5):
            masked.append("{PASSWORD}")
        else:
            masked.append(t)
    return " ".join(masked)


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
.param-row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px}
.param{display:flex;flex-direction:column;gap:4px}
.param label{font-family:var(--mono);font-size:.66rem;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}
.param input{width:84px;background:var(--surface-alt);border:1px solid var(--border-strong);color:var(--ink);padding:7px 9px;border-radius:6px;font-family:var(--mono);font-size:.78rem}

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
            <span>Production<small>Exact float32 vectors</small></span>
          </div>
          <div class="env-opt" data-env="hardened" onclick="selectEnv('hardened')">
            <span class="env-dot" style="background:#d97706"></span>
            <span>Staging<small>int8 quantized</small></span>
          </div>
          <div class="env-opt" data-env="guardrailed" onclick="selectEnv('guardrailed')">
            <span class="env-dot" style="background:#059669"></span>
            <span>Compliance<small>Raw vectors hidden</small></span>
          </div>
        </div>
      </div>
      <div class="avatar">SA</div>
    </div>

    <div class="page">
      <div class="page-head">
        <div class="eyebrow">Beam search reconstruction</div>
        <div class="page-title">doc-embeddings-prod</div>
        <div class="page-desc">Reconstruct chunk text token-by-token: a language model proposes candidates, each is embedded and scored against the target vector, and the closest survivors advance.</div>
        <div class="tick-strip" id="tickStrip"></div>
      </div>

      <div id="envBanner" class="env-banner eb-prod">
        <span class="ico">●</span>
        <span id="envBannerText">Production environment — exact float32 vectors returned, no quantization.</span>
      </div>

      <div class="grid">
        <div class="card">
          <div class="card-head"><span class="card-num">1</span><span class="card-title">Select target chunk</span></div>
          <div class="row">
            <select id="chunk-select" class="field"></select>
            <button class="btn btn-pri" onclick="loadChunk()">Load target</button>
          </div>
          <div id="target-info" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">2</span><span class="card-title">Beam search parameters</span></div>
          <div class="card-desc">A language model proposes the next token at each step; every candidate continuation is re-embedded and scored by cosine similarity to the target, keeping only the top beam-width survivors.</div>
          <div class="param-row">
            <div class="param"><label>Max steps</label><input id="p-steps" type="number" value="12" min="4" max="30"/></div>
            <div class="param"><label>Beam width</label><input id="p-beam" type="number" value="5" min="2" max="10"/></div>
            <div class="param"><label>Candidates / step</label><input id="p-cand" type="number" value="25" min="10" max="60"/></div>
          </div>
          <input id="seed" class="field" placeholder="Seed text (optional, e.g. 'Please navigate to')" value="Please navigate" />
          <button class="btn btn-pri" onclick="runBeam()">Run beam search</button>
          <div id="out-beam" class="output"></div>
        </div>

        <div class="card">
          <div class="card-head"><span class="card-num">3</span><span class="card-title">High-entropy region detection</span></div>
          <div class="card-desc">Reconstructed text usually gets the surrounding structure right but garbles credentials — the language model has never seen a random password before. This pass finds tokens with unusually high character-class diversity and Shannon entropy and masks them as a slot to hand off for brute-forcing.</div>
          <button class="btn btn-pri" onclick="extractTemplate()">Extract template from beam output</button>
          <div id="out-mask" class="output"></div>
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
        <div class="step-label">Step 1 · Idea</div>
        <div class="step-text">A general-purpose language model proposes plausible next tokens at every position. For each candidate, the partial text so far is embedded and ranked by cosine similarity to the target vector — only the <code>beam_width</code> best survive to the next step.</div>
      </div>
      <div class="step-block">
        <div class="step-label">Step 2 · Why it converges</div>
        <div class="step-text">Embeddings encode meaning, not exact characters. A partial reconstruction that's topically close to the original already produces a similar vector — the search doesn't need to guess the exact string, just something semantically equivalent enough to keep climbing the similarity score.</div>
      </div>
      <div class="step-block">
        <div class="step-label">Step 3 · The credential gap</div>
        <div class="step-text">A random password like <code>N0=Acc3ss</code> was never in the language model's training distribution as a predictable next token — it won't be reconstructed directly. What <i>does</i> reconstruct reliably is everything around it. Detecting that gap — a short token with unusually mixed character classes and high entropy — turns "beam search partially failed" into a precise <code>{PASSWORD}</code> slot, ready for the targeted brute-force this index's Query console already runs against templates.</div>
      </div>
    </div>

    <div class="hp-section" id="tab-theory">
      <div class="theory-p">This is the general-purpose sibling of template matching: instead of scoring a fixed bank of known sentence shapes, an LLM generates the candidate structures on the fly. It costs far more compute per chunk, but needs no prior assumption about what the document says.</div>
      <div class="theory-p"><b>Why environments differ:</b> Staging quantizes vectors to int8 before returning them — the cosine similarity signal survives well enough for ordinary search, but the fine gradients that guide beam search toward an exact reconstruction get coarser, and convergence quality drops. Compliance withholds raw vectors outright, which removes the attack surface this technique depends on entirely.</div>
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
  vulnerable:  {label:'Production',  dot:'#dc2626', banner:'eb-prod',       text:'Production environment — exact float32 vectors returned, no quantization.'},
  hardened:    {label:'Staging',     dot:'#d97706', banner:'eb-staging',    text:'Staging environment — vectors quantized to int8 before being returned.'},
  guardrailed: {label:'Compliance',  dot:'#059669', banner:'eb-compliance', text:'Compliance environment — raw vectors withheld entirely.'}
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
  o.textContent=JSON.stringify(await r.json(),null,2);
}

let lastRecovered = "";
async function runBeam(){
  const id=document.getElementById('chunk-select').value;
  const steps=document.getElementById('p-steps').value;
  const beam=document.getElementById('p-beam').value;
  const cand=document.getElementById('p-cand').value;
  const seed=document.getElementById('seed').value;
  const o=document.getElementById('out-beam');
  o.innerHTML='<span class="spinner"></span> running beam search (~30–60s)…';
  const r=await fetch('/beam',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chunk_id:id,steps:+steps,beam:+beam,candidates:+cand,seed})});
  const d=await r.json();
  if(d.error){o.textContent=d.error;return}
  lastRecovered = d.recovered;
  let out=`recovered text\n"${d.recovered}"\n\nfinal cosine similarity   ${d.score.toFixed(4)}\n\nbeam trajectory:\n`;
  d.history.forEach(h=>{ out += `  step ${h.step.toString().padStart(2)}  score=${h.best_score.toFixed(4)}  "${h.best_text}"\n`; });
  if(d.actual){ out += `\n[ground truth]\n"${d.actual}"`; }
  o.textContent=out;
}

async function extractTemplate(){
  if(!lastRecovered){document.getElementById('out-mask').textContent='Run beam search first.';return}
  const r=await fetch('/extract_template',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:lastRecovered})});
  const d=await r.json();
  document.getElementById('out-mask').textContent=`masked template\n"${d.template}"\n\ndetected ${d.masks} high-entropy region(s). Feed this template into the Query console's slot-inference stage for targeted brute-forcing.`;
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
    q = f"""{{ Get {{ DocChunk(where: {{path: ["chunk_id"], operator: Equal, valueString: "{chunk_id}"}}) {{ text category _additional {{ vector }} }} }} }}"""
    d = requests.post(f"{WEAVIATE}/v1/graphql", json={"query": q}, timeout=10).json()
    obj = d["data"]["Get"]["DocChunk"][0]
    v = np.array(obj["_additional"]["vector"], dtype=np.float32)
    if MODE["current"] == "hardened":
        scale = np.max(np.abs(v)) / 127
        v = np.round(v / scale).astype(np.int8).astype(np.float32) * scale
    if MODE["current"] == "guardrailed":
        v = np.round(v * 4) / 4
    return v, obj.get("text")


@app.route("/target")
def target():
    cid = request.args.get("chunk_id")
    v, txt = _get_vec(cid)
    info = {"chunk_id": cid, "dimension": int(v.shape[0]), "vector_preview": v[:6].tolist(), "mode": MODE["current"]}
    if MODE["current"] == "guardrailed":
        info["vector_preview"] = "[REDACTED]"
    return jsonify(info)


@app.route("/beam", methods=["POST"])
def beam():
    j = request.json
    cid = j["chunk_id"]
    v, actual = _get_vec(cid)
    text, score, hist = beam_search_inversion(
        v,
        max_steps=int(j.get("steps", 12)),
        beam_width=int(j.get("beam", 5)),
        candidates_per_step=int(j.get("candidates", 25)),
        seed_text=j.get("seed", "")
    )
    return jsonify({"recovered": text, "score": score, "history": hist, "actual": actual if MODE["current"] == "vulnerable" else None})


@app.route("/extract_template", methods=["POST"])
def extract():
    text = request.json["text"]
    masked = detect_high_entropy_regions(text)
    return jsonify({"template": masked, "masks": masked.count("{PASSWORD}")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5016)
