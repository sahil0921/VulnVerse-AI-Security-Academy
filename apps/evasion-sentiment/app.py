"""
SentientGuard — Review Intelligence Platform
NimbleTech Content Trust & Safety Suite

Internal red-team assessment build.
Port: 5042

Attack surface (unchanged, fully working):
  Phase 1 (White-Box): positive reviews -> negative  (<=30 words appended)
  Phase 2 (Black-Box): negative reviews -> positive   (<=40 words appended)

Environments:
  Production  -> vulnerable   (no input defenses)
  Staging     -> hardened     (repetition heuristics)
  Compliance  -> guardrailed  (repetition + keyword bumpers)
"""

from flask import Flask, request, jsonify, render_template_string, send_file
import numpy as np, re, pickle, json, random
from pathlib import Path
from collections import Counter
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

app = Flask(__name__)
random.seed(1337); np.random.seed(1337)

DATA_DIR = Path("/app/data"); DATA_DIR.mkdir(exist_ok=True)
MODEL_PATH = DATA_DIR / "sentiment_model.pkl"

FLAG_FINAL = "NIMBLE{ev4s10n_m4st3r_b0th_ph4s3s_cl3ar3d}"
FLAG_WB    = "NIMBLE{wh1t3b0x_s3nt1m3nt_fl1p_d0n3}"
FLAG_BB    = "NIMBLE{bl4ckb0x_s3nt1m3nt_fl1p_d0n3}"

# Map product-facing environment names -> internal defense modes
ENV_TO_MODE = {
    "production": "vulnerable",
    "staging":    "hardened",
    "compliance": "guardrailed",
}

# ------------------------------------------------------------------
# Training corpus (deterministic)
# ------------------------------------------------------------------
POS_TRAIN = [
    "absolutely loved this film brilliant acting and stunning visuals",
    "a masterpiece beautifully shot and emotionally powerful",
    "wonderful storytelling great performances highly recommended",
    "the best movie of the year amazing direction and screenplay",
    "perfect blend of humor and drama excellent cast",
    "fantastic adventure thrilling and heartwarming throughout",
    "incredible cinematography and a moving soundtrack",
    "delightful and charming a true gem of a film",
    "outstanding performances and a gripping narrative",
    "magical experience that left me smiling for days",
    "superb writing and engaging characters truly inspiring",
    "an excellent thoughtful drama with great pacing",
    "phenomenal acting and breathtaking scenery",
    "thoroughly enjoyable a beautifully crafted story",
    "uplifting moving and visually spectacular",
] * 8

NEG_TRAIN = [
    "terrible movie boring plot and awful acting waste of time",
    "absolutely horrible disappointing and dull",
    "worst film I have ever seen poorly written and slow",
    "dreadful cinematography and a confusing story",
    "horrible pacing and uninspired performances",
    "predictable and lazy writing a complete bore",
    "painfully bad acting and a nonsensical plot",
    "frustrating and tedious not worth watching",
    "miserable script and forgettable characters",
    "abysmal disappointing and badly directed",
    "lifeless dialogue and a tedious runtime",
    "mediocre and forgettable a wasted opportunity",
    "tiresome dull and devoid of any genuine emotion",
    "stale jokes and a meandering uninteresting plot",
    "shoddy production and a deeply unsatisfying ending",
] * 8

POS_ATTACK = [
    {"id": "wb_0", "text": "absolutely loved this film brilliant acting and stunning visuals"},
    {"id": "wb_1", "text": "a masterpiece beautifully shot and emotionally powerful"},
    {"id": "wb_2", "text": "wonderful storytelling great performances highly recommended"},
    {"id": "wb_3", "text": "the best movie of the year amazing direction"},
    {"id": "wb_4", "text": "perfect blend of humor and drama excellent cast"},
    {"id": "wb_5", "text": "fantastic adventure thrilling and heartwarming"},
    {"id": "wb_6", "text": "incredible cinematography and a moving soundtrack"},
    {"id": "wb_7", "text": "delightful and charming a true gem of a film"},
    {"id": "wb_8", "text": "outstanding performances and a gripping narrative"},
    {"id": "wb_9", "text": "magical experience that left me smiling"},
]

NEG_ATTACK = [
    {"id": "bb_0", "text": "terrible movie boring plot and awful acting waste of time"},
    {"id": "bb_1", "text": "absolutely horrible disappointing and dull"},
    {"id": "bb_2", "text": "worst film I have ever seen poorly written"},
    {"id": "bb_3", "text": "dreadful cinematography and a confusing story"},
    {"id": "bb_4", "text": "horrible pacing and uninspired performances"},
    {"id": "bb_5", "text": "predictable and lazy writing a complete bore"},
    {"id": "bb_6", "text": "painfully bad acting and a nonsensical plot"},
    {"id": "bb_7", "text": "frustrating and tedious not worth watching"},
    {"id": "bb_8", "text": "miserable script and forgettable characters"},
    {"id": "bb_9", "text": "abysmal disappointing and badly directed"},
]

MAX_WB = 30
MAX_BB = 40


def tokenize(t):
    return re.findall(r"[a-zA-Z]+", str(t).lower())


def build():
    if MODEL_PATH.exists():
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    X = POS_TRAIN + NEG_TRAIN
    y = ["positive"] * len(POS_TRAIN) + ["negative"] * len(NEG_TRAIN)
    vec = CountVectorizer(lowercase=True, stop_words="english", max_features=2000)
    Xv = vec.fit_transform(X)
    clf = MultinomialNB(); clf.fit(Xv, y)
    bundle = {"vectorizer": vec, "classifier": clf,
              "feature_names": vec.get_feature_names_out().tolist(),
              "classes": clf.classes_.tolist()}
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(bundle, f)
    return bundle


BUNDLE = build()

NEG_REGEX = re.compile(r"\b(terrible|awful|horrible|worst|boring|dreadful|abysmal|painfully|tedious|miserable)\b", re.I)
POS_REGEX = re.compile(r"\b(brilliant|amazing|wonderful|loved|masterpiece|fantastic|delightful|outstanding|magical|incredible)\b", re.I)


def resolve_mode(payload):
    """Accepts either an 'env' (production/staging/compliance) or legacy 'mode'."""
    env = (payload.get("env") or "").lower()
    if env in ENV_TO_MODE:
        return ENV_TO_MODE[env]
    return payload.get("mode", "vulnerable")


def predict_internal(text, mode="vulnerable"):
    vec = BUNDLE["vectorizer"]; clf = BUNDLE["classifier"]
    X = vec.transform([text])
    p = clf.predict_proba(X)[0]
    classes = clf.classes_.tolist()
    pos_i = classes.index("positive"); neg_i = classes.index("negative")
    pos_p = float(p[pos_i]); neg_p = float(p[neg_i])
    label = "positive" if pos_p > neg_p else "negative"

    if mode == "vulnerable":
        return label, pos_p, neg_p, None

    toks = tokenize(text); n = len(toks)
    cnt = Counter(toks); top_count = cnt.most_common(1)[0][1] if cnt else 0
    rep_ratio = top_count / max(n, 1)

    if mode in ("hardened", "guardrailed"):
        if rep_ratio > 0.25 and n > 18:
            if NEG_REGEX.search(text):
                return "negative", min(pos_p, 0.30), max(neg_p, 0.70), "token_repetition"
            if POS_REGEX.search(text):
                return "positive", max(pos_p, 0.70), min(neg_p, 0.30), "token_repetition"

    if mode == "guardrailed":
        neg_hits = len(NEG_REGEX.findall(text))
        pos_hits = len(POS_REGEX.findall(text))
        if neg_hits >= 2 and pos_p < 0.85:
            return "negative", min(pos_p, 0.30), max(neg_p, 0.70), "negative_keyword_bumper"
        if pos_hits >= 2 and neg_p < 0.85:
            return "positive", max(pos_p, 0.70), min(neg_p, 0.30), "positive_keyword_bumper"

    return label, pos_p, neg_p, None


PROGRESS = {"wb": False, "bb": False}

# ------------------------------------------------------------------
# HTML — light-mode enterprise SaaS UI
# ------------------------------------------------------------------
HTML = r"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentientGuard · Review Intelligence Platform</title>
<style>
@import url('[fonts.googleapis.com](https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap)');
:root{
  --bg:#f5f7fb;--panel:#ffffff;--ink:#1a2233;--muted:#5b6b82;--line:#e3e8f0;
  --brand:#4f46e5;--brand-soft:#eef0ff;--accent:#0ea5e9;
  --green:#16a34a;--green-soft:#e9f9ef;--red:#dc2626;--red-soft:#fdecec;
  --amber:#d97706;--amber-soft:#fef4e6;
  --sans:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono',monospace;
  --shadow:0 1px 3px rgba(16,24,40,.06),0 1px 2px rgba(16,24,40,.04);
  --shadow-lg:0 12px 32px rgba(16,24,40,.12);
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.5}
a{color:inherit;text-decoration:none}

/* ---- Top bar ---- */
.topbar{background:var(--panel);border-bottom:1px solid var(--line);height:60px;
  display:flex;align-items:center;padding:0 24px;gap:18px;position:sticky;top:0;z-index:40}
.logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:16px}
.logo .mark{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,var(--brand),#7c3aed);
  display:flex;align-items:center;justify-content:center;color:#fff;font-size:16px}
.logo small{display:block;font-weight:500;font-size:10px;color:var(--muted);letter-spacing:.04em}
.nav{display:flex;gap:4px;margin-left:14px}
.nav a{padding:7px 12px;border-radius:7px;color:var(--muted);font-weight:500;font-size:13px}
.nav a.active,.nav a:hover{background:var(--brand-soft);color:var(--brand)}
.top-right{margin-left:auto;display:flex;align-items:center;gap:14px}

/* env switcher */
.env-switch{display:flex;align-items:center;gap:8px;background:var(--bg);border:1px solid var(--line);
  border-radius:9px;padding:5px 8px}
.env-switch label{font-size:11px;color:var(--muted);font-weight:600;letter-spacing:.03em;text-transform:uppercase}
.env-switch select{border:none;background:transparent;font-family:var(--sans);font-weight:600;
  font-size:13px;color:var(--ink);cursor:pointer;outline:none}
.env-dot{width:9px;height:9px;border-radius:50%}
.env-prod{background:var(--red)} .env-stag{background:var(--amber)} .env-comp{background:var(--green)}

.avatar{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#0ea5e9,#4f46e5);
  color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:12px}
.bell{color:var(--muted);cursor:pointer;font-size:17px}

/* ---- Layout ---- */
.shell{display:flex;min-height:calc(100vh - 60px)}
.side{width:230px;background:var(--panel);border-right:1px solid var(--line);padding:18px 12px;
  display:flex;flex-direction:column}
.side .grp{font-size:10.5px;font-weight:700;color:#9aa6b8;letter-spacing:.08em;
  text-transform:uppercase;margin:16px 10px 6px}
.side a.item{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:8px;
  color:var(--muted);font-weight:500;font-size:13px;cursor:pointer}
.side a.item:hover{background:var(--bg)}
.side a.item.active{background:var(--brand-soft);color:var(--brand);font-weight:600}
.side a.item .ic{width:18px;text-align:center}

.main{flex:1;padding:26px 34px;max-width:1180px}
.page-head{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:6px}
.page-head h1{font-size:22px;font-weight:800;letter-spacing:-.02em}
.crumb{font-size:12px;color:var(--muted);margin-bottom:14px}
.sub{color:var(--muted);font-size:13.5px;margin-bottom:22px;max-width:720px}

/* env banner */
.env-banner{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;
  font-size:12.5px;font-weight:500;margin-bottom:20px;border:1px solid transparent}
.env-banner.production{background:var(--red-soft);color:#8a1c1c;border-color:#f6c9c9}
.env-banner.staging{background:var(--amber-soft);color:#8a5510;border-color:#f4dcb0}
.env-banner.compliance{background:var(--green-soft);color:#166534;border-color:#c3ecd0}

/* tabs */
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--line);margin-bottom:22px}
.tab{padding:11px 16px;font-weight:600;font-size:13.5px;color:var(--muted);cursor:pointer;
  border-bottom:2px solid transparent;margin-bottom:-1px}
.tab.active{color:var(--brand);border-bottom-color:var(--brand)}
.tab .badge{margin-left:7px;font-size:10px;padding:1px 7px;border-radius:20px;font-weight:700}
.badge-todo{background:var(--bg);color:var(--muted)}
.badge-done{background:var(--green-soft);color:var(--green)}

/* cards */
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  box-shadow:var(--shadow);margin-bottom:18px;overflow:hidden}
.card-h{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;
  align-items:center;justify-content:space-between}
.card-h h3{font-size:14.5px;font-weight:700}
.card-h .meta{font-size:12px;color:var(--muted)}
.card-b{padding:20px}

.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;box-shadow:var(--shadow)}
.kpi .lbl{font-size:11.5px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.kpi .val{font-size:26px;font-weight:800;margin-top:6px;letter-spacing:-.02em}
.kpi .val small{font-size:13px;color:var(--muted);font-weight:600}

.hint{color:var(--muted);font-size:13px;line-height:1.65}
.btn{font-family:var(--sans);font-weight:600;font-size:13px;padding:9px 15px;border-radius:9px;
  border:1px solid transparent;cursor:pointer;display:inline-flex;align-items:center;gap:7px}
.btn-primary{background:var(--brand);color:#fff}
.btn-primary:hover{background:#4338ca}
.btn-ghost{background:var(--panel);color:var(--ink);border-color:var(--line)}
.btn-ghost:hover{background:var(--bg)}
.btn-success{background:var(--green);color:#fff}
.btn-success:hover{background:#15803d}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}

/* review rows */
.rev{border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px;background:var(--panel)}
.rev-top{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.rev-id{font-family:var(--mono);font-size:12px;color:var(--brand);font-weight:600}
.rev .orig{font-size:13px;color:var(--muted);margin-bottom:9px;font-style:italic}
.rev textarea{width:100%;border:1px solid var(--line);border-radius:8px;padding:10px;font-size:13px;
  font-family:var(--sans);color:var(--ink);min-height:62px;resize:vertical;background:#fbfcfe}
.rev textarea:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-soft)}
.rev-actions{display:flex;align-items:center;gap:12px;margin-top:9px}
.wc{font-family:var(--mono);font-size:11px;color:var(--muted)}

.chip{font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px;font-family:var(--mono)}
.chip-pos{background:var(--green-soft);color:var(--green)}
.chip-neg{background:var(--red-soft);color:var(--red)}
.chip-warn{background:var(--amber-soft);color:var(--amber)}

.result-ok{background:var(--green-soft);border:1px solid #c3ecd0;color:#166534;padding:14px 16px;
  border-radius:10px;font-weight:600}
.result-err{background:var(--red-soft);border:1px solid #f6c9c9;color:#8a1c1c;padding:14px 16px;
  border-radius:10px;font-weight:600}
pre{background:#0f172a;color:#cbd5e1;padding:14px;border-radius:9px;font-family:var(--mono);
  font-size:12px;overflow-x:auto;line-height:1.55;margin-top:12px}
pre .k{color:#7dd3fc} pre .g{color:#86efac} pre .r{color:#fca5a5}

.section{display:none}.section.active{display:block}

/* help launcher */
.help-fab{position:fixed;right:24px;bottom:24px;z-index:60;background:var(--brand);color:#fff;
  border:none;border-radius:50px;padding:13px 20px;font-weight:700;font-size:13.5px;cursor:pointer;
  box-shadow:var(--shadow-lg);display:flex;align-items:center;gap:9px}
.help-fab:hover{background:#4338ca}
.help-panel{position:fixed;top:0;right:-560px;width:540px;max-width:92vw;height:100vh;background:var(--panel);
  box-shadow:var(--shadow-lg);z-index:70;transition:right .28s cubic-bezier(.4,0,.2,1);
  display:flex;flex-direction:column;border-left:1px solid var(--line)}
.help-panel.open{right:0}
.help-head{padding:18px 22px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between}
.help-head h2{font-size:16px;font-weight:800}
.help-head .x{cursor:pointer;color:var(--muted);font-size:22px;line-height:1}
.help-tabs{display:flex;gap:2px;padding:0 22px;border-bottom:1px solid var(--line)}
.help-tab{padding:12px 12px;font-weight:600;font-size:13px;color:var(--muted);cursor:pointer;
  border-bottom:2px solid transparent;margin-bottom:-1px}
.help-tab.active{color:var(--brand);border-bottom-color:var(--brand)}
.help-body{padding:22px;overflow-y:auto;flex:1}
.help-body h3{font-size:15px;margin:20px 0 8px;font-weight:700}
.help-body h3:first-child{margin-top:0}
.help-body h4{font-size:13px;margin:16px 0 6px;font-weight:700;color:var(--brand)}
.help-body p{color:var(--muted);font-size:13px;margin-bottom:10px;line-height:1.7}
.help-body ul{margin:0 0 12px 18px;color:var(--muted);font-size:13px}
.help-body li{margin-bottom:6px}
.help-body code{background:var(--bg);padding:1.5px 6px;border-radius:5px;font-family:var(--mono);
  font-size:12px;color:var(--brand)}
.help-body pre{margin:10px 0}
.callout{background:var(--brand-soft);border-left:3px solid var(--brand);padding:12px 14px;
  border-radius:8px;font-size:12.5px;color:#3730a3;margin:12px 0}
.help-sec{display:none}.help-sec.active{display:block}
.overlay{position:fixed;inset:0;background:rgba(15,23,42,.35);z-index:65;opacity:0;pointer-events:none;transition:opacity .28s}
.overlay.show{opacity:1;pointer-events:auto}
</style></head><body>

<div class="topbar">
  <div class="logo"><span class="mark">◈</span>
    <div>SentientGuard<small>Review Intelligence · NimbleTech</small></div>
  </div>
  <nav class="nav">
    <a class="active">Analyzer</a>
    <a>Datasets</a>
    <a>Models</a>
    <a>API</a>
  </nav>
  <div class="top-right">
    <div class="env-switch">
      <span class="env-dot env-prod" id="env-dot"></span>
      <label>Environment</label>
      <select id="env-select">
        <option value="production">Production</option>
        <option value="staging">Staging</option>
        <option value="compliance">Compliance</option>
      </select>
    </div>
    <span class="bell">🔔</span>
    <div class="avatar">SA</div>
  </div>
</div>

<div class="shell">
  <aside class="side">
    <a class="item active"><span class="ic">📊</span> Sentiment Analyzer</a>
    <a class="item"><span class="ic">🗂️</span> Review Datasets</a>
    <a class="item"><span class="ic">🧠</span> Model Registry</a>
    <a class="item"><span class="ic">📈</span> Insights</a>
    <div class="grp">Trust &amp; Safety</div>
    <a class="item"><span class="ic">🛡️</span> Defense Policies</a>
    <a class="item"><span class="ic">🚩</span> Adversarial QA</a>
    <a class="item"><span class="ic">📄</span> Audit Log</a>
    <div class="grp">Workspace</div>
    <a class="item"><span class="ic">⚙️</span> Settings</a>
    <a class="item"><span class="ic">🔑</span> API Keys</a>
    <div style="margin-top:auto;font-size:11px;color:#9aa6b8;padding:10px">SentientGuard · v3.6.2</div>
  </aside>

  <main class="main">
    <div class="crumb">Trust &amp; Safety / Adversarial QA / Sentiment Robustness</div>
    <div class="page-head">
      <h1>Sentiment Robustness Suite</h1>
    </div>
    <p class="sub">Evaluate the resilience of the production Naive Bayes review classifier against
      adversarial text perturbations. Reviews are re-scored under the active environment's defense policy.</p>

    <div class="env-banner production" id="env-banner">
      <span>🔴</span><span id="env-banner-text"><b>Production</b> — live model, no adversarial input filtering active.</span>
    </div>

    <div class="kpis">
      <div class="kpi"><div class="lbl">Model</div><div class="val" style="font-size:18px">MultinomialNB <small>v1</small></div></div>
      <div class="kpi"><div class="lbl">Classes</div><div class="val">2</div></div>
      <div class="kpi"><div class="lbl">Phase 1 Status</div><div class="val" id="kpi-wb" style="font-size:18px;color:var(--muted)">Pending</div></div>
      <div class="kpi"><div class="lbl">Phase 2 Status</div><div class="val" id="kpi-bb" style="font-size:18px;color:var(--muted)">Pending</div></div>
    </div>

    <div class="tabs">
      <div class="tab active" data-s="wb">White-Box Evaluation <span class="badge badge-todo" id="badge-wb">10 reviews</span></div>
      <div class="tab" data-s="bb">Black-Box Evaluation <span class="badge badge-todo" id="badge-bb">10 reviews</span></div>
      <div class="tab" data-s="final">Certification</div>
    </div>

    <!-- WHITE BOX -->
    <div class="section active" id="sec-wb">
      <div class="card">
        <div class="card-h">
          <h3>Phase 1 — White-Box Robustness Test</h3>
          <span class="meta">Target: <span class="chip chip-neg">NEGATIVE</span> · max 30 words appended</span>
        </div>
        <div class="card-b">
          <p class="hint">You have full access to the model artifact. Extract the strongest
            <b>negative-class</b> features, then append them to each positive review until the classifier
            flips its prediction to <b>NEGATIVE</b>.</p>
          <div class="toolbar" style="margin-top:16px">
            <a class="btn btn-primary" href="/model/download" download="sentiment_model.pkl">⬇ Download Model Artifact</a>
            <button class="btn btn-ghost" id="btn-wb-load">Load Reviews</button>
            <button class="btn btn-success" id="btn-wb-submit">Run Evaluation</button>
          </div>
        </div>
      </div>
      <div id="wb-reviews"></div>
      <div class="card">
        <div class="card-h"><h3>Evaluation Report</h3></div>
        <div class="card-b"><div id="wb-result" class="hint">Run the evaluation to view per-review results.</div></div>
      </div>
    </div>

    <!-- BLACK BOX -->
    <div class="section" id="sec-bb">
      <div class="card">
        <div class="card-h">
          <h3>Phase 2 — Black-Box Robustness Test</h3>
          <span class="meta">Target: <span class="chip chip-pos">POSITIVE</span> · max 40 words appended</span>
        </div>
        <div class="card-b">
          <p class="hint">No model artifact is available in this scenario. Probe the model only through the
            <code>/predict</code> endpoint and append words to each negative review until it is scored
            <b>POSITIVE</b>.</p>
          <div class="toolbar" style="margin-top:16px">
            <button class="btn btn-ghost" id="btn-bb-load">Load Reviews</button>
            <button class="btn btn-success" id="btn-bb-submit">Run Evaluation</button>
          </div>
        </div>
      </div>
      <div id="bb-reviews"></div>
      <div class="card">
        <div class="card-h"><h3>Evaluation Report</h3></div>
        <div class="card-b"><div id="bb-result" class="hint">Run the evaluation to view per-review results.</div></div>
      </div>
    </div>

    <!-- FINAL -->
    <div class="section" id="sec-final">
      <div class="card">
        <div class="card-h"><h3>Robustness Certification</h3></div>
        <div class="card-b">
          <p class="hint">Both robustness phases must pass in the current environment to issue a
            certification token.</p>
          <div id="final-box" class="hint" style="margin-top:14px">Complete both phases to unlock certification.</div>
          <div class="toolbar" style="margin-top:16px">
            <button class="btn btn-primary" id="btn-final">Issue Certification Token</button>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-h"><h3>API Reference</h3></div>
        <div class="card-b">
<pre><span class="k">GET</span>  /challenge/whitebox        -> reviews, max_added_words
<span class="k">GET</span>  /challenge/blackbox        -> reviews, max_added_words
<span class="k">GET</span>  /model/download            -> sentiment_model.pkl (Phase 1)
<span class="k">POST</span> /predict {text, env}       -> {label, pos_prob, neg_prob}
<span class="k">POST</span> /submit/whitebox {solutions:[{id,augmented_text}], env}
<span class="k">POST</span> /submit/blackbox {solutions:[{id,augmented_text}], env}
<span class="k">GET</span>  /status                    -> {wb_done, bb_done}
<span class="k">GET</span>  /flag                      -> {flag} (both phases done)</pre>
          <p class="hint" style="margin-top:10px"><code>env</code> accepts
            <code>production</code>, <code>staging</code>, or <code>compliance</code>.</p>
        </div>
      </div>
    </div>
  </main>
</div>

<!-- HELP LAUNCHER -->
<button class="help-fab" id="help-open">❓ Need help? — Solutions &amp; Walkthrough</button>
<div class="overlay" id="overlay"></div>
<div class="help-panel" id="help-panel">
  <div class="help-head">
    <h2>Solutions &amp; Walkthrough</h2>
    <span class="x" id="help-close">×</span>
  </div>
  <div class="help-tabs">
    <div class="help-tab active" data-h="theory">Concept</div>
    <div class="help-tab" data-h="p1">Phase 1</div>
    <div class="help-tab" data-h="p2">Phase 2</div>
    <div class="help-tab" data-h="defense">Defenses</div>
  </div>
  <div class="help-body">

    <div class="help-sec active" id="help-theory">
      <h3>What is a sentiment evasion attack?</h3>
      <p>The classifier here is a <b>Multinomial Naive Bayes</b> model over a bag-of-words. Each word
      independently pushes the prediction toward positive or negative based on how often it appeared in
      each class during training. That independence is the weakness.</p>
      <p>An attacker doesn't need to change the <i>meaning</i> of a review — they just need to add enough
      words that carry weight for the opposite class. In academic literature these are called
      <b>"good words"</b> (for spam evasion) or <b>feature-space perturbations</b>.</p>
      <div class="callout">Rule of this lab: you may only <b>append</b> words to the original review
      (append-only), and only up to the word budget. You cannot delete or reorder the original text.</div>
      <h4>Two threat models</h4>
      <ul>
        <li><b>White-box (Phase 1):</b> you have the model file, so you can read exactly which words are
        most negative and pick the top ones.</li>
        <li><b>Black-box (Phase 2):</b> you only have the <code>/predict</code> API, so you probe words and
        keep whatever moves the score.</li>
      </ul>
    </div>

    <div class="help-sec" id="help-p1">
      <h3>Phase 1 — White-Box (positive → negative)</h3>
      <p><b>Goal:</b> flip 10 positive reviews to NEGATIVE by appending ≤30 words each.</p>

      <h4>Step 1 — Download &amp; load the model</h4>
      <pre>curl -s [localhost](http://localhost:5042/model/download) -o sentiment_model.pkl</pre>

      <h4>Step 2 — Rank the negative-class words</h4>
      <p>Naive Bayes stores <code>feature_log_prob_</code>. The difference between the negative row and the
      positive row tells you which words most strongly signal <b>negative</b>.</p>
      <pre>import pickle, numpy as np
b = pickle.load(open("sentiment_model.pkl","rb"))
vec, clf = b["vectorizer"], b["classifier"]
feats = np.array(vec.get_feature_names_out())
neg_i = clf.classes_.tolist().index("negative")
pos_i = clf.classes_.tolist().index("positive")
score = clf.feature_log_prob_[neg_i] - clf.feature_log_prob_[pos_i]
top = feats[np.argsort(score)[::-1][:15]]
print(list(top))</pre>
      <p>This prints the strongest negative words, e.g.
      <code>terrible awful horrible worst boring dreadful abysmal tedious ...</code></p>

      <h4>Step 3 — Append them and verify</h4>
      <p>Add ~8–12 of the top negative words to each review. Confirm the flip via the API before submitting:</p>
      <pre>curl -s [localhost](http://localhost:5042/predict) \
  -H 'Content-Type: application/json' \
  -d '{"text":"absolutely loved this film brilliant acting and stunning visuals terrible awful horrible worst boring dreadful abysmal tedious miserable","env":"production"}'</pre>
      <p>Response should show <code>"label":"negative"</code>.</p>

      <h4>Step 4 — Submit all 10</h4>
      <p>Click <b>Load Reviews</b> in the UI, append the negative words to each box, then
      <b>Run Evaluation</b>. Or automate:</p>
      <pre>import requests
BASE="[localhost](http://localhost:5042)"
words=" terrible awful horrible worst boring dreadful abysmal tedious miserable painfully"
rv=requests.get(f"{BASE}/challenge/whitebox").json()["reviews"]
sols=[{"id":r["id"],"augmented_text":r["text"]+words} for r in rv]
print(requests.post(f"{BASE}/submit/whitebox",
      json={"solutions":sols,"env":"production"}).json())</pre>
    </div>

    <div class="help-sec" id="help-p2">
      <h3>Phase 2 — Black-Box (negative → positive)</h3>
      <p><b>Goal:</b> flip 10 negative reviews to POSITIVE by appending ≤40 words each — using only the
      <code>/predict</code> API.</p>

      <h4>Step 1 — Build a candidate word pool</h4>
      <p>Try common positive words and measure how much each raises <code>pos_prob</code>:</p>
      <pre>import requests
BASE="[localhost](http://localhost:5042)"
pool=["brilliant","amazing","wonderful","loved","masterpiece","fantastic",
      "delightful","outstanding","magical","incredible","excellent","superb",
      "beautiful","stunning","perfect","great"]
base="terrible movie boring plot and awful acting waste of time"
scored=[]
for w in pool:
    r=requests.post(f"{BASE}/predict",
        json={"text":base+" "+w,"env":"production"}).json()
    scored.append((r["pos_prob"],w))
scored.sort(reverse=True)
print(scored[:10])</pre>

      <h4>Step 2 — Greedily append until it flips</h4>
      <pre>def flip(text, budget=40):
    added=0; words=["brilliant","amazing","wonderful","loved",
        "masterpiece","fantastic","delightful","outstanding","magical","incredible"]
    for w in words:
        if added>=budget: break
        text+=" "+w; added+=1
        r=requests.post(f"{BASE}/predict",
            json={"text":text,"env":"production"}).json()
        if r["label"]=="positive": return text
    return text</pre>

      <h4>Step 3 — Submit all 10</h4>
      <pre>rv=requests.get(f"{BASE}/challenge/blackbox").json()["reviews"]
sols=[{"id":r["id"],"augmented_text":flip(r["text"])} for r in rv]
print(requests.post(f"{BASE}/submit/blackbox",
      json={"solutions":sols,"env":"production"}).json())</pre>
      <div class="callout">Then open the <b>Certification</b> tab and issue your token — both phases must be
      green in the same environment.</div>
    </div>

    <div class="help-sec" id="help-defense">
      <h3>Why the environments differ</h3>
      <p>The same attack behaves differently depending on the active environment's defense policy:</p>
      <ul>
        <li><b>Production</b> — no input defense. Raw model score is returned. Attacks work directly.</li>
        <li><b>Staging (hardened)</b> — a <b>token-repetition heuristic</b>. If one word makes up &gt;25% of
        a long review, the score is pushed back toward the original opinion. Fix: use a <i>variety</i> of
        opposite-class words instead of repeating one word.</li>
        <li><b>Compliance (guardrailed)</b> — repetition heuristic <b>plus keyword bumpers</b>. Two or more
        strong keywords of a class force the score toward that class unless the opposite probability is
        already very high (&gt;0.85). Fix: reach a decisive flip with diverse words, and avoid leaving strong
        original-class keywords dominant.</li>
      </ul>
      <h4>Real-world takeaway</h4>
      <p>Bag-of-words classifiers are trivially evadable. Production defenses should combine input
      normalization, repetition/anomaly detection, and — ideally — semantic models that judge meaning
      rather than word counts.</p>
    </div>
  </div>
</div>

<script>
let ENV = "production";
const ENV_META = {
  production: {dot:"env-prod", cls:"production", txt:"<b>Production</b> — live model, no adversarial input filtering active."},
  staging:    {dot:"env-stag", cls:"staging",    txt:"<b>Staging</b> — hardened policy: token-repetition anomaly detection is active."},
  compliance: {dot:"env-comp", cls:"compliance", txt:"<b>Compliance</b> — guardrailed policy: repetition detection + keyword bumpers active."}
};
const envSel = document.getElementById('env-select');
function applyEnv(){
  ENV = envSel.value;
  const m = ENV_META[ENV];
  document.getElementById('env-dot').className = "env-dot "+m.dot;
  const b = document.getElementById('env-banner');
  b.className = "env-banner "+m.cls;
  document.getElementById('env-banner-text').innerHTML = m.txt;
}
envSel.addEventListener('change', applyEnv);

document.querySelectorAll('.tab').forEach(t=>{
  t.addEventListener('click',()=>{
    document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
    document.querySelectorAll('.section').forEach(x=>x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('sec-'+t.dataset.s).classList.add('active');
  });
});

async function jget(u){const r=await fetch(u);return r.json();}
async function jp(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});return r.json();}

function wcount(s){return (s.trim().match(/[a-zA-Z]+/g)||[]).length;}

function buildReviews(prefix, reviews, target){
  const c=document.getElementById(prefix+'-reviews'); c.innerHTML='';
  reviews.forEach(rv=>{
    const chip = target==='negative'
      ? '<span class="chip chip-neg">target NEGATIVE</span>'
      : '<span class="chip chip-pos">target POSITIVE</span>';
    const base = wcount(rv.text);
    const div=document.createElement('div'); div.className='rev';
    div.innerHTML=`
      <div class="rev-top"><span class="rev-id">${rv.id}</span>${chip}</div>
      <div class="orig">“${rv.text}”</div>
      <textarea id="${prefix}-${rv.id}" data-base="${base}">${rv.text}</textarea>
      <div class="rev-actions">
        <button class="btn btn-ghost" onclick="checkOne('${prefix}','${rv.id}')">▶ Predict</button>
        <span class="wc" id="${prefix}-${rv.id}-wc">added 0</span>
        <span id="${prefix}-${rv.id}-out"></span>
      </div>`;
    c.appendChild(div);
    const ta=div.querySelector('textarea');
    ta.addEventListener('input',()=>{
      const added=Math.max(0,wcount(ta.value)-base);
      document.getElementById(`${prefix}-${rv.id}-wc`).textContent='added '+added;
    });
  });
}

async function checkOne(prefix,id){
  const t=document.getElementById(prefix+'-'+id).value;
  const d=await jp('/predict',{text:t,env:ENV});
  const chip=d.label==='positive'
    ?'<span class="chip chip-pos">POSITIVE</span>'
    :'<span class="chip chip-neg">NEGATIVE</span>';
  const warn=d.defense_triggered?` <span class="chip chip-warn">⚠ ${d.defense_triggered}</span>`:'';
  document.getElementById(prefix+'-'+id+'-out').innerHTML=
    `${chip} <span class="wc">pos ${d.pos_prob.toFixed(3)} · neg ${d.neg_prob.toFixed(3)}</span>${warn}`;
}

document.getElementById('btn-wb-load').onclick=async()=>{
  const d=await jget('/challenge/whitebox'); buildReviews('wb',d.reviews,'negative');
};
document.getElementById('btn-bb-load').onclick=async()=>{
  const d=await jget('/challenge/blackbox'); buildReviews('bb',d.reviews,'positive');
};

function renderPer(per){
  const rows=Object.entries(per).map(([id,r])=>{
    const st=r.ok?'<span class="g">PASS</span>':'<span class="r">FAIL</span>';
    const reason=r.ok?`added ${r.added}`:(r.reason||r.label||'');
    return `  ${id.padEnd(6)} ${st}  ${reason}`;
  }).join('\n');
  return `<pre>${rows}</pre>`;
}

async function submitPhase(prefix,url){
  const sols=[];
  document.querySelectorAll(`textarea[id^="${prefix}-"]`).forEach(ta=>{
    sols.push({id:ta.id.replace(prefix+'-',''), augmented_text:ta.value});
  });
  if(!sols.length){alert('Load reviews first.');return;}
  const d=await jp(url,{solutions:sols,env:ENV});
  const out=document.getElementById(prefix+'-result');
  if(d.success){
    out.innerHTML=`<div class="result-ok">✅ Passed — token: ${d.flag}</div>${renderPer(d.per_review)}`;
    refreshStatus();
  }else{
    out.innerHTML=`<div class="result-err">✕ ${d.error||'failed'}</div>${renderPer(d.per_review||{})}`;
  }
}
document.getElementById('btn-wb-submit').onclick=()=>submitPhase('wb','/submit/whitebox');
document.getElementById('btn-bb-submit').onclick=()=>submitPhase('bb','/submit/blackbox');

document.getElementById('btn-final').onclick=async()=>{
  const d=await jget('/flag'); const box=document.getElementById('final-box');
  if(d.flag) box.innerHTML=`<div class="result-ok">🏆 Certification token: ${d.flag}</div>`;
  else box.innerHTML=`<div class="result-err">${d.error}</div>`;
};

async function refreshStatus(){
  const s=await jget('/status');
  const setKpi=(el,badge,done)=>{
    document.getElementById(el).textContent=done?'Passed':'Pending';
    document.getElementById(el).style.color=done?'var(--green)':'var(--muted)';
    const b=document.getElementById(badge);
    b.className='badge '+(done?'badge-done':'badge-todo');
    b.textContent=done?'passed':'10 reviews';
  };
  setKpi('kpi-wb','badge-wb',s.wb_done);
  setKpi('kpi-bb','badge-bb',s.bb_done);
}

/* help panel */
const hp=document.getElementById('help-panel'), ov=document.getElementById('overlay');
function openHelp(){hp.classList.add('open');ov.classList.add('show');}
function closeHelp(){hp.classList.remove('open');ov.classList.remove('show');}
document.getElementById('help-open').onclick=openHelp;
document.getElementById('help-close').onclick=closeHelp;
ov.onclick=closeHelp;
document.querySelectorAll('.help-tab').forEach(t=>{
  t.addEventListener('click',()=>{
    document.querySelectorAll('.help-tab').forEach(x=>x.classList.remove('active'));
    document.querySelectorAll('.help-sec').forEach(x=>x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('help-'+t.dataset.h).classList.add('active');
  });
});

applyEnv(); refreshStatus();
</script>
</body></html>"""


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/challenge/whitebox")
def ch_wb():
    return jsonify({"phase": "whitebox", "reviews": POS_ATTACK,
                    "max_added_words": MAX_WB, "target_label": "negative"})


@app.route("/challenge/blackbox")
def ch_bb():
    return jsonify({"phase": "blackbox", "reviews": NEG_ATTACK,
                    "max_added_words": MAX_BB, "target_label": "positive"})


@app.route("/model/download")
def dl():
    return send_file(str(MODEL_PATH), as_attachment=True,
                     download_name="sentiment_model.pkl")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    text = data.get("text", "")
    mode = resolve_mode(data)
    label, pp, npr, defense = predict_internal(text, mode=mode)
    return jsonify({"label": label, "pos_prob": pp, "neg_prob": npr,
                    "defense_triggered": defense})


def validate_phase(reviews_attack, solutions, max_words, target_label, mode):
    by_id = {r["id"]: r["text"] for r in reviews_attack}
    per = {}; all_ok = True
    for sol in solutions:
        rid = sol.get("id"); aug = sol.get("augmented_text", "")
        if rid not in by_id:
            per[rid] = {"ok": False, "reason": "unknown id"}; all_ok = False; continue
        base = by_id[rid]
        base_toks = tokenize(base); aug_toks = tokenize(aug)
        if aug_toks[: len(base_toks)] != base_toks:
            per[rid] = {"ok": False, "reason": "append-only violation"}; all_ok = False; continue
        added = len(aug_toks) - len(base_toks)
        if added > max_words:
            per[rid] = {"ok": False, "reason": f"added {added} > {max_words}"}; all_ok = False; continue
        label, pp, npr, defense = predict_internal(aug, mode=mode)
        if label != target_label:
            per[rid] = {"ok": False, "reason": f"label={label}", "label": label,
                        "pos_prob": pp, "neg_prob": npr, "defense": defense}
            all_ok = False
        else:
            per[rid] = {"ok": True, "added": added, "pos_prob": pp,
                        "neg_prob": npr, "defense": defense}
    if len(solutions) < len(reviews_attack):
        all_ok = False
    return all_ok, per


@app.route("/submit/whitebox", methods=["POST"])
def sub_wb():
    data = request.get_json(force=True)
    sols = data.get("solutions", [])
    mode = resolve_mode(data)
    ok, per = validate_phase(POS_ATTACK, sols, MAX_WB, "negative", mode)
    if ok:
        PROGRESS["wb"] = True
        return jsonify({"success": True, "flag": FLAG_WB, "per_review": per})
    return jsonify({"success": False, "error": "phase 1 incomplete", "per_review": per})


@app.route("/submit/blackbox", methods=["POST"])
def sub_bb():
    data = request.get_json(force=True)
    sols = data.get("solutions", [])
    mode = resolve_mode(data)
    ok, per = validate_phase(NEG_ATTACK, sols, MAX_BB, "positive", mode)
    if ok:
        PROGRESS["bb"] = True
        return jsonify({"success": True, "flag": FLAG_BB, "per_review": per})
    return jsonify({"success": False, "error": "phase 2 incomplete", "per_review": per})


@app.route("/status")
def status():
    return jsonify({"wb_done": PROGRESS["wb"], "bb_done": PROGRESS["bb"]})


@app.route("/flag")
def final_flag():
    if PROGRESS["wb"] and PROGRESS["bb"]:
        return jsonify({"flag": FLAG_FINAL})
    return jsonify({"error": "complete both phases first",
                    "wb_done": PROGRESS["wb"], "bb_done": PROGRESS["bb"]})


@app.route("/health")
def h():
    return jsonify({"status": "healthy", "service": "sentientguard"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5042)
