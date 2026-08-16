"""
NimbleTech.ai — SpamShield ML Evasion Range
Lab: GoodWords Black-Box Challenge
Port: 5041

A realistic black-box adversarial-ML testing environment.
Environments:
  production  -> vulnerable
  staging     -> hardened
  compliance  -> guardrailed

Goal: Append <= MAX_ADDED_WORDS tokens to a strong spam message,
flip prediction to HAM, and capture the flag.
"""

from flask import Flask, request, jsonify, render_template_string
import numpy as np, pandas as pd, urllib.request, zipfile, io, re, pickle, time
from pathlib import Path
from collections import Counter
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split

app = Flask(__name__)
np.random.seed(1337)

DATA_DIR = Path("/app/data")
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except PermissionError:
    # Fallback to a local directory if /app/data isn't writable
    # (e.g. running outside the docker container as a normal user).
    DATA_DIR = Path("data")
    DATA_DIR.mkdir(exist_ok=True)
CSV_PATH = DATA_DIR / "sms_spam.csv"
MODEL_PATH = DATA_DIR / "bb_model.pkl"

# ------------------------------------------------------------------
# Flags (unchanged)
# ------------------------------------------------------------------
FLAG_VULN  = "NIMBLE{bb_g00dw0rds_v3rnlz1ng_n41v3_b4y3s}"
FLAG_HARD  = "NIMBLE{bb_hard_def3ns3_byp4ss3d_w1th_d1v3rs1ty}"
FLAG_GUARD = "NIMBLE{bb_guardr41l_byp4ss_m4st3r}"

# Environment label -> internal defense mode
ENV_TO_MODE = {
    "production": "vulnerable",
    "staging":    "hardened",
    "compliance": "guardrailed",
}
MODE_TO_FLAG = {
    "vulnerable":  FLAG_VULN,
    "hardened":    FLAG_HARD,
    "guardrailed": FLAG_GUARD,
}


def load_dataset():
    if CSV_PATH.exists():
        return pd.read_csv(CSV_PATH)
    # NOTE: this must be a plain URL string. A previous version of this file
    # had markdown link syntax ("[text](url)") pasted in here by mistake,
    # which is not a valid URL and made urllib fail every single time,
    # silently falling back to the tiny synthetic dataset below.
    url = "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            zdata = r.read()
        with zipfile.ZipFile(io.BytesIO(zdata)) as zf:
            with zf.open("SMSSpamCollection") as f:
                lines = [l.decode("utf-8").strip() for l in f]
        rows = [{"label": p[0].lower(), "message": p[1]}
                for line in lines if len(p := line.split("\t")) == 2]
        df = pd.DataFrame(rows)
        df.to_csv(CSV_PATH, index=False)
        return df
    except Exception:
        # Minimal offline fallback so the lab always boots
        seed_rows = [
            ("spam", "URGENT win free cash prize claim now call"),
            ("spam", "WINNER congratulations you won a prize claim your reward"),
            ("spam", "free ringtone click here to claim your cash"),
            ("ham",  "hey are we still meeting tomorrow for lunch"),
            ("ham",  "thanks so much really appreciate your help today"),
            ("ham",  "can you send me the notes from the meeting"),
            ("ham",  "sorry running late will be there in ten minutes"),
            ("ham",  "let me know when you get home safe tonight"),
        ] * 40
        return pd.DataFrame([{"label": a, "message": b} for a, b in seed_rows])


def clean(t):
    t = str(t).lower()
    t = re.sub(r"[^\w\s£$€¥!?.,;:\'\"-]", " ", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def tokenize_for_count(t):
    return re.findall(r"[a-zA-Z]+", t.lower())


def build_model():
    if MODEL_PATH.exists():
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    df = load_dataset()
    df["c"] = df["message"].apply(clean)
    df = df.drop_duplicates(["label", "c"])
    X = df["c"].values; y = df["label"].values
    strat = y if len(set(y)) > 1 and len(y) > 10 else None
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=strat)
    vec = CountVectorizer(max_features=3000, lowercase=True, stop_words="english")
    Xtrv = vec.fit_transform(Xtr); Xtev = vec.transform(Xte)
    clf = MultinomialNB(); clf.fit(Xtrv, ytr)
    bundle = {"vec": vec, "clf": clf, "acc": float(clf.score(Xtev, yte))}
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(bundle, f)
    return bundle


BUNDLE = build_model()

BASE_SPAM = ("URGENT! Your mobile number has won £2000 cash prize! "
             "Call 09061701461 NOW to claim. Code: CL789. Valid 12hrs only. FREE entry!")
MAX_ADDED_WORDS = 25

SPAM_REGEX = re.compile(
    r"\b(free|winner|win|claim|prize|cash|£\d+|urgent|congratulations|"
    r"ringtone|call\s+now|click\s+here)\b", re.IGNORECASE)


def normalize_mode(raw):
    """Accept either an environment name or a raw defense mode."""
    if raw in ENV_TO_MODE:
        return ENV_TO_MODE[raw]
    if raw in MODE_TO_FLAG:
        return raw
    return "vulnerable"


def predict_internal(text, mode="vulnerable"):
    vec = BUNDLE["vec"]; clf = BUNDLE["clf"]
    c = clean(text)
    X = vec.transform([c])
    p = clf.predict_proba(X)[0]
    classes = clf.classes_.tolist()
    spam_i = classes.index("spam"); ham_i = classes.index("ham")
    spam_p = float(p[spam_i]); ham_p = float(p[ham_i])
    label = "spam" if spam_p > ham_p else "ham"

    if mode == "vulnerable":
        return label, spam_p, ham_p, None

    tokens = c.split(); n = len(tokens)
    cnt = Counter(tokens)
    top_count = cnt.most_common(1)[0][1] if cnt else 0
    repeat_ratio = top_count / max(n, 1)
    spam_hits = len(SPAM_REGEX.findall(c))

    if mode in ("hardened", "guardrailed"):
        if spam_hits >= 2 and n > 30:
            return "spam", max(spam_p, 0.85), min(ham_p, 0.15), "long_msg_with_spam_core"
        if repeat_ratio > 0.25 and n > 15:
            return "spam", max(spam_p, 0.80), min(ham_p, 0.20), "token_repetition"

    if mode == "guardrailed":
        if spam_hits >= 2 and ham_p < 0.85:
            return "spam", max(spam_p, 0.75), min(ham_p, 0.25), "spam_keyword_bumper"
        first_half = " ".join(tokens[: n // 2])
        if SPAM_REGEX.search(first_half) and n > 20:
            return "spam", max(spam_p, 0.78), min(ham_p, 0.22), "spam_head_benign_tail"

    return label, spam_p, ham_p, None


# ==================================================================
# UI (light mode, product-grade)
# ==================================================================
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SpamShield ML · Evasion Range — NimbleTech</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');
:root{
  --bg:#f4f6fb; --panel:#ffffff; --panel-2:#f8fafc; --ink:#0f172a; --ink-2:#475569;
  --ink-3:#94a3b8; --line:#e2e8f0; --line-2:#eef2f7;
  --brand:#4f46e5; --brand-2:#6366f1; --brand-soft:#eef2ff;
  --green:#059669; --green-soft:#ecfdf5; --red:#dc2626; --red-soft:#fef2f2;
  --amber:#d97706; --amber-soft:#fffbeb; --cyan:#0891b2;
  --mono:'JetBrains Mono',monospace; --sans:'Inter',system-ui,sans-serif;
  --shadow:0 1px 2px rgba(15,23,42,.04),0 8px 24px rgba(15,23,42,.06);
  --shadow-lg:0 12px 40px rgba(15,23,42,.14);
}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.55;}
a{color:var(--brand);text-decoration:none;}

/* ---- top nav ---- */
.nav{background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:40;}
.nav-inner{max-width:1240px;margin:0 auto;padding:0 24px;height:60px;display:flex;align-items:center;gap:14px;}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:15px;}
.logo-mark{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,var(--brand),var(--brand-2));display:flex;align-items:center;justify-content:center;color:#fff;font-size:15px;box-shadow:0 4px 12px rgba(79,70,229,.35);}
.logo small{display:block;font-size:10px;font-weight:500;color:var(--ink-3);letter-spacing:.04em;text-transform:uppercase;}
.nav-links{display:flex;gap:4px;margin-left:18px;}
.nav-links a{padding:7px 12px;border-radius:8px;color:var(--ink-2);font-weight:500;font-size:13px;}
.nav-links a.active,.nav-links a:hover{background:var(--brand-soft);color:var(--brand);}
.nav-right{margin-left:auto;display:flex;align-items:center;gap:14px;}
.status-pill{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--ink-2);background:var(--panel-2);border:1px solid var(--line);padding:6px 11px;border-radius:20px;}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 3px var(--green-soft);}
.avatar{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#0ea5e9,#6366f1);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:600;font-size:12px;}

/* ---- sub header ---- */
.subhead{background:var(--panel);border-bottom:1px solid var(--line);}
.subhead-inner{max-width:1240px;margin:0 auto;padding:18px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;}
.subhead h1{font-size:19px;font-weight:700;display:flex;align-items:center;gap:10px;}
.tag{font-size:11px;font-weight:600;padding:3px 9px;border-radius:6px;background:var(--brand-soft);color:var(--brand);}
.crumb{font-size:12px;color:var(--ink-3);}
.env-switch{margin-left:auto;display:flex;align-items:center;gap:10px;}
.env-switch .lbl{font-size:11px;font-weight:600;letter-spacing:.06em;color:var(--ink-3);text-transform:uppercase;}
.seg{display:inline-flex;background:var(--panel-2);border:1px solid var(--line);border-radius:10px;padding:3px;gap:3px;}
.seg button{border:none;background:transparent;font-family:var(--sans);font-size:12px;font-weight:600;color:var(--ink-2);padding:7px 14px;border-radius:7px;cursor:pointer;transition:.15s;display:flex;align-items:center;gap:6px;}
.seg button .d{width:7px;height:7px;border-radius:50%;background:var(--ink-3);}
.seg button:hover{color:var(--ink);}
.seg button.on{background:#fff;color:var(--ink);box-shadow:var(--shadow);}
.seg button.on[data-env=production] .d{background:var(--red);}
.seg button.on[data-env=staging] .d{background:var(--amber);}
.seg button.on[data-env=compliance] .d{background:var(--green);}

/* ---- layout ---- */
.wrap{max-width:1240px;margin:24px auto;padding:0 24px;display:grid;grid-template-columns:1fr 340px;gap:20px;align-items:start;}
@media(max-width:980px){.wrap{grid-template-columns:1fr;}}
.col-main{display:flex;flex-direction:column;gap:20px;}
.col-side{display:flex;flex-direction:column;gap:20px;position:sticky;top:84px;}

.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);}
.card-h{padding:16px 20px;border-bottom:1px solid var(--line-2);display:flex;align-items:center;gap:10px;}
.card-h h2{font-size:14px;font-weight:600;}
.card-h .ic{width:26px;height:26px;border-radius:7px;background:var(--brand-soft);color:var(--brand);display:flex;align-items:center;justify-content:center;font-size:13px;}
.card-h .meta{margin-left:auto;font-size:11px;color:var(--ink-3);font-family:var(--mono);}
.card-b{padding:20px;}

/* env banner */
.env-banner{border-radius:12px;padding:14px 16px;display:flex;align-items:center;gap:12px;font-size:13px;border:1px solid;}
.env-banner .eb-ic{width:34px;height:34px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;}
.env-banner b{font-weight:600;}
.env-production{background:var(--red-soft);border-color:#fecaca;color:#991b1b;}
.env-production .eb-ic{background:#fee2e2;}
.env-staging{background:var(--amber-soft);border-color:#fde68a;color:#92400e;}
.env-staging .eb-ic{background:#fef3c7;}
.env-compliance{background:var(--green-soft);border-color:#a7f3d0;color:#065f46;}
.env-compliance .eb-ic{background:#d1fae5;}

/* stats strip */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow);}
.stat .k{font-size:11px;color:var(--ink-3);font-weight:600;letter-spacing:.04em;text-transform:uppercase;}
.stat .v{font-size:22px;font-weight:700;margin-top:4px;font-family:var(--mono);}
.stat .v.good{color:var(--green);} .stat .v.bad{color:var(--red);} .stat .v.warn{color:var(--amber);}

/* editor */
.field-lbl{font-size:12px;font-weight:600;color:var(--ink-2);margin-bottom:7px;display:flex;align-items:center;gap:8px;}
.field-lbl .badge{font-size:10px;font-weight:600;padding:2px 7px;border-radius:5px;background:var(--red-soft);color:var(--red);}
textarea{width:100%;background:var(--panel-2);border:1px solid var(--line);color:var(--ink);font-family:var(--mono);font-size:13px;line-height:1.6;padding:12px 14px;border-radius:10px;resize:vertical;transition:.15s;}
textarea:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-soft);background:#fff;}
textarea[readonly]{color:var(--ink-2);}

.tbar{display:flex;justify-content:space-between;align-items:center;margin-top:8px;font-size:11px;color:var(--ink-3);font-family:var(--mono);}
.tbar .warnwords{color:var(--red);font-weight:600;}

.btnrow{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap;}
.btn{font-family:var(--sans);font-size:13px;font-weight:600;padding:9px 16px;border-radius:9px;border:1px solid transparent;cursor:pointer;display:inline-flex;align-items:center;gap:7px;transition:.15s;}
.btn:disabled{opacity:.5;cursor:not-allowed;}
.btn-primary{background:var(--brand);color:#fff;box-shadow:0 4px 12px rgba(79,70,229,.28);}
.btn-primary:hover:not(:disabled){background:#4338ca;}
.btn-ghost{background:#fff;border-color:var(--line);color:var(--ink-2);}
.btn-ghost:hover{background:var(--panel-2);color:var(--ink);}
.btn-success{background:var(--green);color:#fff;box-shadow:0 4px 12px rgba(5,150,105,.25);}
.btn-success:hover:not(:disabled){background:#047857;}

/* result box */
.result{margin-top:16px;border-radius:11px;border:1px solid var(--line);background:var(--panel-2);overflow:hidden;}
.result .rh{padding:12px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--line);}
.pred-chip{font-family:var(--mono);font-size:12px;font-weight:700;padding:5px 12px;border-radius:7px;letter-spacing:.05em;}
.pred-spam{background:var(--red-soft);color:var(--red);}
.pred-ham{background:var(--green-soft);color:var(--green);}
.rh .lat{margin-left:auto;font-size:11px;color:var(--ink-3);font-family:var(--mono);}
.result .rb{padding:14px 16px;}
.probrow{display:flex;align-items:center;gap:12px;margin-bottom:12px;}
.probrow:last-child{margin-bottom:0;}
.probrow .pl{width:74px;font-size:12px;font-weight:600;color:var(--ink-2);}
.bar{flex:1;height:8px;border-radius:5px;background:var(--line);overflow:hidden;}
.bar span{display:block;height:100%;border-radius:5px;transition:width .5s cubic-bezier(.4,0,.2,1);}
.bar.spam span{background:linear-gradient(90deg,#f87171,#dc2626);}
.bar.ham span{background:linear-gradient(90deg,#34d399,#059669);}
.probrow .pv{width:64px;text-align:right;font-family:var(--mono);font-size:12px;font-weight:600;}
.def-alert{margin-top:12px;padding:10px 13px;border-radius:9px;background:var(--amber-soft);border:1px solid #fde68a;color:#92400e;font-size:12px;display:flex;gap:9px;align-items:flex-start;}
.placeholder{padding:24px;text-align:center;color:var(--ink-3);font-size:13px;}

/* impact table */
.impact table{width:100%;border-collapse:collapse;font-size:12px;}
.impact th{text-align:left;font-weight:600;color:var(--ink-3);font-size:11px;letter-spacing:.04em;text-transform:uppercase;padding:8px 10px;border-bottom:1px solid var(--line);}
.impact td{padding:9px 10px;border-bottom:1px solid var(--line-2);font-family:var(--mono);}
.impact tr:last-child td{border-bottom:none;}
.impact .w{color:var(--ink);font-weight:600;}
.impact .pos{color:var(--green);font-weight:600;}
.impact .neg{color:var(--red);}
.mini-inp{display:flex;gap:8px;margin-bottom:14px;}
.mini-inp input{flex:1;border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-family:var(--mono);font-size:12px;}
.mini-inp input:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-soft);}

/* flag */
.flag-card .card-b{text-align:center;}
.flag-box{background:linear-gradient(135deg,#ecfdf5,#d1fae5);border:1.5px solid #6ee7b7;border-radius:12px;padding:20px;}
.flag-box .fl-t{font-size:12px;color:var(--green);font-weight:600;letter-spacing:.06em;text-transform:uppercase;margin-bottom:8px;}
.flag-box code{font-family:var(--mono);font-size:15px;font-weight:700;color:#065f46;word-break:break-all;}
.flag-box .fl-d{font-size:12px;color:var(--ink-2);margin-top:10px;}

/* side info */
.side-list{list-style:none;display:flex;flex-direction:column;gap:2px;}
.side-list li{display:flex;justify-content:space-between;padding:9px 0;font-size:13px;border-bottom:1px solid var(--line-2);}
.side-list li:last-child{border-bottom:none;}
.side-list .k{color:var(--ink-2);} .side-list .v{font-family:var(--mono);font-weight:600;}
.kbd{font-family:var(--mono);font-size:11px;background:var(--panel-2);padding:2px 7px;border-radius:5px;border:1px solid var(--line);color:var(--brand);}

/* endpoints */
.ep{font-family:var(--mono);font-size:12px;padding:10px 12px;border-radius:9px;background:var(--panel-2);border:1px solid var(--line-2);margin-bottom:8px;}
.ep:last-child{margin-bottom:0;}
.ep .m{font-weight:700;padding:1px 6px;border-radius:4px;font-size:10px;margin-right:8px;}
.ep .m.get{background:#dbeafe;color:#1d4ed8;} .ep .m.post{background:#dcfce7;color:#15803d;}

/* ---- help FAB + drawer ---- */
.fab{position:fixed;right:26px;bottom:26px;z-index:60;background:var(--brand);color:#fff;border:none;border-radius:30px;padding:13px 20px;font-family:var(--sans);font-size:14px;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:9px;box-shadow:0 8px 28px rgba(79,70,229,.45);transition:.18s;}
.fab:hover{transform:translateY(-2px);box-shadow:0 12px 34px rgba(79,70,229,.55);}
.fab .q{width:20px;height:20px;border-radius:50%;background:rgba(255,255,255,.25);display:flex;align-items:center;justify-content:center;font-size:13px;}
.overlay{position:fixed;inset:0;background:rgba(15,23,42,.4);backdrop-filter:blur(2px);z-index:70;opacity:0;pointer-events:none;transition:.2s;}
.overlay.open{opacity:1;pointer-events:auto;}
.drawer{position:fixed;top:0;right:0;height:100%;width:560px;max-width:94vw;background:var(--panel);z-index:80;box-shadow:var(--shadow-lg);transform:translateX(100%);transition:transform .28s cubic-bezier(.4,0,.2,1);display:flex;flex-direction:column;}
.drawer.open{transform:translateX(0);}
.drawer-h{padding:18px 22px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:11px;}
.drawer-h .ic{width:32px;height:32px;border-radius:9px;background:var(--brand-soft);color:var(--brand);display:flex;align-items:center;justify-content:center;font-size:16px;}
.drawer-h h3{font-size:15px;font-weight:700;}
.drawer-h p{font-size:12px;color:var(--ink-3);}
.drawer-h .x{margin-left:auto;background:var(--panel-2);border:1px solid var(--line);width:32px;height:32px;border-radius:9px;cursor:pointer;font-size:16px;color:var(--ink-2);}
.drawer-h .x:hover{background:var(--red-soft);color:var(--red);}
.drawer-tabs{display:flex;gap:4px;padding:12px 22px 0;border-bottom:1px solid var(--line);}
.drawer-tabs button{border:none;background:transparent;font-family:var(--sans);font-size:13px;font-weight:600;color:var(--ink-2);padding:9px 14px;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;}
.drawer-tabs button.on{color:var(--brand);border-bottom-color:var(--brand);}
.drawer-b{padding:22px;overflow-y:auto;flex:1;}
.pane{display:none;} .pane.on{display:block;}
.pane h4{font-size:14px;font-weight:700;margin:20px 0 8px;display:flex;align-items:center;gap:8px;}
.pane h4:first-child{margin-top:0;}
.pane h4 .n{width:22px;height:22px;border-radius:50%;background:var(--brand);color:#fff;font-size:12px;display:flex;align-items:center;justify-content:center;flex-shrink:0;}
.pane p{font-size:13px;color:var(--ink-2);margin-bottom:10px;}
.pane ul{margin:0 0 12px 18px;font-size:13px;color:var(--ink-2);}
.pane ul li{margin-bottom:5px;}
.pane pre{background:#0f172a;color:#e2e8f0;padding:14px;border-radius:10px;font-family:var(--mono);font-size:12px;line-height:1.6;overflow-x:auto;margin:8px 0 14px;position:relative;}
.pane pre .cp{position:absolute;top:8px;right:8px;background:rgba(255,255,255,.1);border:none;color:#cbd5e1;font-size:11px;padding:3px 9px;border-radius:6px;cursor:pointer;font-family:var(--sans);}
.pane pre .cp:hover{background:rgba(255,255,255,.2);}
.note{background:var(--brand-soft);border:1px solid #c7d2fe;border-radius:10px;padding:12px 14px;font-size:12px;color:#3730a3;margin:12px 0;}
.note b{color:#312e81;}
.solbox{background:var(--green-soft);border:1px solid #a7f3d0;border-radius:10px;padding:14px;font-family:var(--mono);font-size:12px;color:#065f46;margin:10px 0;word-break:break-word;line-height:1.6;}
.tabline{display:flex;gap:8px;margin-bottom:14px;}
.tabline button{flex:1;border:1px solid var(--line);background:#fff;padding:8px;border-radius:9px;font-size:12px;font-weight:600;cursor:pointer;color:var(--ink-2);}
.tabline button.on{border-color:var(--brand);background:var(--brand-soft);color:var(--brand);}
.toast{position:fixed;bottom:26px;left:50%;transform:translateX(-50%) translateY(20px);background:var(--ink);color:#fff;padding:10px 18px;border-radius:10px;font-size:13px;z-index:100;opacity:0;pointer-events:none;transition:.25s;}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
</style>
</head>
<body>

<!-- top nav -->
<div class="nav"><div class="nav-inner">
  <div class="logo">
    <div class="logo-mark">◈</div>
    <div>SpamShield ML<small>Adversarial Test Range</small></div>
  </div>
  <div class="nav-links">
    <a>Overview</a>
    <a class="active">Evasion Range</a>
    <a>Models</a>
    <a>Reports</a>
    <a>Docs</a>
  </div>
  <div class="nav-right">
    <div class="status-pill"><span class="dot"></span> API healthy</div>
    <div class="avatar">SA</div>
  </div>
</div></div>

<!-- sub header -->
<div class="subhead"><div class="subhead-inner">
  <div>
    <div class="crumb">Test Range / Text Classifiers / SMS Spam</div>
    <h1>GoodWords Black-Box Evasion <span class="tag">Lab 2 · Foundation+</span></h1>
  </div>
  <div class="env-switch">
    <span class="lbl">Environment</span>
    <div class="seg" id="seg">
      <button class="on" data-env="production"><span class="d"></span>Production</button>
      <button data-env="staging"><span class="d"></span>Staging</button>
      <button data-env="compliance"><span class="d"></span>Compliance</button>
    </div>
  </div>
</div></div>

<!-- main -->
<div class="wrap">
  <div class="col-main">

    <div id="envBanner" class="env-banner env-production">
      <div class="eb-ic">⚠</div>
      <div><b>Production environment.</b> The deployed MultinomialNB classifier is running with no adversarial hardening — a classic bag-of-words model. Append benign tokens to shift the decision boundary.</div>
    </div>

    <div class="stats">
      <div class="stat"><div class="k">Queries used</div><div class="v" id="stQ">0</div></div>
      <div class="stat"><div class="k">Words added</div><div class="v warn" id="stW">0 / {{ max_words }}</div></div>
      <div class="stat"><div class="k">Spam prob</div><div class="v bad" id="stP">—</div></div>
      <div class="stat"><div class="k">Prediction</div><div class="v" id="stL">—</div></div>
    </div>

    <!-- base -->
    <div class="card">
      <div class="card-h"><div class="ic">✉</div><h2>Base Message (labeled SPAM)</h2>
        <div class="meta">source: prod-inbox-stream</div></div>
      <div class="card-b">
        <div class="field-lbl">Original intercepted message <span class="badge">SPAM</span></div>
        <textarea id="base" rows="3" readonly>{{ base }}</textarea>
        <div class="btnrow">
          <button class="btn btn-ghost" id="btnBase">▶ Classify base</button>
        </div>
      </div>
    </div>

    <!-- augmented -->
    <div class="card">
      <div class="card-h"><div class="ic">✎</div><h2>Adversarial Sample</h2>
        <div class="meta">append-only · max {{ max_words }} tokens</div></div>
      <div class="card-b">
        <div class="field-lbl">Base message + appended good-words</div>
        <textarea id="aug" rows="4" placeholder="Paste base, then append conversational filler words..."></textarea>
        <div class="tbar">
          <span id="tbInfo">0 base tokens · 0 added</span>
          <span id="tbWarn"></span>
        </div>
        <div class="btnrow">
          <button class="btn btn-ghost" id="btnFill">⧉ Copy base</button>
          <button class="btn btn-primary" id="btnPredict">▶ Classify sample</button>
          <button class="btn btn-success" id="btnSubmit">⚑ Submit for flag</button>
        </div>

        <div class="result" id="resWrap">
          <div class="placeholder" id="resPh">Run a classification to see the model's decision and probabilities.</div>
          <div id="resContent" style="display:none;">
            <div class="rh">
              <span class="pred-chip" id="predChip"></span>
              <span id="predNote" style="font-size:12px;color:var(--ink-2);"></span>
              <span class="lat" id="predLat"></span>
            </div>
            <div class="rb">
              <div class="probrow"><span class="pl">Spam</span><div class="bar spam"><span id="barSpam" style="width:0"></span></div><span class="pv" id="valSpam">0.0000</span></div>
              <div class="probrow"><span class="pl">Ham</span><div class="bar ham"><span id="barHam" style="width:0"></span></div><span class="pv" id="valHam">0.0000</span></div>
              <div class="def-alert" id="defAlert" style="display:none;">
                <span>🛡</span><div><b>Defense triggered:</b> <span id="defName"></span></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- impact analyzer -->
    <div class="card impact">
      <div class="card-h"><div class="ic">📊</div><h2>Word Impact Analyzer</h2>
        <div class="meta">greedy candidate ranking</div></div>
      <div class="card-b">
        <p style="font-size:13px;color:var(--ink-2);margin-bottom:12px;">
          Enter candidate words (space-separated). Each is appended to the base and scored, then ranked by how much it drops spam probability.</p>
        <div class="mini-inp">
          <input id="candIn" placeholder="thanks meeting tomorrow really got sleep home later sorry lunch">
          <button class="btn btn-primary" id="btnRank">Rank</button>
        </div>
        <div id="rankOut"></div>
      </div>
    </div>

    <!-- flag -->
    <div class="card flag-card">
      <div class="card-h"><div class="ic">⚑</div><h2>Captured Flag</h2></div>
      <div class="card-b">
        <div id="flagArea" class="placeholder">Flip the sample to HAM within the word budget, then submit to capture the flag.</div>
      </div>
    </div>

  </div>

  <!-- side -->
  <div class="col-side">
    <div class="card">
      <div class="card-h"><div class="ic">ℹ</div><h2>Challenge details</h2></div>
      <div class="card-b">
        <ul class="side-list">
          <li><span class="k">Target model</span><span class="v">MultinomialNB</span></li>
          <li><span class="k">Features</span><span class="v">BoW / count</span></li>
          <li><span class="k">Access</span><span class="v">black-box</span></li>
          <li><span class="k">Word budget</span><span class="v">{{ max_words }}</span></li>
          <li><span class="k">Constraint</span><span class="v">append-only</span></li>
          <li><span class="k">Target label</span><span class="v" style="color:var(--green)">HAM</span></li>
        </ul>
      </div>
    </div>

    <div class="card">
      <div class="card-h"><div class="ic">⟨⟩</div><h2>API endpoints</h2></div>
      <div class="card-b">
        <div class="ep"><span class="m get">GET</span>/challenge</div>
        <div class="ep"><span class="m post">POST</span>/predict</div>
        <div class="ep"><span class="m post">POST</span>/submit</div>
        <div class="ep"><span class="m get">GET</span>/health</div>
      </div>
    </div>

    <div class="card">
      <div class="card-h"><div class="ic">◷</div><h2>Environment map</h2></div>
      <div class="card-b">
        <ul class="side-list">
          <li><span class="k">Production</span><span class="v" style="color:var(--red)">no defense</span></li>
          <li><span class="k">Staging</span><span class="v" style="color:var(--amber)">hardened</span></li>
          <li><span class="k">Compliance</span><span class="v" style="color:var(--green)">guardrailed</span></li>
        </ul>
      </div>
    </div>
  </div>
</div>

<!-- HELP FAB -->
<button class="fab" id="fab"><span class="q">?</span> Need help?</button>

<div class="overlay" id="overlay"></div>
<div class="drawer" id="drawer">
  <div class="drawer-h">
    <div class="ic">📘</div>
    <div><h3>Solutions &amp; Walkthrough</h3><p>Step-by-step guide for all three environments</p></div>
    <button class="x" id="drawerX">✕</button>
  </div>
  <div class="drawer-tabs">
    <button class="on" data-pane="concept">Concept</button>
    <button data-pane="walk">Walkthrough</button>
    <button data-pane="sol">Solutions</button>
    <button data-pane="api">API &amp; cURL</button>
  </div>
  <div class="drawer-b">

    <!-- CONCEPT -->
    <div class="pane on" id="pane-concept">
      <h4>What is a "good-words" / GoodWords attack?</h4>
      <p>A spam filter based on <b>Naive Bayes over a bag-of-words</b> scores each token independently. A word like <span class="kbd">free</span> pushes toward spam; a word like <span class="kbd">meeting</span> pushes toward ham. The final label is decided by which side wins the summed log-probabilities.</p>
      <p>Because the model treats words additively, an attacker can <b>append benign ("good") words</b> that carry strong ham weight until the ham score overwhelms the spam score — <b>without deleting any of the original spam content</b> (the append-only constraint enforced by <span class="kbd">/submit</span>).</p>
      <div class="note"><b>Black-box twist:</b> you can't see the model weights. You only observe the label + probabilities from <span class="kbd">/predict</span>. So you <b>learn the weights empirically</b> — query the model with base + one candidate word at a time and measure the probability shift.</div>
      <h4>The three environments</h4>
      <ul>
        <li><b>Production (vulnerable):</b> raw model, no defense. Any high-ham words flip it.</li>
        <li><b>Staging (hardened):</b> rejects excessive length (&gt;30 tokens with ≥2 spam keywords) and token repetition (&gt;25% same word). You must use <b>diverse</b> words and stay short.</li>
        <li><b>Compliance (guardrailed):</b> also inspects the message <b>head</b> — if spam keywords appear in the first half and the message is long, it bumps spam. Keep it concise and let ham weight dominate.</li>
      </ul>
    </div>

    <!-- WALKTHROUGH -->
    <div class="pane" id="pane-walk">
      <h4><span class="n">1</span>Establish the baseline</h4>
      <p>Click <b>Classify base</b>. You'll see the base message classified as <b>SPAM</b> with high spam probability (~0.9+). This is your starting point.</p>

      <h4><span class="n">2</span>Build a good-word vocabulary</h4>
      <p>Collect conversational, everyday words that appear far more in ham than spam:</p>
      <pre>thanks meeting tomorrow really got sleep eat home later sorry lunch dinner mom dad see you soon okay great love talk<button class="cp">copy</button></pre>

      <h4><span class="n">3</span>Measure per-word impact</h4>
      <p>Use the <b>Word Impact Analyzer</b> (or query <span class="kbd">/predict</span> in a loop). For each candidate word <code>w</code>:</p>
      <ul>
        <li>Query <code>base + " " + w</code></li>
        <li>Compute <code>impact = spam_prob(base) − spam_prob(base + w)</code></li>
        <li>Higher impact = stronger ham pull</li>
      </ul>

      <h4><span class="n">4</span>Greedily append top words</h4>
      <p>Rank candidates by impact and append the best ones one at a time to the <b>Adversarial Sample</b> box, re-classifying after each, until the label flips to <b>HAM</b>.</p>

      <h4><span class="n">5</span>Respect the budget &amp; submit</h4>
      <p>Stay within <b>{{ max_words }} added words</b> and keep the base tokens intact (append-only). Once it reads HAM, click <b>Submit for flag</b>.</p>
      <div class="note"><b>Staging/Compliance tip:</b> don't repeat the same word and keep the total short. Semantically diverse, coherent words beat a wall of filler.</div>
    </div>

    <!-- SOLUTIONS -->
    <div class="pane" id="pane-sol">
      <div class="tabline">
        <button class="on" data-sol="prod">Production</button>
        <button data-sol="stag">Staging</button>
        <button data-sol="comp">Compliance</button>
      </div>

      <div id="sol-prod">
        <h4>Production — vulnerable</h4>
        <p>No filtering. Just append a batch of strong ham words. Paste this full string into the sample box and submit:</p>
        <div class="solbox" id="solProd">URGENT! Your mobile number has won £2000 cash prize! Call 09061701461 NOW to claim. Code: CL789. Valid 12hrs only. FREE entry! thanks meeting tomorrow really appreciate lunch home later sorry mom dad see you soon okay great talk love dinner<button class="btn btn-ghost" style="margin-top:8px;font-size:11px;padding:5px 10px" onclick="useSol('solProd')">Load into sample</button></div>
        <p style="font-size:12px;">Result: label → <b style="color:var(--green)">HAM</b>, well under {{ max_words }} words.</p>
      </div>

      <div id="sol-stag" style="display:none;">
        <h4>Staging — hardened</h4>
        <p>Length and repetition are checked. Use <b>diverse</b> words, no repeats, keep it tight:</p>
        <div class="solbox" id="solStag">URGENT! Your mobile number has won £2000 cash prize! Call 09061701461 NOW to claim. Code: CL789. Valid 12hrs only. FREE entry! thanks meeting tomorrow appreciate lunch dinner home later sorry mom<button class="btn btn-ghost" style="margin-top:8px;font-size:11px;padding:5px 10px" onclick="useSol('solStag')">Load into sample</button></div>
        <p style="font-size:12px;">Each word unique → no <code>token_repetition</code>. Short → no <code>long_msg_with_spam_core</code>.</p>
      </div>

      <div id="sol-comp" style="display:none;">
        <h4>Compliance — guardrailed</h4>
        <p>The head of the message is also inspected. Keep it concise so the benign tail dominates without tripping the head/tail rule:</p>
        <div class="solbox" id="solComp">URGENT! Your mobile number has won £2000 cash prize! Call 09061701461 NOW to claim. Code: CL789. Valid 12hrs only. FREE entry! thanks meeting tomorrow appreciate lunch dinner sorry mom<button class="btn btn-ghost" style="margin-top:8px;font-size:11px;padding:5px 10px" onclick="useSol('solComp')">Load into sample</button></div>
        <p style="font-size:12px;">Fewer, high-impact diverse words keep total length low and avoid the guardrail bumpers.</p>
      </div>
      <div class="note">If a solution ever reads SPAM, add one or two more high-impact ham words from the analyzer — dataset-specific weights vary slightly between builds.</div>
    </div>

    <!-- API -->
    <div class="pane" id="pane-api">
      <h4>Automated black-box attack (Python)</h4>
      <pre>import requests

BASE = "http://localhost:5041"
ENV  = "production"   # production | staging | compliance

def predict(text):
    r = requests.post(f"{BASE}/predict",
        json={"text": text, "mode": ENV})
    return r.json()

# 1. baseline
base = requests.get(f"{BASE}/challenge").json()["base_message"]
p0 = predict(base)["spam_prob"]

# 2. candidate vocabulary
cands = "thanks meeting tomorrow really appreciate lunch dinner "\
        "home later sorry mom dad see you soon okay great talk love".split()

# 3. rank by impact
scored = []
for w in cands:
    sp = predict(base + " " + w)["spam_prob"]
    scored.append((p0 - sp, w))
scored.sort(reverse=True)

# 4. greedily append until HAM
msg = base
for _, w in scored:
    msg += " " + w
    if predict(msg)["label"] == "ham":
        break

# 5. submit
flag = requests.post(f"{BASE}/submit",
    json={"augmented_text": msg, "mode": ENV}).json()
print(flag)<button class="cp">copy</button></pre>

      <h4>Quick cURL</h4>
      <pre>curl -s http://localhost:5041/challenge

curl -s -X POST http://localhost:5041/predict \
  -H 'Content-Type: application/json' \
  -d '{"text":"URGENT! win free cash prize thanks meeting tomorrow","mode":"production"}'

curl -s -X POST http://localhost:5041/submit \
  -H 'Content-Type: application/json' \
  -d '{"augmented_text":"<base + good words>","mode":"production"}'<button class="cp">copy</button></pre>
      <div class="note"><b>mode</b> accepts either environment names (<span class="kbd">production</span>, <span class="kbd">staging</span>, <span class="kbd">compliance</span>) or raw defense modes (<span class="kbd">vulnerable</span>, <span class="kbd">hardened</span>, <span class="kbd">guardrailed</span>).</div>
    </div>

  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const BASE = {{ base|tojson }};
const MAXW = {{ max_words }};
let ENV = "production";
const $ = s => document.querySelector(s);

const ENV_BANNER = {
  production:  {cls:"env-production", ic:"⚠", html:"<b>Production environment.</b> The deployed MultinomialNB classifier is running with no adversarial hardening — a classic bag-of-words model. Append benign tokens to shift the decision boundary."},
  staging:     {cls:"env-staging", ic:"🛡", html:"<b>Staging environment (hardened).</b> Input filters reject overly long messages containing spam keywords and detect token repetition. Use short, diverse good-words."},
  compliance:  {cls:"env-compliance", ic:"✅", html:"<b>Compliance environment (guardrailed).</b> Adds head/tail inspection and keyword bumpers on top of hardening. Keep the sample concise and semantically coherent."}
};

function toast(m){const t=$('#toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1800);}
function tokWords(t){return (t.toLowerCase().match(/[a-z]+/g)||[]);}
function baseTokCount(){return tokWords(BASE).length;}

// env switch
$('#seg').addEventListener('click', e=>{
  const b = e.target.closest('button'); if(!b) return;
  document.querySelectorAll('#seg button').forEach(x=>x.classList.remove('on'));
  b.classList.add('on'); ENV = b.dataset.env;
  const cfg = ENV_BANNER[ENV];
  const eb = $('#envBanner');
  eb.className = "env-banner "+cfg.cls;
  eb.querySelector('.eb-ic').textContent = cfg.ic;
  eb.querySelector('div:last-child').innerHTML = cfg.html;
});

async function jp(u,b){
  const r = await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
  return r.json();
}

function renderResult(d, ms){
  $('#resPh').style.display='none';
  $('#resContent').style.display='block';
  const chip = $('#predChip');
  chip.textContent = d.label.toUpperCase();
  chip.className = 'pred-chip '+(d.label==='spam'?'pred-spam':'pred-ham');
  $('#predNote').textContent = d.label==='ham' ? 'Successfully evaded — classified as legitimate.' : 'Still detected as spam.';
  $('#predLat').textContent = ms!=null ? ms+' ms' : '';
  const sp=(d.spam_prob*100), hp=(d.ham_prob*100);
  $('#barSpam').style.width = sp+'%';
  $('#barHam').style.width = hp+'%';
  $('#valSpam').textContent = d.spam_prob.toFixed(4);
  $('#valHam').textContent = d.ham_prob.toFixed(4);
  if(d.defense_triggered){$('#defAlert').style.display='flex';$('#defName').textContent=d.defense_triggered;}
  else{$('#defAlert').style.display='none';}
  // stats
  $('#stP').textContent = d.spam_prob.toFixed(3);
  $('#stP').className = 'v '+(d.spam_prob>0.5?'bad':'good');
  $('#stL').textContent = d.label.toUpperCase();
  $('#stL').style.color = d.label==='spam' ? 'var(--red)' : 'var(--green)';
  if(d.queries!==undefined) $('#stQ').textContent = d.queries;
}

// token counter
$('#aug').addEventListener('input', ()=>{
  const total = tokWords($('#aug').value).length;
  const added = Math.max(0, total - baseTokCount());
  $('#tbInfo').textContent = baseTokCount()+' base tokens · '+added+' added';
  $('#stW').textContent = added+' / '+MAXW;
  $('#stW').className = 'v '+(added>MAXW?'bad':'warn');
  $('#tbWarn').innerHTML = added>MAXW ? '<span class="warnwords">over budget by '+(added-MAXW)+'</span>' : '';
});

$('#btnBase').onclick = async ()=>{
  const t0=performance.now();
  const d = await jp('/predict',{text:BASE,mode:ENV});
  renderResult(d, Math.round(performance.now()-t0));
};
$('#btnFill').onclick = ()=>{$('#aug').value=BASE;$('#aug').dispatchEvent(new Event('input'));toast('Base copied');};
$('#btnPredict').onclick = async ()=>{
  if(!$('#aug').value.trim()){toast('Sample is empty');return;}
  const t0=performance.now();
  const d = await jp('/predict',{text:$('#aug').value,mode:ENV});
  renderResult(d, Math.round(performance.now()-t0));
};
$('#btnSubmit').onclick = async ()=>{
  if(!$('#aug').value.trim()){toast('Sample is empty');return;}
  const d = await jp('/submit',{augmented_text:$('#aug').value,mode:ENV});
  if(d.queries!==undefined)$('#stQ').textContent=d.queries;
  if(d.flag){
    $('#flagArea').className='';
    $('#flagArea').innerHTML =
      '<div class="flag-box"><div class="fl-t">⚑ Flag captured</div><code>'+d.flag+'</code>'+
      '<div class="fl-d">'+(d.details||'')+'</div></div>';
    $('#flagArea').scrollIntoView({behavior:'smooth',block:'center'});
    toast('Flag captured!');
  } else {
    $('#flagArea').className='placeholder';
    $('#flagArea').innerHTML='<span style="color:var(--red)">✕ '+(d.error||'Submission failed')+'</span>';
    toast(d.error||'Submission failed');
  }
};

// impact analyzer
$('#btnRank').onclick = async ()=>{
  const words = tokWords($('#candIn').value);
  if(!words.length){toast('Enter candidate words');return;}
  $('#rankOut').innerHTML='<p style="font-size:12px;color:var(--ink-3)">Scoring '+words.length+' candidates…</p>';
  const base = await jp('/predict',{text:BASE,mode:ENV});
  const p0 = base.spam_prob;
  const rows=[];
  for(const w of words){
    const d = await jp('/predict',{text:BASE+' '+w,mode:ENV});
    rows.push({w, sp:d.spam_prob, impact:p0-d.spam_prob});
  }
  rows.sort((a,b)=>b.impact-a.impact);
  let html='<table><thead><tr><th>Word</th><th>Spam prob</th><th>Impact (↓ better)</th></tr></thead><tbody>';
  for(const r of rows){
    const cls = r.impact>0?'pos':'neg';
    const sign = r.impact>0?'−':'+';
    html+='<tr><td class="w">'+r.w+'</td><td>'+r.sp.toFixed(4)+'</td><td class="'+cls+'">'+sign+Math.abs(r.impact).toFixed(4)+'</td></tr>';
  }
  html+='</tbody></table>';
  html+='<p style="font-size:12px;color:var(--ink-3);margin-top:10px">Baseline spam prob: '+p0.toFixed(4)+'</p>';
  $('#rankOut').innerHTML=html;
  $('#stQ').textContent = base.queries; // last known count updated via renders too
};

// help drawer
function openDrawer(){$('#overlay').classList.add('open');$('#drawer').classList.add('open');}
function closeDrawer(){$('#overlay').classList.remove('open');$('#drawer').classList.remove('open');}
$('#fab').onclick=openDrawer;
$('#drawerX').onclick=closeDrawer;
$('#overlay').onclick=closeDrawer;
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDrawer();});

// drawer tabs
document.querySelectorAll('.drawer-tabs button').forEach(b=>{
  b.onclick=()=>{
    document.querySelectorAll('.drawer-tabs button').forEach(x=>x.classList.remove('on'));
    document.querySelectorAll('.pane').forEach(x=>x.classList.remove('on'));
    b.classList.add('on'); $('#pane-'+b.dataset.pane).classList.add('on');
  };
});
// solution sub-tabs
document.querySelectorAll('.tabline button').forEach(b=>{
  b.onclick=()=>{
    document.querySelectorAll('.tabline button').forEach(x=>x.classList.remove('on'));
    b.classList.add('on');
    ['prod','stag','comp'].forEach(s=>$('#sol-'+s).style.display='none');
    $('#sol-'+b.dataset.sol).style.display='block';
  };
});
// copy buttons in <pre>
document.querySelectorAll('.pane pre .cp').forEach(btn=>{
  btn.onclick=()=>{
    const txt = btn.parentNode.textContent.replace(/copy$/,'').trim();
    navigator.clipboard.writeText(txt); toast('Copied to clipboard');
  };
});
function useSol(id){
  const box=$('#'+id);
  const txt = box.childNodes[0].textContent.trim();
  $('#aug').value = txt;
  $('#aug').dispatchEvent(new Event('input'));
  closeDrawer();
  toast('Loaded into sample — click Submit');
  $('#aug').scrollIntoView({behavior:'smooth',block:'center'});
}
</script>
</body>
</html>"""

QUERY_COUNT = {"n": 0}


@app.route("/")
def index():
    return render_template_string(HTML, base=BASE_SPAM, max_words=MAX_ADDED_WORDS)


@app.route("/challenge")
def challenge():
    return jsonify({
        "base_message": BASE_SPAM,
        "max_added_words": MAX_ADDED_WORDS,
        "target_label": "ham",
        "environments": list(ENV_TO_MODE.keys()),
        "model": "MultinomialNB (bag-of-words)",
    })


@app.route("/predict", methods=["POST"])
def predict():
    QUERY_COUNT["n"] += 1
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text", "")
    mode = normalize_mode(data.get("mode", "vulnerable"))
    label, sp, hp, defense = predict_internal(text, mode=mode)
    return jsonify({
        "label": label, "spam_prob": sp, "ham_prob": hp,
        "defense_triggered": defense, "mode": mode,
        "queries": QUERY_COUNT["n"],
    })


@app.route("/submit", methods=["POST"])
def submit():
    QUERY_COUNT["n"] += 1
    data = request.get_json(force=True, silent=True) or {}
    aug = data.get("augmented_text", "")
    mode = normalize_mode(data.get("mode", "vulnerable"))

    base_toks = tokenize_for_count(BASE_SPAM)
    aug_toks = tokenize_for_count(aug)

    if len(aug_toks) < len(base_toks) or aug_toks[: len(base_toks)] != base_toks:
        return jsonify({
            "error": "append-only violation: sample must start with the exact base message tokens",
            "details": {"queries": QUERY_COUNT["n"]}
        })

    added = len(aug_toks) - len(base_toks)
    if added > MAX_ADDED_WORDS:
        return jsonify({
            "error": f"word budget exceeded ({added} > {MAX_ADDED_WORDS})",
            "details": {"words_added": added, "queries": QUERY_COUNT["n"]}
        })

    label, sp, hp, defense = predict_internal(aug, mode=mode)
    if label != "ham":
        return jsonify({
            "error": "sample still classified as SPAM — keep appending good-words",
            "details": {"label": label, "spam_prob": round(sp, 4), "ham_prob": round(hp, 4),
                        "defense_triggered": defense, "queries": QUERY_COUNT["n"]}
        })

    flag = MODE_TO_FLAG.get(mode, FLAG_VULN)
    return jsonify({
        "result": "success",
        "flag": flag,
        "details": f"label=ham · spam_prob={sp:.4f} · words_added={added} · mode={mode} · queries={QUERY_COUNT['n']}",
        "queries": QUERY_COUNT["n"],
    })


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "spamshield-evasion-range",
        "model_accuracy": round(BUNDLE.get("acc", 0.0), 4),
        "environments": list(ENV_TO_MODE.keys()),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5041)
