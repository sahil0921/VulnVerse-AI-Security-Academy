from flask import Flask, request, jsonify, render_template, send_file
import numpy as np
import pandas as pd
import urllib.request, zipfile, io, re, json, pickle, os, time
from pathlib import Path
from collections import Counter
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from datetime import datetime, timezone

app = Flask(__name__)
np.random.seed(1337)

ENV_TO_MODE = {
    "production": "vulnerable",
    "staging": "hardened",
    "compliance": "guardrailed",
}
MODE_TO_ENV = {v: k for k, v in ENV_TO_MODE.items()}
CURRENT_ENV = {"env": "production"}  # mutable state

DATA_DIR = Path("/app/data")
if not DATA_DIR.exists():
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        # Fallback to local directory if /app/data is not writable (e.g. running outside docker)
        DATA_DIR = Path("data")
        DATA_DIR.mkdir(exist_ok=True)
CSV_PATH = DATA_DIR / "sms_spam.csv"

def load_dataset():
    if CSV_PATH.exists():
        return pd.read_csv(CSV_PATH)
    url = "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            zdata = r.read()
        with zipfile.ZipFile(io.BytesIO(zdata)) as zf:
            with zf.open("SMSSpamCollection") as f:
                lines = [l.decode("utf-8").strip() for l in f]
        rows = []
        for line in lines:
            parts = line.split("\t")
            if len(parts) == 2:
                rows.append({"label": parts[0].lower(), "message": parts[1]})
        df = pd.DataFrame(rows)
        df.to_csv(CSV_PATH, index=False)
        return df
    except Exception:
        synth = [
            ("spam", "WINNER!! Free entry to win £900 cash prize claim now"),
            ("spam", "Congratulations you won FREE ringtones text WIN to 80086"),
            ("spam", "URGENT! Your mobile number has won £2000 claim now"),
            ("spam", "Free entry in weekly comp to win FA Cup tickets text FA"),
            ("spam", "You are a winner U have been selected for a prize"),
            ("spam", "Claim your free holiday by calling 08081263000 NOW"),
            ("ham", "Hey are we still meeting tomorrow at the coffee shop"),
            ("ham", "Thanks for the help yesterday really appreciated it"),
            ("ham", "Going home now will call you later ok"),
            ("ham", "Sorry I missed your call was in a meeting"),
            ("ham", "Can you pick up some milk on your way home please"),
            ("ham", "The meeting has been moved to 3pm tomorrow"),
        ] * 25
        df = pd.DataFrame([{"label": l, "message": m} for l, m in synth])
        df.to_csv(CSV_PATH, index=False)
        return df

def clean_text(t):
    t = str(t).lower()
    t = re.sub(r"[^\w\s£$€¥!?.,;:\'\"\-]", " ", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()

MODEL_PATH = DATA_DIR / "model.pkl"

def train_model():
    df = load_dataset()
    df["clean"] = df["message"].apply(clean_text)
    df = df.drop_duplicates(subset=["label", "clean"])
    df = df[df["clean"].str.len() > 0]
    X = df["clean"].values
    y = df["label"].values
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    vec = CountVectorizer(
        max_features=3000,
        token_pattern=r"\b\w+\b|[£$€¥]+|\d+|!!+|\?\?+|\.\.\.+",
        lowercase=True,
        stop_words="english",
    )
    Xtr = vec.fit_transform(X_train)
    Xte = vec.transform(X_test)
    clf = MultinomialNB()
    clf.fit(Xtr, y_train)
    acc = clf.score(Xte, y_test)
    bundle = {
        "vectorizer": vec,
        "classifier": clf,
        "test_accuracy": float(acc),
        "feature_names": vec.get_feature_names_out().tolist(),
        "classes": clf.classes_.tolist(),
        "trained_on": len(X_train),
        "tested_on": len(X_test),
    }
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(bundle, f)
    return bundle

def get_model():
    if MODEL_PATH.exists():
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return train_model()

BUNDLE = get_model()

SPAM_REGEX = re.compile(
    r"\b(free|winner|win|claim|prize|cash|£\d+|urgent|congratulations|"
    r"ringtone|txt|text\s+\w+\s+to\s+\d+|call\s+now|click\s+here)\b",
    re.IGNORECASE,
)

def classify(text, mode="vulnerable"):
    vec = BUNDLE["vectorizer"]
    clf = BUNDLE["classifier"]
    cleaned = clean_text(text)
    X = vec.transform([cleaned])
    proba = clf.predict_proba(X)[0]
    classes = clf.classes_.tolist()
    spam_idx = classes.index("spam")
    ham_idx = classes.index("ham")
    spam_p = float(proba[spam_idx])
    ham_p = float(proba[ham_idx])
    label = "spam" if spam_p > ham_p else "ham"

    if mode == "vulnerable":
        return {"label": label, "spam_prob": spam_p, "ham_prob": ham_p, "defense_triggered": None}

    tokens = cleaned.split()
    n = len(tokens)
    cnt = Counter(tokens)
    top_token, top_count = cnt.most_common(1)[0] if cnt else ("", 0)
    repeat_ratio = top_count / max(n, 1)
    spam_hits = len(SPAM_REGEX.findall(cleaned))

    if mode in ("hardened", "guardrailed"):
        if spam_hits >= 2 and n > 30:
            return {"label": "spam", "spam_prob": max(spam_p, 0.85),
                    "ham_prob": min(ham_p, 0.15),
                    "defense_triggered": "long_message_with_spam_core"}
        if repeat_ratio > 0.25 and n > 15:
            return {"label": "spam", "spam_prob": max(spam_p, 0.80),
                    "ham_prob": min(ham_p, 0.20),
                    "defense_triggered": "token_repetition"}

    if mode == "guardrailed":
        if spam_hits >= 2 and ham_p < 0.85:
            return {"label": "spam", "spam_prob": max(spam_p, 0.75),
                    "ham_prob": min(ham_p, 0.25),
                    "defense_triggered": "spam_keyword_bumper"}
        first_half = " ".join(tokens[: n // 2])
        if SPAM_REGEX.search(first_half) and n > 20:
            return {"label": "spam", "spam_prob": max(spam_p, 0.78),
                    "ham_prob": min(ham_p, 0.22),
                    "defense_triggered": "spam_head_benign_tail"}

    return {"label": label, "spam_prob": spam_p, "ham_prob": ham_p, "defense_triggered": None}

SAMPLE_SPAM = "WINNER!! As a valued network customer you have been selected to receive a £900 prize reward! To claim call 09061701461. Claim code KL341. Valid 12 hours only."

def get_goodwords(k=30):
    clf = BUNDLE["classifier"]
    feats = BUNDLE["feature_names"]
    classes = BUNDLE["classes"]
    ham_idx = classes.index("ham")
    spam_idx = classes.index("spam")
    ham_log = clf.feature_log_prob_[ham_idx]
    spam_log = clf.feature_log_prob_[spam_idx]
    out = []
    for i, w in enumerate(feats):
        ham_p = float(np.exp(ham_log[i]))
        spam_p = float(np.exp(spam_log[i]))
        goodness = ham_p / (spam_p + 1e-10)
        out.append({"word": w, "goodness": goodness, "ham_p": ham_p, "spam_p": spam_p})
    out.sort(key=lambda x: x["goodness"], reverse=True)
    return out[:k]

METRICS = {
    "total_scanned": 156847,
    "detection_rate": 98.2,
    "false_positive_rate": 0.31,
    "model_confidence": 94.7,
    "scanned_change": 12.4,
    "detection_change": 1.8,
    "fp_change": -0.4,
    "confidence_change": 2.1,
    "scan_trend_labels": ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug"],
    "scan_trend_data": [12400, 14200, 15800, 16100, 17200, 18400, 19100, 20500],
    "classification_labels": ["Legitimate", "Spam", "Phishing", "Suspicious"],
    "classification_data": [72, 18, 6, 4],
    "classification_colors": ["#10b981", "#ef4444", "#f59e0b", "#6366f1"],
    "recent_activity": [
        {"icon": "🚨", "text": "Bulk phishing campaign detected — 847 messages quarantined", "time": "12 min ago"},
        {"icon": "✅", "text": "Model retrained on 1.2M corpus — accuracy 98.2%", "time": "2 hr ago"},
        {"icon": "⚠️", "text": "False positive reported by finance@nimbletech.com", "time": "4 hr ago"},
        {"icon": "📊", "text": "Weekly threat report generated — 3,241 threats blocked", "time": "6 hr ago"},
        {"icon": "🔄", "text": "Feature store sync completed — vocabulary updated", "time": "8 hr ago"},
    ]
}

THREAT_FEED = [
    {"id": "TH-9847", "sender": "promo@win-lottery.xyz", "subject": "You've WON £10,000!", "preview": "Congratulations! You have been selected as our lucky winner...", "verdict": "spam", "confidence": 0.997, "severity": "critical", "ts": "2026-08-08 09:41"},
    {"id": "TH-9846", "sender": "security@bankofamerica-verify.com", "subject": "Urgent: Account Suspended", "preview": "Your account has been temporarily suspended. Click here to verify...", "verdict": "spam", "confidence": 0.994, "severity": "critical", "ts": "2026-08-08 09:38"},
    {"id": "TH-9845", "sender": "deals@amazon-prime-offer.net", "subject": "EXCLUSIVE: 90% Off Today Only", "preview": "As a valued Prime member, claim your exclusive discount...", "verdict": "spam", "confidence": 0.982, "severity": "high", "ts": "2026-08-08 09:22"},
    {"id": "TH-9844", "sender": "j.martinez@nimbletech.com", "subject": "Q3 Budget Review Meeting", "preview": "Hi team, please review the attached budget proposal before...", "verdict": "ham", "confidence": 0.012, "severity": "none", "ts": "2026-08-08 09:15"},
    {"id": "TH-9843", "sender": "noreply@fedex-tracking.info", "subject": "Package Delivery Failed", "preview": "We were unable to deliver your package. Click to reschedule...", "verdict": "spam", "confidence": 0.978, "severity": "high", "ts": "2026-08-08 08:55"},
    {"id": "TH-9842", "sender": "hr@nimbletech.com", "subject": "Updated PTO Policy", "preview": "Please find the updated paid time off policy effective...", "verdict": "ham", "confidence": 0.008, "severity": "none", "ts": "2026-08-08 08:30"},
    {"id": "TH-9841", "sender": "support@microsoft-365-renew.com", "subject": "Your Subscription Expires Today", "preview": "URGENT: Your Microsoft 365 subscription will expire in 24 hours...", "verdict": "spam", "confidence": 0.991, "severity": "critical", "ts": "2026-08-08 08:12"},
    {"id": "TH-9840", "sender": "newsletter@techcrunch.com", "subject": "Daily Tech Digest", "preview": "Top stories: AI regulation update, new chip architecture...", "verdict": "ham", "confidence": 0.045, "severity": "none", "ts": "2026-08-08 07:45"},
]

AUDIT_LOG = []
RECENT_SCANS = []

def now_str():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

def audit(event, detail, verdict="info"):
    entry = {"ts": now_str(), "event": event, "detail": detail, "verdict": verdict}
    AUDIT_LOG.insert(0, entry)
    while len(AUDIT_LOG) > 50:
        AUDIT_LOG.pop()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/metrics')
def get_metrics():
    return jsonify(METRICS)

@app.route('/api/info')
def get_info():
    return jsonify({
        "algorithm": "MultinomialNB",
        "vocab_size": len(BUNDLE["feature_names"]),
        "max_features": 3000,
        "test_accuracy": BUNDLE["test_accuracy"],
        "classes": BUNDLE["classes"],
        "trained_on": BUNDLE["trained_on"],
        "tested_on": BUNDLE["tested_on"],
        "environments": ENV_TO_MODE
    })

@app.route('/api/classify', methods=['POST'])
def api_classify():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    mode = data.get("mode")
    if not mode or mode not in ("vulnerable", "hardened", "guardrailed"):
        mode = ENV_TO_MODE.get(CURRENT_ENV["env"], "vulnerable")

    result = classify(text, mode=mode)

    preview = text[:80] + ("..." if len(text) > 80 else "")
    scan_record = {
        "id": f"scan_{int(time.time()*1000)}_{np.random.randint(1000,9999)}",
        "text_preview": preview,
        "result": result,
        "timestamp": now_str()
    }
    RECENT_SCANS.insert(0, scan_record)
    while len(RECENT_SCANS) > 20:
        RECENT_SCANS.pop()

    audit("classification", f"Message classified as {result['label']} (Spam Prob: {result['spam_prob']:.3f})", verdict=result['label'])

    return jsonify(result)

@app.route('/api/goodwords')
def api_goodwords():
    k = int(request.args.get("k", 30))
    return jsonify({"words": get_goodwords(k)})

@app.route('/api/sweep', methods=['POST'])
def api_sweep():
    data = request.get_json(silent=True) or {}
    counts = data.get("counts", [0, 5, 10, 15, 20, 25, 30, 35, 40])
    mode = data.get("mode")
    if not mode or mode not in ("vulnerable", "hardened", "guardrailed"):
        mode = ENV_TO_MODE.get(CURRENT_ENV["env"], "vulnerable")

    df = load_dataset()
    df["clean"] = df["message"].apply(clean_text)
    spam_pool = df[df["label"] == "spam"]["clean"]
    spam_msgs = spam_pool.sample(min(80, len(spam_pool)), random_state=42).tolist()

    max_count = max(counts) if counts else 40
    gw = get_goodwords(max_count)
    word_list = [w["word"] for w in gw]

    results = []
    for n in counts:
        words = " ".join(word_list[:n])
        evaded = 0
        for m in spam_msgs:
            text = m + ((" " + words) if words else "")
            if classify(text, mode=mode)["label"] == "ham":
                evaded += 1
        results.append({
            "num_words": n, "evaded": evaded, "tested": len(spam_msgs),
            "evasion_rate": round(100.0 * evaded / len(spam_msgs), 1),
        })
    return jsonify({"mode": mode, "tested_messages": len(spam_msgs), "results": results})

@app.route('/api/blackbox', methods=['POST'])
def api_blackbox():
    data = request.get_json(silent=True) or {}
    budget = data.get("budget", 40)
    mode = data.get("mode")
    if not mode or mode not in ("vulnerable", "hardened", "guardrailed"):
        mode = ENV_TO_MODE.get(CURRENT_ENV["env"], "vulnerable")
    text = data.get("text", SAMPLE_SPAM)

    words = get_goodwords(budget)
    word_list = [w["word"] for w in words]

    history = []
    current_text = text

    res = classify(current_text, mode=mode)
    history.append({
        "words_added": 0,
        "label": res["label"],
        "spam_prob": res["spam_prob"],
        "defense_triggered": res["defense_triggered"],
        "current_text": current_text
    })

    success = (res["label"] == "ham")
    words_used = 0

    if not success:
        for i in range(budget):
            current_text += " " + word_list[i]
            words_used += 1
            res = classify(current_text, mode=mode)
            history.append({
                "words_added": words_used,
                "label": res["label"],
                "spam_prob": res["spam_prob"],
                "defense_triggered": res["defense_triggered"],
                "current_text": current_text
            })
            if res["label"] == "ham":
                success = True
                break

    return jsonify({
        "success": success,
        "words_used": words_used,
        "history": history,
        "final_text": current_text,
        "final_prob": history[-1]["spam_prob"],
        "defense_triggered": history[-1]["defense_triggered"]
    })

@app.route('/api/threats')
def api_threats():
    return jsonify({"threats": THREAT_FEED})

@app.route('/api/scans')
def api_scans():
    return jsonify({"scans": RECENT_SCANS})

@app.route('/api/chat', methods=['POST'])
def api_chat():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").lower()

    try:
        import llm_client
        system_prompt = "You are SentinelAI, the intelligent assistant for SentinelMail AI email security platform. You help analyze spam patterns, explain ML model behavior, discuss evasion techniques, and provide guidance on email security. Keep responses concise and professional."
        response = llm_client.call_llm(system_prompt, message)
        return jsonify({"response": response, "source": "ai"})
    except Exception:
        if 'spam' in message or 'detection' in message:
            resp = "Our MultinomialNB classifier achieves 98.2% detection rate across 156K+ scanned messages. The model uses a 3000-feature vocabulary with CountVectorizer."
        elif 'evasion' in message or 'attack' in message or 'bypass' in message:
            resp = "GoodWords attacks exploit the additive nature of Naive Bayes by injecting high P(w|ham)/P(w|spam) tokens. The boundary sweep shows evasion rate climbs from ~6% to ~100% with 25+ injected words in vulnerable mode."
        elif 'goodwords' in message or 'feature' in message:
            resp = "Feature importance is derived from the model's feature_log_prob_ matrix. Tokens with high ham-to-spam probability ratios are 'goodwords' — they pull classification toward ham when injected."
        elif 'defense' in message or 'hardened' in message or 'guardrailed' in message:
            resp = "Hardened mode adds token repetition detection and spam-core heuristics. Guardrailed mode adds keyword bumper and head/tail analysis. Production mode runs the raw model with no defenses."
        elif 'model' in message or 'accuracy' in message:
            resp = "The model is MultinomialNB trained on the SMS Spam Collection (UCI). Test accuracy is typically ~98%. The CountVectorizer uses max_features=3000 with English stop words removed."
        else:
            resp = "Hello! I'm SentinelAI. I can help with spam analysis, model performance, evasion techniques, and email security. What would you like to know?"

        return jsonify({"response": resp, "source": "mock"})

@app.route('/api/setmode', methods=['POST'])
def api_setmode():
    data = request.get_json(silent=True) or {}
    env = data.get("env")
    if env in ENV_TO_MODE:
        CURRENT_ENV["env"] = env
        audit("environment_change", f"System environment updated to {env} mode")
        return jsonify({"status": "ok", "env": CURRENT_ENV["env"], "mode": ENV_TO_MODE[CURRENT_ENV["env"]]})
    return jsonify({"error": "Invalid environment"}), 400

@app.route('/api/getmode')
def api_getmode():
    return jsonify({"env": CURRENT_ENV["env"], "mode": ENV_TO_MODE[CURRENT_ENV["env"]]})

@app.route('/api/audit')
def api_audit():
    return jsonify({"log": AUDIT_LOG})

@app.route('/model/download')
def model_download():
    return send_file(str(MODEL_PATH), as_attachment=True, download_name="spam_model.pkl")

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "evasion-spam-wb"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5040)
