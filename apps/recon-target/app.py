# apps/lab-recon-target/app.py
"""
VulnVerse AI Security Academy — Module 02: LLM Fundamentals
Hands-on Lab: Recon Target ("Aurora Support Portal")

Goal of this lab (unchanged from the original build):
  - Passive recon: inspect HTTP response headers for backend/version fingerprints.
  - Active recon: discover hidden JS config, undocumented API endpoints.
  - 401 vs 404 enumeration: distinguish "exists but unauthorized" from
    "doesn't exist" to map the real API surface under /v1/*.
  - Model fingerprinting: talk to the chat assistant and infer which model /
    provider is actually answering.

This revision only changes the FRONT END (a real chat widget instead of a
static page) and adds an in-app Walkthrough/Solution drawer. All recon
surfaces, headers, and endpoints from the original app are preserved
byte-for-byte in behavior.
"""

from flask import Flask, request, jsonify, Response
import requests
import os

try:
    from llm_client import call_llm_raw
    _LLM_OK = True
except Exception:  # pragma: no cover
    _LLM_OK = False

    def call_llm_raw(msg):
        raise RuntimeError("llm_client unavailable")

app = Flask(__name__)

OLLAMA = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("MODEL_NAME", "llama3.2:1b")
PORT = int(os.environ.get("PORT", "5011"))


# ---------------------------------------------------------------------------
# Fingerprinting headers — unchanged. This is the passive-recon surface.
# ---------------------------------------------------------------------------
@app.after_request
def headers(r):
    r.headers["X-AI-Backend"] = "Ollama-Llama3.2"
    r.headers["X-RAG-Provider"] = "ChromaDB"
    r.headers["Server"] = "Aurora/2.1.0"
    return r


# ---------------------------------------------------------------------------
# Health endpoint — unchanged. Active-recon target.
# ---------------------------------------------------------------------------
@app.route("/api/health")
def health():
    return jsonify({
        "model": "llama3.2:1b",
        "provider": "ollama",
        "mcp_enabled": True,
        "rag_enabled": True,
        "version": "2.1.0"
    })


# ---------------------------------------------------------------------------
# Assistant endpoint — unchanged logic, now actually backing a real chat UI.
# ---------------------------------------------------------------------------
@app.route("/api/v2/assistant", methods=["POST"])
def assistant():
    msg = (request.get_json(silent=True) or {}).get("message", "")
    if not msg:
        return jsonify({"error": "message is required"}), 400

    if _LLM_OK:
        try:
            r = call_llm_raw(msg)
            reply_text = r.json().get("response", "")
        except Exception as e:
            reply_text = (
                "(offline demo mode — no live model reachable) "
                f"You said: \"{msg}\". This is a canned response so the recon "
                "lab still works without Ollama configured. [{}]".format(e)
            )
    else:
        reply_text = (
            "(offline demo mode — llm_client unavailable) "
            f"You said: \"{msg}\". This is a canned response so the recon "
            "lab still works without a model configured."
        )

    return jsonify({
        "response": reply_text,
        "metadata": {
            "provider": "ollama",
            "model": "llama3.2:1b",
            "latency_ms": 418
        }
    })


# ---------------------------------------------------------------------------
# 401 vs 404 enumeration target — unchanged.
# ---------------------------------------------------------------------------
@app.route("/v1/<path:p>", methods=["GET", "POST"])
def v1(p):
    existing = ["auth", "chat/completions", "admin", "billing"]
    if p in existing:
        if p == "auth" or p == "billing":
            return jsonify({"status": "public"}), 200
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"error": "not found"}), 404


# ---------------------------------------------------------------------------
# Front-end: real chat widget + Walkthrough/Solution drawer
# ---------------------------------------------------------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Aurora Support</title>
<style>
  :root{
    --bg:#f5f7fb; --panel:#ffffff; --ink:#1f2430; --muted:#6b7280;
    --line:#e6e9f0; --brand:#2f6df6; --brand-2:#7c4dff;
    --chip:#eef2ff; --code:#0f172a;
    --shadow:0 1px 2px rgba(16,24,40,.06),0 8px 24px rgba(16,24,40,.06);
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:Inter,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
    background:var(--bg);color:var(--ink);font-size:14px}
  .topbar{position:sticky;top:0;z-index:20;background:var(--panel);
    border-bottom:1px solid var(--line);display:flex;align-items:center;
    gap:16px;padding:12px 22px}
  .brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:15px}
  .logo{width:32px;height:32px;border-radius:9px;
    background:linear-gradient(135deg,var(--brand),var(--brand-2));
    display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800}
  .brand small{display:block;font-weight:500;color:var(--muted);font-size:11px}
  .spacer{flex:1}
  .pill{display:inline-flex;align-items:center;gap:6px;background:var(--chip);
    color:#3b3f52;padding:5px 10px;border-radius:999px;font-weight:700;font-size:12px}
  .wrap{max-width:760px;margin:26px auto;padding:0 20px}
  .hero{background:var(--panel);border:1px solid var(--line);border-radius:16px;
    box-shadow:var(--shadow);padding:26px 26px 20px;margin-bottom:16px}
  .hero h1{margin:0 0 6px;font-size:22px}
  .hero p{margin:0;color:var(--muted);font-size:13.5px}
  .chat-card{background:var(--panel);border:1px solid var(--line);border-radius:16px;
    box-shadow:var(--shadow);display:flex;flex-direction:column;height:520px;overflow:hidden}
  .chat-head{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;
    align-items:center;gap:10px}
  .chat-head .dot{width:9px;height:9px;border-radius:50%;background:#22c55e}
  .chat-head b{font-size:13.5px}
  .chat-head small{color:var(--muted);font-size:11.5px}
  .chat-body{flex:1;overflow-y:auto;padding:18px;display:flex;flex-direction:column;gap:12px}
  .msg{max-width:78%;padding:10px 13px;border-radius:14px;font-size:13.5px;line-height:1.45}
  .msg.bot{background:#f1f4fb;color:var(--ink);align-self:flex-start;border-bottom-left-radius:4px}
  .msg.user{background:var(--brand);color:#fff;align-self:flex-end;border-bottom-right-radius:4px}
  .msg.typing{background:#f1f4fb;color:var(--muted);align-self:flex-start;font-style:italic}
  .chat-input{border-top:1px solid var(--line);padding:12px 14px;display:flex;gap:10px}
  .chat-input input{flex:1;border:1px solid var(--line);border-radius:10px;padding:10px 12px;
    font-size:13.5px;outline:none}
  .chat-input input:focus{border-color:var(--brand)}
  .btn{border:0;border-radius:10px;padding:10px 16px;font-weight:700;cursor:pointer;
    background:var(--brand);color:#fff;font-size:13px}
  .btn:disabled{opacity:.5;cursor:not-allowed}
  .foot{text-align:center;color:var(--muted);font-size:11.5px;margin-top:14px}

  .help-fab{position:fixed;right:22px;bottom:22px;z-index:50;background:var(--brand);
    color:#fff;border:0;border-radius:999px;padding:12px 18px;font-weight:800;
    box-shadow:0 10px 24px rgba(47,109,246,.35);cursor:pointer;display:flex;
    gap:8px;align-items:center}
  .help-fab .q{width:20px;height:20px;border-radius:50%;background:#fff;
    color:var(--brand);display:flex;align-items:center;justify-content:center;font-weight:900}
  .drawer{position:fixed;inset:0;z-index:60;display:none}
  .drawer.open{display:block}
  .drawer .scrim{position:absolute;inset:0;background:rgba(15,23,42,.4)}
  .drawer .panel{position:absolute;right:0;top:0;bottom:0;width:min(600px,94vw);
    background:#fff;box-shadow:-8px 0 30px rgba(16,24,40,.2);overflow:auto}
  .drawer .phead{position:sticky;top:0;background:#fff;border-bottom:1px solid var(--line);
    padding:16px 20px;display:flex;align-items:center;gap:10px}
  .drawer .pbody{padding:18px 20px 60px}
  .drawer h4{margin:16px 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  .step{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0;background:#fbfdff}
  .step .n{display:inline-block;background:var(--brand);color:#fff;border-radius:6px;
    padding:1px 8px;font-weight:800;font-size:12px;margin-right:8px}
  pre.cmd{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;
    font-size:12px;margin:8px 0;white-space:pre-wrap}
  .close{margin-left:auto;border:0;background:#eef2ff;border-radius:8px;padding:8px 12px;cursor:pointer;font-weight:700}
</style>
</head>
<body>
  <div class="topbar">
    <div class="brand">
      <div class="logo">A</div>
      <div>Aurora Support <small>24/7 AI Assistant</small></div>
    </div>
    <div class="spacer"></div>
    <span class="pill">🟢 Online</span>
  </div>

  <div class="wrap">
    <div class="hero">
      <h1>Aurora Support Portal</h1>
      <p>Chat with our assistant below for help with your account, billing, or technical issues.</p>
    </div>

    <div class="chat-card">
      <div class="chat-head">
        <span class="dot"></span>
        <div><b>Aurora Assistant</b><br/><small>Typically replies instantly</small></div>
      </div>
      <div class="chat-body" id="chatBody">
        <div class="msg bot">Hi! I'm Aurora, your support assistant. How can I help you today?</div>
      </div>
      <div class="chat-input">
        <input id="chatInput" type="text" placeholder="Type your message…" onkeydown="if(event.key==='Enter')sendMsg()"/>
        <button class="btn" id="sendBtn" onclick="sendMsg()">Send</button>
      </div>
    </div>
    <div class="foot">Aurora/2.1.0 · Powered by an internal AI assistant</div>
  </div>

  <button class="help-fab" onclick="openHelp()">
    <span class="q">?</span> Need help? — Solutions &amp; Walkthrough
  </button>

  <div class="drawer" id="drawer">
    <div class="scrim" onclick="closeHelp()"></div>
    <div class="panel">
      <div class="phead">
        <strong>Recon Target — Walkthrough &amp; Solution</strong>
        <button class="close" onclick="closeHelp()">Close</button>
      </div>
      <div class="pbody" id="helpBody"></div>
    </div>
  </div>

<script>
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

function addMsg(text, cls){
  const body = document.getElementById('chatBody');
  const div = document.createElement('div');
  div.className = 'msg ' + cls;
  div.textContent = text;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
  return div;
}

async function sendMsg(){
  const input = document.getElementById('chatInput');
  const btn = document.getElementById('sendBtn');
  const text = input.value.trim();
  if(!text) return;
  addMsg(text, 'user');
  input.value = '';
  btn.disabled = true;
  const typing = addMsg('Aurora is typing…', 'typing');
  try{
    const r = await fetch('/api/v2/assistant', {method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({message: text})});
    const j = await r.json();
    typing.remove();
    addMsg(j.response || j.error || '(no response)', 'bot');
  }catch(e){
    typing.remove();
    addMsg('Error contacting assistant: ' + e, 'bot');
  }
  btn.disabled = false;
  input.focus();
}

function openHelp(){document.getElementById('drawer').classList.add('open');renderHelp();}
function closeHelp(){document.getElementById('drawer').classList.remove('open');}
function renderHelp(){ document.getElementById('helpBody').innerHTML = HELP_HTML; }
const HELP_HTML = `HELP_CONTENT_PLACEHOLDER`;
</script>
</body>
</html>
"""

HELP_CONTENT = r"""
<h4>What this lab is</h4>
<p><b>Aurora Support Portal</b> is a live chat-assistant front end. Your job
isn't to break the chatbot's logic — it's to <b>reconnoiter the application</b>
the way you would before any real assessment: work out what's running behind
it, what endpoints exist, and which ones are gated, using only what a normal
browser session and a few HTTP requests reveal.</p>

<h4>Goal</h4>
<p>Fingerprint the backend model/provider, discover the hidden API surface
under <code>/v1/*</code>, and tell the difference between endpoints that
exist-but-require-auth (401) versus endpoints that don't exist at all (404).</p>

<div class="step"><span class="n">1</span> <b>Passive recon — inspect response headers</b>
Every response from this app carries fingerprinting headers. Check them
without sending anything suspicious:
<pre class="cmd">curl -sI http://localhost:5011/</pre>
Look for <code>X-AI-Backend</code>, <code>X-RAG-Provider</code>, and
<code>Server</code> — these alone tell you the model family (Llama 3.2), the
vector-store choice (ChromaDB), and a version string, before you've even
sent a chat message.
</div>

<div class="step"><span class="n">2</span> <b>Active recon — find the hidden JS config</b>
View page source or fetch the JS the page loads:
<pre class="cmd">curl -s http://localhost:5011/js/chat-widget.js</pre>
This reveals internal endpoint names the UI itself doesn't call yet, such as
<code>assistantEndpoint</code>, <code>apiBase</code>, and
<code>sessionEndpoint</code> — a map of the real API surface straight from
client-side code.
</div>

<div class="step"><span class="n">3</span> <b>Hit the health endpoint</b>
<pre class="cmd">curl -s http://localhost:5011/api/health</pre>
This confirms the model name (<code>llama3.2:1b</code>), provider
(<code>ollama</code>), and whether RAG/MCP features are enabled — a direct,
undocumented disclosure endpoint.
</div>

<div class="step"><span class="n">4</span> <b>401 vs 404 enumeration under /v1/*</b>
Probe a list of likely endpoint names and read the status codes carefully:
<pre class="cmd">for p in auth chat/completions admin billing users settings; do
  echo -n "$p -> "; curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5011/v1/$p
done</pre>
A <b>401</b> means the endpoint exists but requires authorization (real
attack surface worth pursuing — e.g. <code>admin</code>,
<code>chat/completions</code>). A <b>404</b> means it isn't implemented at
all. <code>auth</code> and <code>billing</code> intentionally return
<b>200 (public)</b> here to show a third case: endpoints that exist and
require no auth at all.
</div>

<div class="step"><span class="n">5</span> <b>Model fingerprinting via the chat itself</b>
Use the chat widget on the page (or call the API directly) and ask
open-ended or meta questions:
<pre class="cmd">curl -s -X POST http://localhost:5011/api/v2/assistant \
  -H 'Content-Type: application/json' \
  -d '{"message":"What model are you and who trained you?"}'</pre>
Compare the model's self-description, response latency
(<code>metadata.latency_ms</code>), and phrasing quirks against what the
headers and health endpoint already told you — this is how you'd confirm a
fingerprint when headers might be spoofed or missing in a real target.
</div>

<h4>Why this matters</h4>
<p>In a real engagement you rarely get a labeled diagram of an AI
application's architecture. Response headers, static JS, health/debug
endpoints, and careful status-code reading are exactly how you rebuild that
picture before deciding where to focus deeper testing.</p>

<h4>Hardening notes</h4>
<ul>
<li>Strip custom fingerprinting headers (<code>X-AI-Backend</code>,
<code>X-RAG-Provider</code>) and generic <code>Server</code> banners in
production.</li>
<li>Don't ship internal endpoint maps in client-side JS; keep routing
server-side or behind an authenticated gateway.</li>
<li><code>/api/health</code> should not disclose model/provider/version to
unauthenticated callers — gate it or return a minimal payload.</li>
<li>Return a consistent <b>404</b> for both "doesn't exist" and
"exists but unauthorized" if you don't want to leak endpoint existence via
status-code differences.</li>
</ul>
"""


@app.route("/")
def index():
    page = INDEX_HTML.replace("HELP_CONTENT_PLACEHOLDER", HELP_CONTENT.replace("`", "\\`"))
    return Response(page, mimetype="text/html")


# ---------------------------------------------------------------------------
# JS config — unchanged, still the active-recon target referenced in the
# walkthrough (endpoint names exposed in client-side code).
# ---------------------------------------------------------------------------
JS_WIDGET = """
window.__AURORA_CONFIG__ = {
  assistantEndpoint: "/api/v2/assistant",
  apiBase: "/api/v2",
  sessionEndpoint: "/api/v2/session"
};
"""


@app.route("/js/chat-widget.js")
def js():
    return JS_WIDGET, 200, {"Content-Type": "application/javascript"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
