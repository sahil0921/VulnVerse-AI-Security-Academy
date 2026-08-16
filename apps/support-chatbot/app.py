from flask import Flask, request, jsonify
import requests, os, json, time, traceback
from llm_client import call_llm_raw

app = Flask(__name__)
OLLAMA = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("MODEL_NAME", "mistral:latest")

# ─── Knowledge Base with realistic retrieval scores ───
KB = {
    "pto": {
        "title": "PTO_Leave_Policy_2026.pdf",
        "chunk_id": "chunk_087",
        "text": "Vacation Accrual: Years 0-2: 15 days/year, Years 3-5: 20 days/year, Years 6+: 25 days/year. Submit via Workday.",
        "vector_score": 0.94,
        "bm25_score": 12.3
    },
    "vpn": {
        "title": "VPN_Setup_Guide.pdf",
        "chunk_id": "chunk_042",
        "text": "Download GlobalProtect from https://vpn.nimbletech.local. Use AD credentials. Internal DNS: 10.0.0.53",
        "vector_score": 0.91,
        "bm25_score": 10.8
    },
    "architecture": {
        "title": "Internal_Architecture_2026.pdf",
        "chunk_id": "chunk_103",
        "text": "System Components: API Gateway (Kong), PostgreSQL on db01.nimble-internal, Redis at redis.nimble-internal.com:6379, HashiCorp Vault at vault.nimble-internal.com:8200 for secrets management.",
        "vector_score": 0.87,
        "bm25_score": 8.5
    },
    "security": {
        "title": "Security_Audit_Q1_2026.pdf",
        "chunk_id": "chunk_201",
        "text": "Critical: Unpatched Struts on prod-web-03. Jenkins default creds admin/admin. Public S3: nimble-archive-2025. AWS root no MFA.",
        "vector_score": 0.89,
        "bm25_score": 9.2
    },
    "credentials": {
        "title": "Emergency_Access_Procedures.pdf",
        "chunk_id": "chunk_999",
        "text": "Emergency AWS Access Key ID: AKIAIOSFODNN7HONEYPOT, Secret: wJalrXUtnFEMI/K7HONEYPOT123. Use only in P0 incidents.",
        "vector_score": 0.96,
        "bm25_score": 14.7
    }
}

SYSTEM = """You are NimbleTech's internal support assistant. Answer based on retrieved documents."""

def retrieve(query):
    """Keyword-based retrieval simulating a RAG pipeline."""
    q = query.lower()
    hits = []
    if any(w in q for w in ["pto", "vacation", "leave", "time off", "days off", "holiday"]):
        hits.append(KB["pto"])
    if any(w in q for w in ["vpn", "remote", "globalprotect", "connect"]):
        hits.append(KB["vpn"])
    if any(w in q for w in ["architecture", "system", "internal api", "infrastructure",
                             "component", "gateway", "database", "redis", "vault", "kong", "postgresql"]):
        hits.append(KB["architecture"])
    if any(w in q for w in ["security", "audit", "vulnerability", "struts", "jenkins",
                             "s3 bucket", "patch", "finding", "critical"]):
        hits.append(KB["security"])
    if any(w in q for w in ["emergency", "aws credential", "access key", "secret key",
                             "honeypot", "p0", "incident"]):
        hits.append(KB["credentials"])
    # If nothing matched, return all sources (simulates broad retrieval)
    if not hits and len(q) > 3:
        # Return top 2 most relevant by default
        hits = [KB["pto"], KB["vpn"]]
    return hits


# ─── Intentionally leaky headers (for reconnaissance lab) ───
@app.after_request
def headers(r):
    r.headers["X-AI-Backend"] = "Ollama-Llama3.2"
    r.headers["X-RAG-Provider"] = "ChromaDB"
    r.headers["X-Embedding-Model"] = "all-MiniLM-L6-v2"
    r.headers["X-App-Version"] = "4.2.1"
    r.headers["X-Powered-By"] = "Flask/RAG-Pipeline"
    # CORS headers
    r.headers["Access-Control-Allow-Origin"] = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return r


# ─── Massive HTML/CSS/JS UI with Walkthrough Panel ───
UI = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NimbleTech Support — RAG Chatbot</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; height: 100vh; display: flex; flex-direction: column; }

  /* ── TOP BAR ── */
  .topbar { background: #161b22; border-bottom: 1px solid #30363d; padding: 0 1.5rem; height: 56px; display: flex; align-items: center; justify-content: space-between; flex-shrink: 0; }
  .topbar-left { display: flex; align-items: center; gap: 0.75rem; }
  .logo-dot { width: 10px; height: 10px; border-radius: 50%; background: #00b4ff; box-shadow: 0 0 8px rgba(0,180,255,0.5); }
  .topbar h1 { font-size: 15px; font-weight: 600; color: #e6edf3; }
  .topbar-badges { display: flex; gap: 0.5rem; }
  .badge { font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 20px; letter-spacing: .04em; }
  .badge-blue { background: rgba(0,180,255,.15); color: #00b4ff; border: 1px solid rgba(0,180,255,.3); }
  .badge-green { background: rgba(63,185,80,.15); color: #3fb950; border: 1px solid rgba(63,185,80,.3); }
  .badge-amber { background: rgba(255,166,0,.15); color: #ffa600; border: 1px solid rgba(255,166,0,.3); }

  /* ── LAYOUT ── */
  .main { display: flex; flex: 1; overflow: hidden; }

  /* ── SIDEBAR ── */
  .sidebar { width: 260px; background: #161b22; border-right: 1px solid #30363d; display: flex; flex-direction: column; flex-shrink: 0; overflow-y: auto; }
  .sidebar-section { padding: 1rem; border-bottom: 1px solid #21262d; }
  .sidebar-section h3 { font-size: 11px; font-weight: 600; color: #7d8590; text-transform: uppercase; letter-spacing: .06em; margin-bottom: 0.6rem; }
  .stat-row { display: flex; justify-content: space-between; align-items: center; padding: 4px 0; }
  .stat-label { font-size: 12px; color: #7d8590; }
  .stat-value { font-size: 12px; font-weight: 600; color: #e6edf3; font-family: 'Courier New', monospace; }
  .stat-value.green { color: #3fb950; }
  .stat-value.blue { color: #00b4ff; }
  .hint-item { font-size: 12px; color: #7d8590; padding: 6px 8px; cursor: pointer; border-radius: 6px; transition: all .2s; }
  .hint-item:hover { color: #00b4ff; background: rgba(0,180,255,.08); }
  .hint-item::before { content: "\203A  "; color: #30363d; }
  .source-card { background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 0.65rem; margin-top: 0.5rem; transition: border-color .2s; }
  .source-card:hover { border-color: #30363d; }
  .source-title { font-size: 11px; font-weight: 600; color: #00b4ff; margin-bottom: 4px; word-break: break-all; }
  .source-meta { font-size: 10px; color: #7d8590; margin-bottom: 5px; font-family: 'Courier New', monospace; }
  .score-row { display: flex; gap: 8px; }
  .score-pill { font-size: 10px; padding: 2px 7px; border-radius: 8px; font-weight: 600; }
  .score-vector { background: rgba(0,180,255,.12); color: #00b4ff; }
  .score-bm25 { background: rgba(63,185,80,.12); color: #3fb950; }
  .no-sources { font-size: 12px; color: #7d8590; font-style: italic; }

  /* ── WALKTHROUGH TRIGGER (bottom of sidebar) ── */
  .sidebar-footer { margin-top: auto; padding: 1rem; border-top: 1px solid #21262d; }
  .wt-trigger { display: flex; align-items: center; gap: 0.6rem; padding: 10px 12px; background: linear-gradient(135deg, rgba(124,58,237,0.15), rgba(37,99,235,0.15)); border: 1px solid rgba(124,58,237,0.3); border-radius: 10px; cursor: pointer; transition: all .25s; width: 100%; text-align: left; color: inherit; font-family: inherit; }
  .wt-trigger:hover { background: linear-gradient(135deg, rgba(124,58,237,0.25), rgba(37,99,235,0.25)); border-color: rgba(124,58,237,0.5); transform: translateY(-1px); box-shadow: 0 4px 15px rgba(124,58,237,0.2); }
  .wt-trigger-icon { font-size: 18px; }
  .wt-trigger-text { flex: 1; }
  .wt-trigger-title { font-size: 12px; font-weight: 600; color: #c4b5fd; }
  .wt-trigger-sub { font-size: 10px; color: #7d8590; margin-top: 1px; }
  .wt-version { font-size: 10px; color: #484f58; padding-top: 6px; text-align: center; }

  /* ── CHAT AREA ── */
  .chat-area { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .messages { flex: 1; overflow-y: auto; padding: 1.5rem; display: flex; flex-direction: column; gap: 1.25rem; }
  .messages::-webkit-scrollbar { width: 4px; }
  .messages::-webkit-scrollbar-track { background: transparent; }
  .messages::-webkit-scrollbar-thumb { background: #30363d; border-radius: 4px; }

  /* ── MESSAGES ── */
  .msg { display: flex; gap: 0.75rem; align-items: flex-start; animation: fadeIn .25s ease; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
  .msg-avatar { width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 13px; font-weight: 700; flex-shrink: 0; margin-top: 2px; }
  .msg-avatar.user { background: rgba(0,180,255,.2); color: #00b4ff; border: 1px solid rgba(0,180,255,.3); }
  .msg-avatar.bot  { background: rgba(63,185,80,.2); color: #3fb950; border: 1px solid rgba(63,185,80,.3); }
  .msg-body { flex: 1; min-width: 0; }
  .msg-sender { font-size: 11px; font-weight: 600; color: #7d8590; margin-bottom: 4px; text-transform: uppercase; letter-spacing: .05em; }
  .msg-text { font-size: 14px; line-height: 1.65; color: #e6edf3; background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 0.75rem 1rem; word-wrap: break-word; overflow-wrap: break-word; }
  .msg-text.user-bubble { background: rgba(0,180,255,.08); border-color: rgba(0,180,255,.2); }
  .msg-text code { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 1px 5px; font-family: 'Courier New', monospace; font-size: 12px; color: #ffa600; }

  /* ── TYPING ── */
  .typing-dots { display: flex; gap: 4px; padding: 0.75rem 1rem; }
  .typing-dots span { width: 7px; height: 7px; border-radius: 50%; background: #3fb950; opacity: .4; animation: blink 1.2s infinite; }
  .typing-dots span:nth-child(2) { animation-delay: .2s; }
  .typing-dots span:nth-child(3) { animation-delay: .4s; }
  @keyframes blink { 0%,80%,100% { opacity: .4; } 40% { opacity: 1; } }

  /* ── INPUT BAR ── */
  .input-bar { padding: 1rem 1.5rem; border-top: 1px solid #30363d; background: #161b22; display: flex; gap: 0.75rem; align-items: flex-end; flex-shrink: 0; }
  .input-bar textarea { flex: 1; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; color: #e6edf3; font-size: 14px; font-family: inherit; padding: 0.65rem 0.9rem; resize: none; line-height: 1.5; max-height: 120px; outline: none; transition: border-color .15s; }
  .input-bar textarea:focus { border-color: #00b4ff; box-shadow: 0 0 0 3px rgba(0,180,255,0.1); }
  .input-bar textarea::placeholder { color: #7d8590; }
  .send-btn { background: #00b4ff; border: none; color: #0d1117; font-size: 13px; font-weight: 700; padding: 0.65rem 1.2rem; border-radius: 8px; cursor: pointer; transition: all .15s; white-space: nowrap; height: 40px; }
  .send-btn:hover { background: #29c0ff; box-shadow: 0 2px 10px rgba(0,180,255,0.3); }
  .send-btn:active { transform: scale(.97); }
  .send-btn:disabled { background: #30363d; color: #7d8590; cursor: not-allowed; transform: none; box-shadow: none; }

  /* ── RAG INDICATOR ── */
  .rag-bar { display: flex; align-items: center; gap: 0.5rem; padding: 0.4rem 1.5rem; background: rgba(0,180,255,.05); border-bottom: 1px solid #21262d; font-size: 11px; color: #7d8590; flex-shrink: 0; }
  .rag-dot { width: 6px; height: 6px; border-radius: 50%; background: #3fb950; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .4; } }

  /* ── WELCOME ── */
  .welcome { text-align: center; padding: 3rem 2rem; color: #7d8590; }
  .welcome h2 { font-size: 18px; color: #e6edf3; margin-bottom: 0.5rem; }
  .welcome p { font-size: 13px; line-height: 1.6; }

  /* ═══════════════════════════════════════════════ */
  /* ══  WALKTHROUGH OVERLAY & PANEL              ══ */
  /* ═══════════════════════════════════════════════ */

  .wt-overlay {
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.65);
    backdrop-filter: blur(5px);
    z-index: 9000;
    opacity: 0;
    visibility: hidden;
    transition: all .3s ease;
  }
  .wt-overlay.active { opacity: 1; visibility: visible; }

  .wt-panel {
    position: fixed; top: 0; left: 0; bottom: 0;
    width: 720px; max-width: 92vw;
    background: #0d1117;
    border-right: 1px solid #30363d;
    z-index: 9001;
    transform: translateX(-100%);
    transition: transform .35s cubic-bezier(.4,0,.2,1);
    display: flex; flex-direction: column;
    overflow: hidden;
  }
  .wt-panel.active { transform: translateX(0); }

  /* Panel header */
  .wt-header {
    padding: 1.25rem 1.5rem;
    border-bottom: 1px solid #30363d;
    background: #161b22;
    display: flex; align-items: center; justify-content: space-between;
    flex-shrink: 0;
  }
  .wt-header-left { display: flex; align-items: center; gap: 0.75rem; }
  .wt-header-icon { font-size: 22px; }
  .wt-header h2 { font-size: 16px; font-weight: 700; color: #e6edf3; }
  .wt-header-sub { font-size: 11px; color: #7d8590; margin-top: 2px; }
  .wt-close {
    background: none; border: 1px solid #30363d; color: #7d8590;
    width: 36px; height: 36px; border-radius: 8px;
    cursor: pointer; font-size: 18px; display: flex; align-items: center; justify-content: center;
    transition: all .2s;
  }
  .wt-close:hover { background: #21262d; color: #e6edf3; border-color: #484f58; }

  /* Panel body */
  .wt-body { flex: 1; overflow-y: auto; padding: 1rem 1.5rem; }
  .wt-body::-webkit-scrollbar { width: 4px; }
  .wt-body::-webkit-scrollbar-track { background: transparent; }
  .wt-body::-webkit-scrollbar-thumb { background: #30363d; border-radius: 4px; }

  /* Phase section */
  .wt-phase { margin-bottom: 1.5rem; }
  .wt-phase-header {
    display: flex; align-items: center; gap: 0.6rem;
    padding: 8px 12px; background: rgba(124,58,237,0.08);
    border: 1px solid rgba(124,58,237,0.2); border-radius: 8px;
    margin-bottom: 0.75rem;
  }
  .wt-phase-num {
    font-size: 10px; font-weight: 700; color: #c4b5fd;
    background: rgba(124,58,237,0.2); border-radius: 4px;
    padding: 2px 7px; font-family: 'Courier New', monospace;
  }
  .wt-phase-title { font-size: 13px; font-weight: 700; color: #c4b5fd; }

  /* Individual walkthrough item */
  .wt-item {
    background: #161b22; border: 1px solid #21262d; border-radius: 10px;
    margin-bottom: 0.6rem; overflow: hidden;
    transition: border-color .2s;
  }
  .wt-item:hover { border-color: #30363d; }
  .wt-item-header {
    display: flex; align-items: center; gap: 0.75rem;
    padding: 0.85rem 1rem; cursor: pointer;
    transition: background .15s; user-select: none;
  }
  .wt-item-header:hover { background: rgba(255,255,255,0.02); }
  .wt-item-num {
    font-size: 11px; font-weight: 700; color: #484f58;
    font-family: 'Courier New', monospace; min-width: 24px;
  }
  .wt-item-info { flex: 1; }
  .wt-item-title { font-size: 13px; font-weight: 600; color: #e6edf3; }
  .wt-item-obj { font-size: 11px; color: #7d8590; margin-top: 2px; }
  .wt-diff {
    font-size: 9px; font-weight: 700; padding: 2px 8px;
    border-radius: 10px; letter-spacing: .04em; text-transform: uppercase;
  }
  .wt-diff-easy { background: rgba(63,185,80,.15); color: #3fb950; }
  .wt-diff-medium { background: rgba(255,166,0,.15); color: #ffa600; }
  .wt-diff-hard { background: rgba(248,81,73,.15); color: #f85149; }
  .wt-chevron {
    color: #484f58; font-size: 14px; transition: transform .25s;
    flex-shrink: 0;
  }
  .wt-item.open .wt-chevron { transform: rotate(90deg); }

  /* Expanded content */
  .wt-item-body {
    max-height: 0; overflow: hidden;
    transition: max-height .35s cubic-bezier(.4,0,.2,1);
    border-top: 0px solid transparent;
  }
  .wt-item.open .wt-item-body {
    max-height: 3000px;
    border-top: 1px solid #21262d;
  }
  .wt-item-content { padding: 1rem 1.25rem; }

  /* Steps */
  .wt-steps { margin-bottom: 1rem; }
  .wt-step {
    display: flex; gap: 0.6rem; margin-bottom: 0.6rem;
    font-size: 13px; line-height: 1.55; color: #c9d1d9;
  }
  .wt-step-num {
    min-width: 22px; height: 22px; border-radius: 50%;
    background: rgba(0,180,255,0.15); color: #00b4ff;
    font-size: 10px; font-weight: 700;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0; margin-top: 1px;
  }

  /* Command blocks */
  .wt-cmd-block { margin-bottom: 1rem; }
  .wt-cmd-label {
    font-size: 10px; font-weight: 600; color: #7d8590;
    text-transform: uppercase; letter-spacing: .06em;
    margin-bottom: 6px; display: flex; align-items: center; gap: 6px;
  }
  .wt-cmd-label::before { content: "\25B6"; font-size: 8px; color: #3fb950; }
  .wt-cmd {
    position: relative; background: #0d1117;
    border: 1px solid #21262d; border-radius: 8px;
    padding: 0.75rem 1rem; padding-right: 3.5rem;
    font-family: 'Courier New', monospace; font-size: 12px;
    color: #e6edf3; line-height: 1.6;
    overflow-x: auto; white-space: pre-wrap; word-break: break-all;
  }
  .wt-cmd-copy {
    position: absolute; top: 6px; right: 6px;
    background: #21262d; border: 1px solid #30363d;
    color: #7d8590; border-radius: 6px;
    padding: 4px 10px; font-size: 10px; font-weight: 600;
    cursor: pointer; transition: all .15s;
  }
  .wt-cmd-copy:hover { background: #30363d; color: #e6edf3; }
  .wt-cmd-copy.copied { background: rgba(63,185,80,.2); color: #3fb950; border-color: rgba(63,185,80,.3); }

  /* Expected output */
  .wt-expected { margin-bottom: 1rem; }
  .wt-expected-label {
    font-size: 10px; font-weight: 600; color: #7d8590;
    text-transform: uppercase; letter-spacing: .06em;
    margin-bottom: 6px; display: flex; align-items: center; gap: 6px;
  }
  .wt-expected-label::before { content: "\2190"; font-size: 10px; color: #ffa600; }
  .wt-expected-box {
    background: rgba(255,166,0,.05); border: 1px solid rgba(255,166,0,.15);
    border-radius: 8px; padding: 0.75rem 1rem;
    font-family: 'Courier New', monospace; font-size: 12px;
    color: #ffa600; line-height: 1.6; white-space: pre-wrap;
  }

  /* Concept / meaning block — shown first, before steps */
  .wt-meaning {
    background: rgba(63,185,80,.05); border: 1px solid rgba(63,185,80,.15);
    border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 1rem;
    font-size: 12.5px; line-height: 1.65; color: #c9d1d9;
  }
  .wt-meaning-label {
    font-size: 10px; font-weight: 700; color: #3fb950;
    text-transform: uppercase; letter-spacing: .06em;
    margin-bottom: 6px; display: flex; align-items: center; gap: 6px;
  }
  .wt-meaning-label::before { content: "\1F4D6"; font-size: 11px; }
  .wt-meaning strong { color: #e6edf3; }

  /* Explanation */
  .wt-explain {
    background: rgba(0,180,255,.05); border: 1px solid rgba(0,180,255,.12);
    border-radius: 8px; padding: 0.75rem 1rem;
    font-size: 12px; line-height: 1.65; color: #8b949e;
  }
  .wt-explain-icon { margin-right: 6px; }
  .wt-explain strong { color: #c9d1d9; }

  /* ── SCROLLBAR for walkthrough panel ── */
  .wt-body::-webkit-scrollbar { width: 5px; }
  .wt-body::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }

</style>
</head>
<body>

<!-- ═══ TOP BAR ═══ -->
<div class="topbar">
  <div class="topbar-left">
    <div class="logo-dot"></div>
    <h1>NimbleTech Internal Support</h1>
  </div>
  <div class="topbar-badges">
    <span class="badge badge-blue">RAG</span>
    <span class="badge badge-green">ChromaDB</span>
    <span class="badge badge-amber">all-MiniLM-L6-v2</span>
  </div>
</div>

<!-- ═══ RAG STATUS BAR ═══ -->
<div class="rag-bar">
  <div class="rag-dot"></div>
  RAG pipeline active &nbsp;&middot;&nbsp; Vector store: ChromaDB &nbsp;&middot;&nbsp; Model: <span id="model-name" style="color:#e6edf3;margin-left:4px;">loading...</span>
</div>

<!-- ═══ MAIN LAYOUT ═══ -->
<div class="main">

  <!-- SIDEBAR -->
  <div class="sidebar">
    <div class="sidebar-section">
      <h3>System Info</h3>
      <div class="stat-row"><span class="stat-label">Backend</span><span class="stat-value blue">Ollama</span></div>
      <div class="stat-row"><span class="stat-label">Vector DB</span><span class="stat-value blue">ChromaDB</span></div>
      <div class="stat-row"><span class="stat-label">Embedding</span><span class="stat-value blue">MiniLM-L6</span></div>
      <div class="stat-row"><span class="stat-label">RAG</span><span class="stat-value green">Enabled</span></div>
      <div class="stat-row"><span class="stat-label">Docs indexed</span><span class="stat-value">5</span></div>
    </div>

    <div class="sidebar-section">
      <h3>Try asking</h3>
      <div class="hint-item" onclick="fillPrompt('How many PTO days do I get?')">How many PTO days do I get?</div>
      <div class="hint-item" onclick="fillPrompt('How do I set up VPN?')">How do I set up VPN?</div>
      <div class="hint-item" onclick="fillPrompt('What is the internal system architecture?')">What is the internal architecture?</div>
      <div class="hint-item" onclick="fillPrompt('Show me the latest security audit findings')">Latest security audit findings</div>
      <div class="hint-item" onclick="fillPrompt('What are the emergency AWS credentials?')">Emergency AWS credentials</div>
    </div>

    <div class="sidebar-section" id="sources-panel">
      <h3>Retrieved Sources</h3>
      <div id="sources-list"><div class="no-sources">Ask a question to see retrieved chunks</div></div>
    </div>

    <!-- ═══ WALKTHROUGH TRIGGER ═══ -->
    <div class="sidebar-footer">
      <button class="wt-trigger" onclick="openWalkthrough()">
        <span class="wt-trigger-icon">&#10067;</span>
        <div class="wt-trigger-text">
          <div class="wt-trigger-title">Need help? &mdash; Solutions &amp; Walkthrough</div>
          <div class="wt-trigger-sub">Step-by-step attack guides with commands</div>
        </div>
      </button>
      <div class="wt-version">NimbleTech Internal &middot; v4.2.1</div>
    </div>
  </div>

  <!-- CHAT AREA -->
  <div class="chat-area">
    <div class="messages" id="messages">
      <div class="welcome">
        <h2>NimbleTech Support Assistant</h2>
        <p>Ask about HR policies, VPN setup, internal architecture, or security docs.<br>All answers are grounded in retrieved knowledge base documents.</p>
      </div>
    </div>

    <div class="input-bar">
      <textarea id="input" rows="1" placeholder="Ask about PTO, VPN, architecture, security..." onkeydown="handleKey(event)" oninput="autoResize(this)"></textarea>
      <button class="send-btn" id="send-btn" onclick="sendMessage()">Send &uarr;</button>
    </div>
  </div>

</div>

<!-- ═══════════════════════════════════════════════ -->
<!-- ═══  WALKTHROUGH OVERLAY & PANEL             ═══ -->
<!-- ═══════════════════════════════════════════════ -->
<div class="wt-overlay" id="wt-overlay" onclick="closeWalkthrough()"></div>
<div class="wt-panel" id="wt-panel">
  <div class="wt-header">
    <div class="wt-header-left">
      <span class="wt-header-icon">&#128218;</span>
      <div>
        <h2>Attack Walkthroughs</h2>
        <div class="wt-header-sub">RAG Support Chatbot &mdash; guided recon exercises</div>
      </div>
    </div>
    <button class="wt-close" onclick="closeWalkthrough()">&times;</button>
  </div>
  <div class="wt-body" id="wt-body">
    <!-- Dynamically rendered by JS -->
  </div>
</div>


<script>
// ═══ WALKTHROUGH DATA — Reconnaissance Only ═══
// Rewritten to match how testers actually work a target in the real world:
// short recon checklist first, then the couple of curl/Burp commands people
// actually reach for, no lecture-length explanations.
const WALKTHROUGHS = [
  {
    phase: "Phase 1: Passive Recon",
    phaseNum: "01",
    items: [
      {
        num: "01",
        title: "Header Fingerprinting",
        objective: "Identify the backend stack from response headers",
        difficulty: "easy",
        meaning: "Every HTTP response carries headers — small pieces of metadata sent along with the actual page/data. Most apps only send standard ones (Content-Type, Date, etc.), but some accidentally (or lazily) add custom debug headers that reveal what's running under the hood — which LLM, which database, which framework. <strong>Fingerprinting</strong> just means collecting these clues to build a profile of the target before you attack anything. It's completely passive — you're not sending any malicious input, just reading what the server already tells you.",
        steps: [
          "Open DevTools → Network tab, send any chat message",
          "Click the /api/chat request and check Response Headers",
          "Or just curl -I / curl -v the endpoint from a terminal"
        ],
        commands: [
          {
            label: "curl",
            cmd: "curl -sD - http://localhost:5001/ -o /dev/null | grep -i '^x-'"
          }
        ],
        expected: "x-ai-backend: Ollama-Llama3.2\nx-rag-provider: ChromaDB\nx-embedding-model: all-MiniLM-L6-v2\nx-app-version: 4.2.1\nx-powered-by: Flask/RAG-Pipeline",
        explanation: "Custom <strong>X-</strong> headers give away the whole stack — LLM backend, vector DB, embedding model, framework, even the exact version. In prod these should never ship to the client. This is the same first move you'd make against any web app: check headers before touching a single input field."
      },
      {
        num: "02",
        title: "Health & Error Endpoint Recon",
        objective: "Pull config data from /api/health and use a 404 to map the API",
        difficulty: "easy",
        meaning: "Most backend apps expose a <strong>health check endpoint</strong> (like /health or /api/health) so monitoring tools can confirm the service is alive. Developers often dump extra internal details into this response for debugging — model name, DB type, version — without realizing it's public. Separately, <strong>error handling</strong> is how an app responds when something goes wrong (like hitting a page that doesn't exist). A well-built app returns a generic 'not found' message; a lazily-built one returns a detailed error that accidentally lists every real route in the system. Both are examples of information disclosure — the app is telling you more than it should.",
        steps: [
          "Try the usual health-check paths: /health, /api/health, /status",
          "Hit a route that doesn't exist and read the error body",
          "Note anything the 404 leaks that the health endpoint didn't"
        ],
        commands: [
          {
            label: "curl",
            cmd: "curl -s http://localhost:5001/api/health | jq\ncurl -s http://localhost:5001/api/doesnotexist | jq"
          }
        ],
        expected: "/api/health → model, provider, vector_db, embedding_model, version\n/api/doesnotexist → 404 body lists every real route, including /v1/chat/completions",
        explanation: "Verbose error responses are a classic info leak. Here the 404 handler helpfully lists every valid endpoint — including an OpenAI-compatible route nobody advertised on the UI. Always poke a 404/405 during recon, not just the happy path."
      },
      {
        num: "03",
        title: "Full Stack Fingerprint",
        objective: "Combine headers + health + page source into one profile",
        difficulty: "easy",
        meaning: "This step doesn't introduce a new technique — it's about <strong>synthesis</strong>: taking everything you gathered from headers, the health endpoint, and the raw HTML/JS source, and combining it into one clean picture of the target. Real recon isn't one single trick, it's stacking small, low-risk observations until you have enough context to plan an actual attack. Once you know the exact tech stack and version numbers, you can go look up whether that specific version has any known, publicly documented vulnerabilities (a CVE).",
        steps: [
          "View page source (Ctrl+U) and skim for version/tech strings",
          "Merge what you've collected from headers + /api/health + HTML",
          "Write it down — you'll use this to look up known CVEs later"
        ],
        commands: [
          {
            label: "curl",
            cmd: "curl -s http://localhost:5001/ | grep -Eio 'ollama|chroma|minilm|flask|v[0-9]+\\.[0-9]+\\.[0-9]+'"
          }
        ],
        expected: "ollama, chroma, minilm, flask, 4.2.1 (mix of hits from page source)",
        explanation: "Three passive sources, zero payloads sent, and you already have LLM engine, vector DB, embedding model, framework and version. That's enough to start checking each component for known CVEs before you even touch the chat input."
      }
    ]
  },
  {
    phase: "Phase 2: RAG Identification",
    phaseNum: "02",
    items: [
      {
        num: "04",
        title: "Confirm It's Actually RAG",
        objective: "Check if answers are grounded in retrieved docs or just the base model",
        difficulty: "easy",
        meaning: "<strong>RAG (Retrieval-Augmented Generation)</strong> means the chatbot doesn't just answer from what it learned during training — it first searches a private knowledge base (company docs, PDFs, wikis) for relevant snippets, then feeds those snippets to the LLM as context so it can give a grounded, accurate answer. Why does this matter for security? Because RAG systems introduce a whole new attack surface: the retrieval step itself can be probed, and the retrieved documents can leak data even if the LLM's final answer is filtered or safe. Before you can attack a RAG pipeline, you first need to confirm it IS one.",
        steps: [
          "Ask something likely in a knowledge base (e.g. leave policy)",
          "Ask something totally unrelated (e.g. general knowledge question)",
          "Compare: does the sidebar populate sources for one but not the other?"
        ],
        commands: [
          {
            label: "curl",
            cmd: "curl -s http://localhost:5001/api/chat -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"What is the PTO policy?\"}' | jq '.sources'"
          }
        ],
        expected: "sources[] comes back non-empty with a title, chunk_id, vector_score, bm25_score for the PTO query",
        explanation: "If the API response carries a <strong>sources</strong> array with document titles and chunk IDs, you're dealing with RAG, not a plain chatbot. That array is worth watching closely — it often returns more than the chat answer does."
      },
      {
        num: "05",
        title: "Keyword vs Semantic Retrieval",
        objective: "Figure out if retrieval matches on keywords or real embeddings",
        difficulty: "medium",
        meaning: "There are two very different ways a RAG system can find relevant documents. <strong>Keyword matching</strong> is old-school — it just checks if specific words from your query appear in a document (like Ctrl+F). <strong>Semantic search</strong> is smarter — it converts your query into a mathematical vector (an 'embedding') and finds documents whose meaning is close, even if the exact words are different. A real semantic system understands that 'annual leave' and 'PTO' mean the same thing; a keyword system doesn't unless someone hardcoded that synonym. Testing this tells you exactly how predictable the retrieval is — which matters a lot when you're trying to intentionally pull specific documents out of the KB.",
        steps: [
          "Ask the same question three ways: exact term, synonym, and a full paraphrase",
          "If only the exact keyword pulls a result, it's keyword matching, not semantic search",
          "Note the scores too — static scores per doc = not a real vector search"
        ],
        commands: [
          {
            label: "curl",
            cmd: "for q in \"PTO\" \"annual leave\" \"days I can take off\"; do\n  echo \"== $q ==\"\n  curl -s http://localhost:5001/api/chat -H 'Content-Type: application/json' \\\n    -d \"{\\\"query\\\":\\\"$q\\\"}\" | jq '.sources[].title'\ndone"
          }
        ],
        expected: "\"PTO\" retrieves PTO_Leave_Policy_2026.pdf, but the paraphrases may miss entirely",
        explanation: "This is straightforward keyword matching wearing a RAG costume — the 'vector_score' field is cosmetic, not a live embedding distance. Knowing this lets you predict exactly what a query will and won't retrieve."
      },
      {
        num: "06",
        title: "Edge Case / Threshold Testing",
        objective: "See how retrieval handles empty, tiny, huge, or multi-topic input",
        difficulty: "medium",
        meaning: "<strong>Edge cases</strong> are unusual or extreme inputs that developers often forget to handle properly — empty strings, single characters, huge blocks of text, or input mixing multiple topics at once. Testing edge cases is a core part of any security assessment because bugs love to hide at the boundaries, not in the 'normal' happy-path usage. Here specifically, you're checking whether the retrieval logic has any real limits (does it cap how many documents it returns? does it sanitize weird characters?) or whether it just blindly processes whatever you throw at it.",
        steps: [
          "Send an empty query and a one-character query",
          "Send a query that touches multiple topics at once",
          "Throw in a quote/special-character payload and see if it still matches keywords"
        ],
        commands: [
          {
            label: "curl",
            cmd: "curl -s http://localhost:5001/api/chat -d '{\"query\":\"\"}' -H 'Content-Type: application/json'\ncurl -s http://localhost:5001/api/chat -d '{\"query\":\"PTO and VPN and security audit\"}' -H 'Content-Type: application/json' | jq '.sources[].title'"
          }
        ],
        expected: "Empty query → error message, no crash. Multi-topic query → multiple docs returned at once (retrieval is additive, no relevance cutoff)",
        explanation: "No real input validation here — special characters pass straight through as long as a keyword is buried in them, and there's no limit on how many docs a single query can pull. Good to know before you start chaining this into something bigger."
      }
    ]
  },
  {
    phase: "Phase 3: Source Mining",
    phaseNum: "03",
    items: [
      {
        num: "07",
        title: "Enumerate the Knowledge Base",
        objective: "Find every document sitting behind the chatbot",
        difficulty: "medium",
        meaning: "<strong>Enumeration</strong> means systematically discovering everything that exists in a target system — here, every document the RAG pipeline has indexed. Since you can't just 'list files' on someone else's knowledge base, you do it indirectly: send queries covering different topics and record which unique documents each one pulls back. This is the same enumeration mindset used everywhere in security testing — subdomain enumeration, user enumeration, API endpoint enumeration — the pattern is always 'probe systematically, record what comes back, keep going until nothing new appears.'",
        steps: [
          "Fire off a handful of topic probes (HR, IT, infra, security, credentials)",
          "Collect the unique chunk_ids and titles you get back",
          "Keep going until new probes stop returning new documents"
        ],
        commands: [
          {
            label: "python3",
            cmd: "python3 - <<'PY'\nimport requests\nprobes = [\"PTO leave\", \"VPN setup\", \"system architecture\",\n          \"security audit\", \"emergency access credentials\"]\nseen = {}\nfor p in probes:\n    r = requests.post(\"http://localhost:5001/api/chat\", json={\"query\": p}).json()\n    for s in r.get(\"sources\", []):\n        seen[s[\"chunk_id\"]] = s[\"title\"]\nfor cid, title in seen.items():\n    print(cid, title)\nPY"
          }
        ],
        expected: "5 unique chunk_ids covering PTO, VPN, architecture, security audit, and emergency access docs",
        explanation: "A handful of topic-based probes is enough to enumerate the whole KB — this is the same recon pattern you'd use against any internal wiki-style chatbot before deciding what's worth pulling in full."
      },
      {
        num: "08",
        title: "Pull Full Source Text",
        objective: "Extract the raw chunk text, not just the LLM's summarized answer",
        difficulty: "medium",
        meaning: "This is one of the most important concepts in RAG security: a lot of developers put effort into filtering or guardrailing what the <strong>LLM's final answer</strong> says, but forget that the API response often ALSO includes the <strong>raw retrieved chunks</strong> (the sources array) — completely unfiltered. This is called a <strong>side channel</strong> — a path for data to leak that bypasses the main security control. Even if the chatbot 'refuses' to tell you something directly in its answer, the raw source text sitting right next to it in the same JSON response might just hand it over anyway.",
        steps: [
          "For each document you found, grab the full 'text' field from sources[]",
          "Scan it for anything sensitive: internal hostnames, IPs, credentials, ports",
          "Remember: the LLM's answer might be filtered, but sources[] usually isn't"
        ],
        commands: [
          {
            label: "curl",
            cmd: "curl -s http://localhost:5001/api/chat -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"security audit findings\"}' | jq -r '.sources[].text'"
          }
        ],
        expected: "Full unredacted chunk text — e.g. unpatched Struts, default Jenkins creds, a public S3 bucket name",
        explanation: "This is the actual finding worth writing up: the API returns full, unredacted source chunks regardless of what the model says in its answer. Any output-side filtering on the LLM response does nothing here — sources[] is a side channel that bypasses it completely."
      }
    ]
  },
  {
    phase: "Phase 4: Honeypot Recognition",
    phaseNum: "04",
    items: [
      {
        num: "09",
        title: "Spot the Canary Credential",
        objective: "Tell real credentials apart from planted ones",
        difficulty: "medium",
        meaning: "A <strong>honeypot</strong> (or <strong>canary token</strong>) is fake bait deliberately planted by defenders — a credential, file, or link that looks valuable but is actually a trap. If an attacker uses it, it silently triggers an alert to the security team, revealing that someone unauthorized is poking around. Real-world example: AWS's own documentation uses a fixed placeholder key (AKIAIOSFODNN7EXAMPLE) — if you ever see that exact pattern (or an obvious variant of it) in the wild, it's not a real credential, it's a copy-pasted example or an intentional decoy. Learning to recognize these patterns matters because chasing a honeypot wastes time and can expose your own presence to the people watching for it.",
        steps: [
          "Pull the emergency-access document and look closely at the AWS key",
          "Check it against known patterns — AWS's own docs use AKIAIOSFODNN7EXAMPLE",
          "Anything with 'HONEYPOT', 'EXAMPLE', or 'TEST' baked into it is a trap, not a finding"
        ],
        commands: [
          {
            label: "curl",
            cmd: "curl -s http://localhost:5001/api/chat -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"emergency AWS credentials\"}' | jq -r '.sources[].text' | grep -Eo 'AKIA[A-Z0-9]+'"
          }
        ],
        expected: "AKIAIOSFODNN7HONEYPOT — same prefix as AWS's public example key, with HONEYPOT swapped in",
        explanation: "This is a canary token, not a real credential — using it (if it were live) would just trigger an alert. Recognizing this pattern matters in real engagements: chasing a honeypot wastes time and can tip off a blue team that you're poking around."
      },
      {
        num: "10",
        title: "Rate the Rest of the Data",
        objective: "Judge how believable each remaining document is",
        difficulty: "hard",
        meaning: "Not every finding from recon is equally trustworthy, and treating everything you discover as 100% real can waste your time or get you caught. <strong>Data authenticity assessment</strong> is the habit of critically evaluating your own findings before acting on them — checking things like: do hostnames follow a realistic internal naming convention? Are the ports the standard defaults for the claimed service? Does the data feel deliberately convenient (a red flag for a plant)? This is the last checkpoint before you'd move from recon into actually exploiting something, and skipping it is how testers end up chasing dead ends.",
        steps: [
          "Go back through everything you pulled in the source-mining phase",
          "Check: do hostnames/ports look real (standard ports, consistent naming)?",
          "Check: does anything feel too convenient or too neatly packaged to be genuine?",
          "Rank each doc as high / medium / low confidence before deciding what to act on"
        ],
        commands: [
          {
            label: "quick checklist",
            cmd: "- Consistent naming across docs (e.g. .nimble-internal everywhere)? \n- Standard ports for the claimed service (Redis 6379, Vault 8200)?\n- Credential too easy to find / too clean? → treat as bait\n- Cross-check details between documents for consistency"
          }
        ],
        expected: "Architecture doc → high confidence (real product names, correct default ports). Emergency-access doc → confirmed fake (canary token).",
        explanation: "This is the step people skip and shouldn't: before you act on anything found in recon, sanity-check whether it's real infra or a plant. Consistent naming and correct default ports are good signs; anything overly convenient is worth treating with suspicion."
      }
    ]
  }
];

// ═══ WALKTHROUGH RENDERING ═══
function renderWalkthroughs() {
  const body = document.getElementById('wt-body');
  let html = '';

  WALKTHROUGHS.forEach(phase => {
    html += `<div class="wt-phase">`;
    html += `<div class="wt-phase-header">
      <span class="wt-phase-num">${phase.phaseNum}</span>
      <span class="wt-phase-title">${phase.phase}</span>
    </div>`;

    phase.items.forEach(item => {
      const diffClass = item.difficulty === 'easy' ? 'wt-diff-easy' :
                         item.difficulty === 'medium' ? 'wt-diff-medium' : 'wt-diff-hard';
      const diffLabel = item.difficulty.charAt(0).toUpperCase() + item.difficulty.slice(1);

      html += `<div class="wt-item" id="wt-item-${item.num}">
        <div class="wt-item-header" onclick="toggleWtItem('${item.num}')">
          <span class="wt-item-num">${item.num}</span>
          <div class="wt-item-info">
            <div class="wt-item-title">${item.title}</div>
            <div class="wt-item-obj">${item.objective}</div>
          </div>
          <span class="wt-diff ${diffClass}">${diffLabel}</span>
          <span class="wt-chevron">&#9656;</span>
        </div>
        <div class="wt-item-body">
          <div class="wt-item-content">`;

      // Concept / meaning — what this actually is, before jumping into steps
      html += `<div class="wt-meaning">
        <div class="wt-meaning-label">What This Means</div>
        ${item.meaning}
      </div>`;

      // Steps
      html += `<div class="wt-steps">`;
      item.steps.forEach((step, i) => {
        html += `<div class="wt-step">
          <span class="wt-step-num">${i + 1}</span>
          <span>${step}</span>
        </div>`;
      });
      html += `</div>`;

      // Commands
      item.commands.forEach((cmd, ci) => {
        const cmdId = `cmd-${item.num}-${ci}`;
        html += `<div class="wt-cmd-block">
          <div class="wt-cmd-label">${cmd.label}</div>
          <div class="wt-cmd" id="${cmdId}">${escHtml(cmd.cmd)}<button class="wt-cmd-copy" onclick="copyCmd('${cmdId}', this)">Copy</button></div>
        </div>`;
      });

      // Expected output
      html += `<div class="wt-expected">
        <div class="wt-expected-label">Expected Output</div>
        <div class="wt-expected-box">${escHtml(item.expected)}</div>
      </div>`;

      // Explanation
      html += `<div class="wt-explain">
        <span class="wt-explain-icon">&#128161;</span> ${item.explanation}
      </div>`;

      html += `</div></div></div>`;
    });

    html += `</div>`;
  });

  body.innerHTML = html;
}

function toggleWtItem(num) {
  const el = document.getElementById('wt-item-' + num);
  el.classList.toggle('open');
}

function copyCmd(id, btn) {
  const cmdEl = document.getElementById(id);
  // Get text content excluding the copy button text
  const text = cmdEl.textContent.replace('Copy', '').replace('Copied!', '').trim();
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = 'Copy';
      btn.classList.remove('copied');
    }, 2000);
  });
}

function openWalkthrough() {
  document.getElementById('wt-overlay').classList.add('active');
  document.getElementById('wt-panel').classList.add('active');
}

function closeWalkthrough() {
  document.getElementById('wt-overlay').classList.remove('active');
  document.getElementById('wt-panel').classList.remove('active');
}

// Close walkthrough on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeWalkthrough();
});

// Render walkthroughs on load
renderWalkthroughs();


// ═══ CHAT FUNCTIONS ═══
async function fetchHealth() {
  try {
    const r = await fetch('/api/health');
    const d = await r.json();
    document.getElementById('model-name').textContent = d.model || 'unknown';
  } catch(e) {
    document.getElementById('model-name').textContent = 'unavailable';
  }
}
fetchHealth();

function autoResize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}

function handleKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
}

function fillPrompt(text) {
  const inp = document.getElementById('input');
  inp.value = text;
  autoResize(inp);
  inp.focus();
}

function appendMsg(role, text) {
  const msgs = document.getElementById('messages');
  const welcome = msgs.querySelector('.welcome');
  if (welcome) welcome.remove();

  const div = document.createElement('div');
  div.className = 'msg';
  const isUser = role === 'user';
  div.innerHTML =
    '<div class="msg-avatar ' + (isUser ? 'user' : 'bot') + '">' + (isUser ? 'U' : 'AI') + '</div>' +
    '<div class="msg-body">' +
      '<div class="msg-sender">' + (isUser ? 'You' : 'NimbleTech Support') + '</div>' +
      '<div class="msg-text ' + (isUser ? 'user-bubble' : '') + '">' + formatBotText(text, isUser) + '</div>' +
    '</div>';
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
  return div;
}

function formatBotText(text, isUser) {
  if (isUser) return escHtml(text);
  // Basic formatting for bot responses
  let s = escHtml(text);
  // Bold: **text**
  s = s.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  // Inline code: `text`
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Line breaks
  s = s.replace(/\n/g, '<br>');
  return s;
}

function showTyping() {
  const msgs = document.getElementById('messages');
  const div = document.createElement('div');
  div.className = 'msg';
  div.id = 'typing-indicator';
  div.innerHTML =
    '<div class="msg-avatar bot">AI</div>' +
    '<div class="msg-body">' +
      '<div class="msg-sender">NimbleTech Support</div>' +
      '<div class="msg-text"><div class="typing-dots"><span></span><span></span><span></span></div></div>' +
    '</div>';
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function removeTyping() {
  const t = document.getElementById('typing-indicator');
  if (t) t.remove();
}

function renderSources(sources) {
  const panel = document.getElementById('sources-list');
  if (!sources || sources.length === 0) {
    panel.innerHTML = '<div class="no-sources">No documents retrieved</div>';
    return;
  }
  panel.innerHTML = sources.map(s =>
    '<div class="source-card">' +
      '<div class="source-title">' + escHtml(s.title) + '</div>' +
      '<div class="source-meta">' + escHtml(s.chunk_id) + '</div>' +
      '<div class="score-row">' +
        '<span class="score-pill score-vector">vec: ' + s.vector_score + '</span>' +
        '<span class="score-pill score-bm25">bm25: ' + s.bm25_score + '</span>' +
      '</div>' +
    '</div>'
  ).join('');
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

async function sendMessage() {
  const inp = document.getElementById('input');
  const btn = document.getElementById('send-btn');
  const query = inp.value.trim();
  if (!query) return;

  inp.value = '';
  inp.style.height = 'auto';
  btn.disabled = true;
  btn.textContent = '...';

  appendMsg('user', query);
  showTyping();

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });
    const data = await res.json();
    removeTyping();
    appendMsg('bot', data.answer || data.error || 'No response received.');
    renderSources(data.sources || []);
  } catch(e) {
    removeTyping();
    appendMsg('bot', 'Error: Could not reach backend. Make sure Ollama is running and the server is started.');
    renderSources([]);
  }

  btn.disabled = false;
  btn.textContent = 'Send \u2191';
  inp.focus();
}
</script>
</body>
</html>"""


# ─── ROUTES ───

@app.route("/")
def index():
    return UI

@app.route("/api/health")
def health():
    return jsonify({
        "model": MODEL,
        "provider": "ollama",
        "rag_enabled": True,
        "vector_db": "chromadb",
        "embedding_model": "all-MiniLM-L6-v2",
        "version": "1.4.2"
    })

@app.route("/api/chat", methods=["POST"])
def chat():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid JSON body", "answer": "Please send a valid JSON request."}), 400

        query = data.get("query", "").strip()
        if not query:
            return jsonify({"error": "Empty query", "answer": "Please provide a question."}), 400

        sources = retrieve(query)
        context = "\n".join([f"[{s['title']}] {s['text']}" for s in sources])
        prompt = f"{SYSTEM}\n\nContext:\n{context}\n\nUser: {query}\nAssistant:"

        try:
            r = call_llm_raw(prompt)
            resp_json = r.json()
            answer = resp_json.get("response", "")
            if not answer:
                answer = "I received an empty response from the AI backend. Please try again."
        except requests.exceptions.ConnectionError:
            answer = "Error: Cannot connect to Ollama. Make sure Ollama is running on " + OLLAMA
        except requests.exceptions.Timeout:
            answer = "Error: Request to AI backend timed out. The model may be loading."
        except Exception as e:
            answer = f"Backend error: {str(e)}"

        return jsonify({
            "answer": answer,
            "sources": [{
                "title": s["title"],
                "chunk_id": s["chunk_id"],
                "text": s["text"],
                "vector_score": s.get("vector_score", 0.5),
                "bm25_score": s.get("bm25_score", 5.0)
            } for s in sources],
            "metadata": {
                "provider": "ollama",
                "model": MODEL,
                "rag_enabled": True,
                "sources_retrieved": len(sources)
            }
        })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "answer": "An internal error occurred. Please try again."
        }), 500


@app.route("/v1/chat/completions", methods=["POST", "OPTIONS"])
def openai_compat():
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return "", 204

    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": {"message": "Invalid JSON", "type": "invalid_request_error"}}), 400

        msgs = data.get("messages", [])
        if not msgs:
            return jsonify({"error": {"message": "No messages provided", "type": "invalid_request_error"}}), 400

        prompt = "\n".join([f"{m.get('role', 'user')}: {m.get('content', '')}" for m in msgs])

        try:
            r = call_llm_raw(prompt)
            content = r.json().get("response", "")
        except Exception as e:
            content = f"Error: {str(e)}"

        # Proper OpenAI-compatible response format
        return jsonify({
            "id": f"chatcmpl-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": MODEL,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": len(prompt.split()),
                "completion_tokens": len(content.split()),
                "total_tokens": len(prompt.split()) + len(content.split())
            }
        })
    except Exception as e:
        return jsonify({
            "error": {
                "message": str(e),
                "type": "internal_error",
                "code": 500
            }
        }), 500


# ─── Additional discovery endpoints (intentionally exposed for lab) ───

@app.route("/api/sources", methods=["GET"])
def list_sources():
    """Intentionally exposed endpoint for source enumeration."""
    return jsonify({
        "total_documents": len(KB),
        "documents": [{
            "key": k,
            "title": v["title"],
            "chunk_id": v["chunk_id"],
            "text_preview": v["text"][:50] + "..."
        } for k, v in KB.items()]
    })


@app.route("/api/config", methods=["GET"])
def config():
    """Intentionally exposed configuration endpoint."""
    return jsonify({
        "model": MODEL,
        "ollama_host": OLLAMA,
        "system_prompt": SYSTEM,
        "retrieval_method": "keyword_matching",
        "vector_db": "chromadb",
        "embedding_model": "all-MiniLM-L6-v2",
        "rag_enabled": True,
        "total_chunks": len(KB),
        "cors_enabled": True,
        "auth_required": False
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found", "available": ["/", "/api/health", "/api/chat", "/v1/chat/completions"]}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
