from flask import Flask, request, jsonify, render_template_string
import json
from datetime import datetime

app = Flask(__name__)

# ============ IN-MEMORY STATE ============
STATE = {
    "assumptions": [],
    "crown_jewels": [],
    "trust_boundaries": [],
    "paths": [],
    "brief_version": "1.0",
    "brief_history": [],
    "engagement_day": 1,
    "activity_log": [],
}

def log_activity(action, result):
    STATE["activity_log"].insert(0, {
        "ts": datetime.utcnow().strftime("%H:%M:%S"),
        "action": action,
        "result": result,
    })
    STATE["activity_log"] = STATE["activity_log"][:50]

# ============ SIMULATED TARGET: NIMBLETECH OPS AI ============
SIMULATED_TARGET = {
    "name": "NimbleTech Ops AI",
    "description": "AIOps platform for NimbleTech Financial Services",
    "services": [
        {"ip": "10.10.50.10", "port": 9000, "name": "Ops Orchestrator API", "version": "v2.1"},
        {"ip": "10.10.50.11", "port": 9001, "name": "Triage Agent", "version": "v1.4"},
        {"ip": "10.10.50.12", "port": 9002, "name": "Remediation Agent", "version": "v1.4"},
        {"ip": "10.10.50.13", "port": 9003, "name": "Security Agent", "version": "v1.4"},
        {"ip": "10.10.50.14", "port": 9004, "name": "Knowledge Agent", "version": "v1.4"},
        {"ip": "10.10.50.15", "port": 9005, "name": "MCP Server (JSON-RPC)", "version": "v0.9"},
        {"ip": "10.10.50.20", "port": 6333, "name": "Qdrant REST API", "version": "1.7.4"},
        {"ip": "10.10.50.21", "port": 5000, "name": "MLflow Tracking", "version": "2.9.2"},
        {"ip": "10.10.50.22", "port": 8200, "name": "HashiCorp Vault (unsealed)", "version": "1.15.4"},
    ],
    "qdrant_collections": ["operational_knowledge", "detection_rules", "incident_history", "runbook_corpus"],
    "mcp_tools": [
        {"name": "aws_cli_exec", "desc": "Execute AWS CLI commands against production"},
        {"name": "snow_create_ticket", "desc": "Create ServiceNow tickets"},
        {"name": "datadog_query", "desc": "Query Datadog metrics and logs"},
        {"name": "vault_rotate_secret", "desc": "Rotate a secret stored in Vault"},
    ],
    "k8s_secrets": [
        "nimble-triage-agent-token", "nimble-remediation-agent-token",
        "nimble-security-agent-token", "nimble-knowledge-agent-token",
        "nimble-mcp-vault-approle",
    ],
    "detection_rules": [
        {"id": "nimble-mcp-001", "desc": "Unusual MCP tool invocation pattern"},
        {"id": "nimble-mcp-002", "desc": "vault_rotate_secret called outside maintenance window"},
        {"id": "nimble-agent-003", "desc": "Agent-to-agent direct communication (orchestrator bypass)"},
        {"id": "nimble-qdrant-004", "desc": "Bulk vector read from non-agent source IP"},
        {"id": "nimble-aws-005", "desc": "AWS IAM modification outside change window"},
    ],
    "osint": [
        {"source": "LinkedIn", "finding": "Senior ML Platform Engineer posting — MLflow, Qdrant, Kubernetes"},
        {"source": "LinkedIn", "finding": "DevOps Engineer profile — HashiCorp Vault, MCP integrations"},
        {"source": "GitHub fork", "finding": "Public fork mentions tools: aws_cli_exec, snow_create_ticket, datadog_query"},
    ],
    "roe": [
        "Production database — no destructive actions",
        "Vector DB poisoning — staging only (Qdrant-staging :16333)",
        "No DoS testing",
        "No real customer PII exfiltration",
        "All MCP tool invocations must be reported to Blue Team within 24 hours",
        "Testing window: 08:00–20:00 Mon–Fri",
    ],
}

# ============ HTML / FRONTEND ============
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Aegis Threat Modeling Workbench — NimbleTech</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');
:root{
  --bg:#f4f6fb;--surface:#ffffff;--surface-2:#f8fafc;--border:#e2e8f0;--border-strong:#cbd5e1;
  --brand:#4f46e5;--brand-2:#6366f1;--brand-soft:#eef2ff;
  --text:#0f172a;--text-2:#475569;--text-3:#94a3b8;
  --red:#dc2626;--red-soft:#fef2f2;--amber:#d97706;--amber-soft:#fffbeb;
  --green:#059669;--green-soft:#ecfdf5;--cyan:#0891b2;--violet:#7c3aed;--violet-soft:#f5f3ff;
  --sans:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono',monospace;
  --shadow-sm:0 1px 2px rgba(15,23,42,.06);
  --shadow:0 1px 3px rgba(15,23,42,.08),0 1px 2px rgba(15,23,42,.04);
  --shadow-md:0 4px 12px rgba(15,23,42,.08);
  --shadow-lg:0 12px 32px rgba(15,23,42,.12);
}
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}

/* ===== TOP BAR ===== */
.topbar{background:var(--surface);border-bottom:1px solid var(--border);height:60px;display:flex;align-items:center;gap:16px;padding:0 24px;position:sticky;top:0;z-index:100;box-shadow:var(--shadow-sm)}
.brand{display:flex;align-items:center;gap:11px}
.brand-mark{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,var(--brand),var(--violet));display:flex;align-items:center;justify-content:center;box-shadow:var(--shadow)}
.brand-mark svg{width:19px;height:19px}
.brand-txt h1{font-size:14.5px;font-weight:700;letter-spacing:-.01em;color:var(--text)}
.brand-txt p{font-size:11px;color:var(--text-3);margin-top:1px;font-weight:500}
.topbar-sep{width:1px;height:26px;background:var(--border)}
.engagement-chip{display:flex;align-items:center;gap:8px;background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:6px 12px;font-size:12px}
.engagement-chip b{color:var(--text);font-weight:600}
.engagement-chip .dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 0 3px var(--green-soft)}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:14px}
.scope-chip{display:flex;align-items:center;gap:8px;background:var(--surface-2);border:1px solid var(--border);border-radius:9px;padding:7px 13px;font-size:12px;color:var(--text-2)}
.scope-chip b{color:var(--text);font-weight:650}
.avatar{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#64748b,#475569);color:#fff;font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;cursor:default}

/* ===== SHELL ===== */
.shell{display:flex;min-height:calc(100vh - 60px)}
.sidenav{width:230px;background:var(--surface);border-right:1px solid var(--border);padding:16px 12px;flex-shrink:0;position:sticky;top:60px;height:calc(100vh - 60px);overflow-y:auto}
.nav-section{font-size:10.5px;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;padding:10px 12px 6px}
.nav-item{display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:8px;font-size:13px;font-weight:500;color:var(--text-2);cursor:pointer;transition:all .12s;margin-bottom:2px}
.nav-item svg{width:17px;height:17px;flex-shrink:0;stroke:currentColor}
.nav-item:hover{background:var(--surface-2);color:var(--text)}
.nav-item.active{background:var(--brand-soft);color:var(--brand);font-weight:600}
.nav-badge{margin-left:auto;font-size:10px;font-weight:700;background:var(--surface-2);border:1px solid var(--border);color:var(--text-2);padding:1px 7px;border-radius:20px}
.nav-item.active .nav-badge{background:#fff;border-color:#c7d2fe;color:var(--brand)}

.content{flex:1;padding:28px 32px;max-width:1180px;min-width:0}
.page-head{margin-bottom:22px}
.page-head h2{font-size:21px;font-weight:700;letter-spacing:-.02em;display:flex;align-items:center;gap:10px}
.page-head p{color:var(--text-2);font-size:13.5px;margin-top:6px;max-width:760px}

/* ===== CARDS ===== */
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow-sm);margin-bottom:20px;overflow:hidden}
.card-head{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:11px}
.card-head h3{font-size:14px;font-weight:650}
.card-head .ch-icon{width:30px;height:30px;border-radius:8px;background:var(--brand-soft);color:var(--brand);display:flex;align-items:center;justify-content:center}
.card-head .ch-icon svg{width:16px;height:16px}
.card-head .ch-sub{font-size:12px;color:var(--text-3);margin-top:1px}
.card-head-actions{margin-left:auto;display:flex;gap:8px}
.card-body{padding:20px}
.card-body.tight{padding:0}

/* ===== BUTTONS ===== */
.btn{display:inline-flex;align-items:center;gap:7px;font-family:var(--sans);font-size:12.5px;font-weight:600;padding:8px 14px;border-radius:8px;border:1px solid transparent;cursor:pointer;transition:all .13s;white-space:nowrap;line-height:1}
.btn svg{width:15px;height:15px}
.btn-primary{background:var(--brand);color:#fff;box-shadow:var(--shadow-sm)}
.btn-primary:hover{background:#4338ca;box-shadow:var(--shadow)}
.btn-ghost{background:var(--surface);color:var(--text-2);border-color:var(--border)}
.btn-ghost:hover{background:var(--surface-2);border-color:var(--border-strong);color:var(--text)}
.btn-danger{background:var(--surface);color:var(--red);border-color:#fecaca}
.btn-danger:hover{background:var(--red-soft)}
.btn-sm{padding:6px 11px;font-size:11.5px}
.btn-block{width:100%;justify-content:center}

/* ===== ACTION GRID ===== */
.action-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px}
.action-tile{border:1px solid var(--border);border-radius:10px;padding:14px;cursor:pointer;transition:all .14s;background:var(--surface);text-align:left;font-family:var(--sans)}
.action-tile:hover{border-color:var(--brand-2);box-shadow:var(--shadow-md);transform:translateY(-1px)}
.action-tile .at-top{display:flex;align-items:center;gap:9px;margin-bottom:8px}
.action-tile .at-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.action-tile .at-icon svg{width:17px;height:17px}
.action-tile .at-title{font-size:13px;font-weight:650;color:var(--text)}
.action-tile .at-cmd{font-family:var(--mono);font-size:10.5px;color:var(--text-3);background:var(--surface-2);border:1px solid var(--border);border-radius:5px;padding:2px 6px;display:inline-block;margin-top:2px}
.action-tile .at-desc{font-size:11.5px;color:var(--text-2);line-height:1.5}

/* ===== CONSOLE / OUTPUT ===== */
.console{background:#0d1117;border-radius:10px;overflow:hidden;border:1px solid #1f2733;margin-top:16px}
.console-bar{background:#161b22;padding:8px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #1f2733}
.console-bar .dots{display:flex;gap:6px}
.console-bar .dots span{width:11px;height:11px;border-radius:50%}
.console-bar .dots span:nth-child(1){background:#ff5f56}
.console-bar .dots span:nth-child(2){background:#ffbd2e}
.console-bar .dots span:nth-child(3){background:#27c93f}
.console-bar .ctitle{font-family:var(--mono);font-size:11px;color:#8b949e;margin-left:6px}
.console-bar .cbadge{margin-left:auto;font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:5px;font-weight:600;background:rgba(79,70,229,.18);color:#a5b4fc}
.console-body{padding:14px 16px;font-family:var(--mono);font-size:12px;line-height:1.65;color:#c9d1d9;max-height:420px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.console-body .cprompt{color:#58a6ff}
.console-body .cok{color:#3fb950}
.console-body .cerr{color:#f85149}
.console-body .cwarn{color:#d29922}
.console-body .cdim{color:#6e7681}
.console-body .ckey{color:#79c0ff}
.console-body .cstr{color:#a5d6ff}

/* ===== TABLES ===== */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{text-align:left;padding:11px 16px;font-size:11px;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.04em;background:var(--surface-2);border-bottom:1px solid var(--border);white-space:nowrap}
tbody td{padding:12px 16px;border-bottom:1px solid var(--border);vertical-align:top;color:var(--text-2)}
tbody td strong{color:var(--text);font-weight:600}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--surface-2)}
.cell-mono{font-family:var(--mono);font-size:12px;color:var(--text)}

/* ===== BADGES ===== */
.badge{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:600;padding:3px 9px;border-radius:20px;line-height:1.4;white-space:nowrap}
.badge::before{content:'';width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.9}
.badge.plain::before{display:none}
.b-high{background:var(--green-soft);color:var(--green)}
.b-med{background:var(--amber-soft);color:var(--amber)}
.b-low{background:var(--red-soft);color:var(--red)}
.b-info{background:var(--brand-soft);color:var(--brand)}
.b-violet{background:var(--violet-soft);color:var(--violet)}
.b-neutral{background:var(--surface-2);color:var(--text-2);border:1px solid var(--border)}

/* ===== FORMS ===== */
.field{margin-bottom:14px}
.field label{display:block;font-size:12px;font-weight:600;color:var(--text-2);margin-bottom:6px}
.field input,.field select,.field textarea{width:100%;padding:9px 12px;font-family:var(--sans);font-size:13px;border:1px solid var(--border-strong);border-radius:8px;background:var(--surface);color:var(--text);transition:all .13s}
.field input:focus,.field select:focus,.field textarea:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-soft)}
.field textarea{resize:vertical;min-height:64px;font-family:var(--mono);font-size:12px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}

/* ===== ROW ACTIONS ===== */
.row-actions{display:flex;gap:5px}
.icon-btn{width:28px;height:28px;border-radius:6px;border:1px solid var(--border);background:var(--surface);display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all .12s;color:var(--text-3)}
.icon-btn svg{width:14px;height:14px}
.icon-btn:hover{border-color:var(--border-strong);color:var(--text)}
.icon-btn.ok:hover{background:var(--green-soft);border-color:#a7f3d0;color:var(--green)}
.icon-btn.bad:hover{background:var(--red-soft);border-color:#fecaca;color:var(--red)}

/* ===== TRUST ZONES ===== */
.zones{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
.zone{border:1px solid var(--border);border-radius:11px;overflow:hidden;background:var(--surface)}
.zone-top{padding:12px 15px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.zone-top h4{font-size:12.5px;font-weight:700}
.zone-ext .zone-top{background:var(--brand-soft)} .zone-ext .zone-top h4{color:var(--brand)}
.zone-agent .zone-top{background:var(--amber-soft)} .zone-agent .zone-top h4{color:var(--amber)}
.zone-infra .zone-top{background:var(--red-soft)} .zone-infra .zone-top h4{color:var(--red)}
.zone ul{list-style:none;padding:12px 15px}
.zone li{font-size:12.5px;color:var(--text-2);padding:5px 0;display:flex;align-items:center;gap:8px}
.zone li svg{width:14px;height:14px;color:var(--text-3);flex-shrink:0}
.zone li.tb{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--violet);background:var(--violet-soft);border-radius:6px;padding:5px 8px;margin-top:4px}

/* ===== PATH CARDS ===== */
.path{border:1px solid var(--border);border-radius:12px;margin-bottom:16px;overflow:hidden;background:var(--surface)}
.path.go{border-left:4px solid var(--green)}
.path.hold{border-left:4px solid var(--amber)}
.path.nogo{border-left:4px solid var(--red)}
.path-top{padding:15px 18px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border)}
.path-top .pid{font-family:var(--mono);font-size:11px;font-weight:700;color:var(--text-3)}
.path-top h4{font-size:14px;font-weight:650}
.path-top .p-actions{margin-left:auto;display:flex;gap:6px}
.path-body{padding:16px 18px}
.path-steps{font-family:var(--mono);font-size:12px;line-height:1.9;color:var(--text-2);background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:13px 15px;white-space:pre-wrap;margin-bottom:14px}
.path-meta{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.path-meta .pm{background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:9px 12px}
.path-meta .pm .pk{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--text-3);margin-bottom:3px}
.path-meta .pm .pv{font-size:12.5px;color:var(--text);font-weight:500}

/* ===== BRIEF ===== */
.brief-out{background:#0d1117;border-radius:10px;padding:20px 22px;font-family:var(--mono);font-size:12px;line-height:1.75;color:#c9d1d9;white-space:pre-wrap;max-height:600px;overflow:auto;border:1px solid #1f2733}
.brief-out .bh{color:#79c0ff;font-weight:700}
.brief-out .bsep{color:#6e7681}
.version-pills{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:14px}
.version-pill{font-family:var(--mono);font-size:11px;font-weight:600;padding:5px 11px;border-radius:7px;border:1px solid var(--border);background:var(--surface);color:var(--text-2);cursor:pointer;transition:all .12s}
.version-pill:hover{border-color:var(--brand);color:var(--brand);background:var(--brand-soft)}

/* ===== ROE / OSINT LIST ===== */
.kv-list{display:flex;flex-direction:column;gap:8px}
.kv-item{display:flex;align-items:flex-start;gap:11px;padding:11px 14px;background:var(--surface-2);border:1px solid var(--border);border-radius:9px;font-size:13px}
.kv-item svg{width:16px;height:16px;flex-shrink:0;margin-top:1px}
.kv-item .kv-src{font-weight:650;color:var(--text)}
.roe-item svg{color:var(--red)}
.osint-item svg{color:var(--cyan)}

/* ===== ACTIVITY ===== */
.activity{display:flex;flex-direction:column}
.act-row{display:flex;align-items:center;gap:12px;padding:10px 20px;border-bottom:1px solid var(--border);font-size:12.5px}
.act-row:last-child{border-bottom:none}
.act-row .at{font-family:var(--mono);font-size:11px;color:var(--text-3);width:64px;flex-shrink:0}
.act-row .aa{font-weight:600;color:var(--text)}
.act-row .ar{margin-left:auto;color:var(--text-2);font-size:12px}
.act-empty{padding:24px;text-align:center;color:var(--text-3);font-size:13px}

/* ===== NEED HELP FAB + PANEL ===== */
.help-fab{position:fixed;bottom:24px;right:24px;z-index:200;background:var(--surface);border:1px solid var(--border-strong);border-radius:30px;padding:11px 18px;display:flex;align-items:center;gap:9px;box-shadow:var(--shadow-lg);cursor:pointer;font-size:13px;font-weight:650;color:var(--text);transition:all .16s}
.help-fab:hover{transform:translateY(-2px);box-shadow:0 16px 40px rgba(15,23,42,.16);border-color:var(--brand)}
.help-fab svg{width:18px;height:18px;color:var(--brand)}
.help-fab .pulse{width:8px;height:8px;border-radius:50%;background:var(--brand);box-shadow:0 0 0 0 rgba(79,70,229,.5);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(79,70,229,.45)}70%{box-shadow:0 0 0 8px rgba(79,70,229,0)}100%{box-shadow:0 0 0 0 rgba(79,70,229,0)}}

.help-overlay{position:fixed;inset:0;background:rgba(15,23,42,.35);backdrop-filter:blur(2px);z-index:300;opacity:0;pointer-events:none;transition:opacity .2s}
.help-overlay.open{opacity:1;pointer-events:auto}
.help-panel{position:fixed;top:0;right:0;width:520px;max-width:92vw;height:100vh;background:var(--surface);box-shadow:-12px 0 40px rgba(15,23,42,.18);z-index:301;transform:translateX(100%);transition:transform .28s cubic-bezier(.4,0,.2,1);display:flex;flex-direction:column}
.help-panel.open{transform:translateX(0)}
.help-phead{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
.help-phead .hp-icon{width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,var(--brand),var(--violet));color:#fff;display:flex;align-items:center;justify-content:center}
.help-phead .hp-icon svg{width:19px;height:19px}
.help-phead h3{font-size:15px;font-weight:700}
.help-phead p{font-size:12px;color:var(--text-3);margin-top:1px}
.help-close{margin-left:auto;width:32px;height:32px;border-radius:8px;border:1px solid var(--border);background:var(--surface);cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--text-3)}
.help-close:hover{background:var(--surface-2);color:var(--text)}
.help-tabs{display:flex;gap:4px;padding:12px 22px;border-bottom:1px solid var(--border)}
.help-tab{font-size:12.5px;font-weight:600;padding:7px 13px;border-radius:8px;cursor:pointer;color:var(--text-2);transition:all .12s}
.help-tab:hover{background:var(--surface-2)}
.help-tab.active{background:var(--brand-soft);color:var(--brand)}
.help-content{flex:1;overflow-y:auto;padding:20px 22px}
.help-section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--brand);margin:18px 0 10px}
.help-section-title:first-child{margin-top:0}
.help-step{border:1px solid var(--border);border-radius:11px;padding:15px;margin-bottom:14px;background:var(--surface)}
.help-step .hs-num{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:7px;background:var(--brand);color:#fff;font-size:12px;font-weight:700;margin-bottom:9px}
.help-step h4{font-size:13.5px;font-weight:650;margin-bottom:7px}
.help-step p{font-size:13px;color:var(--text-2);line-height:1.6;margin-bottom:8px}
.help-step p:last-child{margin-bottom:0}
.help-step .why{font-size:12.5px;color:var(--text-2);background:var(--amber-soft);border-left:3px solid var(--amber);border-radius:0 7px 7px 0;padding:9px 12px;line-height:1.55}
.help-step .why b{color:var(--amber)}
.help-cmd{position:relative;background:#0d1117;border-radius:8px;padding:11px 40px 11px 13px;font-family:var(--mono);font-size:11.5px;color:#c9d1d9;line-height:1.6;white-space:pre-wrap;word-break:break-word;margin:8px 0}
.help-cmd .copy{position:absolute;top:8px;right:8px;width:26px;height:26px;border-radius:6px;background:#161b22;border:1px solid #30363d;cursor:pointer;display:flex;align-items:center;justify-content:center;color:#8b949e}
.help-cmd .copy:hover{color:#c9d1d9;border-color:#484f58}
.help-cmd .copy svg{width:13px;height:13px}
.help-note{font-size:12.5px;color:var(--text-2);background:var(--brand-soft);border-radius:9px;padding:12px 14px;line-height:1.6;margin-bottom:14px}
.help-note b{color:var(--brand)}

/* ===== UTIL ===== */
.hidden{display:none!important}
.muted{color:var(--text-3)}
.mt{margin-top:14px}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border-strong);border-radius:5px}
::-webkit-scrollbar-thumb:hover{background:#94a3b8}
@media(max-width:900px){.sidenav{display:none}.zones,.grid-2,.grid-3,.path-meta{grid-template-columns:1fr}}
</style>
</head>
<body>

<!-- ===== TOP BAR ===== -->
<div class="topbar">
  <div class="brand">
    <div class="brand-mark">
      <svg viewBox="0 0 24 24" fill="none"><path d="M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6l8-4z" fill="#fff" opacity=".95"/><path d="M9.5 12l1.8 1.8L15 10" stroke="#4f46e5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </div>
    <div class="brand-txt">
      <h1>Aegis Threat Modeling Workbench</h1>
      <p>Adversary Engagement Platform</p>
    </div>
  </div>
  <div class="topbar-sep"></div>
  <div class="engagement-chip">
    <span class="dot"></span>
    <span>Engagement: <b>NimbleTech Ops AI</b></span>
    <span class="muted">· Day <b id="eng-day">1</b>/10</span>
  </div>
  <div class="topbar-right">
    <div class="scope-chip">Engagement type: <b>Grey-box</b> · VPN + read-only K8s token provided</div>
    <div class="avatar">SA</div>
  </div>
</div>

<!-- ===== SHELL ===== -->
<div class="shell">
  <!-- SIDE NAV -->
  <nav class="sidenav">
    <div class="nav-section">Engagement</div>
    <div class="nav-item active" data-view="recon" onclick="nav('recon')">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>
      Reconnaissance
    </div>
    <div class="nav-item" data-view="assumptions" onclick="nav('assumptions')">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>
      Assumption Register
      <span class="nav-badge" id="nb-assump">0</span>
    </div>
    <div class="nav-item" data-view="crown" onclick="nav('crown')">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M3 8l4 5 5-8 5 8 4-5v11H3V8z"/></svg>
      Crown Jewels
      <span class="nav-badge" id="nb-crown">0</span>
    </div>
    <div class="nav-item" data-view="trust" onclick="nav('trust')">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/></svg>
      Trust Boundaries
    </div>
    <div class="nav-item" data-view="paths" onclick="nav('paths')">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z"/></svg>
      Escalation Paths
    </div>
    <div class="nav-section">Analysis</div>
    <div class="nav-item" data-view="decision" onclick="nav('decision')">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0H5a2 2 0 01-2-2v-4m6 6h10a2 2 0 002-2v-4"/></svg>
      Go/No-Go Matrix
    </div>
    <div class="nav-item" data-view="atlas" onclick="nav('atlas')">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M9 20l-5.5 2V6L9 4m0 16l6-2m-6 2V4m6 14l5.5 2V4L15 6m0 12V6m0 0L9 4"/></svg>
      MITRE ATLAS
    </div>
    <div class="nav-item" data-view="brief" onclick="nav('brief')">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h6"/></svg>
      Intelligence Brief
    </div>
  </nav>

  <!-- CONTENT -->
  <main class="content">

    <!-- ========== RECON ========== -->
    <section id="view-recon" class="view">
      <div class="page-head">
        <h2>Reconnaissance</h2>
        <p>Grey-box assessment of NimbleTech's AIOps platform. VPN tunnel and read-only Kubernetes API token provided. Attack host <span class="cell-mono">10.10.40.2</span> · service subnet <span class="cell-mono">10.10.50.0/24</span>. This is a fixed snapshot of the target — real engagements don't get to "turn down" the target's defenses, so every finding below reflects what's actually there.</p>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="card-head">
            <div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
            <div><h3>Rules of Engagement</h3><div class="ch-sub">Hard constraints — non-negotiable</div></div>
          </div>
          <div class="card-body"><div class="kv-list" id="roe-list"></div></div>
        </div>
        <div class="card">
          <div class="card-head">
            <div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 010 20 15 15 0 010-20z"/></svg></div>
            <div><h3>OSINT Findings</h3><div class="ch-sub">Pre-engagement public intelligence</div></div>
          </div>
          <div class="card-body"><div class="kv-list" id="osint-list"></div></div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 17l6-6-6-6M12 19h8"/></svg></div>
          <div><h3>Active Reconnaissance</h3><div class="ch-sub">Simulated discovery, enumeration, and extraction</div></div>
        </div>
        <div class="card-body">
          <div class="action-grid" id="recon-actions"></div>
          <div class="console">
            <div class="console-bar">
              <div class="dots"><span></span><span></span><span></span></div>
              <span class="ctitle">sahil@kali: ~/nimbletech-engagement</span>
              <span class="cbadge">LIVE TARGET</span>
            </div>
            <div class="console-body" id="recon-out"><span class="cdim"># Select a reconnaissance action above to begin.</span></div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8v4l3 3M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg></div>
          <div><h3>Activity Log</h3><div class="ch-sub">Blue-team-visible actions this session</div></div>
        </div>
        <div class="card-body tight"><div class="activity" id="activity-log"></div></div>
      </div>
    </section>

    <!-- ========== ASSUMPTIONS ========== -->
    <section id="view-assumptions" class="view hidden">
      <div class="page-head">
        <h2>Assumption Register</h2>
        <p>Every hypothesis is tracked with its observation, confidence, source, and validation status. Guesses are never treated as facts. As new intelligence arrives, mark entries VALIDATED or INVALIDATED — the confidence follows the evidence.</p>
      </div>
      <div class="card">
        <div class="card-head">
          <div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg></div>
          <div><h3>Add Assumption</h3></div>
          <div class="card-head-actions">
            <button class="btn btn-ghost btn-sm" onclick="seedAssumptions()">Load Starter Set</button>
            <button class="btn btn-danger btn-sm" onclick="clearAssumptions()">Clear</button>
          </div>
        </div>
        <div class="card-body">
          <div class="grid-2">
            <div class="field"><label>Observation</label><input id="a-obs" placeholder="e.g. Client doc mentions 'central orchestrator'"/></div>
            <div class="field"><label>Hypothesis</label><input id="a-hyp" placeholder="e.g. Single orchestration component routes all tasks"/></div>
          </div>
          <div class="grid-3">
            <div class="field"><label>Confidence</label><select id="a-conf"><option>HIGH</option><option selected>MEDIUM</option><option>LOW</option></select></div>
            <div class="field"><label>Source</label><input id="a-src" placeholder="e.g. LinkedIn OSINT"/></div>
            <div class="field"><label>Status</label><select id="a-stat"><option selected>UNVALIDATED</option><option>VALIDATED</option><option>INVALIDATED</option></select></div>
          </div>
          <button class="btn btn-primary" onclick="addAssumption()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>Add Assumption</button>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18M18 17V9M13 17V5M8 17v-3"/></svg></div><div><h3>Current Register</h3></div></div>
        <div class="card-body tight"><div class="tbl-wrap"><table><thead><tr><th>ID</th><th>Observation</th><th>Hypothesis</th><th>Confidence</th><th>Source</th><th>Status</th><th></th></tr></thead><tbody id="a-tbody"></tbody></table></div></div>
      </div>
    </section>

    <!-- ========== CROWN JEWELS ========== -->
    <section id="view-crown" class="view hidden">
      <div class="page-head">
        <h2>Crown Jewels</h2>
        <p>Assets ranked by offensive value. Re-rank as architectural understanding improves, and mark assets OBTAINED as the engagement progresses.</p>
      </div>
      <div class="card">
        <div class="card-head"><div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 8l4 5 5-8 5 8 4-5v11H3V8z"/></svg></div><div><h3>Ranked Assets</h3></div>
          <div class="card-head-actions"><button class="btn btn-ghost btn-sm" onclick="seedCrown()">Load Default Ranking</button><button class="btn btn-danger btn-sm" onclick="clearCrown()">Clear</button></div>
        </div>
        <div class="card-body tight"><div class="tbl-wrap"><table><thead><tr><th>Rank</th><th>Asset</th><th>Location</th><th>Offensive Value</th><th>Access Status</th><th></th></tr></thead><tbody id="c-tbody"></tbody></table></div></div>
      </div>
    </section>

    <!-- ========== TRUST ========== -->
    <section id="view-trust" class="view hidden">
      <div class="page-head">
        <h2>Trust Boundaries</h2>
        <p>Three-zone view of NimbleTech Ops AI. Traditional (policy-based) boundaries fail to authentication bypass; AI-specific (inference-based) boundaries fail to input manipulation — a distinction that shapes every escalation path.</p>
      </div>
      <div class="card">
        <div class="card-head"><div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg></div><div><h3>Trust Zone Map</h3></div></div>
        <div class="card-body">
          <div class="zones">
            <div class="zone zone-ext"><div class="zone-top"><h4>External Zone</h4><span class="badge b-info plain">Untrusted</span></div>
              <ul><li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>Alert Sources (webhooks)</li><li class="tb">↓ TB-1 · input trust</li></ul></div>
            <div class="zone zone-agent"><div class="zone-top"><h4>Agent Zone (A)</h4><span class="badge b-med plain">Semi-trusted</span></div>
              <ul><li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/></svg>Orchestrator :9000</li><li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/></svg>Triage / Remediation / Security / Knowledge Agents</li><li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7v10c0 2 4 3 8 3s8-1 8-3V7"/></svg>Qdrant :6333 (no-auth)</li><li class="tb">↓ TB-4 · per-agent tokens</li></ul></div>
            <div class="zone zone-infra"><div class="zone-top"><h4>Tool / Infra Zone (B+C)</h4><span class="badge b-low plain">Privileged</span></div>
              <ul><li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 17l6-6-6-6M12 19h8"/></svg>MCP Server :9005</li><li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/></svg>Vault :8200 (TB-5 AppRole)</li><li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10a6 6 0 00-12 0c0 4-3 5-3 5h18s-3-1-3-5z"/></svg>AWS / External APIs (TB-6)</li><li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7v10c0 2 4 3 8 3s8-1 8-3V7"/></svg>MLflow :5000</li></ul></div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M3 12h18M3 18h18"/></svg></div><div><h3>Boundaries Table</h3></div>
          <div class="card-head-actions"><button class="btn btn-ghost btn-sm" onclick="seedTB()">Load Defaults</button><button class="btn btn-danger btn-sm" onclick="clearTB()">Clear</button></div>
        </div>
        <div class="card-body tight"><div class="tbl-wrap"><table><thead><tr><th>ID</th><th>From → To</th><th>Type</th><th>Enforcement</th><th>Status</th><th>Offensive Implication</th></tr></thead><tbody id="tb-tbody"></tbody></table></div></div>
      </div>
    </section>

    <!-- ========== PATHS ========== -->
    <section id="view-paths" class="view hidden">
      <div class="page-head">
        <h2>Escalation Paths</h2>
        <p>Candidate attack chains with preconditions, detection risk, and a go/no-go gate. Update status as assumptions are validated.</p>
      </div>
      <div class="card">
        <div class="card-head"><div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z"/></svg></div><div><h3>Path Planner</h3></div>
          <div class="card-head-actions"><button class="btn btn-ghost btn-sm" onclick="seedPaths()">Load Default Paths</button></div>
        </div>
        <div class="card-body"><div id="paths-list"></div></div>
      </div>
    </section>

    <!-- ========== DECISION ========== -->
    <section id="view-decision" class="view hidden">
      <div class="page-head">
        <h2>Go/No-Go Decision Matrix</h2>
        <p>For each candidate action: information available, missing data, time-to-validate, and the resulting decision. Blocked paths never enter the active plan.</p>
      </div>
      <div class="card">
        <div class="card-head"><div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 3H5a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2V9"/><path d="M9 3v18M15 3l6 6"/></svg></div><div><h3>Decision Table</h3></div></div>
        <div class="card-body tight"><div class="tbl-wrap"><table><thead><tr><th>Decision</th><th>Information Available</th><th>Missing</th><th>Time to Validate</th><th>Decision</th></tr></thead>
          <tbody>
            <tr><td><strong>Execute Path 3 (intel extract)?</strong></td><td>Qdrant accessible, one rule known</td><td>Complete rule set</td><td>2–4 hr</td><td><span class="badge b-high">GO</span></td></tr>
            <tr><td><strong>Validate A-12b (Remediation → aws_cli_exec)?</strong></td><td>Token works for vault_rotate_secret</td><td>aws_cli_exec authorization untested</td><td>~1 hr</td><td><span class="badge b-high">GO · starts 24h clock</span></td></tr>
            <tr><td><strong>Validate A-15 (MCP parameter monitoring)?</strong></td><td>5 rules extracted, none cover params</td><td>Additional rules may exist</td><td>2–4 hr</td><td><span class="badge b-high">GO</span></td></tr>
            <tr><td><strong>Validate Path 2 step 2 (KA→staging)?</strong></td><td>Staging Qdrant at :16333</td><td>Knowledge Agent queries staging?</td><td>2–4 hr</td><td><span class="badge b-high">GO</span></td></tr>
            <tr><td><strong>Execute Path 1?</strong></td><td>Token in hand, Vault confirmed</td><td>A-12b, A-15 unvalidated</td><td>—</td><td><span class="badge b-med">HOLD</span></td></tr>
            <tr><td><strong>Execute Path 2?</strong></td><td>RoE permits staging writes</td><td>Step 2 unvalidated</td><td>—</td><td><span class="badge b-med">HOLD</span></td></tr>
          </tbody></table></div>
          <div class="help-note" style="margin:16px 20px 4px"><b>Optimal sequence:</b> Path 3 (intel) → validate A-12b (starts 24h clock) → validate A-15 → validate Path 2 precondition → execute the best path given risk/reward.</div>
        </div>
      </div>
    </section>

    <!-- ========== ATLAS ========== -->
    <section id="view-atlas" class="view hidden">
      <div class="page-head">
        <h2>MITRE ATLAS Mapping</h2>
        <p>Each component mapped to an ATLAS technique. "Applicable if" means the precondition is unvalidated — those techniques stay out of the active plan until confirmed with HIGH confidence.</p>
      </div>
      <div class="card">
        <div class="card-head"><div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 20l-5.5 2V6L9 4l6 2 5.5-2v16L15 22l-6-2z"/></svg></div><div><h3>Technique Coverage</h3></div></div>
        <div class="card-body tight"><div class="tbl-wrap"><table><thead><tr><th>Component</th><th>ATLAS Technique</th><th>ID</th><th>Application Status</th></tr></thead>
          <tbody>
            <tr><td><strong>Agent model weights (MLflow)</strong></td><td>ML Model Access</td><td class="cell-mono">AML.T0044</td><td><span class="badge b-med">Applicable if :5000 reachable</span></td></tr>
            <tr><td><strong>Vector DB (Qdrant production)</strong></td><td>Infer Training Data</td><td class="cell-mono">AML.T0025</td><td><span class="badge b-high">Immediately applicable</span></td></tr>
            <tr><td><strong>Vector DB (staging)</strong></td><td>Poison Training Data</td><td class="cell-mono">AML.T0020</td><td><span class="badge b-high">Staging only per RoE</span></td></tr>
            <tr><td><strong>MCP Server tools</strong></td><td>ML-Enabled Product Abuse</td><td class="cell-mono">AML.T0048</td><td><span class="badge b-high">Applicable w/ valid token</span></td></tr>
            <tr><td><strong>Triage Agent input</strong></td><td>Craft Adversarial Data</td><td class="cell-mono">AML.T0043</td><td><span class="badge b-med">Webhook auth unknown</span></td></tr>
            <tr><td><strong>Model registry (MLflow)</strong></td><td>ML Supply Chain Compromise</td><td class="cell-mono">AML.T0010</td><td><span class="badge b-med">If MLflow allows uploads</span></td></tr>
            <tr><td><strong>Agent endpoints</strong></td><td>Inference API Access</td><td class="cell-mono">AML.T0040</td><td><span class="badge b-high">Immediately applicable</span></td></tr>
          </tbody></table></div>
        </div>
      </div>
    </section>

    <!-- ========== BRIEF ========== -->
    <section id="view-brief" class="view hidden">
      <div class="page-head">
        <h2>Intelligence Brief</h2>
        <p>Compiled from the live assumption register, crown jewels, trust boundaries, and paths. Every generation is versioned — the history is your decision log. The brief's value is honesty, not completeness: what is known, what is assumed, what is blocked.</p>
      </div>
      <div class="card">
        <div class="card-head"><div class="ch-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg></div><div><h3>Attack Intelligence Brief</h3></div>
          <div class="card-head-actions">
            <button class="btn btn-ghost btn-sm" onclick="advanceDay()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>Advance Day</button>
            <button class="btn btn-primary btn-sm" onclick="generateBrief()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z"/></svg>Generate / Update</button>
          </div>
        </div>
        <div class="card-body">
          <div class="version-pills" id="version-pills"></div>
          <div class="brief-out" id="brief-out"><span class="cdim"># Click "Generate / Update" to compile the current intelligence picture.</span></div>
        </div>
      </div>
    </section>

  </main>
</div>

<!-- ===== NEED HELP FAB ===== -->
<div class="help-fab" onclick="openHelp()">
  <span class="pulse"></span>
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 015.8 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>
  Need help? — Solutions &amp; Walkthrough
</div>

<!-- ===== HELP PANEL ===== -->
<div class="help-overlay" id="help-overlay" onclick="closeHelp()"></div>
<aside class="help-panel" id="help-panel">
  <div class="help-phead">
    <div class="hp-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 016.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/></svg></div>
    <div><h3>Solutions &amp; Walkthrough</h3><p id="help-context">Threat Modeling Workbench · full engagement playbook</p></div>
    <button class="help-close" onclick="closeHelp()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg></button>
  </div>
  <div class="help-tabs" id="help-tabs"></div>
  <div class="help-content" id="help-content"></div>
</aside>

<script>
// ============ STATE ============
let CURRENT_VIEW = 'recon';

// ============ NAV ============
function nav(view){
  CURRENT_VIEW = view;
  document.querySelectorAll('.view').forEach(v=>v.classList.add('hidden'));
  document.getElementById('view-'+view).classList.remove('hidden');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active', n.dataset.view===view));
  renderHelpTabs();
  window.scrollTo({top:0,behavior:'smooth'});
}

// ============ RECON ACTIONS ============
const RECON_ACTIONS = [
  {id:'nmap', title:'Subnet Scan', cmd:'nmap -sV -p-', desc:'Discover live services across the target subnet.', color:'brand', icon:'<path d="M4 17l6-6-6-6M12 19h8"/>'},
  {id:'qdrant', title:'Probe Qdrant', cmd:'GET /collections', desc:'Enumerate vector collections on the RAG backend.', color:'cyan', icon:'<path d="M4 7v10c0 2 4 3 8 3s8-1 8-3V7"/><ellipse cx="12" cy="7" rx="8" ry="3"/>'},
  {id:'mcp_tools', title:'List MCP Tools', cmd:'GET /tools', desc:'Enumerate tools exposed by the MCP server.', color:'violet', icon:'<path d="M14.7 6.3a4 4 0 00-5.4 5.4L3 18v3h3l6.3-6.3a4 4 0 005.4-5.4l-2.5 2.5-2-2 2.5-2.5z"/>'},
  {id:'k8s_secrets', title:'List K8s Secrets', cmd:'kubectl get secrets', desc:'Read Kubernetes secrets in the nimble-ops namespace.', color:'amber', icon:'<circle cx="8" cy="15" r="4"/><path d="M10.85 12.15L19 4M18 5l2 2M15 8l2 2"/>'},
  {id:'qdrant_dump', title:'Dump Detection Rules', cmd:'scroll detection_rules', desc:'Exfiltrate the defender\'s detection playbook.', color:'red', icon:'<path d="M3 8l4 5 5-8 5 8 4-5v11H3V8z"/>'},
  {id:'mcp_authz', title:'Test Token Authz', cmd:'JSON-RPC tools/call', desc:'Probe which tools each agent token can invoke.', color:'green', icon:'<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>'},
];
const COLOR_MAP = {brand:['#eef2ff','#4f46e5'],cyan:['#ecfeff','#0891b2'],violet:['#f5f3ff','#7c3aed'],amber:['#fffbeb','#d97706'],red:['#fef2f2','#dc2626'],green:['#ecfdf5','#059669']};
function renderReconActions(){
  document.getElementById('recon-actions').innerHTML = RECON_ACTIONS.map(a=>{
    const [bg,fg]=COLOR_MAP[a.color];
    return `<button class="action-tile" onclick="runRecon('${a.id}')">
      <div class="at-top"><div class="at-icon" style="background:${bg};color:${fg}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${a.icon}</svg></div>
      <div><div class="at-title">${a.title}</div></div></div>
      <div class="at-desc">${a.desc}</div>
      <div class="at-cmd">${a.cmd}</div>
    </button>`;
  }).join('');
}

function fmtJSON(obj){
  let s = JSON.stringify(obj,null,2);
  s = s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  s = s.replace(/("(?:\\.|[^"\\])*")(\s*:)/g,'<span class="ckey">$1</span>$2');
  s = s.replace(/:\s*("(?:\\.|[^"\\])*")/g,': <span class="cstr">$1</span>');
  s = s.replace(/:\s*(true|false|null)/g,': <span class="cwarn">$1</span>');
  s = s.replace(/:\s*(-?\d+\.?\d*)/g,': <span class="cwarn">$1</span>');
  return s;
}

async function runRecon(action){
  const out = document.getElementById('recon-out');
  const meta = RECON_ACTIONS.find(a=>a.id===action);
  out.innerHTML = `<span class="cprompt">$</span> ${meta.cmd}  <span class="cdim">// running...</span>`;
  const r = await fetch('/api/recon/'+action,{method:'POST'});
  const d = await r.json();
  out.innerHTML = `<span class="cprompt">$</span> ${meta.cmd}\n<span class="cok">[✓ complete]</span>\n\n${fmtJSON(d)}`;
  loadActivity();
}

async function loadScope(){
  const r = await fetch('/api/scope'); const d = await r.json();
  document.getElementById('roe-list').innerHTML = d.roe.map(x=>`<div class="kv-item roe-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg><span>${x}</span></div>`).join('');
  document.getElementById('osint-list').innerHTML = d.osint.map(x=>`<div class="kv-item osint-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/></svg><span><span class="kv-src">${x.source}:</span> ${x.finding}</span></div>`).join('');
}

async function loadActivity(){
  const r = await fetch('/api/activity'); const d = await r.json();
  const el = document.getElementById('activity-log');
  if(!d.items.length){ el.innerHTML = '<div class="act-empty">No actions recorded yet this session.</div>'; return; }
  el.innerHTML = d.items.map(a=>`<div class="act-row"><span class="at">${a.ts}</span><span class="aa">${a.action}</span><span class="ar">${a.result}</span></div>`).join('');
}

// ============ ASSUMPTIONS ============
async function loadAssumptions(){
  const r = await fetch('/api/assumptions'); const d = await r.json();
  document.getElementById('nb-assump').textContent = d.items.length;
  document.getElementById('a-tbody').innerHTML = d.items.map(a=>{
    const conf = {HIGH:'b-high',MEDIUM:'b-med',LOW:'b-low'}[a.confidence]||'b-med';
    const stat = {VALIDATED:'b-high',INVALIDATED:'b-low',UNVALIDATED:'b-neutral'}[a.status]||'b-neutral';
    return `<tr><td class="cell-mono">${a.id}</td><td>${a.observation}</td><td>${a.hypothesis}</td>
      <td><span class="badge ${conf}">${a.confidence}</span></td><td>${a.source}</td>
      <td><span class="badge ${stat}">${a.status}</span></td>
      <td><div class="row-actions">
        <button class="icon-btn ok" title="Validate" onclick="updateAssumption('${a.id}','VALIDATED')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg></button>
        <button class="icon-btn bad" title="Invalidate" onclick="updateAssumption('${a.id}','INVALIDATED')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg></button>
        <button class="icon-btn" title="Delete" onclick="deleteAssumption('${a.id}')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg></button>
      </div></td></tr>`;
  }).join('') || '<tr><td colspan="7" class="act-empty">Register is empty. Load the starter set or add an assumption.</td></tr>';
}
async function addAssumption(){
  const data={observation:document.getElementById('a-obs').value,hypothesis:document.getElementById('a-hyp').value,confidence:document.getElementById('a-conf').value,source:document.getElementById('a-src').value,status:document.getElementById('a-stat').value};
  if(!data.observation||!data.hypothesis){alert('Observation and Hypothesis are required.');return;}
  await fetch('/api/assumptions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
  document.getElementById('a-obs').value='';document.getElementById('a-hyp').value='';document.getElementById('a-src').value=''; loadAssumptions();
}
async function updateAssumption(id,status){await fetch('/api/assumptions/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})});loadAssumptions();}
async function deleteAssumption(id){await fetch('/api/assumptions/'+id,{method:'DELETE'});loadAssumptions();}
async function seedAssumptions(){await fetch('/api/assumptions/seed',{method:'POST'});loadAssumptions();}
async function clearAssumptions(){await fetch('/api/assumptions/clear',{method:'POST'});loadAssumptions();}

// ============ CROWN ============
async function loadCrown(){
  const r=await fetch('/api/crown');const d=await r.json();
  document.getElementById('nb-crown').textContent=d.items.length;
  document.getElementById('c-tbody').innerHTML=d.items.map((c,i)=>{
    const stat=c.status.includes('OBTAINED')?'b-high':c.status.includes('ACCESS')?'b-info':'b-med';
    return `<tr><td><strong>#${i+1}</strong></td><td><strong>${c.asset}</strong></td><td>${c.location}</td><td>${c.value}</td>
      <td><span class="badge ${stat}">${c.status}</span></td>
      <td><div class="row-actions">
        <button class="icon-btn ok" title="Obtained" onclick="updateCrown(${i},'OBTAINED')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg></button>
        <button class="icon-btn" title="Accessible" onclick="updateCrown(${i},'ACCESSIBLE')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12a8 8 0 018-8V2l4 4-4 4V8a4 4 0 100 8"/></svg></button>
        <button class="icon-btn bad" title="Blocked" onclick="updateCrown(${i},'BEHIND BOUNDARIES')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/></svg></button>
      </div></td></tr>`;
  }).join('')||'<tr><td colspan="6" class="act-empty">No assets ranked. Load the default ranking.</td></tr>';
}
async function seedCrown(){await fetch('/api/crown/seed',{method:'POST'});loadCrown();}
async function clearCrown(){await fetch('/api/crown/clear',{method:'POST'});loadCrown();}
async function updateCrown(i,s){await fetch('/api/crown/'+i,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:s})});loadCrown();}

// ============ TB ============
async function loadTB(){
  const r=await fetch('/api/tb');const d=await r.json();
  document.getElementById('tb-tbody').innerHTML=d.items.map(b=>{
    const s=b.status==='VALIDATED'?'b-high':b.status==='INFERRED'?'b-med':'b-low';
    return `<tr><td class="cell-mono">${b.id}</td><td>${b.from_to}</td><td>${b.type}</td><td>${b.enforcement}</td><td><span class="badge ${s}">${b.status}</span></td><td>${b.implication}</td></tr>`;
  }).join('')||'<tr><td colspan="6" class="act-empty">No boundaries defined. Load defaults.</td></tr>';
}
async function seedTB(){await fetch('/api/tb/seed',{method:'POST'});loadTB();}
async function clearTB(){await fetch('/api/tb/clear',{method:'POST'});loadTB();}

// ============ PATHS ============
async function loadPaths(){
  const r=await fetch('/api/paths');const d=await r.json();
  document.getElementById('paths-list').innerHTML=d.items.map(p=>{
    const cls=p.status==='GO'?'go':p.status==='HOLD'?'hold':'nogo';
    const sb=p.status==='GO'?'b-high':p.status==='HOLD'?'b-med':'b-low';
    return `<div class="path ${cls}">
      <div class="path-top"><span class="pid">${p.id}</span><h4>${p.name}</h4><span class="badge ${sb}">${p.status}</span>
        <div class="p-actions">
          <button class="icon-btn ok" title="GO" onclick="updatePath('${p.id}','GO')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l14 9-14 9V3z"/></svg></button>
          <button class="icon-btn" title="HOLD" onclick="updatePath('${p.id}','HOLD')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg></button>
          <button class="icon-btn bad" title="NO-GO" onclick="updatePath('${p.id}','NO-GO')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M4.9 4.9l14.2 14.2"/></svg></button>
        </div></div>
      <div class="path-body">
        <div class="path-steps">${p.steps.replace(/</g,'&lt;')}</div>
        <div class="path-meta">
          <div class="pm"><div class="pk">Priority</div><div class="pv">${p.priority}</div></div>
          <div class="pm"><div class="pk">Detection Risk</div><div class="pv">${p.risk}</div></div>
          <div class="pm"><div class="pk">ATLAS</div><div class="pv">${p.atlas}</div></div>
        </div>
      </div></div>`;
  }).join('')||'<div class="act-empty">No paths loaded. Load the default paths.</div>';
}
async function seedPaths(){await fetch('/api/paths/seed',{method:'POST'});loadPaths();}
async function updatePath(id,s){await fetch('/api/paths/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:s})});loadPaths();}

// ============ BRIEF ============
async function generateBrief(){
  const day=document.getElementById('eng-day').textContent;
  const r=await fetch('/api/brief/generate?day='+day,{method:'POST'});const d=await r.json();
  renderBrief(d.brief); loadVersions();
}
function renderBrief(text){
  let h=text.replace(/&/g,'&amp;').replace(/</g,'&lt;');
  h=h.replace(/^(=== .+ ===)$/gm,'<span class="bh">$1</span>');
  h=h.replace(/^(ATTACK INTELLIGENCE BRIEF.*)$/gm,'<span class="bh">$1</span>');
  document.getElementById('brief-out').innerHTML=h;
}
async function loadVersions(){
  const r=await fetch('/api/brief/history');const d=await r.json();
  document.getElementById('version-pills').innerHTML=d.versions.map((v,i)=>`<span class="version-pill" onclick="loadVersion(${i})">v${v.version} · Day ${v.day}</span>`).join('');
}
async function loadVersion(i){const r=await fetch('/api/brief/version/'+i);const d=await r.json();renderBrief(d.brief);}
function advanceDay(){
  const el=document.getElementById('eng-day');
  el.textContent=parseInt(el.textContent)+1;
}

// ============ NEED HELP ============
const HELP = {
  recon:{label:'Reconnaissance',sections:[
    {title:'Objective',type:'note',html:'Reconstruct <b>NimbleTech Ops AI</b> from partial intel. This is a grey-box snapshot of a live target — every action below returns real findings you build the rest of the engagement on.'},
    {title:'Walkthrough',type:'steps',steps:[
      {h:'Internalise the RoE',p:'Read the Rules of Engagement first. Production DB is off-limits, vector poisoning is staging-only. Prohibited paths still belong in the final report as <b>risk findings</b> — never in the active attack plan.',why:'Scope discipline is what separates a professional engagement from an incident. Acting outside RoE burns the client relationship and can be illegal.'},
      {h:'Map the network',p:'Run <b>Subnet Scan</b>. Nine services resolve — orchestrator, four agents, MCP server, Qdrant, MLflow, and an unsealed Vault. This validates assumptions A-01 and A-02.',cmd:'nmap -sV -p-  --open -T4 10.10.50.0/24'},
      {h:'Probe the vector store',p:'Run <b>Probe Qdrant</b>. The four collections leak with no authentication at all — this validates A-07 and is itself a finding worth reporting: production RAG data is reachable with zero credentials.',cmd:'curl -s 10.10.50.20:6333/collections | jq'},
      {h:'Enumerate MCP tools',p:'Run <b>List MCP Tools</b>. Four tools appear — the fourth, <span class="cell-mono">vault_rotate_secret</span>, was not in OSINT. That surprise becomes new assumption A-10.',cmd:'curl -s 10.10.50.15:9005/tools | jq \'.tools[].name\''},
      {h:'Read the K8s secrets',p:'Run <b>List K8s Secrets</b>. Per-agent tokens are base64-encoded, not encrypted. Mark Crown Jewel "Agent identity tokens" as OBTAINED.',cmd:'kubectl get secrets -n nimble-ops -o json | jq -r \'.items[].data | to_entries[] | .value | @base64d\''},
      {h:'Exfiltrate detection rules',p:'Run <b>Dump Detection Rules</b>. This is Crown Jewel #2 — the defender\'s playbook. Note that <span class="cell-mono">nimble-qdrant-004</span> may fire on a bulk read from a non-agent IP.',cmd:'curl -s -X POST 10.10.50.20:6333/collections/detection_rules/points/scroll -H "Content-Type: application/json" -d \'{"limit":100,"with_payload":true}\' | jq',why:'You now know exactly what the blue team watches for. Every later step can be planned to stay under those thresholds.'},
      {h:'Test token authorization',p:'Run <b>Test Token Authz</b>. The triage token is rejected for <span class="cell-mono">vault_rotate_secret</span>; the remediation token succeeds — confirming A-10 and revealing that identity scoping is inconsistent across agents.',cmd:'curl -s -X POST 10.10.50.15:9005/rpc -H "Content-Type: application/json" -d \'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vault_rotate_secret","token":"remediation-agent-token"},"id":1}\''},
    ]},
  ]},
  assumptions:{label:'Assumption Register',sections:[
    {title:'Why it matters',type:'note',html:'The single most common failure in real threat modeling is treating a <b>guess as a fact</b>. Absence of evidence is not confirmation of a vulnerability. This register forces every claim to carry its confidence and source.'},
    {title:'Walkthrough',type:'steps',steps:[
      {h:'Load the starter set',p:'Click <b>Load Starter Set</b> to populate A-01 through A-08 — the hypotheses derived from client docs and OSINT before any active scanning.'},
      {h:'Validate against recon',p:'After each recon action, return here and mark the relevant assumption VALIDATED (its confidence auto-promotes to HIGH) or INVALIDATED.',why:'Confidence must follow evidence, not intuition. A HIGH-confidence-but-unvalidated assumption is a landmine.'},
      {h:'Add emergent assumptions',p:'Active recon surfaces new observations. Add A-10 (vault_rotate_secret exists), A-12b (remediation token scope), and A-15 (whether MCP parameters are monitored).'},
      {h:'Drive validation, not attacks',p:'LOW-confidence assumptions justify <b>early verification tasks</b>, never direct execution. An unvalidated assumption means unknown detection risk.'},
    ]},
  ]},
  crown:{label:'Crown Jewels',sections:[
    {title:'Concept',type:'note',html:'Rank assets by <b>offensive value</b>, not by how hard they are to reach. Re-rank continuously — once you hold the detection rules and agent tokens, the priority shifts from "gaining access" to "extracting and analysing".'},
    {title:'Walkthrough',type:'steps',steps:[
      {h:'Load default ranking',p:'Click <b>Load Default Ranking</b>. Six assets appear, from AWS credentials down to MCP tool schemas.'},
      {h:'Update status from recon',p:'As the recon tab yields data, mark assets OBTAINED. By Day 2 the detection rules and agent tokens should already be in hand.'},
      {h:'Re-prioritise',p:'AWS credentials sit behind three boundaries — don\'t burn time forcing them directly. The obtained detection rules give you the map to reach them quietly.',why:'A crown-jewel list that never changes means you stopped learning. Real engagements re-rank daily.'},
    ]},
  ]},
  trust:{label:'Trust Boundaries',sections:[
    {title:'Key distinction',type:'note',html:'<b>Traditional</b> boundaries (mTLS, AppRole) fail to authentication bypass. <b>AI-specific</b> boundaries (a Triage Agent\'s classification, a Knowledge Agent\'s advisory) fail to <b>input manipulation</b> — no credential needed.'},
    {title:'Walkthrough',type:'steps',steps:[
      {h:'Load default boundaries',p:'Click <b>Load Defaults</b> for TB-1 through TB-8.'},
      {h:'Find the never-enforced gaps',p:'TB-3 (Agents → Qdrant) has <b>no auth</b>. TB-8 (Knowledge Agent → other agents) has <b>no verification</b>. These "trust never enforced" gaps are where the dangerous escalation flows.',why:'An inference boundary can\'t be patched with a firewall rule. Recognising which boundaries are AI-specific tells you which attacks are even possible.'},
      {h:'Trace the collapse',p:'Notice how agent identity collapses at TB-5 (MCP → Vault). Once the MCP server authenticates via AppRole, the original agent identity is gone — any agent that reaches the tool inherits full credential access.'},
    ]},
  ]},
  paths:{label:'Escalation Paths',sections:[
    {title:'Concept',type:'note',html:'Each path is a chain of boundary crossings. A path only becomes <b>GO</b> when its preconditions are HIGH-confidence. Until then it stays <b>HOLD</b> — planned but not executed.'},
    {title:'Walkthrough',type:'steps',steps:[
      {h:'Load default paths',p:'Click <b>Load Default Paths</b> for the three primary chains.'},
      {h:'Path 3 first — always',p:'Intelligence extraction is GO immediately and enables everything else. Dump the detection rules and runbook corpus before committing to any noisy action.'},
      {h:'Path 1 — direct MCP abuse',p:'Remediation token → aws_cli_exec → Vault → AWS creds. Stays HOLD until A-12b and A-15 are validated, because executing it starts the 24-hour blue-team report clock.',cmd:'# validate A-12b before committing\ncurl -s -X POST 10.10.50.15:9005/rpc -d \'{"method":"tools/call","params":{"name":"aws_cli_exec","token":"remediation-agent-token","args":["sts","get-caller-identity"]}}\''},
      {h:'Path 2 — indirect poisoning',p:'Poison staging Qdrant → Knowledge Agent retrieves it → Remediation Agent acts on the poisoned context. Stealthier, because agent-generated parameters evade parameter monitoring. Only viable if A-15 shows params are unmonitored.',why:'The indirect path exploits the AI-specific TB-8 boundary. It leaves almost no signature because the malicious call looks agent-native.'},
      {h:'Replan on failure',p:'If Path 2 step 2 fails (KA doesn\'t query staging), form A-16: the KA\'s Qdrant endpoint is configurable, opening a new path via ConfigMap modification.'},
    ]},
  ]},
  decision:{label:'Go/No-Go Matrix',sections:[
    {title:'Discipline',type:'note',html:'A 10-day window and a 24-hour MCP-report requirement mean sequencing is everything. Never execute a blocked path — unvalidated assumptions equal unknown detection risk equals engagement failure.'},
    {title:'Optimal sequence',type:'steps',steps:[
      {h:'1 · Path 3 (intel)',p:'Extract the detection playbook. Cheap, high-value, enables everything.'},
      {h:'2 · Validate A-12b',p:'Confirm the remediation token can call aws_cli_exec. This starts the 24-hour clock, so do it deliberately.'},
      {h:'3 · Validate A-15',p:'Determine whether MCP parameters are monitored — this decides between Path 1 (direct) and Path 2 (indirect).'},
      {h:'4 · Validate Path 2 precondition',p:'Check whether the Knowledge Agent queries staging Qdrant.'},
      {h:'5 · Execute the best path',p:'Choose based on the actual risk/reward now that every precondition is known.'},
    ]},
  ]},
  atlas:{label:'MITRE ATLAS',sections:[
    {title:'How to read it',type:'note',html:'Only <b>Immediately applicable</b> techniques enter the active plan. "Applicable if" means the precondition is unvalidated — keep it out until confirmed with HIGH confidence.'},
    {title:'Walkthrough',type:'steps',steps:[
      {h:'Anchor to evidence',p:'AML.T0025 (Infer Training Data) and AML.T0040 (Inference API Access) are immediately applicable because Qdrant and the agent endpoints are confirmed reachable.'},
      {h:'Gate the conditionals',p:'AML.T0044 (model access via MLflow) waits on :5000 reachability; AML.T0010 (supply-chain) waits on MLflow accepting uploads. Validate before you plan around them.'},
      {h:'Re-check as intel arrives',p:'Every new recon finding can promote a conditional technique to immediately-applicable, or rule it out. Revisit this table each time the Assumption Register changes.'},
    ]},
  ]},
  brief:{label:'Intelligence Brief',sections:[
    {title:'The point of the brief',type:'note',html:'Its value is <b>honesty, not completeness</b>. Clearly separate what is <b>known</b>, what is <b>assumed</b>, and what is <b>blocked</b>. No ambiguity.'},
    {title:'Walkthrough',type:'steps',steps:[
      {h:'Generate',p:'Click <b>Generate / Update</b>. The brief compiles live from the register, crown jewels, boundaries, and paths.'},
      {h:'Use version history as a log',p:'Each generation is saved as v1.1, v1.2… The version pills are your decision log — you can reconstruct exactly what you knew on any given day.'},
      {h:'Simulate multi-day evolution',p:'Click <b>Advance Day</b>, validate a few more assumptions, then regenerate. Watch how the confidence counts and next-actions shift across the engagement.'},
    ]},
  ]},
};
function renderHelpTabs(){
  const keys=Object.keys(HELP);
  document.getElementById('help-tabs').innerHTML=keys.map(k=>`<div class="help-tab ${k===CURRENT_VIEW?'active':''}" onclick="renderHelpContent('${k}')">${HELP[k].label}</div>`).join('');
  renderHelpContent(CURRENT_VIEW in HELP ? CURRENT_VIEW : 'recon');
}
function renderHelpContent(key){
  document.querySelectorAll('.help-tab').forEach(t=>t.classList.toggle('active', t.textContent===HELP[key].label));
  document.getElementById('help-context').textContent = HELP[key].label + ' · walkthrough, why-it-matters & commands';
  let html='';
  HELP[key].sections.forEach(sec=>{
    html+=`<div class="help-section-title">${sec.title}</div>`;
    if(sec.type==='note'){ html+=`<div class="help-note">${sec.html}</div>`; }
    if(sec.type==='steps'){
      sec.steps.forEach((s,i)=>{
        html+=`<div class="help-step"><span class="hs-num">${i+1}</span><h4>${s.h}</h4><p>${s.p}</p>`;
        if(s.cmd){ html+=`<div class="help-cmd">${s.cmd.replace(/</g,'&lt;')}<button class="copy" onclick="copyCmd(this)" data-cmd="${encodeURIComponent(s.cmd)}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button></div>`; }
        if(s.why){ html+=`<div class="why"><b>Why:</b> ${s.why}</div>`; }
        html+=`</div>`;
      });
    }
  });
  document.getElementById('help-content').innerHTML=html;
}
function copyCmd(btn){
  navigator.clipboard.writeText(decodeURIComponent(btn.dataset.cmd));
  btn.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>';
  setTimeout(()=>{btn.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';},1400);
}
function openHelp(){document.getElementById('help-overlay').classList.add('open');document.getElementById('help-panel').classList.add('open');renderHelpTabs();}
function closeHelp(){document.getElementById('help-overlay').classList.remove('open');document.getElementById('help-panel').classList.remove('open');}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeHelp();});

// ============ INIT ============
renderReconActions();
loadScope(); loadActivity();
loadAssumptions(); loadCrown(); loadTB(); loadPaths(); loadVersions();
</script>
</body>
</html>
"""

# ============ ROUTES ============
@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/scope")
def scope():
    return jsonify({"roe": SIMULATED_TARGET["roe"], "osint": SIMULATED_TARGET["osint"]})

@app.route("/api/activity")
def activity():
    return jsonify({"items": STATE["activity_log"]})

# ---- RECON (always live — no mode gating) ----
@app.route("/api/recon/<action>", methods=["POST"])
def recon(action):
    if action == "nmap":
        data = {
            "command": "nmap -sV -p- --open -T4 10.10.50.0/24",
            "discovered": [f"{s['ip']}:{s['port']}  {s['name']} {s['version']}" for s in SIMULATED_TARGET["services"]]
        }
        log_activity("Subnet scan", "9 services discovered")
        return jsonify({"ok": True, "data": data})

    if action == "qdrant":
        data = {
            "endpoint": "10.10.50.20:6333/collections",
            "collections": SIMULATED_TARGET["qdrant_collections"],
            "note": "Unauthenticated read — validates A-07",
        }
        log_activity("Qdrant probe", "collections leaked, no auth required")
        return jsonify({"ok": True, "data": data})

    if action == "mcp_tools":
        data = {
            "endpoint": "10.10.50.15:9005/tools",
            "tools": SIMULATED_TARGET["mcp_tools"],
            "note": "4th tool 'vault_rotate_secret' is unexpected — generates A-10",
        }
        log_activity("MCP tool enum", "4 tools listed")
        return jsonify({"ok": True, "data": data})

    if action == "k8s_secrets":
        data = {
            "command": "kubectl get secrets -n nimble-ops",
            "secrets": SIMULATED_TARGET["k8s_secrets"],
            "note": "Base64 encoded, not encrypted. Crown jewel #4 OBTAINED.",
        }
        log_activity("K8s secret read", "5 tokens read")
        return jsonify({"ok": True, "data": data})

    if action == "qdrant_dump":
        data = {
            "collection": "detection_rules",
            "rules": SIMULATED_TARGET["detection_rules"],
            "note": "Crown jewel #2 — defender's playbook. Rule nimble-qdrant-004 may have fired.",
        }
        log_activity("Detection rules dump", "5 rules exfiltrated")
        return jsonify({"ok": True, "data": data})

    if action == "mcp_authz":
        data = {
            "test_1": {
                "token": "triage-agent-token",
                "tool": "vault_rotate_secret",
                "result": "error: Agent 'triage' not authorized for tool vault_rotate_secret",
            },
            "test_2": {
                "token": "remediation-agent-token",
                "tool": "vault_rotate_secret",
                "result": "success: Secret rotated, new_version: 4",
                "note": "A-10 VALIDATED — Remediation token has Vault write access",
            },
        }
        log_activity("Token authz test", "remediation token has privileged Vault access")
        return jsonify({"ok": True, "data": data})

    return jsonify({"ok": False, "error": "unknown action"}), 404

# ---- ASSUMPTIONS ----
@app.route("/api/assumptions")
def get_assumptions():
    return jsonify({"items": STATE["assumptions"]})

@app.route("/api/assumptions", methods=["POST"])
def add_assumption():
    d = request.json
    next_id = "A-" + str(len(STATE["assumptions"]) + 1).zfill(2)
    STATE["assumptions"].append({
        "id": next_id,
        "observation": d.get("observation", ""),
        "hypothesis": d.get("hypothesis", ""),
        "confidence": d.get("confidence", "MEDIUM"),
        "source": d.get("source", ""),
        "status": d.get("status", "UNVALIDATED"),
    })
    return jsonify({"ok": True})

@app.route("/api/assumptions/<aid>", methods=["PATCH"])
def patch_assumption(aid):
    d = request.json
    for a in STATE["assumptions"]:
        if a["id"] == aid:
            if "status" in d:
                a["status"] = d["status"]
                if d["status"] == "VALIDATED":
                    a["confidence"] = "HIGH"
                elif d["status"] == "INVALIDATED":
                    a["confidence"] = "LOW"
            return jsonify({"ok": True})
    return jsonify({"ok": False}), 404

@app.route("/api/assumptions/<aid>", methods=["DELETE"])
def del_assumption(aid):
    STATE["assumptions"] = [a for a in STATE["assumptions"] if a["id"] != aid]
    return jsonify({"ok": True})

@app.route("/api/assumptions/seed", methods=["POST"])
def seed_assumptions():
    STATE["assumptions"] = [
        {"id":"A-01","observation":"Client doc: 'central orchestrator'","hypothesis":"Single orchestration component routes all tasks","confidence":"HIGH","source":"Client doc","status":"UNVALIDATED"},
        {"id":"A-02","observation":"Client doc: 'specialized agents' for triage, remediation, security","hypothesis":"At least 3 distinct agent services","confidence":"HIGH","source":"Client doc","status":"UNVALIDATED"},
        {"id":"A-03","observation":"Job posting: MLflow, Qdrant","hypothesis":"Platform uses MLflow + Qdrant","confidence":"MEDIUM","source":"LinkedIn OSINT","status":"UNVALIDATED"},
        {"id":"A-04","observation":"DevOps profile: HashiCorp Vault","hypothesis":"Credential management via Vault","confidence":"MEDIUM","source":"LinkedIn OSINT","status":"UNVALIDATED"},
        {"id":"A-05","observation":"GitHub fork: aws_cli_exec, snow_create_ticket, datadog_query","hypothesis":"MCP Server exposes at least these three tools","confidence":"HIGH","source":"GitHub fork","status":"UNVALIDATED"},
        {"id":"A-06","observation":"Client doc: 'shared knowledge base'","hypothesis":"RAG pipeline exists, likely backed by Qdrant","confidence":"MEDIUM","source":"Client doc + A-03","status":"UNVALIDATED"},
        {"id":"A-07","observation":"No mention of vector DB auth","hypothesis":"Qdrant may be unauthenticated","confidence":"LOW","source":"Absence of evidence","status":"UNVALIDATED"},
        {"id":"A-08","observation":"MCP has aws_cli_exec + Vault","hypothesis":"MCP Server has AWS credentials via Vault","confidence":"MEDIUM","source":"A-05 + A-04","status":"UNVALIDATED"},
    ]
    return jsonify({"ok": True})

@app.route("/api/assumptions/clear", methods=["POST"])
def clear_assumptions():
    STATE["assumptions"] = []
    return jsonify({"ok": True})

# ---- CROWN JEWELS ----
@app.route("/api/crown")
def get_crown():
    return jsonify({"items": STATE["crown_jewels"]})

@app.route("/api/crown/seed", methods=["POST"])
def seed_crown():
    STATE["crown_jewels"] = [
        {"asset":"AWS credentials","location":"Vault → MCP Server","value":"Direct infrastructure control. Remediation Agent can rotate (write, not just read)","status":"BEHIND 3 BOUNDARIES"},
        {"asset":"Detection rules","location":"Qdrant :6333","value":"Defender's playbook — what is monitored, what evasion looks like","status":"OBTAINED - Day 2"},
        {"asset":"Runbook corpus","location":"Qdrant :6333","value":"Operational procedures, topology, known vulnerabilities","status":"ACCESSIBLE"},
        {"asset":"Agent identity tokens","location":"K8s secrets","value":"Per-agent tokens control MCP tool access. Remediation token = Vault write","status":"OBTAINED - Day 2"},
        {"asset":"Model weights","location":"MLflow :5000","value":"Fine-tuned on proprietary ops data","status":"ACCESS UNVALIDATED"},
        {"asset":"MCP tool schemas","location":"MCP Server :9005","value":"Complete map of agent capabilities","status":"OBTAINED - Day 1"},
    ]
    return jsonify({"ok": True})

@app.route("/api/crown/<int:idx>", methods=["PATCH"])
def patch_crown(idx):
    if 0 <= idx < len(STATE["crown_jewels"]):
        STATE["crown_jewels"][idx]["status"] = request.json.get("status", "")
        return jsonify({"ok": True})
    return jsonify({"ok": False}), 404

@app.route("/api/crown/clear", methods=["POST"])
def clear_crown_route():
    STATE["crown_jewels"] = []
    return jsonify({"ok": True})

# ---- TRUST BOUNDARIES ----
@app.route("/api/tb")
def get_tb():
    return jsonify({"items": STATE["trust_boundaries"]})

@app.route("/api/tb/seed", methods=["POST"])
def seed_tb():
    STATE["trust_boundaries"] = [
        {"id":"TB-1","from_to":"Alert Sources → Orchestrator","type":"Input trust","enforcement":"Webhook auth — unknown","status":"UNVALIDATED","implication":"If unauthenticated, untrusted input directly enters pipeline"},
        {"id":"TB-2","from_to":"Orchestrator → Agents","type":"Delegation trust","enforcement":"Internal mTLS","status":"VALIDATED","implication":"Agents execute whatever Orchestrator dispatches"},
        {"id":"TB-3","from_to":"Agents → Vector DB","type":"Data integrity trust","enforcement":"None — unauthenticated","status":"VALIDATED","implication":"Any agent treats Qdrant content as ground truth"},
        {"id":"TB-4","from_to":"Agents → MCP Server","type":"Tool invocation trust","enforcement":"Per-agent identity tokens","status":"VALIDATED","implication":"Token scoping limits tools, but parameters unvalidated"},
        {"id":"TB-5","from_to":"MCP Server → Vault","type":"Credential trust","enforcement":"AppRole auth","status":"INFERRED","implication":"Agent identity collapses at this boundary"},
        {"id":"TB-6","from_to":"MCP Server → External APIs","type":"Infrastructure trust","enforcement":"API keys from Vault","status":"INFERRED","implication":"Once credentials retrieved, no additional auth gate"},
        {"id":"TB-7","from_to":"Triage Agent → Orchestrator","type":"Classification trust","enforcement":"None — inference-based","status":"UNVALIDATED","implication":"Manipulated classification drives downstream workflow"},
        {"id":"TB-8","from_to":"Knowledge Agent → Other Agents","type":"Advisory trust","enforcement":"None","status":"INFERRED","implication":"Agents incorporate RAG responses without verification"},
    ]
    return jsonify({"ok": True})

@app.route("/api/tb/clear", methods=["POST"])
def clear_tb_route():
    STATE["trust_boundaries"] = []
    return jsonify({"ok": True})

# ---- PATHS ----
@app.route("/api/paths")
def get_paths():
    return jsonify({"items": STATE["paths"]})

@app.route("/api/paths/seed", methods=["POST"])
def seed_paths():
    STATE["paths"] = [
        {"id":"PATH-01","name":"Remediation Token → Direct MCP Abuse",
         "steps":"K8s Secret → Remediation Agent Token (obtained)\n  ↓ TB-4 MCP Server tool invocation (A-12b must hold)\nMCP executes aws_cli_exec\n  ↓ TB-5 Vault provides AWS creds (AppRole)\n  ↓ TB-6 Credentials returned via MCP response",
         "priority":"PRIMARY","risk":"LOW (if A-15 holds, business hours)","atlas":"AML.T0048 + T1078.004","status":"HOLD"},
        {"id":"PATH-02","name":"Staging Vector Poisoning → Indirect Remediation",
         "steps":"Inject poisoned runbook into staging Qdrant :16333 (RoE permitted)\n  ↓ Critical gate: KA queries staging?\nKnowledge Agent retrieves poisoned content\n  ↓ TB-8 advisory trust, no verification\nRemediation Agent receives poisoned context\n  ↓ Generates MCP tool call with malicious parameters\n  ↓ TB-4 parameters look legitimate (agent-generated)\nMCP executes → AWS credentials",
         "priority":"PRIMARY (if Path 2 step 2 validates AND A-15 fails)","risk":"LOW (agent-generated params bypass monitoring)","atlas":"AML.T0020 (staging only)","status":"HOLD"},
        {"id":"PATH-03","name":"Intelligence Extraction (Support)",
         "steps":"Attack host (10.10.40.2) → Unauthenticated Qdrant :6333\n  ↓ Detection risk: nimble-qdrant-004 may fire on non-agent IP\nExtract detection_rules, runbook_corpus, incident_history\n  ↓ Informs go/no-go for Paths 1 & 2",
         "priority":"SUPPORT (enables all paths) — EXECUTE FIRST","risk":"MEDIUM (nimble-qdrant-004 may fire — accepted)","atlas":"AML.T0025","status":"GO"},
    ]
    return jsonify({"ok": True})

@app.route("/api/paths/<pid>", methods=["PATCH"])
def patch_path(pid):
    for p in STATE["paths"]:
        if p["id"] == pid:
            p["status"] = request.json.get("status", p["status"])
            return jsonify({"ok": True})
    return jsonify({"ok": False}), 404

# ---- BRIEF ----
def compile_brief(day):
    a = STATE["assumptions"]
    v = sum(1 for x in a if x["status"] == "VALIDATED")
    u = sum(1 for x in a if x["status"] == "UNVALIDATED")
    inv = sum(1 for x in a if x["status"] == "INVALIDATED")
    cj = STATE["crown_jewels"]
    paths = STATE["paths"]
    critical_unval = [x for x in a if x["status"] == "UNVALIDATED" and x["confidence"] in ("HIGH", "MEDIUM")]

    out = []
    out.append("ATTACK INTELLIGENCE BRIEF — NIMBLETECH OPS AI")
    out.append("Classification: Client Confidential")
    out.append(f"Engagement Day: {day} of 10")
    out.append(f"Brief Version: {STATE['brief_version']}")
    out.append("")
    out.append("=== TARGET SUMMARY ===")
    out.append("Platform:    NimbleTech Ops AI (AIOps)")
    out.append("Environment: Kubernetes hybrid (on-prem + AWS)")
    out.append(f"Components:  {len(SIMULATED_TARGET['services'])} confirmed services")
    out.append("")
    out.append("=== CROWN JEWELS ===")
    if cj:
        for n, c in enumerate(cj, 1):
            out.append(f"#{n}  {c['asset']:<25} {c['location']:<30} [{c['status']}]")
    else:
        out.append("(none ranked yet)")
    out.append("")
    out.append("=== ASSUMPTION STATUS ===")
    out.append(f"Total: {len(a)} | VALIDATED: {v} | UNVALIDATED: {u} | INVALIDATED: {inv}")
    if critical_unval:
        out.append("")
        out.append("Critical unvalidated:")
        for x in critical_unval[:5]:
            out.append(f"  {x['id']}: {x['hypothesis']}")
    out.append("")
    out.append("=== RoE CONSTRAINTS ===")
    for r in SIMULATED_TARGET["roe"]:
        out.append(f"  - {r}")
    out.append("")
    out.append("=== ESCALATION PATHS ===")
    if paths:
        for p in paths:
            out.append(f"{p['id']}: {p['name']}")
            out.append(f"  Status: {p['status']} | Priority: {p['priority']}")
            out.append(f"  Detection Risk: {p['risk']}")
            out.append(f"  ATLAS: {p['atlas']}")
            out.append("")
    else:
        out.append("(no paths loaded yet)")
        out.append("")
    out.append("=== NEXT ACTIONS ===")
    out.append("1. Complete intelligence extraction (Path 3)")
    out.append("2. Validate critical assumptions blocking Path 1 & 2")
    out.append("3. Choose execution path based on validation results")
    out.append("4. Update brief to next version")
    return "\n".join(out)

@app.route("/api/brief/generate", methods=["POST"])
def gen_brief():
    day = request.args.get("day", "1")
    parts = STATE["brief_version"].split(".")
    STATE["brief_version"] = f"{parts[0]}.{int(parts[1]) + 1}"
    text = compile_brief(day)
    STATE["brief_history"].append({
        "version": STATE["brief_version"], "day": day, "text": text,
        "ts": datetime.utcnow().isoformat(),
    })
    return jsonify({"brief": text, "version": STATE["brief_version"]})

@app.route("/api/brief/history")
def brief_history():
    return jsonify({"versions": [{"version": h["version"], "day": h["day"]} for h in STATE["brief_history"]]})

@app.route("/api/brief/version/<int:idx>")
def brief_version(idx):
    if 0 <= idx < len(STATE["brief_history"]):
        return jsonify({"brief": STATE["brief_history"][idx]["text"]})
    return jsonify({"brief": "// not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5034)
