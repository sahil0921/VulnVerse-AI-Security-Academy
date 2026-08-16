from flask import Flask, request, jsonify, render_template
import os, json, time, ipaddress, urllib.parse
from datetime import datetime, timezone

app = Flask(__name__)

LAMBDA_ENV = {
    "AWS_ACCESS_KEY_ID": "ASIAXYKJVV3XAMCKCAIG",
    "AWS_SECRET_ACCESS_KEY": "Bl1FnI+DGg89kMBh4UF1XmdmZfO3DqkPzdZ989fH",
    "AWS_SESSION_TOKEN": "IQoJb3JpZ2luX2VjEDkaCXVzLWVhc3Qt1ABCDEFGHIJKLMNOPQRSTUVWXYZ123",
    "AWS_REGION": "us-east-1",
    "AWS_LAMBDA_FUNCTION_NAME": "pea-portal-report-export",
    "AWS_LAMBDA_FUNCTION_VERSION": "$LATEST",
    "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": "512",
    "AWS_EXECUTION_ENV": "AWS_Lambda_python3.11",
    "BACKEND_ROLE_ARN": "arn:aws:iam::533267328750:role/DataScientistRole",
    "SAGEMAKER_ENDPOINT": "nimbletech-pea-endpoint",
    "DYNAMODB_TABLE": "nimbletech-pea-feedback",
    "REPORT_TEMPLATE_URL": "https://nimbletech-pea-sagemaker-32953eae.s3.amazonaws.com/templates/report.html",
    "S3_BUCKET": "nimbletech-pea-portal-32953eae",
    "_HANDLER": "handler.export_report",
    "LAMBDA_TASK_ROOT": "/var/task",
    "LAMBDA_RUNTIME_DIR": "/var/runtime",
    "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/bin",
    "LANG": "C.UTF-8",
    "TZ": ":UTC",
}

SIMULATED_METADATA = {
    "Code": "Success",
    "LastUpdated": "2026-07-21T04:12:33Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAXYKJVV3XAMCKCAIG",
    "SecretAccessKey": "Bl1FnI+DGg89kMBh4UF1XmdmZfO3DqkPzdZ989fH",
    "Token": "IQoJb3JpZ2luX2VjEDkaCXVzLWVhc3Qt1ABCDEFGHIJKLMNOPQRSTUVWXYZ123",
    "Expiration": "2026-12-31T23:59:59Z",
}

IAM_INFO = {
    "Code": "Success",
    "LastUpdated": "2026-07-21T04:12:33Z",
    "InstanceProfileArn": "arn:aws:iam::533267328750:instance-profile/pea-portal-profile",
    "InstanceProfileId": "AIPAXYKJVV3XZQ9EXAMPLE",
}

FEEDBACK_DATA = [
    {
        "id": "FB-8847",
        "patient": "Sarah Mitchell",
        "department": "Cardiology",
        "date": "2026-07-21",
        "rating": 4.8,
        "sentiment": "positive",
        "text": "The doctors and nurses were incredibly attentive during my stay. Everything was explained clearly to me.",
        "ai_tags": ["thorough-care", "clear-communication", "attentive-staff"],
        "ai_summary": "Patient reports excellent communication and highly attentive staff during their stay."
    },
    {
        "id": "FB-8846",
        "patient": "James Rodriguez",
        "department": "Emergency",
        "date": "2026-07-21",
        "rating": 2.1,
        "sentiment": "negative",
        "text": "Waiting time was absolutely unacceptable. I was in the waiting room for over 4 hours before seeing a doctor.",
        "ai_tags": ["long-wait", "poor-experience", "emergency-delay"],
        "ai_summary": "Patient experienced significant dissatisfaction due to excessive wait times in the ER."
    },
    {
        "id": "FB-8845",
        "patient": "Emily Chen",
        "department": "Pediatrics",
        "date": "2026-07-20",
        "rating": 5.0,
        "sentiment": "positive",
        "text": "Dr. Smith was fantastic with our daughter. He really put her at ease and explained the treatment well.",
        "ai_tags": ["great-with-kids", "excellent-doctor", "reassuring"],
        "ai_summary": "Highly positive feedback regarding physician's bedside manner with a pediatric patient."
    },
    {
        "id": "FB-8844",
        "patient": "Michael Brown",
        "department": "Orthopedics",
        "date": "2026-07-20",
        "rating": 3.0,
        "sentiment": "neutral",
        "text": "The surgery went well, but the food during recovery could have been better. Staff was polite.",
        "ai_tags": ["average-experience", "poor-food", "polite-staff"],
        "ai_summary": "Patient had a successful procedure but noted room for improvement in hospital amenities."
    },
    {
        "id": "FB-8843",
        "patient": "Lisa Taylor",
        "department": "Oncology",
        "date": "2026-07-19",
        "rating": 4.5,
        "sentiment": "positive",
        "text": "The oncology team showed incredible empathy. They provided me with all the resources I needed.",
        "ai_tags": ["empathetic-care", "resourceful", "supportive-team"],
        "ai_summary": "Patient commended the oncology department for their empathy and comprehensive support."
    },
    {
        "id": "FB-8842",
        "patient": "David Wilson",
        "department": "Cardiology",
        "date": "2026-07-19",
        "rating": 1.5,
        "sentiment": "negative",
        "text": "My appointment was cancelled at the last minute and rescheduling has been a nightmare. Very disorganized.",
        "ai_tags": ["scheduling-issue", "poor-organization", "frustrated"],
        "ai_summary": "Patient expressed severe frustration over cancelled appointments and poor scheduling processes."
    },
    {
        "id": "FB-8841",
        "patient": "Robert Davis",
        "department": "Emergency",
        "date": "2026-07-18",
        "rating": 3.5,
        "sentiment": "neutral",
        "text": "Got treated eventually. It was crowded, but the medical care itself was competent.",
        "ai_tags": ["crowded", "competent-care", "acceptable-experience"],
        "ai_summary": "Patient received adequate medical care despite experiencing a crowded environment."
    },
    {
        "id": "FB-8840",
        "patient": "Amanda White",
        "department": "Orthopedics",
        "date": "2026-07-18",
        "rating": 4.9,
        "sentiment": "positive",
        "text": "Physical therapy post-surgery has been outstanding. They really care about my recovery progress.",
        "ai_tags": ["excellent-therapy", "caring-staff", "effective-treatment"],
        "ai_summary": "Patient is highly satisfied with the quality of post-operative physical therapy."
    }
]

METRICS = {
    "total_feedback": 12847,
    "avg_satisfaction": 4.2,
    "ai_confidence": 94.7,
    "response_rate": 87.3,
    "satisfaction_change": 3.2,
    "feedback_change": 12.4,
    "confidence_change": 1.8,
    "response_change": -2.1,
    "trend_labels": ["Aug","Sep","Oct","Nov","Dec","Jan","Feb","Mar","Apr","May","Jun","Jul"],
    "trend_data": [3.8, 3.9, 4.0, 4.1, 4.0, 4.2, 4.3, 4.1, 4.2, 4.4, 4.3, 4.5],
    "dept_labels": ["Cardiology","Emergency","Oncology","Pediatrics","Orthopedics"],
    "dept_data": [3240, 2810, 2450, 2180, 2167],
    "dept_colors": ["#6366f1","#ec4899","#f59e0b","#10b981","#06b6d4"],
    "recent_activity": [
        {"type": "feedback", "icon": "💬", "text": "New feedback from Sarah M. — Cardiology (★4.8)", "time": "2 min ago"},
        {"type": "report", "icon": "📄", "text": "Report exported by M. Chen — Quarterly NPS", "time": "1 hr ago"},
        {"type": "alert", "icon": "⚡", "text": "AI model confidence spike: 94.7% → 96.1%", "time": "3 hr ago"},
        {"type": "feedback", "icon": "💬", "text": "New feedback from James R. — Emergency (★2.1)", "time": "4 hr ago"},
        {"type": "system", "icon": "🔧", "text": "Template store sync completed — 14 templates", "time": "6 hr ago"},
    ]
}

MODE = {"current": "vulnerable"}
IMDSV2_TOKENS = {}
AUDIT_LOG = []
EXPORT_HISTORY = [
    {"id": "EXP-4417", "template": "https://templates.nimbletech.local/quarterly.html", "type": "Quarterly Patient Review", "status": "completed", "ts": "2026-07-21 09:41", "by": "sjohnson@nimbletech.com"},
    {"id": "EXP-4416", "template": "https://templates.nimbletech.local/patient-nps.html", "type": "NPS Analysis", "status": "completed", "ts": "2026-07-21 08:55", "by": "m.chen@nimbletech.com"},
    {"id": "EXP-4415", "template": "https://nimbletech-public.s3.amazonaws.com/tpl/summary.html", "type": "Custom Template", "status": "completed", "ts": "2026-07-20 18:22", "by": "a.rivera@nimbletech.com"},
    {"id": "EXP-4414", "template": "https://templates.nimbletech.local/satisfaction-trend.html", "type": "Satisfaction Trend", "status": "completed", "ts": "2026-07-20 14:05", "by": "sjohnson@nimbletech.com"},
    {"id": "EXP-4413", "template": "https://templates.nimbletech.local/dept-comparison.html", "type": "Department Comparison", "status": "completed", "ts": "2026-07-19 11:30", "by": "l.martinez@nimbletech.com"},
]

def now_str():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

def audit(event, url, verdict, extra=None):
    entry = {
        "ts": now_str(),
        "event": event,
        "target": url,
        "verdict": verdict,
        "src_ip": request.remote_addr or '10.0.4.87',
        "principal": 'pea-portal-lambda-role'
    }
    if extra:
        entry.update(extra)
    AUDIT_LOG.insert(0, entry)
    while len(AUDIT_LOG) > 50:
        AUDIT_LOG.pop()

def normalize_host(url):
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
    except Exception:
        return ""
    if not host:
        return ""
    try:
        as_int = int(host, 0) if host.lower().startswith("0x") else int(host)
        return str(ipaddress.IPv4Address(as_int))
    except (ValueError, ipaddress.AddressValueError):
        pass
    try:
        return str(ipaddress.IPv4Address(host))
    except (ValueError, ipaddress.AddressValueError):
        return host.lower()

def is_metadata_target(url):
    h = normalize_host(url)
    return h in ['169.254.169.254', 'fd00:ec2::254']

def is_internal_target(url):
    h = normalize_host(url)
    if not h:
        return False
    if h in ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254']:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/metrics')
def api_metrics():
    return jsonify(METRICS)

@app.route('/api/feedback')
def api_feedback():
    return jsonify({'feedback': FEEDBACK_DATA})

@app.route('/api/chat', methods=['POST'])
def api_chat():
    data = request.get_json(silent=True) or {}
    msg = data.get("message", "").strip()
    msg_low = msg.lower()

    # Try the real LLM first
    try:
        from llm_client import call_llm
        system_prompt = (
            "You are NimbleAI, the AI analytics assistant for NimbleTech's Customer "
            "Intelligence Platform. You help analyze patient experience data, generate "
            "insights, and answer questions about customer feedback. Keep responses "
            "concise, data-driven, and professional. Use specific numbers when possible."
        )
        response = call_llm(system_prompt, msg)
        return jsonify({"response": response, "source": "ai"})
    except Exception:
        pass

    # Fallback: keyword-based mock responses
    if 'satisfaction' in msg_low or 'score' in msg_low or 'rating' in msg_low:
        res = (f"Based on the latest data, the average patient satisfaction score is "
               f"**{METRICS['avg_satisfaction']}/5.0**, up {METRICS['satisfaction_change']}% "
               f"from last month. Cardiology leads at 4.6/5.0, while Emergency is at 3.2/5.0 — "
               f"primarily driven by wait-time complaints.")
    elif 'department' in msg_low or 'dept' in msg_low:
        parts = [f"{l}: {d:,}" for l, d in zip(METRICS['dept_labels'], METRICS['dept_data'])]
        res = f"Feedback distribution by department:\n" + "\n".join(f"• {p}" for p in parts)
    elif 'trend' in msg_low:
        res = (f"Satisfaction has been trending upward over the past 12 months, from "
               f"{METRICS['trend_data'][0]} to {METRICS['trend_data'][-1]}. The sharpest "
               f"improvement was in Q2 2026. Current trajectory projects 4.6/5.0 by Q4.")
    elif 'feedback' in msg_low or 'count' in msg_low:
        res = (f"We have **{METRICS['total_feedback']:,}** total feedback entries. "
               f"AI confidence on sentiment analysis is {METRICS['ai_confidence']}%, "
               f"and the response rate is {METRICS['response_rate']}%.")
    elif 'report' in msg_low or 'export' in msg_low:
        res = ("To generate a report, go to **Report Export** in the sidebar. You can "
               "choose from internal templates or provide a custom template URL. Reports "
               "are rendered server-side from your configured template store.")
    else:
        res = ("Hello! I'm **NimbleAI**, your analytics assistant. I can help with:\n"
               "• 📊 Satisfaction scores and trends\n"
               "• 🏥 Department performance breakdowns\n"
               "• 💬 Feedback analysis and insights\n"
               "• 📄 Report generation guidance\n\n"
               "What would you like to know?")
    return jsonify({"response": res, "source": "mock"})

@app.route('/api/export')
def api_export():
    url = request.args.get('template_url', '')
    mode = MODE['current']
    low = url.lower()

    # ── HARDENED: naive string blocklist (deliberately bypassable) ──
    if mode == 'hardened':
        blocked = ['file://', '169.254.169.254', 'localhost', '127.0.0.1', 'metadata']
        if any(b in low for b in blocked):
            return jsonify({
                "error": "Blocked by egress URL filter",
                "reason": "URL matched a denied pattern",
                "url": url,
                "mode": mode
            }), 403
        # Note: decimal/octal/hex IP encodings bypass this — intentional

    # ── GUARDRAILED: strict allowlist + IMDSv2 + audit ──
    if mode == 'guardrailed':
        allowed_prefixes = [
            'https://templates.nimbletech.local/',
            'https://nimbletech-public.s3.amazonaws.com/',
        ]
        if not any(url.startswith(p) for p in allowed_prefixes):
            audit('outbound_fetch', url, 'DENY:not-allowlisted')
            return jsonify({
                "error": "URL not in outbound allowlist",
                "allowed": allowed_prefixes,
                "audit_logged": True,
                "mode": mode
            }), 403
        if is_metadata_target(url):
            audit('metadata_access', url, 'DENY:imdsv2-required')
            return jsonify({
                "error": "Metadata access denied — IMDSv2 token required, hop-limit exceeded",
                "audit_logged": True,
                "mode": mode
            }), 403
        audit('outbound_fetch', url, 'ALLOW')
        return jsonify({
            "report": "<html><body>Template rendered from approved store.</body></html>",
            "source": url, "mode": mode, "status": "ok"
        })

    # ── VULNERABLE (and hardened-after-bypass) resolution ──

    # file:// scheme
    if low.startswith('file:///proc/self/environ'):
        env_dump = "\x00".join([f"{k}={v}" for k, v in LAMBDA_ENV.items()])
        return jsonify({"report": env_dump, "status": "generated", "source": url,
                        "hint": "env vars are NUL(\\x00)-separated — split to parse"})

    if low.startswith('file:///etc/passwd'):
        return jsonify({"report": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "sbx_user1051:x:993:990::/tmp:/sbin/nologin\n"
            "slicer:x:497:497::/home/slicer:/sbin/nologin"
        ), "source": url, "status": "generated"})

    if low.startswith('file:///var/task/config.json'):
        return jsonify({"report": json.dumps({
            "region": "us-east-1",
            "model_endpoint": "nimbletech-pea-endpoint",
            "feature_store": "features-db.nimbletech.ai",
            "template_bucket": "nimbletech-pea-portal-32953eae"
        }, indent=2), "source": url, "status": "generated"})

    if low.startswith('file://'):
        return jsonify({"error": "File not found or not readable", "source": url}), 404

    # Metadata service (canonical or encoded IP → normalized)
    if is_metadata_target(url):
        path = urllib.parse.urlparse(url).path
        if 'iam/security-credentials/pea-portal-lambda-role' in path:
            return jsonify({"report": json.dumps(SIMULATED_METADATA, indent=2),
                            "source": url, "status": "generated"})
        if 'iam/security-credentials' in path:
            return jsonify({"report": "pea-portal-lambda-role", "source": url,
                            "hint": "append this role name to enumerate its creds"})
        if 'iam/info' in path:
            return jsonify({"report": json.dumps(IAM_INFO, indent=2), "source": url})
        if path.rstrip('/').endswith('meta-data'):
            return jsonify({"report": (
                "ami-id\ninstance-id\niam/\nhostname\nlocal-ipv4\n"
                "placement/\nsecurity-groups"
            ), "source": url, "hint": "browse into iam/security-credentials/"})
        return jsonify({"report": "latest\n1.0\n2016-09-02", "source": url})

    # localhost / internal
    if is_internal_target(url):
        return jsonify({"report": "<html><title>PEA Internal Health</title>ok</html>",
                        "source": url, "status": "ok"})

    # External template (benign fetch)
    return jsonify({"report": f"<html><body>Template fetched from {url}</body></html>",
                    "source": url, "status": "ok"})

@app.route('/setmode', methods=['POST'])
def set_mode():
    data = request.get_json()
    if data and "mode" in data and data["mode"] in ["vulnerable", "hardened", "guardrailed"]:
        MODE["current"] = data["mode"]
        return jsonify({"status": "ok", "mode": MODE["current"]})
    return jsonify({"error": "invalid mode"}), 400

@app.route('/getmode')
def get_mode():
    return jsonify({"mode": MODE["current"]})

@app.route('/history')
def get_history():
    return jsonify({"exports": EXPORT_HISTORY})

@app.route('/audit')
def get_audit():
    return jsonify({"log": AUDIT_LOG})

@app.route('/imds/token', methods=['PUT'])
def imds_token():
    """Simulates PUT /latest/api/token with X-aws-ec2-metadata-token-ttl-seconds"""
    if 'X-Forwarded-For' in request.headers:
        return '', 403   # IMDSv2 blocks proxied token requests
    tok = 'AQAE' + os.urandom(8).hex().upper()
    IMDSV2_TOKENS[tok] = time.time() + 21600
    resp = app.make_response(tok)
    resp.headers['X-Aws-Ec2-Metadata-Token-Ttl-Seconds'] = '21600'
    return resp

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5026)
