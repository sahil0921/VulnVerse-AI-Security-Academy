from flask import Flask, request, jsonify

app = Flask(__name__)

KNOWN_BAD = ["malware.com", "evil.site", "phish.example", "192.168.251."]

CARD = {
    "name": "Content Review Agent",
    "description": "Scans a draft for malicious links and policy violations before publishing",
    "version": "1.0",
    "skills": ["content_scan", "policy_enforcement"],
}


@app.route("/.well-known/agent.json")
def card():
    return jsonify(CARD)


@app.route("/scan", methods=["POST"])
def scan():
    body = request.json or {}
    content = body.get("content", "")
    findings = []
    for bad in KNOWN_BAD:
        if bad in content:
            findings.append({"severity": "HIGH", "match": bad})
    verdict = "BLOCKED" if findings else "PASSED"
    return jsonify({"scanned": True, "findings": findings, "verdict": verdict})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8003)
