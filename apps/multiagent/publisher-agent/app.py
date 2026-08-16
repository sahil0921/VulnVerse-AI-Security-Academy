from flask import Flask, request, jsonify
import os, uuid, datetime

app = Flask(__name__)

CARD = {
    "name": "Publisher Agent",
    "description": "Publishes an approved draft to the live company blog",
    "version": "1.0",
    "skills": ["publish", "cms_write"],
}

PUBLISHED = {}


@app.route("/.well-known/agent.json")
def card():
    return jsonify(CARD)


@app.route("/publish", methods=["POST"])
def publish():
    body = request.json or {}
    content = body.get("content", "")
    verdict = body.get("review_verdict", "UNKNOWN")

    pid = str(uuid.uuid4())[:8]
    PUBLISHED[pid] = {
        "content": content,
        "review_verdict": verdict,
        "published_at": datetime.datetime.utcnow().isoformat() + "Z",
    }
    return jsonify({
        "status": "published",
        "post_id": pid,
        "live_url": f"https://blog.nimbletech.example/posts/{pid}",
        "review_verdict_recorded": verdict,
    })


@app.route("/posts")
def posts():
    return jsonify(PUBLISHED)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8004)
