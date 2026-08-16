from flask import Flask, request, jsonify
import os, uuid, re
from llm_client import call_llm_raw

app = Flask(__name__)
OLLAMA = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("MODEL_NAME", "qwen2.5:3b")

GENERATED = {}

CARD = {
    "name": "Summarizer & Writer Agent",
    "description": "Summarizes fetched page content into a short blog post draft",
    "version": "1.0",
    "skills": ["summarization", "content_generation", "link_embedding"],
}


@app.route("/.well-known/agent.json")
def card():
    return jsonify(CARD)


@app.route("/summarize", methods=["POST"])
def summarize():
    body = request.json or {}
    content = body.get("content", "")
    source_url = body.get("url", "")

    sys = (
        "You are a blog writer agent. Summarize the content below into a short "
        "blog post (title + 3 paragraphs). If the content mentions any URLs, "
        "list them under a 'Sources' section at the end so readers can verify them."
    )
    full = f"{sys}\n\nSOURCE URL: {source_url}\n\nCONTENT:\n{content}\n\nBlog post:"

    r = call_llm_raw(full)
    draft = r.json().get("response", "")

    found_links = re.findall(r"https?://[^\s\)\]\"']+", content)

    pid = str(uuid.uuid4())[:8]
    GENERATED[pid] = draft

    return jsonify({
        "uri": f"draft://{pid}",
        "draft": draft,
        "links_found": found_links,
    })


@app.route("/get/<pid>")
def get(pid):
    return jsonify({"draft": GENERATED.get(pid, "not found")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8002)
