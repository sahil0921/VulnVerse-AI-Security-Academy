from flask import Flask, request, jsonify
import requests, os
from llm_client import call_llm_raw

app = Flask(__name__)
OLLAMA = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("MODEL_NAME", "qwen2.5:3b")

CARD = {
    "name": "URL Fetcher Agent",
    "description": "Fetches a URL and extracts readable page content for downstream agents",
    "version": "1.0",
    "skills": ["web_fetch", "html_extraction"],
}

SAMPLE_PAGES = {
    "https://blog.example.com/ai-agents-2026": (
        "AI Agents in 2026: A Practical Guide\n\n"
        "Multi-agent systems are now standard in production content pipelines. "
        "This article covers orchestration patterns, tool use, and safety guardrails "
        "teams should adopt before shipping an agentic pipeline."
    ),
}

SIMULATE = os.environ.get("SIMULATE", "1") == "1"


@app.route("/.well-known/agent.json")
def card():
    return jsonify(CARD)


@app.route("/fetch", methods=["POST"])
def fetch():
    body = request.json or {}
    url = body.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400

    if SIMULATE and url in SAMPLE_PAGES:
        raw = SAMPLE_PAGES[url]
    elif SIMULATE:
        raw = body.get("raw_content", url)
    else:
        try:
            r = requests.get(url, timeout=10)
            raw = r.text[:6000]
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    prompt = f"""You are a page-reading agent. Extract the main readable content
from the following page text. Ignore navigation/boilerplate. Return plain text only.

PAGE CONTENT:
{raw}
"""
    r = call_llm_raw(prompt)
    extracted = r.json().get("response", raw)

    return jsonify({"url": url, "raw_content": raw, "extracted_content": extracted})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
