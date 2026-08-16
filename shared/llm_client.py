"""
shared/llm_client.py

Central LLM router used by every lab in this repo. Reads LLM_PROVIDER /
LLM_MODEL / API_PROVIDER / API_KEY / OLLAMA_HOST from the environment
(these are injected via the `x-llm-env` anchor in docker-compose.yml, which
is filled in from .env by setup.sh).

Usage in any app.py:

    from llm_client import call_llm
    answer = call_llm(system_prompt, user_prompt)

If a call fails (bad key, network issue, etc.) this raises a RuntimeError
with a readable message rather than crashing with a raw traceback, so labs
that don't handle exceptions gracefully still show something useful.
"""

import os
import requests


class _OllamaCompat:
    """
    Mimics the tiny slice of the requests.Response interface that every lab
    actually uses: `.json()` returning {"response": "..."}. This lets us
    swap out `requests.post(f"{OLLAMA}/api/generate", ...)` for a single
    `call_llm_raw(prompt)` call without touching any downstream code that
    does `r.json().get("response", "")`.
    """
    def __init__(self, text: str):
        self._text = text

    def json(self):
        return {"response": self._text}


def call_llm_raw(prompt: str, max_tokens: int = 1000) -> "_OllamaCompat":
    """
    Drop-in replacement for the old Ollama-only call. `prompt` here is the
    FULL prompt (system + context + user already concatenated, exactly like
    the old code built it) — no separate system_prompt needed since every
    lab already merges everything into one string before calling Ollama.
    Returns an object with .json() so existing `r.json().get("response","")`
    call sites keep working unchanged.
    """
    text = call_llm("", prompt, max_tokens)
    return _OllamaCompat(text)


def call_llm(system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> str:
    provider = os.environ.get("LLM_PROVIDER", "ollama").strip().lower()

    if provider == "api":
        return _call_api_provider(system_prompt, user_prompt, max_tokens)
    return _call_ollama(system_prompt, user_prompt)


def _call_ollama(system_prompt: str, user_prompt: str) -> str:
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
    model = os.environ.get("LLM_MODEL") or "mistral:latest"
    prompt = f"{system_prompt}\n\n{user_prompt}"
    try:
        r = requests.post(
            f"{host}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=180,
        )
        r.raise_for_status()
        return r.json().get("response", "")
    except Exception as e:
        raise RuntimeError(f"Ollama call failed (host={host}, model={model}): {e}")


def _call_api_provider(system_prompt: str, user_prompt: str, max_tokens: int) -> str:
    sub = os.environ.get("API_PROVIDER", "").strip().lower()
    key = os.environ.get("API_KEY", "")
    model = os.environ.get("LLM_MODEL", "")

    if not key:
        raise RuntimeError("API_PROVIDER is set but API_KEY is empty. Check your .env.")

    try:
        if sub == "claude":
            import anthropic
            client = anthropic.Anthropic(api_key=key)
            resp = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return resp.content[0].text

        elif sub == "openai":
            import openai
            client = openai.OpenAI(api_key=key)
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return resp.choices[0].message.content

        elif sub == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=key)
            m = genai.GenerativeModel(model, system_instruction=system_prompt) if system_prompt and system_prompt.strip() else genai.GenerativeModel(model)
            return m.generate_content(user_prompt).text

        elif sub in ("openrouter", "nvidia"):
            base = (
                "https://openrouter.ai/api/v1"
                if sub == "openrouter"
                else "https://integrate.api.nvidia.com/v1"
            )
            r = requests.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                },
                timeout=180,
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]

        else:
            raise RuntimeError(f"Unsupported API_PROVIDER: '{sub}'")

    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"{sub or 'API'} call failed (model={model}): {e}")
