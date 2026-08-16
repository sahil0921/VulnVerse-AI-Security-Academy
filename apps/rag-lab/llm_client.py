"""
shared/llm_client.py

Central LLM router used by every lab in this repo. Reads LLM_PROVIDER /
LLM_MODEL / API_PROVIDER / API_KEY / OLLAMA_HOST from the environment
(these are injected via the `x-llm-env` anchor in docker-compose.yml, which
is filled in from .env by setup.sh).

Usage in any app.py:

    from llm_client import call_llm
    answer = call_llm(system_prompt, user_prompt)

If a call fails (bad key, network issue, rate limit, etc.) this raises a
RuntimeError with a readable message rather than crashing with a raw
traceback, so labs that don't handle exceptions gracefully still show
something useful.
"""

import os
import time
import requests

# Ollama (especially reasoning models like deepseek-r1) can take a long time
# to respond, particularly on a cold start or modest hardware. 600s = 10 min.
OLLAMA_TIMEOUT = 600
API_TIMEOUT = 300

# How many times to retry on a transient error (timeout / connection / 429 /
# 5xx) before giving up, and how long to wait between retries.
MAX_RETRIES = 2
RETRY_DELAY_SECONDS = 5


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
        return _with_retries(lambda: _call_api_provider(system_prompt, user_prompt, max_tokens))
    return _with_retries(lambda: _call_ollama(system_prompt, user_prompt))


def _is_transient(err: Exception) -> bool:
    """Heuristic: is this error worth a retry (timeout/connection/429/5xx)?"""
    msg = str(err).lower()
    return any(s in msg for s in [
        "timeout", "timed out", "connection", "429", "rate limit",
        "resourceexhausted", "503", "502", "500", "overloaded",
    ])


def _with_retries(fn):
    last_err = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            return fn()
        except RuntimeError as e:
            last_err = e
            if attempt < MAX_RETRIES and _is_transient(e):
                time.sleep(RETRY_DELAY_SECONDS)
                continue
            raise
    raise last_err


def _call_ollama(system_prompt: str, user_prompt: str) -> str:
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
    model = os.environ.get("LLM_MODEL") or "mistral:latest"
    prompt = f"{system_prompt}\n\n{user_prompt}" if system_prompt else user_prompt
    try:
        r = requests.post(
            f"{host}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=OLLAMA_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise RuntimeError(f"Ollama returned an error: {data['error']}")
        return data.get("response", "")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Ollama call failed (host={host}, model={model}): {e}")
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Ollama call failed (host={host}, model={model}): {e}")


def _call_api_provider(system_prompt: str, user_prompt: str, max_tokens: int) -> str:
    sub = os.environ.get("API_PROVIDER", "").strip().lower()
    key = os.environ.get("API_KEY", "")
    model = os.environ.get("LLM_MODEL", "")

    if not sub:
        raise RuntimeError("LLM_PROVIDER=api but API_PROVIDER is empty. Check your .env.")
    if not key:
        raise RuntimeError(f"API_PROVIDER={sub} but API_KEY is empty. Check your .env.")
    if not model:
        raise RuntimeError(f"API_PROVIDER={sub} but LLM_MODEL is empty. Check your .env.")

    try:
        if sub == "claude":
            return _call_claude(system_prompt, user_prompt, max_tokens, key, model)
        elif sub == "openai":
            return _call_openai(system_prompt, user_prompt, key, model)
        elif sub == "gemini":
            return _call_gemini(system_prompt, user_prompt, key, model)
        elif sub in ("openrouter", "nvidia"):
            return _call_openai_compatible(sub, system_prompt, user_prompt, key, model)
        else:
            raise RuntimeError(
                f"Unsupported API_PROVIDER: '{sub}'. "
                f"Expected one of: claude, openai, gemini, nvidia, openrouter."
            )
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"{sub} call failed (model={model}): {e}")


def _call_claude(system_prompt, user_prompt, max_tokens, key, model):
    try:
        import anthropic
    except ImportError:
        raise RuntimeError("The 'anthropic' package is not installed. Add it to requirements.txt.")

    try:
        client = anthropic.Anthropic(api_key=key, timeout=API_TIMEOUT)
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt or "You are a helpful assistant.",
            messages=[{"role": "user", "content": user_prompt}],
        )
        if not resp.content:
            raise RuntimeError("Claude returned an empty response.")
        return resp.content[0].text

    except anthropic.AuthenticationError as e:
        raise RuntimeError(f"Claude authentication failed — check API_KEY: {e}")
    except anthropic.NotFoundError as e:
        raise RuntimeError(f"Claude model '{model}' not found — check LLM_MODEL: {e}")
    except anthropic.RateLimitError as e:
        raise RuntimeError(f"Claude rate limit / quota exceeded (429): {e}")
    except anthropic.APIStatusError as e:
        raise RuntimeError(f"Claude API error ({e.status_code}): {e}")
    except anthropic.APIConnectionError as e:
        raise RuntimeError(f"Could not connect to Claude API: {e}")


def _call_openai(system_prompt, user_prompt, key, model):
    try:
        import openai
    except ImportError:
        raise RuntimeError("The 'openai' package is not installed. Add it to requirements.txt.")

    try:
        client = openai.OpenAI(api_key=key, timeout=API_TIMEOUT)
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt or "You are a helpful assistant."},
                {"role": "user", "content": user_prompt},
            ],
        )
        if not resp.choices:
            raise RuntimeError("OpenAI returned no choices in response.")
        return resp.choices[0].message.content or ""

    except openai.AuthenticationError as e:
        raise RuntimeError(f"OpenAI authentication failed — check API_KEY: {e}")
    except openai.NotFoundError as e:
        raise RuntimeError(f"OpenAI model '{model}' not found — check LLM_MODEL: {e}")
    except openai.RateLimitError as e:
        raise RuntimeError(f"OpenAI rate limit / quota exceeded (429): {e}")
    except openai.APIConnectionError as e:
        raise RuntimeError(f"Could not connect to OpenAI API: {e}")
    except openai.APIStatusError as e:
        raise RuntimeError(f"OpenAI API error ({e.status_code}): {e}")


def _call_gemini(system_prompt, user_prompt, key, model):
    try:
        import google.generativeai as genai
        from google.api_core import exceptions as gexc
    except ImportError:
        raise RuntimeError("The 'google-generativeai' package is not installed. Add it to requirements.txt.")

    try:
        genai.configure(api_key=key)
        if system_prompt and system_prompt.strip():
            m = genai.GenerativeModel(model, system_instruction=system_prompt)
        else:
            m = genai.GenerativeModel(model)

        resp = m.generate_content(
            user_prompt,
            request_options={"timeout": API_TIMEOUT},
        )

        if not getattr(resp, "candidates", None):
            reason = getattr(resp, "prompt_feedback", "unknown")
            raise RuntimeError(f"Gemini returned no candidates (possibly blocked): {reason}")

        return resp.text

    except gexc.ResourceExhausted as e:
        raise RuntimeError(
            f"Gemini quota/rate limit exceeded (429) for model '{model}'. "
            f"Free tier has a low daily request cap — switch LLM_PROVIDER=ollama "
            f"or enable billing. Details: {e}"
        )
    except gexc.PermissionDenied as e:
        raise RuntimeError(f"Gemini authentication failed — check API_KEY: {e}")
    except gexc.NotFound as e:
        raise RuntimeError(f"Gemini model '{model}' not found — check LLM_MODEL: {e}")
    except gexc.DeadlineExceeded as e:
        raise RuntimeError(f"Gemini request timed out: {e}")
    except gexc.GoogleAPIError as e:
        raise RuntimeError(f"Gemini API error: {e}")


def _call_openai_compatible(sub, system_prompt, user_prompt, key, model):
    base = (
        "https://openrouter.ai/api/v1"
        if sub == "openrouter"
        else "https://integrate.api.nvidia.com/v1"
    )
    try:
        r = requests.post(
            f"{base}/chat/completions",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt or "You are a helpful assistant."},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=API_TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Could not connect to {sub} API: {e}")

    if r.status_code == 401:
        raise RuntimeError(f"{sub} authentication failed — check API_KEY.")
    if r.status_code == 404:
        raise RuntimeError(f"{sub} model '{model}' not found — check LLM_MODEL.")
    if r.status_code == 429:
        raise RuntimeError(f"{sub} rate limit / quota exceeded (429): {r.text[:300]}")
    if r.status_code >= 500:
        raise RuntimeError(f"{sub} server error ({r.status_code}): {r.text[:300]}")
    if not r.ok:
        raise RuntimeError(f"{sub} API error ({r.status_code}): {r.text[:300]}")

    data = r.json()
    choices = data.get("choices")
    if not choices:
        raise RuntimeError(f"{sub} returned no choices: {data}")
    return choices[0]["message"]["content"] or ""
