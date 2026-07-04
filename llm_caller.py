#!/usr/bin/env python3
"""
jrSOCtriage - LLM Caller Module
Sends triage prompts to Ollama or llama.cpp via HTTP.
Stateless single-shot calls - no conversation history.
Supports multiple endpoints with priority-based fallback.
"""

import logging
import random
import re
import threading
import time
import requests
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Per-endpoint concurrency semaphores — keyed by endpoint name
# Created on first use, limited by max_concurrent in endpoint config
_endpoint_semaphores: dict = {}
_semaphore_lock = threading.Lock()

# Per-endpoint failure-reason cache. _call_endpoint records the most recent
# failure reason here (HTTP code, timeout, parse error, etc) keyed by
# endpoint name. call_llm reads it after each failed _call_endpoint to
# include actionable detail in the synthetic FAILED verdict's REASONING
# field, so operators see "openai=HTTP 500" instead of having to grep
# journalctl. Thread-safe via the dict's GIL-protected mutation; stale
# entries are harmless (only the most recent matters) and overwrites
# are intentional.
_last_failure_reasons: dict = {}
# FT: guards _last_failure_reasons under free-threading. The dict is a
# module-global keyed by endpoint name, written/read by concurrent workers.
# The lock prevents data-structure corruption on concurrent record/pop/get
# (the GIL no longer serializes these on python3.14t). It does NOT make the
# pop->call->get sequence atomic across a worker's endpoint call — that
# cross-worker reason-attribution was already best-effort ("only the most
# recent matters", above) and remains so; the lock is for structural safety,
# not for fixing that pre-existing benign race.
_last_failure_lock = threading.Lock()


# Retry policy for transient cloud-API errors. Local endpoints (ollama,
# llamacpp) skip this entirely — local failures should fall through fast,
# either because the next configured endpoint can take over, or so the
# operator notices the local LLM is broken instead of having it papered
# over by retries.
#
# Per code: max_retries is the number of additional attempts beyond the
# first (so 2 = up to 3 total requests). default_delay is in seconds.
# The actual delay gets ±20% jitter applied to spread retries across
# concurrent workers.
_RETRY_POLICY = {
    429: {"max_retries": 2, "default_delay": 5.0, "honor_retry_after": True},
    500: {"max_retries": 1, "default_delay": 2.0, "honor_retry_after": False},
    502: {"max_retries": 2, "default_delay": 2.0, "honor_retry_after": False},
    503: {"max_retries": 2, "default_delay": 2.0, "honor_retry_after": False},
    504: {"max_retries": 2, "default_delay": 2.0, "honor_retry_after": False},
}
# Cumulative wall-clock budget per single endpoint call. If retry waits
# would exceed this, fall through to the next endpoint immediately.
_RETRY_BUDGET_SECONDS = 30.0
# Endpoint types eligible for retry. Local endpoints are not.
_RETRY_ELIGIBLE_TYPES = {"anthropic", "openai", "gemini"}

# Sampling parameters applied uniformly across cloud endpoint types.
# Local engines (ollama, llamacpp) do NOT use _LLM_MAX_TOKENS — they let
# the server use its default (unlimited within context). This is because
# thinking-capable models served by local engines (gemma4, future qwen
# with thinking) consume output-token budget on internal reasoning, and
# an explicit cap causes empty responses when reasoning exhausts the
# allocation. Cloud APIs (gemini, openai, anthropic) handle reasoning
# tokens via separate billing-tracked paths and only count visible output
# against max_tokens, so an explicit cap is safe and useful there.
#
# Centralizing the cloud-side limit here prevents the per-endpoint drift
# that previously existed (gemini was at 8192 while anthropic was at 1024,
# etc.). 4096 accommodates modern reasoning-capable cloud models with
# generous headroom — production verdict format is ~500 chars (~150
# tokens), leaving ~3900 tokens for any visible reasoning output the
# model wants to produce.
#
# Temperature 0.2 matches the deterministic profile that has been running
# in production for cloud endpoints, applied uniformly across all engines
# (local and cloud) for cross-engine consistency.
_LLM_TEMPERATURE = 0.2
_LLM_MAX_TOKENS  = 4096


def _build_openai_body(model, prompt):
    """Build the OpenAI chat-completions request body, accounting for the
    GPT-5 family's API changes:
      - GPT-5 models REQUIRE 'max_completion_tokens' and reject 'max_tokens'
        (HTTP 400 unsupported_parameter).
      - GPT-5 reasoning models reject a non-default 'temperature' (only the
        default of 1 is accepted), so we omit temperature for them rather
        than send 0.2 and get a 400.
    Older chat models (gpt-4o-mini, gpt-4.1-mini, etc.) keep the legacy
    'max_tokens' + explicit temperature.
    Detection is a name-prefix check ('gpt-5'); extend the tuple if OpenAI
    ships more families with the new contract.
    """
    m = (model or "").lower()
    is_gpt5 = m.startswith("gpt-5") or m.startswith("o1") or m.startswith("o3")
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }
    if is_gpt5:
        body["max_completion_tokens"] = _LLM_MAX_TOKENS
        # omit temperature: GPT-5/o-series reject non-default values
    else:
        body["max_tokens"] = _LLM_MAX_TOKENS
        body["temperature"] = _LLM_TEMPERATURE
    return body


def _jittered(base_delay: float, jitter_pct: float = 0.20) -> float:
    """Return base_delay ± jitter_pct%. Jitter spreads concurrent retries
    so 9 workers all 429-ing at once don't all retry at the exact same
    moment. Bounded at 0.1s minimum."""
    spread = base_delay * jitter_pct
    return max(0.1, base_delay + random.uniform(-spread, spread))


def _record_failure(name: str, reason: str) -> None:
    """Record the most recent failure reason for an endpoint. The reason
    is later included in the synthetic FAILED verdict's REASONING field
    when all endpoints exhaust, so operators see actionable detail in
    the email/Graylog instead of needing to grep journalctl. Most recent
    overwrites; only the latest matters."""
    with _last_failure_lock:
        _last_failure_reasons[name] = reason


def _compute_retry_delay(status_code, retry_after_header, attempts_used,
                         elapsed_so_far, name):
    """
    Decide whether to retry an HTTP failure and how long to wait.

    Returns the delay in seconds (caller should sleep that long, then
    retry), or None if no retry should happen (out of budget, exceeded
    max retries, or status not retryable).
    """
    policy = _RETRY_POLICY.get(status_code)
    if policy is None:
        return None  # Status not retryable

    if attempts_used >= policy["max_retries"]:
        return None  # Out of retries

    # Compute base delay
    delay = policy["default_delay"]

    if policy["honor_retry_after"] and retry_after_header:
        # Anthropic and others may send Retry-After: <seconds> on 429.
        # Honor it but cap at remaining budget.
        try:
            requested = float(retry_after_header)
            delay = max(0.1, requested)
        except (ValueError, TypeError):
            # Header isn't a number we can parse (could be HTTP-date format).
            # Fall through with default delay.
            pass

    delay = _jittered(delay)

    # Budget check: would this delay + an estimated request time blow
    # past the 30s cumulative budget? If so, give up and fall through.
    # Estimate ~3s for the actual request after the delay.
    if elapsed_so_far + delay + 3.0 > _RETRY_BUDGET_SECONDS:
        logger.warning(
            f"[{name}] HTTP {status_code} retry would exceed budget "
            f"({_RETRY_BUDGET_SECONDS}s) — falling through to next endpoint"
        )
        return None

    return delay


def _post_with_retry(url, ep_type, name, **kwargs):
    """
    HTTP POST with automatic retry on transient errors for cloud endpoints.

    For local endpoint types (ollama, llamacpp): performs a single POST
    with no retry logic. Local failures should propagate fast.

    For cloud endpoint types (anthropic, openai, gemini): retries on
    HTTP 429/500/502/503/504 per _RETRY_POLICY, with jittered backoff
    and a 30-second cumulative budget. All other failures (connection
    errors, timeouts, non-retryable status codes) propagate immediately.

    Returns the final requests.Response (which may be a successful 200
    or a final non-retryable failure that the caller will handle).
    Raises requests.RequestException on connection-level failures, just
    as a normal requests.post would.
    """
    if ep_type not in _RETRY_ELIGIBLE_TYPES:
        # Local endpoint — single attempt, no retry overhead
        return requests.post(url, **kwargs)

    attempts_used = 0
    elapsed = 0.0
    start = time.monotonic()

    while True:
        resp = requests.post(url, **kwargs)
        elapsed = time.monotonic() - start

        # Success or non-retryable failure — return immediately
        if resp.status_code == 200 or resp.status_code not in _RETRY_POLICY:
            return resp

        # Retryable status — decide if we have budget and attempts left
        retry_after = resp.headers.get("Retry-After") if resp.headers else None
        delay = _compute_retry_delay(
            resp.status_code, retry_after, attempts_used, elapsed, name
        )
        if delay is None:
            # No retry — return this response and let caller handle it
            return resp

        attempts_used += 1
        logger.warning(
            f"[{name}] HTTP {resp.status_code}, retrying in {delay:.1f}s "
            f"(attempt {attempts_used}/{_RETRY_POLICY[resp.status_code]['max_retries']})"
        )
        time.sleep(delay)
        # Loop back and try again


def _get_semaphore(name: str, max_concurrent: int) -> threading.Semaphore:
    """Get or create a semaphore for an endpoint."""
    with _semaphore_lock:
        if name not in _endpoint_semaphores:
            _endpoint_semaphores[name] = threading.Semaphore(max_concurrent)
        return _endpoint_semaphores[name]

# Round robin state - shared across calls, thread-safe
_rr_lock  = threading.Lock()
_rr_index = 0


def _get_next_endpoint_rr(endpoints):
    """Return next endpoint using round robin, skipping none."""
    global _rr_index
    with _rr_lock:
        idx = _rr_index % len(endpoints)
        _rr_index += 1
    return idx


# ---------------------------------------------------------------------------
# Endpoint helpers
# ---------------------------------------------------------------------------

def get_endpoints(config):
    """
    Return ordered list of endpoint configs from config.llm.
    Supports both legacy single-endpoint and new multi-endpoint formats.

    Legacy format:
        "llm": {"endpoint": "...", "model": "...", ...}

    New format:
        "llm": {"endpoints": [{"name": "...", "url": "...", "model": "...", ...}]}

    Returns list of dicts sorted by priority (lowest first).
    """
    llm_cfg = config.get("llm", {})

    # New multi-endpoint format
    if "endpoints" in llm_cfg:
        endpoints = [e for e in llm_cfg["endpoints"] if e.get("enabled", True)]
        if not endpoints:
            logger.warning("All LLM endpoints are disabled")
        return sorted(endpoints, key=lambda e: e.get("priority", 99))

    # Legacy single-endpoint format — wrap in list for uniform handling
    if llm_cfg.get("endpoint"):
        return [{
            "name":            "default",
            "url":             llm_cfg.get("endpoint", "").rstrip("/"),
            "model":           llm_cfg.get("model", "gemma4:26b"),
            "type":            llm_cfg.get("type", "ollama"),
            "priority":        1,
            "timeout_seconds": llm_cfg.get("timeout_seconds", 60),
            "keep_alive":      llm_cfg.get("keep_alive", -1),
        }]

    return []


def _call_endpoint(prompt, endpoint_cfg, config=None):
    """
    Make a single LLM call to one endpoint.
    Returns 5-tuple: (response_text, endpoint_name, model_name, anonymized, anon_prompt).
    On failure returns (None, name, model, False, None).
    Supports type: "ollama" (default), "llamacpp", "gemini", "openai", "anthropic".
    Anonymizes prompt for cloud endpoints if configured.
    """
    url        = endpoint_cfg.get("url", "").rstrip("/")
    model      = endpoint_cfg.get("model", "gemma4:26b")
    timeout    = endpoint_cfg.get("timeout_seconds", 60)
    keep_alive = endpoint_cfg.get("keep_alive", -1)
    ep_type    = endpoint_cfg.get("type", "ollama").lower()
    name       = endpoint_cfg.get("name", url)
    max_concurrent = int(endpoint_cfg.get("max_concurrent", 10))

    # Acquire per-endpoint concurrency semaphore.
    # IMPORTANT: _call_endpoint_inner has its own try/finally that releases
    # the semaphore. We do NOT release here on exception paths — that would
    # be a double-release, corrupting the semaphore counter and eventually
    # allowing unbounded concurrency. The inner's finally is the sole owner
    # of the release.
    semaphore = _get_semaphore(name, max_concurrent)
    semaphore.acquire()
    try:
        return _call_endpoint_inner(prompt, endpoint_cfg, config, semaphore, name, model,
                                    timeout, keep_alive, ep_type, url)
    except RuntimeError as e:
        # Anonymization refused the call — already logged at ERROR level inside.
        # Inner's finally already released the semaphore. Return failure so the
        # strategy dispatcher tries the next endpoint (another cloud endpoint
        # would also likely fail closed, a local ollama endpoint would not
        # require anonymization and could succeed).
        _record_failure(name, f"anonymization refused: {e}")
        return None, name, model, False, None
    except Exception as e:
        # Unexpected exception. Inner's finally already released the semaphore.
        logger.warning(f"[{name}] Unexpected error: {e}")
        _record_failure(name, f"unexpected error: {e}")
        return None, name, model, False, None


def _call_endpoint_inner(prompt, endpoint_cfg, config, semaphore, name, model,
                         timeout, keep_alive, ep_type, url):
    """Inner call — semaphore already acquired, always released in finally."""
    reverse_lookup = {}
    anonymized = False
    try:
        start = datetime.now(timezone.utc).timestamp()
        # debug_llm_payload — verifies anonymization works as expected on
        # cloud endpoints by logging the exact prompt and response. This is
        # an audit tool for cloud-bound traffic only. We deliberately do
        # NOT log payloads for local endpoints (ollama/llamacpp) because:
        #   1. Local endpoints don't anonymize, so prompts contain raw
        #      hostnames, IPs, usernames from the alert. Logging at
        #      WARNING level would persist that data to the system log
        #      indefinitely — a real data-leak risk if logs are shipped
        #      elsewhere or readable by other users.
        #   2. There's no anonymization to verify on local endpoints, so
        #      the debug feature has no purpose there.
        # If you need to inspect a local prompt for debugging, look at
        # the prompt_builder output or set logging level to DEBUG on
        # the prompt_builder module specifically.
        debug_mode = (
            bool(config and config.get("logging", {}).get("debug_llm_payload", False))
            and ep_type not in ("ollama", "llamacpp")
        )

        # Anonymize prompt for cloud endpoints if configured.
        # TRUST BOUNDARY: if anonymization is requested and fails for any
        # reason, refuse to call the cloud API. Sending raw data to a cloud
        # LLM after an anonymization failure would silently break the user's
        # explicit opt-in to anonymization. Fail closed.
        if ep_type not in ("ollama", "llamacpp") and config:  # cloud endpoints: gemini, openai, anthropic
            anon_requested = bool(endpoint_cfg.get("anonymize"))
            if anon_requested:
                try:
                    from anonymize import anonymize_prompt
                    prompt, reverse_lookup = anonymize_prompt(prompt, config, endpoint_cfg)
                    if reverse_lookup:
                        anonymized = True
                        logger.info(f"[{name}] Anonymization complete: {len(reverse_lookup)} substitutions")
                except Exception as e:
                    logger.error(
                        f"[{name}] Anonymization FAILED: {e} — REFUSING to send prompt "
                        f"to cloud endpoint. Raw data will not leak. Check anonymization "
                        f"config files (anonymization.json, users.json, domain.json, "
                        f"ip_aliases.json, hosts.json)."
                    )
                    raise RuntimeError(
                        f"Anonymization failed for endpoint '{name}' — cloud call refused"
                    ) from e

        if debug_mode:
            logger.warning(f"[{name}] [DEBUG_PAYLOAD] Exact prompt being sent to API ({len(prompt)} chars):\n----- BEGIN PROMPT -----\n{prompt}\n----- END PROMPT -----")

        # --- Endpoint dispatch ---
        if ep_type == "llamacpp":
            # llama.cpp server: use /v1/chat/completions so the harmony parser
            # separates the model's thinking blocks from its final answer.
            # Without this, /v1/completions returns raw tokens including
            # channel markers like "<|channel|>thought" inline with the
            # output, which corrupts parsing.
            #
            # Response handling: gemma is a thinking-capable model. The chat
            # endpoint returns:
            #   choices[0].message.content          -> final answer
            #   choices[0].message.reasoning_content -> internal thinking
            # If content is empty (model exhausted budget during reasoning
            # and never wrote a final answer), we fall back to reasoning_content
            # because that's where the structured VERDICT/CONFIDENCE/SUMMARY
            # block lives in observed gemma behavior with this prompt.
            #
            # max_tokens is set generously (16384) for thinking-capable models.
            # See the parallel note in the ollama block below: gemma's thinking
            # phase consumes tokens before the visible answer is emitted, so a
            # tight cap on max_tokens truncates the model mid-reasoning and the
            # final answer is never written. In observed production data, a
            # 4096 cap produced a cluster of ~34s responses with 10-40k chars
            # of leaked reasoning_content and no clean content block. 16384
            # gives gemma enough headroom to complete deliberation and write
            # a clean final-answer block within the request timeout.
            resp = requests.post(
                f"{url}/v1/chat/completions",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "temperature": _LLM_TEMPERATURE,
                    "max_tokens": 16384,
                },
                timeout=timeout,
            )
            if resp.status_code != 200:
                logger.warning(f"[{name}] HTTP {resp.status_code}: {resp.text[:200]}")
                _record_failure(name, f"HTTP {resp.status_code}")
                return None, name, model, False, None
            data = resp.json()
            message = data.get("choices", [{}])[0].get("message", {}) or {}
            response_text = (message.get("content") or "").strip()
            if not response_text:
                # Final-answer block was empty; fall back to reasoning_content.
                # Observed gemma behavior on llama-server: the VERDICT block
                # is emitted inside reasoning when the model doesn't produce
                # a separate final-answer phase.
                reasoning = (message.get("reasoning_content") or "").strip()
                if reasoning:
                    logger.info(f"[{name}] content empty; using reasoning_content ({len(reasoning)} chars)")
                    response_text = reasoning

        elif ep_type == "gemini":
            api_key = endpoint_cfg.get("api_key", "")
            if not api_key:
                logger.warning(f"[{name}] No api_key configured for Gemini endpoint")
                _record_failure(name, "no api_key configured")
                return None, name, model, False, None
            resp = _post_with_retry(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                ep_type, name,
                headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "maxOutputTokens": _LLM_MAX_TOKENS,
                        "temperature": _LLM_TEMPERATURE,
                    },
                },
                timeout=timeout,
            )
            if resp.status_code != 200:
                logger.warning(f"[{name}] HTTP {resp.status_code}: {resp.text[:500]}")
                _record_failure(name, f"HTTP {resp.status_code}")
                return None, name, model, False, None
            data = resp.json()
            try:
                parts = data["candidates"][0]["content"]["parts"]
                response_text = "".join(p.get("text", "") for p in parts if "text" in p).strip()
            except (KeyError, IndexError) as e:
                logger.warning(f"[{name}] Could not parse Gemini response: {e} | raw: {str(data)[:300]}")
                _record_failure(name, f"unparseable response ({e})")
                return None, name, model, False, None

        elif ep_type == "openai":
            api_key = endpoint_cfg.get("api_key", "")
            base_url = url.rstrip("/") if url else "https://api.openai.com"
            if not api_key:
                logger.warning(f"[{name}] No api_key configured for OpenAI endpoint")
                _record_failure(name, "no api_key configured")
                return None, name, model, False, None
            resp = _post_with_retry(
                f"{base_url}/v1/chat/completions",
                ep_type, name,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=_build_openai_body(model, prompt),
                timeout=timeout,
            )
            if resp.status_code != 200:
                logger.warning(f"[{name}] HTTP {resp.status_code}: {resp.text[:500]}")
                _record_failure(name, f"HTTP {resp.status_code}")
                return None, name, model, False, None
            data = resp.json()
            try:
                response_text = data["choices"][0]["message"]["content"].strip()
            except (KeyError, IndexError) as e:
                logger.warning(f"[{name}] Could not parse OpenAI response: {e} | raw: {str(data)[:300]}")
                _record_failure(name, f"unparseable response ({e})")
                return None, name, model, False, None

        elif ep_type == "anthropic":
            api_key = endpoint_cfg.get("api_key", "")
            if not api_key:
                logger.warning(f"[{name}] No api_key configured for Anthropic endpoint")
                _record_failure(name, "no api_key configured")
                return None, name, model, False, None
            resp = _post_with_retry(
                "https://api.anthropic.com/v1/messages",
                ep_type, name,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": _LLM_MAX_TOKENS,
                    "temperature": _LLM_TEMPERATURE,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=timeout,
            )
            if resp.status_code != 200:
                logger.warning(f"[{name}] HTTP {resp.status_code}: {resp.text[:500]}")
                _record_failure(name, f"HTTP {resp.status_code}")
                return None, name, model, False, None
            data = resp.json()
            try:
                response_text = data["content"][0]["text"].strip()
            except (KeyError, IndexError) as e:
                logger.warning(f"[{name}] Could not parse Anthropic response: {e} | raw: {str(data)[:300]}")
                _record_failure(name, f"unparseable response ({e})")
                return None, name, model, False, None

        else:
            # Ollama /api/generate
            # NOTE: We intentionally do NOT set num_predict here. Gemma's
            # thinking-capable models (gemma4:26b included — see `ollama show
            # gemma4:26b` capabilities: "thinking") may consume an explicit
            # num_predict budget on internal reasoning tokens before reaching
            # the visible response. When that happens, ollama returns HTTP 200
            # with an empty `response` field despite eval_count showing tokens
            # were generated. Letting ollama use its default (-1 = unlimited
            # within context window) prevents this. Temperature is still
            # explicit for cross-engine consistency with cloud endpoints.
            resp = requests.post(
                f"{url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "keep_alive": keep_alive,
                    "options": {
                        "temperature": _LLM_TEMPERATURE,
                    },
                },
                timeout=timeout,
            )
            if resp.status_code != 200:
                logger.warning(f"[{name}] HTTP {resp.status_code}: {resp.text[:200]}")
                _record_failure(name, f"HTTP {resp.status_code}")
                return None, name, model, False, None
            data = resp.json()
            response_text = data.get("response", "").strip()

        elapsed = round(datetime.now(timezone.utc).timestamp() - start, 1)
        logger.info(f"[{name}] {model} responded in {elapsed}s ({len(response_text)} chars)")

        # Empty response detection (L-15).
        # Before this guard, HTTP-200-with-empty-content would silently return
        # an empty string. The caller would treat it as "no response" and fall
        # through to the next endpoint without _record_failure being called, so
        # the failure reason logged in L-8's synthetic FAILED verdict was
        # "unknown failure (no reason recorded)". Operators couldn't diagnose
        # why. This guard records a specific reason AND logs forensic detail
        # on the raw response so future empty responses can be analyzed for
        # patterns (was it done_reason=length? was eval_count>0 indicating
        # thinking budget was consumed? was prompt malformed?).
        if not response_text:
            # Only ollama returns a 'data' dict with these fields; cloud
            # endpoints set response_text via different parsing paths and
            # this branch protects all of them with appropriate detail.
            try:
                done_reason = data.get("done_reason", "unset")
                eval_count = data.get("eval_count", "unset")
                prompt_eval_count = data.get("prompt_eval_count", "unset")
                keys = list(data.keys()) if isinstance(data, dict) else "n/a"
                forensic = (
                    f"done_reason={done_reason} eval_count={eval_count} "
                    f"prompt_eval_count={prompt_eval_count} keys={keys}"
                )
            except Exception:
                forensic = "(unable to extract forensic detail)"
            logger.warning(f"[{name}] Empty response despite HTTP 200 — {forensic}")
            _record_failure(name, f"empty response ({forensic})")
            return None, name, model, False, None

        if debug_mode:
            logger.warning(f"[{name}] [DEBUG_PAYLOAD] Raw response from API BEFORE deanonymization:\n----- BEGIN RESPONSE -----\n{response_text}\n----- END RESPONSE -----")

        # De-anonymize response before returning
        if reverse_lookup:
            try:
                from anonymize import deanonymize_response
                response_text = deanonymize_response(response_text, reverse_lookup)
            except Exception as e:
                logger.warning(f"[{name}] De-anonymization failed: {e}")

        return response_text, name, model, anonymized, prompt

    except requests.exceptions.Timeout:
        logger.warning(f"[{name}] Timed out after {timeout}s")
        _record_failure(name, f"timeout after {timeout}s")
        return None, name, model, False, None
    except requests.exceptions.ConnectionError:
        logger.warning(f"[{name}] Connection failed — host unreachable")
        _record_failure(name, "connection failed (host unreachable)")
        return None, name, model, False, None
    except (requests.RequestException, ValueError) as e:
        logger.warning(f"[{name}] Request error: {e}")
        _record_failure(name, f"request error: {e}")
        return None, name, model, False, None
    finally:
        semaphore.release()

# ---------------------------------------------------------------------------
# Model warmup — load model into VRAM before first alert
# ---------------------------------------------------------------------------

def warmup_model(config):
    """
    Warm up all enabled LLM endpoints.
    For Ollama/llama.cpp: sends a dummy prompt to load model into VRAM.
    For cloud endpoints (Gemini/OpenAI): no warmup needed.
    Returns True if at least one endpoint is ready.
    """
    endpoints = get_endpoints(config)
    if not endpoints:
        logger.error("No LLM endpoints configured")
        return False

    any_ready = False
    for ep in endpoints:
        name       = ep.get("name", "unknown")
        ep_type    = ep.get("type", "ollama").lower()
        model      = ep.get("model", "gemma4:26b")
        url        = ep.get("url", "").rstrip("/")
        timeout    = ep.get("timeout_seconds", 60)
        keep_alive = ep.get("keep_alive", -1)

        # Cloud endpoints don't need warmup
        if ep_type in ("gemini", "openai", "anthropic"):
            logger.info(f"[{name}] Cloud endpoint — no warmup needed")
            print(f"[OK] {name} ready (cloud)")
            any_ready = True
            continue

        logger.info(f"Warming up [{name}] {model} ...")
        print(f"[..] Loading {model} on {name} ...")

        try:
            if ep_type == "llamacpp":
                # llama-server warmup with realistic prompt to force model load,
                # KV cache initialization, and CUDA kernel JIT-compile. A tiny
                # "ping" prompt completes before any of that happens and leaves
                # the first real alert to absorb 30-60s of one-time setup cost,
                # often timing out at the per-call timeout. The filler prompt
                # below is ~6k tokens, comparable to a real jrSOCtriage prompt.
                # Uses /v1/chat/completions to match the production code path.
                warmup_prompt = "The quick brown fox jumps over the lazy dog. " * 800
                resp = requests.post(
                    f"{url}/v1/chat/completions",
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": warmup_prompt}],
                        "max_tokens": 32,
                        "stream": False,
                    },
                    timeout=max(timeout, 120),  # warmup needs more time than normal calls
                )
            else:
                resp = requests.post(
                    f"{url}/api/generate",
                    json={"model": model, "prompt": "ping", "stream": False, "keep_alive": keep_alive},
                    timeout=timeout,
                )
            if resp.status_code == 200:
                logger.info(f"[{name}] Ready")
                print(f"[OK] {name} ready")
                any_ready = True
            else:
                logger.warning(f"[{name}] Warmup HTTP {resp.status_code}")
                print(f"[!!] {name} warmup failed (HTTP {resp.status_code})")
        except requests.exceptions.ConnectionError:
            logger.warning(f"[{name}] Unreachable during warmup")
            print(f"[!!] {name} unreachable")
        except requests.exceptions.Timeout:
            logger.warning(f"[{name}] Warmup timed out")
            print(f"[!!] {name} warmup timed out")
        except Exception as e:
            logger.warning(f"[{name}] Warmup error: {e}")
            print(f"[!!] {name} warmup error: {e}")

    return any_ready



# ---------------------------------------------------------------------------
# Main LLM caller — round robin or fallback across endpoints
# ---------------------------------------------------------------------------

def call_llm(prompt, config, raw_config=None):
    """
    Send prompt to LLM endpoints in priority order.
    Falls back to next endpoint on failure.
    raw_config is the full config dict passed to anonymize functions.

    Returns 5-tuple: (response_text, endpoint_name, model_name, anonymized, anon_prompt)

    On total failure (all endpoints exhausted), returns a SYNTHETIC response
    containing VERDICT: FAILED and a reasoning block listing which endpoint
    failed and why. This makes pipeline failures visible in Graylog searches
    (gl2_llm_verdict:FAILED) rather than silently dropping the alert into the
    "triage_complete but no verdict" blind spot. Operators can alert on
    FAILED verdicts crossing a threshold to catch LLM stack issues early.
    """
    if raw_config is None:
        raw_config = config
    llm_cfg = config.get("llm", {})
    if not llm_cfg.get("enabled", False):
        logger.info("LLM disabled in config")
        return None, None, None, False, None

    endpoints = get_endpoints(config)
    if not endpoints:
        logger.error("No LLM endpoints configured")
        return _synthesize_failure(
            "No LLM endpoints configured in config.llm.endpoints"
        )

    strategy = llm_cfg.get("strategy", "fallback").lower()
    logger.info(f"Sending prompt ({len(prompt)} chars) to LLM (strategy={strategy})")

    if strategy == "round_robin" and len(endpoints) > 1:
        start_idx = _get_next_endpoint_rr(endpoints)
        ordered = endpoints[start_idx:] + endpoints[:start_idx]
    else:
        ordered = endpoints

    # Track why each endpoint failed so we can include the detail in the
    # synthetic failure response. Keyed by endpoint name. The actual
    # reason is set by _record_failure inside _call_endpoint at the
    # specific failure site (HTTP status, timeout, anonymization refused,
    # etc.) and read back here. This puts actionable detail in the
    # synthetic FAILED verdict's REASONING field, so operators see
    # "openai=HTTP 500; ollama=connection failed" in their email/Graylog
    # without needing to grep journalctl.
    failure_reasons = {}

    for ep in ordered:
        name = ep.get("name", ep.get("url", "unknown"))
        # Clear any stale reason for this endpoint before the call so we
        # don't reuse a failure from a previous alert if this call succeeds
        # (success would skip the _record_failure path entirely).
        with _last_failure_lock:
            _last_failure_reasons.pop(name, None)
        response_text, ep_name, model, anonymized, anon_prompt = _call_endpoint(prompt, ep, config=raw_config)
        if response_text:
            return response_text, ep_name, model, anonymized, anon_prompt
        # Read the structured failure reason recorded by _call_endpoint.
        # Fall back to a generic message if for some reason no reason was
        # recorded (defensive — every failure path in _call_endpoint
        # should call _record_failure, but we don't want call_llm to
        # crash if a future code path forgets).
        with _last_failure_lock:
            failure_reasons[name] = _last_failure_reasons.get(
                name, "unknown failure (no reason recorded)"
            )
        logger.warning(f"[{name}] Failed ({failure_reasons[name]}) — trying next endpoint")

    logger.error("All LLM endpoints failed")
    detail = "; ".join(f"{name}={reason}" for name, reason in failure_reasons.items())
    return _synthesize_failure(
        f"All {len(ordered)} LLM endpoint(s) failed: {detail}"
    )


def _synthesize_failure(reason):
    """
    Build a synthetic LLM response tuple for pipeline-failure visibility.
    Returns a 5-tuple that matches call_llm's normal return shape, but with
    a synthetic VERDICT: FAILED response_text. Downstream parse_llm_response
    will extract the FAILED verdict and the reason, making the failure
    visible and searchable in Graylog.
    """
    response_text = (
        "VERDICT: FAILED\n"
        "CONFIDENCE: HIGH\n"
        "SUMMARY: LLM triage unavailable for this alert.\n"
        f"REASONING: {reason}\n"
        "MISSING INFO: Pipeline could not obtain LLM analysis. "
        "Review this alert manually using the enrichment data shipped "
        "alongside (zeek flows, ntopng data, host context, baseline). "
        "If FAILED verdicts are recurring, investigate LLM endpoint health "
        "(Ollama service, API keys, network connectivity)."
    )
    # endpoint_name="pipeline" and model="n/a" mark this as a synthetic
    # response rather than one from a real endpoint. anonymized=False
    # because no real prompt was sent anywhere. anon_prompt=None for same
    # reason.
    return response_text, "pipeline", "n/a", False, None

# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def parse_llm_response(response_text):
    """
    Parse the structured LLM output into a dict.
    Handles minor formatting variations gracefully.

    Expected format:
        VERDICT: [NOTIFY / NOTE / SUPPRESS]
        CONFIDENCE: [HIGH / MEDIUM / LOW]
        SUMMARY: One sentence.
        REASONING: 2-3 sentences.
        MISSING INFO: ...

    The parser also accepts VERDICT: FAILED, which is reserved for the
    pipeline's own synthetic responses when all LLM endpoints exhaust
    (see _synthesize_failure). Real LLMs are never instructed to emit
    FAILED.

    Returns dict with keys: verdict, confidence, summary, reasoning,
    missing_info, raw, parse_error. All default to None if not found
    or if parsing fails. parse_error is set to a string describing what
    couldn't be parsed; check for None to confirm a clean parse.
    """
    if not response_text:
        return {
            "verdict":      None,
            "confidence":   None,
            "summary":      None,
            "reasoning":    None,
            "missing_info": None,
            "raw":          response_text,
            "parse_error":  "Empty response",
        }

    result = {
        "verdict":      None,
        "confidence":   None,
        "summary":      None,
        "reasoning":    None,
        "missing_info": None,
        "raw":          response_text,
        "parse_error":  None,
    }

    # Extract each field with flexible regex.
    # FAILED is a synthetic verdict emitted by _synthesize_failure when all
    # LLM endpoints exhaust; it flows through parse the same as real verdicts
    # so the failure becomes visible in Graylog (gl2_llm_verdict:FAILED).
    patterns = {
        "verdict":      r"VERDICT\s*:\s*(NOTIFY|NOTE|SUPPRESS|FAILED)",
        "confidence":   r"CONFIDENCE\s*:\s*(HIGH|MEDIUM|LOW)",
        "summary":      r"SUMMARY\s*:\s*(.+?)(?=\nREASONING|\nMISSING|$)",
        "reasoning":    r"REASONING\s*:\s*(.+?)(?=\nMISSING|$)",
        "missing_info": r"MISSING INFO\s*:\s*(.+?)(?=$)",
    }

    for field, pattern in patterns.items():
        match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
        if match:
            result[field] = match.group(1).strip()

    # Validate critical fields
    if not result["verdict"]:
        result["parse_error"] = "Could not parse VERDICT"
        logger.warning(f"LLM parse error - no VERDICT found in: {response_text[:200]}")
    if not result["confidence"]:
        result["parse_error"] = (result["parse_error"] or "") + " | Could not parse CONFIDENCE"
        logger.warning("LLM parse error - no CONFIDENCE found")

    # Normalize to uppercase
    if result["verdict"]:
        result["verdict"] = result["verdict"].upper()
    if result["confidence"]:
        result["confidence"] = result["confidence"].upper()

    return result


# ---------------------------------------------------------------------------
# Email decision
# ---------------------------------------------------------------------------

def should_email(parsed_response, config):
    """
    Decide whether to send an email based on LLM verdict and confidence.
    Logic:
        VERDICT == NOTIFY AND confidence >= min_confidence_to_email → "notify"
        VERDICT == NOTE   AND confidence >= min_confidence_to_note  → "note"
        VERDICT == NOTE   AND note_address is empty                 → False
        Everything else → False
    Returns "notify", "note", or False.
    """
    if not parsed_response:
        return False

    verdict    = parsed_response.get("verdict", "")
    confidence = parsed_response.get("confidence", "")

    email_cfg = config.get("email", {})

    confidence_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    actual_rank     = confidence_rank.get(confidence, 0)

    if verdict == "NOTIFY":
        min_confidence = email_cfg.get("min_confidence_to_email", "MEDIUM").upper()
        min_rank       = confidence_rank.get(min_confidence, 2)
        if actual_rank >= min_rank:
            return "notify"

    if verdict == "NOTE":
        note_address   = email_cfg.get("note_address", "").strip()
        min_confidence = email_cfg.get("min_confidence_to_note", "LOW").upper()
        min_rank       = confidence_rank.get(min_confidence, 1)
        if note_address and actual_rank >= min_rank:
            return "note"

    return False


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    from ingest import load_config, load_hosts, read_new_alerts, safe_get
    from enrich import enrich_alert
    from database import get_connection, record_alert, calculate_baseline
    from graylog_fetch import search_graylog, format_logs_for_prompt, parse_alert_timestamp
    from zeek_fetch import fetch_zeek_flows
    from dedup import is_duplicate
    from prompt_builder import build_prompt

    print("=== jrSOCtriage LLM Caller Smoke Test ===\n")
    # KNOWN BUG (documented, not fixed): read_new_alerts() below advances the
    # shared .ingest_position, so running this smoke test against a LIVE
    # pipeline makes the pipeline skip the alerts consumed here. Run with the
    # pipeline stopped, or on the test platform. Same class as the ntopng /
    # zeek / email smoke tests. NOTE for v1.1: the interface "Test LLM
    # Connection" feature should NOT reuse this alert-driven smoke test —
    # build it like the email test (synthetic prompt, no ingest, shell out
    # to /usr/bin/python3, not the interface venv, since this module
    # imports requests).

    config     = load_config("config.json")
    hosts_data = load_hosts(config)
    conn       = get_connection(config)

    # Warmup model
    if not warmup_model(config):
        print("[FAIL] Could not load model - check Ollama is running on fedora")
        exit(1)

    print()

    silence_seconds = config.get("processing", {}).get("dedup_silence_seconds", 240)
    min_level       = config.get("filtering", {}).get("min_rule_level", 6)

    alerts = list(read_new_alerts(config, min_level=0))
    print(f"Loaded {len(alerts)} alert(s)\n")

    triaged = 0
    for alert in alerts:
        enrichment = enrich_alert(alert, config, hosts_data)
        dedup_key  = enrichment["dedup_key"]
        level      = int(safe_get(alert, "rule", "level", default=0))

        record_alert(conn, enrichment, alert)

        if is_duplicate(dedup_key, silence_seconds):
            continue

        if level < min_level:
            continue

        # Fetch context
        alert_time   = parse_alert_timestamp(alert)
        graylog_logs = None
        zeek_data    = None

        gl_messages  = search_graylog(config, enrichment["canonical_hostname"], alert_time)
        graylog_logs = format_logs_for_prompt(gl_messages)

        ips = enrichment.get("ips", {})
        if ips.get("all") and alert_time:
            zeek_data = fetch_zeek_flows(config, alert, ips["all"], alert_time)

        baseline = calculate_baseline(
            conn, config,
            enrichment["gl2_rule_id"],
            enrichment["canonical_hostname"],
            alert_ts=alert_time.timestamp() if alert_time else None,
        )

        prompt = build_prompt(
            alert, enrichment, baseline, hosts_data,
            graylog_logs=graylog_logs,
            zeek_data=zeek_data,
            config=config,
        )

        print(f"--- Triaging: [{level}] {dedup_key} ---")
        print(f"    {safe_get(alert, 'rule', 'description')}")

        # call_llm returns a 5-tuple (response_text, endpoint, model,
        # anonymized, anon_prompt) — same shape main.py unpacks. The old
        # single-name assignment here predated that signature and passed
        # the whole tuple into parse_llm_response (TypeError on first
        # alert; tuple is always truthy so the [FAIL] guard never fired).
        response_text, _ep_name, _llm_model, _anonymized, _anon_prompt = \
            call_llm(prompt, config)

        if not response_text:
            print("    [FAIL] No response from LLM\n")
            continue

        parsed = parse_llm_response(response_text)
        print(f"    ENDPOINT   : {_ep_name} ({_llm_model})")

        print(f"    VERDICT    : {parsed['verdict']}")
        print(f"    CONFIDENCE : {parsed['confidence']}")
        print(f"    SUMMARY    : {parsed['summary']}")
        print(f"    REASONING  : {parsed['reasoning']}")
        print(f"    MISSING    : {parsed['missing_info']}")
        print(f"    EMAIL      : {'YES' if should_email(parsed, config) else 'no'}")
        if parsed.get("parse_error"):
            print(f"    PARSE ERR  : {parsed['parse_error']}")
        print()

        triaged += 1
        if triaged >= 3:
            break

    conn.close()
    print(f"Triaged {triaged} alert(s)")
    print("=== Done ===")
