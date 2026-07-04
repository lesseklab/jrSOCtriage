#!/usr/bin/env python3
"""
jrSOCtriage - Graylog Fetcher Module
Queries Graylog REST API for logs related to a host
within a time window around an alert timestamp.
"""

import logging
from datetime import datetime, timezone, timedelta

import time
import requests

import perf_diag

# ---------------------------------------------------------------------------
# Shared HTTP session + result cache
#
# WHY (2026-06-11 LOAC investigation, ablation-confirmed): the hot path
# called bare requests.get() per query, constructing a new connection
# pool + TCP connection every time — ~24ms of CPU per shipped alert and
# the single largest term in the throughput regression. One module-level
# Session with a pool sized for the worker count fixes the churn; a
# short-TTL result cache keyed on a 10-second window bucket fixes the
# redundancy (clone alerts from one source host issue near-identical
# queries shifted by ~1s — same trick as zeek_fetch's cache).
# ---------------------------------------------------------------------------
import threading as _threading
from collections import OrderedDict
from requests.adapters import HTTPAdapter as _HTTPAdapter

_session = None
_session_lock = _threading.Lock()

def _get_session():
    """Lazily build the shared session (thread-safe, built once)."""
    global _session
    if _session is None:
        with _session_lock:
            if _session is None:
                s = requests.Session()
                adapter = _HTTPAdapter(pool_connections=4, pool_maxsize=64)
                s.mount("http://", adapter)
                s.mount("https://", adapter)
                _session = s
    return _session

_gl_cache = OrderedDict()
_gl_cache_lock = _threading.Lock()
_GL_CACHE_TTL_S = 60
_GL_CACHE_MAX = 256


from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def get_auth(config):
    """Build HTTPBasicAuth from config."""
    auth_cfg = config.get("sources", {}).get("graylog", {}).get("auth", {})
    username = auth_cfg.get("username", "")
    password = auth_cfg.get("password", "")
    return HTTPBasicAuth(username, password)


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def parse_alert_timestamp(alert):
    """
    Parse Wazuh alert timestamp to UTC datetime.
    Handles formats like '2026-04-08T00:00:03.228+0000'.
    Returns datetime or None.
    """
    from ingest import safe_get
    ts_str = safe_get(alert, "timestamp")
    if ts_str == "N/A":
        return None
    try:
        # Normalize +0000 to +00:00 for fromisoformat
        ts_str = ts_str.replace("+0000", "+00:00")
        return datetime.fromisoformat(ts_str)
    except ValueError:
        logger.warning(f"Could not parse timestamp: {ts_str}")
        return None


def effective_context_time(alert, alert_time):
    """
    Return the datetime that the Graylog (and other context) windows
    should be anchored on for this alert.

    For most alerts this is just `alert_time` — when Wazuh emitted the
    alert. But Wazuh's syscheck FIM module runs in scheduled mode by
    default, which means `alert.timestamp` reflects when the scheduled
    scan ran, NOT when the file actually changed. The change could have
    happened many minutes earlier, outside the context window.

    When `syscheck.mtime_after` is present and recent (within the last
    hour), use it instead. This shifts the context window to the actual
    time of file modification, where the surrounding logs are likely to
    show what process or user caused it.

    The "within the last hour" guard protects against pathological cases
    where mtime is wildly old (e.g., baseline scan after long downtime,
    or a touch-back-dated file). For those, fall back to alert_time so
    we are at least pulling something coherent.

    Returns a datetime (the anchor) or None if neither timestamp is usable.
    """
    if not alert_time:
        return None

    from ingest import safe_get
    mtime_str = safe_get(alert, "syscheck", "mtime_after")
    if mtime_str == "N/A" or not mtime_str:
        return alert_time

    # mtime_after format example: "2026-04-29T15:25:38" (no timezone).
    # Wazuh emits it in the manager's local time; treat as UTC since
    # that is jrSOCtriage's working timezone for everything else.
    # If a deployment runs Wazuh in a non-UTC timezone, this assumption
    # could shift logs by hours — flag in docs.
    try:
        # NOTE: this normalizes naive ("no + and no Z") to UTC and fixes
        # +0000 -> +00:00. It does NOT handle an explicit negative offset
        # like "-0500" (no '+', no 'Z' -> treated as naive, gets +00:00
        # appended -> parsed in the wrong zone). In practice mtime_after
        # is timezone-less (see comment above), and even a mis-zoned parse
        # is contained: the 0<=delta<=3600 guard below would reject the
        # shifted value and fall back to alert_time, so the failure mode is
        # "ignore mtime", not "use a wrong anchor". Revisit with a proper
        # offset-aware normalizer if a deployment is found emitting offsets.
        if "+" not in mtime_str and "Z" not in mtime_str:
            mtime_str_norm = mtime_str + "+00:00"
        else:
            mtime_str_norm = mtime_str.replace("+0000", "+00:00")
        mtime_dt = datetime.fromisoformat(mtime_str_norm)
    except ValueError:
        logger.warning(f"Could not parse syscheck mtime_after: {mtime_str}")
        return alert_time

    delta = (alert_time - mtime_dt).total_seconds()
    # Only use mtime_after if it is in the past relative to the alert
    # (which it should be — the scan finds an existing change), and not
    # more than 1 hour earlier. Outside that range, fall back.
    if 0 <= delta <= 3600:
        logger.info(
            f"Anchoring context window on syscheck mtime_after ({mtime_dt.isoformat()}) "
            f"instead of alert_time ({alert_time.isoformat()}) — "
            f"delta {int(delta)}s"
        )
        return mtime_dt
    return alert_time


def build_time_window(alert_time, window_minutes):
    """
    Return (from_str, to_str) in ISO8601 UTC for Graylog query.
    """
    half = timedelta(minutes=window_minutes / 2)
    from_dt = alert_time - half
    to_dt   = alert_time + half
    # We stamp a literal 'Z', so the wall-clock fields MUST be UTC. An
    # alert_time carrying a non-UTC offset (e.g. a Wazuh manager emitting
    # +0200) would otherwise be formatted in its local wall-clock and
    # mislabeled Z, shifting the whole window by the offset. Convert
    # aware datetimes to UTC first. Naive datetimes are left as-is
    # (assumed already UTC — jrSOCtriage's working timezone).
    if from_dt.tzinfo is not None:
        from_dt = from_dt.astimezone(timezone.utc)
        to_dt   = to_dt.astimezone(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    return from_dt.strftime(fmt), to_dt.strftime(fmt)


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------

def _escape_lucene_phrase(value):
    """
    Escape a value for safe embedding inside a Lucene DOUBLE-QUOTED phrase.

    Within a quoted phrase Lucene treats every metacharacter literally
    EXCEPT the backslash (escape) and the double-quote (which would close
    the phrase). So only those two need escaping — backslash first, then
    quote, to avoid double-escaping. A hostname containing a stray quote
    would otherwise produce a malformed query (-> HTTP 400 -> that host
    silently gets no context). Mirrors the input-escaping discipline
    already applied to hostnames in interface.py (HTML context there;
    Lucene context here — different special chars, same principle).
    """
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def build_query(agent_name, extra_terms=None):
    """
    Build a Graylog search query string.
    Searches by source name. Optionally adds extra terms.
    """
    safe_name = _escape_lucene_phrase(agent_name)
    # Match on `source` only. Grounded in the live index:
    #   - source           : exists, carries the hostname, matches the
    #                         raw upstream context logs. Kept.
    #   - host             : _exists_:host returns NO. Dropped.
    #   - gl2_source_input : exists, but its value is the Graylog INPUT's
    #                         ObjectId (observed: "69d6a2e693f76e5a770987fb"),
    #                         not a hostname — so gl2_source_input:"<host>"
    #                         never matched. Dropped.
    name_query = f'source:"{safe_name}"'
    if extra_terms:
        return f"({name_query}) AND ({extra_terms})"
    return f"({name_query})"


# ---------------------------------------------------------------------------
# Graylog search
# ---------------------------------------------------------------------------

def search_graylog(config, agent_name, alert_time, stream_id=None):
    """
    Query Graylog for logs from agent_name around alert_time.

    Args:
        config:      jrSOCtriage config dict
        agent_name:  Hostname to search for, matched against Graylog's
                     `source` field (see build_query)
        alert_time:  datetime to center the time window around
        stream_id:   Optional Graylog stream ID to scope the search

    Returns list of log message dicts, or empty list on failure.
    """
    gl_cfg = config.get("sources", {}).get("graylog", {})

    if not gl_cfg.get("enabled", False):
        perf_diag.cache("graylog", "disabled")
        logger.debug("Graylog source disabled in config")
        return []

    endpoint       = gl_cfg.get("endpoint", "").rstrip("/")
    window_minutes = gl_cfg.get("context_window_minutes", 0.5)  # default 30 seconds each side
    max_results    = gl_cfg.get("max_results", 100)
    # Default to True (secure) — opt-out via config for self-signed reverse
    # proxies. Matches the pattern used in ntopng_fetch.
    verify_ssl     = gl_cfg.get("verify_ssl", True)

    if not endpoint:
        logger.warning("Graylog endpoint not configured")
        return []

    if not alert_time:
        logger.warning("No alert timestamp, skipping Graylog fetch")
        return []

    # Security hint: plaintext HTTP means credentials and API responses
    # travel unencrypted. Fine on a trusted lab segment; a real concern
    # elsewhere. Warn once so the operator sees it. Mirrors ntopng_fetch.
    if endpoint.startswith("http://") and not search_graylog._http_warned:
        logger.warning(
            "Graylog endpoint is http:// — credentials and API responses "
            "will be sent in cleartext. Put Graylog behind a TLS reverse "
            "proxy for any non-lab deployment."
        )
        search_graylog._http_warned = True

    from_str, to_str = build_time_window(alert_time, window_minutes)
    query = build_query(agent_name)

    # Graylog absolute search endpoint
    url = f"{endpoint}/api/search/universal/absolute"

    params = {
        "query": query,
        "from":  from_str,
        "to":    to_str,
        "limit": max_results,
        "sort":  "timestamp:asc",
    }

    # Scope to a specific stream if provided
    if stream_id:
        params["filter"] = f"streams:{stream_id}"

    # Result cache: 10s window bucket — clone alerts of one source host
    # query the same agent over windows shifted ~1s; bucketing makes them
    # cache hits (incl. the common 0-message result). TTL 60s, cap 256.
    _bucket = int(alert_time.timestamp() // 10)
    _ckey = (query, stream_id, _bucket, window_minutes, max_results)
    _now = time.time()
    with _gl_cache_lock:
        _hit = _gl_cache.get(_ckey)
        if _hit and _now - _hit[0] < _GL_CACHE_TTL_S:
            perf_diag.cache("graylog", "cache_hit")
            logger.debug(f"Graylog cache hit for {agent_name}")
            return list(_hit[1])

    perf_diag.cache("graylog", "cache_miss")
    try:
        perf_diag.cache("graylog", "real_query")
        logger.debug(f"Querying Graylog for {agent_name} | window: {from_str} to {to_str}")
        resp = _get_session().get(
            url,
            params=params,
            auth=get_auth(config),
            headers={"Accept": "application/json"},
            verify=verify_ssl,
            timeout=10,
        )

        if resp.status_code == 401:
            perf_diag.cache("graylog", "auth_error")
            logger.error("Graylog auth failed - check username/password in config")
            return []

        if resp.status_code == 400:
            perf_diag.cache("graylog", "bad_request")
            logger.error(f"Graylog bad request: {resp.text[:200]}")
            return []

        resp.raise_for_status()

        try:
            data = resp.json()
        except ValueError:
            perf_diag.cache("graylog", "error")
            logger.error(f"Graylog non-JSON response (first 500 chars): {resp.text[:500]}")
            return []

        messages = data.get("messages", [])
        logger.debug(f"Graylog returned {len(messages)} message(s) for {agent_name}")
        with _gl_cache_lock:
            # REG-19: O(1) evict-oldest (was O(n) min(key=timestamp) scan under
            # _gl_cache_lock on every insert). Same fix/validity as zeek REG-20
            # and enrich REG-10..13: the read path never refreshes an entry's
            # timestamp on a hit, so insertion order == age order and
            # popitem(last=False) evicts the true oldest. Evict only when adding
            # a genuinely NEW key (a re-insert of an existing expired key doesn't
            # grow the cache, so it must not evict). move_to_end on insert keeps
            # position tracking the newest timestamp for the expiry-refresh case
            # (re-inserted _ckey carries a fresh _now).
            if len(_gl_cache) >= _GL_CACHE_MAX and _ckey not in _gl_cache:
                _gl_cache.popitem(last=False)
            _gl_cache[_ckey] = (_now, messages)
            _gl_cache.move_to_end(_ckey)
        return list(messages)

    except requests.exceptions.ConnectionError:
        perf_diag.cache("graylog", "error")
        logger.error(f"Could not connect to Graylog at {endpoint}")
        return []
    except requests.exceptions.Timeout:
        perf_diag.cache("graylog", "timeout")
        logger.error("Graylog request timed out")
        return []
    except requests.exceptions.RequestException as e:
        perf_diag.cache("graylog", "error")
        logger.error(f"Graylog request failed: {e}")
        return []


# One-time HTTP-cleartext warning flag. Set after the first plaintext
# endpoint is observed so the warning doesn't repeat on every alert.
search_graylog._http_warned = False


# ---------------------------------------------------------------------------
# Format logs for prompt
# ---------------------------------------------------------------------------

def condense_repeated_logs(raw_lines):
    """
    Collapse consecutive identical messages into a single line with count.
    Comparison is on message text only, ignoring timestamp.
    Input: list of (ts, source, message) tuples
    Output: list of condensed (ts, source, message, count, last_ts) tuples
    """
    if not raw_lines:
        return []

    condensed = []
    prev_msg    = None
    prev_source = None
    count       = 0
    first_ts    = None
    last_ts     = None

    for ts, source, message in raw_lines:
        # Normalize message for comparison - strip whitespace
        msg_key = message.strip()

        if msg_key == prev_msg and source == prev_source:
            count  += 1
            last_ts = ts
        else:
            if prev_msg is not None:
                condensed.append((first_ts, prev_source, prev_msg, count, last_ts))
            prev_msg    = msg_key
            prev_source = source
            first_ts    = ts
            last_ts     = ts
            count       = 1

    if prev_msg is not None:
        condensed.append((first_ts, prev_source, prev_msg, count, last_ts))

    return condensed


def format_logs_for_prompt(messages, max_lines=30):
    """
    Convert Graylog message list to a readable block for the LLM prompt.
    Condenses repeated identical messages before applying max_lines cap.
    Returns a string, or None if no messages.
    """
    if not messages:
        return None

    # Build raw line tuples first
    raw_lines = []
    for msg in messages:
        m = msg.get("message", msg)
        # Coerce to str defensively: Graylog returns strings for these in
        # practice, but a non-string message/source/timestamp would break
        # the len()/strip()/format below with a TypeError. Cheap guard.
        ts      = str(m.get("timestamp", "?"))
        source  = str(m.get("source", "?"))
        message = str(m.get("message", "?"))

        # Truncate very long messages
        if len(message) > 200:
            message = message[:197] + "..."

        raw_lines.append((ts, source, message))

    # Condense repeated messages BEFORE applying max_lines cap
    condensed = condense_repeated_logs(raw_lines)

    # Now format and cap
    lines = []
    for ts, source, message, count, last_ts in condensed[:max_lines]:
        if count > 1:
            lines.append(f"{ts} | {source} | {message} (x{count}, last: {last_ts})")
        else:
            lines.append(f"{ts} | {source} | {message}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    from ingest import load_config, load_hosts, read_new_alerts, safe_get

    print("=== jrSOCtriage Graylog Fetcher Smoke Test ===\n")

    config     = load_config("config.json")
    hosts_data = load_hosts(config)

    # Connectivity check first
    gl_cfg   = config.get("sources", {}).get("graylog", {})
    endpoint = gl_cfg.get("endpoint", "").rstrip("/")
    print(f"[..] Testing Graylog connectivity at {endpoint} ...")

    try:
        resp = requests.get(
            f"{endpoint}/api/system",
            auth=get_auth(config),
            verify=gl_cfg.get("verify_ssl", False),
            timeout=5,
        )
        if resp.status_code == 200:
            info = resp.json()
            print(f"[OK] Connected to Graylog {info.get('version','?')} "
                  f"| cluster: {info.get('cluster_id','?')[:8]}...\n")
        elif resp.status_code == 401:
            print(f"[FAIL] Auth rejected - check credentials in config.json")
            exit(1)
        else:
            print(f"[WARN] Unexpected status {resp.status_code} - continuing anyway\n")
    except requests.exceptions.ConnectionError:
        print(f"[FAIL] Cannot reach Graylog at {endpoint}")
        exit(1)

    # Pull a few alerts and fetch logs for each
    alerts = list(read_new_alerts(config))
    print(f"Loaded {len(alerts)} alert(s)\n")

    seen_agents = set()
    tested = 0

    for alert in alerts:
        agent_name = safe_get(alert, "agent", "name")

        # Test one alert per unique agent to avoid hammering Graylog
        if agent_name in seen_agents:
            continue
        seen_agents.add(agent_name)

        alert_time = parse_alert_timestamp(alert)
        print(f"--- Agent: {agent_name} | Alert time: {alert_time} ---")

        messages = search_graylog(config, agent_name, alert_time)
        formatted = format_logs_for_prompt(messages)

        if formatted:
            print(f"  Sample log lines ({len(messages)} total):")
            for line in formatted.splitlines()[:5]:
                print(f"    {line}")
        else:
            print(f"  No logs returned for this host/window")

        print()
        tested += 1
        if tested >= 3:
            break

    print("=== Done ===")
