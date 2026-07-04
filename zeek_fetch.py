#!/usr/bin/env python3
"""
jrSOCtriage - Zeek Fetcher Module
Reads Zeek conn.log and dns.log for flows involving alert IPs.
Only called when src/dst IPs are present in the alert.

REQUIREMENT — Zeek must be in TSV log mode (the default). This reader parses
the TSV `#fields` header and tab-separated rows. If Zeek is configured for
JSON logs (json-streaming / the `json-logs` policy), there is no `#fields`
header, so the reader silently skips every row and returns empty Zeek context
with NO error. Verify the Zeek sensor logs TSV before pointing jrSOCtriage at
it. JSON / dual-format support is planned as a v1.1 feature; until then TSV is
a hard requirement (see running instructions).
"""

import gzip
import time
import json
import logging
import os
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

from ingest import safe_get

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Zeek log helpers
# ---------------------------------------------------------------------------

def open_zeek_log(path):
    """Open a Zeek log file, handling gzip if needed."""
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def zeek_log_time_range(path):
    """
    Read just the header lines of a Zeek log to get #start and #close times.
    Returns (start_dt, close_dt) or (None, None) if not found.
    Reads only first 20 lines so it's fast.
    """
    start_dt = close_dt = None
    try:
        with open_zeek_log(path) as f:
            for i, line in enumerate(f):
                if i > 20:
                    break
                line = line.strip()
                if line.startswith("#open") or line.startswith("#start"):
                    # Zeek uses #open YYYY-MM-DD-HH-MM-SS format
                    parts = line.split()
                    if len(parts) >= 2:
                        val = parts[1]
                        # Handle both epoch and YYYY-MM-DD-HH-MM-SS formats.
                        # parse_zeek_ts RETURNS None on non-epoch input (it
                        # does not raise), so the dash-format fallback must be
                        # gated on `is None`, not on an exception — otherwise
                        # it is dead code and standard Zeek headers yield None.
                        start_dt = parse_zeek_ts(val)
                        if start_dt is None:
                            try:
                                start_dt = datetime.strptime(val, "%Y-%m-%d-%H-%M-%S").replace(tzinfo=timezone.utc)
                            except ValueError:
                                pass
                elif line.startswith("#close"):
                    parts = line.split()
                    if len(parts) >= 2:
                        val = parts[1]
                        close_dt = parse_zeek_ts(val)
                        if close_dt is None:
                            try:
                                close_dt = datetime.strptime(val, "%Y-%m-%d-%H-%M-%S").replace(tzinfo=timezone.utc)
                            except ValueError:
                                pass
                if start_dt and close_dt:
                    break
    except (OSError, IOError):
        pass
    return start_dt, close_dt


def log_covers_window(path, from_dt, to_dt):
    """
    Returns True if the Zeek log file covers any part of the query window.
    If we can't read the header, assume it might be relevant and include it.
    """
    start_dt, close_dt = zeek_log_time_range(path)
    if start_dt is None and close_dt is None:
        return True  # can't tell, include it
    if close_dt and close_dt < from_dt:
        return False  # log ended before our window starts
    if start_dt and start_dt > to_dt:
        return False  # log started after our window ends
    return True


def parse_zeek_ts(ts_str):
    """Convert Zeek epoch timestamp string to datetime."""
    try:
        return datetime.fromtimestamp(float(ts_str), tz=timezone.utc)
    except (ValueError, TypeError):
        return None


def _parse_filename_window(path, alert_date_str, tz_offset_hours=None):
    """
    Parse time window from Zeek archive filename.
    Format: conn.HH:MM:SS-HH:MM:SS.log.gz
    Filenames are in LOCAL time. Returns (start_dt, end_dt) in UTC.
    tz_offset_hours: local timezone offset from UTC (e.g. -5 for CDT)
    """
    name = Path(path).name
    match = re.search(r'(\d{2}:\d{2}:\d{2})-(\d{2}:\d{2}:\d{2})', name)
    if not match:
        return None, None
    try:
        # Parse as local time then convert to UTC
        if tz_offset_hours is not None:
            local_tz = timezone(timedelta(hours=tz_offset_hours))
        else:
            # Use system local timezone
            local_tz = datetime.now().astimezone().tzinfo

        start_str = f"{alert_date_str}T{match.group(1)}"
        end_str   = f"{alert_date_str}T{match.group(2)}"
        start_dt  = datetime.fromisoformat(start_str).replace(tzinfo=local_tz).astimezone(timezone.utc)
        end_dt    = datetime.fromisoformat(end_str).replace(tzinfo=local_tz).astimezone(timezone.utc)
        # Handle midnight rollover
        if end_dt <= start_dt:
            end_dt += timedelta(days=1)
        return start_dt, end_dt
    except ValueError:
        return None, None


def find_zeek_logs(current_log_dir, archive_log_dir, log_name, alert_time=None, config=None):
    """
    Find Zeek log files for a given log name and alert time.

    Two separate path arguments because Zeek's default rotation postprocessor
    writes current logs to one directory (e.g. /opt/zeek/logs/current) and
    dated rollover archives to another (e.g. /var/log/zeek-archive/YYYY-MM-DD/).
    These often live on the same mount but don't have to — archives are
    commonly moved to bulk storage on a separate volume.

    Expected archive layout (matches stock Zeek rotation postprocessor):
        archive_log_dir/
          YYYY-MM-DD/
            conn.HH:MM:SS-HH:MM:SS.log.gz
            dns.HH:MM:SS-HH:MM:SS.log.gz
            ...

    For archived logs, parses the time window from the filename directly
    (format: conn.HH:MM:SS-HH:MM:SS.log.gz) to find the right hourly file.
    Falls back to current/ log for recent alerts.
    Returns list of matching paths.
    """
    current_dir = Path(current_log_dir)
    archive_dir = Path(archive_log_dir)

    found = []

    if not alert_time:
        # No time context - just return current log
        current_log = current_dir / f"{log_name}.log"
        if current_log.exists():
            found.append(current_log)
        return found

    # Check current log - use header check since filename has no time range
    current_log = current_dir / f"{log_name}.log"
    if current_log.exists() and log_covers_window(current_log,
            alert_time - timedelta(minutes=1), alert_time + timedelta(minutes=1)):
        found.append(current_log)

    # Check dated archive directory
    # Zeek filenames use LOCAL time - convert alert UTC time to local
    tz_offset = None
    if config:
        tz_offset = config.get("timezone", {}).get("zeek_local_tz_offset", None)
    if tz_offset is not None:
        alert_local = alert_time.astimezone(timezone(timedelta(hours=tz_offset)))
    else:
        alert_local = alert_time.astimezone()
    dates_to_check = [alert_local.strftime("%Y-%m-%d")]
    # Also check adjacent day since UTC/local conversion can shift the date
    dates_to_check.append(
        (alert_local - timedelta(days=1)).strftime("%Y-%m-%d")
    )
    dates_to_check.append(
        (alert_local + timedelta(days=1)).strftime("%Y-%m-%d")
    )

    for date_str in dates_to_check:
        dated_dir = archive_dir / date_str
        if not dated_dir.exists():
            continue
        for f in sorted(dated_dir.glob(f"{log_name}.*.log.gz")):
            start_dt, end_dt = _parse_filename_window(f, date_str, tz_offset_hours=tz_offset)
            if start_dt is None:
                # Can't parse filename - include it as fallback
                found.append(f)
                continue
            # Include if alert_time falls within this file's window
            window_start = alert_time - timedelta(minutes=1)
            window_end   = alert_time + timedelta(minutes=1)
            if start_dt <= window_end and end_dt >= window_start:
                found.append(f)

    return found


# ---------------------------------------------------------------------------
# Zeek log reader - generic reader used for conn.log, dns.log, ntlm.log
# All Zeek logs share the same TSV format with #fields header.
# The reader dynamically uses the field names from the file header, so it
# works for any Zeek log type without needing a per-log field constant.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Performance: result cache + tail-seek
#
# WHY (2026-06-11 LOAC regression investigation): read_zeek_log scanned the
# CURRENT spool log front-to-back on every fetch and applied the time window
# per-row in Python. The window caps what RETURNS, not what is READ — so
# per-fetch cost grew with the spool file all hour, inside every worker
# thread, on the GIL. Two fixes:
#   1. RESULT CACHE: alert clones from the same source host request the
#      identical (log, ips, window) within seconds of each other (the LOAC
#      journal shows the same fetch repeated dozens of times per minute).
#      60s TTL, small LRU-ish cap. Returns a shallow copy so callers that
#      mutate row dicts don't poison the cache.
#   2. TAIL-SEEK (plain files only; gzip archives are bounded hourly files
#      and keep the full scan): the query window is recent, the file is
#      append-ordered by connection CLOSE time while ts is START time, so
#      we read backward from EOF in doubling blocks until the oldest row in
#      the block predates from_dt by TAIL_SLACK, then parse just that tail.
#      TAIL_SLACK covers close-time lag: an in-window row can be written up
#      to its connection's duration after from_dt, so rows from connections
#      longer than TAIL_SLACK could in principle be ordered after our stop
#      point and be missed. 15 min of slack makes that rare, and this data
#      is best-effort triage context, not forensic ground truth — the
#      tradeoff is documented rather than hidden.
# ---------------------------------------------------------------------------
import threading as _threading
from collections import OrderedDict

# REG-20: OrderedDict so eviction is O(1) popitem(last=False) instead of an
# O(n) min(key=timestamp) scan UNDER _zeek_cache_lock on every cache insert.
# The old scan was held under the lock while a wave of cache-missing workers
# queued behind it — a convoy seed (observed: workers parked in zeek). Validity:
# the read path does NOT refresh an entry's timestamp on a hit (plain .get,
# returns a copy), so insertion order == age order and popitem(last=False)
# evicts the true oldest. The ONE case that would break that — re-inserting an
# already-present key after TTL expiry with a fresh timestamp — is handled by
# move_to_end on insert (below), so position always tracks the newest timestamp
# for that key.
_zeek_cache = OrderedDict()
_zeek_cache_lock = _threading.Lock()
_ZEEK_CACHE_TTL_S = 60
_ZEEK_CACHE_MAX = 256
TAIL_SLACK_S = 15 * 60
_TAIL_INITIAL_BLOCK = 4 * 1024 * 1024  # 4 MB


def _read_header_fields(path):
    """Read the #fields header from the top of a Zeek TSV log."""
    try:
        with open(path, "r", errors="replace") as f:
            for _ in range(64):
                line = f.readline()
                if not line:
                    break
                if line.startswith("#fields"):
                    return line.strip().split("\t")[1:]
                if line and not line.startswith("#"):
                    break
    except (OSError, IOError):
        pass
    return None


def _tail_lines(path, from_dt):
    """Return decoded lines from the tail of a plain (non-gzip) log,
    starting at a point safely before from_dt (see TAIL_SLACK_S note
    above). Falls back to None (caller does full scan) on any surprise."""
    try:
        size = os.path.getsize(path)
        if size <= _TAIL_INITIAL_BLOCK:
            return None  # small file — full scan is already cheap
        block = _TAIL_INITIAL_BLOCK
        cutoff = from_dt.timestamp() - TAIL_SLACK_S
        with open(path, "rb") as f:
            while True:
                f.seek(max(0, size - block))
                data = f.read()
                text = data.decode("utf-8", errors="replace")
                lines = text.split("\n")
                if size - block > 0:
                    lines = lines[1:]  # drop partial first line
                # oldest parsable ts in this block
                first_ts = None
                for ln in lines:
                    if not ln or ln.startswith("#"):
                        continue
                    ts_str = ln.split("\t", 1)[0]
                    try:
                        first_ts = float(ts_str)
                    except ValueError:
                        continue
                    break
                if block >= size:
                    return lines  # block covers whole file
                if first_ts is not None and first_ts < cutoff:
                    return lines  # tail reaches safely past the window
                block *= 2
    except (OSError, IOError, ValueError):
        return None


def read_zeek_log(log_path, target_ips, from_dt, to_dt):
    """
    Read a Zeek TSV log and return rows involving target_ips
    within the time window. Used for conn.log, dns.log, ntlm.log.

    Field names are read from the #fields header line in the file, so
    this works for any Zeek log type. Results are cached for 60s per
    (path, ips, window) and current-log reads use tail-seek — see the
    performance block above.
    """
    # Cache key quantizes the window to 30s buckets: clone alerts from the
    # same source host produce windows shifted by ~1s of alert time, which
    # made exact-window keys miss on every call (observed live: windows
    # 03:48:09 vs 03:48:10 for identical IP sets). The zeek query window is
    # 30s-4min wide, so coarsening the bucket to 30s shifts which rows return
    # by a negligible amount while collapsing many more near-identical clone
    # windows onto the same cache entry (a 10s bucket still missed on windows
    # that straddled a bucket edge ~1s apart). This data is best-effort triage
    # context; a few seconds of window imprecision does not change the verdict.
    _b = 30
    _fk = int(from_dt.timestamp() // _b)
    _tk = int(to_dt.timestamp() // _b)
    cache_key = (str(log_path), frozenset(target_ips), _fk, _tk)
    now = time.time()
    with _zeek_cache_lock:
        hit = _zeek_cache.get(cache_key)
        if hit and now - hit[0] < _ZEEK_CACHE_TTL_S:
            return list(hit[1])

    results = _read_zeek_log_uncached(log_path, target_ips, from_dt, to_dt)

    with _zeek_cache_lock:
        if len(_zeek_cache) >= _ZEEK_CACHE_MAX and cache_key not in _zeek_cache:
            # REG-20: O(1) evict-oldest. Valid because a hit never refreshes the
            # timestamp, so insertion order == age order. Only evict when adding
            # a genuinely new key (a re-insert of an existing key doesn't grow
            # the cache, so it must not evict).
            _zeek_cache.popitem(last=False)
        _zeek_cache[cache_key] = (now, results)
        # If this key already existed (expired entry just recomputed), it kept
        # its OLD position but now carries a NEWER timestamp; move it to the end
        # so position tracks newest-timestamp and popitem(last=False) stays
        # equal to oldest-by-time.
        _zeek_cache.move_to_end(cache_key)
    return list(results)


def _read_zeek_log_uncached(log_path, target_ips, from_dt, to_dt):
    results = []
    fields = None

    # Tail-seek path for plain current logs
    p = str(log_path)
    if not p.endswith(".gz"):
        tail = _tail_lines(p, from_dt)
        if tail is not None:
            fields = _read_header_fields(p)
            if fields:
                # ts lives in column 0 of every Zeek TSV: filter on the raw
                # float BEFORE building the row dict. The tail block holds
                # tens of thousands of rows to keep a few hundred; dict
                # construction per discarded row was the dominant CPU cost
                # of the whole fetch.
                _f_ts = from_dt.timestamp()
                _t_ts = to_dt.timestamp()
                for line in tail:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) < len(fields):
                        continue
                    try:
                        _raw_ts = float(parts[0])
                    except ValueError:
                        continue
                    if not (_f_ts <= _raw_ts <= _t_ts):
                        continue
                    row = dict(zip(fields, parts))
                    ts = parse_zeek_ts(row.get("ts"))
                    if not ts or not (from_dt <= ts <= to_dt):
                        continue
                    orig_h = row.get("id.orig_h", "")
                    resp_h = row.get("id.resp_h", "")
                    if not any(ip in (orig_h, resp_h) for ip in target_ips):
                        continue
                    results.append(row)
                return results
            # header unreadable — fall through to full scan

    try:
        with open_zeek_log(log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Zeek TSV header lines
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue

                if fields is None:
                    continue

                parts = line.split("\t")
                if len(parts) < len(fields):
                    continue

                # Cheap ts prefilter on column 0 before dict construction
                # (same rationale as the tail path above).
                try:
                    if not (from_dt.timestamp() <= float(parts[0])
                            <= to_dt.timestamp()):
                        continue
                except ValueError:
                    continue

                row = dict(zip(fields, parts))

                # Timestamp filter
                ts = parse_zeek_ts(row.get("ts"))
                if not ts or not (from_dt <= ts <= to_dt):
                    continue

                # IP filter
                orig_h = row.get("id.orig_h", "")
                resp_h = row.get("id.resp_h", "")
                if not any(ip in (orig_h, resp_h) for ip in target_ips):
                    continue

                results.append(row)

    except (OSError, IOError) as e:
        logger.warning(f"Could not read {log_path}: {e}")

    return results


# Backwards-compatible wrappers in case anything imports the old names
read_conn_log = read_zeek_log
read_dns_log  = read_zeek_log
read_ntlm_log = read_zeek_log


# ---------------------------------------------------------------------------
# Time window builder
# ---------------------------------------------------------------------------

def build_zeek_window(alert_time, window_minutes=0.5):
    """Return (from_dt, to_dt) datetimes around alert_time."""
    half = timedelta(minutes=window_minutes / 2)
    return alert_time - half, alert_time + half


def _resolve_zeek_paths(zeek_cfg):
    """
    Resolve current_log_dir and archive_log_dir from zeek config with
    backward compatibility for the old single-value 'log_dir' field.

    Preference order:
      1. Explicit 'current_log_dir' + 'archive_log_dir' (new, preferred)
      2. Legacy 'log_dir' → treated as current; archive defaults to parent
         (matches pre-split behavior where archives were assumed to be
         siblings of current/ under a shared parent directory)

    Returns (current_log_dir, archive_log_dir) or (None, None) if neither
    form is usable. Logs a one-time deprecation warning if the legacy
    'log_dir' form is in use.
    """
    current = zeek_cfg.get("current_log_dir", "").strip()
    archive = zeek_cfg.get("archive_log_dir", "").strip()
    legacy  = zeek_cfg.get("log_dir", "").strip()

    if current:
        # New form. If archive not set, default to parent of current for
        # backward compat with symlink-based single-mount deployments.
        if not archive:
            archive = str(Path(current).parent)
        return current, archive

    if legacy:
        # Legacy form. Warn once, then behave as before.
        if not _resolve_zeek_paths._warned:
            logger.warning(
                "Zeek config uses deprecated 'log_dir' — please switch to "
                "'current_log_dir' and 'archive_log_dir'. Treating 'log_dir' "
                "as current_log_dir with archives at its parent directory."
            )
            _resolve_zeek_paths._warned = True
        return legacy, str(Path(legacy).parent)

    return None, None


_resolve_zeek_paths._warned = False


# ---------------------------------------------------------------------------
# Master Zeek fetch
# ---------------------------------------------------------------------------

def _fetch_log_type(log_name, current_log_dir, archive_log_dir,
                    target_ips, from_dt, to_dt, alert_time, config):
    """
    Fetch a single Zeek log type (conn, dns, ntlm) with uid-based deduplication.

    The current log and any matching archives may both contain rows for the
    same connection (rotation overlap; current is the next file's predecessor
    until rollover completes). Dedup by Zeek connection uid prevents the LLM
    from seeing the same flow twice. Returns a list of row dicts.
    """
    rows = []
    seen_uids = set()
    for log_path in find_zeek_logs(current_log_dir, archive_log_dir,
                                   log_name, alert_time, config=config):
        for row in read_zeek_log(log_path, target_ips, from_dt, to_dt):
            uid = row.get("uid", "")
            if uid and uid not in seen_uids:
                seen_uids.add(uid)
                rows.append(row)
    return rows


def effective_zeek_window_minutes(config, alert):
    """
    Compute the EFFECTIVE Zeek context window in minutes for this alert:
    sources.zeek.context_window_minutes (default 0.5), expanded to at
    least 4.0 for multi-fire alerts (firedtimes > 1) to cover the full
    dedup trail, capped there to prevent prompt bloat.

    Single source of truth: used by fetch_zeek_flows for the actual
    fetch window AND by prompt_builder for the ZEEK FLOWS section
    header — so the prompt's window label always matches what was
    actually fetched. (Before this helper, the header reused the
    GRAYLOG window value: a fired-many alert fetched 4 minutes of
    flows under a header claiming the graylog window, e.g. "1 minute".)
    """
    window_minutes = config.get("sources", {}).get("zeek", {}).get(
        "context_window_minutes", 0.5
    )

    # For multi-fire alerts, expand window to cover full dedup trail
    # capped at 4 minutes to prevent prompt bloat
    fired_times = safe_get(alert, "rule", "firedtimes", default=1)
    try:
        if int(fired_times) > 1:
            window_minutes = max(window_minutes, 4.0)
    except (ValueError, TypeError):
        pass
    return window_minutes


def fetch_zeek_flows(config, alert, alert_ips, alert_time):
    """
    Main entry point. Fetches conn.log and dns.log entries
    for all IPs in alert_ips around alert_time.

    Returns dict:
    {
        "conn": [list of conn rows],
        "dns":  [list of dns rows],
        "ntlm": [list of ntlm rows],
    }
    Only call this when alert_ips is non-empty.
    """
    zeek_cfg = config.get("sources", {}).get("zeek", {})

    if not zeek_cfg.get("enabled", False):
        logger.debug("Zeek source disabled in config")
        return {"conn": [], "dns": [], "ntlm": []}

    current_log_dir, archive_log_dir = _resolve_zeek_paths(zeek_cfg)
    if not current_log_dir:
        logger.warning("Zeek current_log_dir not configured")
        return {"conn": [], "dns": [], "ntlm": []}

    if not alert_time:
        logger.warning("No alert timestamp for Zeek window")
        return {"conn": [], "dns": [], "ntlm": []}

    window_minutes = effective_zeek_window_minutes(config, alert)

    from_dt, to_dt = build_zeek_window(alert_time, window_minutes)
    target_ips = set(alert_ips)

    logger.info(
        f"Zeek fetch | IPs: {target_ips} | "
        f"window: {from_dt.strftime('%H:%M:%S')} - {to_dt.strftime('%H:%M:%S')}"
    )

    conn_rows = _fetch_log_type("conn", current_log_dir, archive_log_dir,
                                target_ips, from_dt, to_dt, alert_time, config)
    dns_rows  = _fetch_log_type("dns",  current_log_dir, archive_log_dir,
                                target_ips, from_dt, to_dt, alert_time, config)
    ntlm_rows = _fetch_log_type("ntlm", current_log_dir, archive_log_dir,
                                target_ips, from_dt, to_dt, alert_time, config)

    logger.debug(f"Zeek returned {len(conn_rows)} conn, {len(dns_rows)} dns, {len(ntlm_rows)} ntlm row(s)")
    return {"conn": conn_rows, "dns": dns_rows, "ntlm": ntlm_rows}


# ---------------------------------------------------------------------------
# Format for prompt
# ---------------------------------------------------------------------------

def format_zeek_for_prompt(zeek_data, max_conn=20, max_dns=10):
    """
    Format Zeek conn and dns rows into a readable block for the LLM.
    Returns string or None if nothing to show.
    """
    lines = []

    conn_rows = zeek_data.get("conn", [])
    if conn_rows:
        lines.append("CONNECTIONS:")
        for row in conn_rows[:max_conn]:
            orig_h  = row.get("id.orig_h", "?")
            orig_p  = row.get("id.orig_p", "?")
            resp_h  = row.get("id.resp_h", "?")
            resp_p  = row.get("id.resp_p", "?")
            proto   = row.get("proto", "?")
            service = row.get("service", "-")
            dur     = row.get("duration", "-")
            state   = row.get("conn_state", "?")
            o_bytes = row.get("orig_bytes", "-")
            r_bytes = row.get("resp_bytes", "-")
            lines.append(
                f"  {orig_h}:{orig_p} -> {resp_h}:{resp_p} "
                f"| {proto}/{service} | {state} | "
                f"dur={dur}s orig={o_bytes}B resp={r_bytes}B"
            )

    dns_rows = zeek_data.get("dns", [])
    if dns_rows:
        lines.append("DNS QUERIES:")
        for row in dns_rows[:max_dns]:
            orig_h  = row.get("id.orig_h", "?")
            query   = row.get("query", "?")
            qtype   = row.get("qtype_name", "?")
            rcode   = row.get("rcode_name", "?")
            answers = row.get("answers", "-")
            lines.append(
                f"  {orig_h} -> {query} [{qtype}] "
                f"rcode={rcode} answers={answers}"
            )

    ntlm_rows = zeek_data.get("ntlm", [])
    if ntlm_rows:
        lines.append("NTLM AUTHENTICATIONS:")
        for row in ntlm_rows[:10]:
            orig_h   = row.get("id.orig_h", "?")
            resp_h   = row.get("id.resp_h", "?")
            username = row.get("username", "-")
            hostname = row.get("hostname", "-")
            domain   = row.get("domainname", "-")
            success  = row.get("success", "?")
            lines.append(
                f"  {orig_h} -> {resp_h} | user={username} "
                f"host={hostname} domain={domain} success={success}"
            )

    return "\n".join(lines) if lines else None


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    from ingest import load_config, load_hosts, read_new_alerts
    from enrich import extract_ips
    from graylog_fetch import parse_alert_timestamp

    # KNOWN BUG (documented, not fixed): read_new_alerts() below advances the
    # shared .ingest_position, so running this smoke test against a LIVE
    # pipeline makes the pipeline skip the alerts consumed here. Run with the
    # pipeline stopped, or on the test platform. Same class as the ntopng /
    # email smoke tests; hard to decouple because the test needs real alert
    # IPs to exercise the Zeek window+filter against actual flows.
    print("=== jrSOCtriage Zeek Fetcher Smoke Test ===\n")

    config     = load_config("config.json")
    hosts_data = load_hosts(config)

    zeek_cfg = config.get("sources", {}).get("zeek", {})
    current_log_dir, archive_log_dir = _resolve_zeek_paths(zeek_cfg)
    print(f"Zeek current dir : {current_log_dir}")
    print(f"Zeek archive dir : {archive_log_dir}")
    print(f"Enabled          : {zeek_cfg.get('enabled', False)}")

    conn_logs = find_zeek_logs(current_log_dir, archive_log_dir, "conn")
    dns_logs  = find_zeek_logs(current_log_dir, archive_log_dir, "dns")
    print(f"conn.log files found : {len(conn_logs)}")
    print(f"dns.log files found  : {len(dns_logs)}\n")

    alerts = list(read_new_alerts(config))
    print(f"Loaded {len(alerts)} alert(s)\n")

    tested = 0
    for alert in alerts:
        ips = extract_ips(alert)
        all_ips = ips["all"]

        # Only test alerts that have IPs
        if not all_ips:
            continue

        agent_name = safe_get(alert, "agent", "name")
        alert_time = parse_alert_timestamp(alert)

        print(f"--- Agent: {agent_name} | IPs: {all_ips} ---")
        print(f"    Alert time: {alert_time}")

        zeek_data = fetch_zeek_flows(config, alert, all_ips, alert_time)
        formatted = format_zeek_for_prompt(zeek_data)

        if formatted:
            print(formatted)
        else:
            print("  No Zeek flows found in window")

        print()
        tested += 1
        if tested >= 3:
            break

    if tested == 0:
        print("No alerts with IPs found in current batch - Zeek fetch correctly skipped")

    print("=== Done ===")
