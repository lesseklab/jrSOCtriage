#!/usr/bin/env python3
"""
jrSOCtriage - Dedup Module
In-memory silence window check.
Gates the enrichment/triage pipeline — not the database.
Database records everything. This decides what gets processed.

The cache is kept from growing unbounded by periodic prune_cache()
calls from the main loop. If this module is used outside the normal
pipeline (e.g. from a one-off script that never prunes), the cache
will grow for the life of the process.
"""

import logging
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# INGEST-PERIOD ACCOUNTING
# ---------------------------------------------------------------------------
#
# Three counters bounded by the ingest-to-ingest period:
#   _STATS_INGEST  : alerts ingested at start of current window
#   _STATS_DEDUP   : of those, how many returned True from is_duplicate()
#   _STATS_STREAM2 : of those, how many returned False (passed dedup)
#
# In a no-lag window, _STATS_INGEST roughly equals _STATS_DEDUP +
# _STATS_STREAM2 plus still-in-flight alerts (inside is_duplicate, or
# queued waiting for a worker). Under backlog drain this is NOT an
# invariant: decisions for alerts ingested in earlier windows land in
# the current one, so the decision counters can temporarily exceed or
# trail the ingest count (the rate_pct>100 case documented in
# running_instructions). The [DEDUP] line deliberately emits the three
# raw counters and no derived difference: that same submit→decision
# lag makes (ingest - dedup - stream2) oscillate +N/-N between
# adjacent windows, so a difference field would not measure anything
# reliable. The watchdog reads inflight_count live under pending_lock and
# is the authoritative "is work being abandoned?" signal.
#
# Window starts: at top of each cycle, RIGHT BEFORE ingest.read_alerts is
# acted on (snapshot_and_reset() called with the new cycle's alert count).
# Window ends: at the same point in the NEXT cycle. So each [DEDUP] line
# describes exactly one ingest-to-ingest period.
#
# Located in dedup.py module-level (not lag_logger.py) so the counters are
# always exposed regardless of lag instrumentation toggle state.

_STATS_LOCK = threading.Lock()
_STATS_INGEST = 0
_STATS_DEDUP = 0
_STATS_STREAM2 = 0
_STATS_PERIOD_START_T = None
_STATS_INITIALIZED = False


def note_dedup_decision(was_dropped):
    """Called from is_duplicate() at the moment of decision.

    Atomic increment of the appropriate counter for the current window.
    Per-alert dedup latency is microseconds-to-ms, so a race against
    snapshot_and_reset is rare; when it does manifest, the decision
    lands in the adjacent window, so neighboring windows' counts can
    each be off by that alert relative to their ingest counts —
    harmless and self-correcting.
    """
    global _STATS_DEDUP, _STATS_STREAM2
    with _STATS_LOCK:
        if was_dropped:
            _STATS_DEDUP += 1
        else:
            _STATS_STREAM2 += 1


def snapshot_and_reset(n_new_ingest):
    """Close the just-finished window and open a new one.

    Called at the top of each cycle, immediately after ingest.read_alerts()
    returns. The just-closed window's data is returned for the caller to
    log; the new window opens with n_new_ingest as its ingest count.

    Returns (period_s, ingest, dedup, stream2, rate_pct).
    On the first cycle, period_s=0.0 and prior counts are all 0; caller
    should suppress the [DEDUP] emission for the bootstrap call.

    rate_pct = -1.0 sentinel when ingest=0 (no alerts in window) so
    quiet windows don't read as misleading 0%.

    Note: the tuple deliberately contains the three raw counters and
    no derived difference (ingest - dedup - stream2). That difference
    oscillates +N/-N across adjacent windows when worker
    submit→decision lag crosses a window boundary, so it would not
    measure anything reliable. The watchdog reads inflight_count live
    under pending_lock and is the authoritative "is work being
    abandoned?" signal.
    """
    global _STATS_INGEST, _STATS_DEDUP, _STATS_STREAM2
    global _STATS_PERIOD_START_T, _STATS_INITIALIZED
    with _STATS_LOCK:
        now = time.time()
        if not _STATS_INITIALIZED:
            period_s = 0.0
            prev_ingest = 0
            prev_dedup = 0
            prev_stream2 = 0
            rate_pct = -1.0
            _STATS_INITIALIZED = True
        else:
            period_s = now - _STATS_PERIOD_START_T
            prev_ingest = _STATS_INGEST
            prev_dedup = _STATS_DEDUP
            prev_stream2 = _STATS_STREAM2
            if prev_ingest > 0:
                rate_pct = 100.0 * prev_dedup / prev_ingest
            else:
                rate_pct = -1.0
        # Open new window
        _STATS_INGEST = n_new_ingest
        _STATS_DEDUP = 0
        _STATS_STREAM2 = 0
        _STATS_PERIOD_START_T = now
    return (period_s, prev_ingest, prev_dedup, prev_stream2, rate_pct)


# ---------------------------------------------------------------------------
# Dedup state - in memory, does not persist across restarts
# ---------------------------------------------------------------------------
#
# Cache shape: dedup_key -> (first_seen_epoch, last_seen_epoch, count)
#
# - first_seen: when this dedup_key first arrived (start of current
#               silence window). Used to decide escalation timing —
#               a dedup_key escalates again when (now - first_seen) >=
#               silence_seconds, regardless of how many duplicates
#               came in during the window. ALSO used as the window_ts
#               that identifies this window's row in alert_history, so
#               the window-close UPDATE finds the opener's row.
# - last_seen:  most recent occurrence of this dedup_key, including
#               duplicates that get suppressed. Used by enrich.py to
#               populate wazuh_last_seen so the prompt's "Alert trail"
#               line can show storm duration accurately.
# - count:      number of occurrences in the CURRENT window (opener + all
#               suppressed duplicates so far). Accumulated in memory; never
#               touches the DB per duplicate. Written to the DB only twice
#               per window: 1 at open (record_window_open), and the final
#               total at close (record_window_close). This is the
#               dedup-aggregated frequency scheme — the ~85-90% write
#               reduction vs the old per-raw-alert record_alert.
#
# WINDOW CLOSE: a window closes when its key re-anchors (a fresh occurrence
# arrives after silence expiry — handled in is_duplicate, which returns the
# closing window's (dedup_key, window_ts, count) for the caller to flush) or
# when prune_cache evicts a quiet key (flushed via the prune path). Both
# routes hand the final count to database.record_window_close.
#
# Lock scope is the critical section (read-then-write inside is_duplicate
# and the iteration in prune_cache), not the whole function. This keeps
# the held time to a few microseconds.
#
# LOCK-NESTING ORDER: is_duplicate calls note_dedup_decision while
# holding _lock, which takes _STATS_LOCK — the order is strictly
# _lock -> _STATS_LOCK and nothing may acquire them in reverse.
# (_STATS_LOCK sections are nanosecond counter bumps, so the nesting
# adds no meaningful hold time.) Related micro-note: prune_cache's
# debug line reads the cache length just after releasing _lock —
# a single len() is atomic under the GIL and the value is
# display-only. At v1.0-v1.6 scales (hundreds to
# tens of thousands of alerts/min) this is invisible. At v1.7 the
# substrate moves to Redis and the lock disappears entirely (Redis is
# the synchronization point); the public interface stays the same.

_dedup_cache = {}
_lock = threading.Lock()


# Returned by is_duplicate. `.is_dup` is the original boolean (True = drop).
# The close_* fields are populated ONLY when this call re-anchored an expired
# window — i.e. a prior window just closed and the caller should flush its
# final count to the DB via database.record_window_close. They are None on
# every other call (fresh key, or in-window duplicate).
from collections import namedtuple

DedupResult = namedtuple(
    "DedupResult",
    ["is_dup", "open_window_ts", "close_dedup_key", "close_window_ts", "close_count"],
)

# Convenience constructors keep the hot path readable.
# open_window_ts is set on the PASS paths (the window this alert opens or
# re-opens); the worker uses it as the timestamp for record_window_open so
# the later record_window_close UPDATE matches the same row. It is None on a
# duplicate drop (no window opened).
def _dup_no_close():
    return DedupResult(True, None, None, None, None)

def _pass_no_close(open_window_ts):
    return DedupResult(False, open_window_ts, None, None, None)

def _pass_with_close(open_window_ts, key, window_ts, count):
    return DedupResult(False, open_window_ts, key, window_ts, count)


def is_duplicate(dedup_key, silence_seconds):
    """
    Check if dedup_key has been seen within the silence window.
    Returns True if duplicate (drop from pipeline), False if new (process).

    The cache does NOT persist across restarts. This is a deliberate
    design choice: persisting dedup state would risk stale entries
    surviving code changes or silence-window adjustments, and in the
    worst case the pipeline would silently drop legitimate alerts
    because of state left behind by an earlier version. Accepting a
    small amount of duplicate processing right after a restart is
    preferable to that failure mode. The database has a complete
    record regardless, so no visibility is lost.

    Storm tracking: when a duplicate is detected, last_seen is updated
    to `now` while first_seen is preserved. This lets enrich.py read
    the actual most-recent-occurrence time via get_last_seen() rather
    than receiving the alert's own timestamp (which during a storm is
    only ever the timestamp of the first non-duplicate that got
    through). first_seen is the anchor for silence-window math, so
    the hard escalation cadence (silence_seconds) is preserved.

    Empty dedup_key (returned by ingest.make_dedup_key for malformed
    alerts that have no useful identifying fields) is processed via
    the same path under the synthetic key '_malformed_' — see
    ingest.py for the rationale.
    """
    now = datetime.now(timezone.utc).timestamp()

    with _lock:
        entry = _dedup_cache.get(dedup_key)

        if entry is not None:
            first_seen, _, count = entry
            if (now - first_seen) < silence_seconds:
                logger.debug(
                    f"Dedup hit: {dedup_key} (first seen "
                    f"{round(now - first_seen, 1)}s ago)"
                )
                # In-window duplicate: bump the count IN MEMORY only, keep
                # first_seen anchored, advance last_seen. No DB write here —
                # the running count is flushed to the DB at window close.
                _dedup_cache[dedup_key] = (first_seen, now, count + 1)
                note_dedup_decision(was_dropped=True)
                return _dup_no_close()

            # Entry exists but the silence window EXPIRED — this is a window
            # CLOSE + re-anchor. Capture the closing window's final count and
            # its window_ts (the old first_seen) so the caller can flush it to
            # the DB, then start a fresh window at count=1 anchored at now.
            close_key = dedup_key
            close_window_ts = first_seen
            close_count = count
            _dedup_cache[dedup_key] = (now, now, 1)
            note_dedup_decision(was_dropped=False)
            return _pass_with_close(now, close_key, close_window_ts, close_count)

        # Brand-new key — open the first window at count=1. Nothing to close.
        _dedup_cache[dedup_key] = (now, now, 1)
        note_dedup_decision(was_dropped=False)
        return _pass_no_close(now)


def get_last_seen(dedup_key):
    """
    Return the (first_seen, last_seen) tuple for dedup_key, or None.

    Used by enrich.py to populate wazuh_first_seen and wazuh_last_seen
    in the enrichment dict. Returning the tuple (rather than just
    last_seen) lets the caller compute storm duration as
    (last_seen - first_seen) without a second lookup.

    The cache entry is a 3-tuple (first_seen, last_seen, count); this
    returns only the (first_seen, last_seen) pair so enrich's existing
    2-tuple unpack contract is unchanged — the occurrence count is an
    internal frequency-aggregation detail enrich does not consume.

    Reads under the same lock as is_duplicate to ensure a consistent
    view — without the lock, a concurrent is_duplicate() update could
    return inconsistent first/last values mid-update.
    """
    with _lock:
        entry = _dedup_cache.get(dedup_key)
        if entry is None:
            return None
        first_seen, last_seen, _ = entry
        return (first_seen, last_seen)


def clear_cache():
    """Clear the dedup cache. Useful for testing."""
    with _lock:
        _dedup_cache.clear()


def cache_size():
    """Return number of keys currently in cache."""
    with _lock:
        return len(_dedup_cache)


def prune_cache(max_age_seconds=3600):
    """
    Remove entries whose last_seen is older than max_age_seconds.
    Call periodically from main loop to prevent unbounded growth.

    CONTRACT: max_age_seconds must be >= the largest silence window in
    use, or a once-seen key can be evicted mid-window and a sparse
    repeat re-escalates early. main.py honors this by deriving the
    horizon from the LARGEST window in use — the global
    dedup_silence_seconds AND every per-rule override in rules.json
    (max(3600, 2x largest)).

    Pruning on last_seen (rather than first_seen) means active storms
    stay in cache as long as duplicates keep arriving. Quiet alerts
    age out normally. The hard escalation cadence is unaffected
    because is_duplicate's silence-window math uses first_seen, which
    is never updated after the initial entry.

    WINDOW-CLOSE FLUSH: an evicted key is a window that closed quietly
    (it never re-anchored, so is_duplicate never emitted its close
    payload). Its final count must still be written to the DB. This
    function stays DB-free (dedup gates the pipeline, not the database),
    so instead of writing here it RETURNS the list of closing windows as
    (dedup_key, window_ts, count) tuples; the main-loop caller flushes
    them via database.record_window_close. window_ts is the entry's
    first_seen (the window's identity for the close UPDATE).

    Iterates a snapshot to avoid mutating the dict while iterating.

    Returns: list of (dedup_key, window_ts, count) for the caller to flush.
    """
    now = datetime.now(timezone.utc).timestamp()
    cutoff = now - max_age_seconds

    closed = []
    with _lock:
        before = len(_dedup_cache)
        keys_to_remove = [
            k for k, (_, last_seen, _) in list(_dedup_cache.items())
            if last_seen < cutoff
        ]
        for k in keys_to_remove:
            first_seen, _last_seen, count = _dedup_cache.pop(k)
            closed.append((k, first_seen, count))
        pruned = before - len(_dedup_cache)

    if pruned:
        logger.debug(
            f"Dedup cache pruned {pruned} entries, "
            f"{len(_dedup_cache)} remain"
        )
    return closed


def flush_all_windows():
    """
    Drain the ENTIRE dedup cache and return every window's close payload.

    Shutdown analog of prune_cache: prune evicts only windows quiet past a
    horizon; this evicts ALL of them regardless of age, so a graceful stop
    can flush every still-open window's accumulated count to the DB before
    the process exits. Without it, any window holding count>1 in memory at
    shutdown loses those suppressed-duplicate counts — the frequency
    baseline would permanently under-report every window that happened to be
    open at stop time.

    Must be called only after the worker pool has drained (no concurrent
    is_duplicate mutating the cache), so the snapshot is final. record_*
    writes are the caller's job (dedup stays DB-free); the caller flushes
    each returned (dedup_key, window_ts, count) via
    database.record_window_close under db_lock.

    Returns: list of (dedup_key, window_ts, count) for the caller to flush.
    """
    with _lock:
        closed = [
            (k, first_seen, count)
            for k, (first_seen, _last_seen, count) in _dedup_cache.items()
        ]
        _dedup_cache.clear()
    if closed:
        logger.info(f"Dedup shutdown flush: {len(closed)} open window(s) drained")
    return closed


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

    print("=== jrSOCtriage Dedup Smoke Test ===\n")

    config     = load_config("config.json")
    hosts_data = load_hosts(config)

    silence_seconds = config.get("processing", {}).get("dedup_silence_seconds", 240)
    print(f"Silence window : {silence_seconds}s")
    print(f"Cache size     : {cache_size()}\n")

    alerts = list(read_new_alerts(config, min_level=0))
    print(f"Loaded {len(alerts)} alert(s)\n")

    processed = 0
    dupes     = 0

    for alert in alerts[:20]:
        enrichment = enrich_alert(alert, config, hosts_data)
        dedup_key  = enrichment["dedup_key"]
        level      = safe_get(alert, "rule", "level", default=0)

        if is_duplicate(dedup_key, silence_seconds).is_dup:
            dupes += 1
            logger.debug(f"DROPPED: {dedup_key}")
            continue

        processed += 1
        min_level = config.get("filtering", {}).get("min_rule_level", 6)
        send_to_llm = int(level) >= min_level

        print(f"  [{level}] {dedup_key}")
        print(f"       {safe_get(alert, 'rule', 'description')}")
        print(f"       LLM: {'YES' if send_to_llm else 'no (below min level)'}")
        print()

    print(f"Processed : {processed}")
    print(f"Dupes dropped : {dupes}")
    print(f"Cache size after : {cache_size()}")
    print("\n=== Done ===")
