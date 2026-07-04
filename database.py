#!/usr/bin/env python3
"""
jrSOCtriage - Database Module
SQLite-based alert history tracking.
Stores alert occurrences, calculates baselines, flags anomalies.
Retention: 14 days, pruned on every write.
"""

import logging
import random
import queue
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

from ingest import safe_get
from graylog_fetch import parse_alert_timestamp

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Write retry with jittered backoff
# ---------------------------------------------------------------------------
#
# At multi-worker concurrency (24+ workers for 3M/day LLM-on capacity),
# `sqlite3.OperationalError: database is locked` can occur in tight bursts
# when many workers attempt record_alert simultaneously. The busy_timeout=500
# at connection time handles most single-collision cases, but burst windows
# of 7+ simultaneous writes exceed what 500ms of timeout can serialize.
#
# Without retry, each lock = one frequency-history row missed (alert still
# ships; baseline computation has a tiny sparse hole). With retry, most
# locks become brief latency penalties (20-300ms) instead of data sparseness.
#
# Backoff schedule: 20ms, 60ms, 300ms — each with ±50% uniform jitter so
# concurrent retriers don't re-collide. Total worst-case retry budget per
# write: ~600ms. After 3 failed retries, give up and log error (preserves
# the prior "log and continue" semantics).

_DB_WRITE_RETRY_BACKOFFS_MS = (20, 60, 300)


def _db_write_with_retry(fn, op_name, identifier=""):
    """Execute fn() with retry on 'database is locked' errors.

    fn:   callable that performs the write (execute + commit)
    op_name: short tag for log messages ("record_alert", "record_escalation")
    identifier: optional dedup_key or similar to include in error log

    Returns True on success, False on final failure (after retries).
    Non-lock OperationalErrors and other exceptions are not caught here —
    callers handle those.
    """
    last_err = None
    for attempt in range(len(_DB_WRITE_RETRY_BACKOFFS_MS) + 1):
        try:
            fn()
            if attempt > 0:
                logger.debug(
                    f"{op_name} succeeded on retry {attempt} ({identifier})"
                )
            return True
        except sqlite3.OperationalError as e:
            err_str = str(e).lower()
            if "locked" not in err_str:
                # Not a lock; re-raise to original handler
                raise
            last_err = e
            if attempt >= len(_DB_WRITE_RETRY_BACKOFFS_MS):
                break
            backoff_ms = _DB_WRITE_RETRY_BACKOFFS_MS[attempt]
            # ±50% jitter
            jittered = backoff_ms * (0.5 + random.random())
            time.sleep(jittered / 1000.0)
    logger.error(
        f"Failed {op_name} after {len(_DB_WRITE_RETRY_BACKOFFS_MS)} "
        f"retries{(' ' + identifier) if identifier else ''}: {last_err}"
    )
    return False


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

# Default path is relative to the pipeline working directory.
# Override via config.paths.db_file.
DEFAULT_DB_PATH = "jrsoc.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_history (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id            TEXT    NOT NULL,
    canonical_hostname TEXT    NOT NULL,
    dedup_key          TEXT    NOT NULL,
    rule_level         INTEGER,
    rule_description   TEXT,
    timestamp          REAL    NOT NULL,
    inserted_at        REAL    NOT NULL,
    count              INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_dedup_key  ON alert_history(dedup_key);
CREATE INDEX IF NOT EXISTS idx_timestamp  ON alert_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_rule_host  ON alert_history(rule_id, canonical_hostname);

CREATE TABLE IF NOT EXISTS rule_escalation_log (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id            TEXT    NOT NULL,
    canonical_hostname TEXT    NOT NULL,
    hour_bucket        TEXT    NOT NULL,
    count              INTEGER NOT NULL DEFAULT 0,
    last_escalated_at  REAL    NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_escalation_bucket
    ON rule_escalation_log(rule_id, canonical_hostname, hour_bucket);

CREATE TABLE IF NOT EXISTS maintenance_mode (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_hostname TEXT    NOT NULL UNIQUE,
    expires_at         REAL    NOT NULL,
    set_at             REAL    NOT NULL,
    set_by             TEXT    NOT NULL DEFAULT 'manual'
);
"""

def get_db_path(config):
    return config.get("paths", {}).get("db_file", DEFAULT_DB_PATH)


class _NullCursor:
    """Cursor whose reads return 'nothing'. Every reader in this
    module treats no-row as its fail-open default (e.g.
    check_rate_limit: no row -> count 0 -> allowed;
    is_in_maintenance_mode: no row -> False; calculate_baseline and
    is_first_seen: explicit row-is-None guards, since their aggregate
    queries would otherwise subscript None). So an all-empty cursor
    makes EVERY read path fail open with zero changes to the
    reader functions."""
    def fetchone(self):  return None
    def fetchall(self):  return []
    def fetchmany(self, n=1): return []
    def __iter__(self):  return iter(())


class _NullConnection:
    """Returned by get_connection() when database.enabled is false.

    Writes are no-ops (record_alert / record_escalation / prune /
    schema) so NO write path to a real DB file exists — DB-related
    failure modes (corruption, lock contention, a blocked write) are
    removed by construction, not by hoping every call site was gated.
    Reads return empty so every
    reader fails OPEN (no baseline, rate-limit not enforced,
    maintenance not active). In-memory dedup is unaffected (it never
    touched the DB), so the pipeline's core noise suppression fully
    survives DB-off. This is the cleanest expression of the
    'rather lose the database than stop processing' principle: not a
    timeout that hopes, a switch that removes the risk entirely."""
    def execute(self, *a, **k):       return _NullCursor()
    def executescript(self, *a, **k): return _NullCursor()
    def executemany(self, *a, **k):   return _NullCursor()
    def cursor(self):                 return _NullCursor()
    def commit(self):                 pass
    def rollback(self):               pass
    def close(self):                  pass
    def __enter__(self):              return self
    def __exit__(self, *a):           return False


def _migrate_add_count_column(conn):
    """
    Add alert_history.count to pre-existing databases that were created
    before the dedup-aggregated frequency change.

    CREATE TABLE IF NOT EXISTS does not alter an existing table, so a DB
    file created by an older version keeps the old (count-less) shape.
    Fresh DBs (including the tmpfs DB recreated each reboot) already get
    the column from SCHEMA, so this is a no-op for them. Idempotent:
    checks the column list first and only ALTERs when count is absent.

    DEFAULT 1 means any legacy rows (one row per raw alert in the old
    scheme) read as a single occurrence, so SUM(count) over a mixed
    old/new table is still the correct occurrence total.
    """
    try:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(alert_history)")]
        if "count" not in cols:
            conn.execute("ALTER TABLE alert_history ADD COLUMN count INTEGER NOT NULL DEFAULT 1")
            logger.info("Migrated alert_history: added count column (DEFAULT 1)")
    except sqlite3.OperationalError as e:
        # Non-fatal: if the ALTER fails the readers still function against
        # the old shape via the COALESCE fallback in the queries.
        logger.warning(f"alert_history count-column migration skipped: {e}")


def get_connection(config):
    """
    Open a SQLite connection to the jrsoc database.
    Creates the database and schema if it doesn't exist.

    SQLite does not work reliably on network filesystems (NFS, SMB, CIFS).
    For public deployments: place the database on local disk.

    If config database.enabled is false, returns a _NullConnection:
    no DB file is opened or written, every read fails open, dedup
    (in-memory) still works. Recommended for high-alert-volume
    deployments that prefer to remove DB write pressure as a
    reliability variable — see the startup banner emitted by main.py.
    """
    if not config.get("database", {}).get("enabled", True):
        return _NullConnection()

    db_path = get_db_path(config)
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        # P1 (REG-03 GAP-2 fix): set busy_timeout CENTRALLY here so EVERY
        # connection — pool workers, the async db-writer, the main/prune
        # connection — inherits the same ~500ms bound. Previously only the
        # per-worker thread_conn set this (in main.py), so the db-writer's
        # connection opened at SQLite's default and could block on a locked DB
        # far longer than intended. busy_timeout is in ms and is the explicit
        # form of the connect(timeout=) arg above (which becomes redundant but
        # harmless). 500ms matches the per-worker intent.
        conn.execute("PRAGMA busy_timeout=500")
        conn.executescript(SCHEMA)
        _migrate_add_count_column(conn)
        conn.commit()
    except sqlite3.OperationalError as e:
        logger.error(f"Failed to open database at {db_path}: {e}")
        raise

    return conn


# ---------------------------------------------------------------------------
# Write + prune
# ---------------------------------------------------------------------------

RETENTION_DAYS = 14

# Future-timestamp tolerance: alerts with timestamps more than this many
# seconds ahead of real wall-clock time are clamped to real now and logged.
# Catches clock skew, misconfigured NTP, and malformed log sources without
# crashing or polluting baselines.
FUTURE_TIMESTAMP_TOLERANCE_SECONDS = 3600  # 1 hour

# Periodic prune dispatch state. Both alert_history and rule_escalation_log
# need pruning to stay bounded, but pruning on every write is wasteful — at
# high worker counts, every worker contends on the SQLite write lock to do
# DELETEs that mostly delete nothing (the cutoff only advances 1 second per
# second). Instead, dispatch a real prune at most once per interval. The
# Python lock is held only briefly during the check-and-update; the actual
# DELETE happens outside the lock.
#
# Process restart resets _LAST_PRUNES — first relevant write after startup
# triggers a prune. Harmless.
_PRUNE_LOCK = threading.Lock()
_LAST_PRUNES = {"alert": 0, "escalation": 0}
_PRUNE_INTERVALS = {
    "alert":      300,   # 5 minutes  — alert_history rows age out daily
    "escalation": 3600,  # 1 hour     — escalation_log buckets are hourly
}


def _should_prune(kind, now):
    """
    Returns True at most once per _PRUNE_INTERVALS[kind] seconds across all
    workers. Workers that don't prune skip immediately; one worker per
    interval pays the DELETE cost. Acceptable serialization for the
    benefit of bounded table growth at scale.
    """
    with _PRUNE_LOCK:
        if now - _LAST_PRUNES[kind] > _PRUNE_INTERVALS[kind]:
            _LAST_PRUNES[kind] = now
            return True
        return False


def _sanitize_alert_timestamp(alert_ts, now, dedup_key=""):
    """
    Clamp suspicious timestamps to real-now to protect baseline calculations.
    Returns the validated timestamp.

    Rules:
      - Timestamps more than 1 hour in the future → clamp to now, warn.
      - Timestamps more than 30 days in the past → clamp to now, warn.
        (Older than retention, would silently distort days_of_data.)
      - None → fall back to now.
    """
    if alert_ts is None:
        return now
    if alert_ts > now + FUTURE_TIMESTAMP_TOLERANCE_SECONDS:
        logger.warning(
            f"Alert timestamp {alert_ts} is in the future (now={now}) for {dedup_key}. "
            f"Clamping to now. Check NTP on source host."
        )
        return now
    thirty_days_ago = now - (30 * 86400)
    if alert_ts < thirty_days_ago:
        logger.warning(
            f"Alert timestamp {alert_ts} is more than 30 days old for {dedup_key}. "
            f"Clamping to now. Check source log timestamps."
        )
        return now
    return alert_ts


def record_alert(conn, enrichment, alert):
    """
    Insert an alert into history and prune records older than RETENTION_DAYS.
    Call this for every alert that passes dedup, before baseline calculation.
    """
    now = datetime.now(timezone.utc).timestamp()

    rule_id            = enrichment.get("gl2_rule_id", safe_get(alert, "rule", "id", default="unknown"))
    canonical_hostname = enrichment.get("canonical_hostname", "unknown")
    dedup_key          = enrichment.get("dedup_key", f"{rule_id}|{canonical_hostname}")
    rule_level         = enrichment.get("gl2_rule_level", 0)
    rule_description   = safe_get(alert, "rule", "description", default="")

    alert_dt = parse_alert_timestamp(alert)
    raw_ts = alert_dt.timestamp() if alert_dt else None
    alert_ts = _sanitize_alert_timestamp(raw_ts, now, dedup_key)

    try:
        def _do_record():
            conn.execute("""
                INSERT INTO alert_history
                    (rule_id, canonical_hostname, dedup_key, rule_level, rule_description, timestamp, inserted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (rule_id, canonical_hostname, dedup_key, rule_level, rule_description, alert_ts, now))

            # Periodic prune dispatch — at most one prune per _PRUNE_INTERVALS["alert"]
            # seconds across all workers. The previous design pruned on every insert,
            # which at high worker counts caused write-lock contention for DELETEs
            # that mostly deleted nothing. See _should_prune for the rationale.
            if _should_prune("alert", now):
                cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).timestamp()
                conn.execute("DELETE FROM alert_history WHERE timestamp < ?", (cutoff,))

            conn.commit()

        if _db_write_with_retry(_do_record, "record_alert", dedup_key):
            logger.debug(f"Recorded alert: {dedup_key}")
    except sqlite3.OperationalError as e:
        # Non-lock OperationalError (disk full, schema mismatch, etc).
        # Lock errors are handled inside _db_write_with_retry. Log and
        # continue — losing one alert record is preferable to crashing.
        logger.error(f"Failed to record alert {dedup_key}: {e}")


# ---------------------------------------------------------------------------
# Dedup-aggregated frequency writes (replaces per-raw-alert record_alert)
# ---------------------------------------------------------------------------
#
# Instead of one alert_history row per raw alert (record_alert above, fired
# for EVERY alert before dedup, including the ~85-90% that dedup drops), the
# aggregated scheme writes ONE row per dedup WINDOW and carries an occurrence
# count on it:
#
#   - record_window_open: the alert that PASSES dedup (the window opener)
#     INSERTs its row immediately with count=1, so calculate_baseline can
#     read it the same millisecond — preserving today's behavior where the
#     row is in the table before the baseline read. Returns the window_ts
#     used, which the dedup cache keeps so the close can find this exact row.
#
#   - record_window_close: when the window ends (re-anchor in is_duplicate
#     when a fresh occurrence arrives after silence expiry, or prune
#     eviction when the key goes quiet), the final accumulated count — held
#     in the dedup cache the whole window, never touching the DB per
#     duplicate — is written with a single UPDATE to the opener's row.
#
# Net: 2 DB writes per window (one INSERT, one UPDATE) regardless of how
# many duplicates landed. A 200-duplicate window is 2 writes, not 200. The
# duplicates accumulate in memory (dedup cache), which is the ~85-90% write
# reduction. record_alert + the per-raw-row scheme remain defined above as a
# reversible fallback but are no longer on the live path.
#
# The window is identified by (dedup_key, window_ts) where window_ts is the
# window's first_seen — unique per window for a key, so the close UPDATE
# targets exactly the opener's row.


def record_window_open(conn, enrichment, alert, window_ts):
    """
    INSERT the opening row for a dedup window with count=1.

    window_ts is the window's first_seen epoch (from the dedup cache), used
    as the row's `timestamp` so the close UPDATE can find this exact row by
    (dedup_key, timestamp). It is sanitized here the same way record_alert
    sanitized the alert timestamp, so bad clocks can't corrupt baseline
    query windows.

    Returns the sanitized window_ts actually written (the dedup cache should
    store THIS value so the matching close UPDATE keys on the same number),
    or None on write failure.
    """
    now = datetime.now(timezone.utc).timestamp()

    rule_id            = enrichment.get("gl2_rule_id", safe_get(alert, "rule", "id", default="unknown"))
    canonical_hostname = enrichment.get("canonical_hostname", "unknown")
    dedup_key          = enrichment.get("dedup_key", f"{rule_id}|{canonical_hostname}")
    rule_level         = enrichment.get("gl2_rule_level", 0)
    rule_description   = safe_get(alert, "rule", "description", default="")

    window_ts = _sanitize_alert_timestamp(window_ts, now, dedup_key)

    try:
        def _do_open():
            conn.execute("""
                INSERT INTO alert_history
                    (rule_id, canonical_hostname, dedup_key, rule_level, rule_description, timestamp, inserted_at, count)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """, (rule_id, canonical_hostname, dedup_key, rule_level, rule_description, window_ts, now))

            # Periodic prune dispatch — carried over from record_alert: at
            # most one prune per _PRUNE_INTERVALS["alert"] across all workers.
            if _should_prune("alert", now):
                cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).timestamp()
                conn.execute("DELETE FROM alert_history WHERE timestamp < ?", (cutoff,))

            conn.commit()

        if _db_write_with_retry(_do_open, "record_window_open", dedup_key):
            logger.debug(f"Window open: {dedup_key} (count=1)")
            return window_ts
    except sqlite3.OperationalError as e:
        logger.error(f"Failed to open window {dedup_key}: {e}")
    return None


def record_window_close(conn, dedup_key, window_ts, count):
    """
    UPDATE the opener's row to the window's final accumulated count.

    Matches the row written by record_window_open via (dedup_key, timestamp
    == window_ts). count is the total occurrences in the window (opener + all
    suppressed duplicates), accumulated in the dedup cache without touching
    the DB per duplicate.

    No-op when count <= 1 (the opener already wrote count=1, so a window that
    saw no duplicates needs no UPDATE — saves a write on singleton windows,
    which are the ~10% that never repeat). Under DB-off (_NullConnection) the
    execute is a harmless no-op.
    """
    if count <= 1:
        return  # opener already wrote count=1; nothing to finalize

    now = datetime.now(timezone.utc).timestamp()
    try:
        def _do_close():
            conn.execute("""
                UPDATE alert_history
                   SET count = ?
                 WHERE dedup_key = ? AND timestamp = ?
            """, (count, dedup_key, window_ts))
            conn.commit()

        _db_write_with_retry(_do_close, "record_window_close", dedup_key)
        logger.debug(f"Window close: {dedup_key} (count={count})")
    except sqlite3.OperationalError as e:
        logger.error(f"Failed to close window {dedup_key}: {e}")


# ---------------------------------------------------------------------------
# REG-03 Branch A: async window-close writer
#
# The window-close flush (record_window_close) is an UPDATE+commit held under
# db_lock on the hot path. It is SAFE to defer (unlike record_window_open):
#   - It is window-EXPIRY-triggered, so it always fires >= silence_seconds
#     after its own opener committed -> no open->close race.
#   - calculate_baseline reads count, but ALREADY tolerates unclosed windows
#     reading as their opener count=1 (the close always lagged by up to the
#     silence window even synchronously) -> deferring adds only sub-second
#     more staleness to an already eventually-consistent number.
#   - On hard crash, an undrained close leaves a row at its opener count -- a
#     stats imperfection, no alert lost, no row corrupted.
#
# This defers ONE UPDATE per close; it is NOT a write-back cache (no in-memory
# authoritative copy, no read reconciliation). SQLite stays the single source
# of truth. Pattern mirrors the anon-flusher: Event-signalled daemon thread,
# started at startup, drained-and-stopped in the graceful-shutdown handler.
#
# A single writer thread owns its OWN connection (SQLite connections are not
# shareable across threads) and is the only writer of closes -> zero
# cross-worker db_lock contention for the flush. Workers enqueue and continue.
# ---------------------------------------------------------------------------

_db_writer_queue = queue.Queue()
_db_writer_shutdown = threading.Event()
# REG-03 resilience (review 2026-06-23): _db_writer_alive is set ONLY after the
# writer thread successfully opens its connection, and cleared when the thread
# exits for ANY reason (clean stop OR failed startup OR crash). enqueue checks
# it so a disabled DB or a dead writer can never silently pile work into the
# unbounded queue behind a thread that will never drain it.
_db_writer_alive = threading.Event()
_db_writer_thread = None
_db_writer_lock = threading.Lock()
_db_writer_started = False
# Sentinel pushed by stop_db_writer to wake the drain loop promptly.
_DB_WRITER_SENTINEL = object()


def enqueue_window_close(dedup_key, window_ts, count):
    """Called by pool workers / prune in place of a synchronous
    record_window_close. Non-blocking: hands the close to the writer thread and
    returns. count<=1 is skipped (matches record_window_close's no-op).

    REG-03 resilience (review 2026-06-23): if the writer is NOT alive — DB
    disabled (writer never started), failed startup, or a crashed writer — this
    is a TRUE no-op (drop), NOT a queue insert. Previously it always pushed into
    the unbounded _db_writer_queue, so with no draining thread the queue grew
    without bound (a memory leak, not the 'harmless no-op' the old comment
    claimed). Dropping is correct here: with DB disabled there is no DB to write,
    and a dead/never-started writer means there is no one to drain — the close is
    a deferred stats-finalization (count update on an already-committed row),
    bounded-loss-tolerant by the same argument as the rest of Branch A."""
    if count <= 1:
        return
    if not _db_writer_alive.is_set():
        return  # writer not running — drop rather than leak into a dead queue
    _db_writer_queue.put((dedup_key, window_ts, count))


def _db_writer_main(config):
    """Drain (dedup_key, window_ts, count) tuples and apply each as a
    record_window_close on this thread's OWN connection. On shutdown, drain
    the queue to EMPTY before exiting so no pending close is lost on a clean
    stop.

    REG-03 resilience (review 2026-06-23): the connection is opened INSIDE the
    try, and _db_writer_alive is set ONLY after it succeeds. If get_connection
    raises (e.g. a storage wedge — the same failure class as the fsync hazard),
    the thread exits WITHOUT ever setting _alive, so enqueue_window_close sees a
    not-alive writer and drops rather than piling into a queue behind a dead
    thread. The finally clears _alive AND _started so a later start_db_writer
    could re-spawn, and so the not-alive guard holds for every post-death
    enqueue."""
    global _db_writer_started
    conn = None
    try:
        conn = get_connection(config)
        _db_writer_alive.set()  # only now is the writer able to drain
        while True:
            try:
                item = _db_writer_queue.get(timeout=1.0)
            except queue.Empty:
                if _db_writer_shutdown.is_set():
                    break
                continue
            if item is _DB_WRITER_SENTINEL:
                # shutdown wake; loop will re-check the queue then the flag
                _db_writer_queue.task_done()
                continue
            try:
                dedup_key, window_ts, count = item
                record_window_close(conn, dedup_key, window_ts, count)
            except Exception as e:
                logger.error(f"[db-writer] close failed: {e}", exc_info=True)
            finally:
                _db_writer_queue.task_done()
            # If shutting down, keep draining until the queue is empty, then exit.
            if _db_writer_shutdown.is_set() and _db_writer_queue.empty():
                break
    except Exception as e:
        # Failed startup (e.g. get_connection raised) or unexpected crash.
        logger.error(f"[db-writer] writer thread exiting on error: {e}",
                     exc_info=True)
    finally:
        # Mark not-alive and not-started for ANY exit reason so enqueue drops
        # (never leaks) and a future start_db_writer can re-spawn.
        _db_writer_alive.clear()
        with _db_writer_lock:
            _db_writer_started = False
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def start_db_writer(config):
    """Idempotent. Call once at pipeline startup (main.py), only when the DB
    is enabled. Spawns the daemon writer thread."""
    global _db_writer_thread, _db_writer_started
    with _db_writer_lock:
        if _db_writer_started:
            return
        _db_writer_shutdown.clear()
        _db_writer_alive.clear()
        # REG-03 resilience: set _started BEFORE start() so a fast-failing
        # writer thread's finally (which sets _started=False under this same
        # lock) cannot run before this line and leave us in a started=True /
        # dead-thread state. The thread can only acquire _db_writer_lock after
        # we release it here, so the ordering is deterministic: True now,
        # possibly False later if the thread dies. Liveness is tracked by
        # _db_writer_alive, not _started.
        _db_writer_started = True
        _db_writer_thread = threading.Thread(
            target=_db_writer_main, args=(config,),
            name="db-writer", daemon=True)
        _db_writer_thread.start()
        logger.info("[db-writer] started (async window-close flush)")


def stop_db_writer(timeout_s=10.0):
    """Call from the graceful-shutdown handler AFTER the worker pool has
    drained (so every close has been enqueued). Signals the writer to drain
    the remaining queue and exit, then joins it so a clean shutdown loses
    zero closes. Safe to call even if never started."""
    global _db_writer_started
    with _db_writer_lock:
        if not _db_writer_started:
            return
        _db_writer_shutdown.set()
        _db_writer_queue.put(_DB_WRITER_SENTINEL)  # wake the get() promptly
        t = _db_writer_thread
    if t is not None:
        t.join(timeout=timeout_s)
        if t.is_alive():
            logger.warning(
                f"[db-writer] did not drain within {timeout_s}s; "
                f"{_db_writer_queue.qsize()} close(s) may be unflushed "
                f"(stats imperfection only)")
    with _db_writer_lock:
        _db_writer_started = False


# ---------------------------------------------------------------------------
# Baseline calculation
# ---------------------------------------------------------------------------

def calculate_baseline(conn, config, rule_id, canonical_hostname, alert_ts=None):
    """
    Calculate historical counts and averages for a rule+host combination.

    Returns dict with counts, averages, anomaly flags, and a
    human-readable baseline_note for the LLM prompt.
    """
    multiplier        = config.get("processing", {}).get("baseline_multiplier", 2.0)
    min_baseline_days = config.get("processing", {}).get("min_baseline_days", 3)

    wall_now = datetime.now(timezone.utc).timestamp()
    # Clamp alert_ts to prevent bad timestamps from corrupting the query
    # windows (hour_ago, day_ago, etc.).
    now = _sanitize_alert_timestamp(alert_ts, wall_now,
                                     dedup_key=f"{rule_id}|{canonical_hostname}")

    hour_ago  = now - 3600
    day_ago   = now - 86400
    week_ago  = now - 604800
    two_weeks = now - (RETENTION_DAYS * 86400)

    try:
        row = conn.execute("""
            SELECT
                SUM(CASE WHEN timestamp >= ? THEN COALESCE(count, 1) ELSE 0 END) as count_last_hour,
                SUM(CASE WHEN timestamp >= ? THEN COALESCE(count, 1) ELSE 0 END) as count_last_24h,
                SUM(CASE WHEN timestamp >= ? THEN COALESCE(count, 1) ELSE 0 END) as count_last_7d,
                SUM(COALESCE(count, 1))                                          as count_last_14d,
                MIN(timestamp)                                                   as oldest_ts
            FROM alert_history
            WHERE rule_id = ? AND canonical_hostname = ?
              AND timestamp >= ?
        """, (hour_ago, day_ago, week_ago, rule_id, canonical_hostname, two_weeks)).fetchone()
    except sqlite3.OperationalError as e:
        logger.error(f"Baseline query failed for {rule_id}|{canonical_hostname}: {e}")
        # Return a safe empty baseline so downstream doesn't crash.
        return {
            "count_last_hour": 0, "count_last_24h": 0, "count_last_7d": 0, "count_last_14d": 0,
            "hourly_avg": 0, "daily_avg": 0,
            "above_hourly": False, "above_daily": False,
            "days_of_data": 0,
            "baseline_note": "Baseline unavailable - database error.",
        }

    # row is None only when conn is the DB-off _NullConnection — a real
    # aggregate query (SUM/COUNT) always returns exactly one row, and
    # _NullCursor.fetchone() returns None without raising, bypassing the
    # except above. Same situation as the guard in is_first_seen. Without
    # this, every alert under database.enabled=false raised TypeError here
    # (caught by main.py's broad baseline except — so processing survived,
    # but as one warning per alert instead of the designed graceful
    # fail-open).
    if row is None:
        return {
            "count_last_hour": 0, "count_last_24h": 0, "count_last_7d": 0, "count_last_14d": 0,
            "hourly_avg": 0, "daily_avg": 0,
            "above_hourly": False, "above_daily": False,
            "days_of_data": 0,
            "baseline_note": "Baseline unavailable - database disabled.",
        }

    count_last_hour = row["count_last_hour"] or 0
    count_last_24h  = row["count_last_24h"]  or 0
    count_last_7d   = row["count_last_7d"]   or 0
    count_last_14d  = row["count_last_14d"]  or 0
    oldest_ts       = row["oldest_ts"]

    if oldest_ts and count_last_14d > 0:
        days_of_data = max(1, (now - oldest_ts) / 86400)
    else:
        days_of_data = 1

    hourly_avg = round(count_last_14d / (days_of_data * 24), 2)
    daily_avg  = round(count_last_14d / days_of_data, 2)

    has_baseline = days_of_data >= min_baseline_days
    above_hourly = has_baseline and (hourly_avg > 0) and (count_last_hour > hourly_avg * multiplier)
    above_daily  = has_baseline and (daily_avg  > 0) and (count_last_24h  > daily_avg  * multiplier)

    # Human readable note for LLM prompt
    if count_last_14d == 0:
        baseline_note = "First occurrence - no historical baseline."
    else:
        parts = []
        parts.append(f"Last hour: {count_last_hour} (avg {hourly_avg}/hr)")
        parts.append(f"Last 24h: {count_last_24h} (avg {daily_avg}/day)")
        parts.append(f"Last 7d: {count_last_7d}")
        if not has_baseline:
            parts.append(f"Baseline not yet established ({round(days_of_data, 1)} of {min_baseline_days} days needed)")
        if above_hourly:
            parts.append(f"** ABOVE HOURLY BASELINE ({multiplier}x) **")
        if above_daily:
            parts.append(f"** ABOVE DAILY BASELINE ({multiplier}x) **")
        baseline_note = " | ".join(parts)

    return {
        "count_last_hour":   count_last_hour,
        "count_last_24h":    count_last_24h,
        "count_last_7d":     count_last_7d,
        "count_last_14d":    count_last_14d,
        "hourly_avg":        hourly_avg,
        "daily_avg":         daily_avg,
        "above_hourly":      above_hourly,
        "above_daily":       above_daily,
        "days_of_data":      round(days_of_data, 1),
        "min_baseline_days": min_baseline_days,
        "baseline_note":     baseline_note,
    }


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def get_hour_bucket(ts=None):
    """Return current hour as a string bucket key: '2026-04-14-15'"""
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%d-%H")


def check_rate_limit(conn, rule_id, canonical_hostname, max_per_hour, scope="host"):
    """
    Check if this rule+host is still within its hourly escalation budget.
    scope="host" tracks per rule+host. scope="rule" tracks per rule only.

    Returns True if the escalation is allowed (budget not yet exceeded).
    Returns False if the hourly limit has been hit.
    """
    bucket = get_hour_bucket()

    if scope == "rule":
        key_host = "__all__"
    else:
        key_host = canonical_hostname

    try:
        row = conn.execute(
            """SELECT count FROM rule_escalation_log
               WHERE rule_id=? AND canonical_hostname=? AND hour_bucket=?""",
            (rule_id, key_host, bucket)
        ).fetchone()
    except sqlite3.OperationalError as e:
        logger.error(f"Rate limit query failed: {e}")
        return True  # fail open — allow escalation on DB error

    current_count = row["count"] if row else 0
    return current_count < max_per_hour


def record_escalation(conn, rule_id, canonical_hostname, scope="host"):
    """
    Increment the escalation counter for this rule+host in the current hour.
    """
    now = datetime.now(timezone.utc).timestamp()
    bucket = get_hour_bucket()

    if scope == "rule":
        key_host = "__all__"
    else:
        key_host = canonical_hostname

    try:
        def _do_record_escalation():
            conn.execute(
                """INSERT INTO rule_escalation_log
                       (rule_id, canonical_hostname, hour_bucket, count, last_escalated_at)
                   VALUES (?, ?, ?, 1, ?)
                   ON CONFLICT(rule_id, canonical_hostname, hour_bucket)
                   DO UPDATE SET count=count+1, last_escalated_at=excluded.last_escalated_at""",
                (rule_id, key_host, bucket, now)
            )

            # Periodic prune dispatch — at most one prune per _PRUNE_INTERVALS["escalation"]
            # seconds across all workers. Without this, rule_escalation_log grows
            # unbounded — each unique (rule_id, host, hour_bucket) tuple becomes a
            # permanent row. At SMB scale (~5-12k unique tuples/day) that's
            # millions of rows per year. See _should_prune for the rationale.
            if _should_prune("escalation", now):
                prune_escalation_log(conn)

            conn.commit()

        _db_write_with_retry(
            _do_record_escalation, "record_escalation", f"{rule_id}|{key_host}"
        )
    except sqlite3.OperationalError as e:
        logger.error(f"Failed to record escalation for {rule_id}|{key_host}: {e}")


def prune_escalation_log(conn):
    """Remove escalation log entries older than 25 hours."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=25)).timestamp()
    try:
        conn.execute(
            "DELETE FROM rule_escalation_log WHERE last_escalated_at < ?", (cutoff,)
        )
        conn.commit()
    except sqlite3.OperationalError as e:
        logger.error(f"Failed to prune escalation log: {e}")


# ---------------------------------------------------------------------------
# First-seen detection
# ---------------------------------------------------------------------------

def is_first_seen(conn, rule_id, canonical_hostname, lookback_days=14):
    """
    Returns True if this rule+host combination has never been seen
    in the lookback window. Used for first-seen escalation override.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).timestamp()
    try:
        row = conn.execute(
            """SELECT COUNT(*) as c FROM alert_history
               WHERE rule_id=? AND canonical_hostname=? AND timestamp >= ?""",
            (rule_id, canonical_hostname, cutoff)
        ).fetchone()
    except sqlite3.OperationalError as e:
        logger.error(f"First-seen query failed: {e}")
        return False  # fail closed — don't trigger first-seen escalation on error
    # row is None when conn is the DB-off _NullConnection —
    # _NullConnection.fetchone() returns None and does NOT raise
    # sqlite3.OperationalError, so it bypasses the except above. A
    # real COUNT(*) always returns exactly one row, so row is None
    # ONLY under DB-off (or a degenerate driver). Fail closed,
    # identical to the OperationalError path: with no history DB,
    # "first seen" cannot be determined, so do not force-escalate
    # on it. (Without this guard, every alert reaching first-seen
    # evaluation under DB-off would raise TypeError and fail the
    # whole alert.)
    if row is None:
        return False
    return row["c"] == 0


# ---------------------------------------------------------------------------
# Maintenance mode
# ---------------------------------------------------------------------------

def set_maintenance_mode(conn, canonical_hostname, minutes, set_by="manual"):
    """
    Put a host into maintenance mode for the specified duration.
    Suppresses non-external LLM escalations for this host.
    """
    now = datetime.now(timezone.utc).timestamp()
    expires_at = now + (minutes * 60)
    try:
        conn.execute(
            """INSERT INTO maintenance_mode
                   (canonical_hostname, expires_at, set_at, set_by)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(canonical_hostname)
               DO UPDATE SET expires_at=excluded.expires_at,
                             set_at=excluded.set_at,
                             set_by=excluded.set_by""",
            (canonical_hostname, expires_at, now, set_by)
        )
        conn.commit()
        logger.info(f"Maintenance mode set for {canonical_hostname} — expires in {minutes} minutes")
    except sqlite3.OperationalError as e:
        logger.error(f"Failed to set maintenance mode for {canonical_hostname}: {e}")


def clear_maintenance_mode(conn, canonical_hostname):
    """Remove a host from maintenance mode."""
    try:
        conn.execute(
            "DELETE FROM maintenance_mode WHERE canonical_hostname=?",
            (canonical_hostname,)
        )
        conn.commit()
        logger.info(f"Maintenance mode cleared for {canonical_hostname}")
    except sqlite3.OperationalError as e:
        logger.error(f"Failed to clear maintenance mode for {canonical_hostname}: {e}")


def is_in_maintenance_mode(conn, canonical_hostname):
    """
    Returns True if the host is currently in maintenance mode.
    Expired entries are cleared lazily only when they are found.
    """
    now = datetime.now(timezone.utc).timestamp()

    try:
        row = conn.execute(
            "SELECT expires_at FROM maintenance_mode WHERE canonical_hostname=?",
            (canonical_hostname,)
        ).fetchone()
    except sqlite3.OperationalError as e:
        logger.error(f"Maintenance mode query failed: {e}")
        # Fail OPEN by this module's convention: not-in-maintenance means
        # alerts keep escalating (suppression is what maintenance adds).
        return False

    if row is None:
        return False

    if row["expires_at"] < now:
        # Clean up this specific expired entry
        try:
            conn.execute(
                "DELETE FROM maintenance_mode WHERE canonical_hostname=? AND expires_at < ?",
                (canonical_hostname, now)
            )
            conn.commit()
        except sqlite3.OperationalError as e:
            logger.warning(f"Failed to clean expired maintenance row: {e}")
        return False

    return True


def get_maintenance_status(conn):
    """Return list of all hosts currently in maintenance mode with expiry info."""
    now = datetime.now(timezone.utc).timestamp()
    try:
        rows = conn.execute(
            "SELECT canonical_hostname, expires_at, set_at, set_by FROM maintenance_mode WHERE expires_at > ?",
            (now,)
        ).fetchall()
    except sqlite3.OperationalError as e:
        logger.error(f"Maintenance status query failed: {e}")
        return []
    results = []
    for row in rows:
        remaining = int((row["expires_at"] - now) / 60)
        results.append({
            "host":      row["canonical_hostname"],
            "remaining_minutes": remaining,
            "set_by":    row["set_by"],
        })
    return results


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    from ingest import load_config, load_hosts, read_new_alerts
    from enrich import enrich_alert

    print("=== jrSOCtriage Database Smoke Test ===\n")
    # KNOWN BUG (documented, not fixed): read_new_alerts() below advances the
    # shared .ingest_position, so running this smoke test against a LIVE
    # pipeline makes the pipeline skip the alerts consumed here. The DB side
    # IS isolated (separate /tmp database, deleted after) — only the ingest
    # position is shared. Run with the pipeline stopped, or on the test
    # platform. Same class as the other module smoke tests.

    config     = load_config("config.json")
    hosts_data = load_hosts(config)

    # Smoke test uses a separate database to avoid polluting production data.
    # Deleted after the test so repeated runs start clean.
    import os
    test_db_path = "/tmp/jrsoc_smoketest.db"
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    # Force config to point at our test DB for this run only.
    config.setdefault("paths", {})["db_file"] = test_db_path

    db_path = get_db_path(config)
    print(f"Database path : {db_path}  (smoke test isolated)")

    conn = get_connection(config)
    print(f"[OK] Database connected and schema ready\n")

    count = conn.execute("SELECT COUNT(*) as c FROM alert_history").fetchone()["c"]
    print(f"Existing records in history: {count}\n")

    alerts = list(read_new_alerts(config, min_level=0))
    print(f"Loaded {len(alerts)} alert(s)\n")

    processed = 0

    for alert in alerts[:10]:
        enrichment = enrich_alert(alert, config, hosts_data)

        record_alert(conn, enrichment, alert)

        alert_dt = parse_alert_timestamp(alert)
        alert_ts = alert_dt.timestamp() if alert_dt else None

        baseline = calculate_baseline(
            conn, config,
            enrichment["gl2_rule_id"],
            enrichment["canonical_hostname"],
            alert_ts=alert_ts,
        )

        print(f"--- {enrichment['dedup_key']} ---")
        print(f"  Rule       : [{safe_get(alert,'rule','level')}] {safe_get(alert,'rule','description')}")
        print(f"  Canonical  : {enrichment['canonical_hostname']}")
        print(f"  Baseline   : {baseline['baseline_note']}")
        print(f"  Above hourly : {baseline['above_hourly']}")
        print(f"  Above daily  : {baseline['above_daily']}")
        print()

        processed += 1

    print(f"Recorded: {processed}")

    total = conn.execute("SELECT COUNT(*) as c FROM alert_history").fetchone()["c"]
    print(f"Total records in history after run: {total}")

    conn.close()

    # Clean up test database
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    print("\n=== Done ===")
