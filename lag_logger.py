"""
lag_logger - periodic pipeline observability emitter for jrSOCtriage.

Emits a single [LAG] line into jrSOCtriage's main log every N seconds with
queue depth, age-of-oldest-queued, age-of-last-processed, cycle duration,
LLM-in-flight count, and rolling-mean LLM latency.

What this tool is (and is not):
  - It is a troubleshooting instrument, off by default. Enabling it
    takes BOTH config.observability.lag_log_interval_seconds > 0 AND
    logging.level = "debug" — the interval starts the emitter, but
    [LAG] lines are emitted at DEBUG level, so default info-level
    logging hides them. Turn it on when something has visibly gone
    wrong and you need to locate WHERE time is going — queue growth,
    a slow stage, LLM latency, submit-loop backpressure.
  - Its numbers are coarse by design: sampled gauges and point-in-time
    snapshots, several measured from the worker's perspective, some
    summarizing a window that has already closed. Read TRENDS across
    many lines, not any single line as precise truth — individual
    values can mislead if treated as exact (a gauge sampled mid-burst,
    an age that includes queue wait, a count that lags by one cycle).
  - It is not a health metric to alarm on. The authoritative "is work
    being lost?" signals are the watchdog's abandoned_total and the
    [ACCOUNTING] invariant in main.py. A healthy pipeline gives you
    nothing interesting here; that is the expected state.

Architectural rationale (settled in design discussion):
  - One log stream, not two. Lag telemetry goes through the same logging
    pipeline as every other jrSOCtriage event so future log-compliance work
    (SOC 2, ISO 27001, etc.) covers it by default with no separate audit
    accounting. The cost is that operators reading lag data need
    journalctl access (sudo or systemd-journal group), but that cost is
    contained — single source of truth wins.
  - [LAG] token in the message body makes the lines trivially grep-able
    from journalctl output, log aggregators, or the future interface
    health tab.
  - Logger name is 'lag' (separate from __main__) so callers filtering by
    logger name can isolate lag traffic without grep.
  - All state mutation is guarded by a single lock. The emitter thread
    reads under lock and releases before formatting/logging — log I/O
    must never block the producers.
  - The emitter is a daemon thread. If the main pipeline crashes, the
    lag log going silent is the correct behavior — there is nothing to
    observe.
  - If the lag emitter itself crashes, the main pipeline must be
    unaffected. The emitter catches all exceptions in its tick and
    warns-once per error class so a bad clock or full disk does not
    spam the log.

Public surface:
  - LagState                      : the shared mutable state object
  - start_lag_logger(state, conf) : spin up the emitter thread, return it
  - stop_lag_logger(thread)       : signal the thread to exit cleanly

Producer hooks (call from main.py and process_alert):
  - state.set_queue_depth(n, oldest_alert_ts)
  - state.mark_alert_processed(alert_ts)
  - state.mark_cycle_complete(duration_s)
  - state.mark_llm_started()
  - state.mark_llm_completed(latency_s)

Each producer hook is O(1) under a tiny critical section and never blocks.
"""

import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone

# Dedicated logger name so consumers can filter by logger if they prefer
# the structured filter path over grep '[LAG]'. Inherits handlers from the
# root jrSOCtriage logger configured at startup.
logger = logging.getLogger("lag")

# Rolling window size for LLM latency mean. 20 is a balance between
# responsiveness to recent behavior and stability against single-call
# outliers. At ~10 LLM calls/minute filtered-mode, 20 samples covers
# ~2 minutes — long enough to smooth, short enough to react to surge.
LLM_LATENCY_WINDOW = 20


def _parse_alert_timestamp(ts):
    """
    Convert a Wazuh-style ISO timestamp into a UNIX float, tolerating the
    several formats Wazuh has shipped over the years:
      - "2026-05-15T15:30:00.000+0000"   (current default)
      - "2026-05-15T15:30:00.000Z"
      - "2026-05-15T15:30:00+00:00"
      - "2026-05-15 15:30:00.000"        (rarer, some older decoders)
    Returns None on parse failure rather than raising — a single
    unparseable timestamp must not poison the lag emitter.
    """
    if not ts:
        return None
    # datetime.fromisoformat() in 3.11+ accepts 'Z'; for older Pythons
    # we normalize first.
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Wazuh's +0000 (no colon) form needs a colon to satisfy fromisoformat
    # on Pythons < 3.11. Insert it if missing.
    if len(s) >= 5 and s[-5] in ("+", "-") and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    try:
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return None


class NullLagState:
    """Zero-overhead stand-in used when lag observability is disabled
    (observability.lag_log_interval_seconds == 0, the default).

    WHY: LagState's per-stage brackets and counters run on EVERY alert
    through a shared lock even when nothing will ever be logged — the
    interval setting only gated the emitter thread, not the state
    machine. At 40 workers that is hundreds of contended lock
    acquisitions per second of pure overhead (observed during the
    2026-06-11 LOAC throughput investigation). Disabled must mean zero:
    every method on this object is a no-op, and snapshot() returns an
    empty dict for any caller that inspects it.
    """
    def __getattr__(self, _name):
        return self._noop

    @staticmethod
    def _noop(*_a, **_k):
        return None

    def snapshot(self):
        return {}


class LagState:
    """
    Thread-safe mutable state shared between the main pipeline and the
    lag emitter thread. All public methods are O(1) under a tiny critical
    section.

    The state represents *current* pipeline status, not history. The
    emitter thread reads a snapshot, formats, and logs. Historical data
    lives in the log stream itself, not in this object.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Queue state — set per cycle from the main loop. queue_depth is
        # the count of alerts read from alerts.json in the current cycle
        # that have not yet completed triage. oldest_queued_ts is the
        # UNIX timestamp of the oldest such alert (used to compute age).
        # Both reset to 0 / None when the cycle's batch is drained.
        self._queue_depth = 0
        self._oldest_queued_ts = None

        # Last-processed state — updated as each alert completes triage.
        # last_processed_ts is the timestamp ON the alert, not when
        # processing completed; this measures end-to-end pipeline lag
        # from alert origin to triage completion.
        self._last_processed_ts = None

        # Cycle timing — last completed cycle's duration in seconds.
        # 0.0 until the first cycle finishes.
        self._cycle_duration_s = 0.0

        # LLM in-flight tracking. Producers increment on call start and
        # decrement on call completion (success or failure). The
        # decrement path lives in a finally block in the producer so
        # an exception during the call still releases the count.
        self._llm_pending = 0

        # Rolling LLM latency window. deque with maxlen auto-evicts.
        self._llm_latencies = deque(maxlen=LLM_LATENCY_WINDOW)

        # In-flight count mirror. main.py's worker pool tracks
        # in-flight work (inflight_count, guarded by pending_lock);
        # that count is mirrored here so the lag emitter can report
        # it without coupling the emitter to the pool's internals.
        # Updated at the end of every polling cycle by main.py via
        # set_executor_pending(). 0 at startup. (The executor_ name
        # is kept for [LAG] grep compatibility — the field predates
        # the executor-to-pool rewrite.)
        self._executor_pending = 0
        # Queue-FLOW signals. Depth alone cannot distinguish a healthy
        # churning queue (40 in, 40 out) from one not moving (40
        # waiting). _oldest_pending_submit_t = wall time the OLDEST
        # still-in-flight alert was submitted; pending_oldest_age_s
        # derived from it climbs while work isn't completing and
        # resets when it flows. _reaped_accum counts completions
        # since the last [LAG]; snapshot reads-and-resets it, so
        # reaped_since_last=0 alongside executor_pending>0 states
        # "submitted but nothing completing" as data.
        self._oldest_pending_submit_t = None
        self._reaped_accum = 0

        # Live queue reference. The cycle-boundary qsize sample
        # only captures state once per cycle. If the queue size changes
        # mid-cycle (worker drains then queue refills or vice versa),
        # the cycle-boundary value is misleading. Pass a queue ref
        # here via set_queue_ref(); snapshot reads .qsize() directly.
        # Defensive: None until set, never crashes if absent.
        self._queue_ref = None

        # Cumulative totals. main.py pushes once per
        # cycle via set_totals(); snapshot reports dedup_rate_pct.
        self._cum_seen = 0
        self._cum_deduped = 0

        # Per-record stage tracker. Aggregate counters (reaped /
        # executor_pending) measure submission bookkeeping, not records
        # moving through stages — a record spending a long time at any
        # single pipeline stage is invisible to them. This maps
        # record_id -> (stage_name, enter_time). Worker calls
        # mark_stage on entering each stage; clear_stage on return.
        # snapshot() reports the OLDEST in-flight record's stage +
        # age = "where, exactly, is the slowest record right now",
        # as data, no inference. Minimal by design: observation
        # hooks should be the smallest change that yields the signal.
        # NOTE (v1.0): currently UNWIRED — no caller invokes
        # mark_stage/clear_stage, so this dict stays empty and the
        # stuck_* fields read none/0.0/0 in every [LAG] line. The
        # fields are retained for [LAG] column safety; the per-stage
        # counters below cover where-is-time-going in aggregate.
        # v1.1 decision: wire the per-record hooks or remove the
        # tracker and its fields together.
        self._stages = {}  # record_id -> (stage_name, enter_t)

        # Pool queue depth + submit-loop wait time. Two
        # pure-observation counters that locate where a backlog is
        # being held when the pipeline is busier than it is
        # completing:
        # (a) executor_qsize: jobs submitted but not yet picked up
        #     by a worker. A large value that burns down over
        #     minutes means the queue itself is the holding
        #     location and the pipeline is draining it.
        # (b) submit_wait_s_max: longest single inflight_sem.
        #     acquire() wait observed by the main submit loop
        #     since the last [LAG] snapshot. A large value means
        #     the in-flight limit is the bottleneck (all slots
        #     genuinely busy); a near-zero value means submission
        #     is flowing freely.
        # Both reset/refresh per snapshot. Both ship to [LAG] at
        # END of order tuple (column-safe).
        self._executor_qsize = 0
        self._submit_wait_s_max = 0.0

        # Stage counters: one integer per pipeline stage = number of
        # workers CURRENTLY in that stage, covering every accumulation
        # point between dedup and the LLM call. Worker increments on
        # entry, decrements on exit (in finally so exceptions can't
        # leak a count). The dict is keyed by stage name; iteration
        # over the keys in snapshot() emits all of them. Adding a
        # stage = add a key here + one inc/dec pair in main.py + one
        # entry in the snapshot/order tuple. Stages are listed in
        # pipeline order.
        self._stage_counters = {
            "post_dedup":       0,   # passed dedup, before fetches
            "graylog_fetch":    0,   # inside search_graylog
            "zeek_fetch":       0,   # inside fetch_zeek_flows
            "ntopng_fetch":     0,   # inside fetch_ntopng_flows
            "baseline":         0,   # inside calculate_baseline
            "ship1":            0,   # inside ship_to_graylog
            "rules":            0,   # inside evaluate_rule
            "escalation_check": 0,   # post-rules escalation logic
            "prompt_build":    0,   # inside build_prompt
            "llm_call":         0,   # inside call_llm
            # dedup and worker_run were added at the END so existing
            # fields keep their column positions for any grep/awk
            # that indexes by offset. dedup brackets the
            # is_duplicate() call so time spent at the dedup lock
            # (prune_cache contention or otherwise) is visible.
            "dedup":            0,   # inside is_duplicate (lock+work)
            # worker_run wraps the entirety of _worker_run. In a
            # [LAG] line, stage_worker_run=0 alongside
            # executor_pending>0 means workers are between jobs,
            # waiting at the queue.
            "worker_run":       0,   # entire _worker_run body
            # enrich appended at END (column-safe). Brackets enrich_alert,
            # which runs on EVERY alert and can block a worker for a DNS/
            # external lookup (PTR/rdns/geoip/abuse). Before this, enrich ran
            # outside all stage instrumentation — a worker slow/stuck here
            # showed worker_run active but NO stage, a [LAG] blind spot and a
            # watchdog false-positive risk (could look like parked-at-get()).
            "enrich":           0,   # inside enrich_alert (DNS/external lookups)
        }

        # --- REG-15 lock-free stage counters (2026-06-23) ---------------
        # The shared _stage_counters dict above is RETAINED as the canonical
        # set of valid stage names (and as the zero-base / column order for
        # the snapshot). It is NO LONGER mutated on the hot path.
        #
        # WHY: enter_stage/exit_stage bracket enrich and dedup on EVERY alert
        # (~4 lock-takes/alert). Taking self._lock there made the instrument
        # serialize ON the two primary convoy stages it measures
        # (measurement back-action), and fed a possibly-stale stage_worker_run
        # to the watchdog's abandon decision. (See GIL_convoy_fix.md REG-15.)
        #
        # FIX: each worker thread accumulates its OWN per-stage counts in a
        # thread-local dict. enter_stage/exit_stage touch ONLY the calling
        # thread's dict -> NO lock on the hot path -> no back-action, and the
        # recorded count can never be delayed by the contention it records.
        # snapshot() SUMS across all registered threads to reproduce the exact
        # same totals the shared dict held.
        #
        # The registry lock is taken ONCE PER THREAD (at first stage touch),
        # never per-access. Pool workers are long-lived (24 persistent
        # threads), so registrations are bounded and stable.
        self._stage_local = threading.local()
        self._stage_registry = []          # list of per-thread dicts
        self._stage_registry_lock = threading.Lock()
        self._stage_names = tuple(self._stage_counters.keys())

    def _my_stage_counts(self):
        """Return the calling thread's own per-stage count dict, creating
        and registering it on first use. After registration the worker
        mutates ONLY this dict, with no lock (single-writer per thread)."""
        d = getattr(self._stage_local, "counts", None)
        if d is None:
            d = {name: 0 for name in self._stage_names}
            self._stage_local.counts = d
            # One-time registration so snapshot() can find this thread's dict.
            with self._stage_registry_lock:
                self._stage_registry.append(d)
        return d

    def _sum_stage_counters(self):
        """Sum every registered thread's per-stage counts into the canonical
        {stage_name: total} shape the snapshot expects. Clamped at >=0 per
        stage (defensive; each worker's net is bounded by paired enter/exit).
        Snapshots the registry list under the registry lock (cheap, off the
        hot path), then sums outside the lock."""
        with self._stage_registry_lock:
            dicts = list(self._stage_registry)
        totals = {name: 0 for name in self._stage_names}
        for d in dicts:
            for name in self._stage_names:
                totals[name] += d.get(name, 0)
        for name in self._stage_names:
            if totals[name] < 0:
                totals[name] = 0
        return totals

    # --- Producer interface (called from main.py / process_alert) ---

    def note_reaped(self, n=1):
        """Called by each worker as it completes a job (workers
        self-reap in the pool design; there is no separate drain or
        reaper path). Accumulates until the next snapshot, which
        reads and zeroes it. Cheap, lock-guarded, decoupled from the
        pool's internals."""
        if n <= 0:
            return
        with self._lock:
            self._reaped_accum += int(n)

    def mark_stage(self, record_id, stage_name):
        """(Currently unwired — see the _stages note in __init__.)
        A worker has ENTERED `stage_name` for record_id.
        Overwrites any prior stage for that record (monotonic
        progress through the pipeline). enter_time = now. Cheap,
        lock-guarded; one call per stage transition."""
        with self._lock:
            self._stages[record_id] = (stage_name, time.time())

    def clear_stage(self, record_id):
        """(Currently unwired — see the _stages note in __init__.)
        record_id has left the pipeline (returned from
        _process_alert_inner — shipped, dedup-dropped, suppressed,
        or errored). Remove it so it no longer counts as in-flight.
        Idempotent (KeyError-safe) so a double-clear can never crash
        a worker or the emitter (instrument failure must never crash the instrumented)."""
        with self._lock:
            self._stages.pop(record_id, None)

    def set_executor_qsize(self, qsize):
        """Called from the main loop with the current work-queue
        qsize(). Pure observation; no behavioural effect. Defensive
        int() so a None/odd value never crashes the snapshot."""
        with self._lock:
            try:
                self._executor_qsize = int(qsize)
            except (TypeError, ValueError):
                self._executor_qsize = -1  # signal "could not read"

    def set_queue_ref(self, queue_obj):
        """Register the pool's work queue so the lag emitter
        can sample .qsize() FRESH at every snapshot, not just at
        cycle boundaries. Without this, executor_qsize in [LAG] is
        the value captured once per cycle (every 30s), which can be
        stale across the multi-snapshot reporting interval. With
        this, [LAG] reports executor_qsize as actually-now."""
        with self._lock:
            self._queue_ref = queue_obj

    def set_totals(self, seen, deduped):
        """Cumulative totals. Once per cycle main.py pushes
        total_seen and total_deduped so [LAG] can report
        dedup_rate_pct — making the actual dedup rate visible per
        snapshot. When deduped == seen, no full-pipeline work is in
        flight and an idle worker is the expected state; when
        deduped < seen, real work exists and worker activity should
        show in the stage counters."""
        with self._lock:
            try:
                self._cum_seen = int(seen)
                self._cum_deduped = int(deduped)
            except (TypeError, ValueError):
                pass

    def note_submit_wait(self, wait_s):
        """Called from the submit loop after each
        inflight_sem.acquire() returns, with the wall-clock seconds
        spent waiting. snapshot() reads-and-resets the max so the
        [LAG] line reports the worst acquire-wait seen during the
        prior snapshot interval — the direct measurement of whether
        the main loop is blocked at acquire or flowing freely."""
        if wait_s <= 0:
            return
        with self._lock:
            if wait_s > self._submit_wait_s_max:
                self._submit_wait_s_max = float(wait_s)

    def enter_stage(self, stage_name):
        """Worker has entered `stage_name`. Increment the calling thread's
        OWN per-stage counter (lock-free: single-writer per thread; see the
        REG-15 note in __init__). Defensive: unknown stage name silently
        ignored so a typo in the caller can never crash a worker (instrument
        failure must not crash the instrumented). MUST be paired with
        exit_stage in a finally block by the caller."""
        d = self._my_stage_counts()
        if stage_name in d:
            d[stage_name] += 1

    def exit_stage(self, stage_name):
        """Worker has exited `stage_name`. Decrement the calling thread's OWN
        counter (lock-free). Clamp at 0 per-thread so a double-exit (or exit
        without enter due to a code-path bug) can never push this thread's own
        count negative. Unknown stage name silently ignored, same reason as
        enter_stage. (Cross-thread totals are also clamped >=0 in
        _sum_stage_counters.)"""
        d = self._my_stage_counts()
        if stage_name in d:
            if d[stage_name] > 0:
                d[stage_name] -= 1

    def set_queue_depth(self, depth, oldest_alert_ts):
        """
        Set the current queue depth and the timestamp of the oldest
        alert still in queue. Called at cycle start with the freshly-
        read batch, and decremented as alerts complete.

        oldest_alert_ts is the Wazuh ISO timestamp string from the
        alert; we parse it to UNIX seconds here so the read path
        does no parsing under lock.
        """
        oldest_unix = _parse_alert_timestamp(oldest_alert_ts) if oldest_alert_ts else None
        with self._lock:
            self._queue_depth = max(0, int(depth))
            self._oldest_queued_ts = oldest_unix

    def mark_alert_processed(self, alert_ts):
        """
        An alert just finished the full triage pipeline. Update
        last_processed_ts and decrement queue depth. Called from the
        worker's result-handling path as it self-reaps a completed
        job.

        We do NOT recompute oldest_queued_ts here — that would require
        knowing the next-oldest alert in queue, which we don't track.
        The age metric stays accurate enough at cycle granularity;
        finer accuracy isn't worth the bookkeeping cost.
        """
        ts_unix = _parse_alert_timestamp(alert_ts)
        with self._lock:
            if ts_unix is not None:
                # Always advance to the latest processed timestamp.
                # Wazuh alerts can arrive out of order so we keep the max.
                if self._last_processed_ts is None or ts_unix > self._last_processed_ts:
                    self._last_processed_ts = ts_unix
            if self._queue_depth > 0:
                self._queue_depth -= 1
                # Queue drained — clear oldest timestamp so it reads
                # as 0.0 age in the next emit (the natural idle signal).
                if self._queue_depth == 0:
                    self._oldest_queued_ts = None

    def mark_cycle_complete(self, duration_s):
        """Record the just-completed cycle's wall-clock duration."""
        with self._lock:
            self._cycle_duration_s = float(duration_s)

    def set_executor_pending(self, count, oldest_submit_t=None):
        """
        Mirror main.py's in-flight work count (pool bookkeeping:
        inflight_count) so the lag emitter can include it in [LAG]
        lines. (Method and field keep the executor_ name for [LAG]
        grep compatibility — both predate the pool rewrite.)

        oldest_submit_t (optional): wall-clock time.time() of the
        OLDEST still-in-flight alert (main.py: min of
        inflight_submit_times). None when nothing is in flight.
        Drives pending_oldest_age_s, the clearest single
        is-work-completing signal (climbs while nothing finishes,
        resets when work flows). Still decoupled: main.py owns the
        in-flight bookkeeping and passes the derived scalar, not
        its internal structures.

        Called from main.py at the end of every polling cycle (and
        after drain operations). Negative values clamped to 0 in
        case of a bookkeeping race; arithmetic should never produce
        them, but defensive zero-clamp is essentially free.
        """
        with self._lock:
            self._executor_pending = max(0, int(count))
            self._oldest_pending_submit_t = oldest_submit_t

    def mark_llm_started(self):
        """Called before a call_llm() invocation."""
        with self._lock:
            self._llm_pending += 1

    def mark_llm_completed(self, latency_s):
        """
        Called in a finally block after call_llm(), regardless of
        success or failure. Records the latency in the rolling window
        and decrements the in-flight counter.
        """
        with self._lock:
            self._llm_pending = max(0, self._llm_pending - 1)
            self._llm_latencies.append(float(latency_s))

    # --- Snapshot interface (called from the emitter thread) ---

    def snapshot(self, now=None):
        """
        Capture a consistent point-in-time snapshot of all metrics.
        Returns a dict ready to be formatted as logfmt. now is the
        UNIX timestamp to compute ages against; defaults to time.time()
        but is parameterized for testability.
        """
        if now is None:
            now = time.time()
        with self._lock:
            queue_depth = self._queue_depth
            oldest_queued_ts = self._oldest_queued_ts
            last_processed_ts = self._last_processed_ts
            cycle_duration_s = self._cycle_duration_s
            llm_pending = self._llm_pending
            executor_pending = self._executor_pending
            oldest_pending_submit_t = self._oldest_pending_submit_t
            # read-and-reset: reaped count is per-interval
            reaped_since_last = self._reaped_accum
            self._reaped_accum = 0
            # copy() so the running mean doesn't see deque mutation
            # mid-calculation if a producer thread races us
            latencies = list(self._llm_latencies)
            # Snapshot the stage map inside the lock so the
            # oldest-record computation (done outside the lock) sees
            # a consistent point-in-time view.
            stages_snapshot = list(self._stages.values())
            # Read-and-reset executor_qsize (a snapshot of
            # the most recent set value — owner: main loop) and the
            # submit_wait_s_max (read-and-RESET: we want the per-
            # interval worst-wait, not lifetime).
            executor_qsize = self._executor_qsize
            submit_wait_s_max = self._submit_wait_s_max
            self._submit_wait_s_max = 0.0
            # Live queue ref — if registered, sample qsize()
            # fresh INSIDE the lock. Replaces the cycle-boundary
            # cached value with the actually-now state.
            _qref = self._queue_ref
            # Snapshot cumulative totals for dedup_rate_pct.
            cum_seen = self._cum_seen
            cum_deduped = self._cum_deduped
            # Per-stage counters are now LOCK-FREE (REG-15): summed across
            # all worker threads' thread-local dicts OUTSIDE self._lock, just
            # below. Nothing to read here under self._lock anymore.

        # Sample live queue OUTSIDE the lock (qsize takes its own
        # mutex internally; no nested locking).
        if _qref is not None:
            try:
                executor_qsize = _qref.qsize()
            except Exception:
                pass  # keep cached value

        # Per-stage counters: sum across all worker threads' thread-local
        # dicts (REG-15 lock-free). Computed OUTSIDE self._lock; uses its own
        # one-shot registry-lock to snapshot the thread list, then sums
        # lock-free. Produces the same {stage_name: total} shape the old
        # shared dict did, so stage_worker_run / stage_llm_call etc. are
        # unchanged for the [LAG] line and the watchdog.
        stage_counters_snap = self._sum_stage_counters()

        # Cumulative dedup ratio. 100.0 means every alert this run
        # was a dedup drop (no full-pipeline work — workers correctly
        # idle). <100 means full-pipeline work exists, so worker
        # activity should be visible in the stage counters.
        if cum_seen > 0:
            dedup_rate_pct = round(100.0 * cum_deduped / cum_seen, 1)
        else:
            dedup_rate_pct = 0.0

        # Derived values computed outside the lock — no shared state
        # touched here so we can take all the time we want.
        oldest_queued_age_s = (now - oldest_queued_ts) if oldest_queued_ts else 0.0
        last_processed_age_s = (now - last_processed_ts) if last_processed_ts else 0.0
        llm_latency_recent_s = (sum(latencies) / len(latencies)) if latencies else 0.0
        # pending_oldest_age_s — wall time the oldest in-flight
        # alert has been waiting. 0.0 when nothing is in flight.
        # Climbs while work is not completing; resets when it flows.
        pending_oldest_age_s = (
            (now - oldest_pending_submit_t)
            if oldest_pending_submit_t else 0.0
        )
        # Live worker-thread census. threading.enumerate() is cheap
        # and safe from this thread. Counts worker threads alive —
        # pairs with executor_pending / reaped_since_last so one
        # [LAG] line states both "how much work is pending" and
        # "how many workers exist to do it" as data. For the exact
        # frame each worker is in, use the SIGUSR1 stack dump
        # (see main.py).
        try:
            _workers = [
                t for t in threading.enumerate()
                if t.name.startswith("jsoc-worker")
                or t.name.startswith("jrsoc-worker")
                or t.name.startswith("jrsoc-pool")  # current pool naming
            ]
            workers_alive = sum(1 for t in _workers if t.is_alive())
        except Exception:
            workers_alive = -1  # census failed; -1 flags it, never crashes the emitter

        # stall_state: a one-word progress verdict so the reader
        # doesn't have to correlate raw columns (executor_pending,
        # reaped_since_last, pending_oldest_age_s) to answer "is
        # work flowing?". Field-name note: stall_state must appear
        # in BOTH this dict and the _format_logfmt order tuple — a
        # key present in one but not the other raises KeyError
        # inside the daemon emitter, which then dies silently and
        # [LAG] lines stop. Keep the two matched whenever fields
        # change.
        _stall_age_thresh = max(60.0, cycle_duration_s * 2.0)
        if executor_pending <= 0:
            stall_state = "idle"
        elif reaped_since_last == 0 and pending_oldest_age_s > _stall_age_thresh:
            stall_state = "STALL"
        elif reaped_since_last == 0:
            stall_state = "suspect"
        else:
            stall_state = "draining"

        # Per-record slow point. Of all in-flight records, which
        # stage is the OLDEST one currently in, and for how long.
        # Aggregate counters answer "is the pipeline busy"; this
        # answers "which specific stage is the slowest record at" —
        # the question that matters when locating a bottleneck.
        # stuck_stage=none when nothing is in flight. (stuck_* are
        # the established [LAG] field names; they stay for grep
        # compatibility.)
        if stages_snapshot:
            _oldest = min(stages_snapshot, key=lambda sv: sv[1])
            stuck_stage = _oldest[0]
            stuck_age_s = round(now - _oldest[1], 1)
            stuck_count = len(stages_snapshot)
        else:
            stuck_stage = "none"
            stuck_age_s = 0.0
            stuck_count = 0

        return {
            "queue_depth": queue_depth,
            "oldest_queued_age_s": round(oldest_queued_age_s, 1),
            "last_processed_age_s": round(last_processed_age_s, 1),
            "cycle_duration_s": round(cycle_duration_s, 1),
            "llm_pending": llm_pending,
            "llm_latency_recent_s": round(llm_latency_recent_s, 1),
            "executor_pending": executor_pending,
            "pending_oldest_age_s": round(pending_oldest_age_s, 1),
            "reaped_since_last": reaped_since_last,
            "workers_alive": workers_alive,
            "stall_state": stall_state,
            "stuck_stage": stuck_stage,
            "stuck_age_s": stuck_age_s,
            "stuck_count": stuck_count,
            # Appended at END (column-position safe): where a
            # backlog is held (queue) and whether submission is
            # blocked (acquire wait).
            "executor_qsize": executor_qsize,
            "submit_wait_s_max": round(submit_wait_s_max, 1),
            # Stage counters, appended at END (column-safe). One
            # field per accumulation point between dedup and the
            # LLM call; a persistently non-zero stage is where
            # worker time is going.
            "stage_post_dedup":      stage_counters_snap["post_dedup"],
            "stage_graylog_fetch":   stage_counters_snap["graylog_fetch"],
            "stage_zeek_fetch":      stage_counters_snap["zeek_fetch"],
            "stage_ntopng_fetch":    stage_counters_snap["ntopng_fetch"],
            "stage_baseline":        stage_counters_snap["baseline"],
            "stage_ship1":           stage_counters_snap["ship1"],
            "stage_rules":           stage_counters_snap["rules"],
            "stage_escalation_check":stage_counters_snap["escalation_check"],
            "stage_prompt_build":    stage_counters_snap["prompt_build"],
            "stage_llm_call":        stage_counters_snap["llm_call"],
            # Appended at end (column-position safe).
            "stage_dedup":           stage_counters_snap["dedup"],
            "stage_worker_run":      stage_counters_snap["worker_run"],
            # enrich appended at END (column-position safe).
            "stage_enrich":          stage_counters_snap["enrich"],
            # Cumulative dedup ratio at end (column-position safe).
            "dedup_rate_pct":        dedup_rate_pct,
        }


def _format_logfmt(snapshot):
    """
    Render a snapshot dict as logfmt key=value pairs in stable order.
    Stable ordering matters for grep/awk pipelines that index by
    column position.
    """
    order = (
        "queue_depth",
        "oldest_queued_age_s",
        "last_processed_age_s",
        "cycle_duration_s",
        "llm_pending",
        "llm_latency_recent_s",
        "executor_pending",
        # Appended (never insert mid-order — existing grep/awk
        # pipelines index by column position):
        "pending_oldest_age_s",
        "reaped_since_last",
        "workers_alive",
        # Appended at END (column-position safe): the one-word
        # progress verdict so the reaped-vs-pending relationship
        # never has to be correlated by eye.
        "stall_state",
        # Appended at END (column-position safe): the per-record
        # slow point. stuck_stage names WHICH pipeline stage the
        # oldest in-flight record is currently in; stuck_age_s how
        # long; stuck_count how many records are in flight.
        "stuck_stage",
        "stuck_age_s",
        "stuck_count",
        # Appended at END (column-position safe). executor_qsize:
        # jobs waiting in the queue; submit_wait_s_max: whether the
        # submit loop is blocked at the in-flight limit.
        "executor_qsize",
        "submit_wait_s_max",
        # Appended at END (column-position safe): one counter per
        # accumulation point between dedup and the LLM call. Must
        # stay in the same order as the return dict, and every key
        # must exist in both places — see the stall_state note in
        # snapshot().
        "stage_post_dedup",
        "stage_graylog_fetch",
        "stage_zeek_fetch",
        "stage_ntopng_fetch",
        "stage_baseline",
        "stage_ship1",
        "stage_rules",
        "stage_escalation_check",
        "stage_prompt_build",
        "stage_llm_call",
        # Appended at end (column-position safe).
        # stage_dedup: worker is at is_duplicate (lock-wait or work).
        # stage_worker_run: worker is anywhere inside _worker_run.
        # stage_worker_run=0 with executor_pending>0 means workers
        # are between jobs, waiting at the queue.
        "stage_dedup",
        "stage_worker_run",
        # enrich appended at END (column-position safe). stage_enrich:
        # worker is inside enrich_alert (a DNS/external lookup). Non-zero
        # here under a stall means workers are piling in enrich, NOT parked
        # at get() — distinguishes a slow-enrich backlog from a hand-off
        # stall, and explains any watchdog fire that coincides with it.
        "stage_enrich",
        # Cumulative dedup ratio at end (column-position safe).
        "dedup_rate_pct",
    )
    return " ".join(f"{k}={snapshot[k]}" for k in order)


class _LagEmitter(threading.Thread):
    """
    Background thread that periodically snapshots state and writes a
    [LAG] line to the jrSOCtriage logger.

    Lifecycle: start() spins it up as a daemon, stop() sets the stop
    event and the thread exits at its next loop iteration. Uses
    Event.wait(interval) instead of time.sleep() so stop() is
    responsive (max latency = one tick of the wait, which is the
    interval itself; we accept that — interval is typically 30s and
    process shutdown can afford a 30s grace).
    """

    def __init__(self, state, interval_seconds):
        super().__init__(name="lag-emitter", daemon=True)
        self._state = state
        self._interval = float(interval_seconds)
        # NOTE: must NOT name this attribute `_stop` — Python's
        # threading.Thread has an internal `_stop()` method called
        # during join(), and naming our Event `_stop` shadows it
        # with a non-callable, breaking join() in unrelated code.
        self._stop_event = threading.Event()
        # Error-class suppression: once we've warned about a given
        # exception type, suppress further warnings for the rest of
        # the run. Prevents log spam from a persistent issue
        # (disk full, permission flip, etc.).
        self._warned_errors = set()

    def run(self):
        # First emit happens after the first interval, not at startup.
        # Startup state is uninteresting (zero queue, no processed
        # alerts yet) and emitting it immediately just adds noise
        # to log diffs.
        while not self._stop_event.wait(self._interval):
            try:
                snap = self._state.snapshot()
                # [LAG] is emitted at DEBUG level so it's hidden from
                # operators running default logging (level=info). This
                # is a diagnostic tool, not authoritative — its numbers
                # are least reliable during quiet/dedup-heavy windows,
                # which are the very conditions it tends to be read
                # against during troubleshooting. The trustworthy
                # work-loss signal is the watchdog's abandoned_total.
                # To see [LAG] for active troubleshooting, set
                # logging.level = "debug" in config (exposed in the
                # interface's Debug section).
                logger.debug("[LAG] " + _format_logfmt(snap))
            except Exception as e:
                # Catch absolutely everything. The emitter must
                # never bring down the pipeline.
                err_class = type(e).__name__
                if err_class not in self._warned_errors:
                    self._warned_errors.add(err_class)
                    # Use the root logger here, not the lag logger,
                    # in case the lag logger is itself the problem.
                    logging.getLogger(__name__).warning(
                        f"lag emitter error ({err_class}): {e}. "
                        f"Suppressing further warnings of this class."
                    )

    def signal_stop(self):
        self._stop_event.set()


def start_lag_logger(state, config):
    """
    Spin up the lag emitter thread per config. Returns the thread
    handle (a _LagEmitter), or None if lag logging is disabled.

    Disabled when:
      - config.observability.lag_log_interval_seconds == 0
      - config.observability key missing entirely (back-compat with
        configs that predate this feature; defaults to disabled
        rather than guess an interval)
      - the value is not coercible to a number (hand-edited garbage):
        warn loudly and disable rather than crash startup — lag
        logging is optional observability, so unlike
        processing.max_workers (which exits) the proportionate
        response is to run without the instrument. A quoted-but-
        valid value like "30" coerces and works, matching the
        max_workers precedent for coercible values.
    """
    obs = config.get("observability", {}) if config else {}
    raw_interval = obs.get("lag_log_interval_seconds", 0)
    try:
        interval = float(raw_interval)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid observability.lag_log_interval_seconds=%r; "
            "lag logging disabled",
            raw_interval,
        )
        return None
    if interval <= 0:
        logger.debug("Lag logging disabled (interval=%s)", raw_interval)
        return None
    emitter = _LagEmitter(state, interval)
    emitter.start()
    logger.info(f"Lag emitter started (interval={interval}s)")
    return emitter


def stop_lag_logger(emitter):
    """Signal the emitter to stop. Safe to call with None."""
    if emitter is not None:
        emitter.signal_stop()
