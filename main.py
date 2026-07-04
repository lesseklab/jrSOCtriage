#!/usr/bin/env python3
"""
jrSOCtriage - Main Loop
Continuously polls Wazuh alerts and runs the full triage pipeline.

Pipeline per alert:
  1. Enrich - host lookup, IP enrichment, MITRE, canonical hostname
       (produces the dedup_key and the data the DB record needs)
  2. Record in database (all alerts, no filter)
  3. Dedup check - drop if seen within silence window
  4. Fetch context - Graylog logs, Zeek flows (if IPs present)
  5. Ship enriched GELF to Graylog
  6. If rule.level >= min_rule_level:
       - Build LLM prompt
       - Submit to thread pool (max_workers concurrent LLM calls)
       - Parse verdict
       - Ship updated GELF with LLM verdict
       - If NOTIFY/NOTE + confidence >= threshold: send email

NOTE: enrich + DB record currently run BEFORE dedup, so duplicate
alerts still pay enrich + DB before being dropped. Hoisting dedup
ahead of enrich/DB (so the ~90% duplicate-drop is truly cheap) is a
known optimization, not yet done — see findings/roadmap.
"""

import logging
import queue
import random
import threading
import signal
import sys
import time
from collections import Counter
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_running = True

def _handle_signal(signum, frame):
    global _running
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    _running = False

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# On-demand all-thread stack dump. `kill -USR1 <MainPID>` dumps the
# full stack of every thread — main loop, all pool workers, the lag
# emitter (when enabled), and the stall watchdog — to stderr, which
# under systemd goes straight to the journal
# (the same `journalctl -u jrsoctriage` stream). Zero cost when not
# signalled; no hot-path code. It's a troubleshooting aid: if workers
# ever appear unresponsive, this shows the exact frame each one is in.
# Fire it before any restart — in-flight state, and this evidence, are
# lost when the process exits.
#   PID=$(systemctl show -p MainPID --value jrsoctriage)
#   sudo kill -USR1 $PID
# Note: a worker blocked in a C call (e.g. a libsqlite write) shows the
# Python stack down to the .execute() boundary and stops there; that
# bottoming-out at a SQLite write is informative, not a failed dump.
import faulthandler
faulthandler.register(signal.SIGUSR1, all_threads=True, chain=False)


# ---------------------------------------------------------------------------
# Pipeline - process one alert
# ---------------------------------------------------------------------------

def process_alert(alert, config, hosts_data, conn, ntopng_session=None, rules=None, db_lock=None, lag_state=None):
    """
    Run the full pipeline for a single alert.
    Safe to call from multiple threads — each thread gets its own DB connection.
    Returns dict with processing results for logging.

    NOTE: the `conn` parameter is accepted but UNUSED — every call
    creates its own thread-local connection below (the fd-safety
    design). It is vestigial plumbing from the pre-thread-connection
    design; removing it end-to-end (signature, submit tuple, worker
    args) is deferred to v1.1 as a hot-path signature change.

    lag_state, if provided, is a LagState instance whose
    mark_llm_started()/mark_llm_completed() hooks are called around
    the call_llm() invocation. Optional so process_alert remains
    callable from contexts that don't need lag observability (tests,
    one-shot reprocessing).
    """
    if db_lock is None:
        db_lock = threading.Lock()  # fallback for single-threaded use

    # Each worker thread needs its own SQLite connection.
    # IMPORTANT: always close it before returning. Under Python 3.14.x,
    # relying on implicit cleanup of sqlite3.Connection objects caused
    # connections / file descriptors to accumulate in this hot path until
    # the process hit memory/FD pressure and failed. Python 3.13+ also emits
    # ResourceWarning for sqlite3.Connection objects that are deleted without
    # an explicit close() (CPython gh-105539). Explicit try/finally close is
    # the only safe pattern here.
    from database import get_connection
    thread_conn = get_connection(config)
    # Bound DB blocking. Without this, a corrupt or locked DB could make
    # a write block indefinitely — and a try/except cannot catch a call
    # that never returns. busy_timeout makes SQLite raise "database is
    # locked" after N ms instead of waiting, which the try/except wrappers
    # around the DB calls then catch and log. 500ms is chosen because a
    # healthy write is sub-1ms and normal brief drain/worker contention is
    # tens of ms, so 500ms never trips on a healthy DB; if a write ever did
    # block for tens of seconds, 500ms surfaces it ~10x faster than a 5s
    # value would. Low enough to fail fast, high enough never to drop a
    # healthy write under normal contention. Tunable if real contention
    # proves higher.
    try:
        thread_conn.execute("PRAGMA busy_timeout=500")
    except Exception as e:
        logger.warning(f"Could not set busy_timeout: {e}")

    try:
        return _process_alert_inner(
            alert, config, hosts_data, thread_conn,
            ntopng_session=ntopng_session, rules=rules, db_lock=db_lock,
            lag_state=lag_state,
        )
    finally:
        try:
            thread_conn.close()
        except Exception as e:
            logger.debug(f"thread_conn close raised: {e}")


def _process_alert_inner(alert, config, hosts_data, thread_conn,
                         ntopng_session=None, rules=None, db_lock=None,
                         lag_state=None):
    """Inner pipeline - thread_conn lifecycle is owned by the caller."""

    from ingest import safe_get
    from enrich import enrich_alert
    from database import record_alert, calculate_baseline
    from database import record_window_open, record_window_close
    from database import enqueue_window_close
    from dedup import is_duplicate
    from graylog_fetch import search_graylog, format_logs_for_prompt, parse_alert_timestamp, effective_context_time
    from zeek_fetch import fetch_zeek_flows
    from prompt_builder import build_prompt
    from llm_caller import call_llm, parse_llm_response, should_email
    from gelf_shipper import ship_to_graylog
    from email_sender import send_email
    from rules import evaluate_rule, record_rule_escalation

    result = {
        "dedup_key":  None,
        "level":      0,
        "dropped":    False,
        "enriched":   False,
        "shipped":    False,
        "triaged":    False,
        "emailed":    False,
        "verdict":    None,
        "confidence": None,
    }

    # Stage-counter helpers, defined before Step 1 so the post_dedup
    # bracket (which starts right after dedup returns False) can use
    # them. The stage counters instrument every accumulation point
    # between dedup and the LLM call, including the pass-off region
    # between dedup-return and graylog_fetch entry, so lag observability
    # covers the full path rather than leaving a gap there.
    def _enter(stage):
        if lag_state is not None:
            lag_state.enter_stage(stage)
    def _exit(stage):
        if lag_state is not None:
            lag_state.exit_stage(stage)

    # REG-02 entrance de-phasing (GIL/compat build only). A µs-scale lock hit
    # by a batch-released wave of 24 workers can't be self-spaced by the OS
    # (the hold ~3µs is far shorter than the scheduler's wakeup granularity
    # ~1-5ms), so the wave clumps onto the lock within one scheduler tick and
    # seeds a GIL convoy. _dephase injects the spacing the scheduler is too
    # coarse to provide: each worker sleeps a uniform-random 0..jitter_ms
    # BEFORE entering the contended lock, spreading arrivals across a window
    # wider than wakeup granularity. Sized at the wakeup floor (NOT hold×24,
    # which is ~0.069ms = irrelevant); final value tuned against
    # oldest_queued_age_s at GIL stress. Default 0 (off) — no effect on FT
    # (no convoy) and lets the GIL build A/B it. Mirrors the existing
    # get-jitter idiom (random.random()*0.010, main.py ~1082).
    def _dephase(jitter_ms):
        if jitter_ms > 0:
            time.sleep(random.uniform(0.0, jitter_ms / 1000.0))

    # --- Step 1: Enrich (needed for dedup key and DB record) ---
    # Bracketed as the "enrich" stage. enrich_alert runs on EVERY alert and
    # can block a worker for the duration of a DNS/external lookup (PTR,
    # rdns, geoip, abuse). Before this bracket, enrich ran OUTSIDE all stage
    # instrumentation: a worker slow/stuck here registered as stage_worker_run
    # active but in NO stage, which (a) was a [LAG] blind spot and (b) risked
    # the watchdog misreading a cluster of enrich-blocked workers as a
    # parked-at-get() stall (stage_worker_run could read low while work was
    # pending) and FALSELY abandoning workers that were just doing slow DNS.
    # Bracketing makes enrich-time visible and keeps the watchdog honest.
    _enter("enrich")
    try:
        enrichment = enrich_alert(alert, config, hosts_data)
    except Exception as e:
        logger.error(f"Enrichment failed: {e}")
        return result
    finally:
        _exit("enrich")

    dedup_key = enrichment.get("dedup_key", "unknown")
    level     = int(safe_get(alert, "rule", "level", default=0))
    result["dedup_key"] = dedup_key
    result["level"]     = level

    # --- Step 2: Dedup check (now BEFORE the DB write) ---
    # Dedup runs first so the ~85-90% of alerts that are duplicates are
    # dropped WITHOUT any DB write — that is the dedup-aggregated frequency
    # change. The per-window occurrence count is accumulated in the dedup
    # cache (in memory); the database is written only twice per window:
    # record_window_open when a window opens (below, AFTER the first-seen /
    # baseline reads so they see the table as it was before this alert), and
    # record_window_close when the window closes. enrich still runs before
    # dedup because it produces the dedup_key and canonical hostname.
    #
    # Per-rule dedup_silence_seconds override. rules.json can specify
    # dedup_silence_seconds per rule_id; when present, use that instead
    # of the global default. The lookup happens BEFORE the dedup check
    # so the per-rule value actually governs whether this alert
    # deduplicates.
    silence_seconds = config.get("processing", {}).get("dedup_silence_seconds", 240)
    if rules:
        rule_id = enrichment.get("gl2_rule_id", "")
        rule_entry = rules.get(str(rule_id))
        if rule_entry and "dedup_silence_seconds" in rule_entry:
            try:
                silence_seconds = int(rule_entry["dedup_silence_seconds"])
            except (TypeError, ValueError):
                pass  # malformed rule entry — fall back to global
    # REG-02: entrance de-phasing jitter for the dedup lock. GIL/compat-build
    # only (default 0 = off; FT has no convoy so it's left off there). The
    # dedup _lock is unavoidable and already µs-short (nothing to shrink), so
    # entrance jitter is the correct and only tool here.
    _dedup_jitter_ms = config.get("processing", {}).get("dephase_jitter_ms", 0)
    # Bracket the is_duplicate() call so the worker's time at dedup
    # (including lock-wait under contention, including any wait during a
    # prune_cache hold) is visible in [LAG]. This measures the worker's
    # perspective; don't instrument inside dedup.py itself or the
    # lock-wait window would be missed. The de-phase sleep is placed INSIDE
    # the bracket so the injected wait is included in the worker's measured
    # dedup-stage presence (ENTRANCE only — never key anything on _exit/tail).
    _enter("dedup")
    try:
        _dephase(_dedup_jitter_ms)
        _dedup = is_duplicate(dedup_key, silence_seconds)
    finally:
        _exit("dedup")

    # If this call re-anchored an expired window, a prior window just closed.
    # REG-03 Branch A: hand the final-count flush to the async db-writer thread
    # instead of doing the UPDATE+commit under db_lock on the hot path. Safe to
    # defer (window-expiry-triggered, never races its own open; baseline already
    # tolerates unclosed windows reading as opener count; drained on clean
    # shutdown). enqueue is non-blocking; count<=1 is skipped inside enqueue.
    if _dedup.close_dedup_key is not None:
        try:
            enqueue_window_close(
                _dedup.close_dedup_key,
                _dedup.close_window_ts, _dedup.close_count,
            )
        except Exception as e:
            logger.error(f"Window close enqueue failed for {_dedup.close_dedup_key}: {e}")

    if _dedup.is_dup:
        result["dropped"] = True
        logger.debug(f"Dedup drop: {dedup_key}")
        return result

    # is_duplicate() returned False, which GUARANTEES a fresh silence
    # window (new key, or expired window just reset). enrichment's
    # wazuh_first/last_seen were read BEFORE that check and, for the
    # first alert after an expiry, still carry the EXPIRED window's
    # storm timing — which would misinform the prompt's Alert-trail
    # line. (The prompt is the ONLY consumer of these two enrichment
    # fields: gelf_shipper ships the alert's own timestamp as
    # _wazuh_first_seen and never reads enrichment storm timing —
    # verified in the gelf_shipper audit.) Fresh window means first
    # occurrence:
    # the alert's own timestamp is the correct value for both (the
    # same semantics as enrichment's cache-miss branch). The pre-dedup
    # DB record retains the uncorrected read — accepted; the prompt
    # is the consumer that matters.
    _alert_ts = safe_get(alert, "timestamp")
    if _alert_ts != "N/A":
        enrichment["wazuh_first_seen"] = _alert_ts
        enrichment["wazuh_last_seen"] = _alert_ts

    result["enriched"] = True

    # Bracket the pass-off region (helper defs, timestamp parsing)
    # between the dedup return and context fetch, so a worker's time
    # spent here is visible in [LAG] rather than falling in a gap
    # between instrumented stages. _enter/_exit are defined at the top
    # of the function so this call site is reachable.
    _enter("post_dedup")
    try:

        # --- Step 4: Fetch context ---
        alert_time   = parse_alert_timestamp(alert)
        # For syscheck/FIM alerts, Wazuh's scheduled scan can detect a file
        # change minutes after it actually happened. Anchor the context
        # windows on the actual modification time when it is available and
        # recent — see graylog_fetch.effective_context_time for details.
        context_time = effective_context_time(alert, alert_time)
        graylog_logs = None
        zeek_data    = None
    finally:
        _exit("post_dedup")

    _enter("graylog_fetch")
    try:
        gl_messages  = search_graylog(config, enrichment["canonical_hostname"], context_time)
        graylog_logs = format_logs_for_prompt(gl_messages)
    except Exception as e:
        logger.warning(f"Graylog fetch failed for {dedup_key}: {e}")
    finally:
        _exit("graylog_fetch")

    ips = enrichment.get("ips", {})
    # Gate Zeek at the call site as well as inside zeek_fetch.py.
    # This avoids entering the zeek_fetch stage at all when
    # sources.zeek.enabled=false, which keeps disabled Zeek truly
    # zero-cost in LOAC/perf tests and prevents future fetch-module
    # changes from accidentally doing work while disabled.
    zeek_enabled = bool(config.get("sources", {}).get("zeek", {}).get("enabled", False))
    if zeek_enabled and ips.get("all") and context_time:
        _enter("zeek_fetch")
        try:
            zeek_data = fetch_zeek_flows(config, alert, ips["all"], context_time)
        except Exception as e:
            logger.warning(f"Zeek fetch failed for {dedup_key}: {e}")
        finally:
            _exit("zeek_fetch")

    # ntopng active flows (if enabled)
    ntopng_data = None
    if ips.get("all") and ntopng_session:
        _enter("ntopng_fetch")
        try:
            from ntopng_fetch import fetch_ntopng_flows, format_ntopng_for_prompt
            ntopng_results = fetch_ntopng_flows(config, ips["all"], ntopng_session=ntopng_session)
            if ntopng_results:
                ntopng_data = format_ntopng_for_prompt(ntopng_results)
        except Exception as e:
            logger.warning(f"ntopng fetch failed for {dedup_key}: {e}")
        finally:
            _exit("ntopng_fetch")

    # --- Step 5: Baseline ---
    baseline = None
    _enter("baseline")
    try:
        baseline = calculate_baseline(
            thread_conn, config,
            enrichment["gl2_rule_id"],
            enrichment["canonical_hostname"],
            alert_ts=alert_time.timestamp() if alert_time else None,
        )
    except Exception as e:
        logger.warning(f"Baseline calc failed for {dedup_key}: {e}")
    finally:
        _exit("baseline")

    # --- Step 6: Ship enriched GELF (without LLM result yet) ---
    _enter("ship1")
    try:
        # ship_to_graylog reports failure via a False return (output
        # disabled, host unconfigured, JSON/zlib/socket error,
        # oversize drop) — honor it, or the shipped counter counts
        # attempts instead of sends. This mattered MORE after the
        # serialization catch was added in gelf_shipper: errors that
        # previously raised (and counted failed) now return False.
        _sent = ship_to_graylog(
            alert, enrichment, baseline, config,
            graylog_logs=graylog_logs,
            zeek_data=zeek_data,
            ntopng_data=ntopng_data,
        )
        result["shipped"] = bool(_sent)
    except Exception as e:
        logger.error(f"GELF ship failed for {dedup_key}: {e}")
    finally:
        _exit("ship1")

    # --- Step 7: LLM triage ---
    min_level = config.get("filtering", {}).get("min_rule_level", 6)
    escalation_reason = None

    # --- Rules engine evaluation ---
    _enter("rules")
    try:
        rule_decision = evaluate_rule(
            enrichment.get("gl2_rule_id", ""),
            enrichment,
            config,
            thread_conn,
            rules=rules,
        )
    finally:
        _exit("rules")

    # --- Open the dedup window's DB row (AFTER baseline + first-seen reads) ---
    # The opener row is written here, not before dedup, so calculate_baseline
    # (step 5) and is_first_seen (inside evaluate_rule just above) read the
    # alert_history table as it was BEFORE this alert — preserving correct
    # first-seen detection (a genuinely new key reads zero prior rows) and
    # keeping this window out of its own baseline. The row carries count=1;
    # the final count is written by record_window_close when the window ends.
    # Only the window OPENER reaches here (duplicates returned at dedup); a
    # re-anchor pass also opens a fresh window and writes its opener row.
    if _dedup.open_window_ts is not None:
        try:
            # REG-03 Branch B: entrance de-phase OUTSIDE db_lock. The open
            # must stay SYNCHRONOUS (later alerts' baseline/first-seen reads
            # need this opener row immediately visible — see ordering note
            # above), so it can't be deferred or batched. Its commit is
            # already cheap (WAL) and its writers already ~10× thinned
            # (Item 25: only dedup survivors reach here). The residual is the
            # arrival collision of the passing-worker wave at db_lock, which
            # entrance jitter de-phases. Same dephase_jitter_ms knob as dedup
            # (REG-02); GIL/compat-build only (default 0 = off, FT unaffected).
            _dephase(_dedup_jitter_ms)
            with db_lock:
                record_window_open(thread_conn, enrichment, alert, _dedup.open_window_ts)
        except Exception as e:
            logger.error(f"Window open write failed for {dedup_key}: {e}")

    # Hard suppress from rules engine
    if rule_decision["should_escalate"] is False and not rule_decision["force_escalate"]:
        if rule_decision["rate_limit_hit"]:
            logger.info(f"Rate limit hit for {dedup_key}: {rule_decision['reason']}")
        elif rule_decision["maintenance_mode"]:
            logger.info(f"Maintenance mode suppressed {dedup_key}: {rule_decision['reason']}")
        else:
            logger.debug(f"Rules engine suppressed {dedup_key}: {rule_decision['reason']}")
        return result

    # The escalation_check stage brackets all the post-rules escalation
    # override logic (force_escalate, first_seen, always_include, abuse
    # score, baseline multiplier, escalate_if). It's all pure Python, so
    # this counter is here for completeness of the stage timeline rather
    # than because significant time is expected here.
    _enter("escalation_check")
    try:
        # Force escalate from rules engine
        if rule_decision["force_escalate"]:
            escalation_reason = f"Rules engine: {rule_decision['reason']}"

        # First seen note
        if rule_decision["first_seen"] and not escalation_reason:
            escalation_reason = f"Rules engine: {rule_decision['reason']}"

        # Escalation override 0: always_include networks or hosts
        always_include = config.get("filtering", {}).get("always_include", {})
        always_networks = always_include.get("networks", [])
        always_hosts = always_include.get("hosts", [])

        if not escalation_reason:
            import ipaddress
            all_ips = enrichment.get("ips", {}).get("all", [])

            for ip_str in all_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    for net in always_networks:
                        if ip_obj in ipaddress.ip_network(net, strict=False):
                            escalation_reason = f"IP {ip_str} is in always_include network {net}"
                            break
                except ValueError:
                    pass
                if escalation_reason:
                    break

            if not escalation_reason:
                canonical = enrichment.get("canonical_hostname", "")
                if canonical in always_hosts:
                    escalation_reason = f"Host {canonical} is in always_include hosts list"

        # Escalation override 1: high abuse score on external IP
        abuse_threshold = config.get("filtering", {}).get("abuse_escalation_threshold", 50)
        abuse_score = enrichment.get("gl2_abuse_score", "N/A")
        try:
            if abuse_score != "N/A" and int(abuse_score) >= abuse_threshold:
                escalation_reason = f"External IP abuse score {abuse_score} >= threshold {abuse_threshold}"
        except (ValueError, TypeError):
            pass

        # Escalation override 2: count > escalation_multiplier x daily average.
        # Gated by filtering.frequency_escalation_enabled (default true).
        # Operators can disable for testing (LOAC produces artificial rate
        # spikes that trigger this constantly) or for deployments that
        # don't want rate-based escalation at all.
        if baseline and not escalation_reason:
            frequency_escalation_enabled = config.get("filtering", {}).get(
                "frequency_escalation_enabled", True)
            if frequency_escalation_enabled:
                escalation_multiplier = config.get("processing", {}).get("escalation_multiplier", 4.0)
                count_24h  = baseline.get("count_last_24h", 0)
                daily_avg  = baseline.get("daily_avg", 0)
                has_baseline = baseline.get("days_of_data", 0) >= config.get(
                    "processing", {}).get("min_baseline_days", 3)
                if has_baseline and daily_avg > 0 and count_24h > daily_avg * escalation_multiplier:
                    escalation_reason = (
                        f"Alert count {count_24h} exceeds {escalation_multiplier}x "
                        f"daily average ({daily_avg})"
                    )
    finally:
        _exit("escalation_check")

    # Apply escalate_if conditions from rules engine
    if rule_decision["should_escalate"] is False:
        if not escalation_reason:
            logger.debug(f"Rules engine escalate_if not met for {dedup_key}: {rule_decision['reason']}")
            return result

    if level < min_level and not escalation_reason:
        logger.debug(f"Below min level ({level} < {min_level}), skipping LLM: {dedup_key}")
        return result

    if escalation_reason:
        logger.info(f"Escalation override for {dedup_key}: {escalation_reason}")

    if not config.get("llm", {}).get("enabled", False):
        return result

    _enter("prompt_build")
    try:
        prompt = build_prompt(
            alert, enrichment, baseline, hosts_data,
            graylog_logs=graylog_logs,
            zeek_data=zeek_data,
            ntopng_data=ntopng_data,
            config=config,
            escalation_reason=escalation_reason,
            rules=rules,
        )
    finally:
        _exit("prompt_build")

    try:

        # LLM call lifecycle is bracketed by lag_state hooks so the
        # background lag emitter can report in-flight count and rolling
        # latency mean. The mark_llm_completed call lives in a finally so
        # an exception in call_llm() (timeout, malformed response, network
        # error) still decrements the pending counter — otherwise a single
        # failed call would permanently inflate the reported in-flight
        # count and corrupt the lag metric.
        _llm_call_start = time.time()
        if lag_state is not None:
            lag_state.mark_llm_started()
        _enter("llm_call")
        try:
            response_text, llm_endpoint, llm_model, llm_anonymized, anon_prompt = call_llm(prompt, config, raw_config=config)
        finally:
            _exit("llm_call")
            if lag_state is not None:
                lag_state.mark_llm_completed(time.time() - _llm_call_start)

        # Determine which prompt to ship to Graylog based on config
        prompt_log_mode = config.get("logging", {}).get("prompt_log_mode", "anonymized")
        if prompt_log_mode == "none":
            logged_prompt = None
        elif prompt_log_mode == "deanonymized":
            logged_prompt = prompt  # pre-anon version
        else:  # "anonymized" (default)
            logged_prompt = anon_prompt if anon_prompt else prompt
        if llm_anonymized and not anon_prompt:
            logger.warning(f"[DEBUG] Anonymized flag set but anon_prompt is None for {dedup_key}")
        # parse_llm_response always returns a dict (it never returns
        # None — empty/unparseable input yields verdict=None with
        # parse_error set), so the attaches below are unconditional.
        llm_result = parse_llm_response(response_text)
        llm_result["endpoint"]   = llm_endpoint
        llm_result["model"]      = llm_model
        llm_result["anonymized"] = llm_anonymized
        # A non-empty response with no parseable VERDICT would otherwise
        # ship a verdict-less record to Graylog — invisible to the
        # documented gl2_llm_verdict:FAILED search and indistinguishable
        # from a record that never reached triage. Normalize it to the
        # FAILED verdict so the failure is searchable, consistent with
        # the synthetic FAILED emitted when all endpoints exhaust.
        # endpoint/model stay as the real endpoint that produced the
        # unparseable output, which is exactly what the operator needs
        # to know.
        if not llm_result.get("verdict"):
            _perr = llm_result.get("parse_error") or "unparseable LLM response"
            llm_result["verdict"]    = "FAILED"
            llm_result["confidence"] = "HIGH"
            llm_result["summary"]    = "LLM response could not be parsed into a verdict."
            llm_result["reasoning"]  = (
                f"Parse error: {_perr}. The first 200 chars of the raw "
                f"response are in the pipeline log ('LLM parse error' warning)."
            )
            if not llm_result.get("missing_info"):
                llm_result["missing_info"] = (
                    "Review this alert manually using the enrichment data "
                    "shipped alongside (zeek flows, ntopng data, host "
                    "context, baseline)."
                )

        result["triaged"]    = True
        # DB write is best-effort. A failed or slow escalation write must
        # not take down the pipeline. It holds db_lock, which after the
        # stats_lock split is shared ONLY with other survivors' DB writes
        # (open/close/escalation) — NOT with worker completion/stats, which
        # moved to stats_lock. So a slow escalation write stalls at most
        # other survivor writes (~10% of traffic), never the universal
        # completion path. Log loudly, drop the write, keep processing —
        # surfacing the failure while letting the pipeline survive.
        try:
            with db_lock:
                record_rule_escalation(
                    thread_conn,
                    enrichment.get("gl2_rule_id", ""),
                    enrichment.get("canonical_hostname", "unknown"),
                    rules=rules,
                )
        except Exception as e:
            logger.error(
                f"DB escalation write FAILED for {dedup_key} "
                f"(dropped, pipeline continuing): {e}"
            )
        result["verdict"]    = llm_result.get("verdict")
        result["confidence"] = llm_result.get("confidence")

        # Ship updated GELF with LLM verdict and full prompt
        try:
            _sent2 = ship_to_graylog(
                alert, enrichment, baseline, config,
                llm_result=llm_result,
                graylog_logs=graylog_logs,
                zeek_data=zeek_data,
                prompt=logged_prompt,
                ntopng_data=ntopng_data,
            )
            if not _sent2 and config.get("output", {}).get(
                    "graylog", {}).get("enabled", False):
                # Log symmetry with the failure modes ship1 surfaces
                # via the counter; ship2 has no counter of its own.
                # Gated on output.graylog.enabled: with GELF disabled
                # (email-only deployments), False is the designed
                # per-alert return, not a failure — erroring on every
                # triaged alert would spam a deliberate config choice.
                logger.error(
                    f"GELF ship (with LLM) returned False for {dedup_key}")
        except Exception as e:
            logger.error(f"GELF ship (with LLM) failed for {dedup_key}: {e}")

        # Email if warranted
        email_type = should_email(llm_result, config)
        if email_type:
            try:
                sent = send_email(alert, enrichment, baseline, llm_result, config, prompt=prompt)
                result["emailed"] = sent
                if sent:
                    logger.info(f"Email sent ({email_type}): {dedup_key}")
            except Exception as e:
                logger.error(f"Email failed for {dedup_key}: {e}")

    except Exception as e:
        logger.error(f"LLM triage failed for {dedup_key}: {e}")

    return result


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(config_path="config.json"):
    """
    Main pipeline loop. Runs until SIGINT or SIGTERM.
    """
    # --- Imports ---
    from ingest import (load_config, load_hosts, load_roles, read_new_alerts,
                        read_alerts_batch, load_position, save_position)
    from database import get_connection
    from dedup import prune_cache, flush_all_windows, snapshot_and_reset as dedup_snapshot_and_reset
    from llm_caller import warmup_model

    # --- Setup logging ---
    log_cfg   = {}
    log_level = logging.INFO
    log_file  = None

    try:
        import json
        with open(config_path) as f:
            cfg_check = json.load(f)
        log_cfg   = cfg_check.get("logging", {})
        log_level = getattr(logging, log_cfg.get("level", "info").upper(), logging.INFO)
        log_file  = log_cfg.get("log_file")
    except Exception:
        pass

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        try:
            handlers.append(logging.FileHandler(log_file))
        except OSError as e:
            print(f"Warning: Could not open log file {log_file}: {e}")

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )

    logger.info("=" * 60)
    logger.info("jrSOCtriage starting up")
    logger.info("=" * 60)

    # --- Load config and hosts ---
    try:
        config     = load_config(config_path)
        hosts_data = load_hosts(config)
        roles_data = load_roles(config)
        # Attach roles to hosts_data as a sibling key so enrich_alert can
        # reach it without threading a new roles_data argument through the
        # hot-path worker-submit chain (process_alert / _process_alert_inner /
        # _pool_submit), which the code defers as an invasive signature change.
        # hosts_data already threads everywhere enrich_alert is called. The
        # underscore marks it as internal context, not part of the hosts list.
        if isinstance(hosts_data, dict):
            hosts_data["_roles"] = roles_data
    except FileNotFoundError as e:
        logger.error(f"Startup failed: {e}")
        sys.exit(1)

    poll_interval = config.get("processing", {}).get("poll_interval_seconds", 30)
    min_level     = config.get("filtering",  {}).get("min_rule_level", 6)

    logger.info(f"Poll interval  : {poll_interval}s")
    logger.info(f"Min LLM level  : {min_level}")
    logger.info(f"LLM enabled    : {config.get('llm', {}).get('enabled', False)}")
    logger.info(f"Email enabled  : {config.get('email', {}).get('enabled', False)}")

    # Deployment identity — surfaced at startup so the operator can see which
    # org / security_domain this instance stamps on every GELF record
    # (jrsoc_org / jrsoc_security_domain). Empty/unset shows as "N/A", matching
    # what ships. Read-at-use-site, consistent with the rest of config.
    _deploy = config.get("deployment", {})
    logger.info(f"Deployment org : {_deploy.get('org') or 'N/A'}")
    logger.info(f"Security domain: {_deploy.get('security_domain') or 'N/A'}")

    # --- Operational mode messaging ---
    # Make the deployment shape obvious in logs. Three relevant cases:
    #   1) llm.enabled=false -> enrichment-only mode (deliberate choice)
    #   2) llm.enabled=true  + endpoints empty -> misconfiguration (every alert
    #      will fail triage); warn loudly so a first-time operator sees it
    #   3) llm.enabled=true  + endpoints present -> normal mode, no extra log
    _llm_cfg = config.get("llm", {})
    _llm_enabled = _llm_cfg.get("enabled", False)
    _llm_endpoints = _llm_cfg.get("endpoints", []) or []
    _llm_endpoints_active = [e for e in _llm_endpoints if e.get("enabled", True)]
    if not _llm_enabled:
        logger.info(
            "Mode: ENRICHMENT-ONLY (llm.enabled=false). Alerts will be enriched "
            "and shipped to Graylog with full context, but no LLM verdict will "
            "be generated and no email will be sent. Graylog stream rules "
            "filtering on _gl2_triage_complete:true will not match in this mode."
        )
    elif not _llm_endpoints_active:
        logger.warning(
            "llm.enabled=true but no LLM endpoints are configured (or all are "
            "disabled). Every alert that reaches the LLM stage will produce "
            "VERDICT: FAILED. Add at least one endpoint via the web interface "
            "(LLM Endpoints card), or set llm.enabled=false to run in "
            "enrichment-only mode deliberately."
        )

    # --- Database ---
    try:
        conn = get_connection(config)
        if not config.get("database", {}).get("enabled", True):
            logger.warning("=" * 60)
            logger.warning(
                "DATABASE OFF — running stateless. Disabled: alert "
                "history, baseline frequency context, rule "
                "rate-limiting, maintenance-mode suppression. "
                "In-memory dedup STILL ACTIVE (noise suppression "
                "intact). Expect HIGHER LLM call volume (rate-limit "
                "fails open). No DB writes means no DB-related failure "
                "modes. Recommended for high-alert-volume "
                "deployments.")
            logger.warning("=" * 60)
        else:
            logger.info("Database ready")
    except Exception as e:
        logger.error(f"Database init failed: {e}")
        sys.exit(1)

    # --- LLM warmup ---
    if config.get("llm", {}).get("enabled", False):
        if not warmup_model(config):
            logger.error("LLM warmup failed - triage will be disabled this session")
            config["llm"]["enabled"] = False

    # --- Rules engine ---
    from rules import load_rules
    rules = load_rules(config)
    logger.info(f"Rules engine     : {len(rules)} rule entries loaded")

    # --- Thread pool for concurrent LLM calls ---
    # Persistent pool: created once at startup, lives for the
    # process lifetime, shut down on SIGTERM. This replaces an earlier
    # design that recreated a ThreadPoolExecutor per ingest cycle
    # inside a `with` block. The per-cycle pattern enforced an implicit batch
    # barrier — ingest could not read the next batch until ALL workers
    # finished the current batch, which wasted up to ~30% of worker
    # capacity to tail latency (one slow alert held up the whole batch
    # while N-1 workers sat idle).
    #
    # With a persistent pool, workers stay continuously busy as
    # long as there is pending work. Ingest reads as fast as it can,
    # submits to the pool, and applies backpressure ONLY when the
    # in-flight count exceeds MAX_PENDING. This bounds memory growth
    # under sustained over-capacity load while letting workers
    # pipeline freely under normal load.
    # Hard-validated: a non-integer here (e.g. a quoted "2" hand-edited
    # into config.json) would propagate as a string into max_pending
    # arithmetic and range(); a value < 1 would start a pool with no
    # workers and the queue would never drain. Fail loud at startup
    # rather than misbehave quietly. (The interface clamps its input
    # to >= 1; this guards direct JSON edits.)
    try:
        max_workers = int(config.get("processing", {}).get("max_workers", 1))
    except (TypeError, ValueError):
        logger.error("Invalid processing.max_workers; must be an integer >= 1")
        sys.exit(1)
    if max_workers < 1:
        logger.error("Invalid processing.max_workers; must be an integer >= 1")
        sys.exit(1)
    # MAX_PENDING caps how many alerts can be in-flight (submitted but
    # not yet completed) at any time. Picked as 4× workers: small
    # enough to bound memory (at 20 workers, 80 in-flight alerts ≈ a
    # few MB of state) while large enough that workers rarely starve
    # waiting for queued work to complete. Empirically 4× is the
    # standard rule-of-thumb for worker-pool backpressure caps.
    MAX_PENDING_MULTIPLIER = 4
    max_pending = max_workers * MAX_PENDING_MULTIPLIER
    # The in-flight bound is a semaphore rather than a count-based gate:
    # acquire() before submit, the worker release()s on completion. This
    # design replaces an earlier max_pending gate plus a separate drain
    # thread with a single mechanism.
    inflight_sem = threading.Semaphore(max_pending)
    logger.info(f"Global workers   : {max_workers}")
    logger.info(f"Max pending      : {max_pending} (4x workers)")
    db_lock = threading.Lock()  # protects DB writes ONLY (open/close/escalation)
    # REG-03 follow-up (2026-06-24): stats_lock guards the in-memory completion
    # counters, split OUT of db_lock. Previously db_lock guarded BOTH slow DB
    # writes (record_window_open / record_rule_escalation, which can enter
    # SQLite busy_timeout — up to 500ms — when the async close-writer's separate
    # connection contends at the file lock) AND the per-completion stats block
    # that EVERY worker (incl. the ~90% dedup drops) passes through before
    # releasing its inflight_sem permit. So one survivor stuck in a slow open
    # held db_lock and stalled every worker's completion -> permits not released
    # -> submit loop starved -> queue built (observed oldest_queued_age_s -> 95s).
    # Splitting means a slow DB write blocks only other DB writers (~10%
    # survivors), never the universal completion path. stats_lock is held ONLY
    # for trivial counter math — never across a DB write, a log flush, or
    # another lock.
    stats_lock = threading.Lock()

    # ------------------------------------------------------------------
    # INGEST REDESIGN: dedicated reader thread + explicit handoff queue.
    #
    # Pre-redesign, the main thread did read -> submit-entire-batch ->
    # read, and the submit phase blocks on inflight_sem for the whole
    # batch. Under sustained over-capacity load the submit phase grows
    # (batch/throughput seconds), reads happen minutes apart in giant
    # gulps, and ingest-to-ship latency (process_time_s) becomes the
    # gulp interval. Run 10 (500x/60min): 8 reads in 39 minutes,
    # 53k alerts/gulp, process_time_s avg 153s.
    #
    # IMPORTANT: the ingest handoff queue is NOT sized from max_pending
    # and the reader does NOT decide how many raw alerts to read from
    # slow-worker/LLM queue geometry. That was wrong for duplicate-heavy
    # storms: dedup collapses the raw stream later, so using post-dedup
    # worker math to throttle pre-dedup ingest makes the system pretend
    # dedup does not exist. Here, handoff_queue_size is just an explicit
    # raw ingest buffer. The reader reads up to max_batch_size per pump
    # and blocks only when this actual queue is full.
    #
    # Position still advances at SUBMIT (offset high-water persisted by
    # the submit side). Read/queued but unsubmitted alerts re-read on
    # restart because position never advanced past them.
    #
    # Ledger (checked at shutdown):
    #   total_read     — alerts successfully queued by reader thread
    #                    (sole writer; main thread only reads it)
    #   total_drained  — items pulled off the handoff queue by main
    #   total_ingested — items actually handed to the pool (existing)
    #   invariant: total_read == total_drained + handoff_q.qsize()
    #   drained-but-unsubmitted (shutdown break) =
    #              total_drained - total_ingested; those re-read on
    #              restart because position never advanced past them.
    # ------------------------------------------------------------------
    # The ONLY throughput limit is max_batch_size (per-pump read size).
    # handoff_queue_size is a MEMORY ceiling, not a throughput knob.
    # DEFAULT = max_batch_size: the queue holds exactly one batch, so the
    # reader is at most one batch ahead of the drain — memory is bounded
    # (~2 batches peak: one in the queue, one in the drained list being
    # submitted) AND the reader can always put a full batch into an empty
    # queue, so this default NEVER throttles below max_batch_size. A cap
    # below one batch WOULD throttle (reader blocks mid-batch, silently
    # capping below max_batch_size) — that is rejected below.
    # Explicit 0 = unbounded (advanced: buffer limited only by the source;
    # risks unbounded memory if the source outpaces workers indefinitely —
    # opt in only when the source is known-finite or known-rate-limited).
    _read_max_batch = config.get("processing", {}).get(
        "max_batch_size", 250)
    try:
        handoff_cap = int(config.get("processing", {}).get(
            "handoff_queue_size", _read_max_batch))
    except (TypeError, ValueError):
        logger.error("Invalid processing.handoff_queue_size; "
                     "must be an integer >= 0 (0 = unbounded)")
        sys.exit(1)
    if handoff_cap < 0:
        logger.error("Invalid processing.handoff_queue_size; "
                     "must be an integer >= 0 (0 = unbounded)")
        sys.exit(1)
    if handoff_cap != 0 and handoff_cap < _read_max_batch:
        logger.error(
            f"processing.handoff_queue_size ({handoff_cap}) < "
            f"max_batch_size ({_read_max_batch}): a handoff cap below one "
            f"batch makes the reader block mid-batch and silently caps "
            f"throughput below max_batch_size. Set handoff_queue_size >= "
            f"max_batch_size, or 0 for unbounded.")
        sys.exit(1)
    # queue.Queue(maxsize=0) is unbounded; maxsize=N bounds to N items.
    # UNBOUNDED (maxsize=0): the reader's put() can never block, so a pool
    # stall can never propagate back and stall ingest. Work piles up HERE
    # (and downstream in _pool_work_queue) on a genuine pool stall — that is
    # the allowed, correct pile-up; ingest stays alive. handoff_cap retained
    # for the startup-guard log/validation only; it no longer bounds the queue.
    handoff_q = queue.Queue(maxsize=0)
    total_read = 0      # reader thread is the only writer; means queued
    total_drained = 0   # main thread is the only writer
    _ingest_logger = logging.getLogger("ingest")
    logger.info(
        f"Handoff queue size: "
        f"{'unbounded (0)' if handoff_cap == 0 else handoff_cap} "
        f"(memory ceiling, not a throughput limit); "
        f"max_batch_size={_read_max_batch} is the read-rate limit")

    def _ingest_reader_main():
        """Dedicated reader. Does not use slow-worker/LLM capacity to
        choose the raw read size. Keeps position state IN MEMORY (the
        position FILE is owned by the submit side, written at submit-time
        high-water).

        Two clocks, deliberately decoupled:
          PUMP  (0.5s): read up to max_batch_size raw alerts per pump,
                independent of max_pending/inflight worker geometry. If
                the explicit handoff queue itself is full, put() waits;
                that is real queue capacity, not hidden post-dedup math.
          HEARTBEAT (poll_interval): emit the legacy
                "Read N alerts at or above level 0" line with the count
                successfully queued since the last heartbeat, preserving
                the grep-able cadence signal operators/tools rely on.
        """
        nonlocal total_read
        PUMP_SLEEP = 0.5
        read_state = load_position(config)
        read_since_hb = 0
        q_full_waits = 0
        last_hb = time.time()
        while _running:
            try:
                items, new_state = read_alerts_batch(
                    config, read_state, min_level=0,
                    max_count=_read_max_batch,
                )
            except Exception as e:
                logger.error(f"Alert read failed: {e}", exc_info=True)
                items = []
            else:
                read_state = new_state
                cur_head = read_state.get("head")
                queued = 0
                for _alert, _off in items:
                    while _running:
                        try:
                            handoff_q.put(
                                (_alert, _off, cur_head), timeout=1.0)
                            queued += 1
                            break
                        except queue.Full:
                            q_full_waits += 1
                            continue
                    else:
                        break  # shutting down mid-queue
                total_read += queued
                read_since_hb += queued

            now = time.time()
            if now - last_hb >= poll_interval:
                # Legacy log shape preserved ("ingest: Read N alerts
                # at or above level 0") so existing greps keep working.
                suffix = (
                    f" (handoff queue full-wait {q_full_waits}x this window,"
                    f" cap={handoff_cap})" if q_full_waits else ""
                )
                _ingest_logger.info(
                    f"Read {read_since_hb} alerts at or above level 0"
                    f"{suffix}"
                )
                read_since_hb = 0
                q_full_waits = 0
                last_hb = now

            time.sleep(PUMP_SLEEP)
        logger.info("Ingest reader thread exiting")

    _reader_thread = threading.Thread(
        target=_ingest_reader_main, name="ingest-reader", daemon=True)

    # Diagnostics toggles. Read once at startup; these flags govern
    # whether per-alert / per-cycle instrumentation fires. Defaults are
    # picked so a normal deployment gets the structural signals without
    # the high-volume per-alert / per-cycle log lines. Operators can
    # enable the verbose markers in config.json when they want deeper
    # visibility. The stage_worker_run and stage_dedup brackets are
    # deliberately NOT configurable: the watchdog's stall detection
    # consumes stage_worker_run, so a toggle that disables it would
    # silently convert the watchdog into a false-abandonment generator
    # (a worker busy >30s in a non-LLM stage would read as idle). The
    # brackets cost one lock+int each per transition — always on.
    _diag = config.get("diagnostics", {})
    _DIAG_LOG_INGEST   = bool(_diag.get("log_ingest_marker", False))
    _DIAG_LOG_PICKUP   = bool(_diag.get("log_worker_pickup", False))
    # Watchdog config. The watchdog is a safety net from the stall
    # investigation: it detects no-progress (workers present in the pool
    # but the in-flight count not advancing) and, when abandon_on_stall
    # is set, "abandons" the stalled worker's slot — releases the
    # inflight semaphore so the pipeline keeps moving. "Abandon" is
    # accounting-only: it frees the SLOT, it does NOT kill the worker
    # thread, and the abandoned worker still returns and finishes its
    # alert. So abandoning a worker is not losing its work. (See the two
    # distinct counters below and in the watchdog loop: _abandoned_total
    # = worker slots released; _abandoned_completed = those workers that
    # came back and finished. These are unrelated to the shutdown-drain
    # "abandoned" counter, which is alerts still pending at service stop.)
    #
    # There is no longer any reason to enable it: the condition it was
    # built to catch has been root-caused and fixed. Cause = a GIL
    # hand-off convoy. Origin: ingest is pulsed (alerts arrive in
    # bursts), so before mitigation a pulse handed work to all 24 workers
    # at once and they hit the same serialization site (enrich was the
    # widest) in the same microsecond. 24 threads contending at a
    # GIL-bound site simultaneously is the convoy — the GIL hands off to
    # one, the other 23 pile up; workers end up starved/parked (some at
    # the queue get(), some stalled inside enrich BECAUSE of the convoy).
    # Fix = de-phasing: inject jitter so the workers no longer reach the
    # serialization sites in lockstep. It does not make those sites
    # faster; it breaks the synchronization the pulse imposed, so the
    # simultaneous pile-up never forms. Auditing and de-phasing every
    # such site resolved the stalls on the GIL build itself; running on
    # the free-threaded (no-GIL) interpreter, where the convoy cannot
    # exist, independently confirmed the cause (the stalls vanished with
    # the GIL removed). With the convoy gone the watchdog has nothing to
    # detect.
    #
    # It did fire in production during the investigation, before the fix:
    # on 2026-05-24 it abandoned 6 worker slots and all 6 of those
    # workers returned and finished their work (0 work lost), and that
    # firing is what carried the 6.4M/day load test through to completion
    # while the (then-undiagnosed) convoy stalls were occurring — i.e.
    # the watchdog was load-bearing in that test, not idle scaffolding.
    # Note the history: at the time, these 6 firings were ASSUMED to be
    # false positives, and that was a reasonable call then for two
    # reasons. (1) The watchdog mixes data sources: the authoritative
    # signal is a live atomic read of inflight_count from the pool's
    # pending dict under lock, but some of its inputs derived from [LAG],
    # which gives stale cached state and was known to be unreliable — so
    # a firing partly fed by bad [LAG] data was reasonably distrusted.
    # (2) The behavior self-resolved: what was observed was the pipeline
    # slowing down and then speeding back up and catching up, not
    # stopping and staying stopped. Because it always completed and
    # caught up, it did not read as a "stall" at the time — it looked
    # like bursty/uneven throughput, and the watchdog firing on it looked
    # like over-sensitivity. Only later, once the convoy was understood,
    # was "slows down then catches up, flagged by the watchdog"
    # recognized as the convoy forming and clearing — genuine transient
    # stalls, not noise — and the 6 firings re-read as real convoy
    # events. (Real signal present early and initially dismissed.) It has
    # not fired since the convoy was fixed. (Do NOT restore any "never
    # fired / abandoned_total=0 / no stalls ever happened" wording here —
    # that earlier claim was wrong; the 2026-05-24 event is the
    # documented counterexample. abandoned_total=0 only ever meant no
    # WORK was lost, never that no stall occurred.)
    #
    # The code is deliberately LEFT IN PLACE rather than removed. Its
    # hooks (the progress/age bracketing, the pending-age signal) touch
    # the whole pipeline, so ripping them out is a far larger and riskier
    # change than leaving dormant code that does nothing while disabled.
    # Disabled is fully disabled: with stall_watchdog_enabled=False the
    # watchdog thread is never started and nothing in the hot path runs.
    # Default is False (flipped 2026-06-12, Kevin). It can be opted back
    # in for diagnostics via diagnostics.stall_watchdog_enabled = true,
    # but a production deployment has no reason to. abandon_on_stall
    # (below) only matters if the watchdog is enabled; set it false to
    # observe-and-log without abandoning.
    _DIAG_WATCHDOG_ENABLED = bool(_diag.get("stall_watchdog_enabled", False))
    _DIAG_ABANDON_ON_STALL = bool(_diag.get("abandon_on_stall", True))
    _DIAG_STALL_THRESHOLD_S = float(_diag.get("stall_threshold_s", 30.0))
    _DIAG_WATCHDOG_INTERVAL_S = float(_diag.get("watchdog_interval_s", 5.0))
    logger.info(
        f"[DIAG] ingest_marker={_DIAG_LOG_INGEST} "
        f"worker_pickup={_DIAG_LOG_PICKUP}"
    )
    logger.info(
        f"[DIAG] watchdog_enabled={_DIAG_WATCHDOG_ENABLED} "
        f"abandon_on_stall={_DIAG_ABANDON_ON_STALL} "
        f"stall_threshold_s={_DIAG_STALL_THRESHOLD_S} "
        f"watchdog_interval_s={_DIAG_WATCHDOG_INTERVAL_S}"
    )

    # Custom polling pool, used instead of ThreadPoolExecutor. This is a
    # deliberately minimal worker pool: persistent threads pulling from a
    # queue.Queue, chosen over concurrent.futures so the pool's behavior
    # is fully visible and under our control rather than relying on
    # executor internals.
    #
    # Design:
    # - queue.Queue with get(timeout=2.0). The timeout is a safety net:
    #   workers wake at least every 2s even if no new item signals them,
    #   so a worker can never sit indefinitely while items wait in the
    #   queue. This guarantees forward progress without depending on the
    #   queue's wakeup behavior.
    # - Persistent worker threads in a simple while loop — no
    #   _idle_semaphore, no _adjust_thread_count, no concurrent.futures
    #   internals.
    # - Same _worker_run body (that function is unchanged).
    # - Submit interface: _pool_submit() replaces executor.submit().
    # - Shutdown: _pool_shutdown sets a flag, drops sentinels, joins.
    _pool_work_queue = queue.Queue()
    _pool_workers: list = []
    _pool_shutdown_event = threading.Event()

    def _pool_submit(*args):
        """Replaces executor.submit(_worker_run, *args). Just puts a
        tuple of args onto our queue. _worker_main pops and invokes
        _worker_run with the same arity."""
        _pool_work_queue.put(args)

    def _worker_main(worker_id):
        """Polling worker loop, used instead of concurrent.futures.thread.
        _worker. Wakes at least every 2s via the Queue.get timeout, which
        is the safety net that guarantees a worker never sits indefinitely
        while work is queued.
        """
        logger.info(f"Pool worker {worker_id} started")
        _empty_qsize_streak = 0
        while True:
            if _pool_shutdown_event.is_set():
                # Shutdown drain. The agreed shutdown behavior is: stop
                # ingesting (the submit loop exits when _running flips),
                # then give pending alerts up to the shutdown budget to
                # finish. Ingestion has stopped, so the queue can only
                # shrink: keep pulling and processing remaining work
                # until the queue is empty, then exit. Sentinels (None)
                # are wake-up signals, not work — skip them.
                try:
                    item = _pool_work_queue.get_nowait()
                except queue.Empty:
                    break
                if item is None:
                    _pool_work_queue.task_done()
                    continue
                try:
                    _worker_run(*item)
                except BaseException as e:
                    logger.error(
                        f"Pool worker {worker_id} unhandled exception "
                        f"from _worker_run during drain: {e}",
                        exc_info=True
                    )
                finally:
                    _pool_work_queue.task_done()
                continue

            # Normal operation: jittered timed get.
            # Timeout-overrun check. If get(timeout=2.0) blocks for
            # substantially longer than 2.0s, the queue's timeout isn't
            # being honored — worth a warning, since the 2s wakeup is
            # the pool's forward-progress guarantee. Cheap timing
            # wrapper: one time.time() call before, one after, and it
            # only logs when the threshold is exceeded.
            #
            # The 0-10ms jitter on the get() timeout staggers worker
            # wakeups. Workers that all hit the queue at the same
            # microsecond (e.g. after a batch of fast dedup-drops)
            # serialize on queue.Queue's internal threading.Lock +
            # Condition, and the collision burst briefly slows
            # whichever worker is doing heavier work (Stream 2
            # enrichment). Spreading each worker's timeout across an
            # 8ms window — wider than the OS scheduling quantum —
            # prevents the collision. Cost: a worker may sleep up to
            # 10ms longer when the queue is empty, which is free in
            # practice (the worker has no work anyway when the timeout
            # fires).
            _wait_start = time.time()
            _timeout = 2.0 + random.random() * 0.010
            try:
                item = _pool_work_queue.get(timeout=_timeout)
            except queue.Empty:
                _wait_dur = time.time() - _wait_start
                if _wait_dur > 3.0:
                    # The honored timeout would be ~2.0s + ~10ms jitter.
                    # >3.0s means the get() waited well past its timeout
                    # (or the thread was scheduled out for a long time) —
                    # either way, worth surfacing.
                    logger.warning(
                        f"[POOL_TIMEOUT_OVERRUN] worker {worker_id} "
                        f"get(timeout={_timeout:.4f}) blocked for {_wait_dur:.2f}s"
                    )
                # Queue consistency check. Empty-with-qsize>0 is usually
                # NOT an inconsistency: an item can arrive in the gap
                # between the get() timing out and the qsize() call —
                # normal racing, and the next loop iteration picks the
                # item up immediately. Only a REPEAT of that state on
                # consecutive timeouts (the item sat there through a
                # full 2s get without being delivered) is anomalous,
                # and even then it's a diagnostic curiosity, not an
                # operator action item — logged at DEBUG.
                _qsz = _pool_work_queue.qsize()
                if _qsz > 0:
                    _empty_qsize_streak += 1
                    if _empty_qsize_streak >= 2:
                        logger.debug(
                            f"[POOL_INCONSISTENT] worker {worker_id} "
                            f"got Empty on get() with qsize()={_qsz} "
                            f"on {_empty_qsize_streak} consecutive "
                            f"timeouts"
                        )
                else:
                    _empty_qsize_streak = 0
                continue
            _empty_qsize_streak = 0
            # Also log an overrun on a successful get if it took far
            # longer than the timeout — covers the case where get()
            # eventually returns an item but only after waiting
            # dramatically past the 2s bound.
            _wait_dur = time.time() - _wait_start
            if _wait_dur > 3.0:
                logger.warning(
                    f"[POOL_TIMEOUT_OVERRUN] worker {worker_id} "
                    f"get(timeout=2.0) returned item after {_wait_dur:.2f}s"
                )
            if item is None:
                # Sentinel: shutdown was signalled while this worker was
                # blocked in get(). Loop back so the drain branch at the
                # top finishes any remaining queued work before exit.
                _pool_work_queue.task_done()
                continue
            try:
                # item is the args tuple from _pool_submit. The
                # _worker_run signature is unchanged, just invoked
                # via a positional unpack here instead of through
                # the old executor's submit/future machinery.
                _worker_run(*item)
            except BaseException as e:
                # Defensive: any exception inside _worker_run that
                # escapes its own try/finally is logged here to
                # avoid the worker thread silently dying. Should be
                # unreachable since _worker_run has its own broad
                # except, but belt-and-suspenders.
                logger.error(
                    f"Pool worker {worker_id} unhandled exception "
                    f"from _worker_run: {e}", exc_info=True
                )
            finally:
                _pool_work_queue.task_done()
        logger.info(f"Pool worker {worker_id} shutting down")

    def _pool_start():
        """Spawn the worker threads. daemon=True so the process can
        always exit cleanly even if a worker thread is blocked in a
        call that never returns — a deliberate choice: process exit
        should never depend on every worker being joinable."""
        for i in range(max_workers):
            t = threading.Thread(
                target=_worker_main,
                args=(i,),
                name=f"jrsoc-pool-{i}",
                daemon=True,
            )
            t.start()
            _pool_workers.append(t)
        logger.info(
            f"Pool started with {max_workers} worker(s); "
            f"queue.Queue with get(timeout=2.0) polling"
        )

    def _pool_shutdown(wait_s):
        """Signal shutdown and try to join workers cleanly. A worker
        blocked in a non-returning call is not killed (Python can't);
        daemon=True means the process can exit regardless."""
        _pool_shutdown_event.set()
        # Drop sentinels so any worker blocked in get() wakes
        # immediately rather than waiting up to 2s for the timeout.
        for _ in _pool_workers:
            try:
                _pool_work_queue.put_nowait(None)
            except Exception:
                pass
        if wait_s > 0:
            deadline = time.time() + wait_s
            for t in _pool_workers:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                t.join(timeout=remaining)
            alive = sum(1 for t in _pool_workers if t.is_alive())
            if alive:
                logger.warning(
                    f"Pool shutdown: {alive} worker(s) did not exit "
                    f"within {wait_s}s — daemon threads will be torn "
                    f"down with the process"
                )

    # Watchdog. Defined here so the closure captures pending_lock,
    # inflight_submit_times, inflight_sem, and lag_state. Started below
    # if _DIAG_WATCHDOG_ENABLED.
    #
    # Mechanism:
    # - Wakes every _DIAG_WATCHDOG_INTERVAL_S seconds
    # - Reads a lag_state snapshot
    # - Checks the no-progress signature: stage_worker_run=0 AND
    #   llm_pending=0 AND stage_llm_call=0 AND executor_pending>0
    #   (workers idle, nothing in flight, yet alerts are waiting)
    # - Requires the signature to hold across N consecutive checks
    #   (N = ceil(stall_threshold_s / watchdog_interval_s)) so a brief
    #   quiet moment doesn't trigger it
    # - On a confirmed no-progress condition: abandon the oldest pending
    #   alert so the pipeline resumes
    # - "Abandon" = add submit_t to _abandoned_set, decrement
    #   inflight_count, release inflight_sem. This does NOT kill or
    #   interrupt the worker — the worker handling that alert can still
    #   finish it normally. "Abandon" only means the watchdog stops
    #   waiting on it and frees its slot so the pipeline resumes. If the
    #   worker does complete, its finally checks _abandoned_set first and
    #   skips its own decrement/release, so the alert isn't counted twice.
    # - RESIDUAL RISK if the completes-eventually theory fails (a worker
    #   truly wedged forever in some un-timeouted call): that thread can
    #   never be killed from Python, so its ~8MB stack plus the alert
    #   state in its frames is held for process lifetime, and — the real
    #   damage — that worker never returns to the queue, permanently
    #   reducing pool capacity (at max_workers=1, the entire pipeline:
    #   the watchdog would keep abandoning into a dead pool). Every
    #   external call in the pipeline carries a timeout (LLM, HTTP
    #   fetches, DB busy_timeout) precisely so this requires a
    #   pathological case. Detection: abandoned_total climbing in
    #   [WATCHDOG_HEARTBEAT] with no matching [ABANDON_RECOVERY] lines.
    #   Remedy is a service restart — the watchdog's job is to make the
    #   condition loud and keep what capacity remains moving, not to
    #   recover the thread.
    #   Note: the watchdog HAS fired in production. In every observed case
    #   the abandoned worker still returned and finished its alert normally —
    #   "abandon" is accounting-only (drop from inflight count, release sem),
    #   it does not kill the worker. So the "worker finishes afterward"
    #   behavior is observed, not just reasoned from the code. (Accuracy of
    #   the trigger itself is tracked separately — stage_worker_run staleness
    #   and presence-vs-progress semantics; see the GIL convoy fix doc REG-15.)
    import math as _math
    _stall_checks_needed = max(
        1, _math.ceil(_DIAG_STALL_THRESHOLD_S / _DIAG_WATCHDOG_INTERVAL_S)
    )

    def _watchdog_loop():
        nonlocal _abandoned_total, _abandoned_completed
        nonlocal inflight_count
        consec = 0
        # Watchdog heartbeat. Tick counter so the watchdog periodically
        # logs "alive" without spamming — one heartbeat per minute
        # (12 ticks at the 5s interval) confirms the watchdog thread is
        # still running.
        _wd_tick = 0
        logger.info(
            f"Stall watchdog started: threshold={_DIAG_STALL_THRESHOLD_S}s, "
            f"interval={_DIAG_WATCHDOG_INTERVAL_S}s, "
            f"checks_needed={_stall_checks_needed}, "
            f"abandon={_DIAG_ABANDON_ON_STALL}"
        )
        while _running:
            time.sleep(_DIAG_WATCHDOG_INTERVAL_S)
            if not _running:
                break

            # Outer defensive wrapper. Any exception from the snapshot,
            # locking, or abandonment path is logged and the loop
            # continues. Without this, an unexpected exception would kill
            # the watchdog thread silently — and the watchdog needs to
            # stay alive to do its job, so it must survive its own errors.
            try:
                _wd_tick += 1
                if _wd_tick % 12 == 0:
                    logger.info(
                        f"[WATCHDOG_HEARTBEAT] alive, "
                        f"consec={consec}, abandoned_total={_abandoned_total}"
                    )

                # Read snapshot for stage counters and LLM signals
                # (those are updated in real-time).
                snap = lag_state.snapshot()

                # Live pending check. lag_state's executor_pending is
                # sampled once per cycle (every 30s) by the main loop, so
                # during the 25-29s between samples the cached value can be
                # stale — it could say "4 pending" when workers have already
                # completed several. Reading inflight_count live under
                # pending_lock avoids acting on a stale count.
                # The oldest submit_t is captured in the same critical
                # section for consistency (count and oldest match).
                with pending_lock:
                    live_pending = inflight_count
                    live_oldest = (
                        min(inflight_submit_times)
                        if inflight_submit_times else None
                    )

                is_stall = (
                    snap.get("stage_worker_run", 0) == 0 and
                    snap.get("stage_llm_call", 0) == 0 and
                    snap.get("llm_pending", 0) == 0 and
                    live_pending > 0
                )

                if is_stall:
                    consec += 1
                else:
                    consec = 0  # reset on any sign of life

                if consec < _stall_checks_needed:
                    continue

                # Confirmed stall. We already have live_oldest from the
                # same critical section as live_pending. Use it. (Race
                # window between the check and abandonment is still
                # possible — worker could finish between our checks
                # and our abandonment — so we re-verify below.)
                if live_oldest is None:
                    # Race: stall signature said pending>0 but the list
                    # was empty at lock time. Skip; consec stays.
                    consec = 0
                    continue
                oldest = live_oldest
                age = time.time() - oldest

                logger.warning(
                    f"[STALL_DETECTED] consec_checks={consec} "
                    f"executor_pending={snap.get('executor_pending')} "
                    f"qsize={snap.get('executor_qsize')} "
                    f"oldest_age_s={age:.1f} "
                    f"abandoning={_DIAG_ABANDON_ON_STALL}"
                )

                if not _DIAG_ABANDON_ON_STALL:
                    # Observer mode: just log, don't abandon. Reset
                    # consec so the same no-progress event isn't
                    # re-logged every interval.
                    consec = 0
                    continue

                # Re-check under lock. Between the no-progress check and
                # now, a worker could have finished the oldest alert.
                # Re-verify it's still pending before abandoning, and do
                # the dec/release inside the same critical section so a
                # worker finally running concurrently sees a consistent
                # state.
                with pending_lock:
                    if oldest not in inflight_submit_times:
                        # Worker finished it between our check and now.
                        # Not a stall after all (or worker recovered).
                        # Skip abandonment, reset consec.
                        logger.info(
                            f"[STALL_AVERTED] submit_t={oldest:.3f} "
                            f"completed between detection and abandonment"
                        )
                        consec = 0
                        continue
                    # Still pending. Mark as abandoned and decrement.
                    with _abandoned_lock:
                        _abandoned_set.add(oldest)
                        _abandoned_total += 1
                        abandoned_total_snapshot = _abandoned_total
                    inflight_count -= 1
                    # REG-16: Counter decrement (was list.remove). Drop at zero.
                    if inflight_submit_times[oldest] > 1:
                        inflight_submit_times[oldest] -= 1
                    else:
                        inflight_submit_times.pop(oldest, None)

                try:
                    inflight_sem.release()
                except ValueError as e:
                    # Semaphore released too many times — would mean a
                    # logic error somewhere else. Log but don't crash.
                    logger.error(
                        f"[STALL_DETECTED] inflight_sem.release() raised: {e}"
                    )

                logger.warning(
                    f"[STALL_ABANDONED] submit_t={oldest:.3f} "
                    f"age_s={age:.1f} "
                    f"abandoned_total={abandoned_total_snapshot}"
                )

                # Reset consec so the watchdog doesn't immediately abandon
                # again on the next tick — the pipeline gets a full
                # threshold window to make progress before another
                # abandonment could happen.
                consec = 0

            except BaseException as e:
                # Outer guard: any exception in the loop body is logged
                # but does not kill the thread. The watchdog has to
                # survive its own errors to do its job — without this, a
                # single bad iteration would end the watchdog silently.
                logger.error(
                    f"[WATCHDOG_ERROR] iteration failed: {e}",
                    exc_info=True,
                )
                # Reset consec so we don't carry forward stale state
                # into the next iteration.
                consec = 0

    # The watchdog thread is defined here but started later, after
    # lag_state exists (it calls lag_state.snapshot()).
    _watchdog_thread = None

    # NOTE: _pool_start() is intentionally NOT called here.
    # _worker_main calls _worker_run, which is defined inside the
    # cycle loop below (nested for nonlocal access to counters and
    # batch state). Workers must spawn AFTER _worker_run exists.
    # The _pool_started flag below gates the spawn to fire exactly once
    # on the first cycle iteration. Python closures track rebinding via
    # cell references, so workers spawned during cycle 1 correctly
    # see cycle N's batch_alert_durations after the per-cycle
    # rebinding at the top of each cycle.
    _pool_started = False

    # In-flight tracking is a single integer plus a small list of
    # submit times (workers self-reap; nothing is tracked per job).
    # inflight_count is incremented at submit and decremented in the
    # worker's finally; inflight_submit_times gets the submit_t
    # appended/removed at the same points. BOTH are guarded by
    # pending_lock (and only pending_lock — db_lock guards the DB
    # writes (open/close/escalation) and stats_lock guards the completion
    # counters; both are separate concerns). The oldest
    # entry in inflight_submit_times drives the [LAG]
    # pending_oldest_age_s signal and the watchdog's age check.
    inflight_count = 0
    # REG-16: a Counter (multiset) instead of a list. On EVERY alert completion
    # the old `list.remove(submit_t)` was an O(n) linear scan under pending_lock,
    # where n = in-flight depth (up to 4x workers) — and the depth is HIGHEST
    # during a convoy, so the scan was longest exactly when the lock hold most
    # hurt. Counter gives O(1) increment (submit) and O(1) decrement (completion).
    # A multiset (not a set) is required: two alerts can share a submit_t (same
    # clock tick), and a set would collapse them and corrupt the count. min() of
    # the keys (watchdog/ACCOUNTING oldest-pending read) stays correct and runs
    # only on the 5s watchdog cadence, not the hot path. Membership (`in`) and
    # truthiness both work on a Counter as-is.
    inflight_submit_times = Counter()  # submit_t -> in-flight count (multiset)

    # Watchdog state. Tracks submit_t values the watchdog has already
    # abandoned, so the worker's finally doesn't double-release.
    # abandoned_completed and abandoned_total are counters for
    # visibility.
    _abandoned_set: set = set()  # submit_t values abandoned by watchdog
    _abandoned_lock = threading.Lock()
    _abandoned_total = 0
    _abandoned_completed = 0  # worker's finally fired after abandonment

    # pending_lock guards inflight_count and inflight_submit_times only.
    pending_lock = threading.Lock()

    # --- ntopng session ---
    ntopng_session = None
    if config.get("sources", {}).get("ntopng", {}).get("enabled", False):
        from ntopng_fetch import NtopngSession
        ntopng_session = NtopngSession(config)
        if ntopng_session.login():
            logger.info("ntopng session ready")
        else:
            logger.warning("ntopng login failed - ntopng enrichment disabled")
            ntopng_session = None

    # --- Lag observability emitter ---
    # Periodic [LAG] log lines for pipeline health monitoring (queue
    # depth, age-of-oldest-queued, LLM in-flight, cycle duration).
    # Driven by config.observability.lag_log_interval_seconds; 0 or
    # missing disables. Designed to share jrSOCtriage's main log
    # stream so future log-compliance work covers lag telemetry by
    # default without separate audit accounting.
    from lag_logger import LagState, NullLagState, start_lag_logger, stop_lag_logger
    # Lag observability is opt-in (observability.lag_log_interval_seconds,
    # default 0 = off). When off, use NullLagState so the per-alert stage
    # brackets and counters cost literally nothing — see NullLagState's
    # docstring in lag_logger.py for why the real state machine is too
    # expensive to leave running unconditionally at 40 workers.
    _lag_interval_raw = (config.get("observability", {}) or {}).get(
        "lag_log_interval_seconds", 0)
    try:
        _lag_enabled = float(_lag_interval_raw) > 0
    except (TypeError, ValueError):
        _lag_enabled = False
    lag_state = LagState() if _lag_enabled else NullLagState()
    lag_emitter = start_lag_logger(lag_state, config)

    # Register the queue with lag_state so [LAG] reports a fresh
    # qsize() on every snapshot, not just at cycle boundaries. Must be
    # after lag_state is created.
    lag_state.set_queue_ref(_pool_work_queue)

    # Start the watchdog thread AFTER lag_state exists —
    # _watchdog_loop calls lag_state.snapshot(), so it must not
    # start before lag_state is available.
    if _DIAG_WATCHDOG_ENABLED:
        _watchdog_thread = threading.Thread(
            target=_watchdog_loop,
            name="jrsoc-watchdog",
            daemon=True,
        )
        _watchdog_thread.start()

    # Start the anonymization alias flusher. Aliases minted during a run
    # live in anonymize.py's in-memory category caches; the flusher
    # periodically persists dirty categories to disk, and stop_anon_flusher()
    # (in the shutdown path below) does a final synchronous flush. Without
    # this, every alias minted since startup is lost on stop — the alias
    # tables would silently reset each run, breaking de-anonymization
    # continuity. Idempotent.
    from anonymize import start_anon_flusher
    start_anon_flusher()

    # REG-03 Branch A: start the async window-close writer thread. It owns its
    # own DB connection and applies deferred close-flushes off the hot path.
    # Only meaningful when the DB is enabled; when disabled the enqueue path is
    # a harmless no-op, but we still skip starting a thread that would do
    # nothing. stop_db_writer() in the shutdown path drains it.
    if config.get("database", {}).get("enabled", True):
        from database import start_db_writer
        start_db_writer(config)

    logger.info("Pipeline ready - entering main loop")
    logger.info("=" * 60)

    # --- Main loop ---
    cycle          = 0
    total_seen     = 0
    total_deduped  = 0
    total_shipped  = 0
    total_triaged  = 0
    total_emailed  = 0
    # Bookkeeping counters for the alerts_unaccounted detector. The
    # invariant: every alert that enters the pipeline must end up in
    # exactly one of three buckets — completed (worker finished it),
    # failed (worker raised; logged and counted), or still-in-flight
    # (counted in inflight_count). If
    #   ingested != completed + failed + pending
    # at any moment, accounting is broken — alerts are being dropped
    # somewhere we don't see. The detector emits this in the [LAG]
    # line and the [SHUTDOWN] line so any data-loss regression in
    # this code path surfaces within 30s of starting.
    total_ingested   = 0
    total_completed  = 0
    total_failed     = 0
    last_prune     = time.time()
    last_stats_time   = time.time()
    triaged_since_stats = 0
    # Track per-batch metrics for the [BATCH] line. Reset each ingest
    # cycle. Per-alert durations collected here cover the time from
    # submit_t to worker completion, including queue wait time when
    # pending exceeds workers.
    batch_alert_durations = []
    batch_dedup_drops = 0  # per-batch dedup counter (pre-loop init)

    # Start the dedicated reader. From here on, the main loop never
    # touches the alerts file — it drains the handoff queue and submits.
    _reader_thread.start()
    logger.info("Ingest reader thread started (dedicated read cadence)")

    while _running:
        cycle += 1
        cycle_start = time.time()

        # Drain the handoff queue. Block up to poll_interval for the
        # first item so quiet periods still tick (~poll_interval) for
        # the [DEDUP] heartbeat, then take everything already queued.
        # This queue is an explicit raw ingest buffer. It is not sized
        # from worker/LLM capacity; submit backpressure remains below
        # this point and must not decide raw read size.
        drained = []
        try:
            drained.append(handoff_q.get(timeout=poll_interval))
            while True:
                drained.append(handoff_q.get_nowait())
        except queue.Empty:
            pass
        total_drained += len(drained)
        alerts = [item[0] for item in drained]

        # [DEDUP] line: close the just-finished ingest-to-ingest window
        # and open a new one. Emitted every cycle, even on quiet cycles
        # where ingest=0, so operators get a steady heartbeat in the
        # journal. The internal rate sentinel -1.0 (returned when ingest=0,
        # no rate to compute) is rendered as rate_pct=N/A in the output so
        # the journal reads cleanly.
        #
        # Window semantics: window starts when this cycle's
        # snapshot_and_reset is called; window closes when the NEXT
        # cycle's snapshot_and_reset is called. The [DEDUP] line emitted
        # here describes the just-closed PRIOR window — it is
        # retrospective, a summary of completed work, not a list of
        # pending work.
        #
        # The counters deliberately exclude a derived "difference" field
        # (ingest - dedup - stream2): worker submit→decision lag crossing
        # a window boundary makes that value oscillate +N/-N across
        # adjacent windows, so it doesn't measure anything reliable. The
        # watchdog's abandoned_total is the authoritative "is work being
        # abandoned?" signal. The same clock split means rate_pct can
        # exceed 100 when a backlog drains (decisions landing in this
        # window for alerts ingested in earlier ones) — transient is
        # normal; persistent is a capacity signal. Operator guidance
        # lives in running_instructions' [DEDUP] reference.
        d_period_s, d_ing, d_dedup, d_s2, d_rate = \
            dedup_snapshot_and_reset(len(alerts) if alerts else 0)
        # Suppress emission for the bootstrap call (no prior window)
        if d_period_s > 0.0:
            # rate_pct is the -1.0 sentinel when ingest=0 (nothing to compute
            # a dedup rate from). Render that as N/A so the journal reads
            # cleanly instead of showing a cryptic impossible -1.0 percentage.
            d_rate_str = "N/A" if d_ing == 0 else f"{d_rate:.1f}"
            logger.info(
                f"[DEDUP] period_s={d_period_s:.1f} "
                f"ingest={d_ing} dedup={d_dedup} stream2={d_s2} "
                f"rate_pct={d_rate_str}"
            )
            # Inline reminder for the operator reading journalctl:
            # [DEDUP] above summarizes the window that just closed.
            # Reading it as forward-looking (pending work) is the
            # natural misread; this note heads it off.
            logger.info(
                "[DEDUP_NOTE] Dedup is retrospective of last ingest cycle."
            )

        # INGEST marker. High-cadence; gated behind a diagnostics
        # toggle. Pairs with [WORKER_PICKUP] to make the relationship
        # between ingest cycles and worker pickup visible when both
        # markers are enabled.
        if _DIAG_LOG_INGEST:
            logger.info(
                f"[INGEST_START] cycle={cycle} alerts={len(alerts)} "
                f"ts={cycle_start:.3f}"
            )

        if alerts:
            logger.info(f"Cycle {cycle}: {len(alerts)} new alert(s)")

        # Lag state: record this cycle's queue depth and oldest-alert
        # timestamp. We pull the oldest alert's `timestamp` field (Wazuh
        # ISO string); LagState parses to UNIX seconds internally. If
        # the timestamp field is missing, we pass None and the lag
        # emitter will report age 0.0 — acceptable degradation.
        if alerts:
            oldest_ts = None
            for a in alerts:
                ts = a.get("timestamp")
                if ts:
                    # alerts.json delivers in chronological order so
                    # the first non-empty timestamp is the oldest
                    oldest_ts = ts
                    break
            lag_state.set_queue_depth(len(alerts), oldest_ts)

        if alerts:
            # NOTE: total_ingested is incremented per successful submit
            # inside the loop below, not here. Up-front "+= len(alerts)"
            # caused a false [ACCOUNTING] alarm at clean shutdown:
            # alerts skipped via shutdown-break paths (5x in the loop:
            # _running checks before/during/after permit acquire, plus
            # RuntimeError/Exception submit paths) would be counted as
            # ingested but never reach completed/failed/inflight,
            # producing "alerts_unaccounted > 0 — data-loss bug" at
            # shutdown when nothing was actually lost. Unsubmitted
            # alerts will be re-read on next startup because
            # .ingest_position was never advanced past them.

            # Reset per-batch metrics. Attribution semantics: the
            # [BATCH] line emitted at the end of this cycle reports
            # completions OBSERVED during this cycle's submit window,
            # regardless of which cycle submitted them — pipelined
            # work from a prior cycle that finishes now is counted
            # now. Consequently completed_in_batch can exceed alerts,
            # and duration percentiles attribute to the window in
            # which work completed. The numbers are honest for "what
            # finished while this batch ran"; they are not a strict
            # per-submission-cohort report.
            batch_alert_durations = []
            batch_start_t = time.time()
            batch_first_complete_t = None
            batch_submit_count = 0
            batch_backpressure_waits = 0
            # Per-batch dedup counter so the [BATCH] line can say "of N
            # alerts, X dedup-dropped" — granular per-cycle visibility
            # rather than relying on the stats line every 5 minutes.
            batch_dedup_drops = 0

            # In-flight counter helpers. int is immutable so mutation
            # needs nonlocal; centralise the two mutations (submit-side
            # +1, worker-finally -1) under pending_lock for a consistent
            # [LAG]/[ACCOUNTING] read.
            def _inc_inflight(submit_t):
                nonlocal inflight_count
                with pending_lock:
                    inflight_count += 1
                    inflight_submit_times[submit_t] += 1   # REG-16: O(1)
            def _dec_inflight_and_forget(submit_t):
                nonlocal inflight_count
                with pending_lock:
                    inflight_count -= 1
                    # REG-16: O(1) decrement; drop the key at zero so min()
                    # and `in` stay correct and zero-count keys don't pile up.
                    if inflight_submit_times[submit_t] > 1:
                        inflight_submit_times[submit_t] -= 1
                    else:
                        # covers count==1 (normal) and count==0/absent (already
                        # gone, e.g. abandoned then completed) — del is safe via
                        # pop with default.
                        inflight_submit_times.pop(submit_t, None)

            # Worker body. A closure so it shares run()'s counters
            # directly. Runs the full pipeline (survivor DB writes —
            # window-open / escalation — under db_lock inside process_alert),
            # then does completion/stats accounting under stats_lock — NOT
            # db_lock; the two were split so a slow DB write can never stall
            # the universal completion path — marks lag state, and ALWAYS
            # releases the in-flight semaphore in finally. A per-alert
            # deadline is enforced as a soft timeout on result-handling
            # only — Python can't kill the underlying thread, so the
            # accepted trade is a bounded, loudly-logged failure rather
            # than an unbounded quiet one. submit_t is passed in for
            # duration metrics.
            def _worker_run(alert, _cfg, _hosts, _conn,
                            _ntop, _rules, _dblock, _lag, submit_t):
                nonlocal total_seen, total_deduped, total_shipped
                nonlocal total_triaged, total_emailed, total_completed
                nonlocal total_failed, triaged_since_stats
                nonlocal batch_first_complete_t, inflight_count
                nonlocal _abandoned_completed
                nonlocal batch_dedup_drops

                # WORKER_PICKUP marker. Logged immediately on entry,
                # before any processing. Pairs with [INGEST_START] to
                # make the queue-wait between submission and pickup
                # visible when both markers are enabled. High-cadence;
                # gated behind a diagnostics toggle.
                if _DIAG_LOG_PICKUP:
                    _pickup_t = time.time()
                    logger.info(
                        f"[WORKER_PICKUP] alert_ts={alert.get('timestamp', '?')} "
                        f"submit_t={submit_t:.3f} pickup_t={_pickup_t:.3f} "
                        f"queue_wait_s={_pickup_t - submit_t:.3f}"
                    )

                # STAGE_WORKER_RUN bracket. Counts when any work is
                # happening inside _worker_run. In a [LAG] line,
                # stage_worker_run=0 alongside executor_pending>0 means
                # workers are outside _worker_run (waiting at the queue),
                # which locates time spent at the queue/handoff layer
                # rather than inside alert processing.
                _lag.enter_stage("worker_run")
                try:
                    try:
                        result = process_alert(
                            alert, _cfg, _hosts, _conn,
                            ntopng_session=_ntop, rules=_rules,
                            db_lock=_dblock, lag_state=_lag,
                        )
                    except Exception as e:
                        logger.error(
                            f"Unhandled error processing alert: {e}",
                            exc_info=True,
                        )
                        with stats_lock:
                            total_failed += 1
                        _lag.mark_alert_processed(
                            alert.get("timestamp"))
                        return
                    alert_duration = time.time() - submit_t
                    batch_alert_durations.append(alert_duration)
                    if batch_first_complete_t is None:
                        batch_first_complete_t = time.time()
                    _lag.mark_alert_processed(alert.get("timestamp"))
                    # stats_lock (not db_lock): hold ONLY for the in-memory
                    # counter increments. note_reaped (its own lock) and the
                    # Triage log (a potentially slow synchronous flush) are
                    # deliberately OUTSIDE the lock so the universal completion
                    # path can never be stalled by a log write or a nested lock.
                    with stats_lock:
                        total_seen      += 1
                        total_completed += 1
                        if result["dropped"]:
                            total_deduped += 1
                            batch_dedup_drops += 1
                        if result["shipped"]:
                            total_shipped += 1
                        if result["triaged"]:
                            total_triaged += 1
                            triaged_since_stats += 1
                        if result["emailed"]:
                            total_emailed += 1
                    lag_state.note_reaped(1)
                    if result["triaged"]:
                        logger.info(
                            f"Triage: {result['dedup_key']} | "
                            f"[{result['level']}] "
                            f"{result['verdict']} / "
                            f"{result['confidence']}"
                        )
                finally:
                    _lag.exit_stage("worker_run")
                    # Abandonment-aware finally. If the watchdog already
                    # abandoned this submit_t, it already did the
                    # dec/release. Skip ours to avoid double-counting.
                    _was_abandoned = False
                    with _abandoned_lock:
                        if submit_t in _abandoned_set:
                            _abandoned_set.discard(submit_t)
                            _was_abandoned = True
                            _abandoned_completed += 1
                            _ac = _abandoned_completed
                    if _was_abandoned:
                        # The worker completed the work even though the
                        # watchdog had stopped waiting on it. Logged for
                        # visibility: it confirms abandoned work finishes
                        # late rather than being lost.
                        logger.info(
                            f"[ABANDON_RECOVERY] submit_t={submit_t:.3f} "
                            f"abandoned_completed_total={_ac}"
                        )
                    else:
                        _dec_inflight_and_forget(submit_t)
                        inflight_sem.release()

            # Gated pool spawn. Workers spawn exactly once, on the
            # first cycle iteration, AFTER _worker_run is first bound —
            # the gate guarantees the name exists before any worker can
            # call it. Name-resolution mechanics: _worker_main resolves
            # the name _worker_run through run()'s closure cell AT EACH
            # CALL, so workers always invoke the most recently bound
            # definition. Each cycle's `def _worker_run` rebinds that
            # cell with a new (identical-source) function object — the
            # re-definitions are redundant but harmless, not unused.
            # The same cell mechanism applies to the variables: whatever
            # instance is executing resolves batch_alert_durations /
            # batch_first_complete_t through cells at use time, so it
            # appends to the CURRENT cycle's objects (which is also why
            # completions attribute to the window they finish in — see
            # the batch-metrics attribution comment above).
            if not _pool_started:
                _pool_start()
                _pool_started = True

            # There is deliberately no separate drain/reaper thread.
            # Each worker runs _worker_run (below), which does the FULL
            # pipeline, then its own completion/stats accounting under
            # stats_lock (NOT db_lock — see the stats_lock split at its
            # declaration), then releases the in-flight semaphore in
            # `finally`. A slot
            # frees the INSTANT the worker completes — submission is
            # throttled by worker availability, never by a reaper's
            # cadence. (A separate reaper on its own schedule can hold
            # done-but-unreaped slots closed while a worker sits idle;
            # self-reaping workers make that impossible by design.)
            # No pending_futures dict, no drain thread, no
            # FIRST_COMPLETED wait.

            # Submission loop. Backpressure comes from
            # inflight_sem.acquire(): the loop blocks ONLY when
            # max_pending slots hold genuinely in-flight work, and a
            # slot is released by the WORKER on completion (success or
            # exception), not by a reaper. The slot frees the instant
            # work completes, and the pool is process-lifetime so
            # cycle N+1 pipelines freely with no per-cycle full-batch
            # barrier.
            # Per-batch position high-water. Set on each successful
            # submit; persisted once after the submit loop. Submit-time
            # persistence (vs the old read-time save) means a crash
            # loses NO read-but-unsubmitted alerts — they re-read on
            # restart. Items are FIFO from the reader, so the last
            # submitted offset IS the high-water.
            _hw_offset = None
            _hw_head = None
            for alert, _alert_off, _alert_head in drained:
                if not _running:
                    break

                # Hardened submit. Backpressure: block until a worker
                # frees a slot — the wait is on worker availability, not
                # on a separate reaper's cadence. Robustness choices:
                # - explicit _have_permit flag instead of probing
                #   inflight_sem._value (private API, racy)
                # - explicit _submitted flag prevents double-rollback
                #   on partial-success submit failures
                # - RuntimeError (pool shut down) caught separately
                #   for cleaner logs
                # - exc_info=True on unexpected for stack traces
                # - break submit loop on any failure (pool may be
                #   unhealthy; continuing would spam errors)
                # The acquire-wait is timed so [LAG] can report the
                # worst case per snapshot interval.
                _acq_start = time.time()
                _have_permit = False
                while not _have_permit:
                    if not _running:
                        break
                    _have_permit = inflight_sem.acquire(timeout=1.0)
                    if not _have_permit:
                        batch_backpressure_waits += 1
                _acq_wait = time.time() - _acq_start
                if _acq_wait > 0.0:
                    lag_state.note_submit_wait(_acq_wait)

                # If shutdown signal arrived during permit acquisition
                # without us ever acquiring, stop without releasing
                # (we never held a permit).
                if not _have_permit:
                    break

                # Shutdown can race with acquire(). If _running flipped
                # to False between acquire() returning True and this
                # check, release the permit and stop.
                if not _running:
                    inflight_sem.release()
                    break

                # Hardened submit with rollback. _submitted tracks
                # whether the work was actually accepted by the pool;
                # the rollback path uses this to avoid double-release if
                # something later fires. The underlying Queue.put rarely
                # raises (only edge cases like a corrupted queue object),
                # so the rollback path is mostly defensive — kept because
                # a wrong in-flight count would quietly skew the
                # accounting invariant checked at shutdown.
                _submit_t = time.time()
                _submitted = False
                try:
                    _inc_inflight(_submit_t)
                    _pool_submit(
                        alert, config, hosts_data, conn,
                        ntopng_session, rules, db_lock, lag_state,
                        _submit_t,
                    )
                    _submitted = True
                    batch_submit_count += 1
                    # Per-submit increment (paired with batch_submit_count)
                    # so total_ingested only counts alerts actually handed
                    # to the pool. Alerts skipped via shutdown-break paths
                    # don't inflate this counter, preserving the
                    # ingested == completed + failed + inflight invariant
                    # at shutdown.
                    total_ingested += 1
                    # Submit succeeded: this alert's file offset is now
                    # the persistence high-water (FIFO order guarantee).
                    _hw_offset = _alert_off
                    _hw_head = _alert_head
                except RuntimeError as e:
                    # Pool shut down or other RuntimeError. Don't
                    # keep trying — every subsequent submit would
                    # also fail with the same error.
                    logger.error(
                        f"Pool submit RuntimeError: {e}"
                    )
                    if not _submitted:
                        _dec_inflight_and_forget(_submit_t)
                    inflight_sem.release()
                    break
                except Exception as e:
                    # Includes BrokenThreadPool and any unexpected
                    # failures. Pool may be unhealthy; stop submitting.
                    # Known, accepted race: if submit raised AFTER the
                    # work item was actually queued, this rollback
                    # double-releases. The window is microseconds wide
                    # and the consequence is a transiently over-counted
                    # free slot — accepted rather than complicating the
                    # rollback path.
                    logger.error(
                        f"Failed to submit alert: {e}", exc_info=True
                    )
                    if not _submitted:
                        _dec_inflight_and_forget(_submit_t)
                    inflight_sem.release()
                    break

            # Submission complete. Persist the submit-time position
            # high-water (atomic temp+fsync+rename inside save_position).
            # Failure is logged, not fatal: a stale position re-reads
            # already-submitted alerts on restart — safe direction.
            if _hw_offset is not None:
                try:
                    save_position(_hw_offset, _hw_head, config)
                except Exception as e:
                    logger.error(f"Position save failed: {e}")

            # Workers self-reap as they finish, so
            # no post-submit inline drain exists or is needed. [BATCH]
            # below is submit-side only.

            batch_duration_s = time.time() - batch_start_t
            # Per-alert duration percentiles for [BATCH] line. If no
            # alerts completed within this cycle, percentiles default
            # to 0.0; that's accurate — none have measured durations
            # yet (they're still in flight).
            # FT-safety (review 2026-06-23): worker threads append to
            # batch_alert_durations concurrently with this read. Free-threaded
            # Python does NOT guarantee safe iteration of a list being mutated
            # by another thread (list.copy() IS atomic). Snapshot first, then
            # sort the snapshot. Metrics-only (never affected alert correctness),
            # but the snapshot removes the race cleanly.
            _durs_snapshot = batch_alert_durations.copy()
            if _durs_snapshot:
                sorted_durs = sorted(_durs_snapshot)
                n = len(sorted_durs)
                p50 = sorted_durs[n // 2]
                p95 = sorted_durs[min(n - 1, int(n * 0.95))]
                p99 = sorted_durs[min(n - 1, int(n * 0.99))]
                d_min = sorted_durs[0]
                d_max = sorted_durs[-1]
            else:
                p50 = p95 = p99 = d_min = d_max = 0.0

            first_complete_s = (
                (batch_first_complete_t - batch_start_t)
                if batch_first_complete_t else 0.0
            )
            # throughput_per_s is meaningful only when work completed
            # during a NON-TRIVIAL batch window. Two degenerate cases
            # both report 0.00: (a) instant submit with nothing
            # completed (microsecond window, the common unblocked
            # case), and (b) instant submit where prior-cycle
            # completions happened to land inside the microsecond
            # window — the per-window rate is then honest math but a
            # meaningless number (observed: 3 late completions in a
            # 2.6ms window = "1138/s"). The 0.5s floor keeps every
            # backpressured batch (the case the metric exists for)
            # and discards only windows too small to be a rate
            # denominator.
            # Use the SAME _durs_snapshot taken above for the counts, so the
            # whole [BATCH] line is internally consistent: a completion landing
            # between the snapshot and these reads can't make percentiles (from
            # the snapshot) disagree with completed_in_batch (live). Metrics-only,
            # but a snapshot is pointless if the rest of the line ignores it.
            _completed_in_batch = len(_durs_snapshot)
            throughput = (
                _completed_in_batch / batch_duration_s
                if (batch_duration_s >= 0.5 and _completed_in_batch > 0)
                else 0.0
            )
            logger.info(
                f"[BATCH] alerts={batch_submit_count} "
                f"workers={max_workers} "
                f"pending_after={inflight_count} "
                f"backpressure_waits={batch_backpressure_waits} "
                f"batch_total_s={batch_duration_s:.2f} "
                f"first_complete_s={first_complete_s:.2f} "
                f"throughput_per_s={throughput:.2f} "
                f"completed_in_batch={_completed_in_batch} "
                f"dedup_drops_in_batch={batch_dedup_drops} "
                f"full_pipeline_in_batch={_completed_in_batch - batch_dedup_drops} "
                f"alert_p50_s={p50:.2f} "
                f"alert_p95_s={p95:.2f} "
                f"alert_p99_s={p99:.2f} "
                f"alert_min_s={d_min:.2f} "
                f"alert_max_s={d_max:.2f}"
            )

        # Even when no new alerts arrived this cycle, nothing needs
        # draining here: workers self-reap as they complete, so the
        # in-flight count stays honest and [LAG] reflects current
        # reality without the submit/poll loop doing any reaping.

        # alerts_unaccounted check: the bookkeeping invariant. Real
        # data loss shows as a PERSISTENTLY POSITIVE value (an alert
        # ingested but never completed/failed/pending). A transiently
        # NEGATIVE value is a known benign race: a completing worker
        # increments total_completed under stats_lock, then decrements
        # inflight_count under pending_lock in its finally — in the
        # microseconds between, the alert is counted in both buckets,
        # and this unlocked read can land inside that window (one -1
        # per worker currently in it). So: alarm only on the loss
        # direction. A real loss coinciding with in-window completions
        # is masked for at most one check and caught on the next —
        # loss persists, the window doesn't.
        accounted = total_completed + total_failed + inflight_count
        unaccounted = total_ingested - accounted
        if unaccounted > 0:
            logger.error(
                f"[ACCOUNTING] alerts_unaccounted={unaccounted} "
                f"(ingested={total_ingested} completed={total_completed} "
                f"failed={total_failed} pending={inflight_count}) "
                f"— this indicates a data-loss bug; investigate immediately"
            )

        # Update lag state with the current in-flight count AND the
        # oldest in-flight submit time. Both read under pending_lock in
        # one critical section so the count and the oldest-age are
        # mutually consistent. min() of inflight_submit_times; None
        # when empty -> pending_oldest_age_s reads 0.0 (idle signal).
        with pending_lock:
            _pf_count = inflight_count
            _oldest_submit_t = (
                min(inflight_submit_times)
                if inflight_submit_times else None
            )
        lag_state.set_executor_pending(_pf_count, _oldest_submit_t)

        # Cumulative totals so [LAG] can report dedup_rate_pct —
        # gives the operator the actual dedup rate per snapshot
        # rather than leaving it to inference.
        with stats_lock:
            _seen_snap = total_seen
            _dedup_snap = total_deduped
        lag_state.set_totals(_seen_snap, _dedup_snap)

        # Report the pool's queue depth (jobs submitted but not yet
        # picked up by a worker). The queue is queue.Queue, so
        # .qsize() is a public, documented API. Try/except kept as
        # defense — instrument failure must never crash the
        # instrumented.
        try:
            _qsize = _pool_work_queue.qsize()
        except Exception:
            _qsize = -1
        lag_state.set_executor_qsize(_qsize)

        # Prune caches every 10 minutes
        if time.time() - last_prune > 600:
            from dedup import prune_cache
            from enrich import clear_enrichment_cache
            # Prune horizon is COUPLED to the LARGEST configured
            # silence window — the global default AND every per-rule
            # dedup_silence_seconds override in rules.json (the same
            # overrides the pre-dedup lookup in process_alert
            # honors). A horizon below any window in use silently
            # breaks it: a once-seen key gets evicted at the horizon
            # and a sparse repeat inside the operator's intended
            # window re-escalates early. max(3600, 2x largest) keeps
            # the old horizon for normal configs and guarantees prune
            # never undercuts ANY configured window. Active storms
            # are unaffected either way (prune is on last_seen, which
            # repeats refresh). Recomputed per prune (every 600s,
            # ~dozen entries) so a future rules reload is covered.
            _silence_candidates = [
                config.get("processing", {}).get(
                    "dedup_silence_seconds", 240)
            ]
            if rules:
                for _rule_entry in rules.values():
                    if (isinstance(_rule_entry, dict)
                            and "dedup_silence_seconds" in _rule_entry):
                        _silence_candidates.append(
                            _rule_entry["dedup_silence_seconds"])
            _max_silence_s = 240.0
            for _v in _silence_candidates:
                try:
                    _max_silence_s = max(_max_silence_s, float(_v))
                except (TypeError, ValueError):
                    pass  # malformed value — same fallback as the
                          # per-alert lookup in process_alert
            _closed_windows = prune_cache(max_age_seconds=max(3600.0, _max_silence_s * 2))
            # Each evicted key is a window that closed quietly (never
            # re-anchored). REG-03 GAP-1 FIX (P0): route these final-count
            # closes through the SAME async db-writer as the hot-path re-anchor
            # closes, instead of looping record_window_close synchronously under
            # db_lock in the MAIN thread. The old synchronous loop could pause
            # submission, hold db_lock across many commits during a large
            # quiet-key cleanup, and create exactly the burst-release this
            # campaign removes elsewhere — i.e. a convoy seed. enqueue is
            # non-blocking and already no-ops count<=1 internally (singleton
            # windows the opener already wrote cost nothing). Safe to defer for
            # the same reasons as Branch A: it finalizes a count on an
            # already-committed row, nothing reads that count back synchronously,
            # and the prune fires inside the main loop so it always precedes
            # stop_db_writer() in the shutdown path (no enqueue-after-stop).
            if _closed_windows:
                from database import enqueue_window_close
                for _ck, _cwts, _ccount in _closed_windows:
                    try:
                        enqueue_window_close(_ck, _cwts, _ccount)
                    except Exception as e:
                        logger.error(f"Prune-time window close enqueue failed for {_ck}: {e}")
            clear_enrichment_cache()
            last_prune = time.time()
            logger.debug("Caches pruned")

        # Stats every 10 cycles
        if cycle % 10 == 0:
            now = time.time()
            elapsed_min = (now - last_stats_time) / 60.0
            llm_rpm = round(triaged_since_stats / elapsed_min, 1) if elapsed_min > 0 else 0.0
            logger.info(
                f"Stats | seen={total_seen} deduped={total_deduped} "
                f"shipped={total_shipped} triaged={total_triaged} "
                f"emailed={total_emailed} | llm_rpm={llm_rpm}"
            )
            last_stats_time = now
            triaged_since_stats = 0

        # Lag state: record this cycle's wall-clock duration. Captured
        # after the cycle body but before the sleep so the metric
        # reflects work-time, not work-plus-idle. A cycle that runs
        # the full poll_interval is fully utilized; a cycle that runs
        # much less is mostly idle.
        lag_state.mark_cycle_complete(time.time() - cycle_start)

        # No unconditional tail sleep. Pacing now comes from the
        # handoff_q.get(timeout=poll_interval) at the top of the loop:
        # quiet periods tick at poll_interval; loaded periods loop
        # immediately to drain and submit. The OLD tail sleep here would
        # reintroduce an artificial raw-ingest cap and must not return.

    # --- Shutdown ---
    logger.info("Shutting down...")
    # Give the reader a brief chance to finish its current put loop before
    # computing the queue ledger. This avoids false mismatch warnings from
    # sampling while the daemon reader is still exiting.
    _reader_thread.join(timeout=2.0)
    # INGEST LEDGER: the read-side invariant (companion to the
    # ingested/completed accounting below). Queue integrity:
    # everything the reader queued was either drained or is still in
    # the queue. drained-but-unsubmitted (shutdown broke the submit
    # loop) re-reads on restart because position never advanced past
    # it — reported, not lost.
    _q_remaining = handoff_q.qsize()
    _unsubmitted = total_drained - total_ingested
    if total_read != total_drained + _q_remaining:
        logger.warning(
            f"[INGEST_LEDGER] MISMATCH read={total_read} "
            f"drained={total_drained} queued={_q_remaining} "
            f"(read != drained + queued; delta="
            f"{total_read - total_drained - _q_remaining}) — "
            f"queue integrity bug, investigate"
        )
    else:
        logger.info(
            f"[INGEST_LEDGER] read={total_read} "
            f"submitted={total_ingested} "
            f"drained_unsubmitted={_unsubmitted} "
            f"queued_unsubmitted={_q_remaining} (clean; "
            f"unsubmitted re-read on next start)"
        )
    # Capture the moment the shutdown section begins. NOTE: this is
    # NOT the moment the signal arrived — the main loop observes
    # _running at its top, so up to one poll interval can elapse
    # between SIGTERM and reaching here, and the worker keeps
    # completing work in that gap. The count captured below is
    # therefore pending-at-shutdown-start; fast items (dedup drops)
    # submitted just before the signal may already be done and will
    # not appear in it. Used with actual_shutdown_s so operators can
    # judge whether SHUTDOWN_TIMEOUT_S (85s) needs adjustment.
    shutdown_start_t = time.time()
    with pending_lock:
        pending_at_shutdown_start = inflight_count

    # Graceful drain. The shutdown design: stop ingesting (the submit
    # loop has already exited), then give pending alerts up to
    # SHUTDOWN_TIMEOUT_S to finish. Workers drain the remaining queue
    # (see the drain branch in _worker_main) and release their in-flight
    # slots as each alert completes; this loop just waits for
    # inflight_count to reach 0 or the budget to expire.
    #
    # 85s is the v1.0 budget. Sizing: max_pending is fixed at 4x
    # workers and drain parallelism scales with workers, so the worst
    # realistic drain is ~4 slow local-LLM calls per worker slot
    # (~20s each) ≈ 80s regardless of worker count; 85s covers it
    # (worst observed in production: 18.2s). The deliberately-
    # sacrificed case: a degraded run where cloud-fallback retries
    # stretch per-alert time well past ~21s — that drain times out
    # and still-queued alerts are dropped in favor of a fast restart
    # (the LLM stack is already unhealthy in that scenario, and the
    # in-flight alerts still ship). Hardcoded intentionally — adding
    # a config knob for every operational parameter bloats the
    # config surface. The [SHUTDOWN] line below captures
    # actual_shutdown_s and timed_out, so operators have data to
    # revisit the number.
    #
    # COUPLED SETTING: jrsoctriage.service sets TimeoutStopSec=100 so
    # systemd's SIGKILL arrives after this budget elapses (15s of
    # headroom for the join attempts and final logging below). If
    # either number changes, reconsider the other: the drain budget
    # must stay comfortably inside systemd's stop timeout or SIGKILL
    # cuts the drain off midway.
    SHUTDOWN_TIMEOUT_S = 85.0
    # Graceful drain: there is no drain thread to stop — workers
    # self-reap and release the semaphore on completion. Setting the
    # shutdown event flips workers into drain mode (see the drain
    # branch in _worker_main): each worker finishes its current
    # alert, then keeps pulling and processing queued alerts until
    # the queue is empty, then exits. This loop waits for
    # inflight_count to fall to 0 within the budget.
    _pool_shutdown(wait_s=0)  # signal shutdown but don't join yet — let workers drain naturally
    while (time.time() - shutdown_start_t) < SHUTDOWN_TIMEOUT_S:
        with pending_lock:
            _remaining = inflight_count
        if _remaining <= 0:
            break
        time.sleep(0.2)

    actual_shutdown_s = time.time() - shutdown_start_t
    with pending_lock:
        abandoned = inflight_count
    timed_out = abandoned > 0

    if timed_out:
        # Hard cutoff: pool is already in shutdown_event state. Any
        # worker still running cannot be cancelled (Python threading
        # has no safe interruption); they will finish their LLM call
        # and exit silently. The corresponding alerts are lost — an
        # accepted shutdown trade-off, bounded to <=SHUTDOWN_TIMEOUT_S
        # of work. Daemon threads will be torn down with the process.
        logger.warning(
            f"Shutdown timeout reached with {abandoned} pending alert(s); "
            f"daemon worker threads will exit with the process"
        )
        # Brief join attempt for any worker that's between alerts.
        _pool_shutdown(wait_s=1.0)
    else:
        # Clean drain. Try to join workers with a short timeout; any
        # still-blocking ones are daemon and will be torn down on exit.
        _pool_shutdown(wait_s=5.0)

    # Signal the lag emitter to exit. The emitter is a daemon thread
    # so the process can exit without joining, but signalling first
    # lets it skip its next wait-tick and exit promptly. join() with
    # a short timeout to give it a chance without blocking shutdown
    # on a slow log handler.
    stop_lag_logger(lag_emitter)
    if lag_emitter is not None:
        lag_emitter.join(timeout=2.0)

    # REG-03 Branch A: drain + stop the async window-close writer NOW — after
    # the pool has drained (so every re-anchor close a worker produced is
    # already enqueued) and BEFORE the shutdown window-flush below. Draining
    # first means the writer thread (and its own connection) is fully done
    # before flush_all_windows writes on `conn`, so there are never two
    # connections writing alert_history concurrently. A clean shutdown drains
    # the queue to empty -> zero deferred closes lost.
    if config.get("database", {}).get("enabled", True):
        try:
            from database import stop_db_writer
            stop_db_writer()
        except Exception as e:
            logger.error(f"db-writer shutdown drain failed: {e}")

    # --- Shutdown flushes (workers have drained; caches are now final) ---
    # 1. Dedup windows: every window still open in the dedup cache holds an
    #    accumulated count in memory. Flush each to the DB so the frequency
    #    baseline keeps the suppressed-duplicate counts instead of discarding
    #    them at exit. record_window_close is a no-op for count<=1, so quiet
    #    singleton windows cost nothing. Under db_lock to match every other
    #    write. Safe to run after the drain: no worker is mutating the cache.
    try:
        _shutdown_windows = flush_all_windows()
        if _shutdown_windows:
            from database import record_window_close as _rwc_shutdown
            with db_lock:
                for _ck, _cwts, _ccount in _shutdown_windows:
                    try:
                        _rwc_shutdown(conn, _ck, _cwts, _ccount)
                    except Exception as e:
                        logger.error(f"Shutdown window close failed for {_ck}: {e}")
    except Exception as e:
        logger.error(f"Dedup shutdown flush failed: {e}")

    # 2. Anon aliases: signal the flusher thread to exit and do a final
    #    synchronous flush of any dirty alias categories, so aliases minted
    #    during this run persist to disk (de-anonymization continuity across
    #    restarts).
    try:
        from anonymize import stop_anon_flusher
        stop_anon_flusher()
    except Exception as e:
        logger.error(f"Anon shutdown flush failed: {e}")

    # Final accounting check. Same invariant as the per-cycle check,
    # but now pending should be 0 if the drain completed cleanly. If
    # not, abandoned alerts contribute to "unaccounted" and that's a
    # known hazard documented above. Same cross-lock skew as the
    # per-cycle check applies on the timed-out path (a daemon worker
    # completing between the abandoned snapshot and this computation
    # can produce a transient -1 in the printed value) — informational
    # here, no alarm, and Final stats below is the definitive count.
    final_accounted = total_completed + total_failed + abandoned
    final_unaccounted = total_ingested - final_accounted

    logger.info(
        f"[SHUTDOWN] requested_timeout_s={SHUTDOWN_TIMEOUT_S:.0f} "
        f"actual_shutdown_s={actual_shutdown_s:.2f} "
        f"pending_at_shutdown_start={pending_at_shutdown_start} "
        f"abandoned={abandoned} "
        f"timed_out={timed_out} "
        f"ingested={total_ingested} "
        f"completed={total_completed} "
        f"failed={total_failed} "
        f"unaccounted={final_unaccounted}"
    )

    # The [SHUTDOWN] line above is a snapshot at drain-budget-end.
    # Daemon worker threads continue running their in-flight LLM/HTTP
    # calls after that snapshot (bounded above by systemd's
    # TimeoutStopSec). Those completions DO log per-alert Triage
    # lines, DO update the counters used by Final stats below, DO
    # write to jrsoc.db, and DO ship to Graylog normally. So Final
    # stats is the more definitive number; the [SHUTDOWN] snapshot
    # just captures the moment the drain budget elapsed.
    if abandoned > 0:
        logger.info(
            f"[SHUTDOWN_NOTE] {abandoned} alert(s) still pending at "
            f"drain-budget-end. Any mid-worker completions continue to "
            f"log and ship until interpreter exit; alerts still queued "
            f"will not complete. Final stats below reflects work "
            f"completed by interpreter exit."
        )

    logger.info(
        f"Final stats | seen={total_seen} deduped={total_deduped} "
        f"shipped={total_shipped} triaged={total_triaged} "
        f"emailed={total_emailed}"
    )
    conn.close()
    logger.info("jrSOCtriage stopped")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="jrSOCtriage - Wazuh alert triage pipeline")
    parser.add_argument(
        "--config", default="config.json",
        help="Path to config file (default: config.json)"
    )
    args = parser.parse_args()

    run(config_path=args.config)
