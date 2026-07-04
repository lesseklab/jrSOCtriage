#!/usr/bin/env python3
"""
jrSOCtriage - GELF Shipper Module
Sends enriched alerts to Graylog via GELF UDP.
Includes all gl2_ dashboard fields and LLM verdict if available.
"""

import json
import logging
import os
import socket
import time
import zlib
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# GELF UDP max chunk size
GELF_CHUNK_SIZE = 1420
GELF_MAGIC      = b'\x1e\x0f'

# Ship-gap tracking. gelf_gap_s on each ship line is the time
# since the previous successful LOCAL GELF send — UDP is fire-and-
# forget, so "success" means the socket write didn't error, not that
# Graylog received the message. It is measured RIGHT
# HERE — the single chokepoint every ship passes through — so it
# directly answers "is output flowing, and how steadily?" in one
# number per line, with no cross-referencing of other counters.
# Cheap (one timestamp + lock per ship) and kept as a permanent
# health signal in the ship line.
import threading as _gap_threading
_LAST_SHIP_LOCK = _gap_threading.Lock()
_LAST_SHIP_T = {"v": None}


# ---------------------------------------------------------------------------
# GELF message builder
# ---------------------------------------------------------------------------

def build_gelf_message(alert, enrichment, baseline, llm_result=None,
                       graylog_logs=None, zeek_data=None, prompt=None,
                       ntopng_data=None, org="N/A", security_domain="N/A"):
    """
    Build a GELF message dict from alert, enrichment, baseline and LLM result.
    All gl2_ fields are included for Graylog dashboard use.

    org / security_domain are per-deployment identity constants (operator-set
    in config, same on every record this instance ships) stamped as the core
    identity fields _jrsoc_org / _jrsoc_security_domain. They are read from
    config and passed in by ship_to_graylog; they are NOT computed enrichment
    (so jrsoc_ prefix, the config/identity bucket — not gl2_). Empty/unset
    resolves to "N/A" at the ship layer, matching every other field's
    missing-value convention.
    """
    from ingest import safe_get

    now = datetime.now(timezone.utc).timestamp()

    # Parse alert timestamp for GELF timestamp field
    ts_str = safe_get(alert, "timestamp", default=None)
    if ts_str:
        try:
            ts_str = ts_str.replace("+0000", "+00:00")
            alert_ts = datetime.fromisoformat(ts_str).timestamp()
        except ValueError:
            alert_ts = now
    else:
        alert_ts = now

    # Base GELF structure
    gelf = {
        "version":       "1.1",
        "host":          enrichment.get("canonical_hostname", "unknown"),
        "short_message": safe_get(alert, "rule", "description", default="Unknown alert"),
        "timestamp":     alert_ts,
        "level":         _wazuh_level_to_syslog(safe_get(alert, "rule", "level", default=0)),

        # Core alert fields
        "_wazuh_rule_id":    safe_get(alert, "rule", "id"),
        "_wazuh_rule_level": safe_get(alert, "rule", "level"),
        "_wazuh_agent_name": safe_get(alert, "agent", "name"),
        "_wazuh_agent_ip":   safe_get(alert, "agent", "ip"),
        "_wazuh_alert_id":   safe_get(alert, "id"),
        # Defensive join: groups should be a list of strings, but a
        # malformed alert with a bare string would char-split under
        # join, and a non-str element would raise TypeError — and
        # build_gelf_message runs OUTSIDE send_gelf_udp's
        # serialization catch, so that raise escapes to the worker.
        "_wazuh_groups":      _join_groups(safe_get(alert, "rule", "groups", default=[])),
        "_wazuh_fired_times": safe_get(alert, "rule", "firedtimes", default=1),
        "_wazuh_first_seen":  safe_get(alert, "timestamp"),
        "_full_log":          safe_get(alert, "full_log"),

        # Enrichment fields
        "_canonical_hostname": enrichment.get("canonical_hostname", "unknown"),
        # Renamed from _wazuh_last_seen — the value is the time this GELF
        # message was shipped to Graylog, not the time Wazuh last saw the
        # event. The old name was misleading: operators querying Graylog
        # for "when did Wazuh last fire this rule" would get the pipeline's
        # ship time instead, off by tens of seconds in typical production.
        # Keep the field for archival/debugging (helps reconstruct pipeline
        # latency from Wazuh write time to Graylog ingest time).
        "_last_shipped_at":    datetime.now(timezone.utc).isoformat(),
        # End-to-end jrSOCtriage pipeline latency for
        # this alert (ingest read -> ship). Better than Graylog's
        # gl2_process_time, which only measures Graylog-internal time
        # and misses everything jrSOCtriage does before shipping. Use
        # this field for SOC SLA dashboards and latency percentiles.
        # None if the ingest stamp is missing (legacy/manual injection).
        "_jrsoc_process_time_s": (
            round(now - alert["_jrsoc_received_t"], 3)
            if isinstance(alert.get("_jrsoc_received_t"), (int, float))
            else None
        ),
        "_agent_host_desc":    enrichment.get("agent_host", "unknown"),
        "_dedup_key":          enrichment.get("dedup_key", "unknown"),

        # Deployment identity (operator-set config constants, not computed
        # enrichment — jrsoc_ bucket). Same value on every record this instance
        # ships; lets multiple orgs / security domains on one shared Graylog
        # filter and stream their own alerts. Empty/unset arrives as "N/A".
        "_jrsoc_org":             org,
        "_jrsoc_security_domain": security_domain,

        # MITRE fields - useful for dashboard aggregations
        "_gl2_mitre_tactics":    enrichment.get("gl2_mitre_tactics", "N/A"),
        "_gl2_mitre_techniques": enrichment.get("gl2_mitre_techniques", "N/A"),
        "_gl2_mitre_ids":        enrichment.get("gl2_mitre_ids", "N/A"),

        # External IP enrichment fields - for geo/org dashboards
        "_gl2_src_country":      enrichment.get("gl2_src_country", "N/A"),
        "_gl2_src_country_code": enrichment.get("gl2_src_country_code", "N/A"),
        "_gl2_src_org":          enrichment.get("gl2_src_org", "N/A"),
        "_gl2_src_asn":          enrichment.get("gl2_src_asn", "N/A"),
        "_gl2_src_rdns":         enrichment.get("gl2_src_rdns", "N/A"),
        "_gl2_abuse_score":      enrichment.get("gl2_abuse_score", "N/A"),

        # Baseline fields - for anomaly dashboards
        "_gl2_count_last_hour":       baseline.get("count_last_hour", 0) if baseline else 0,
        "_gl2_count_last_24h":        baseline.get("count_last_24h", 0)  if baseline else 0,
        "_gl2_count_last_7d":         baseline.get("count_last_7d", 0)   if baseline else 0,
        "_gl2_hourly_avg":            baseline.get("hourly_avg", 0)       if baseline else 0,
        "_gl2_daily_avg":             baseline.get("daily_avg", 0)        if baseline else 0,
        "_gl2_above_hourly_baseline": baseline.get("above_hourly", False) if baseline else False,
        "_gl2_above_daily_baseline":  baseline.get("above_daily", False)  if baseline else False,
        "_gl2_baseline_note":         baseline.get("baseline_note", "")   if baseline else "",
    }

    # IP lists as comma-separated strings
    # Use comma-no-space to keep Graylog field values clean for aggregation
    # and search; padded values would split inconsistently if anything
    # downstream did .split(",") without stripping.
    ips = enrichment.get("ips", {})
    gelf["_internal_ips"] = ",".join(ips.get("internal", []))
    gelf["_external_ips"] = ",".join(ips.get("external", []))

    # Graylog context logs - host logs from alert time window
    if graylog_logs:
        gelf["_context_logs"] = graylog_logs

    # Zeek flows - time-windowed flows from alert window
    # Not stored anywhere else so we preserve them here
    if zeek_data:
        from zeek_fetch import format_zeek_for_prompt
        zeek_formatted = format_zeek_for_prompt(zeek_data)
        if zeek_formatted:
            gelf["_zeek_flows"] = zeek_formatted

    # LLM triage result fields - always set triage_complete so stream rules work
    gelf["_gl2_triage_complete"] = "true" if llm_result else "false"
    if llm_result:
        gelf["_gl2_llm_verdict"]    = llm_result.get("verdict", "N/A")
        gelf["_gl2_llm_confidence"] = llm_result.get("confidence", "N/A")
        gelf["_gl2_llm_summary"]    = llm_result.get("summary", "N/A")
        gelf["_gl2_llm_reasoning"]  = llm_result.get("reasoning", "N/A")
        gelf["_gl2_llm_missing"]    = llm_result.get("missing_info", "N/A")
        if llm_result.get("endpoint"):
            gelf["_gl2_llm_endpoint"] = llm_result["endpoint"]
        if llm_result.get("model"):
            gelf["_gl2_llm_model"]    = llm_result["model"]
        gelf["_gl2_anon"] = "true" if llm_result.get("anonymized") else "false"
        if prompt:
            gelf["_gl2_llm_prompt"] = prompt

    # ntopng active flow data - ship regardless of LLM triage
    if ntopng_data:
        gelf["_gl2_ntopng_flows"] = ntopng_data

    # Remove any None values - GELF doesn't like nulls
    gelf = {k: v for k, v in gelf.items() if v is not None}

    return gelf


def _join_groups(groups):
    """Comma-join rule groups defensively (see call-site comment)."""
    if isinstance(groups, list):
        return ",".join(str(x) for x in groups)
    if groups in (None, "N/A", ""):
        return ""
    return str(groups)


def _wazuh_level_to_syslog(wazuh_level):
    """
    Map Wazuh rule level (0-15) to syslog severity (0-7).
    Higher Wazuh level = more severe = lower syslog number.
    """
    try:
        level = int(wazuh_level)
    except (ValueError, TypeError):
        return 6  # informational

    if level >= 12:
        return 2  # critical
    elif level >= 9:
        return 3  # error
    elif level >= 6:
        return 4  # warning
    elif level >= 3:
        return 5  # notice
    else:
        return 6  # informational


# ---------------------------------------------------------------------------
# GELF UDP sender
# ---------------------------------------------------------------------------

def send_gelf_udp(gelf_dict, host, port):
    """
    Send a GELF message via UDP.
    Handles chunking for large messages (> GELF_CHUNK_SIZE bytes).
    Returns True on success, False on failure.

    Uses a context manager for the socket so the file descriptor is
    always released, including on exceptions. Under Python 3.14.x,
    relying on implicit cleanup of sockets proved unreliable in this
    hot path — descriptors accumulated until resource pressure.
    Python 3.13+ also emits ResourceWarning for sockets deleted
    without an explicit close. Every socket MUST be explicitly
    closed.

    Failure modes (all return False, all logged):
      - JSON serialization error (alert dict contains non-serializable values)
      - zlib compression error (typically out-of-memory on huge payloads)
      - Socket / OS error (network down, no route, etc.)
      - Oversized message exceeding 128 chunks (~ 180KB compressed) —
        the GELF chunked-message protocol caps at 128 sequence numbers
        in a single byte, so larger messages cannot be sent. Previously
        truncated silently; now logged and dropped so the operator can
        see the failure.
    """
    try:
        payload = json.dumps(gelf_dict).encode("utf-8")

        # Compress with zlib
        # zlib level 1 (2026-06-12, operator choice): ~2x faster compress
        # (~0.09ms saved/ship, benched) at lower ratio. Tradeoff: fat
        # messages may go from 1 GELF chunk to 2; chunked UDP loses the
        # whole message if any chunk drops — acceptable on LAN to a
        # local Graylog, and the prompt-builder diff fix shrank the
        # fattest payloads anyway.
        compressed = zlib.compress(payload, 1)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            if len(compressed) <= GELF_CHUNK_SIZE:
                # Single chunk - send directly
                sock.sendto(compressed, (host, port))
            else:
                # Multi-chunk GELF
                chunks = [
                    compressed[i:i + GELF_CHUNK_SIZE]
                    for i in range(0, len(compressed), GELF_CHUNK_SIZE)
                ]
                if len(chunks) > 128:
                    # GELF protocol limit: sequence number is one byte, so
                    # max chunks is 128 (the protocol uses 0-127 for seq;
                    # this code uses 0-127 as well). A truncated send would
                    # produce a malformed message that Graylog discards
                    # after timeout — silently delivering nothing. Better
                    # to log and drop so the operator knows the alert
                    # didn't make it.
                    short_msg = gelf_dict.get("short_message", "?")
                    dedup_key = gelf_dict.get("_dedup_key", "?")
                    logger.error(
                        f"GELF message too large to send: {len(chunks)} chunks "
                        f"(max 128, ~{len(compressed)} bytes compressed) "
                        f"for {dedup_key} ({short_msg!r}). Message dropped."
                    )
                    return False

                message_id = _generate_message_id()
                num_chunks = len(chunks)

                for seq, chunk in enumerate(chunks):
                    chunk_header = (
                        GELF_MAGIC +
                        message_id +
                        bytes([seq, num_chunks])
                    )
                    sock.sendto(chunk_header + chunk, (host, port))
                    time.sleep(0.001)  # brief pause between chunks

        return True

    except (TypeError, ValueError) as e:
        # json.dumps: TypeError on non-serializable values, ValueError
        # on circular references. Without this clause the exception
        # escaped to the worker's broad except and counted the alert
        # FAILED — while the docstring above promised a logged False.
        logger.error(f"GELF JSON serialization failed: {e}")
        return False
    except zlib.error as e:
        logger.error(f"GELF zlib compression failed: {e}")
        return False
    except (socket.error, OSError) as e:
        logger.error(f"GELF UDP send failed: {e}")
        return False


def _generate_message_id():
    """Generate an 8-byte message ID for GELF chunking."""
    return os.urandom(8)


# ---------------------------------------------------------------------------
# Main ship function
# ---------------------------------------------------------------------------

def ship_to_graylog(alert, enrichment, baseline, config,
                    llm_result=None, graylog_logs=None, zeek_data=None,
                    prompt=None, ntopng_data=None):
    """
    Build and send a GELF message to Graylog.
    Call this for every alert that passes dedup.
    llm_result, graylog_logs, zeek_data, prompt, ntopng_data are optional.
    Returns True on success, False on failure.
    """
    output_cfg = config.get("output", {}).get("graylog", {})

    if not output_cfg.get("enabled", False):
        logger.debug("Graylog output disabled in config")
        return False

    host = output_cfg.get("host", "")
    port = output_cfg.get("port", 12201)

    if not host:
        logger.error("Graylog output host not configured")
        return False

    # Deployment identity constants (per-deployment, read at ship; empty/unset
    # -> "N/A" to match every other field's missing-value convention). Parsed
    # here at use site, consistent with how the pipeline reads config.
    deployment_cfg = config.get("deployment", {})
    org             = deployment_cfg.get("org") or "N/A"
    security_domain = deployment_cfg.get("security_domain") or "N/A"

    gelf = build_gelf_message(alert, enrichment, baseline, llm_result,
                              graylog_logs=graylog_logs, zeek_data=zeek_data,
                              prompt=prompt, ntopng_data=ntopng_data,
                              org=org, security_domain=security_domain)

    success = send_gelf_udp(gelf, host, port)
    if success:
        _now_ship = time.time()
        with _LAST_SHIP_LOCK:
            _prev = _LAST_SHIP_T["v"]
            _LAST_SHIP_T["v"] = _now_ship
        _gap = (_now_ship - _prev) if _prev is not None else 0.0
        # End-to-end pipeline latency for this alert.
        # Only emit if the ingest-read stamp is present (won't be for
        # manually-injected test alerts; defensive None handling).
        _received_t = alert.get("_jrsoc_received_t")
        _pt_str = ""
        if isinstance(_received_t, (int, float)):
            _process_time = _now_ship - _received_t
            _pt_str = f" process_time_s={_process_time:.1f}"
        logger.info(
            f"Shipped to Graylog: {enrichment.get('dedup_key', '?')} "
            f"gelf_gap_s={_gap:.1f}{_pt_str}"
        )
    else:
        logger.error(f"Failed to ship: {enrichment.get('dedup_key', '?')}")

    return success


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
    from graylog_fetch import parse_alert_timestamp
    from dedup import is_duplicate

    print("=== jrSOCtriage GELF Shipper Smoke Test ===\n")

    config     = load_config("config.json")
    hosts_data = load_hosts(config)
    conn       = get_connection(config)

    output_cfg = config.get("output", {}).get("graylog", {})
    print(f"Graylog output : {output_cfg.get('host')}:{output_cfg.get('port')}")
    print(f"Enabled        : {output_cfg.get('enabled', False)}\n")

    silence_seconds = config.get("processing", {}).get("dedup_silence_seconds", 240)

    alerts  = list(read_new_alerts(config, min_level=0))
    print(f"Loaded {len(alerts)} alert(s)\n")

    shipped = 0
    for alert in alerts[:20]:
        enrichment = enrich_alert(alert, config, hosts_data)
        dedup_key  = enrichment["dedup_key"]

        record_alert(conn, enrichment, alert)

        if is_duplicate(dedup_key, silence_seconds):
            continue

        alert_time = parse_alert_timestamp(alert)
        baseline   = calculate_baseline(
            conn, config,
            enrichment["gl2_rule_id"],
            enrichment["canonical_hostname"],
            alert_ts=alert_time.timestamp() if alert_time else None,
        )

        # Ship without LLM result first to test basic shipping
        success = ship_to_graylog(alert, enrichment, baseline, config)

        level = safe_get(alert, "rule", "level", default=0)
        print(f"  {'[OK]' if success else '[FAIL]'} [{level}] {dedup_key}")
        shipped += 1

    conn.close()
    print(f"\nShipped {shipped} alert(s) to Graylog")
    print("Check Graylog for messages with _dedup_key field")
    print("=== Done ===")
