#!/usr/bin/env python3
"""
jrSOCtriage - Prompt Builder Module
Assembles the structured LLM triage prompt from all enrichment sources.
Follows the Goldfish SOC template - stateless, single-shot, no memory.
"""

import copy
import json
import logging
from datetime import datetime, timezone

# Module-level imports from sibling modules. ingest.py and zeek_fetch.py
# do NOT import prompt_builder, so these are safe at module-load time.
# (Previously these were inline imports inside functions, which masked any
# future circular-import bug until runtime.)
from ingest import safe_get
from zeek_fetch import format_zeek_for_prompt, effective_zeek_window_minutes
# _safe_ip canonicalizes IP strings (handles IPv4/IPv6 case differences and
# expanded vs compact IPv6) so two IPs that look textually different but
# represent the same address compare equal. Imported from enrich.py to
# avoid duplicating the helper. enrich.py does not import prompt_builder,
# so this import is safe at module-load time.
from enrich import _safe_ip

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Network and host context blocks - built from hosts.json
# ---------------------------------------------------------------------------

def build_network_context(hosts_data):
    """Build the NETWORK CONTEXT block from hosts.json networks."""
    lines = []
    for net in hosts_data.get("networks", []):
        cidr = net.get("cidr", "?")
        name = net.get("name", "?")
        role = net.get("role", "?")
        lines.append(f"- {name}: {cidr} - {role}")
    return "\n".join(lines) if lines else "No network data available"


def format_host_entry(host):
    """Format a single host record into a prompt line."""
    name    = host.get("name", "?")
    # role may be a string or a list (multi-role host). Render as comma-joined
    # names here — the host inventory stays sparse (names only); the full role
    # description/notes context goes in the alert host's SOURCE ENRICHMENT.
    role_raw = host.get("role", "")
    if isinstance(role_raw, list):
        role = ", ".join(r.strip() for r in role_raw if isinstance(r, str) and r.strip()) or "?"
    elif isinstance(role_raw, str) and role_raw.strip():
        role = role_raw.strip()
    else:
        role = "?"
    host_os = host.get("os", "?")  # 'os' shadows stdlib module if imported
    vlan    = host.get("vlan", "?")
    tags    = host.get("tags", [])
    notes   = host.get("notes", "")
    # identifiers.ip can be a string (single IP) or a list (multi-IP host
    # — e.g., a phone with both LAN and VPN addresses). Normalize to a
    # display string for the prompt. Filter out empty/falsy entries so
    # malformed data (trailing comma, double-comma) doesn't render as
    # "192.168.10.45, , 10.6.0.5".
    raw_ip  = host.get("identifiers", {}).get("ip", "")
    if isinstance(raw_ip, list):
        ip = ", ".join(s for s in raw_ip if s)
    else:
        ip = raw_ip

    parts = [f"{name}"]
    if ip:
        parts.append(ip)
    parts.append(f"VLAN {vlan}")
    parts.append(f"{role} / {host_os}")

    tag_notes = []
    for tag in tags:
        if tag == "auto_updates":
            tag_notes.append("runs automatic unattended updates")
        elif tag == "untrusted":
            tag_notes.append("UNTRUSTED device")
        elif tag == "critical":
            tag_notes.append("CRITICAL infrastructure")
        elif tag == "transit":
            tag_notes.append("transit network")
        elif tag == "domain_joined":
            tag_notes.append("domain joined")
        elif tag == "dmz":
            tag_notes.append("DMZ host")
        else:
            tag_notes.append(tag)
    if tag_notes:
        parts.append(f"[{', '.join(tag_notes)}]")

    if notes:
        parts.append(f"Note: {notes}")

    return f"- {' | '.join(parts)}"


def build_host_inventory(hosts_data, enrichment=None, zeek_data=None):
    """
    Build the HOST INVENTORY block from hosts.json hosts.
    When enrichment and zeek_data are provided, only includes hosts that are
    relevant to this alert — the alert host plus any hosts seen in flows or logs.
    Remaining hosts are summarized as a count to keep prompts scalable.
    """
    all_hosts = hosts_data.get("hosts", [])
    if not all_hosts:
        return "No host inventory available"

    # If no context provided, include all hosts (fallback for small networks)
    if enrichment is None:
        lines = [format_host_entry(h) for h in all_hosts]
        return "\n".join(lines)

    # Build set of relevant hostnames and IPs from alert context.
    # Canonical IP objects (IPv4Address / IPv6Address) are stored alongside
    # the original string forms so cross-source comparisons work even when
    # IP strings differ in case or representation (e.g., "2001:DB8::1" vs
    # "2001:db8::1" should match). _safe_ip returns None for invalid input
    # — those cases drop out and the string-only fallback handles them.
    relevant_names = set()
    relevant_ips   = set()         # original string forms (legacy fallback)
    relevant_addrs = set()         # canonical IP objects for canonical compare

    def _add_ip(s):
        if not s:
            return
        relevant_ips.add(s)
        addr = _safe_ip(s)
        if addr is not None:
            relevant_addrs.add(addr)

    # Always include the alert host
    canonical = enrichment.get("canonical_hostname", "")
    if canonical:
        relevant_names.add(canonical.lower())

    # Include hosts from structured-field IPs in this alert. This
    # deliberately reads from ips["internal"] + ips["external"]
    # rather than ips["all"], because ips["all"] now also contains
    # IPs found via regex scan of full_log ("mentioned" IPs). Those
    # mentioned IPs may not be parties to the alert (e.g., DNS
    # resolution entries on a DC log every name the DC resolved,
    # regardless of whether that host was involved in the alerted
    # event), so they must NOT pull hosts.json entries into the
    # host inventory block. The mentioned-IPs block renders them
    # separately with neutral labeling.
    ips_dict = enrichment.get("ips", {})
    structured_ips = ips_dict.get("internal", []) + ips_dict.get("external", [])
    internal_context = enrichment.get("internal_context", [])
    for ip in structured_ips:
        _add_ip(ip)
        # Resolve IP to hostname via internal_context. Use canonical
        # comparison so e.g. ctx["ip"] == "2001:DB8::1" matches an
        # all_ips entry of "2001:db8::1".
        ip_addr = _safe_ip(ip)
        for ctx in internal_context:
            ctx_ip = ctx.get("ip", "")
            ctx_addr = _safe_ip(ctx_ip)
            matched = (
                (ip_addr is not None and ctx_addr is not None and ip_addr == ctx_addr)
                or (ctx_ip == ip)  # string fallback for non-IP edge cases
            )
            if matched:
                h = ctx.get("hostname", "")
                if h:
                    relevant_names.add(h.lower())

    # Include hosts seen in Zeek flows
    if zeek_data:
        for row in zeek_data.get("conn", []):
            for field in ("id.orig_h", "id.resp_h"):
                _add_ip(row.get(field, ""))
        for row in zeek_data.get("dns", []):
            _add_ip(row.get("id.orig_h", ""))
        for row in zeek_data.get("ntlm", []):
            for field in ("id.orig_h", "id.resp_h"):
                _add_ip(row.get(field, ""))

    # Match hosts against relevant names and IPs
    included = []
    excluded_count = 0

    # Pre-compute first-label set for FQDN-aware fallback (PB-10).
    # If hosts.json has an FQDN like "host01.example.local" but
    # canonical_hostname resolved to "host01" (or vice versa), exact-match
    # against relevant_names misses. Compare first labels as a fallback.
    relevant_first_labels = {n.split(".")[0] for n in relevant_names if n}

    for host in all_hosts:
        name = host.get("name", "").lower()
        name_short = name.split(".")[0]
        # identifiers.ip can be a string OR a list (multi-IP hosts).
        # Normalize to BOTH a list of IP strings AND a list of canonical
        # IP objects. The string check handles legacy / exact-form match;
        # the canonical check catches cross-form matches (e.g., IPv6 case
        # or expansion differences across enrichment sources).
        raw_ip = host.get("identifiers", {}).get("ip", "")
        if isinstance(raw_ip, list):
            host_ips = [s for s in raw_ip if s]
        elif raw_ip:
            host_ips = [raw_ip]
        else:
            host_ips = []
        host_addrs = [a for a in (_safe_ip(s) for s in host_ips) if a is not None]

        matched = False
        if name in relevant_names:
            matched = True
        elif name_short and name_short in relevant_first_labels:
            matched = True
        elif any(ip in relevant_ips for ip in host_ips):
            matched = True
        elif any(addr in relevant_addrs for addr in host_addrs):
            matched = True

        if matched:
            included.append(format_host_entry(host))
        else:
            excluded_count += 1

    lines = included
    if excluded_count > 0:
        lines.append(
            f"- [{excluded_count} additional host(s) in inventory not involved in this alert]"
        )

    return "\n".join(lines) if lines else "No host inventory available"


# ---------------------------------------------------------------------------
# Alert summary block - 6-7 reliable fields only
# ---------------------------------------------------------------------------

def build_alert_summary(alert, enrichment):
    """Build the structured ALERT SUMMARY block."""
    timestamp   = safe_get(alert, "timestamp")
    rule_id     = safe_get(alert, "rule", "id")
    rule_level  = safe_get(alert, "rule", "level")
    description = safe_get(alert, "rule", "description")
    agent_name  = safe_get(alert, "agent", "name")
    agent_ip    = safe_get(alert, "agent", "ip")
    mitre       = enrichment.get("mitre", {})
    fired_times = safe_get(alert, "rule", "firedtimes", default=1)

    lines = [
        f"- Time        : {timestamp}",
        f"- Rule ID     : {rule_id}",
        f"- Level       : {rule_level}",
        f"- Description : {description}",
        f"- Agent/Host  : {agent_name} ({agent_ip})",
        f"- Canonical   : {enrichment.get('canonical_hostname', 'unknown')}",
    ]

    # Storm/dedup trail - show duration if fired multiple times
    try:
        ft = int(fired_times)
        if ft > 1:
            first_seen = enrichment.get("wazuh_first_seen") or timestamp
            last_seen  = enrichment.get("wazuh_last_seen")

            if last_seen and first_seen and last_seen != first_seen:
                # Parse timestamps and compute duration
                def parse_ts(ts_str):
                    try:
                        return datetime.fromisoformat(
                            str(ts_str).replace("+0000", "+00:00")
                        )
                    except Exception:
                        return None

                first_dt = parse_ts(first_seen)
                last_dt  = parse_ts(last_seen)

                if first_dt and last_dt:
                    duration_secs = (last_dt - first_dt).total_seconds()
                    if duration_secs < 60:
                        duration_str = f"{int(duration_secs)}s"
                    elif duration_secs < 3600:
                        duration_str = f"{int(duration_secs/60)}m {int(duration_secs%60)}s"
                    else:
                        duration_str = f"{int(duration_secs/3600)}h {int((duration_secs%3600)/60)}m"

                    # Display Format A — concise. Exact UTC timestamps
                    # are available elsewhere in the prompt (alert
                    # timestamp, Zeek flow times); the trail line just
                    # needs count and duration to convey storm shape.
                    lines.append(
                        f"- Alert trail  : Fired {ft} times "
                        f"(storm duration: {duration_str})"
                    )
                else:
                    lines.append(f"- Alert trail  : Fired {ft} times")
            else:
                lines.append(f"- Alert trail  : Fired {ft} times")
    except (ValueError, TypeError):
        pass

    tactics = mitre.get("tactics", "")
    if tactics and tactics != "N/A":
        lines.append(f"- MITRE Tactics    : {tactics}")

    techniques = mitre.get("techniques", "")
    if techniques and techniques != "N/A":
        lines.append(f"- MITRE Techniques : {techniques}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Enrichment / source context block
# ---------------------------------------------------------------------------

def build_enrichment_block(enrichment):
    """Build the SOURCE ENRICHMENT block."""
    lines = []

    # Internal IPs
    for ctx in enrichment.get("internal_context", []):
        ip       = ctx.get("ip", "?")
        hostname = ctx.get("hostname", ip)
        host     = ctx.get("host", "unknown")
        notes    = ctx.get("notes", "")
        if hostname != ip:
            line = f"- {ip} ({hostname}): {host}"
        else:
            line = f"- {ip}: {host}"
        if notes:
            line += f" | Note: {notes}"
        lines.append(line)

    # External IPs
    for ext in enrichment.get("external_context", []):
        ip      = ext.get("ip", "?")
        rdns    = ext.get("rdns", "N/A")
        org     = ext.get("org", "N/A")
        country = ext.get("country", "N/A")
        city    = ext.get("city", "N/A")
        asn     = ext.get("asn", "N/A")
        abuse   = ext.get("abuse_score", "N/A")

        parts = [f"- {ip} (EXTERNAL)"]
        if rdns != "N/A":
            parts.append(f"rdns={rdns}")
        if org != "N/A":
            parts.append(f"org={org}")
        if country != "N/A":
            loc = f"{city}, {country}" if city != "N/A" else country
            parts.append(f"geo={loc}")
        if asn != "N/A":
            parts.append(f"asn={asn}")
        if abuse != "N/A":
            parts.append(f"abuse_score={abuse}")
        lines.append(" | ".join(parts))

    if not lines:
        # Differentiate "internal but no external" vs "no enrichment at all"
        # so the LLM gets accurate context. The old single-message version
        # said "host-local event" even when neither internal nor external
        # context existed, which was misleading.
        if enrichment.get("ips", {}).get("internal"):
            lines.append("Internal IPs only — no external network enrichment applicable")
        else:
            lines.append("No IP enrichment available for this alert")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Mentioned-IP block — IPs found by regex scan of full_log
# ---------------------------------------------------------------------------

# Maximum number of mentioned IPs to render in the prompt. Verbose
# alert types (e.g., DNS server analytical logs on a busy DC) can
# spray dozens of IPs into full_log; without a cap the block dominates
# the prompt. 10 is a balance between "enough to see the pattern" and
# "bounded prompt size." Excess count is reported as a tail count so
# the LLM knows the list was truncated.
_MENTIONED_BLOCK_MAX = 10


def build_mentioned_block(enrichment):
    """
    Build the 'IPS MENTIONED IN RAW LOG' block. These are IPs that
    appeared in full_log via regex scan but were NOT in the structured
    IP fields — they may or may not be parties to the alert.

    Returns None if there are no mentioned IPs (caller suppresses the
    block entirely in that case).
    """
    mentioned = enrichment.get("mentioned_context", [])
    if not mentioned:
        return None

    lines = []
    for ctx in mentioned[:_MENTIONED_BLOCK_MAX]:
        ip = ctx.get("ip", "?")
        if ctx.get("external"):
            # External: render with reputation/geo signal but stay
            # compact — same field shape as build_enrichment_block
            # external rendering for consistency.
            rdns    = ctx.get("rdns", "N/A")
            org     = ctx.get("org", "N/A")
            country = ctx.get("country", "N/A")
            city    = ctx.get("city", "N/A")
            asn     = ctx.get("asn", "N/A")
            abuse   = ctx.get("abuse_score", "N/A")
            parts = [f"- {ip} (EXTERNAL)"]
            if rdns != "N/A":
                parts.append(f"rdns={rdns}")
            if org != "N/A":
                parts.append(f"org={org}")
            if country != "N/A":
                loc = f"{city}, {country}" if city != "N/A" else country
                parts.append(f"geo={loc}")
            if asn != "N/A":
                parts.append(f"asn={asn}")
            if abuse != "N/A":
                parts.append(f"abuse_score={abuse}")
            lines.append(" | ".join(parts))
        else:
            # Internal: hostname + segment only. Deliberately no host
            # notes — the point of this block is to flag mention
            # without pulling in page-sized hosts.json entries for IPs
            # that aren't actually parties to the alert.
            hostname = ctx.get("hostname", ip)
            network  = ctx.get("network")
            if hostname and hostname != ip:
                head = f"- {ip} ({hostname})"
            else:
                head = f"- {ip}"
            if network:
                lines.append(f"{head} | {network} segment")
            else:
                lines.append(head)

    overflow = len(mentioned) - _MENTIONED_BLOCK_MAX
    if overflow > 0:
        lines.append(f"- [+{overflow} more not shown]")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Baseline block
# ---------------------------------------------------------------------------

def build_baseline_block(baseline):
    """Build the BASELINE block from database stats in a structured readable format."""
    if not baseline:
        return "No baseline data available"

    days_of_data     = baseline.get("days_of_data", 0)
    # Read min_baseline_days from the baseline dict so prompt status stays
    # consistent with database.py's own threshold decision. Falls back to 3
    # only if the baseline dict was produced by an older version of
    # database.py that didn't expose this field.
    min_days         = baseline.get("min_baseline_days", 3)
    count_last_hour  = baseline.get("count_last_hour", 0)
    count_last_24h   = baseline.get("count_last_24h", 0)
    count_last_7d    = baseline.get("count_last_7d", 0)
    hourly_avg       = baseline.get("hourly_avg", 0)
    daily_avg        = baseline.get("daily_avg", 0)
    above_hourly     = baseline.get("above_hourly", False)
    above_daily      = baseline.get("above_daily", False)
    has_baseline     = days_of_data >= min_days

    # Status line
    if has_baseline:
        status = f"Established ({days_of_data} days)"
    else:
        status = f"Learning ({days_of_data} / {min_days} days)"

    # Hourly assessment
    if not has_baseline:
        hourly_note = "insufficient data"
    elif above_hourly:
        hourly_note = f"⚠ ABOVE BASELINE (avg {hourly_avg}/hr)"
    elif hourly_avg > 0 and count_last_hour <= hourly_avg * 0.5:
        hourly_note = "below average"
    else:
        hourly_note = f"within expected range (avg {hourly_avg}/hr)"

    # Daily assessment
    if not has_baseline:
        daily_note = "insufficient data"
    elif above_daily:
        daily_note = f"⚠ ABOVE BASELINE (avg {daily_avg}/day)"
    elif daily_avg > 0 and count_last_24h <= daily_avg * 0.5:
        daily_note = "below average"
    else:
        daily_note = f"stable (avg {daily_avg}/day)"

    # Trend
    if not has_baseline:
        trend = "Baseline not yet established — treat frequency as unknown"
    elif above_hourly or above_daily:
        # Neutral statement — let the SITE-SPECIFIC TRIAGE GUIDANCE drive
        # interpretation. The previous "— investigate" instruction conflicted
        # with operator guidance for low-frequency rules where a single
        # occurrence mathematically registers as ABOVE BASELINE despite
        # being normal behavior.
        trend = "Significant deviation from recent activity"
    else:
        trend = "No significant deviation from recent activity"

    lines = [
        f"- Status: {status}",
        f"- Last hour: {count_last_hour} events → {hourly_note}",
        f"- Last 24h: {count_last_24h} events → {daily_note}",
        f"- Last 7d:  {count_last_7d} events",
        f"- Trend: {trend}",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Full prompt assembler
# ---------------------------------------------------------------------------

# Baseline triage guidance — the core "how to think about an alert" rules
# that apply to every deployment regardless of sensors, network shape, or
# operator preference. Rendered into the "When evaluating alerts:" rubric
# of every prompt, ahead of any site-specific guidance from
# prompt_customization.triage_guidance.
#
# These are intentionally not exposed in the config UI: they describe how
# this pipeline does triage, not how a particular operator's environment
# is shaped. Customizing them is possible — edit this constant — but it
# is not recommended. They were arrived at empirically over weeks of
# production observation and changing them tends to make verdicts worse,
# not better.
#
# Site-specific guidance (the SPAN artifact rule, ntopng L7 caveats, etc.)
# stays in prompt_customization.triage_guidance where operators can edit
# it through the interface.
_BASELINE_TRIAGE_GUIDANCE = [
    "Distinguish between user applications and background agents/services "
    "(e.g., updaters, schedulers, service hosts, browser agents) — do not "
    "assume a user was actively present unless the evidence supports it.",

    "Include key corroborating evidence (e.g., relevant Zeek flows, DNS "
    "queries, log entries) that directly supports the root cause "
    "identification — don't just state conclusions, show the evidence.",

    "Baseline frequency analysis is only meaningful when the rule fires "
    "often enough to have a real average. For low-frequency rules "
    "(hourly_avg below ~0.5/hr or daily_avg below ~1/day), a single "
    "occurrence will mathematically register as ABOVE BASELINE even "
    "though it is normal behavior for that rule. When you see ABOVE "
    "BASELINE on a rule with a tiny hourly average and a single-digit "
    "count, treat the baseline signal as not informative and rely on "
    "the alert content and enrichment instead.",

    "When providing instructions in MISSING INFO, use detailed "
    "specific commands that fit the context. Generic guidance like "
    "'check the logs' is less useful than concrete invocations the "
    "analyst can paste and run.",
]

# Fields removed from the raw alert before it goes into the prompt's
# ALERT ABRIDGED JSON block. Each field falls into one of two categories:
#
# 1. Always-same-value across alerts in a typical deployment, so they
#    add tokens without information:
#       - rule.mail        (always false in normal Wazuh use)
#
# 2. Already represented in the structured ALERT SUMMARY block above the
#    JSON, so including them in the JSON duplicates information:
#       - rule.level, rule.description, rule.id, rule.firedtimes
#       - rule.mitre (rendered into MITRE Tactics/Techniques in summary)
#       - rule.pci_dss / gpg13 / gdpr / hipaa / nist_800_53 / tsc
#         (compliance metadata; LLM never cites it for triage decisions)
#       - agent.id, agent.name, agent.ip (rendered into Agent/Host line)
#       - id (Wazuh internal alert ID; not used by LLM)
#       - decoder (how Wazuh parsed the event; not relevant to triage)
#       - _jrsoc_received_t (pipeline-internal ingest timestamp added by
#         ingest.py; bookkeeping only, no triage value. Prompt-only
#         strip — it was never a searchable Graylog field; it only
#         appeared inside the gl2_llm_prompt text blob.)
#
# Kept intentionally:
#       - manager (cheap to retain; future-proofs multi-manager deployments)
#       - rule.groups (real classification signal; LLM uses it)
#       - data.* (the actual event payload — Suricata flow info, Windows
#                 event data, AppArmor audit details, etc. — critical)
#       - timestamp (LLM cross-references between alert and event time)
#       - location (tells LLM what log source: EventChannel/journald/etc.)
#       - full_log, predecoder (carry info not in data.* for some types)
#
# Reduces typical prompt by ~250 tokens (more on Windows-event alerts
# with full compliance metadata, less on terse Suricata/AppArmor alerts).
_PROMPT_STRIP_TOP_LEVEL = ("id", "decoder", "_jrsoc_received_t")
_PROMPT_STRIP_RULE = (
    "level", "description", "id", "firedtimes", "mail", "mitre",
    "pci_dss", "gpg13", "gdpr", "hipaa", "nist_800_53", "tsc",
)
_PROMPT_STRIP_AGENT = ("id", "name", "ip")



# --- Large duplicate-field handling (2026-06-12) -----------------------
# Rule-533-class alerts (netstat change, syscheck-style before/after)
# carry the ENTIRE state dump up to three times: previous_output,
# full_log, and previous_log are near-identical multi-KB blobs. Found
# when LOAC run-8 prompts measured ~26KB uniformly: ~20KB was one
# netstat table triplicated inside the "ABRIDGED" block. previous_log
# is dropped outright (duplicate of previous_output). When both
# previous_output and full_log are large, they are replaced by a
# line-level CHANGE SUMMARY (added/removed lines) plus a truncated
# current log — which is also better triage input: the model no longer
# has to eyeball-diff two 130-line tables to find the one changed port.
_PROMPT_DIFF_THRESHOLD = 1500     # both fields larger than this -> diff
_PROMPT_DIFF_MAX_LINES = 40       # cap added/removed lines listed
_PROMPT_FULL_LOG_CAP = 4000       # standalone full_log truncation cap
_PROMPT_FULL_LOG_DIFFED_CAP = 1500  # full_log cap when diff supplied


def _truncate_text(text, cap):
    if not isinstance(text, str) or len(text) <= cap:
        return text
    return (text[:cap]
            + f"\n[... truncated by jrSOCtriage: {len(text)} chars total]")


def _diff_change_summary(previous, current):
    """Line-level added/removed summary between two large text dumps."""
    prev_lines = previous.splitlines()
    curr_lines = current.splitlines()
    prev_set = set(prev_lines)
    curr_set = set(curr_lines)
    added = [l for l in curr_lines if l not in prev_set and l.strip()]
    removed = [l for l in prev_lines if l not in curr_set and l.strip()]
    parts = []
    if added:
        shown = added[:_PROMPT_DIFF_MAX_LINES]
        parts.append("LINES ADDED vs previous output:\n" + "\n".join(shown))
        if len(added) > len(shown):
            parts.append(f"[+{len(added) - len(shown)} more added lines]")
    if removed:
        shown = removed[:_PROMPT_DIFF_MAX_LINES]
        parts.append("LINES REMOVED vs previous output:\n" + "\n".join(shown))
        if len(removed) > len(shown):
            parts.append(f"[+{len(removed) - len(shown)} more removed lines]")
    if not parts:
        parts.append("No line-level differences between previous and "
                     "current output (change may be ordering/whitespace).")
    return "\n".join(parts)


def _strip_alert_for_prompt(alert):
    """
    Return a deep copy of the alert with redundant or noise fields removed,
    leaving only what's not already represented in structured prompt blocks.

    Reduces prompt tokens without losing LLM-useful information. The
    original alert dict is not modified — gelf_shipper still ships the
    full alert verbatim. See _PROMPT_STRIP_* constants above for the
    reasoning behind each removed field.

    Defensive: handles non-dict alert (returns unchanged), missing fields
    (no-op via .pop default), and non-dict rule/agent sub-blocks (left
    alone rather than mutated unsafely).
    """
    if not isinstance(alert, dict):
        return alert

    cleaned = copy.deepcopy(alert)

    # Top-level redundant fields
    for key in _PROMPT_STRIP_TOP_LEVEL:
        cleaned.pop(key, None)

    # rule.* — strip redundant + compliance metadata, keep groups
    rule_block = cleaned.get("rule")
    if isinstance(rule_block, dict):
        for key in _PROMPT_STRIP_RULE:
            rule_block.pop(key, None)

    # agent.* — strip all (already in alert summary), pop empty agent block
    agent_block = cleaned.get("agent")
    if isinstance(agent_block, dict):
        for key in _PROMPT_STRIP_AGENT:
            agent_block.pop(key, None)
        if not agent_block:
            cleaned.pop("agent", None)

    # Large duplicate-field handling — see the constants block above.
    cleaned.pop("previous_log", None)
    prev_out = cleaned.get("previous_output")
    full_log = cleaned.get("full_log")
    if (isinstance(prev_out, str) and isinstance(full_log, str)
            and len(prev_out) > _PROMPT_DIFF_THRESHOLD
            and len(full_log) > _PROMPT_DIFF_THRESHOLD):
        cleaned["change_summary"] = _diff_change_summary(prev_out, full_log)
        cleaned.pop("previous_output", None)
        cleaned["full_log"] = _truncate_text(
            full_log, _PROMPT_FULL_LOG_DIFFED_CAP)
    else:
        if isinstance(full_log, str):
            cleaned["full_log"] = _truncate_text(
                full_log, _PROMPT_FULL_LOG_CAP)
        if isinstance(prev_out, str):
            cleaned["previous_output"] = _truncate_text(
                prev_out, _PROMPT_FULL_LOG_CAP)

    return cleaned


def build_prompt(alert, enrichment, baseline, hosts_data,
                 graylog_logs=None, zeek_data=None, ntopng_data=None,
                 config=None, escalation_reason=None, rules=None):
    """
    Assemble the full LLM triage prompt.

    Parameters:
        alert       - raw Wazuh alert dict
        enrichment  - enrichment dict from enrich_alert()
        baseline    - baseline dict from calculate_baseline()
        hosts_data  - loaded hosts.json
        graylog_logs - formatted string from format_logs_for_prompt() or None
        zeek_data   - dict from fetch_zeek_flows() or None
        config      - config dict for window settings

    Returns prompt string.
    """
    search_window = 0.5
    if config:
        search_window = config.get("sources", {}).get(
            "graylog", {}).get("context_window_minutes", 0.5)

    # Use canonical_hostname for the HOST LOGS / ZEEK FLOWS section headers,
    # not agent.name. The Graylog query in graylog_fetch is keyed on
    # canonical_hostname (see search_graylog), so the section header should
    # describe what was actually queried. For Suricata alerts where
    # agent.name is "wazuh.manager", the previous header said
    # "HOST LOGS (wazuh.manager - ...)" which lied about the query subject —
    # Graylog was actually queried for the canonical host (e.g., "dmz-web-01").
    # Falls back to agent.name then "unknown" if canonical is somehow missing.
    canonical_hostname = enrichment.get("canonical_hostname", "")
    if canonical_hostname:
        agent_name = canonical_hostname
    else:
        agent_name = safe_get(alert, "agent", "name", default="unknown")

    ips = enrichment.get("ips", {})
    has_ips = bool(ips.get("all"))

    sections = []

    # --- Rule context (note from rules.json if present) ---
    rule_id   = safe_get(alert, "rule", "id", default="")
    rule_desc = safe_get(alert, "rule", "description", default="")
    if rules and rule_id:
        # rules.json may be either a dict keyed by rule_id, or a list of
        # rule entries each with a "rule_id" field. Handle both shapes.
        rule_entry = None
        if isinstance(rules, dict):
            rule_entry = rules.get(str(rule_id))
        elif isinstance(rules, list):
            for r in rules:
                if str(r.get("rule_id", "")) == str(rule_id):
                    rule_entry = r
                    break
        rule_note  = rule_entry.get("note", "").strip() if rule_entry else ""
        host_notes = rule_entry.get("host_notes", {}) if rule_entry else {}
        # Match host note key against canonical hostname.
        # Two-stage matching for FQDN tolerance (PB-40):
        #   1. Exact (case-insensitive) — e.g., "host01" matches "HOST01"
        #   2. First-label fallback — "host01.example.local" matches
        #      "host01" (and vice versa). Same defensive pattern as the host
        #      inventory matcher (PB-10) and lookup_host_by_name (Pin #9).
        host_note = ""
        if canonical_hostname and host_notes:
            ch_lower = canonical_hostname.lower()
            ch_short = ch_lower.split(".")[0]
            # Stage 1: exact match
            for hn_key, hn_val in host_notes.items():
                if hn_key and hn_key.lower() == ch_lower:
                    host_note = hn_val.strip() if hn_val else ""
                    break
            # Stage 2: first-label match (only if exact didn't hit)
            if not host_note:
                for hn_key, hn_val in host_notes.items():
                    if hn_key and hn_key.lower().split(".")[0] == ch_short:
                        host_note = hn_val.strip() if hn_val else ""
                        break
        # Only emit RULE CONTEXT if there's actual note content (PB-39).
        # Without notes, the block would just duplicate the alert summary's
        # Rule ID / Description lines, wasting tokens on no-information.
        # (PB-38: the previous nested `if rule_id:` was redundant — outer
        # `if rules and rule_id:` already guarantees rule_id is truthy.)
        if rule_note or host_note:
            sections.append("RULE CONTEXT:")
            sections.append(f"Rule {rule_id} - {rule_desc}")
            if rule_note:
                sections.append(f'Site-specific note: "{rule_note}"')
            if host_note:
                sections.append(f'Host-specific note for {canonical_hostname}: "{host_note}"')

    # --- Network context ---
    sections.append("NETWORK CONTEXT:")
    sections.append(build_network_context(hosts_data))

    # --- Sensor context - read from config ---
    prompt_cfg = config.get("prompt_customization", {}) if config else {}
    sensor_lines = prompt_cfg.get("sensor_context", [
        "Suricata is running on a SPAN/mirror port",
        "SPAN sensors may generate TCP anomaly alerts due to packet capture artifacts",
        "Wazuh agents report from individual hosts; alerts without src/dst IP are host-local events",
    ])
    sections.append("\nSENSOR CONTEXT:")
    sections.append("\n".join(f"- {line}" for line in sensor_lines))

    # --- Host inventory - context-aware, only relevant hosts ---
    sections.append("\nHOST INVENTORY (alert-relevant hosts only):")
    sections.append(build_host_inventory(hosts_data, enrichment=enrichment, zeek_data=zeek_data))

    # --- Alert summary ---
    sections.append("\nALERT SUMMARY:")
    sections.append(build_alert_summary(alert, enrichment))

    # --- Alert JSON (abridged or full, controlled by config) ---
    # By default, redundant fields already present in ALERT SUMMARY (rule
    # description, agent name, etc.) and noise fields (compliance metadata,
    # internal Wazuh IDs) are stripped before serialization. This reduces
    # prompt tokens without losing LLM-useful information. Set
    # prompt_customization.strip_redundant_fields = false in config to
    # disable and ship the full raw alert (useful if a custom workflow
    # depends on the stripped fields). The label changes to match what
    # is actually shipped — "ABRIDGED" when stripping is on, "FULL"
    # when it is off — so operators reading the prompt are not misled.
    strip_enabled = bool(prompt_cfg.get("strip_redundant_fields", True))
    if strip_enabled:
        alert_for_prompt = _strip_alert_for_prompt(alert)
        sections.append("\nALERT ABRIDGED JSON:")
    else:
        alert_for_prompt = alert
        sections.append("\nALERT FULL JSON:")
    sections.append("--- BEGIN RAW ALERT ---")
    try:
        sections.append(json.dumps(alert_for_prompt, indent=2))
    except (TypeError, ValueError):
        sections.append(str(alert_for_prompt))
    sections.append("--- END RAW ALERT ---")

    # --- Source enrichment ---
    sections.append("\nSOURCE ENRICHMENT:")
    sections.append(build_enrichment_block(enrichment))

    # --- Alert host role context ---
    # The alert host's role(s) resolved to their description/notes from
    # roles.json (set by enrich_alert as agent_role_context). Blank-aware:
    # the list is empty when the host has no roles, roles.json is absent, or
    # the roles are bare stubs — in which case nothing is appended.
    role_ctx = enrichment.get("agent_role_context", [])
    if role_ctx:
        sections.append("\nHOST ROLE CONTEXT (what is normal for this host's role(s)):")
        sections.append("\n".join(role_ctx))

    # --- Mentioned-IP block ---
    # IPs found by regex scan of full_log that did NOT appear in the
    # alert's structured IP fields. Rendered as a separate block with
    # explicit neutral framing so the LLM doesn't treat them as
    # actors. Suppressed entirely when there are no mentioned IPs.
    mentioned_block = build_mentioned_block(enrichment)
    if mentioned_block:
        sections.append(
            "\nIPS MENTIONED IN RAW LOG "
            "(may or may not be parties to this alert):"
        )
        sections.append(mentioned_block)

    # --- Baseline ---
    sections.append("\nALERT FREQUENCY BASELINE:")
    sections.append(build_baseline_block(baseline))

    # --- Escalation override note ---
    if escalation_reason:
        sections.append("\nESCALATION OVERRIDE:")
        # State the bare fact (rule + threshold) and stop. The previous
        # "Apply extra scrutiny" instruction biased the LLM toward NOTIFY
        # regardless of supporting evidence — well-known scanners hitting
        # closed services would still get NOTIFY when NOTE was the
        # appropriate verdict. Trust the evidence in the prompt and the
        # site-specific triage_guidance to drive verdict; don't editorialize.
        sections.append(
            f"This alert was escalated outside normal level filtering. "
            f"Reason: {escalation_reason}."
        )

    # --- Host logs ---
    sections.append(f"\nHOST LOGS ({agent_name} - "
                    f"{search_window} minute window around alert):")
    if graylog_logs:
        sections.append(graylog_logs)
    else:
        sections.append("No logs returned for this host/window")

    # --- Zeek flows - only if IPs present ---
    if has_ips and zeek_data:
        zeek_formatted = format_zeek_for_prompt(zeek_data)
        if zeek_formatted:
            # The Zeek window is NOT the graylog window: it has its own
            # config key (sources.zeek.context_window_minutes) and is
            # expanded to >=4 minutes for multi-fire alerts. Use the
            # shared helper (same one fetch_zeek_flows uses) so this
            # header always states the window that was actually fetched.
            zeek_window = (
                effective_zeek_window_minutes(config, alert)
                if config else 0.5
            )
            sections.append(f"\nZEEK FLOWS ({agent_name} - "
                            f"{zeek_window:g} minute window around alert):")
            sections.append(zeek_formatted)

    # --- ntopng active flows ---
    if ntopng_data:
        sections.append("\nNTOPNG ACTIVE FLOWS (current — not historical):")
        sections.append(ntopng_data)

    # --- Task ---
    sections.append("\nTASK:")
    # Baseline triage guidance from the module constant gets folded into
    # the "When evaluating alerts:" rubric. These are project-level rules
    # (how this pipeline does triage) rather than site customization,
    # which is why they live in code rather than config. Site-specific
    # additions still come through prompt_customization.triage_guidance
    # below and render in their own labeled section.
    baseline_bullets = "".join(
        f"- {line}\n" for line in _BASELINE_TRIAGE_GUIDANCE
    )
    sections.append(
        "Triage this alert for a solo home lab administrator. "
        "Your output must follow this exact format:\n\n"
        "VERDICT: [NOTIFY / NOTE / SUPPRESS]\n"
        "CONFIDENCE: [HIGH / MEDIUM / LOW]\n"
        "SUMMARY: One sentence explanation of what happened.\n"
        "REASONING: 2-3 sentences max. Focus on why this is or is not actionable.\n"
        "MISSING INFO: List critical gaps that would change the verdict. "
        "If the verdict can be validated with simple checks, include 1-3 concise commands to confirm or rule it out or diagnose issue. "
        "Include commands when they are directly relevant and reliable. "
        "Where commands are not applicable, provide brief investigation steps appropriate to the platform. "
        "Do not invent commands or tools. If none, state \"None.\"\n\n"
        "VERDICT definitions:\n"
        "- NOTIFY   : Requires immediate attention — something may be wrong, investigate now.\n"
        "- NOTE     : No immediate action needed but worth tracking on a to-do list. "
        "Use for: CVEs on non-internet-facing hosts, known scanners on internet-facing hosts, "
        "low-CVSS vulnerabilities, recurring background patterns that should be addressed eventually.\n"
        "- SUPPRESS : Confirmed noise, known benign activity, or expected behavior for this host "
        "as documented in host inventory notes. No action needed now or ever.\n\n"
        "When evaluating alerts:\n"
        "- Identify the root cause where possible (e.g., application crash, "
        "service restart, scheduled task, configuration change)\n"
        "- Do not justify SUPPRESS solely with \"normal network activity\" — "
        "explain WHY it is normal for this specific host and context\n"
        "- If the root cause is unclear, flag it in MISSING INFO\n"
        + baseline_bullets
    )

    # Triage guidance from config
    triage_lines = prompt_cfg.get("triage_guidance", [])
    if triage_lines:
        guidance = "\n".join(f"- {line}" for line in triage_lines)
        sections.append(f"\nSITE-SPECIFIC TRIAGE GUIDANCE:\n{guidance}")

    # Network notes from config
    network_notes = prompt_cfg.get("network_notes", [])
    if network_notes:
        notes = "\n".join(f"- {line}" for line in network_notes)
        sections.append(f"\nNETWORK NOTES:\n{notes}")

    sections.append(
        "\n"
        "Do not provide recommendations, rule adjustments, or general security advice "
        "unless the verdict is NOTIFY or NOTE. Output the structured format only. "
        "Do not add any text outside the format."
    )

    return "\n".join(sections)


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

    print("=== jrSOCtriage Prompt Builder Smoke Test ===\n")
    # KNOWN BUG (documented, not fixed): read_new_alerts() below advances the
    # shared .ingest_position, so running this smoke test against a LIVE
    # pipeline makes the pipeline skip the alerts consumed here. Run with the
    # pipeline stopped, or on the test platform. Same class as the ntopng /
    # zeek / email / llm_caller smoke tests.

    config     = load_config("config.json")
    hosts_data = load_hosts(config)
    conn       = get_connection(config)

    silence_seconds = config.get("processing", {}).get("dedup_silence_seconds", 240)
    min_level       = config.get("filtering", {}).get("min_rule_level", 6)

    alerts = list(read_new_alerts(config, min_level=0))
    print(f"Loaded {len(alerts)} alert(s)\n")

    shown = 0
    for alert in alerts:
        enrichment = enrich_alert(alert, config, hosts_data)
        dedup_key  = enrichment["dedup_key"]
        level      = int(safe_get(alert, "rule", "level", default=0))

        # Record in DB always
        record_alert(conn, enrichment, alert)

        # Dedup check
        if is_duplicate(dedup_key, silence_seconds):
            continue

        # Only build prompts for alerts at or above min_level
        if level < min_level:
            continue

        # Fetch supporting context
        alert_time   = parse_alert_timestamp(alert)
        graylog_logs = None
        zeek_data    = None

        gl_messages  = search_graylog(config, enrichment["canonical_hostname"], alert_time)
        graylog_logs = format_logs_for_prompt(gl_messages)

        ips = enrichment.get("ips", {})
        if ips.get("all") and alert_time:
            zeek_data = fetch_zeek_flows(config, alert, ips["all"], alert_time)

        # Baseline
        baseline = calculate_baseline(
            conn, config,
            enrichment["gl2_rule_id"],
            enrichment["canonical_hostname"],
            alert_ts=alert_time.timestamp() if alert_time else None
        )

        # Build prompt
        prompt = build_prompt(
            alert, enrichment, baseline, hosts_data,
            graylog_logs=graylog_logs,
            zeek_data=zeek_data,
            config=config,
        )

        print(f"=== PROMPT FOR: {dedup_key} ===")
        print(f"[Level {level}] {safe_get(alert, 'rule', 'description')}")
        print(f"Prompt length: {len(prompt)} chars\n")
        print(prompt)
        print("\n" + "="*60 + "\n")

        shown += 1
        if shown >= 2:
            break

    if shown == 0:
        print("No alerts at or above min_level found in batch")

    conn.close()
    print("=== Done ===")
