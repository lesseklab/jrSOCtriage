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
    role    = host.get("role", "?")
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
            gnoise  = ctx.get("greynoise_class", "N/A")
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
            if gnoise != "N/A":
                # Mentioned IPs are not necessarily parties to the alert,
                # so they don't get GREYNOISE STATUS block entries — but
                # the categorical rides inline (like abuse_score) since
                # reputation on a mentioned external IP may still be
                # operationally relevant.
                parts.append(f"greynoise={gnoise}")
            # VT/OTX ride the mention only on hash-bearing alerts
            # (enrich gates the lookups; see mentioned_context build).
            # Compact segments — the full interpretation notes live in
            # the party blocks, not here.
            vt_state = ctx.get("vt_state")
            if vt_state in ("hit", "clean"):
                parts.append(
                    f"vt={ctx.get('vt_malicious', 0)}"
                    f"/{ctx.get('vt_total', '?')} engines")
            elif vt_state in ("RATE_LIMITED", "AUTH_FAILED"):
                parts.append(f"vt={vt_state}")
            elif vt_state == "not_known":
                parts.append("vt=not in corpus")
            otx_state = ctx.get("otx_state")
            if otx_state == "referenced":
                p = ctx.get("otx_pulses", 0)
                p_str = "50+" if isinstance(p, int) and p >= 50 else str(p)
                parts.append(f"otx={p_str} pulses")
            elif otx_state == "no_reports":
                parts.append("otx=no reports")
            elif otx_state == "RATE_LIMITED":
                parts.append("otx=RATE_LIMITED")
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
# CISA KEV block — v1.1
# ---------------------------------------------------------------------------

# LLM interpretation note for KEV results (Kevin, 2026-07-13). Rendered
# ONLY when KEV entries actually appear in the prompt — the note exists to
# stop two specific verdict failure modes:
#   1. KEV-listed CVE  -> inflating a routine probe into "active attack"
#   2. CVE not in KEV  -> treating absence as evidence of benignity
# It rides the block, never appears standalone, and costs zero tokens on
# the (overwhelmingly common) no-CVE alert. Scope is KEV ONLY — MITRE
# tactic/technique interpretation is deliberately untouched.
_KEV_INTERPRETATION_NOTE = (
    "Interpretation: A CVE listed in KEV means that vulnerability has "
    "confirmed exploitation in the wild somewhere, at some time - it is "
    "NOT evidence that THIS alert represents active exploitation. A CVE "
    "absent from KEV is NOT evidence this alert is benign; absence only "
    "means CISA has not confirmed exploitation. Treat KEV status as "
    "priority context for the vulnerability, never as evidence about "
    "this specific event."
)


def build_kev_block(enrichment):
    """
    Build the KEV STATUS block from enrichment kev_context/kev_state.

    Returns None when the alert produced no KEV output at all (KEV
    disabled, or no CVEs extracted) — caller suppresses the block
    entirely, so the interpretation note only ever appears alongside
    actual KEV results (Kevin's conditional-note rule).

    Degraded states:
      UNAVAILABLE — CVEs were present but no catalog could be fetched.
                    One-line statement, no per-CVE entries, no
                    interpretation note (there are no results to
                    interpret; the CVEs themselves are visible in the
                    alert content above).
      STALE       — entries render normally from the old catalog, with
                    a staleness caveat line, plus the note.
    """
    kev_state = enrichment.get("kev_state")
    if not kev_state:
        return None

    if kev_state == "UNAVAILABLE":
        return ("KEV lookup UNAVAILABLE - this alert references CVE(s) "
                "but the CISA KEV catalog could not be fetched. Treat "
                "exploitation-confirmation status as unknown.")

    lines = []
    for entry in enrichment.get("kev_context", []):
        cve = entry.get("cve", "?")
        if entry.get("listed"):
            details = []
            if entry.get("date_added"):
                details.append(f"added {entry['date_added']}")
            if entry.get("ransomware_use"):
                details.append("known ransomware campaign use")
            suffix = f" ({', '.join(details)})" if details else ""
            lines.append(f"- {cve}: LISTED in CISA KEV{suffix}")
        else:
            lines.append(f"- {cve}: not in KEV catalog")

    if kev_state == "STALE":
        lines.append("- [KEV catalog is >48h stale (refresh failing); "
                     "listings above are best-effort]")

    lines.append(_KEV_INTERPRETATION_NOTE)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GreyNoise block — v1.1
# ---------------------------------------------------------------------------

# LLM interpretation note for GreyNoise results (spec locked 2026-07-14).
# Rendered ONLY when GreyNoise results are present in the record — same
# conditional-note rule as KEV: it rides the block, never appears
# standalone, and costs zero tokens on internal-only alerts. Uses API
# semantics only (noise / riot / classification) — the red/green/grey
# color language belongs to the GreyNoise visualizer palette, not the
# API, and would teach the LLM vocabulary that doesn't exist in the
# data. The note exists to stop two specific verdict failure modes:
#   1. noise+malicious -> inflating an aggressive MASS scanner (hitting
#      everyone, opportunistically) into evidence of targeting
#   2. not_seen        -> reading absence as missing data instead of
#      what it is: the targeted-activity signal
_GREYNOISE_INTERPRETATION_NOTE = (
    "Interpretation: GreyNoise reports whether an IP has been observed "
    "mass-scanning the ENTIRE internet. An IP observed as noise is "
    "engaging in opportunistic internet-wide activity - even when "
    "classified malicious, that means a known hostile/aggressive MASS "
    "scanner hitting everyone, NOT evidence this network is specifically "
    "targeted. A RIOT-listed IP is a known benign business service "
    "(common DNS, CDN, vendor infrastructure) - a strong "
    "de-prioritization signal for that indicator. An IP NOT observed "
    "scanning has no internet-wide footprint in GreyNoise - activity "
    "from it against this network is more plausibly targeted; treat "
    "that absence as a signal, not as missing data. RATE_LIMITED means "
    "the lookup could not be made - treat noise status as unknown."
)


def build_greynoise_block(enrichment):
    """
    Build the GREYNOISE STATUS block from greynoise_* fields on the
    external_context records (populated by enrich_external_ip when
    enrichment.greynoise is enabled).

    Returns None when no external IP carries a GreyNoise result (source
    disabled, internal-only alert, or every lookup unavailable) — caller
    suppresses the block entirely, so the interpretation note only ever
    appears alongside actual results (the conditional-note rule).

    Per-IP states rendered:
      riot          known benign business service (keyed lookups only —
                    the keyless tier strips RIOT data)
      benign/malicious/unknown
                    observed internet-wide mass scanner, with
                    actor/service name and last_seen when present
      not_seen      NOT observed scanning — a real answer, the
                    interesting branch
      RATE_LIMITED  lookup couldn't be made; annotated, not hidden

    N/A entries (lookup unavailable: 401 / timeout / transient) are
    skipped — same suppression as an N/A abuse_score in the enrichment
    block. Unrecognized future state strings are skipped defensively.
    """
    lines = []
    for ext in enrichment.get("external_context", []):
        cls = ext.get("greynoise_class", "N/A")
        if cls == "N/A":
            continue
        ip = ext.get("ip", "?")
        if cls == "riot":
            line = f"- {ip}: known benign business service (RIOT)"
            if ext.get("greynoise_name"):
                line += f" - {ext['greynoise_name']}"
        elif cls in ("benign", "malicious", "unknown"):
            parts = [f"- {ip}: observed mass-scanning the internet",
                     f"classification={cls}"]
            if ext.get("greynoise_name"):
                parts.append(f"actor/service={ext['greynoise_name']}")
            if ext.get("greynoise_last_seen"):
                parts.append(f"last_seen={ext['greynoise_last_seen']}")
            line = " | ".join(parts)
        elif cls == "not_seen":
            line = f"- {ip}: NOT observed scanning the internet"
        elif cls == "RATE_LIMITED":
            line = f"- {ip}: lookup RATE_LIMITED - noise status unknown"
        else:
            continue
        lines.append(line)

    if not lines:
        return None

    lines.append(_GREYNOISE_INTERPRETATION_NOTE)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# EPSS block — v1.1
# ---------------------------------------------------------------------------

# LLM interpretation note for EPSS results (spec locked 2026-07-15).
# Same conditional-note rule as KEV/GreyNoise: rides the block, never
# standalone, zero tokens on no-CVE alerts. The note's job is the
# decision rule, not the definition — the local-vs-global distinction
# (per Kevin 2026-07-15): likelihood of exploitation in the wild is
# NOT evidence of exploitation here; the verdict comes from the
# totality of the evidence. Parallels the shipped KEV note; must never
# drift into "confirmed/supersedes" phrasing, which is exactly what
# inflates a signature-mention into a false NOTIFY.
_EPSS_INTERPRETATION_NOTE = (
    "Interpretation: EPSS is the modeled probability (0 to 1, updated "
    "daily by FIRST.org) that each CVE will be exploited in the wild "
    "somewhere within the next 30 days; percentile is its rank among "
    "all scored CVEs. A high score or percentile is informative for "
    "prioritizing the vulnerability but is NOT evidence that this "
    "alert represents active exploitation on this network - likelihood "
    "of exploitation in the wild is not the same as exploitation "
    "observed here. Base the verdict on the totality of the evidence "
    "in this alert: the observed traffic, host context, and whether "
    "the activity actually reached or affected anything. \"Not scored\" "
    "means EPSS has no entry for that identifier - treat as unknown, "
    "not as low. RATE_LIMITED/unavailable means the lookup could not "
    "be made - treat probability as unknown."
)


def _fmt_epss(v):
    """Render an EPSS/percentile float compactly: 0.99999, 0.00018, 0.5
    — trailing zeros trimmed, never scientific notation."""
    return f"{v:.5f}".rstrip("0").rstrip(".") or "0"


def build_epss_block(enrichment):
    """
    Build the EPSS SCORES block from epss_state/epss_entries (populated
    by enrich_alert when enrichment.epss is enabled and the alert
    carries CVEs).

    Returns None when EPSS didn't run for this alert (disabled or no
    CVEs) — the conditional-note rule. When EPSS ran, the block always
    renders: scored and not-scored entries line-per-CVE, and a degraded
    state (RATE_LIMITED / UNAVAILABLE) renders an explicit failure line
    — the LLM should know scores were attempted and are unknown, not
    silently absent. On a partial failure (some CVEs served from cache,
    fetch failed for the rest) both the cached lines and the failure
    line render.
    """
    if "epss_state" not in enrichment:
        return None

    state   = enrichment.get("epss_state", "ok")
    entries = enrichment.get("epss_entries", [])

    lines = []
    for e in entries:
        cve = e.get("cve", "?")
        if e.get("scored"):
            lines.append(f"- {cve}: EPSS {_fmt_epss(e['epss'])} | "
                         f"percentile {_fmt_epss(e['percentile'])}")
        else:
            lines.append(f"- {cve}: not scored by EPSS")

    if state != "ok":
        lines.append(f"- [EPSS lookup {state} - remaining CVE(s) could "
                     f"not be scored; treat their probability as unknown]")

    lines.append(_EPSS_INTERPRETATION_NOTE)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# VirusTotal block — v1.1
# ---------------------------------------------------------------------------

# LLM interpretation note for VirusTotal results (spec locked
# 2026-07-16). Same conditional-note rule as its siblings. This note
# DELIBERATELY departs from the uniform local-vs-global reputation
# framing (locked D5): a high-detection file hash ON a host is
# near-direct evidence about the file itself, and a note that
# dismissed it with the standard "priority context, not evidence"
# language would muzzle the one source that can legitimately escalate
# a verdict on its own weight. The file/IP split keeps both truths;
# the previous-hash sentence covers the removed-malware case.
_VT_INTERPRETATION_NOTE = (
    "Interpretation: VirusTotal reports how many antivirus engines "
    "detect an indicator, based on GLOBAL submissions. For a FILE HASH "
    "found on a host: a high detection count means that exact file "
    "content is known malware - this is strong evidence about the file "
    "itself, though the verdict still depends on what the file was "
    "doing there (quarantine directories, AV samples, and honeypots "
    "legitimately hold malware). A malicious PREVIOUS hash on a changed "
    "file means known-bad content was present on the host and has just "
    "been overwritten - evidence of past presence (attacker cleanup, "
    "malware self-replacement, or AV remediation), worth escalation "
    "consideration even when the current file is clean. For an IP: "
    "detections describe the address's reputation elsewhere, NOT "
    "evidence this event is that activity - weigh with the totality of "
    "the evidence, as with other reputation sources. \"Not in VT "
    "corpus\" means never submitted - treat as unknown, not as clean; "
    "unknown hashes on unexpected paths deserve MORE scrutiny, not "
    "less. NOT_CHECKED means the per-alert lookup cap was reached. "
    "AUTH_FAILED means the VirusTotal API key was rejected - a "
    "configuration problem, not evidence about the alert. "
    "RATE_LIMITED/unavailable means the lookup could not be made - "
    "treat as unknown."
)

_VT_ROLE_LABEL = {"current": "current file", "previous": "previous content"}


def _vt_line(prefix, entry):
    """Render one VT result line. Returns None for skip-states."""
    state = entry.get("state")
    if state in (None, "N/A"):
        # Unavailable — same suppression as an N/A abuse_score.
        return None
    if state == "hit":
        parts = [f"{prefix}: {entry.get('malicious', '?')}/"
                 f"{entry.get('total', '?')} engines malicious"]
        if entry.get("suspicious"):
            parts.append(f"{entry['suspicious']} suspicious")
        if entry.get("label"):
            parts.append(f"label: {entry['label']}")
        return " | ".join(parts)
    if state == "clean":
        return (f"{prefix}: known to VT, 0 detections "
                f"({entry.get('total', '?')} engines)")
    if state == "not_known":
        return f"{prefix}: not in VT corpus - never submitted, treat as unknown"
    if state == "NOT_CHECKED":
        return f"{prefix}: NOT_CHECKED (per-alert cap)"
    if state == "RATE_LIMITED":
        return f"{prefix}: lookup RATE_LIMITED - reputation unknown"
    if state == "AUTH_FAILED":
        return (f"{prefix}: lookup AUTH_FAILED - VirusTotal API key "
                f"rejected; all VT lookups unavailable until the key "
                f"is fixed")
    return None  # future-proof: unrecognized state, skip


def build_vt_block(enrichment):
    """
    Build the VIRUSTOTAL block from vt_hashes (enrich_alert) and the
    vt_* fields on external_context records (enrich_external_ip).

    Returns None when nothing renders (source disabled, no indicators,
    or every lookup unavailable) — the conditional-note rule: the
    interpretation note only ever rides actual results. Hash lines
    render first (they're the headline), current-file before
    previous-content (extraction order), then IP lines.
    """
    lines = []
    for e in enrichment.get("vt_hashes", []):
        role = _VT_ROLE_LABEL.get(e.get("role"), "file")
        line = _vt_line(f"- {role} {e.get('hash', '?')}", e)
        if line:
            lines.append(line)
    for ext in enrichment.get("external_context", []):
        if "vt_state" not in ext:
            continue
        entry = {"state": ext.get("vt_state"),
                 "malicious": ext.get("vt_malicious"),
                 "total": ext.get("vt_total"),
                 "label": ext.get("vt_label")}
        line = _vt_line(f"- {ext.get('ip', '?')}", entry)
        if line:
            lines.append(line)

    if not lines:
        return None

    lines.append(_VT_INTERPRETATION_NOTE)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# AlienVault OTX block — v1.1
# ---------------------------------------------------------------------------

# The note's name-skepticism language leads (revised per live curls
# 2026-07-17): the attribution payload — pulse names — is polluted
# exactly where counts are high (EICAR's top pulses are literally
# student labs), so names are framed as leads to corroborate, never
# attribution. The one earned exception mirrors VT's locked-D5
# asymmetry: a named family/adversary on a FILE HASH found on a host
# is the strongest form of this signal, but only IF corroborated.
# "No community reports" honestly covers BOTH unknown indicators and
# known-but-unreferenced — live-verified, the API cannot distinguish
# them — so the note maps it to unknown, not clean.
_OTX_INTERPRETATION_NOTE = (
    "Interpretation: OTX pulses are community-contributed threat "
    "reports (IOC collections for campaigns, malware families, and "
    "attacker infrastructure). Pulse membership means someone "
    "referenced this indicator in community reporting - it is a "
    "POINTER, not a verdict, and not evidence that this alert is that "
    "activity. Pulse names are UNVETTED community labels: training-lab "
    "exercises and auto-generated pulses are common, so treat names as "
    "leads to corroborate, not as attribution. Recency matters - weigh "
    "the latest reference date. A named malware family or adversary on "
    "a FILE HASH found on a host is the strongest form of this signal, "
    "worth naming in the verdict reasoning IF corroborated by the "
    "other evidence (VirusTotal detections, file path, host context). "
    "\"No community reports\" means no analyst reference exists OR the "
    "indicator is unknown to OTX - treat as unknown, not as clean. "
    "RATE_LIMITED/unavailable means the lookup could not be made - "
    "treat as unknown."
)


def _otx_line(prefix, entry):
    """Render one OTX result line. Returns None for skip-states."""
    state = entry.get("state")
    if state in (None, "N/A"):
        # Unavailable — same suppression as an N/A vt_state.
        return None
    if state == "referenced":
        count = entry.get("pulses", 0)
        # 50 is the observed page-cap saturation point — render as a
        # floor, not an exact count. The numeric field stays 50.
        count_str = "50+" if isinstance(count, int) and count >= 50 \
            else str(count)
        plural = "" if count == 1 else "s"
        parts = [f"{prefix}: {count_str} community pulse{plural}"]
        if entry.get("latest"):
            parts.append(f"latest {entry['latest']}")
        names = entry.get("names") or []
        if names:
            parts.append(", ".join(f'"{n}"' for n in names))
        families = entry.get("families") or []
        if families:
            parts.append(f"families: {', '.join(families)}")
        if entry.get("adversary"):
            parts.append(f"adversary: {entry['adversary']}")
        return " | ".join(parts)
    if state == "no_reports":
        return f"{prefix}: no community reports"
    if state == "RATE_LIMITED":
        return f"{prefix}: lookup RATE_LIMITED - community status unknown"
    return None  # future-proof: unrecognized state, skip


def build_otx_block(enrichment):
    """
    Build the OTX COMMUNITY INTELLIGENCE block from otx_hashes
    (enrich_alert) and the otx_* fields on external_context records
    (enrich_external_ip).

    Returns None when nothing renders (source disabled, no indicators,
    or every lookup unavailable) — the conditional-note rule: the
    interpretation note only ever rides actual results. Hash lines
    render first (the hash-first lesson: FIM alerts fire daily, IP
    lines sit behind the external-alert gate), current-file before
    previous-content (extraction order), then IP lines. Role labels
    are shared with VT — same extraction, same vocabulary.
    """
    lines = []
    for e in enrichment.get("otx_hashes", []):
        role = _VT_ROLE_LABEL.get(e.get("role"), "file")
        line = _otx_line(f"- {role} {e.get('hash', '?')}", e)
        if line:
            lines.append(line)
    for ext in enrichment.get("external_context", []):
        if "otx_state" not in ext:
            continue
        entry = {"state": ext.get("otx_state"),
                 "pulses": ext.get("otx_pulses"),
                 "latest": ext.get("otx_latest"),
                 "names": ext.get("otx_names"),
                 "families": ext.get("otx_families"),
                 "adversary": ext.get("otx_adversary")}
        line = _otx_line(f"- {ext.get('ip', '?')}", entry)
        if line:
            lines.append(line)

    if not lines:
        return None

    lines.append(_OTX_INTERPRETATION_NOTE)
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

    # --- CISA KEV status (v1.1) ---
    # Suppressed entirely unless KEV produced output for this alert;
    # the interpretation note rides inside the block (see build_kev_block).
    kev_block = build_kev_block(enrichment)
    if kev_block:
        sections.append("\nKEV STATUS (CISA Known Exploited Vulnerabilities):")
        sections.append(kev_block)

    # --- EPSS scores (v1.1) ---
    # Adjacent to KEV (locked D1: both are CVE-keyed; the LLM reads the
    # confirmed-past / forward-likelihood pairing together). Suppressed
    # entirely unless EPSS ran for this alert; the interpretation note
    # rides inside the block (see build_epss_block).
    epss_block = build_epss_block(enrichment)
    if epss_block:
        sections.append("\nEPSS SCORES (exploitation probability, next 30 days):")
        sections.append(epss_block)

    # --- GreyNoise status (v1.1) ---
    # Suppressed entirely unless at least one external IP carries a
    # GreyNoise result; the interpretation note rides inside the block
    # (see build_greynoise_block).
    greynoise_block = build_greynoise_block(enrichment)
    if greynoise_block:
        sections.append("\nGREYNOISE STATUS "
                        "(internet-wide mass-scanning intelligence):")
        sections.append(greynoise_block)

    # --- VirusTotal (v1.1) ---
    # Suppressed entirely unless VT produced results for this alert;
    # the interpretation note (with the locked evidence-asymmetry
    # framing) rides inside the block (see build_vt_block).
    vt_block = build_vt_block(enrichment)
    if vt_block:
        sections.append("\nVIRUSTOTAL (antivirus engine detections):")
        sections.append(vt_block)

    # --- AlienVault OTX (v1.1) ---
    # After VT deliberately: engine detections say WHAT a file is;
    # pulses say WHO has reported it and in connection with what — the
    # LLM reads the fact before the attribution-flavored context.
    # Suppressed entirely unless OTX produced results for this alert;
    # the interpretation note (name-skepticism lead) rides inside the
    # block (see build_otx_block).
    otx_block = build_otx_block(enrichment)
    if otx_block:
        sections.append("\nOTX COMMUNITY INTELLIGENCE "
                        "(analyst-contributed threat reports):")
        sections.append(otx_block)

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
