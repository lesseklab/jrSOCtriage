#!/usr/bin/env python3
"""
jrSOCtriage - Enrichment Module
Extracts IPs from alerts, classifies internal vs external,
looks up hosts and network segments, enriches external IPs.
"""

import ipaddress
import json
import logging
import re
import subprocess
from pathlib import Path

import requests

# Reverse DNS via dnspython for thread-safe per-call timeout.
# Replaces the legacy socket.gethostbyaddr + socket.setdefaulttimeout
# pattern, which used process-global timeout state and was unsafe under
# concurrency.
import threading
import time
from collections import OrderedDict
import dns.resolver
import dns.reversename
import dns.exception

import perf_diag

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# External IP enrichment cache
# Persists for the life of the process - same IP never enriched twice
# ---------------------------------------------------------------------------

# External-IP enrichment cache: ip -> enrichment dict. Shared across
# worker threads WITHOUT a lock, deliberately: every access is a
# SINGLE .get() or set (atomic under the GIL, no torn state) — a
# membership-then-index pattern here previously raced the prune-
# cadence clear() into a KeyError that skipped one IP's enrichment;
# use .get(), never `in` + index. The remaining benign race — two
# workers check-then-enrich the same IP concurrently — costs a duplicate
# external lookup with last-write-wins on equivalent results, which
# is cheaper than serializing every cache hit behind a lock in the
# enrichment hot path. Two contracts keep this safe:
#   1. Cached entries are READ-ONLY after insertion. Consumers do
#      ext.get(...) reads; never mutate a cached dict in place, or
#      the mutation leaks into every later alert that hits that IP.
#   2. main.py clears this cache on its prune cadence (every 600s,
#      alongside dedup prune), which bounds both growth and staleness
#      (a config change like a new AbuseIPDB key takes effect within
#      one prune interval).
_ip_enrichment_cache = {}
# FT: guards _ip_enrichment_cache mutations. Under the GIL a single .get()/
# assignment was atomic; under free-threading (python3.14t) the read-miss-
# store sequence races and the dict itself can corrupt under concurrent
# mutation. Lock guards only the dict ops — the network enrichment call
# (enrich_external_ip) is deliberately OUTSIDE the lock, so a cold miss on
# the same IP across two workers does the lookup twice (idempotent, cheap)
# rather than serializing all enrichment behind one in-flight network call.
_ip_enrichment_cache_lock = threading.Lock()

def clear_enrichment_cache():
    """Clear the IP enrichment cache. Called by main.py's prune
    cadence (see the cache comment above); also useful for testing."""
    with _ip_enrichment_cache_lock:
        _ip_enrichment_cache.clear()


# ---------------------------------------------------------------------------
# Internal validation / normalization helpers
# ---------------------------------------------------------------------------

def _safe_ip(ip_str):
    """
    Validate and canonicalize an IP address.

    Returns ipaddress.IPv4Address or IPv6Address object, or None if input
    is None, "N/A", empty, not a string, or unparseable. Callers can
    compare returned objects for equality (handles IPv6 form normalization
    automatically) or convert back to string with str().

    Centralizes input safety and IPv6 canonicalization so individual
    functions don't each need their own None guards and try/except blocks.
    """
    if not isinstance(ip_str, str):
        return None
    if not ip_str or ip_str == "N/A":
        return None
    try:
        return ipaddress.ip_address(ip_str)
    except (ValueError, TypeError, AttributeError):
        return None


def _truncate(s, max_length):
    """
    Truncate a string to max_length characters.

    Returns empty string if input is not a string (defensive against
    None or unexpected types from external APIs). Used to cap third-party
    enrichment values (rdns, whois, geoip) at sensible lengths to protect
    against malformed responses producing overlong prompt content.
    """
    if not isinstance(s, str):
        return ""
    return s[:max_length]



# ---------------------------------------------------------------------------
# DNS + AbuseIPDB caches (2026-06-11 LOAC investigation)
#
# _reverse_dns previously built a NEW dns.resolver.Resolver() per call —
# re-reading and re-parsing /etc/resolv.conf every lookup — and had no
# result cache, so the same PTR was resolved over and over (canonical
# resolution pays this per sensor-origin alert). One shared resolver is
# built per distinct timeout (dnspython resolvers are safe for concurrent
# resolve() calls; timeout lives on the instance, hence per-timeout
# instances rather than mutating a shared one). Results — including
# negative ones, NXDOMAIN repeats being the common case — are cached
# with a TTL. AbuseIPDB gets its own longer-TTL cache: scores change
# slowly and the free tier is quota-limited.
# ---------------------------------------------------------------------------
_resolvers = {}
_resolver_lock = threading.Lock()

def _get_resolver(timeout):
    r = _resolvers.get(timeout)
    if r is None:
        with _resolver_lock:
            r = _resolvers.get(timeout)
            if r is None:
                r = dns.resolver.Resolver()
                r.timeout = timeout
                r.lifetime = timeout
                _resolvers[timeout] = r
    return r

_ptr_cache = OrderedDict()      # insertion order == age order (see _cache_put)
_ptr_cache_lock = threading.Lock()
_PTR_TTL_S = 300
_PTR_MAX = 4096

_abuse_cache = OrderedDict()    # insertion order == age order
_abuse_cache_lock = threading.Lock()
_ABUSE_TTL_S = 1800
_ABUSE_MAX = 1024

# whois (org/netname) and geoip (country/asn/city) are static registry
# metadata for an IP block — stable for months. Cache aggressively with
# long TTLs so we fork the whois subprocess / hit ip-api at most once per
# IP per lifetime. abuse stays at 1800s above because reputation scores
# genuinely change on a useful timescale; these do not.
_whois_cache = OrderedDict()    # insertion order == age order
_whois_cache_lock = threading.Lock()
_WHOIS_TTL_S = 86400      # 24h
_WHOIS_MAX = 4096

_geoip_cache = OrderedDict()    # insertion order == age order
_geoip_cache_lock = threading.Lock()
_GEOIP_TTL_S = 86400      # 24h
_GEOIP_MAX = 4096

# GreyNoise (v1.1): categorical noise/riot classification per IP. Same
# TTL as abuse — classifications move on a similar reputation timescale.
# not_seen results (404, or a 200 noise:false miss) ARE cached: "not
# observed scanning the internet" is an answer, not a failure.
# RATE_LIMITED and unavailable results are never cached (self-healing
# the moment quota/key recovers).
_greynoise_cache = OrderedDict()   # insertion order == age order
_greynoise_cache_lock = threading.Lock()
_GREYNOISE_TTL_S = 1800
_GREYNOISE_MAX = 1024

# EPSS (v1.1): per-CVE exploitation-probability scores. 24h TTL matches
# the daily publication cadence (EPSS v4 scores new CVEs within ~24h of
# NVD publication, so the TTL also naturally picks up newly-scored
# CVEs). Scored AND not-scored results are cached — "checked, not in
# the corpus" is an answer. RATE_LIMITED and unavailable results are
# never cached (self-healing).
_epss_cache = OrderedDict()        # insertion order == age order
_epss_cache_lock = threading.Lock()
_EPSS_TTL_S = 86400
_EPSS_MAX = 2048

# VirusTotal (v1.1): per-indicator engine-detection lookups. One cache,
# two TTLs by indicator kind: hash verdicts move slowly and every cache
# hit is free-tier quota saved (24h); IP reputation moves on the same
# cadence as abuse/greynoise (30min). hit/clean/not_known are all
# cached — "known clean" and "never submitted" are answers.
# RATE_LIMITED and unavailable results are never cached (self-healing).
_vt_cache = OrderedDict()          # insertion order == age order
_vt_cache_lock = threading.Lock()
_VT_HASH_TTL_S = 86400
_VT_IP_TTL_S = 1800
_VT_MAX = 2048

# AlienVault OTX (v1.1): per-indicator community-pulse lookups. Same
# kind-keyed one-cache/two-TTLs shape as VT: pulse membership on a hash
# moves slowly (24h); IP infrastructure gets referenced and ages on the
# reputation cadence (30min). referenced AND no_reports are both
# cached — "checked, no community reports" is an answer, and per live
# verification 2026-07-17 the API cannot distinguish an unknown
# indicator from a known-but-unreferenced one (both return 200 with
# pulse count 0), so both are honestly no_reports. RATE_LIMITED and
# unavailable results are never cached (self-healing).
_otx_cache = OrderedDict()         # insertion order == age order
_otx_cache_lock = threading.Lock()
_OTX_HASH_TTL_S = 86400
_OTX_IP_TTL_S = 1800
_OTX_MAX = 2048

def _cache_get(cache, lock, key, ttl):
    now = time.time()
    with lock:
        hit = cache.get(key)
        if hit and now - hit[0] < ttl:
            return True, hit[1]
    return False, None

def _cache_put(cache, lock, key, value, max_size):
    # REG-10..13 shrink (2026-06-23): eviction is now O(1) instead of an
    # O(n) min() scan UNDER the lock. The caches are OrderedDicts and
    # _cache_get never refreshes an entry's timestamp on hit, so insertion
    # order == age order; popitem(last=False) removes the OLDEST entry —
    # identical eviction semantics to the old `min(cache, key=age)` scan,
    # but constant-time. This collapses the worst-case lock hold from
    # O(max_size) (up to 4096 entries scanned while holding the lock, the
    # primary enrich convoy seed) to a fixed pop+insert. Re-inserting an
    # existing key is moved to the end so it doesn't falsely look oldest.
    with lock:
        if key in cache:
            # refresh position so a re-put key is treated as newest
            cache.move_to_end(key)
        elif len(cache) >= max_size:
            cache.popitem(last=False)   # evict oldest, O(1)
        cache[key] = (time.time(), value)

def _reverse_dns(ip_str, timeout, metric_name="dns"):
    """
    Thread-safe reverse DNS lookup via dnspython.

    Returns the FQDN string (with trailing dot stripped) or None on any
    failure (NXDOMAIN, timeout, malformed response, invalid input, etc.).

    Uses dnspython instead of socket.gethostbyaddr because the socket
    approach requires socket.setdefaulttimeout() which is process-global
    and unsafe under concurrent use. dnspython's resolver applies timeout
    per-call via instance attributes, so multiple threads can each have
    their own timeout without trampling each other.

    The 'timeout' parameter sets BOTH per-query timeout (resolver.timeout)
    AND total operation deadline (resolver.lifetime), so a slow or broken
    DNS server can't exceed the bound regardless of retries.

    Internal code expects FQDNs without trailing dots (matching the legacy
    socket.gethostbyaddr return shape), so we strip the dot before returning.
    """
    if _safe_ip(ip_str) is None:
        perf_diag.cache(metric_name, "invalid")
        return None
    found, cached = _cache_get(_ptr_cache, _ptr_cache_lock, ip_str, _PTR_TTL_S)
    if found:
        perf_diag.cache(metric_name, "cache_hit")
        if cached is None:
            perf_diag.cache(metric_name, "lookup_miss")
        else:
            perf_diag.cache(metric_name, "lookup_hit")
        return cached
    perf_diag.cache(metric_name, "cache_miss")
    try:
        resolver = _get_resolver(timeout)
        reverse_name = dns.reversename.from_address(ip_str)
        answer = resolver.resolve(reverse_name, "PTR")
        for rdata in answer:
            fqdn = str(rdata).rstrip(".")
            if fqdn:
                perf_diag.cache(metric_name, "lookup_hit")
                _cache_put(_ptr_cache, _ptr_cache_lock, ip_str, fqdn, _PTR_MAX)
                return fqdn
        perf_diag.cache(metric_name, "lookup_miss")
        _cache_put(_ptr_cache, _ptr_cache_lock, ip_str, None, _PTR_MAX)
        return None
    except (dns.exception.DNSException, ValueError, OSError):
        # Negative-cache failures too: repeated NXDOMAIN/timeout on the
        # same IP is the common case under alert storms.
        perf_diag.cache(metric_name, "error")
        perf_diag.cache(metric_name, "lookup_miss")
        _cache_put(_ptr_cache, _ptr_cache_lock, ip_str, None, _PTR_MAX)
        return None




# ---------------------------------------------------------------------------
# RFC1918 / private range check
# ---------------------------------------------------------------------------

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT (RFC6598) - used by Tailscale, some VPN providers
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local addresses (RFC4193)
]

def is_private(ip_str):
    """Return True if IP is private/loopback/link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return True  # unparseable = treat as internal, don't enrich


def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# IP extraction - scrape every field that might carry an IP
# ---------------------------------------------------------------------------

# Regex to find IPv4 addresses in arbitrary strings
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Regex to find IPv6 addresses in arbitrary strings.
# Two alternatives, IPv4-mapped tried first to avoid truncating "::ffff:1.2.3.4"
# at the dotted-quad boundary:
#   1. IPv4-mapped form: hex/colon prefix followed by dotted-quad
#   2. Standard IPv6: hex groups separated by colons, last group required
# Permissive on purpose — false positives (MAC addresses, timestamps) are
# filtered out by is_valid_ip() validation downstream. The cost of a few
# wasted regex matches is preferred over a more complex regex.
IPV6_RE = re.compile(
    r'(?:[0-9a-fA-F]{0,4}:){2,6}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{1,4}'
)

# Known fields that carry IPs across different alert types
IP_FIELD_PATHS = [
    # Suricata
    ("data", "src_ip"),
    ("data", "dest_ip"),
    # Windows Security Events
    ("data", "win", "eventdata", "ipAddress"),
    ("data", "win", "eventdata", "sourceAddress"),
    # Agent
    ("agent", "ip"),
]

def extract_ips(alert):
    """
    Extract all IPs from an alert. Returns dict:
    {
        "internal":  [list of private IPs from structured fields],
        "external":  [list of public IPs from structured fields],
        "mentioned": [list of IPs from regex scan of full_log, minus
                      anything already in internal/external],
        "all":       [combined deduplicated list of internal + external + mentioned]
    }
    Skips loopback (127.x, ::1) and unparseable values.

    The internal/external split represents IPs that are parties to the
    alert (extracted from known structured fields). The mentioned list
    represents IPs found by regex scan of full_log — these may or may
    not be parties to the alert (e.g., DNS resolution log entries on a
    DC will contain IPs that were merely looked up, not actors).
    Downstream consumers use this distinction to avoid pulling
    hosts.json entries for IPs that only appear incidentally.
    """
    # --- Structured-field extraction (parties to the alert) ---
    structured = set()
    from ingest import safe_get
    for path in IP_FIELD_PATHS:
        val = safe_get(alert, *path)
        if val != "N/A" and is_valid_ip(val):
            structured.add(val)

    # --- Regex scan of full_log (mentions, not necessarily actors) ---
    # IPs found here may be passive references in log text — DNS
    # resolutions on a domain controller, proxied source IPs, mail
    # recipient addresses, etc. is_valid_ip() filters out regex false
    # positives (MAC addresses, timestamps, hex strings).
    scanned = set()
    full_log = safe_get(alert, "full_log")
    if full_log != "N/A":
        for match in IPV4_RE.findall(full_log):
            if is_valid_ip(match):
                scanned.add(match)
        for match in IPV6_RE.findall(full_log):
            if is_valid_ip(match):
                scanned.add(match)

    # mentioned = scanned minus anything already in structured. An IP
    # that appears in both gets the higher-confidence "structured"
    # classification and drops out of mentioned.
    mentioned_raw = scanned - structured

    # --- Filter loopback / 0.0.0.0 from all three sets ---
    # Skip all loopback addresses (entire 127.0.0.0/8, ::1) to avoid
    # surfacing Docker/local service binds (e.g., 127.0.0.5) as
    # "internal hosts." Also skip 0.0.0.0 (the unspecified-address
    # sentinel, which is not loopback per is_loopback but should
    # never appear in alert context as a real host).
    def _keep(ip):
        # Drop address classes that can never be a real alert-context
        # host: loopback, unspecified (0.0.0.0 / ::), multicast
        # (SSDP's 239.255.255.250 is a constant presence in lab
        # Windows logs and was previously classified "external" —
        # burning AbuseIPDB/GeoIP quota on multicast), and reserved
        # (which covers 255.255.255.255 broadcast). Documentation
        # ranges (192.0.2.0/24 etc.) escape every ipaddress property
        # and are accepted residual: rare in real logs, and they
        # enrich to harmless N/A rows.
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False
        if (addr.is_loopback or addr.is_unspecified
                or addr.is_multicast or addr.is_reserved):
            return False
        return True

    internal = []
    external = []
    for ip in structured:
        if not _keep(ip):
            continue
        if is_private(ip):
            internal.append(ip)
        else:
            external.append(ip)

    mentioned = [ip for ip in mentioned_raw if _keep(ip)]

    return {
        "internal":  sorted(internal),
        "external":  sorted(external),
        "mentioned": sorted(mentioned),
        "all":       sorted(set(internal + external + mentioned))
    }


# ---------------------------------------------------------------------------
# Host lookup
# ---------------------------------------------------------------------------

def lookup_host_by_name(name, hosts_data):
    """
    Match alert agent name against hosts.json.

    Two-stage matching for FQDN tolerance:
      1. Exact match (case-insensitive) — preserves existing behavior
      2. First-label match — handles cases where the input or hosts.json
         entry is an FQDN. e.g., looking up "host01.example.local"
         matches "host01" in hosts.json, and looking up "host01" matches
         "host01.example.local" in hosts.json. Symmetric.

    The first-label fallback is essential for operators whose Wazuh agents
    register with FQDNs, or whose rdns_lookup returns FQDNs for canonical
    resolution.
    """
    if not name or name == "N/A":
        return None
    name_lower = name.lower()
    name_short = name_lower.split(".")[0]

    # Stage 1: exact match
    for host in hosts_data.get("hosts", []):
        host_name = host.get("name", "").lower()
        if host_name == name_lower:
            return host

    # Stage 2: first-label match (symmetric — handles FQDN on either side)
    for host in hosts_data.get("hosts", []):
        host_name = host.get("name", "").lower()
        host_short = host_name.split(".")[0]
        if host_short and host_short == name_short:
            return host

    return None


def lookup_host_by_ip(ip_str, hosts_data):
    """
    Match an IP against explicit identifiers in hosts.json.

    Supports two schema forms for identifiers.ip:
      - String:  "192.168.10.45"           (legacy, single IP)
      - List:    ["192.168.10.45", "10.6.0.5"]  (multi-IP, e.g., a phone
                 with both LAN and VPN addresses)

    Both forms work in the same hosts.json — operators can mix per-host.

    IP comparisons use _safe_ip canonicalization so IPv6 forms compare
    correctly: "2001:DB8::1" matches "2001:db8::1" and "2001:0db8:0000:
    0000:0000:0000:0000:0001". Without canonicalization, equivalent IPv6
    addresses written in different forms would silently fail to match.

    Returns the matching host record or None.
    """
    target = _safe_ip(ip_str)
    if target is None:
        return None

    for host in hosts_data.get("hosts", []):
        identifiers = host.get("identifiers", {})
        ips = identifiers.get("ip")
        if ips is None:
            continue
        # Normalize string-or-list to a list for uniform handling
        if isinstance(ips, str):
            ip_list = [ips]
        elif isinstance(ips, list):
            ip_list = ips
        else:
            # Malformed — skip silently. load_hosts validation in v1.1
            # will surface this at startup.
            continue
        for candidate in ip_list:
            candidate_addr = _safe_ip(candidate)
            if candidate_addr is not None and candidate_addr == target:
                return host
    return None


def lookup_network(ip_str, hosts_data):
    """Match an IP to a network segment in hosts.json."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for network in hosts_data.get("networks", []):
        try:
            net = ipaddress.ip_network(network.get("cidr", ""), strict=False)
            if addr in net:
                return network
        except ValueError:
            continue
    return None


def describe_host(host, network=None):
    """Build a readable one-liner for a known host."""
    if not host:
        return "Unknown host"
    parts = [host.get("name", "?")]
    role = host.get("role")
    # role may be a single string (single-role host) or a list (multi-role
    # host, e.g. AM5 = vm_host + windows_workstation + soc_station). Render
    # either as a comma-joined name string; a bare list would break the
    # " | ".join() below.
    role_str = _role_names_str(role)
    if role_str:
        parts.append(role_str)
    if host.get("os"):
        parts.append(host["os"])
    if network:
        parts.append(f"{network.get('name','?')} ({network.get('role','?')})")
    tags = host.get("tags", [])
    if tags:
        parts.append(f"[{', '.join(tags)}]")
    return " | ".join(parts)


def _role_names_str(role):
    """Normalize a host's role field (string OR list) to a comma-joined
    display string of role names. Empty/blank entries are dropped. Returns
    "" when there are no roles."""
    if isinstance(role, list):
        names = [r.strip() for r in role if isinstance(r, str) and r.strip()]
        return ", ".join(names)
    if isinstance(role, str):
        return role.strip()
    return ""


def role_context_lines(host, role_lookup):
    """Resolve a host's role(s) to their description/notes context for the
    prompt. role_lookup is the name->role-block dict from build_role_lookup.

    Returns a list of formatted lines (one+ per role) ready to drop into the
    SOURCE ENRICHMENT block, blank-aware: a role's description and notes are
    each emitted only when non-empty, and a role with neither (a fresh stub,
    or a name not found in roles.json) renders just its name. Returns [] when
    the host has no roles or no lookup is available — so a missing/empty
    roles.json degrades cleanly to no role context, never an error."""
    if not host or not role_lookup:
        return []
    role = host.get("role")
    if isinstance(role, list):
        names = [r.strip() for r in role if isinstance(r, str) and r.strip()]
    elif isinstance(role, str) and role.strip():
        names = [role.strip()]
    else:
        names = []

    lines = []
    for name in names:
        block = role_lookup.get(name.lower())
        desc  = (block.get("description") or "").strip() if block else ""
        notes = (block.get("notes") or "").strip() if block else ""
        if desc and notes:
            lines.append(f"  - {name}: {desc}")
            lines.append(f"    {notes}")
        elif desc:
            lines.append(f"  - {name}: {desc}")
        elif notes:
            lines.append(f"  - {name}: {notes}")
        else:
            # no context (fresh stub or name not in roles.json) — name only
            lines.append(f"  - {name}")
    return lines


# ---------------------------------------------------------------------------
# Canonical hostname resolution
# ---------------------------------------------------------------------------

def ptr_lookup(ip_str):
    """
    Reverse DNS PTR lookup. Returns short hostname (first label, lowercased)
    or None on any failure.

    Uses 0.5-second timeout — fast LAN DNS expected (valid PTR on this
    network answers in single-digit ms; the only thing the timeout governs
    is how long a worker blocks on a DEAD lookup). PTR is the source of
    truth for canonical hostname resolution on the lab network.

    Timeout reduced 3s -> 0.5s (2026-06-18): enrich runs OUTSIDE the stage
    brackets, so a worker blocked here is a watchdog blind spot; a 3s block
    risked the watchdog misreading slow-DNS workers as parked-at-get() and
    abandoning them. 0.5s fast-fails dead lookups. Failures are negative-
    cached so a miss doesn't repeat per alert.

    Returns the SHORT form: 'host01' from 'host01.example.local'.
    For the full FQDN, use rdns_lookup.
    """
    fqdn = _reverse_dns(ip_str, timeout=0.5, metric_name="dns")
    if fqdn is None:
        return None
    return fqdn.split(".")[0].lower()

def resolve_canonical_hostname(alert, hosts_data, config=None):
    """
    Resolve the canonical hostname for an alert's source host.
    Priority:
      1. agent.name match in hosts.json (Wazuh agent names are registered and stable)
      2. PTR lookup on agent.ip (DNS is source of truth on this network)
      3. For sensor-origin alerts (wazuh.manager, suricata, etc. — names
         configured via processing.sensor_agent_names), fall back to
         internal src_ip / dest_ip from the alert payload. Accepts PTR-only
         results when hosts.json has no entry — operators with incomplete
         host inventories still get useful canonical names.
      4. Fallback: agent.name as-is, lowercased
      5. Final fallback: "unknown"
    Returns (canonical_hostname, host_record_or_None)

    The config parameter is optional for backward compatibility with code
    that doesn't have config in scope (e.g., existing tests). When None,
    falls back to the historical hardcoded defaults.
    """
    from ingest import safe_get

    agent_name = safe_get(alert, "agent", "name")
    agent_ip   = safe_get(alert, "agent", "ip")

    # 0. Synthetic test-harness traffic bypass. Alerts generated by
    #    the synthetic load-test harness have agent.name =
    #    "loac-host-NNNNN" but preserve a real agent.ip so Zeek/ntopng
    #    have flow data to enrich against. A PTR lookup on that real IP
    #    would collapse every synthetic clone back to the source host's
    #    real name, defeating the dedup-key uniqueness the test relies
    #    on. The "loac-host-" prefix is distinctive enough that it
    #    cannot collide with a real Wazuh agent name on the network, so
    #    we treat it as canonical and skip resolution. This is the only
    #    test-harness-aware branch in production code; the trade-off is
    #    accepted because the synthetic harness is part of the project's
    #    verification story (see running_instructions.txt for details).
    #    Note this branch runs BEFORE the PTR lookup below, which is why
    #    synthetic clones are never resolved back to one host.
    if agent_name != "N/A" and agent_name.startswith("loac-host-"):
        return agent_name.lower(), None

    # 1. agent.name match in hosts.json (Wazuh agent names are registered and stable)
    host_record = lookup_host_by_name(agent_name, hosts_data)
    if host_record:
        return host_record.get("name", agent_name).lower(), host_record

    # 2. PTR lookup on agent.ip
    if agent_ip != "N/A" and is_valid_ip(agent_ip):
        ptr = ptr_lookup(agent_ip)
        if ptr:
            # Try to match PTR result against hosts.json
            host_record = lookup_host_by_name(ptr, hosts_data)
            return ptr, host_record

    # 3. For Suricata/sensor alerts - agent is wazuh.manager or a sensor host,
    #    not the actual traffic source. Try to resolve from internal src_ip instead.
    if config is not None:
        sensor_names = set(
            safe_get(config, "processing", "sensor_agent_names",
                     default=["wazuh.manager", "wazuh-manager", "suricata"])
        )
    else:
        sensor_names = {"wazuh.manager", "wazuh-manager", "suricata"}

    if agent_name.lower() in sensor_names:
        # Try data.src_ip first (Suricata flow source)
        src_ip = safe_get(alert, "data", "src_ip")
        if src_ip != "N/A" and is_valid_ip(src_ip) and is_private(src_ip):
            h, hr = resolve_ip_hostname(src_ip, hosts_data)
            if hr:
                return hr.get("name", h).lower(), hr
            # PTR-only fallback: hosts.json had no entry, but PTR found
            # something better than the IP itself. Use PTR result so the
            # alert isn't tagged with the sensor's own name.
            if h != src_ip:
                return h.lower(), None

        # Try dest_ip if src was external
        dest_ip = safe_get(alert, "data", "dest_ip")
        if dest_ip != "N/A" and is_valid_ip(dest_ip) and is_private(dest_ip):
            h, hr = resolve_ip_hostname(dest_ip, hosts_data)
            if hr:
                return hr.get("name", h).lower(), hr
            # Same PTR-only fallback for dest_ip
            if h != dest_ip:
                return h.lower(), None

    # 4. Fallback - use agent.name as-is
    if agent_name != "N/A":
        return agent_name.lower(), None

    return "unknown", None


def resolve_ip_hostname(ip_str, hosts_data):
    """
    Resolve a hostname for any IP in the alert (not just the agent).
    Priority: hosts.json explicit IP → hosts.json name match via PTR → PTR only
    Returns (hostname_or_ip, host_record_or_None)
    """
    # Check explicit IP identifiers in hosts.json
    host_record = lookup_host_by_ip(ip_str, hosts_data)
    if host_record:
        return host_record.get("name", ip_str).lower(), host_record

    # PTR lookup
    ptr = ptr_lookup(ip_str)
    if ptr:
        host_record = lookup_host_by_name(ptr, hosts_data)
        return ptr, host_record

    # Fallback to IP
    return ip_str, None


# ---------------------------------------------------------------------------
# External IP enrichment
# ---------------------------------------------------------------------------

def rdns_lookup(ip_str):
    """
    Reverse DNS lookup returning the full FQDN. Returns hostname string
    or None on any failure.

    Uses 1-second timeout. rdns is an EXTERNAL lookup (upstream resolver
    chains), but context enrichment is best-effort: a missing FQDN is a
    minor context gap, not worth blocking a worker for 5s. Capped at 1s
    (2026-06-18) — if the upstream chain can't answer in 1s, the LLM does
    without it. Pipeline throughput > completeness of optional context.

    Result is truncated to RFC 1035 max hostname length (253 chars) to
    defend against malformed or hostile PTR records returning overlong
    strings that would bloat the prompt or leak unexpected content.
    """
    fqdn = _reverse_dns(ip_str, timeout=1, metric_name="rdns")
    if fqdn is None:
        return None
    return _truncate(fqdn, 253)


def whois_org(ip_str):
    """
    Run whois and extract the org/netname line.
    Returns org string or None.

    Input is validated as an IP address before being passed to subprocess
    to prevent any possibility of whois arg injection (e.g. @server, -h).

    Result is truncated to 200 chars to defend against malformed or
    deliberately hostile whois records returning overlong strings.
    """
    if not is_valid_ip(ip_str):
        return None
    found, cached = _cache_get(_whois_cache, _whois_cache_lock, ip_str,
                               _WHOIS_TTL_S)
    if found:
        return cached
    org = None
    try:
        result = subprocess.run(
            ["whois", ip_str],
            # 10s -> 2s (2026-06-18): whois forks an external process that
            # can block a worker the full timeout in the (now-bracketed)
            # enrich stage. org-name is best-effort context — a 10s block is
            # not worth it. 2s (not 1s like the HTTP lookups): whois queries
            # to RIR servers are legitimately slower, so 2s keeps a fair
            # catch-rate while still bounding the worst-case worker block.
            # TimeoutExpired is caught below and the lookup returns no org.
            capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            line_lower = line.lower()
            if any(line_lower.startswith(k) for k in ("org-name:", "orgname:", "netname:", "organization:")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    val = parts[1].strip()
                    if val:
                        org = _truncate(val, 200)
                        break
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    _cache_put(_whois_cache, _whois_cache_lock, ip_str, org, _WHOIS_MAX)
    return org


def geoip_lookup(ip_str):
    """
    GeoIP via ip-api.com (free, no key required).
    Returns dict with country, country_code, city, org, asn or empty dict.

    Field values are truncated to per-field caps to defend against
    malformed or hostile API responses returning overlong strings:
      - country_code: 8 chars (always 2 in valid data; cap is defensive)
      - country, city: 100 chars (longest legit names well under)
      - org: 200 chars (corporate names can run long)
      - asn: 100 chars (typical "AS#### Provider Name" form)
    """
    if _safe_ip(ip_str) is None:
        return {}
    found, cached = _cache_get(_geoip_cache, _geoip_cache_lock, ip_str,
                               _GEOIP_TTL_S)
    if found:
        return cached
    result = {}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip_str}",
            params={"fields": "status,country,countryCode,city,org,as"},
            timeout=1
        )
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "country":      _truncate(data.get("country", ""), 100),
                "country_code": _truncate(data.get("countryCode", ""), 8),
                "city":         _truncate(data.get("city", ""), 100),
                "org":          _truncate(data.get("org", ""), 200),
                "asn":          _truncate(data.get("as", ""), 100),
            }
    except (requests.RequestException, ValueError):
        pass
    _cache_put(_geoip_cache, _geoip_cache_lock, ip_str, result, _GEOIP_MAX)
    return result


def abuseipdb_lookup(ip_str, api_key):
    """
    AbuseIPDB confidence score lookup.
    Returns dict with abuse_score, total_reports or empty dict.

    Returns empty dict (not zero-defaults) on missing/malformed response
    fields so callers can distinguish "AbuseIPDB has no data" from
    "AbuseIPDB confirmed score of 0". Defaulting missing data to 0 would
    silently bias verdicts toward "this IP is clean" when we actually
    have no information about it.
    """
    if not api_key or api_key == "REPLACE_ME":
        perf_diag.cache("abuse", "disabled")
        return {}
    if _safe_ip(ip_str) is None:
        perf_diag.cache("abuse", "invalid")
        return {}
    found, cached = _cache_get(_abuse_cache, _abuse_cache_lock, ip_str,
                               _ABUSE_TTL_S)
    if found:
        perf_diag.cache("abuse", "cache_hit")
        perf_diag.cache("abuse", "lookup_hit")
        return dict(cached)
    perf_diag.cache("abuse", "cache_miss")
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip_str, "maxAgeInDays": 90},
            timeout=1
        )
        # Fail-loud rate-limit handling (v1.1). A 429 body has no "data"
        # key, so before this check it fell through the lookup_miss branch
        # below — silently indistinguishable from "AbuseIPDB has no data on
        # this IP". Detect it explicitly: warn the operator (per lookup,
        # with the IP that went unchecked — on the free tier a rate limit
        # at homelab volume likely means an attack in progress, so each
        # line is signal, and lookups are NEVER suppressed or backed off
        # for the same reason), and return a sentinel the caller turns
        # into a RATE_LIMITED record annotation. The sentinel is not
        # cached: rate-limited is state, not data.
        if resp.status_code == 429:
            perf_diag.cache("abuse", "rate_limited")
            logger.warning(
                f"AbuseIPDB rate-limited (HTTP 429) - reputation lookup "
                f"skipped for {ip_str}; record annotated RATE_LIMITED"
            )
            return {"rate_limited": True}
        data = resp.json().get("data", {})
        if "abuseConfidenceScore" not in data:
            perf_diag.cache("abuse", "lookup_miss")
            return {}
        perf_diag.cache("abuse", "lookup_hit")
        result = {
            "abuse_score":   data["abuseConfidenceScore"],
            "total_reports": data.get("totalReports", 0),
        }
        _cache_put(_abuse_cache, _abuse_cache_lock, ip_str, result,
                   _ABUSE_MAX)
        return dict(result)
    except (requests.RequestException, ValueError):
        perf_diag.cache("abuse", "error")
    # Note: failures are NOT cached here — a transient API error should
    # not suppress lookups for 30 minutes.
    return {}


GREYNOISE_URL = "https://api.greynoise.io/v3/community/"

# 401 warns once per process, not per lookup — a bad key at alert rate
# would otherwise spam the log. Plain module flag: the check-then-set
# race under free-threading can at worst double-log the warning, which
# is harmless and not worth a lock on the hot path.
_greynoise_401_warned = False


def greynoise_lookup(ip_str, api_key, warn_on_429=True):
    """
    GreyNoise Community lookup: is this IP known internet-wide
    mass-scanning / a known benign business service (RIOT), or has
    GreyNoise NOT seen it scanning at all?

    Returns one of:
      {"class": "riot", ["name"]}                 known benign business
                                                  service (KEYED only)
      {"class": "benign"|"malicious"|"unknown",   observed mass scanner;
       ["name"], ["last_seen"]}                   class from the API's
                                                  classification field
      {"class": "not_seen"}                       NOT observed scanning —
                                                  a real answer (404 or a
                                                  200 miss), the
                                                  targeted-activity signal
      {"rate_limited": True}                      429 — caller annotates
                                                  RATE_LIMITED
      {}                                          unavailable (401 /
                                                  timeout / error)

    Keyless operation (empty api_key) is a supported tier: the endpoint
    answers unauthenticated at very low volume (~10 lookups/day; free
    accounts no longer receive API keys). The keyless tier STRIPS RIOT
    data — canonical RIOT IPs return riot:false keyless (verified live
    2026-07-14) — so keyless riot:false is meaningless and the riot
    field is never read without a key: RIOT status is UNKNOWN keyless,
    not false. Riot classification renders keyed only.

    Timeout 1s (locked): supplementary reputation signal — a slow answer
    is worth less than a fast pipeline. No backoff/retry on 429 (locked).
    """
    global _greynoise_401_warned
    if _safe_ip(ip_str) is None:
        perf_diag.cache("greynoise", "invalid")
        return {}
    found, cached = _cache_get(_greynoise_cache, _greynoise_cache_lock,
                               ip_str, _GREYNOISE_TTL_S)
    if found:
        perf_diag.cache("greynoise", "cache_hit")
        return dict(cached)
    perf_diag.cache("greynoise", "cache_miss")
    headers = {"Accept": "application/json"}
    if api_key:
        # Header only when keyed — an empty key header is not the same
        # as no header on this endpoint (unauthenticated tier).
        headers["key"] = api_key
    try:
        resp = requests.get(GREYNOISE_URL + ip_str, headers=headers,
                            timeout=1)

        if resp.status_code == 404:
            # A real answer, NOT an error: GreyNoise has not observed
            # this IP scanning the internet — activity against this
            # network is plausibly targeted. Cached: it is data.
            perf_diag.cache("greynoise", "not_seen")
            result = {"class": "not_seen"}
            _cache_put(_greynoise_cache, _greynoise_cache_lock, ip_str,
                       result, _GREYNOISE_MAX)
            return dict(result)

        if resp.status_code == 429:
            perf_diag.cache("greynoise", "rate_limited")
            # Warning gated by enrichment.greynoise.rate_limit_warnings
            # (caller passes it): with a commercial key, a 429 during
            # normal ops signals elevated external-IP volume — warn
            # loud, per lookup, with the IP that went unchecked (the
            # AbuseIPDB fail-loud template). Keyless at ~10/day, 429 is
            # routine — operators disable the warning; the RATE_LIMITED
            # record annotation ships regardless. No backoff, never
            # cached: rate-limited is state, not data.
            if warn_on_429:
                logger.warning(
                    f"GreyNoise rate-limited (HTTP 429) - noise lookup "
                    f"skipped for {ip_str}; record annotated RATE_LIMITED"
                )
            return {"rate_limited": True}

        if resp.status_code == 401:
            perf_diag.cache("greynoise", "unauthorized")
            if not _greynoise_401_warned:
                _greynoise_401_warned = True
                logger.warning(
                    "GreyNoise API key rejected (HTTP 401) - noise "
                    "lookups unavailable until the key is fixed "
                    "(warned once per process)")
            return {}

        if resp.status_code != 200:
            perf_diag.cache("greynoise", "error")
            return {}

        data = resp.json()

        # RIOT — keyed only. The keyless tier strips RIOT data (see
        # docstring), so the field is only meaningful with a key.
        if api_key and data.get("riot"):
            perf_diag.cache("greynoise", "riot")
            result = {"class": "riot"}
            name = _truncate(str(data.get("name") or ""), 100)
            if name:
                result["name"] = name
            _cache_put(_greynoise_cache, _greynoise_cache_lock, ip_str,
                       result, _GREYNOISE_MAX)
            return dict(result)

        if data.get("noise"):
            # Observed mass scanner. Full fields ship on hits in BOTH
            # tiers (verified live keyless 2026-07-14 on Stretchoid:
            # classification/name/last_seen all present). Class is
            # clamped to the API's three values so a future API
            # addition can't leak an unexpected string into GELF.
            classification = str(data.get("classification")
                                 or "unknown").lower()
            if classification not in ("benign", "malicious", "unknown"):
                classification = "unknown"
            perf_diag.cache("greynoise", "noise")
            result = {"class": classification}
            name = _truncate(str(data.get("name") or ""), 100)
            if name:
                result["name"] = name
            last_seen = _truncate(str(data.get("last_seen") or ""), 32)
            if last_seen:
                result["last_seen"] = last_seen
            _cache_put(_greynoise_cache, _greynoise_cache_lock, ip_str,
                       result, _GREYNOISE_MAX)
            return dict(result)

        # 200 with noise:false (and no usable riot) — same semantics as
        # 404: not observed scanning. This is the keyless miss shape
        # verified live (bare {ip, noise:false, riot:false, message}).
        perf_diag.cache("greynoise", "not_seen")
        result = {"class": "not_seen"}
        _cache_put(_greynoise_cache, _greynoise_cache_lock, ip_str,
                   result, _GREYNOISE_MAX)
        return dict(result)
    except (requests.RequestException, ValueError):
        perf_diag.cache("greynoise", "error")
    # Transient failures are NOT cached — same rule as abuse.
    return {}


def _record_degraded(record):
    """True when an enrichment record carries a rate-limit annotation.

    Degraded records are NOT stored in _ip_enrichment_cache (same principle
    as the abuse cache's failures-are-not-cached rule: rate-limited is
    state, not data). Every subsequent alert touching the IP re-runs
    enrichment - nearly free, since rdns/whois/geoip hit their own 24h
    caches - and the moment quota recovers, the next lookup produces a
    clean record which caches normally. Self-healing, no stale RATE_LIMITED
    annotations. Checks values generically so the v1.1 enrichment sources
    inherit the behavior by using the same annotation string. AUTH_FAILED
    (added with VirusTotal, 2026-07-16) is equally cache-excluding: a
    fixed API key must take effect on the next alert, not after a cache
    TTL."""
    return any(v in ("RATE_LIMITED", "AUTH_FAILED")
               for v in record.values())


def enrich_external_ip(ip_str, config, include_vt_otx=True):
    """
    Run all external enrichment for one IP.
    Returns a dict of everything we found.
    """
    enrichment_cfg = config.get("enrichment", {})
    abuseipdb_cfg  = enrichment_cfg.get("abuseipdb", {})
    greynoise_cfg  = enrichment_cfg.get("greynoise", {})
    virustotal_cfg = enrichment_cfg.get("virustotal", {})
    otx_cfg        = enrichment_cfg.get("otx", {})

    result = {"ip": ip_str}

    if enrichment_cfg.get("rdns", {}).get("enabled", True):
        result["rdns"] = rdns_lookup(ip_str) or "N/A"

    if enrichment_cfg.get("whois", {}).get("enabled", True):
        result["whois_org"] = whois_org(ip_str) or "N/A"

    if enrichment_cfg.get("geo_ip", {}).get("enabled", True):
        geo = geoip_lookup(ip_str)
        result["country"]      = geo.get("country", "N/A")
        result["country_code"] = geo.get("country_code", "N/A")
        result["city"]         = geo.get("city", "N/A")
        result["org"]          = geo.get("org", "N/A")
        result["asn"]          = geo.get("asn", "N/A")

    if abuseipdb_cfg.get("enabled", False):
        abuse = abuseipdb_lookup(ip_str, abuseipdb_cfg.get("api_key", ""))
        if abuse.get("rate_limited"):
            # Warranted lookup (enabled, keyed, valid IP, cache miss) hit
            # the API rate limit. Annotate rather than N/A so the prompt,
            # GELF (gl2_abuse_score:RATE_LIMITED is searchable), and the
            # operator can all distinguish "no data" from "couldn't ask".
            result["abuse_score"]   = "RATE_LIMITED"
            result["total_reports"] = "RATE_LIMITED"
        else:
            result["abuse_score"]   = abuse.get("abuse_score", "N/A")
            result["total_reports"] = abuse.get("total_reports", "N/A")

    if greynoise_cfg.get("enabled", False):
        gn = greynoise_lookup(
            ip_str,
            greynoise_cfg.get("api_key", ""),
            warn_on_429=greynoise_cfg.get("rate_limit_warnings", True),
        )
        if gn.get("rate_limited"):
            # Same fail-loud contract as AbuseIPDB: annotate rather than
            # N/A so the prompt, GELF (gl2_greynoise_class:RATE_LIMITED
            # is searchable), and the operator can all distinguish "no
            # data" from "couldn't ask". _record_degraded keys on this
            # exact string, keeping the whole record out of the
            # enrichment cache so the next alert re-asks.
            result["greynoise_class"] = "RATE_LIMITED"
        elif gn:
            result["greynoise_class"] = gn.get("class", "N/A")
            if gn.get("name"):
                result["greynoise_name"] = gn["name"]
            if gn.get("last_seen"):
                result["greynoise_last_seen"] = gn["last_seen"]
        else:
            # Unavailable (401 / timeout / transient error) — noise
            # status is unknown, not a classification.
            result["greynoise_class"] = "N/A"

    if include_vt_otx:
        result.update(_vt_otx_ip_fields(ip_str, config))

    return result


def _needs_vt_otx_upgrade(rec, config):
    """
    True when a cached IP record predates (or was built without) the
    hash-gated VT/OTX fields that the current consumer needs: the
    record lacks a state field for an enabled source. Disabled sources
    never require an upgrade.
    """
    enr = config.get("enrichment", {})
    vt_cfg = enr.get("virustotal", {})
    if vt_cfg.get("enabled", False) and vt_cfg.get("api_key") \
            and "vt_state" not in rec:
        return True
    otx_cfg = enr.get("otx", {})
    if otx_cfg.get("enabled", False) and "otx_state" not in rec:
        return True
    return False


def _vt_otx_ip_fields(ip_str, config):
    """
    The VT-IP and OTX-IP lookups, factored out of enrich_external_ip
    so they can be (a) skipped for mentioned IPs on hash-less alerts
    — per the 2026-07-18 decision, mentioned-IP VT/OTX reputation is
    only decision-relevant when the alert also carries a hash change,
    so hash-less alerts spend no VT/OTX quota on regex-found IPs —
    and (b) run standalone to UPGRADE a cached lite record when a
    party consumer (or a hash-bearing mention) later needs the
    fields. Returns the field dict to merge into the IP record.
    """
    result = {}
    enrichment_cfg = config.get("enrichment", {})
    virustotal_cfg = enrichment_cfg.get("virustotal", {})
    otx_cfg        = enrichment_cfg.get("otx", {})

    if virustotal_cfg.get("enabled", False) and virustotal_cfg.get("api_key"):
        vt = vt_lookup(ip_str, "ip", virustotal_cfg.get("api_key", ""),
                       warn_on_429=virustotal_cfg.get(
                           "rate_limit_warnings", False))
        state = vt.get("state")
        if state == "RATE_LIMITED":
            # Same fail-loud contract as AbuseIPDB/GreyNoise:
            # _record_degraded keys on this exact string, keeping the
            # record out of the enrichment cache so the next alert
            # re-asks. IP lookups are NOT counted against the per-alert
            # hash cap — they're bounded by the alert's external-IP
            # count and this per-IP record cache instead (a cross-
            # function budget would interact incoherently with cached
            # records that carry vt fields without spending anything).
            result["vt_state"] = "RATE_LIMITED"
        elif state:
            result["vt_state"] = state
            if state in ("hit", "clean"):
                result["vt_malicious"] = vt.get("malicious", 0)
                result["vt_total"]     = vt.get("total", 0)
            if vt.get("label"):
                result["vt_label"] = vt["label"]
        else:
            result["vt_state"] = "N/A"

    if otx_cfg.get("enabled", False):
        # Key NOT required — keyless runs at the lower public ceiling
        # (GreyNoise model; see otx_lookup docstring).
        ox = otx_lookup(ip_str, "ip", otx_cfg.get("api_key", ""),
                        warn_on_429=otx_cfg.get(
                            "rate_limit_warnings", False))
        state = ox.get("state")
        if state == "RATE_LIMITED":
            # Same fail-loud contract as AbuseIPDB/GreyNoise/VT:
            # _record_degraded keys on this exact string, keeping the
            # record out of the enrichment cache so the next alert
            # re-asks the moment quota recovers.
            result["otx_state"] = "RATE_LIMITED"
        elif state:
            result["otx_state"] = state
            if state == "referenced":
                result["otx_pulses"] = ox.get("pulses", 0)
                if ox.get("latest"):
                    result["otx_latest"] = ox["latest"]
                if ox.get("names"):
                    result["otx_names"] = ox["names"]
                if ox.get("families"):
                    result["otx_families"] = ox["families"]
                if ox.get("adversary"):
                    result["otx_adversary"] = ox["adversary"]
        else:
            # Unavailable (timeout / 5xx / husk) — community status is
            # unknown, not an answer.
            result["otx_state"] = "N/A"

    return result


# ---------------------------------------------------------------------------
# CISA KEV (Known Exploited Vulnerabilities) enrichment — v1.1
#
# Architectural odd-one-out among enrichment sources: CISA publishes the
# KEV catalog only as one JSON document (no per-CVE endpoint, no key, no
# rate limit), so this is a LOOKUP against a periodically refreshed local
# copy — alerts' own CVEs are matched against it; nothing is scanned
# against traffic, so it stays lookup-shaped, not a detection feed.
#
# Refresh contract (non-blocking, fail-loud):
#   - Lazy: the first CVE-bearing alert after TTL expiry triggers the
#     fetch. Alerts with no CVEs never cause any KEV activity at all.
#   - One worker fetches; concurrent workers serve the OLD catalog (or
#     degrade, if none exists yet) rather than waiting on the lock.
#   - Fetch failures: with no catalog in memory, lookups degrade to
#     UNAVAILABLE (annotated, warned). With a cached catalog, it serves
#     silently up to _KEV_STALE_LIMIT_S, then serves WITH a STALE
#     annotation + warning (an old catalog is still mostly right — KEV
#     only grows). Fetch attempts are throttled to one per
#     _KEV_RETRY_THROTTLE_S so an outage doesn't tax every alert.
# ---------------------------------------------------------------------------

KEV_CATALOG_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                   "known_exploited_vulnerabilities.json")
_KEV_TTL_S = 86400            # refresh cadence: 24h
_KEV_STALE_LIMIT_S = 172800   # serve stale silently until 48h, then annotate
_KEV_RETRY_THROTTLE_S = 60    # min gap between fetch attempts after failure

_kev_catalog = None           # dict: CVE-ID -> {date_added, ransomware_use, name}
_kev_fetched_at = 0.0         # epoch of last SUCCESSFUL fetch
_kev_last_attempt = 0.0       # epoch of last fetch ATTEMPT (success or fail)
_kev_fetch_lock = threading.Lock()

# CVE identifier pattern. Case-insensitive; matches are canonicalized to
# uppercase. 4-7 digit sequence per the official ID scheme.
CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)


def extract_cves(alert):
    """
    Extract CVE identifiers from an alert. The CVE analog of extract_ips.

    Scanned surfaces:
      - rule.description (Suricata ET signature names carry CVEs here
        when wrapped by Wazuh)
      - full_log (raw signature text / payload context)
      - data.vulnerability.cve (Wazuh vulnerability-detector structured
        field; may be a string or a list)

    Returns a sorted, deduplicated list of uppercase CVE IDs. Empty list
    for the (overwhelmingly common) no-CVE alert — the entire KEV feature
    is a no-op for those.
    """
    from ingest import safe_get
    found = set()

    for surface in (safe_get(alert, "rule", "description"),
                    safe_get(alert, "full_log")):
        if isinstance(surface, str) and surface != "N/A":
            for m in CVE_RE.findall(surface):
                found.add(m.upper())

    vd = safe_get(alert, "data", "vulnerability", "cve")
    vd_items = vd if isinstance(vd, list) else [vd]
    for item in vd_items:
        if isinstance(item, str):
            for m in CVE_RE.findall(item):
                found.add(m.upper())

    return sorted(found)


def _kev_fetch():
    """
    Fetch and install a fresh KEV catalog. Returns True on success.

    Runs under _kev_fetch_lock (caller holds it). 10s timeout — unlike
    the 1s per-indicator lookups this is a ~2MB document fetched at most
    once per _KEV_TTL_S, and only ever from a worker already handling a
    CVE-bearing alert; a rare bounded 10s worst case is accepted for a
    once-a-day operation.
    """
    global _kev_catalog, _kev_fetched_at
    try:
        # Explicit User-Agent: cisa.gov is CDN-fronted and CDNs commonly
        # 403 the default python-requests agent string.
        resp = requests.get(KEV_CATALOG_URL, timeout=10,
                            headers={"User-Agent": "jrSOCtriage/1.1"})
        if resp.status_code != 200:
            perf_diag.cache("kev", "fetch_fail")
            logger.warning(
                f"KEV catalog fetch failed: HTTP {resp.status_code}")
            return False
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            # A 200 with an empty/alien body is a failure, not an empty
            # catalog — KEV has >1000 entries; never install a husk.
            perf_diag.cache("kev", "fetch_fail")
            logger.warning("KEV catalog fetch returned no vulnerabilities "
                           "- keeping previous catalog")
            return False
        catalog = {}
        for v in vulns:
            cve = str(v.get("cveID", "")).upper()
            if cve:
                catalog[cve] = {
                    "date_added":     _truncate(str(v.get("dateAdded", "")), 32),
                    "ransomware_use": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                    "name":           _truncate(str(v.get("vulnerabilityName", "")), 200),
                }
        _kev_catalog = catalog
        _kev_fetched_at = time.time()
        perf_diag.cache("kev", "fetch_ok")
        logger.info(f"KEV catalog refreshed: {len(catalog)} entries")
        return True
    except (requests.RequestException, ValueError) as e:
        perf_diag.cache("kev", "fetch_fail")
        logger.warning(f"KEV catalog fetch failed: {e}")
        return False


def kev_lookup(cves):
    """
    Match extracted CVEs against the KEV catalog.

    Returns (state, entries):
      state:   "ok" | "STALE" | "UNAVAILABLE"
      entries: [{cve, listed, date_added, ransomware_use}, ...] — one per
               input CVE, INCLUDING not-listed ones ("checked, not in
               catalog" is information). Empty when UNAVAILABLE.

    Never blocks on another worker's in-flight fetch: if the fetch lock
    is held, this call serves whatever catalog currently exists.
    """
    global _kev_last_attempt
    now = time.time()
    age = now - _kev_fetched_at

    if (_kev_catalog is None or age >= _KEV_TTL_S) and \
            (now - _kev_last_attempt) >= _KEV_RETRY_THROTTLE_S:
        # Non-blocking single-fetcher: if another worker is fetching,
        # skip and serve what exists.
        if _kev_fetch_lock.acquire(blocking=False):
            try:
                _kev_last_attempt = time.time()
                _kev_fetch()
                age = time.time() - _kev_fetched_at
            finally:
                _kev_fetch_lock.release()

    if _kev_catalog is None:
        perf_diag.cache("kev", "unavailable")
        logger.warning(
            "KEV lookup degraded: no catalog available "
            "(fetch failing); records annotated UNAVAILABLE")
        return "UNAVAILABLE", []

    state = "ok"
    if age >= _KEV_STALE_LIMIT_S:
        state = "STALE"
        perf_diag.cache("kev", "stale")
        logger.warning(
            f"KEV catalog is stale ({age/3600:.1f}h old; refresh failing) "
            f"- serving anyway, records annotated STALE")

    entries = []
    for cve in cves:
        hit = _kev_catalog.get(cve)
        if hit:
            perf_diag.cache("kev", "listed")
            entries.append({
                "cve":            cve,
                "listed":         True,
                "date_added":     hit["date_added"],
                "ransomware_use": hit["ransomware_use"],
            })
        else:
            perf_diag.cache("kev", "not_listed")
            entries.append({
                "cve":            cve,
                "listed":         False,
                "date_added":     "",
                "ransomware_use": False,
            })
    return state, entries


EPSS_URL = "https://api.first.org/data/v1/epss"


def epss_lookup(cves):
    """
    Batch-score CVEs against FIRST.org's EPSS (Exploit Prediction
    Scoring System). CVE-keyed sibling of kev_lookup, but per-alert
    batch API lookup instead of a resident catalog: the EPSS corpus is
    ~250k entries (vs KEV's ~1,300) and the API takes a comma-separated
    CVE list, so one HTTP call covers an entire alert.

    Returns (state, entries):
      state:   "ok" | "RATE_LIMITED" | "UNAVAILABLE"
      entries: [{cve, scored, epss, percentile}, ...] — one per input
               CVE, INCLUDING not-scored ones (scored=False): a CVE
               silently absent from the API's data[] is a real answer,
               "not in the EPSS corpus" (verified live 2026-07-15:
               batch of one scored + one unassigned CVE returned
               total=1 with the unassigned ID absent). On a failed
               fetch, entries still carries whatever the cache had —
               state signals the failure, cached data is not discarded
               (serve-what-you-have, the KEV stale-serve principle);
               entries is empty only when nothing was cached.

    Convoy-safety (standing constraint): _epss_cache_lock is held only
    for O(1) dict ops, never across I/O; the HTTP call runs outside any
    lock; there is no shared fetch to coordinate — the whole KEV
    single-flight problem doesn't exist here. No backoff, no retry.

    Timeout 1s (locked): supplementary signal; a slow answer is worth
    less than a fast pipeline.
    """
    entries_by_cve = {}
    misses = []
    for cve in cves:
        found, cached = _cache_get(_epss_cache, _epss_cache_lock,
                                   cve, _EPSS_TTL_S)
        if found:
            perf_diag.cache("epss", "cache_hit")
            entries_by_cve[cve] = dict(cached)
        else:
            perf_diag.cache("epss", "cache_miss")
            misses.append(cve)

    state = "ok"
    if misses:
        try:
            resp = requests.get(EPSS_URL,
                                params={"cve": ",".join(misses)},
                                timeout=1)
            if resp.status_code == 429:
                perf_diag.cache("epss", "rate_limited")
                # Unconditional warning (locked D3): unlike GreyNoise
                # keyless there is no routine-429 operating mode here —
                # one batched call per CVE-bearing alert, cached 24h,
                # should never hit a limit. A 429 is always anomalous.
                logger.warning(
                    f"EPSS rate-limited (HTTP 429) - scores skipped for "
                    f"{','.join(misses)}; record annotated RATE_LIMITED")
                state = "RATE_LIMITED"
            elif resp.status_code != 200:
                perf_diag.cache("epss", "unavailable")
                state = "UNAVAILABLE"
            else:
                body = resp.json()
                data = body.get("data")
                if body.get("status") != "OK" or not isinstance(data, list):
                    # Husk-guard principle: a 200 with an alien body is
                    # a failure, not a corpus miss — never install
                    # garbage as "not scored".
                    perf_diag.cache("epss", "unavailable")
                    state = "UNAVAILABLE"
                else:
                    returned = {}
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        cve_id = str(item.get("cve", "")).upper()
                        try:
                            # Decimal strings per the API contract;
                            # clamp defensively so a malformed value
                            # can't leak an out-of-range float into
                            # GELF. Malformed entries are skipped, not
                            # batch-fatal.
                            score = min(max(float(item.get("epss")), 0.0), 1.0)
                            pct   = min(max(float(item.get("percentile")), 0.0), 1.0)
                        except (TypeError, ValueError):
                            continue
                        if cve_id:
                            returned[cve_id] = (score, pct)
                    for cve in misses:
                        if cve in returned:
                            perf_diag.cache("epss", "scored")
                            entry = {"cve": cve, "scored": True,
                                     "epss": returned[cve][0],
                                     "percentile": returned[cve][1]}
                        else:
                            # Requested but absent from data[] — not in
                            # the EPSS corpus. A real answer; cached.
                            perf_diag.cache("epss", "not_scored")
                            entry = {"cve": cve, "scored": False,
                                     "epss": None, "percentile": None}
                        entries_by_cve[cve] = entry
                        _cache_put(_epss_cache, _epss_cache_lock, cve,
                                   dict(entry), _EPSS_MAX)
        except (requests.RequestException, ValueError):
            perf_diag.cache("epss", "error")
            state = "UNAVAILABLE"
        # Failed fetches (429/5xx/timeout/husk) cache nothing — the next
        # CVE-bearing alert re-asks.

    entries = [entries_by_cve[c] for c in cves if c in entries_by_cve]
    return state, entries


# 32/40/64 hex = md5/sha1/sha256. Longest-first so a sha256 never
# half-matches as two shorter digests; word-bounded so hex inside
# longer tokens doesn't false-positive.
HASH_RE = re.compile(
    r"\b[0-9a-f]{64}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{32}\b", re.IGNORECASE)


def extract_hashes(alert):
    """
    Extract file hashes from an alert as an ordered list of
    (digest, role) tuples, role in ("current", "previous").

    STRUCTURED-FIRST (locked D1): when alert.syscheck is present, hashes
    come ONLY from its structured fields — the full_log of a syscheck
    alert repeats all six digests in prose and regexing it would
    double-count. One lookup per FILE STATE, not per digest: a
    md5/sha1/sha256 triplet describes one content state, so take the
    strongest available digest (sha256 > sha1 > md5) per state.

    ORDER IS PRIORITY (locked D1): "current" (_after) states first —
    the content on the host now — then "previous" (_before) states,
    which fill remaining per-alert budget. The before-state exists to
    catch the removed-malware case (known-bad content just overwritten:
    attacker cleanup, malware self-replacement, AV remediation).

    Regex sweep of rule.description + full_log is the FALLBACK for
    hash-bearing non-FIM rules only (role "current"; deduplicated,
    first-seen order).
    """
    from ingest import safe_get
    out = []
    syscheck = alert.get("syscheck")
    if isinstance(syscheck, dict):
        for role, suffix in (("current", "_after"), ("previous", "_before")):
            for alg in ("sha256", "sha1", "md5"):
                h = syscheck.get(f"{alg}{suffix}")
                if isinstance(h, str) and HASH_RE.fullmatch(h.strip()):
                    out.append((h.strip().lower(), role))
                    break
        return out

    seen = set()
    for surface in (safe_get(alert, "rule", "description"),
                    safe_get(alert, "full_log")):
        if isinstance(surface, str) and surface != "N/A":
            for m in HASH_RE.findall(surface):
                h = m.lower()
                if h not in seen:
                    seen.add(h)
                    out.append((h, "current"))
    return out


VT_URL = "https://www.virustotal.com/api/v3"

# 401 warns once per process — bad-key spam guard, same pattern and
# same FT rationale as the GreyNoise flag (double-log at worst).
_vt_401_warned = False


def vt_lookup(indicator, kind, api_key, warn_on_429=False):
    """
    VirusTotal engine-detection lookup for one indicator.
    kind: "file" (md5/sha1/sha256) or "ip".

    Returns one of:
      {"state": "hit", "malicious": N, "suspicious": N, "total": N,
       ["label": str]}                  detections present
      {"state": "clean", "malicious": 0, "suspicious": 0, "total": N}
                                        in corpus, zero detections
      {"state": "not_known"}            404 — never submitted; a real
                                        answer (NOT "clean"), cached
      {"state": "RATE_LIMITED"}         429 quota — annotated, not cached
      {}                                unavailable (no key / 401 /
                                        timeout / error / husk)

    Denominator rule (live-verified 2026-07-16): total = sum of ALL
    last_analysis_stats values — the key set differs by kind (files
    carry confirmed-timeout/failure/type-unsupported, IPs don't), so
    the keys are never hardcoded. EICAR: 65 malicious of 74; 8.8.8.8:
    0 of 91.

    Timeout 1s (locked D4 by measurement: 7/8 keyed requests
    0.26-0.37s from the oob box). No local quota gate (locked D2):
    call-and-annotate; on the free tier 429s are routine, the warning
    is config-gated (default off), and RATE_LIMITED annotations
    accumulating in Graylog are the upgrade signal by design. No
    backoff, no retry, nothing ever waits on quota.
    """
    global _vt_401_warned
    if not api_key:
        return {}
    if kind == "ip":
        if _safe_ip(indicator) is None:
            perf_diag.cache("virustotal", "invalid")
            return {}
        endpoint, ttl = "ip_addresses", _VT_IP_TTL_S
    else:
        if not HASH_RE.fullmatch(indicator or ""):
            perf_diag.cache("virustotal", "invalid")
            return {}
        endpoint, ttl = "files", _VT_HASH_TTL_S

    cache_key = f"{kind}:{indicator}"
    found, cached = _cache_get(_vt_cache, _vt_cache_lock, cache_key, ttl)
    if found:
        perf_diag.cache("virustotal", "cache_hit")
        return dict(cached)
    perf_diag.cache("virustotal", "cache_miss")

    try:
        resp = requests.get(f"{VT_URL}/{endpoint}/{indicator}",
                            headers={"x-apikey": api_key,
                                     "Accept": "application/json"},
                            timeout=1)

        if resp.status_code == 404:
            # NotFoundError — not in the VT corpus. A real answer:
            # "never submitted", which is UNKNOWN, not clean (the
            # interpretation note carries that distinction). Cached.
            perf_diag.cache("virustotal", "not_known")
            result = {"state": "not_known"}
            _cache_put(_vt_cache, _vt_cache_lock, cache_key, result,
                       _VT_MAX)
            return dict(result)

        if resp.status_code == 429:
            perf_diag.cache("virustotal", "rate_limited")
            if warn_on_429:
                logger.warning(
                    f"VirusTotal rate-limited (HTTP 429) - lookup "
                    f"skipped for {kind} {indicator}; record annotated "
                    f"RATE_LIMITED")
            return {"state": "RATE_LIMITED"}

        if resp.status_code == 401:
            perf_diag.cache("virustotal", "unauthorized")
            if not _vt_401_warned:
                _vt_401_warned = True
                logger.warning(
                    "VirusTotal API key rejected (HTTP 401) - lookups "
                    "unavailable until the key is fixed (warned once "
                    "per process)")
            # AUTH_FAILED is a first-class state (fail-loud, Kevin
            # 2026-07-16), NOT the generic unavailable {}: a rejected
            # key on a required-key source is a persistent
            # misconfiguration that would otherwise render as N/A —
            # indistinguishable from a transient timeout — silently
            # disabling the feature while the operator believes it's
            # on. The state flows to the record, the prompt block, and
            # (via gl2_llm_prompt full text) Graylog. Never cached, and
            # it degrades the whole-IP record (see _record_degraded) so
            # a fixed key takes effect immediately.
            return {"state": "AUTH_FAILED"}

        if resp.status_code != 200:
            perf_diag.cache("virustotal", "error")
            return {}

        body = resp.json()
        stats = (body.get("data", {}).get("attributes", {})
                 .get("last_analysis_stats"))
        if not isinstance(stats, dict) or not stats:
            # Husk guard: a 200 with an alien body is a failure, never
            # an answer.
            perf_diag.cache("virustotal", "error")
            return {}

        total = 0
        for v in stats.values():
            try:
                total += int(v)
            except (TypeError, ValueError):
                continue
        malicious  = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)

        if malicious or suspicious:
            perf_diag.cache("virustotal", "hit")
            result = {"state": "hit", "malicious": malicious,
                      "suspicious": suspicious, "total": total}
            label = (body.get("data", {}).get("attributes", {})
                     .get("popular_threat_classification", {})
                     .get("suggested_threat_label"))
            if isinstance(label, str) and label.strip():
                result["label"] = _truncate(label.strip(), 100)
        else:
            perf_diag.cache("virustotal", "clean")
            result = {"state": "clean", "malicious": 0,
                      "suspicious": 0, "total": total}
        _cache_put(_vt_cache, _vt_cache_lock, cache_key, result, _VT_MAX)
        return dict(result)
    except (requests.RequestException, ValueError):
        perf_diag.cache("virustotal", "error")
    # Transient failures are NOT cached — same rule as every sibling.
    return {}


OTX_URL = "https://otx.alienvault.com/api/v1"


def otx_lookup(indicator, kind, api_key, warn_on_429=False):
    """
    AlienVault OTX community-pulse lookup for one indicator
    (lookup endpoint only — no subscriptions, no feed sync).
    kind: "file" (md5/sha1/sha256) or "ip" (v4 or v6).

    Returns one of:
      {"state": "referenced", "pulses": N, "names": [up to 3],
       ["latest": "YYYY-MM-DD"], ["families": [...]],
       ["adversary": str]}              community pulses reference it
      {"state": "no_reports"}           pulse count 0 — covers BOTH
                                        unknown indicators and
                                        known-but-unreferenced
                                        (live-verified 2026-07-17: the
                                        API returns 200/count-0 for
                                        both and cannot distinguish
                                        them); a real answer, cached
      {"state": "RATE_LIMITED"}         429 — annotated, never cached
      {}                                unavailable (timeout / 5xx /
                                        husk)

    No AUTH_FAILED state and no key validation — deliberately, not an
    omission: key validity is UNOBSERVABLE on the indicator endpoint in
    both directions (live-verified 2026-07-17: valid key, bad key, and
    no key all return HTTP 200 with identical public data). The key's
    only function is the rate ceiling, and a mistyped key silently
    behaves as keyless; the interface hint sends the operator to
    otx.alienvault.com to verify. Keyless is a first-class mode
    (GreyNoise model): an empty key means lookups run unauthenticated
    at the lower public ceiling — never bail on a missing key.

    pulse count saturates at 50 (observed page cap) — stored numeric;
    the prompt renders 50 as "50+". Timeout 1s (0.57s observed keyed
    from the oob box). 429 handling is defensive (never observed live):
    call-and-annotate, no backoff, no retry, nothing ever waits on
    quota. Convoy-safe by construction — one cache lock with ns holds,
    HTTP outside the lock, no shared fetch, no waits.
    """
    if kind == "ip":
        ip_obj = _safe_ip(indicator)
        if ip_obj is None:
            perf_diag.cache("otx", "invalid")
            return {}
        ind_type = "IPv6" if ip_obj.version == 6 else "IPv4"
        ttl = _OTX_IP_TTL_S
    else:
        if not HASH_RE.fullmatch(indicator or ""):
            perf_diag.cache("otx", "invalid")
            return {}
        ind_type, ttl = "file", _OTX_HASH_TTL_S

    cache_key = f"{kind}:{indicator}"
    found, cached = _cache_get(_otx_cache, _otx_cache_lock, cache_key, ttl)
    if found:
        perf_diag.cache("otx", "cache_hit")
        return dict(cached)
    perf_diag.cache("otx", "cache_miss")

    headers = {"Accept": "application/json"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    try:
        resp = requests.get(
            f"{OTX_URL}/indicators/{ind_type}/{indicator}/general",
            headers=headers, timeout=1)

        if resp.status_code == 429:
            perf_diag.cache("otx", "rate_limited")
            if warn_on_429:
                logger.warning(
                    f"OTX rate-limited (HTTP 429) - lookup skipped for "
                    f"{kind} {indicator}; record annotated RATE_LIMITED")
            return {"state": "RATE_LIMITED"}

        if resp.status_code != 200:
            # No 404 branch: unknown indicators return 200 with pulse
            # count 0 (live-verified), so any non-200 here is a real
            # service failure, not an answer.
            perf_diag.cache("otx", "error")
            return {}

        body = resp.json()
        pulse_info = body.get("pulse_info") if isinstance(body, dict) \
            else None
        if not isinstance(pulse_info, dict):
            # Husk guard: a 200 with an alien body is a failure, never
            # "no_reports".
            perf_diag.cache("otx", "error")
            return {}

        try:
            count = int(pulse_info.get("count", 0))
        except (TypeError, ValueError):
            perf_diag.cache("otx", "error")
            return {}

        if count <= 0:
            perf_diag.cache("otx", "no_reports")
            result = {"state": "no_reports"}
            _cache_put(_otx_cache, _otx_cache_lock, cache_key, result,
                       _OTX_MAX)
            return dict(result)

        perf_diag.cache("otx", "referenced")
        pulses = pulse_info.get("pulses")
        pulses = pulses if isinstance(pulses, list) else []

        names, families, adversary, latest = [], [], None, None
        fam_seen = set()
        for p in pulses:
            if not isinstance(p, dict):
                continue
            name = p.get("name")
            if isinstance(name, str) and name.strip() and len(names) < 3:
                names.append(_truncate(name.strip(), 80))
            modified = p.get("modified")
            if isinstance(modified, str) and len(modified) >= 10:
                # ISO strings compare chronologically; keep the max so
                # "latest" is the most recent reference across ALL
                # returned pulses, not whichever happens to be first.
                if latest is None or modified > latest:
                    latest = modified
            for fam in (p.get("malware_families") or []):
                dn = fam.get("display_name") if isinstance(fam, dict) \
                    else None
                if isinstance(dn, str) and dn.strip() \
                        and dn not in fam_seen and len(families) < 3:
                    fam_seen.add(dn)
                    families.append(_truncate(dn.strip(), 60))
            adv = p.get("adversary")
            if adversary is None and isinstance(adv, str) and adv.strip():
                adversary = _truncate(adv.strip(), 60)

        result = {"state": "referenced", "pulses": count, "names": names}
        if latest:
            result["latest"] = latest[:10]
        if families:
            result["families"] = families
        if adversary:
            result["adversary"] = adversary
        _cache_put(_otx_cache, _otx_cache_lock, cache_key, result,
                   _OTX_MAX)
        return dict(result)
    except (requests.RequestException, ValueError):
        perf_diag.cache("otx", "error")
    # Transient failures are NOT cached — same rule as every sibling.
    return {}


# ---------------------------------------------------------------------------
# MITRE field extraction
# ---------------------------------------------------------------------------

def extract_mitre(alert):
    """
    Pull MITRE tactics, techniques, and IDs from an alert.

    Returns a dict with two representations of each field:
      - 'tactics' / 'techniques' / 'ids': comma-space joined ("A, B, C")
        for human-readable prompt context.
      - 'tactics_csv' / 'techniques_csv' / 'ids_csv': comma-only joined
        ("A,B,C") for Graylog field aggregation. Whitespace-padded values
        in Graylog break field-based aggregation and search.

    Both representations are produced from the same source data so they
    stay in sync.
    """
    from ingest import safe_get
    tactics    = safe_get(alert, "rule", "mitre", "tactic",    default=[])
    techniques = safe_get(alert, "rule", "mitre", "technique", default=[])
    mitre_ids  = safe_get(alert, "rule", "mitre", "id",        default=[])

    def _join_pretty(v):
        return ", ".join(v) if isinstance(v, list) else str(v)

    def _join_csv(v):
        return ",".join(v) if isinstance(v, list) else str(v)

    return {
        "tactics":        _join_pretty(tactics),
        "techniques":     _join_pretty(techniques),
        "ids":            _join_pretty(mitre_ids),
        "tactics_csv":    _join_csv(tactics),
        "techniques_csv": _join_csv(techniques),
        "ids_csv":        _join_csv(mitre_ids),
    }


# ---------------------------------------------------------------------------
# Master enrichment function
# ---------------------------------------------------------------------------

def enrich_alert(alert, config, hosts_data, roles_data=None):
    """
    Full enrichment pass for one alert.
    Returns an enrichment dict ready for prompt building and GELF shipping.

    roles_data (optional) is the loaded roles.json. When provided, the alert
    host's role(s) are resolved to their description/notes context for the
    prompt. Omitted/None → no role context (the feature degrades cleanly;
    existing deployments without roles.json behave exactly as before).
    """
    # Defensive entry guard: malformed input (None, non-dict) returns empty
    # enrichment rather than crashing. Should never happen in normal flow
    # since alerts come from JSON parsing, but cheap insurance against a
    # malformed line in the alert file taking down the worker.
    if not isinstance(alert, dict):
        logger.warning("enrich_alert called with non-dict input; returning empty enrichment")
        return {}

    from ingest import safe_get

    enrichment = {}

    # --- Canonical hostname resolution ---
    canonical_hostname, host_record = resolve_canonical_hostname(alert, hosts_data, config)
    enrichment["canonical_hostname"] = canonical_hostname

    agent_name = safe_get(alert, "agent", "name")
    agent_ip   = safe_get(alert, "agent", "ip")

    host_network = None
    if agent_ip != "N/A" and is_valid_ip(agent_ip):
        host_network = lookup_network(agent_ip, hosts_data)

    enrichment["agent_host"] = describe_host(host_record, host_network)

    # Role data: prefer an explicit roles_data argument (tests, one-shot
    # reprocessing); otherwise fall back to roles attached to hosts_data at
    # load time (the hot path, avoiding a new threaded argument). Either may
    # be absent — role context then degrades to empty.
    if roles_data is None and isinstance(hosts_data, dict):
        roles_data = hosts_data.get("_roles")

    # --- Role context for the alert host (primary host only) ---
    # Resolve the alert host's role(s) to their description/notes from
    # roles.json so the LLM sees "what's normal for this kind of host"
    # context. Only the alert's own host gets this (the host inventory stays
    # sparse). Blank-aware and degrades to [] when roles_data is absent.
    if roles_data:
        from ingest import build_role_lookup
        role_lookup = build_role_lookup(roles_data)
        enrichment["agent_role_context"] = role_context_lines(host_record, role_lookup)
    else:
        enrichment["agent_role_context"] = []

    # --- Dedup key: rule.id + canonical_hostname ---
    rule_id = safe_get(alert, "rule", "id", default="unknown")
    enrichment["dedup_key"] = f"{rule_id}|{canonical_hostname}"

    # --- IP extraction ---
    ips = extract_ips(alert)
    enrichment["ips"] = ips

    # --- Top-level aliases for rule-condition fields ---
    # These are the field names exposed in the docs and the web interface
    # condition builder (rules_instructions.txt → CONDITION REFERENCE).
    # They are flat aliases over the nested structures above, so users can
    # write {"field": "external_ips", "op": "exists"} without learning
    # dotted-path syntax. Keep this list in sync with the documented
    # AVAILABLE FIELDS table.
    enrichment["external_ips"] = ips.get("external", [])
    enrichment["internal_ips"] = ips.get("internal", [])
    enrichment["agent_name"]   = agent_name
    enrichment["network"]      = host_network.get("name") if host_network else None

    # --- Internal IP context - resolve each IP to hostname ---
    # Per-iteration try/except: a single bad IP that survived extract_ips
    # validation but breaks downstream resolution shouldn't kill the entire
    # alert's enrichment. Skip the bad IP, continue with the others.
    internal_context = []
    for ip in ips["internal"]:
        try:
            hostname, h = resolve_ip_hostname(ip, hosts_data)
            net = lookup_network(ip, hosts_data)
            internal_context.append({
                "ip":       ip,
                "hostname": hostname,
                "host":     describe_host(h, net) if h else f"{hostname} ({net['name'] if net else 'unknown segment'})",
                "network":  net,
                "notes":    h.get("notes", "") if h else "",
            })
        except Exception as e:
            logger.warning(f"Failed to resolve internal IP {ip}: {e}")
            continue
    enrichment["internal_context"] = internal_context

    # --- Hash-source gate (v1.1) ---
    # One extract_hashes pass feeds three consumers: the VT/OTX hash
    # sections below, and the mentioned-IP gate — mentioned externals
    # get VT/OTX lookups ONLY on hash-bearing alerts (locked
    # 2026-07-18: IP reputation on a regex-found IP earns its quota
    # only when it can corroborate hash intel on the same record).
    _vt_cfg_g  = config.get("enrichment", {}).get("virustotal", {})
    _otx_cfg_g = config.get("enrichment", {}).get("otx", {})
    vt_on   = _vt_cfg_g.get("enabled", False) and _vt_cfg_g.get("api_key")
    otx_on  = _otx_cfg_g.get("enabled", False)
    alert_hashes = extract_hashes(alert) if (vt_on or otx_on) else []
    mention_vt_otx = bool(alert_hashes)

    # --- External IP enrichment - cached to avoid duplicate lookups ---
    # Per-iteration try/except: same defensive logic as internal_context.
    # Network failures, malformed API responses, or unexpected errors on
    # one external IP shouldn't kill the alert's full enrichment.
    external_context = []
    for ip in ips["external"]:
        try:
            # Single .get() read — NOT membership-then-index, which
            # is two operations: clear_enrichment_cache() (main
            # thread, prune cadence) landing between them raised
            # KeyError and skipped this IP's enrichment for the
            # alert. One read is atomic under the GIL.
            ext = None
            with _ip_enrichment_cache_lock:
                ext = _ip_enrichment_cache.get(ip)
            if ext is not None:
                perf_diag.cache("external_ip", "cache_hit")
                logger.debug(f"External IP cache hit: {ip}")
                if _needs_vt_otx_upgrade(ext, config):
                    # Cached lite record (built for a hash-less
                    # mention) — party consumers always need the
                    # VT/OTX fields. Build-new-and-swap: never mutate
                    # the published record in place (FT safety).
                    ext = dict(ext)
                    ext.update(_vt_otx_ip_fields(ip, config))
                    if not _record_degraded(ext):
                        with _ip_enrichment_cache_lock:
                            _ip_enrichment_cache[ip] = ext
            else:
                perf_diag.cache("external_ip", "cache_miss")
                logger.info(f"Enriching external IP: {ip}")
                ext = enrich_external_ip(ip, config)
                if not _record_degraded(ext):
                    with _ip_enrichment_cache_lock:
                        _ip_enrichment_cache[ip] = ext
            external_context.append(ext)
        except Exception as e:
            logger.warning(f"Failed to enrich external IP {ip}: {e}")
            continue
    enrichment["external_context"] = external_context

    # --- Mentioned IP context ---
    # IPs found via regex scan of full_log. May or may not be parties
    # to the alert (e.g., DNS resolution log entries record IPs that
    # were merely looked up). Resolved lightly: private IPs get a
    # hostname lookup only (no notes — that's what makes this block
    # cheap on tokens); public IPs get external enrichment (AbuseIPDB,
    # GeoIP, etc.) since reputation signal on a mentioned external IP
    # may still be operationally relevant.
    # Capped at 10 entries downstream in prompt rendering to bound
    # prompt size against verbose DNS-server alerts that could
    # otherwise spray dozens of IPs into the block.
    mentioned_context = []
    for ip in ips["mentioned"]:
        try:
            if is_private(ip):
                # Lightweight resolution: hostname only, no host notes.
                # The point of this block is to flag mention without
                # pulling in page-sized hosts.json entries.
                hostname, h = resolve_ip_hostname(ip, hosts_data)
                net = lookup_network(ip, hosts_data)
                mentioned_context.append({
                    "ip":       ip,
                    "hostname": hostname,
                    "network":  net["name"] if net else None,
                    "external": False,
                })
            else:
                # External mentioned IP — full enrichment so reputation
                # signal is visible. Cached identically to external_context
                # so back-to-back hits on the same IP cost one lookup.
                # Same atomic .get() pattern as external_context
                # above (clear() race).
                ext = None
                with _ip_enrichment_cache_lock:
                    ext = _ip_enrichment_cache.get(ip)
                if ext is not None:
                    perf_diag.cache("external_ip", "cache_hit")
                    logger.debug(f"External IP cache hit: {ip}")
                    if mention_vt_otx and _needs_vt_otx_upgrade(ext, config):
                        # Hash-bearing alert needs VT/OTX on this
                        # mention but the cached record is lite —
                        # upgrade (build-new-and-swap).
                        ext = dict(ext)
                        ext.update(_vt_otx_ip_fields(ip, config))
                        if not _record_degraded(ext):
                            with _ip_enrichment_cache_lock:
                                _ip_enrichment_cache[ip] = ext
                else:
                    perf_diag.cache("external_ip", "cache_miss")
                    logger.info(f"Enriching mentioned external IP: {ip}")
                    ext = enrich_external_ip(ip, config,
                                             include_vt_otx=mention_vt_otx)
                    if not _record_degraded(ext):
                        with _ip_enrichment_cache_lock:
                            _ip_enrichment_cache[ip] = ext
                m_entry = {
                    "ip":          ip,
                    "external":    True,
                    "rdns":        ext.get("rdns", "N/A"),
                    "org":         ext.get("org", "N/A"),
                    "country":     ext.get("country", "N/A"),
                    "city":        ext.get("city", "N/A"),
                    "asn":         ext.get("asn", "N/A"),
                    "abuse_score": ext.get("abuse_score", "N/A"),
                    "greynoise_class": ext.get("greynoise_class", "N/A"),
                }
                if mention_vt_otx:
                    # Hash-bearing alert: VT/OTX ride the mention so
                    # IP reputation can corroborate the hash intel in
                    # the same record. Copied only when present.
                    for k in ("vt_state", "vt_malicious", "vt_total",
                              "vt_label", "otx_state", "otx_pulses"):
                        if k in ext:
                            m_entry[k] = ext[k]
                mentioned_context.append(m_entry)
        except Exception as e:
            logger.warning(f"Failed to resolve mentioned IP {ip}: {e}")
            continue
    enrichment["mentioned_context"] = mentioned_context

    # --- Mentioned-IP intel flat fields (v1.1) ---
    # The party/mentioned split is deliberate and stays: gl2_greynoise_
    # class and gl2_abuse_score describe IPs that are PARTIES to the
    # alert (structured fields), never regex finds — a DC alert whose
    # full_log contains a resolved malicious IP must not ship a
    # malicious class on the party fields. But v1.1 put verdict-grade
    # intel on the mentioned line, so mentioned results get their OWN
    # searchable fields, worst-of across all external mentions.
    # Both are present only when at least one mentioned external IP
    # produced a real answer (the gl2_epss_max presence pattern);
    # degraded (RATE_LIMITED) and N/A results contribute nothing.
    _GN_SEVERITY = {"malicious": 5, "unknown": 4, "not_seen": 3,
                    "benign": 2, "riot": 1}
    m_abuse = []
    m_worst = None
    for m in mentioned_context:
        if not m.get("external"):
            continue
        score = m.get("abuse_score")
        if isinstance(score, (int, float)):
            m_abuse.append(score)
        cls = m.get("greynoise_class")
        if cls in _GN_SEVERITY and (
                m_worst is None
                or _GN_SEVERITY[cls] > _GN_SEVERITY[m_worst]):
            m_worst = cls
    if m_abuse:
        enrichment["gl2_mentioned_abuse_max"] = max(m_abuse)
    if m_worst is not None:
        enrichment["gl2_mentioned_greynoise_worst"] = m_worst
    # VT/OTX mentioned worst-ofs exist only on hash-bearing alerts
    # (the gate above) — same numeric-when-present pattern: hit/clean
    # and referenced/no_reports are answers (clean/none contribute 0);
    # degraded contributes nothing.
    m_vt = [e.get("vt_malicious", 0) for e in mentioned_context
            if e.get("external") and e.get("vt_state") in ("hit", "clean")]
    if m_vt:
        enrichment["gl2_mentioned_vt_malicious"] = max(m_vt)
    m_otx = [e.get("otx_pulses", 0) for e in mentioned_context
             if e.get("external")
             and e.get("otx_state") in ("referenced", "no_reports")]
    if m_otx:
        enrichment["gl2_mentioned_otx_pulses"] = max(m_otx)

    # --- MITRE ---
    enrichment["mitre"] = extract_mitre(alert)

    # --- CISA KEV + EPSS (v1.1) ---
    # Both are CVE-keyed and share one extract_cves pass. Only when
    # enabled AND the alert actually carries CVEs. The no-CVE alert
    # (the overwhelmingly common case) produces no context, no gl2
    # fields, no fetches, no log lines - a true no-op.
    kev_cfg  = config.get("enrichment", {}).get("cisa_kev", {})
    epss_cfg = config.get("enrichment", {}).get("epss", {})
    kev_on   = kev_cfg.get("enabled", False)
    epss_on  = epss_cfg.get("enabled", False)
    cves = extract_cves(alert) if (kev_on or epss_on) else []
    if cves and kev_on:
        kev_state, kev_entries = kev_lookup(cves)
        enrichment["kev_context"] = kev_entries
        enrichment["kev_state"] = kev_state
        if kev_state == "ok":
            enrichment["gl2_kev_listed"] = (
                "true" if any(e["listed"] for e in kev_entries)
                else "false")
        else:
            # Degraded lookups annotate the state itself so a Graylog
            # search can find verdicts made without KEV context.
            enrichment["gl2_kev_listed"] = kev_state
    if cves and epss_on:
        epss_state, epss_entries = epss_lookup(cves)
        enrichment["epss_state"] = epss_state
        enrichment["epss_entries"] = epss_entries
        scored = [e["epss"] for e in epss_entries if e.get("scored")]
        if scored:
            # Numeric, present ONLY when at least one CVE scored
            # (locked D2): gl2_epss_max exists for range searches
            # (gl2_epss_max:>0.5), and shipping "N/A" strings into the
            # same field would break numeric typing in Elasticsearch.
            # Degraded/not-scored states are visible in the prompt and
            # in epss_state, not this field.
            enrichment["gl2_epss_max"] = max(scored)

    # --- VirusTotal + OTX hashes (v1.1) ---
    # Both are hash-keyed and share one extract_hashes pass (the
    # kev/epss shared-extract_cves precedent — zero extra extraction).
    # Structured-first extraction, one lookup per file state,
    # current-content states prioritized over previous-content. VT
    # runs under the per-alert cap (locked D1/D3 — bounds latency and
    # free-tier burn during FIM storms; over-cap states annotate
    # NOT_CHECKED, visible not silent). OTX needs no cap (limits are
    # orders of magnitude above our volume; extraction bounds FIM
    # lookups at <=2 anyway) and no key (keyless-at-lower-ceiling).
    # Each runs under its own config gate, independent of the other.
    # No-hash alerts are a true no-op for both.
    # vt_on / otx_on / alert_hashes hoisted above the context builds
    # (one extract_hashes pass feeds hash sections AND the
    # mentioned-IP gate).
    vt_cfg  = _vt_cfg_g
    otx_cfg = _otx_cfg_g
    if vt_on and alert_hashes:
        try:
            cap = max(1, int(vt_cfg.get("per_alert_cap", 4)))
        except (TypeError, ValueError):
            cap = 4
        warn429 = vt_cfg.get("rate_limit_warnings", False)
        vt_hashes = []
        spent = 0
        for digest, role in alert_hashes:
            if spent >= cap:
                vt_hashes.append({"hash": digest, "role": role,
                                  "state": "NOT_CHECKED"})
                continue
            r = vt_lookup(digest, "file", vt_cfg["api_key"],
                          warn_on_429=warn429)
            spent += 1
            entry = {"hash": digest, "role": role}
            if r.get("state"):
                entry.update(r)
            else:
                entry["state"] = "N/A"   # unavailable
            vt_hashes.append(entry)
        enrichment["vt_hashes"] = vt_hashes

    if otx_on and alert_hashes:
        warn429 = otx_cfg.get("rate_limit_warnings", False)
        otx_hashes = []
        for digest, role in alert_hashes:
            r = otx_lookup(digest, "file", otx_cfg.get("api_key", ""),
                          warn_on_429=warn429)
            entry = {"hash": digest, "role": role}
            if r.get("state"):
                entry.update(r)
            else:
                entry["state"] = "N/A"   # unavailable
            otx_hashes.append(entry)
        enrichment["otx_hashes"] = otx_hashes

    # gl2_vt_malicious: numeric max malicious count across every
    # indicator that returned engine counts — hashes AND external IPs,
    # hit AND clean (a checked-clean alert ships 0, distinguishing
    # "checked, clean" from unchecked/absent). Present only when
    # something returned counts (the gl2_epss_max pattern; range-
    # searchable gl2_vt_malicious:>5).
    vt_counts = [e["malicious"] for e in enrichment.get("vt_hashes", [])
                 if e.get("state") in ("hit", "clean")]
    for ext in external_context:
        if ext.get("vt_state") in ("hit", "clean"):
            vt_counts.append(ext.get("vt_malicious", 0))
    if vt_counts:
        enrichment["gl2_vt_malicious"] = max(vt_counts)

    # gl2_otx_pulses: numeric max community-pulse count across every
    # checked indicator — hashes AND external IPs. no_reports
    # contributes 0 (checked-and-unreferenced is an answer, the VT
    # checked-clean-zero precedent, so 0 distinguishes "checked, no
    # community reports" from unchecked/absent); degraded and
    # unavailable states contribute nothing. Present only when
    # something was checked (the gl2_epss_max pattern; range-
    # searchable gl2_otx_pulses:>0). Count saturates at 50 upstream —
    # the field stays numeric; the prompt renders "50+".
    otx_counts = [e.get("pulses", 0)
                  for e in enrichment.get("otx_hashes", [])
                  if e.get("state") in ("referenced", "no_reports")]
    for ext in external_context:
        if ext.get("otx_state") in ("referenced", "no_reports"):
            otx_counts.append(ext.get("otx_pulses", 0))
    if otx_counts:
        enrichment["gl2_otx_pulses"] = max(otx_counts)

    # --- Wazuh timing fields - for storm duration in prompt ---
    # Storm tracking: read from the dedup cache if a previous occurrence
    # of this dedup_key is being tracked. This makes wazuh_first_seen
    # reflect the storm's actual start (when the silence window opened),
    # not the timestamp of whichever alert in the storm happens to be
    # passing through enrich_alert right now. wazuh_last_seen reflects
    # the most-recent occurrence including duplicates that were
    # suppressed — so the prompt's "Alert trail" line can show storm
    # duration accurately. Falls back to the alert's own timestamp on
    # a fresh dedup_key (cache miss = first occurrence in current window).
    # TIMING NOTE: this read happens BEFORE main.py's is_duplicate()
    # call (enrichment creates the dedup_key the check needs). For the
    # first alert after a silence-window expiry, the cache still holds
    # the EXPIRED window's timing here — main.py corrects these two
    # fields immediately after is_duplicate() returns False (fresh
    # window confirmed), so the prompt and GELF ship see fresh values.
    # The pre-dedup DB record retains the uncorrected read; v1.1 may
    # move window-timing ownership out of enrichment entirely.
    from dedup import get_last_seen
    alert_ts = safe_get(alert, "timestamp")
    cache_entry = get_last_seen(enrichment["dedup_key"])
    if cache_entry is not None:
        # Convert epoch floats from cache back to ISO strings to match
        # the existing schema. Other consumers (gelf_shipper, prompt
        # builder) read these as strings.
        first_epoch, last_epoch = cache_entry
        from datetime import datetime, timezone
        enrichment["wazuh_first_seen"] = datetime.fromtimestamp(
            first_epoch, tz=timezone.utc
        ).isoformat()
        enrichment["wazuh_last_seen"] = datetime.fromtimestamp(
            last_epoch, tz=timezone.utc
        ).isoformat()
    else:
        # Fresh dedup_key — alert's own timestamp serves as both
        # first_seen and last_seen until is_duplicate populates the cache.
        enrichment["wazuh_first_seen"] = alert_ts
        enrichment["wazuh_last_seen"] = alert_ts
    enrichment["wazuh_fired_times"] = safe_get(alert, "rule", "firedtimes", default=1)

    # --- Flat dashboard fields (for GELF) ---
    enrichment["gl2_rule_level"]     = safe_get(alert, "rule", "level", default=0)
    enrichment["gl2_rule_id"]        = safe_get(alert, "rule", "id")
    enrichment["gl2_agent_name"]     = agent_name
    enrichment["gl2_mitre_tactics"]  = enrichment["mitre"]["tactics_csv"]
    enrichment["gl2_mitre_techniques"] = enrichment["mitre"]["techniques_csv"]
    enrichment["gl2_mitre_ids"]      = enrichment["mitre"]["ids_csv"]

    if external_context:
        first_ext = external_context[0]
        enrichment["gl2_src_country"]  = first_ext.get("country", "N/A")
        enrichment["gl2_src_country_code"] = first_ext.get("country_code", "N/A")
        enrichment["gl2_src_org"]      = first_ext.get("org", "N/A")
        enrichment["gl2_src_asn"]      = first_ext.get("asn", "N/A")
        enrichment["gl2_src_rdns"]     = first_ext.get("rdns", "N/A")
        enrichment["gl2_abuse_score"]  = first_ext.get("abuse_score", "N/A")
        enrichment["gl2_greynoise_class"] = first_ext.get("greynoise_class", "N/A")
    else:
        enrichment["gl2_src_country"]      = "N/A"
        enrichment["gl2_src_country_code"] = "N/A"
        enrichment["gl2_src_org"]          = "N/A"
        enrichment["gl2_src_asn"]          = "N/A"
        enrichment["gl2_src_rdns"]         = "N/A"
        enrichment["gl2_abuse_score"]      = "N/A"
        enrichment["gl2_greynoise_class"]  = "N/A"

    return enrichment


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    from ingest import load_config, load_hosts, read_new_alerts, safe_get

    print("=== jrSOCtriage Enrichment Smoke Test ===\n")

    config     = load_config("config.json")
    hosts_data = load_hosts(config)

    alerts = list(read_new_alerts(config))
    print(f"Loaded {len(alerts)} alert(s) for enrichment test\n")

    for i, alert in enumerate(alerts[:3], 1):
        print(f"--- Alert {i} ---")
        print(f"  Rule       : [{safe_get(alert,'rule','level')}] {safe_get(alert,'rule','description')}")
        print(f"  Agent      : {safe_get(alert,'agent','name')} ({safe_get(alert,'agent','ip')})")

        enrichment = enrich_alert(alert, config, hosts_data)

        print(f"  Canonical  : {enrichment['canonical_hostname']}")
        print(f"  Dedup key  : {enrichment['dedup_key']}")
        print(f"  Host desc  : {enrichment['agent_host']}")
        print(f"  IPs found  : internal={enrichment['ips']['internal']}  external={enrichment['ips']['external']}  mentioned={enrichment['ips']['mentioned']}")
        print(f"  MITRE      : {enrichment['mitre']['tactics']}")
        print(f"  gl2_src_country : {enrichment['gl2_src_country']}")

        for ctx in enrichment["internal_context"]:
            print(f"  Internal   : {ctx['ip']} -> {ctx['hostname']} | {ctx['host']}")

        if enrichment["external_context"]:
            for ext in enrichment["external_context"]:
                print(f"  External IP : {ext}")

        for ctx in enrichment.get("mentioned_context", []):
            kind = "EXTERNAL" if ctx.get("external") else "internal"
            print(f"  Mentioned  : {ctx['ip']} ({kind})")

        print()

    print("=== Done ===")
