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


def enrich_external_ip(ip_str, config):
    """
    Run all external enrichment for one IP.
    Returns a dict of everything we found.
    """
    enrichment_cfg = config.get("enrichment", {})
    abuseipdb_cfg  = enrichment_cfg.get("abuseipdb", {})

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
        result["abuse_score"]   = abuse.get("abuse_score", "N/A")
        result["total_reports"] = abuse.get("total_reports", "N/A")

    return result


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
            else:
                perf_diag.cache("external_ip", "cache_miss")
                logger.info(f"Enriching external IP: {ip}")
                ext = enrich_external_ip(ip, config)
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
                else:
                    perf_diag.cache("external_ip", "cache_miss")
                    logger.info(f"Enriching mentioned external IP: {ip}")
                    ext = enrich_external_ip(ip, config)
                    with _ip_enrichment_cache_lock:
                        _ip_enrichment_cache[ip] = ext
                mentioned_context.append({
                    "ip":          ip,
                    "external":    True,
                    "rdns":        ext.get("rdns", "N/A"),
                    "org":         ext.get("org", "N/A"),
                    "country":     ext.get("country", "N/A"),
                    "city":        ext.get("city", "N/A"),
                    "asn":         ext.get("asn", "N/A"),
                    "abuse_score": ext.get("abuse_score", "N/A"),
                })
        except Exception as e:
            logger.warning(f"Failed to resolve mentioned IP {ip}: {e}")
            continue
    enrichment["mentioned_context"] = mentioned_context

    # --- MITRE ---
    enrichment["mitre"] = extract_mitre(alert)

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
    else:
        enrichment["gl2_src_country"]      = "N/A"
        enrichment["gl2_src_country_code"] = "N/A"
        enrichment["gl2_src_org"]          = "N/A"
        enrichment["gl2_src_asn"]          = "N/A"
        enrichment["gl2_src_rdns"]         = "N/A"
        enrichment["gl2_abuse_score"]      = "N/A"

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
