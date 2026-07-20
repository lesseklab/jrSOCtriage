#!/usr/bin/env python3
"""
jrSOCtriage - ntopng Fetcher Module
Queries ntopng REST API for host flow data.
Only called when IPs are present in the alert.

API VERSION ASSUMPTION: the REST v2 endpoints (/lua/rest/v2/get/...), the
cookie+basic auth login returning HTTP 302, and the response field names
(score.as_client, total_flows.as_server, num_blacklisted_flows, ndpi block,
etc.) are matched to the ntopng version currently deployed. A future ntopng
upgrade (e.g. when moving to a newer base OS) could rename fields or change
endpoint paths, which would silently degrade enrichment (fields default to 0
/ "" rather than erroring). Re-verify field extraction against a live host
after any ntopng upgrade.
"""

import logging
import time
import requests

try:
    import perf_diag
except ModuleNotFoundError:
    # perf_diag is an optional internal diagnostic counter module and is not
    # part of the distributed package. Its absence must never stop the
    # pipeline, so fall back to a no-op stub with the same call surface.
    # Stateless by design: safe under free-threading, no locks, no allocation
    # on the per-alert path.
    class _PerfDiagStub:
        @staticmethod
        def configure(_config=None):
            return False

        @staticmethod
        def enabled():
            return False

        @staticmethod
        def count(_name, _n=1):
            pass

        @staticmethod
        def cache(_name, _outcome, _n=1):
            pass

        @staticmethod
        def observe(_name, _value):
            pass

        @staticmethod
        def stage_enter(_name):
            return 0.0

        @staticmethod
        def stage_exit(_name, _start=None):
            pass

        @staticmethod
        def snapshot_and_reset():
            return {}

        @staticmethod
        def log_summary(_logger):
            pass

    perf_diag = _PerfDiagStub()

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ntopng session - cookie based auth
# ---------------------------------------------------------------------------

class NtopngSession:
    """
    Manages a logged-in ntopng session via cookie auth.
    Reuses the session across multiple calls.
    """

    def __init__(self, config):
        ntop_cfg        = config.get("sources", {}).get("ntopng", {})
        self.endpoint   = ntop_cfg.get("endpoint", "").rstrip("/")
        self.username   = ntop_cfg.get("auth", {}).get("username", "admin")
        self.password   = ntop_cfg.get("auth", {}).get("password", "")
        self.ifid       = ntop_cfg.get("ifid", 2)
        self.enabled    = ntop_cfg.get("enabled", False)
        # TLS verification toggle. Default True. Set to False for self-signed
        # reverse-proxy deployments. Matches the pattern used in graylog_fetch.
        self.verify_ssl = ntop_cfg.get("verify_ssl", True)
        self.session    = requests.Session()
        # Pool sized for the worker count. The default HTTPAdapter
        # (pool_maxsize=10) under 40 workers caused constant connection
        # churn — connections 11..40 were created, used once, and
        # discarded ("Connection pool is full, discarding connection",
        # counter in the hundreds during the 2026-06-11 LOAC runs).
        _adapter = requests.adapters.HTTPAdapter(
            pool_connections=4, pool_maxsize=64)
        self.session.mount("http://", _adapter)
        self.session.mount("https://", _adapter)
        self._logged_in = False

    def login(self):
        """Authenticate and store session cookie."""
        if not self.enabled or not self.endpoint:
            return False

        # Security hint: plaintext HTTP means credentials and API responses
        # travel unencrypted. Fine for a trusted home-lab segment, a real
        # concern in any other environment. Warn once at login so the
        # operator sees it.
        if self.endpoint.startswith("http://"):
            logger.warning(
                "ntopng endpoint is http:// — credentials and API responses "
                "will be sent in cleartext. Put ntopng behind a TLS reverse "
                "proxy or enable ntopng's HTTPS Client Authentication for "
                "any non-lab deployment."
            )

        try:
            resp = self.session.post(
                f"{self.endpoint}/authorize.html",
                data={"user": self.username, "password": self.password},
                timeout=5,
                allow_redirects=False,
                verify=self.verify_ssl,
            )
            if resp.status_code == 302:
                self._logged_in = True
                logger.info("ntopng login successful")
                return True
            logger.error(f"ntopng login failed: HTTP {resp.status_code}")
            return False
        except requests.RequestException as e:
            logger.error(f"ntopng login error: {e}")
            return False

    def get(self, path, params=None):
        """Make an authenticated GET request using basic auth."""
        try:
            resp = self.session.get(
                f"{self.endpoint}{path}",
                params=params,
                auth=(self.username, self.password),
                timeout=10,
                verify=self.verify_ssl,
            )
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError:
                    logger.error(f"ntopng non-JSON response for {path}: {resp.text[:200]}")
                    return None
            logger.warning(f"ntopng GET {path} returned {resp.status_code}")
            return None
        except requests.RequestException as e:
            logger.error(f"ntopng request error: {e}")
            return None

    def is_logged_in(self):
        """Return True if the session has completed a successful login."""
        return self._logged_in


# ---------------------------------------------------------------------------
# Host data fetch
# ---------------------------------------------------------------------------

def fetch_host_data(session, ip_str, ifid):
    """
    Fetch ntopng host data for a single IP.
    Returns dict of key metrics or None.
    """
    data = session.get(
        "/lua/rest/v2/get/host/data.lua",
        params={"host": ip_str, "ifid": ifid}
    )

    if not data or data.get("rc") != 0:
        logger.debug(f"ntopng: no data for {ip_str}")
        return None

    rsp = data.get("rsp", {})
    if not rsp:
        return None

    # Extract the fields most useful for LLM triage context
    result = {
        "ip":                    ip_str,
        "score":                 rsp.get("score", 0),
        "score_as_client":       rsp.get("score.as_client", 0),
        "score_as_server":       rsp.get("score.as_server", 0),
        "bytes_sent":            rsp.get("bytes.sent", 0),
        "bytes_rcvd":            rsp.get("bytes.rcvd", 0),
        "throughput_bps":        round(rsp.get("throughput_bps", 0), 2),
        "total_flows_as_client": rsp.get("total_flows.as_client", 0),
        "total_flows_as_server": rsp.get("total_flows.as_server", 0),
        "alerted_flows_client":  rsp.get("alerted_flows.as_client", 0),
        "alerted_flows_server":  rsp.get("alerted_flows.as_server", 0),
        "active_alerted_flows":  rsp.get("active_alerted_flows", 0),
        # KNOWN LIMITATION (documented, not fixed): this counts only the
        # client-side blacklisted-flow total. A host blacklisted as a SERVER
        # (inbound flows from blacklisted IPs) is not reflected here. The
        # ntopng blacklisted-flow path is unexercised in the reference
        # deployment (only Suricata blacklists have been observed in alerts,
        # not ntopng's), and whether this (older) ntopng version's
        # num_blacklisted_flows even exposes a tot_as_server sibling is
        # unverified — so the client-only read is left as-is rather than
        # referencing a field that may not exist. Also note: the {} default
        # only applies if the key is MISSING; an explicit null would raise on
        # .get() (caught upstream by main's broad except -> ntopng skipped for
        # that alert). Revisit if/when ntopng blacklisted flows are seen live.
        "blacklisted_flows":     rsp.get("num_blacklisted_flows", {}).get("tot_as_client", 0),
        "is_blacklisted":        rsp.get("is_blacklisted", False),
        "country":               rsp.get("country", ""),
        "os_detail":             rsp.get("os_detail", ""),
        "duration_seen":         rsp.get("duration", 0),
    }

    # Top protocols from ndpi block
    ndpi = rsp.get("ndpi", {})
    if ndpi:
        # Sort by bytes sent, take top 5
        top_protos = sorted(
            ndpi.items(),
            key=lambda x: x[1].get("bytes.sent", 0) + x[1].get("bytes.rcvd", 0),
            reverse=True
        )[:5]
        result["top_protocols"] = [
            {
                "protocol":   proto,
                "flows":      proto_data.get("num_flows", 0),
                "bytes_sent": proto_data.get("bytes.sent", 0),
                "bytes_rcvd": proto_data.get("bytes.rcvd", 0),
                "breed":      proto_data.get("breed", ""),
            }
            for proto, proto_data in top_protos
        ]
    else:
        result["top_protocols"] = []

    return result


# ---------------------------------------------------------------------------
# Active flow fetch
# ---------------------------------------------------------------------------

def fetch_active_flows(session, ip_str, ifid, max_flows=10):
    """
    Fetch currently active flows for a specific IP from ntopng.
    Returns list of flow dicts or empty list.
    Note: These are CURRENT flows, not historical. Useful for real-time
    or near-real-time alerts only.
    """
    data = session.get(
        "/lua/rest/v2/get/flow/active.lua",
        params={"host": ip_str, "ifid": ifid}
    )

    if not data or data.get("rc") != 0:
        return []

    flows = data.get("rsp", {}).get("data", [])
    results = []

    for flow in flows[:max_flows]:
        client = flow.get("client", {})
        server = flow.get("server", {})
        proto  = flow.get("protocol", {})

        results.append({
            "client_ip":   client.get("ip", "?"),
            "client_port": client.get("port", "?"),
            "server_ip":   server.get("ip", "?"),
            "server_port": server.get("port", "?"),
            "l4":          proto.get("l4", "?"),
            "l7":          proto.get("l7", "?"),
            "bytes":       flow.get("bytes", 0),
            "duration":    flow.get("duration", 0),
            "first_seen":  flow.get("first_seen", 0),
            "last_seen":   flow.get("last_seen", 0),
        })

    return results


# ---------------------------------------------------------------------------
# Master ntopng fetch
# ---------------------------------------------------------------------------

def _should_skip_ntopng_lookup(ip_str, skip_networks):
    """
    Decide whether to skip ntopng lookup for this IP.

    ntopng tracks traffic seen on the SPAN/mirror interface. Some IPs
    will never have meaningful data because they're host-internal or
    not routable on the wire:
      - Loopback (127.0.0.0/8, ::1) — local-only, never on SPAN
      - Link-local (169.254.0.0/16, fe80::/10) — APIPA / IPv6 LL,
        rarely SPAN-visible
      - Docker bridge gateways (e.g. 172.17.0.1) — exist only inside
        the Docker host's network namespace
      - Any operator-defined host-private ranges

    Querying these addresses produces 404s from ntopng, which clutter
    logs and waste API round-trips. This filter skips them up front.

    The default skip list covers loopback and link-local. Operators
    with Docker hosts, VPN gateways, or other host-private addresses
    can extend the list via sources.ntopng.skip_networks in config.
    """
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Malformed IP — let the actual lookup fail naturally so the
        # error path is still exercised for genuinely-bad input.
        return False

    # Built-in skips: IPs that never have ntopng host data. This mirrors
    # the IP gating on the enrich/AbuseIPDB path (enrich.py — the SSDP
    # quota-burn hardening): multicast (224.0.0.0/4, e.g. 239.255.255.250
    # SSDP / 224.0.0.251 mDNS), unspecified (0.0.0.0, ::), and reserved
    # (which covers the 255.255.255.255 limited broadcast) are not hosts,
    # so ntopng will never have data for them and a query is a wasted
    # login+lookup round-trip. is_link_local is also skipped here (rarely
    # SPAN-visible); the enrich path does not gate it, but for ntopng's
    # SPAN-visibility context skipping it is correct.
    if (ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_unspecified or ip.is_reserved):
        return True

    # Operator-defined skip ranges (config-driven)
    for cidr in skip_networks:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            # Malformed CIDR in config — log once, ignore
            logger.warning(f"Invalid skip_networks entry in config: {cidr!r}")
            continue

    return False



# ---------------------------------------------------------------------------
# Per-IP result cache
#
# ntopng host/flow endpoints return CURRENT state ("now"), not a window
# around the alert time — so for any alert processed late, the data never
# matched the alert's moment anyway. Caching the now-snapshot per
# (endpoint, ifid, ip) for a short TTL therefore loses nothing
# semantically and gains two things: clone alerts of one source host stop
# hammering ntopng with identical requests (the dominant traffic pattern
# under alert storms), and all clones of a burst see the SAME snapshot
# instead of 40 workers each grabbing slightly different "nows".
# Negative results ("no data": external IPs, docker bridges) are cached
# too — those 404s repeat constantly and are the cheapest wins.
# TTL configurable via sources.ntopng.cache_ttl_seconds (default 30).
# ---------------------------------------------------------------------------
import threading as _threading
from collections import OrderedDict

_ntop_cache = OrderedDict()
_ntop_cache_lock = _threading.Lock()
_NTOP_CACHE_TTL_DEFAULT_S = 30
_NTOP_CACHE_MAX = 1024
_ntop_cache_ttl = _NTOP_CACHE_TTL_DEFAULT_S

def _ntop_cache_get(key):
    now = time.time()
    with _ntop_cache_lock:
        hit = _ntop_cache.get(key)
        if hit and now - hit[0] < _ntop_cache_ttl:
            return True, hit[1]
    return False, None

def _ntop_cache_put(key, value):
    with _ntop_cache_lock:
        # REG-21: O(1) evict-oldest (was O(n) min(key=timestamp) scan under
        # _ntop_cache_lock on every put). Same fix/validity as zeek REG-20 /
        # graylog REG-19 / enrich REG-10..13: _ntop_cache_get never refreshes an
        # entry's timestamp on a hit, so insertion order == age order and
        # popitem(last=False) evicts the true oldest. Evict only on a genuinely
        # new key; move_to_end on insert keeps position == newest-timestamp for
        # the expiry-refresh case (re-put of an existing key with a fresh
        # time.time()). Note: ntopng caches NEGATIVE results (value=None for
        # no-data IPs) — eviction is purely timestamp-based and value-agnostic,
        # so negative entries age out exactly like positive ones.
        if len(_ntop_cache) >= _NTOP_CACHE_MAX and key not in _ntop_cache:
            _ntop_cache.popitem(last=False)
        _ntop_cache[key] = (time.time(), value)
        _ntop_cache.move_to_end(key)


def fetch_ntopng_flows(config, alert_ips, ntopng_session=None):
    """
    Main entry point. Fetches ntopng host data for all IPs in alert_ips.
    Accepts an optional pre-authenticated NtopngSession for reuse.

    IPs that match the skip filter (loopback, link-local, configured
    host-private ranges) are filtered out before querying — see
    _should_skip_ntopng_lookup for details.

    Returns list of host data dicts, one per IP found.
    Only call this when alert_ips is non-empty.
    """
    ntop_cfg = config.get("sources", {}).get("ntopng", {})

    if not ntop_cfg.get("enabled", False):
        perf_diag.cache("ntopng", "disabled")
        logger.debug("ntopng source disabled in config")
        return []

    if not alert_ips:
        return []

    # Filter out IPs that ntopng will never have data for. Skipped IPs
    # are logged at DEBUG so troubleshooters can verify the filter is
    # behaving but normal logs stay quiet.
    skip_networks = ntop_cfg.get("skip_networks", [])
    queryable_ips = []
    for ip in alert_ips:
        if _should_skip_ntopng_lookup(ip, skip_networks):
            perf_diag.cache("ntopng", "skip")
            logger.debug(f"Skipping ntopng lookup for {ip} (host-private or non-routable)")
        else:
            queryable_ips.append(ip)

    if not queryable_ips:
        # All IPs were skipped — nothing to query.
        return []

    # Use provided session or create and login a new one
    if ntopng_session and ntopng_session.is_logged_in():
        session = ntopng_session
    else:
        session = NtopngSession(config)
        if not session.login():
            return []

    ifid = ntop_cfg.get("ifid", 2)
    global _ntop_cache_ttl
    try:
        _ntop_cache_ttl = float(ntop_cfg.get(
            "cache_ttl_seconds", _NTOP_CACHE_TTL_DEFAULT_S))
    except (TypeError, ValueError):
        _ntop_cache_ttl = _NTOP_CACHE_TTL_DEFAULT_S
    results = []

    for ip in queryable_ips:
        _ckey = (ifid, ip)
        _found, _cached = _ntop_cache_get(_ckey)
        if _found:
            perf_diag.cache("ntopng", "cache_hit")
            logger.debug(f"ntopng cache hit for {ip}")
            if _cached is not None:
                perf_diag.cache("ntopng", "lookup_hit")
                results.append(dict(_cached))
            else:
                perf_diag.cache("ntopng", "lookup_miss")
            continue
        perf_diag.cache("ntopng", "cache_miss")
        perf_diag.cache("ntopng", "real_query")
        logger.debug(f"Fetching ntopng data for {ip}")
        host_data = fetch_host_data(session, ip, ifid)
        if host_data:
            perf_diag.cache("ntopng", "lookup_hit")
            # Also fetch active flows for this IP
            active_flows = fetch_active_flows(session, ip, ifid)
            host_data["active_flows"] = active_flows
            _ntop_cache_put(_ckey, host_data)
            results.append(dict(host_data))
        else:
            perf_diag.cache("ntopng", "lookup_miss")
            # Negative cache: "no data" repeats constantly for external
            # IPs and docker bridges — skip re-querying for the TTL.
            _ntop_cache_put(_ckey, None)

    logger.debug(f"ntopng returned data for {len(results)}/{len(queryable_ips)} IP(s)")
    return results


# ---------------------------------------------------------------------------
# Format for prompt
# ---------------------------------------------------------------------------

def format_ntopng_for_prompt(ntopng_results):
    """
    Format ntopng host data into a readable block for the LLM prompt.
    Returns string or None if no data.
    """
    if not ntopng_results:
        return None

    lines = []
    for host in ntopng_results:
        ip = host.get("ip", "?")
        lines.append(f"HOST: {ip}")
        lines.append(
            f"  Score: {host['score']} "
            f"(client={host['score_as_client']} server={host['score_as_server']})"
        )
        lines.append(
            f"  Traffic: sent={_human_bytes(host['bytes_sent'])} "
            f"rcvd={_human_bytes(host['bytes_rcvd'])} "
            f"throughput={host['throughput_bps']}bps"
        )
        lines.append(
            f"  Flows: client={host['total_flows_as_client']} "
            f"server={host['total_flows_as_server']}"
        )
        if host["alerted_flows_client"] or host["alerted_flows_server"]:
            lines.append(
                f"  ALERTED flows: client={host['alerted_flows_client']} "
                f"server={host['alerted_flows_server']} "
                f"active={host['active_alerted_flows']}"
            )
        if host["blacklisted_flows"]:
            lines.append(f"  BLACKLISTED flows: {host['blacklisted_flows']}")
        if host["is_blacklisted"]:
            lines.append(f"  ** HOST IS BLACKLISTED **")
        if host["top_protocols"]:
            proto_str = ", ".join(
                f"{p['protocol']}({p['flows']}flows)" 
                for p in host["top_protocols"]
            )
            lines.append(f"  Top protocols: {proto_str}")

        # Active flows - note these are current, not historical
        active = host.get("active_flows", [])
        if active:
            lines.append(f"  Active flows (ntopng state at triage time, typically within ~1-3 min of alert; alert pattern often still active — L7 labels reflect destination service, not source intent):")
            for f in active:
                duration = f"{f['duration']}s" if f['duration'] else "<1s"
                lines.append(
                    f"    {f['client_ip']}:{f['client_port']} -> "
                    f"{f['server_ip']}:{f['server_port']} | "
                    f"{f['l4']}/{f['l7']} | "
                    f"{_human_bytes(f['bytes'])} | {duration}"
                )

    return "\n".join(lines)


def _human_bytes(b):
    """Convert bytes to human readable string."""
    try:
        b = int(b)
    except (ValueError, TypeError):
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b}{unit}"
        b //= 1024
    return f"{b}TB"


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    from ingest import load_config, load_hosts, read_new_alerts, safe_get
    from enrich import extract_ips

    print("=== jrSOCtriage ntopng Fetcher Smoke Test ===\n")

    config     = load_config("config.json")
    hosts_data = load_hosts(config)

    ntop_cfg = config.get("sources", {}).get("ntopng", {})
    print(f"ntopng endpoint : {ntop_cfg.get('endpoint')}")
    print(f"Enabled         : {ntop_cfg.get('enabled', False)}\n")

    # Test login - create ONE session and reuse it everywhere
    session = NtopngSession(config)
    if not session.login():
        print("[FAIL] Could not login to ntopng")
        exit(1)
    print("[OK] ntopng login successful")

    # Discover ifid using the logged-in session
    iface_data = session.get("/lua/rest/v2/get/ntopng/interfaces.lua")
    if iface_data and iface_data.get("rc") == 0:
        ifid = iface_data["rsp"][0]["ifid"]
        print(f"[OK] Interface: {iface_data['rsp'][0]['ifname']} ifid={ifid}\n")
    else:
        print(f"[WARN] Could not discover ifid, using config default\n")

    # Test with a known host from the screenshot
    test_ips = ["192.168.10.50", "192.168.10.103"]
    print(f"Testing with known hosts: {test_ips}\n")

    results = fetch_ntopng_flows(config, test_ips, ntopng_session=session)
    formatted = format_ntopng_for_prompt(results)

    if formatted:
        print(formatted)
    else:
        print("No ntopng data returned")

    # Also test with alerts that have IPs
    # Also test with alerts that have IPs.
    # KNOWN BUG (documented, not fixed): read_new_alerts() below advances the
    # SHARED .ingest_position file, so running this alert-based section against
    # a LIVE pipeline causes the pipeline to skip the alerts consumed here.
    # Run this smoke test with the pipeline stopped, or on the test platform.
    # Hard to decouple cleanly: unlike the email smoke test (which only needed
    # a synthetic alert), this section's whole point is exercising IP
    # extraction + ntopng lookup against REAL alert IPs. The synthetic-IP test
    # above (test_ips) already covers ntopng connectivity without touching the
    # stream, so that part is safe to run anytime.
    print("\n--- Alert-based test ---")
    alerts = list(read_new_alerts(config))
    print(f"Loaded {len(alerts)} alert(s)\n")

    tested = 0
    for alert in alerts:
        ips = extract_ips(alert)
        if not ips["all"]:
            continue

        agent_name = safe_get(alert, "agent", "name")
        print(f"Agent: {agent_name} | IPs: {ips['all']}")

        results = fetch_ntopng_flows(config, ips["all"], ntopng_session=session)
        formatted = format_ntopng_for_prompt(results)

        if formatted:
            print(formatted)
        else:
            print("  No ntopng data for these IPs")

        print()
        tested += 1
        if tested >= 3:
            break

    print("=== Done ===")
