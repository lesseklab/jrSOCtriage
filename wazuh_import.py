#!/usr/bin/env python3
"""
jrSOCtriage - Wazuh Agent Import Module

The ONLY place in jrSOCtriage that speaks the Wazuh management API. It pulls
the agent list (GET /agents) so the operator can onboard hosts into hosts.json
without hand-typing host blocks, and verifies each agent's name and IP against
DNS before importing — because the Wazuh record may be incorrect and DNS is the
source of truth for host identity (see the project's host-identity principle:
DNS PTR -> hosts.json name match -> Wazuh agent.name fallback).

Design boundaries (deliberate, firm):
  - This module is self-contained. interface.py calls it; NOTHING else does.
    The triage pipeline reads Wazuh *alerts* off disk/journal — a completely
    different coupling than the Wazuh *management API* this module uses — so
    keeping the API client isolated means the hot path never grows an API
    dependency.
  - All Wazuh-API specifics (auth, endpoint, response shape, version quirks)
    live behind the function surface below. If the Wazuh API changes, this is
    the one file to fix.
  - Errors are RETURNED, not raised, so the UI can show a clean message
    ("couldn't connect", "invalid credentials") instead of a 500.

Config (top-level `wazuh_api` block in config.json):
    url         e.g. "https://192.168.30.4:55000"
    username    Wazuh API user (NOT the dashboard login — default Docker
                stack API user is "wazuh-wui")
    password    that user's password
    dns_server  optional resolver for verification lookups; blank = system DNS
    verify_ssl  bool; uncheck for self-signed certs (Wazuh API is HTTPS by
                default with a self-signed cert)

Public surface:
    fetch_agents(cfg)        -> (agents, error)  raw parsed agent list
    verify_agents(agents, hosts, cfg)
                             -> (buckets, error)  agents classified vs DNS+hosts
    import_preview(cfg, hosts)
                             -> (result, error)  one-call: fetch + verify

`error` is None on success or a short human-readable string on failure.
"""

import logging
import ipaddress

import requests
from requests.auth import HTTPBasicAuth
import urllib3

import dns.resolver
import dns.reversename
import dns.exception

logger = logging.getLogger(__name__)

# The Wazuh API is HTTPS with a self-signed cert by default; when the operator
# turns Verify SSL off we pass verify=False to requests, which otherwise spams
# InsecureRequestWarning. Suppress just that warning class (the operator made
# an informed choice via the toggle); all other warnings pass through.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Network timeouts (seconds). The import is an interactive operator action, not
# a hot path, so these are generous but bounded — a hung Wazuh API should fail
# the import with a message, not hang the UI forever.
_AUTH_TIMEOUT_S = 15
_FETCH_TIMEOUT_S = 30
_DNS_TIMEOUT_S = 5

# GET /agents page size. The dashboard uses 500; that covers any realistic
# single deployment in one request. We still paginate if total exceeds it so
# a large corp network (thousands of agents) is handled correctly.
_PAGE_LIMIT = 500


# ---------------------------------------------------------------------------
# Config access
# ---------------------------------------------------------------------------
def _cfg(cfg):
    """Pull the wazuh_api block with safe defaults. Returns a dict."""
    w = (cfg or {}).get("wazuh_api", {}) or {}
    return {
        "url": (w.get("url") or "").rstrip("/"),
        "username": w.get("username") or "",
        "password": w.get("password") or "",
        "dns_server": (w.get("dns_server") or "").strip(),
        "verify_ssl": w.get("verify_ssl", True),
    }


# ---------------------------------------------------------------------------
# Wazuh API
# ---------------------------------------------------------------------------
def _authenticate(w):
    """
    POST /security/user/authenticate with HTTP Basic creds, return
    (token, error). On success error is None; on failure token is None and
    error is a short message suitable for the UI.
    """
    if not w["url"]:
        return None, "No Wazuh API URL configured."
    if not w["username"]:
        return None, "No Wazuh API username configured."
    try:
        resp = requests.post(
            f"{w['url']}/security/user/authenticate",
            auth=HTTPBasicAuth(w["username"], w["password"]),
            verify=w["verify_ssl"],
            timeout=_AUTH_TIMEOUT_S,
        )
    except requests.exceptions.SSLError:
        return None, ("SSL verification failed. If the Wazuh API uses a "
                      "self-signed certificate, turn off Verify SSL.")
    except requests.exceptions.ConnectionError:
        return None, (f"Could not connect to the Wazuh API at {w['url']}. "
                      "Check the URL, that port 55000 is reachable, and that "
                      "the manager container publishes it.")
    except requests.exceptions.Timeout:
        return None, "Timed out connecting to the Wazuh API."
    except Exception as e:  # pragma: no cover - defensive
        return None, f"Wazuh API authentication error: {e}"

    if resp.status_code == 401:
        return None, ("Invalid credentials. Note the Wazuh API user is NOT "
                      "the dashboard login — the default Docker stack API user "
                      "is 'wazuh-wui'.")
    if resp.status_code != 200:
        return None, f"Wazuh API authentication failed (HTTP {resp.status_code})."

    try:
        token = resp.json()["data"]["token"]
    except Exception:
        return None, "Wazuh API returned an unexpected authentication response."
    return token, None


def _get_agents_page(w, token, offset):
    """
    GET /agents for one page. Returns (affected_items, total, error).
    Excludes the manager itself (id=000) via the q filter.
    """
    try:
        resp = requests.get(
            f"{w['url']}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"offset": offset, "limit": _PAGE_LIMIT, "q": "id!=000"},
            verify=w["verify_ssl"],
            timeout=_FETCH_TIMEOUT_S,
        )
    except requests.exceptions.RequestException as e:
        return None, 0, f"Error fetching agents from the Wazuh API: {e}"

    if resp.status_code != 200:
        return None, 0, f"Wazuh API /agents returned HTTP {resp.status_code}."
    try:
        data = resp.json()["data"]
        return data.get("affected_items", []), data.get("total_affected_items", 0), None
    except Exception:
        return None, 0, "Wazuh API returned an unexpected /agents response."


def fetch_agents(cfg):
    """
    Authenticate and pull the full agent list (paginated). Returns
    (agents, error). Each agent is normalized to the fields the import needs:

        {name, ip, os, groups (list), status, id}

    `os` is the platform string (os.platform, e.g. "windows"/"ubuntu").
    `groups` is the raw group list; "default"-only is treated as "no real
    group" downstream. error is None on success.
    """
    w = _cfg(cfg)
    token, err = _authenticate(w)
    if err:
        return None, err

    agents = []
    offset = 0
    total = None
    # Cap pages defensively so a misbehaving API can't loop forever; 20 pages
    # x 500 = 10,000 agents, well past any single-instance deployment.
    for _ in range(20):
        items, total, err = _get_agents_page(w, token, offset)
        if err:
            return None, err
        for a in items:
            agents.append(_normalize_agent(a))
        offset += len(items)
        if not items or offset >= total:
            break

    logger.info("Wazuh import: fetched %d agent(s)", len(agents))
    return agents, None


def _normalize_agent(a):
    """Reduce a raw Wazuh agent record to the fields the import uses."""
    return {
        "name": a.get("name", ""),
        "ip": a.get("ip", ""),
        "os": (a.get("os") or {}).get("platform", ""),
        "groups": a.get("group", []) or [],
        "status": a.get("status", ""),
        "id": a.get("id", ""),
    }


# ---------------------------------------------------------------------------
# DNS verification
# ---------------------------------------------------------------------------
def _make_resolver(dns_server):
    """
    Build a dns.resolver.Resolver. If dns_server is set, point it at that
    nameserver (the split-horizon case: the agents resolve on a DNS server
    that isn't this host's default). Blank = system resolver.
    """
    r = dns.resolver.Resolver(configure=not bool(dns_server))
    if dns_server:
        r.nameservers = [dns_server]
    r.timeout = _DNS_TIMEOUT_S
    r.lifetime = _DNS_TIMEOUT_S
    return r


def _first_label(name):
    """Lowercase first DNS label (the host-identity key). 'dc01.ad.x' -> 'dc01'."""
    return (name or "").split(".")[0].strip().lower()


def _forward_ips(resolver, name):
    """
    Resolve name -> set of IP strings (A + AAAA). Empty set if unresolvable.

    IMPORTANT: callers must pass an FQDN, not a bare short name. AD / Windows
    DNS (and many resolvers) SERVFAIL or return nothing for a bare short name
    queried directly without a search suffix — the short-name path that works
    in `ping`/`nslookup` relies on the OS resolver appending search domains,
    which dnspython does NOT do by default. Querying the FQDN avoids that
    entirely. (Confirmed against a real AD DNS: `DC01` -> SERVFAIL,
    `dc01.ad.example.com` -> answers.)
    """
    ips = set()
    for rrtype in ("A", "AAAA"):
        try:
            for rdata in resolver.resolve(name, rrtype):
                ips.add(str(rdata))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.DNSException):
            pass
    return ips


def _reverse_name(resolver, ip):
    """Reverse-resolve ip -> first PTR name (lowercased FQDN), or '' if none."""
    try:
        rev = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev, "PTR")
        for rdata in answers:
            return str(rdata).rstrip(".").lower()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException,
            ValueError):
        pass
    return ""


def _domain_of(fqdn):
    """'dc01.ad.example.com' -> 'ad.example.com'; '' if no dot."""
    parts = (fqdn or "").split(".", 1)
    return parts[1] if len(parts) == 2 else ""


def _learn_search_domain(agents, resolver):
    """
    Discover the DNS search domain from the agents' own PTR records. Most
    agents reverse-resolve to FQDNs like `host.ad.example.com`; the common
    suffix is the search domain. Returns the most frequently seen domain, or
    '' if none could be learned.

    Why: to forward-verify a host that has NO reverse record (e.g. a roaming
    host currently on a VPN subnet with no reverse zone), we must query its
    FQDN — which means appending the search domain to its short agent name.
    The network tells us the suffix via the PTRs we DO get, so we don't have
    to ask the operator for it.
    """
    from collections import Counter
    counts = Counter()
    for a in agents:
        ip = a.get("ip", "")
        if _is_ip(ip):
            ptr = _reverse_name(resolver, ip)
            dom = _domain_of(ptr)
            if dom:
                counts[dom] += 1
    return counts.most_common(1)[0][0] if counts else ""


def _verify_one(agent, resolver, search_domain=""):
    """
    Verify a single agent's name and IP against DNS. Returns a classification
    dict describing what DNS says, WITHOUT deciding the bucket (verify_agents
    combines this with hosts.json membership to pick the final bucket).

    Strategy (reverse-anchored, FQDN-forward):
      1. REVERSE is the anchor: resolve the agent's IP to a PTR. If the PTR's
         first label matches the agent's first label, BOTH name and IP are
         verified at once — the PTR is, by definition, the DNS record for that
         exact IP, so a matching PTR proves the IP belongs to that host.
      2. If reverse is absent (e.g. a subnet with no reverse zone, like a
         roaming host on a VPN) or doesn't match, fall back to FORWARD: query
         the agent's FQDN (short name + learned search domain). If it resolves,
         the name is real; whether the agent's reported IP is among the
         forward IPs decides ip_matches.

    Outcome fields:
      dns_name      the PTR FQDN for the agent's IP ('' if no reverse record)
      dns_ips       IPs DNS has for the host (forward A/AAAA) — used for the
                    "stale static -> populate" option; may be empty if only
                    reverse is available
      name_matches  agent first-label is confirmed by DNS (reverse OR forward)
      ip_matches    DNS confirms the agent's reported IP belongs to this host
    """
    agent_name = agent["name"]
    agent_ip = agent["ip"]
    agent_label = _first_label(agent_name)

    # --- Reverse anchor: agent IP -> PTR FQDN ---
    ptr_name = _reverse_name(resolver, agent_ip) if _is_ip(agent_ip) else ""
    ptr_label = _first_label(ptr_name)
    reverse_confirms = bool(ptr_label and ptr_label == agent_label)

    # --- Forward (FQDN): agent name -> DNS IPs ---
    # Build the FQDN to query. Prefer the PTR's own FQDN if reverse gave us a
    # matching one (most precise); otherwise append the learned search domain
    # to the short agent name; if neither is available, fall back to the bare
    # name (best effort — may SERVFAIL on AD DNS, handled gracefully).
    if ptr_name and reverse_confirms:
        fqdn = ptr_name
    elif search_domain and agent_label:
        fqdn = f"{agent_label}.{search_domain}"
    else:
        fqdn = agent_name
    fwd_ips = _forward_ips(resolver, fqdn) if fqdn else set()

    # Name match: confirmed if reverse PTR matches OR forward resolves (the
    # FQDN exists in DNS). A roaming host with no reverse still verifies its
    # name via forward.
    name_matches = bool(reverse_confirms or fwd_ips)

    # IP match: the reverse PTR alone proves the agent's IP belongs to this
    # host (the PTR IS the record for that IP). Otherwise, the agent's reported
    # IP must be among the forward IPs DNS has for the host.
    ip_matches = bool(reverse_confirms or (agent_ip and agent_ip in fwd_ips))

    return {
        "dns_name": ptr_name,
        "dns_ips": sorted(fwd_ips),
        "name_matches": name_matches,
        "ip_matches": ip_matches,
    }


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Bucket classification
# ---------------------------------------------------------------------------
def _host_name_set(hosts):
    """Lowercased first-label set of host names already in hosts.json (the
    match key, mirroring enrich's first-label host matching)."""
    names = set()
    for h in (hosts or {}).get("hosts", []):
        n = h.get("name", "")
        if n:
            names.add(_first_label(n))
    return names


def verify_agents(agents, hosts, cfg):
    """
    Classify each fetched agent into one of four buckets by combining DNS
    verification with hosts.json membership. Returns (buckets, error).

    buckets = {
      "already_in":   [...],   # name+IP verify clean AND already in hosts.json
      "addable":      [...],   # name+IP verify clean, NOT yet in hosts.json
      "ip_mismatch":  [...],   # name matches DNS, IP doesn't -> blank by default,
                               #   "stale static" option to populate dns_ips
      "name_mismatch":[...],   # name doesn't match DNS -> agent needs Wazuh-side
                               #   reconfiguration; report-only, not imported
    }

    Each entry carries the normalized agent plus its DNS verification fields
    (dns_name, dns_ips, name_matches, ip_matches) so the UI can render the
    add form, the blank-with-stale-static option, and the reconfigure report.
    """
    w = _cfg(cfg)
    try:
        resolver = _make_resolver(w["dns_server"])
    except Exception as e:
        return None, f"Could not initialise DNS resolver: {e}"

    # Learn the DNS search domain from the agents' own PTR records, so a host
    # with no reverse entry (e.g. roaming on a VPN subnet with no reverse zone)
    # can still be forward-verified by FQDN (short name + search domain).
    search_domain = _learn_search_domain(agents, resolver)
    if search_domain:
        logger.info("Wazuh import: learned DNS search domain '%s'", search_domain)

    existing = _host_name_set(hosts)
    buckets = {"already_in": [], "addable": [],
               "ip_mismatch": [], "name_mismatch": []}

    for agent in agents:
        v = _verify_one(agent, resolver, search_domain)
        entry = {**agent, **v}
        in_hosts = _first_label(agent["name"]) in existing

        if not v["name_matches"]:
            # Layer 2: the agent name doesn't match DNS. Only Wazuh-side
            # reconfiguration can fix this — report it, don't import.
            buckets["name_mismatch"].append(entry)
        elif not v["ip_matches"]:
            # Layer 1: name is fine, IP disagrees. Default to blank (assume
            # DHCP); the UI offers "stale static" to populate dns_ips.
            buckets["ip_mismatch"].append(entry)
        elif in_hosts:
            buckets["already_in"].append(entry)
        else:
            buckets["addable"].append(entry)

    return buckets, None


# ---------------------------------------------------------------------------
# Commit-time helpers (called when the operator actually adds a host)
#
# These keep ALL host-construction logic in the module so interface.py stays
# thin plumbing: it calls build_host_entry and inserts the result, rather than
# assembling a host dict itself.
# ---------------------------------------------------------------------------
def group_to_role(groups):
    """
    Derive a host role from the agent's Wazuh group list. OPT-IN: this is only
    called when the operator turns on "Use Wazuh agent groups to pre-fill
    roles". Returns a role string, or "" when there is no real group.

    Fail-loudly rule: a "default"-only or empty group list yields NO role
    (blank) rather than a junk "default" role — the system never writes a role
    that means nothing. If there are real groups beyond "default", the first
    non-default one becomes the role (a host's group membership is the natural
    role hint; multi-group refinement is left to the operator on the Roles tab).
    """
    real = [g for g in (groups or []) if g and g.lower() != "default"]
    return real[0] if real else ""


def build_host_entry(agent, use_group_role=False, ip_choice="blank"):
    """
    Build a hosts.json entry dict from a verified agent + the operator's
    choices. Returns a dict matching the shape saveHosts writes, so
    interface.py can insert it directly with no host-construction logic.

      agent          a verified agent entry (normalized + DNS fields)
      use_group_role opt-in: derive role from agent groups (group_to_role)
      ip_choice      what to do with the IP field:
                       "blank"  -> no identifiers.ip (resolve live; the DHCP/
                                   default case)
                       "agent"  -> pin the agent's reported IP
                       "dns"    -> pin the DNS-verified IP(s) (the "stale
                                   static" populate case; uses dns_ips)

    Conventions mirrored from saveHosts:
      - role / identifiers are only present when non-empty
      - a single value is stored as a string, multiple as a list
      - vlan defaults to 10, tags defaults to []
    """
    entry = {
        "name": agent.get("name", ""),
        "os": agent.get("os", ""),
        "vlan": 10,
        "tags": [],
        "notes": "",
        "alias": "",
    }

    if use_group_role:
        role = group_to_role(agent.get("groups", []))
        if role:
            entry["role"] = role

    ips = []
    if ip_choice == "agent":
        if agent.get("ip"):
            ips = [agent["ip"]]
    elif ip_choice == "dns":
        ips = list(agent.get("dns_ips", []) or [])
    # "blank" (default) leaves ips empty -> no identifiers written, host
    # resolves live. This is the right default for the IP-mismatch (assume
    # DHCP) case and harmless for clean hosts (the pipeline resolves anyway).

    if len(ips) == 1:
        entry["identifiers"] = {"ip": ips[0]}
    elif len(ips) > 1:
        entry["identifiers"] = {"ip": ips}

    return entry


def import_preview(cfg, hosts):
    """
    One-call convenience for the UI: fetch the agent list and classify it.
    Returns (result, error) where result = {"buckets": {...}, "counts": {...},
    "total": N}. error is None on success or a short message on failure.
    """
    agents, err = fetch_agents(cfg)
    if err:
        return None, err
    buckets, err = verify_agents(agents, hosts, cfg)
    if err:
        return None, err
    counts = {k: len(v) for k, v in buckets.items()}
    return {"buckets": buckets, "counts": counts, "total": len(agents)}, None


# ---------------------------------------------------------------------------
# Renumber: reconcile hosts.json STORED IPs against current agent+DNS consensus
#
# Different question than the import. The import asks "agent vs DNS"; renumber
# asks "the IP STORED in hosts.json vs what agent+DNS now agree on." This
# catches the case the import misses: a host already in hosts.json with an OLD
# pinned IP, where the agent and DNS both now report a NEW IP — the import lands
# it in already_in (agent==DNS, looks clean) and never checks the stale stored
# value. Renumber compares the stored value and surfaces the drift.
#
# SAFETY GATE (consensus): only offer to change a stored IP when the WAZUH AGENT
# IP and the DNS IP AGREE on a value that differs from the stored IP. Two
# independent sources concurring is required before overwriting the record;
# DNS alone could be stale/mid-renumber/typo'd. If agent and DNS disagree, the
# host is flagged (not auto-changed).
# ---------------------------------------------------------------------------
def _stored_ips(host):
    """The pinned IP(s) for a host as a list of strings. identifiers.ip may be a
    single string or a list; absent/empty means BLANK (no pin)."""
    ident = host.get("identifiers") or {}
    ip = ident.get("ip")
    if not ip:
        return []
    return [ip] if isinstance(ip, str) else [str(x) for x in ip]


def _dns_consensus_ip(agent_ip, dns_ips):
    """The IP that the WAZUH AGENT and DNS agree on, or '' if no agreement.
    Agreement = the agent's reported IP is among DNS's IPs for the host (or the
    agent IP equals the single DNS IP). That shared value is the consensus."""
    if not agent_ip or not _is_ip(agent_ip):
        return ""
    if agent_ip in set(dns_ips):
        return agent_ip
    return ""


def renumber_preview(cfg, hosts, include_blank=False):
    """
    Compare hosts.json STORED IPs against current agent+DNS consensus and
    classify every host for the renumber UI. Returns (result, error) where
    result = {
      "drifted":   [ {name, stored_ip, consensus_ip, agent_ip, dns_ips,
                      currently_blank} ... ],  # stored IP != consensus; offer
                                               #   Update (pin consensus) / Blank
                                               #   / Leave
      "unchanged": int,   # stored IP already == consensus (nothing to do)
      "skipped":   [ {name, reason} ... ],     # no agent, or agent/DNS disagree
      "counts": {...}, "total_hosts": N,
    }

    include_blank=False (default): only hosts with a PINNED IP are examined.
      Blank hosts are skipped — they always "differ" from DNS trivially (blank
      vs any IP), so diffing them is pure noise, and they're already in the
      renumber-safe resolve-live state.
    include_blank=True: blank hosts are ALSO examined and, when a stable
      agent+DNS consensus IP exists, offered for PINNING. Use this after moving
      hosts onto static / MAC-reserved addressing (you now WANT pins where you
      previously had none).
    """
    agents, err = fetch_agents(cfg)
    if err:
        return None, err

    w = _cfg(cfg)
    try:
        resolver = _make_resolver(w["dns_server"])
    except Exception as e:
        return None, f"Could not initialise DNS resolver: {e}"
    search_domain = _learn_search_domain(agents, resolver)

    # Index agents by first-label name (mirrors enrich/hosts matching).
    agent_by_label = {_first_label(a["name"]): a for a in agents}

    drifted, skipped, unchanged = [], [], 0

    for host in (hosts or {}).get("hosts", []):
        name = host.get("name", "")
        if not name:
            continue
        label = _first_label(name)
        stored = _stored_ips(host)
        is_blank = not stored

        # Scope: skip blank hosts unless include_blank (blank trivially differs
        # from DNS — noise — and is already renumber-safe).
        if is_blank and not include_blank:
            continue

        agent = agent_by_label.get(label)
        if not agent:
            # No agent for this host -> no second source for consensus. Only
            # report it as skipped if it was a candidate (pinned, or blank when
            # include_blank); blank-skipped hosts above never reach here.
            if not is_blank:
                skipped.append({"name": name, "reason": "no matching Wazuh agent"})
            continue

        v = _verify_one(agent, resolver, search_domain)
        agent_ip = agent.get("ip", "")
        consensus = _dns_consensus_ip(agent_ip, v["dns_ips"])

        if not consensus:
            # Agent and DNS don't agree on an IP -> can't safely auto-change.
            skipped.append({"name": name,
                            "reason": "Wazuh agent and DNS disagree on the IP"})
            continue

        # Consensus exists. Compare against the stored value.
        if is_blank:
            # include_blank path: blank host with a stable consensus IP -> offer
            # to PIN it.
            drifted.append({"name": name, "stored_ip": "", "consensus_ip": consensus,
                            "agent_ip": agent_ip, "dns_ips": v["dns_ips"],
                            "currently_blank": True})
        elif consensus in stored:
            # Stored IP already matches consensus -> nothing to do.
            unchanged += 1
        else:
            # Stored IP differs from the agreed-upon value -> drift.
            drifted.append({"name": name,
                            "stored_ip": stored[0] if len(stored) == 1 else ", ".join(stored),
                            "consensus_ip": consensus, "agent_ip": agent_ip,
                            "dns_ips": v["dns_ips"], "currently_blank": False})

    counts = {"drifted": len(drifted), "unchanged": unchanged, "skipped": len(skipped)}
    return {"drifted": drifted, "unchanged": unchanged, "skipped": skipped,
            "counts": counts,
            "total_hosts": len((hosts or {}).get("hosts", []))}, None
