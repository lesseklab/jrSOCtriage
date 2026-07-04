#!/usr/bin/env python3
"""
jrSOCtriage - Anonymization Module
Substitutes sensitive identifiers in prompts before sending to cloud LLM endpoints.
Reverses substitution in responses before storing.

Anonymization layers (each independently toggleable in anonymization.json):
  - hostnames : host names from hosts.json alias field
  - users     : usernames/emails from users.json
  - domain    : domain names from domain.json
  - ips       : IP addresses from ip_aliases.json

Files are the lookup tables — program generates aliases for blank entries
and writes them back. Aliases are stable across restarts.
"""

import json
import logging
import os
import random
import re
import string
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)


# Override via config.paths.* fields.
DEFAULT_ANON_PATH   = "anonymization.json"
DEFAULT_USERS_PATH  = "users.json"
DEFAULT_DOMAIN_PATH = "domain.json"
DEFAULT_IP_PATH     = "ip_aliases.json"
DEFAULT_HOSTS_PATH  = "hosts.json"


# ---------------------------------------------------------------------------
# Read-once cache for the anonymization master config (anonymization.json)
# ---------------------------------------------------------------------------
# anonymize_prompt() used to stat+open+json.load this file on EVERY call (i.e.
# every triaged alert). Under LOAC burst that put 24 workers through a per-call
# disk read + JSON parse on the hot path. The file does not change during a run
# (operator edits land via the interface and take effect on restart, same as
# every other config), so we read+parse it ONCE and serve the parsed dict from
# memory thereafter — matching the "read once, keep in memory" model the alias
# core already uses.
#
# Fail-closed semantics are PRESERVED and just moved to load time: the loader
# distinguishes three outcomes the caller must still handle exactly as before:
#   - loaded dict        -> the parsed config
#   - _ANON_CFG_MISSING  -> file absent (sentinel; caller decides per ep_anon)
#   - raises RuntimeError -> file present but unreadable/invalid (fail closed)
# A sentinel (not None) is used for "missing" so it's distinct from "not yet
# loaded" and can't be confused with a falsy parse result.

_ANON_CFG_MISSING = object()       # sentinel: file does not exist
_anon_cfg_cache = None             # None = not loaded yet; else dict or sentinel
_anon_cfg_path_loaded = None       # path the cache was loaded from (re-load if it changes)
_anon_cfg_lock = threading.Lock()


def _get_anon_config_cached(anon_cfg_path):
    """
    Return the parsed anonymization.json ONCE, cached in memory.

    Returns the parsed dict, or _ANON_CFG_MISSING if the file does not exist.
    Raises RuntimeError if the file exists but is unreadable/not a JSON object
    (fail-closed — identical to the old inline behavior, just done once).

    Thread-safe: first caller under the lock does the read; everyone else gets
    the cached result. Double-checked so the common (already-loaded) path never
    takes the lock.
    """
    global _anon_cfg_cache, _anon_cfg_path_loaded

    # Fast path: already loaded for this same path, no lock.
    if _anon_cfg_cache is not None and _anon_cfg_path_loaded == anon_cfg_path:
        return _anon_cfg_cache

    with _anon_cfg_lock:
        # Re-check inside the lock (another thread may have just loaded it).
        if _anon_cfg_cache is not None and _anon_cfg_path_loaded == anon_cfg_path:
            return _anon_cfg_cache

        if not Path(anon_cfg_path).exists():
            _anon_cfg_cache = _ANON_CFG_MISSING
            _anon_cfg_path_loaded = anon_cfg_path
            return _anon_cfg_cache

        try:
            with open(anon_cfg_path) as f:
                loaded = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            raise RuntimeError(
                f"anonymization requested but {anon_cfg_path} is unreadable "
                f"or invalid ({e}) — refusing cloud call (fail closed)"
            )
        if not isinstance(loaded, dict):
            raise RuntimeError(
                f"anonymization requested but {anon_cfg_path} is not a JSON "
                f"object — refusing cloud call (fail closed)"
            )

        _anon_cfg_cache = loaded
        _anon_cfg_path_loaded = anon_cfg_path
        return _anon_cfg_cache


def reset_anon_config_cache():
    """Drop the cached anon config (forces a re-read on next use).
    For tests, and for an explicit operator reload hook if one is ever added.
    """
    global _anon_cfg_cache, _anon_cfg_path_loaded
    with _anon_cfg_lock:
        _anon_cfg_cache = None
        _anon_cfg_path_loaded = None


# ===========================================================================
# CACHED ALIAS CORE (replaces per-call file-lock load-modify-save).
# See anon_core_rewrite for design rationale. SOLE file writer is the
# flusher thread; hot path is lock-free reads + per-IP-miss lock.
# ===========================================================================

# ---------------------------------------------------------------------------
# Per-category cache state
# ---------------------------------------------------------------------------
# Each category owns: its lock, its loaded flag, the on-disk list (for flush),
# the derived lookup dict (for serving), warm minting state, and a dirty flag.
# Reads hit `lookup` lock-free. Misses take `lock` to mint+insert and set dirty.
# The flusher thread snapshots the list under `lock` then writes outside it.

class _Cat:
    __slots__ = ("lock", "loaded", "path", "entries", "lookup", "mint_state",
                 "dirty")
    def __init__(self):
        self.lock = threading.Lock()
        self.loaded = False
        self.path = None
        self.entries = []      # on-disk list form: [{"name"/"original":..., "alias":...}]
        self.lookup = {}       # derived: {original: alias} (+ lowercase variants)
        self.mint_state = {}   # category-specific warm counters / used-sets
        self.dirty = False

_users   = _Cat()
_domains = _Cat()
_hosts   = _Cat()
_ips     = _Cat()

# NOTE: reads are lock-free on the assumption that dict .get during a
# concurrent insert is safe under CPython's GIL (it is for a single get).
# The lookup dict is only ever mutated while holding the category lock, and
# we never delete keys, so a reader sees either the old or new value, never a
# corrupt state.
# FT (python3.14t): the named categories (users/domains/hosts) mint only at
# load and are immutable after — lock-free reads stay safe. The IP category
# mints at runtime; in-place insertion into a live dict is NOT safe for a
# concurrent lock-free reader without the GIL, so load_ip_aliases() below was
# converted to COPY-ON-WRITE: it builds a new dict under the lock and swaps
# _ips.lookup in one atomic reference assignment. A reader grabbing the
# reference sees either the complete old dict or the complete new one, never
# a half-built one — so reads remain lock-free on 3.14t too.


# ---------------------------------------------------------------------------
# Flusher thread — SOLE file writer
# ---------------------------------------------------------------------------
_flush_interval_s = 300            # 5 min
_flusher_started = False
_flusher_lock = threading.Lock()
_shutdown = threading.Event()


def _save_json_atomic(path, data):
    """Atomic tmp+fsync+rename. SOLE caller is the flusher thread, so no lock
    is needed here (single writer by construction)."""
    tmp_path = f"{path}.tmp"
    try:
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except OSError as e:
        logger.error(f"Failed to save {path}: {e}")
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass


def _snapshot_if_dirty(cat):
    """Under the category lock: if dirty, copy the entries list and clear
    dirty. Returns (path, snapshot) or None. Copy is cheap; the actual disk
    write happens OUTSIDE the lock in the caller."""
    with cat.lock:
        if not cat.dirty or not cat.loaded:
            return None
        # shallow-copy each entry dict so a later mint can't mutate our snapshot
        snapshot = {"_list": [dict(e) for e in cat.entries]}
        cat.dirty = False
        return (cat.path, snapshot)


def _flush_all():
    """Flush every dirty category. Snapshot under lock, write outside."""
    for cat, root_key in ((_users, "users"), (_domains, "domains"),
                          (_hosts, "hosts"), (_ips, "ips")):
        snap = _snapshot_if_dirty(cat)
        if snap is None:
            continue
        path, payload = snap
        # rebuild the on-disk shape {root_key: [entries]}
        _save_json_atomic(path, {root_key: payload["_list"]})


def _flusher_main():
    while not _shutdown.wait(_flush_interval_s):
        try:
            _flush_all()
        except Exception as e:
            logger.error(f"[anon-flusher] flush failed: {e}", exc_info=True)
    # final flush on shutdown
    try:
        _flush_all()
    except Exception as e:
        logger.error(f"[anon-flusher] final flush failed: {e}", exc_info=True)


def start_anon_flusher():
    """Idempotent. Call once at pipeline startup (main.py)."""
    global _flusher_started
    with _flusher_lock:
        if _flusher_started:
            return
        t = threading.Thread(target=_flusher_main, name="anon-flusher",
                             daemon=True)
        t.start()
        _flusher_started = True
        logger.info(f"[anon-flusher] started (interval={_flush_interval_s}s)")


def stop_anon_flusher():
    """Call from the graceful-shutdown handler. Signals the flusher to do a
    final flush and exit. Safe to call even if never started."""
    _shutdown.set()
    # one synchronous final flush so a fast shutdown still persists aliases
    try:
        _flush_all()
    except Exception as e:
        logger.error(f"[anon-flusher] shutdown flush failed: {e}", exc_info=True)


def _load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to load {path}: {e}")
        return default


# ---------------------------------------------------------------------------
# IPs — the complex one. Warm mint_state holds the subnet/prefix used-sets and
# the all_originals set so we never rebuild them per call.
# ---------------------------------------------------------------------------

def _ensure_ips_loaded(config):
    if _ips.loaded:
        return
    with _ips.lock:
        if _ips.loaded:
            return
        import ipaddress
        path = config.get("paths", {}).get("ip_aliases_file", "ip_aliases.json")
        data = _load_json(path, {"ips": []})
        entries = data.get("ips", [])

        used_octets = {}      # subnet -> set(last octets)
        used_suffixes = {}    # prefix -> set(host suffixes)
        all_originals = set()
        lookup = {}

        def _seed(ip_str):
            if "." in ip_str:
                p = ip_str.split(".")
                if len(p) == 4:
                    try:
                        used_octets.setdefault(".".join(p[:3]), set()).add(int(p[3]))
                    except ValueError:
                        pass
            elif ":" in ip_str:
                try:
                    g = ipaddress.IPv6Address(ip_str).exploded.split(":")
                    if len(g) == 8:
                        used_suffixes.setdefault(":".join(g[:4]), set()).add(":".join(g[4:]))
                except (ipaddress.AddressValueError, ValueError):
                    pass

        for e in entries:
            o, a = e.get("original", ""), e.get("alias", "")
            if o:
                all_originals.add(o); _seed(o)
            if o and a:
                lookup[o] = a; _seed(a)

        # ONE-TIME repair pass (was per-call in original) — regenerate any
        # existing alias that equals a known original IP.
        changed = False
        for e in entries:
            o, a = e.get("original", ""), e.get("alias", "")
            if not o or not a or a not in all_originals:
                continue
            try:
                addr = ipaddress.ip_address(o)
            except ValueError:
                continue
            if isinstance(addr, ipaddress.IPv4Address):
                parts = o.split(".")
                used = used_octets.setdefault(".".join(parts[:3]), set())
                new_a = _gen_ip_alias(o, used)
            else:
                groups = ipaddress.IPv6Address(o).exploded.split(":")
                used = used_suffixes.setdefault(":".join(groups[:4]), set())
                new_a = _gen_ipv6_alias(o, used)
            logger.warning(f"IP alias conflict repaired: '{a}' for '{o}' -> '{new_a}'")
            e["alias"] = new_a
            lookup[o] = new_a
            changed = True

        _ips.path = path
        _ips.entries = entries
        _ips.lookup = lookup
        _ips.mint_state = {"used_octets": used_octets,
                           "used_suffixes": used_suffixes,
                           "all_originals": all_originals}
        _ips.dirty = changed
        _ips.loaded = True


def load_ip_aliases(config, target_ips=None):
    """Drop-in replacement. Returns {original_ip: alias} for all known + any
    newly-minted target_ips. Hot path: cache hit = lock-free. Miss = lock,
    mint in-memory, mark dirty."""
    import ipaddress
    _ensure_ips_loaded(config)

    # Fast path: everything requested already known -> no lock, just return
    # the current lookup (a superset; substitution only uses keys it needs).
    if not target_ips:
        return _ips.lookup

    missing = [ip for ip in target_ips if ip not in _ips.lookup]
    if not missing:
        return _ips.lookup

    with _ips.lock:
        ms = _ips.mint_state
        used_octets = ms["used_octets"]
        used_suffixes = ms["used_suffixes"]
        all_originals = ms["all_originals"]

        # FT COPY-ON-WRITE: mint into a copy, swap the reference once at the
        # end. Every in-lock reference below uses _new_lookup; lock-free
        # readers keep seeing the old _ips.lookup until the atomic swap.
        _new_lookup = dict(_ips.lookup)

        # NAMESPACE RULE (preserved from original): an alias must never equal
        # a known original IP. The original rebuilt the used-sets from the
        # full table every call, so every original's octet/suffix was always
        # marked used before any mint. The cache keeps the used-sets warm, but
        # runtime-new originals must be SEEDED before we mint ANY of them —
        # otherwise (a) a new IP's alias could equal another new IP in the
        # same batch/subnet, or (b) an alias could equal a brand-new original.
        # Seed the whole missing batch's octets/suffixes first, then mint.
        def _seed_runtime(ip_str):
            if "." in ip_str:
                p = ip_str.split(".")
                if len(p) == 4:
                    try:
                        used_octets.setdefault(".".join(p[:3]), set()).add(int(p[3]))
                    except ValueError:
                        pass
            elif ":" in ip_str:
                try:
                    g = ipaddress.IPv6Address(ip_str).exploded.split(":")
                    if len(g) == 8:
                        used_suffixes.setdefault(":".join(g[:4]), set()).add(":".join(g[4:]))
                except (ipaddress.AddressValueError, ValueError):
                    pass

        for ip in missing:
            if ip not in _new_lookup:
                all_originals.add(ip)
                _seed_runtime(ip)          # mark this original's addr used
                # RUNTIME REPAIR: if this brand-new original's address was
                # already handed out as someone else's ALIAS, that's the
                # namespace hazard. The original code's per-call repair pass
                # caught this; under incremental discovery we must catch it
                # when the colliding original first appears. Regenerate the
                # offending alias (breaks that one entry's stability — the
                # correct trade, same as the original's repair pass).
                for entry in _ips.entries:
                    if entry.get("alias") != ip:
                        continue
                    victim = entry.get("original", "")
                    if not victim:
                        continue
                    try:
                        vaddr = ipaddress.ip_address(victim)
                    except ValueError:
                        continue
                    if isinstance(vaddr, ipaddress.IPv4Address):
                        vp = victim.split(".")
                        vused = used_octets.setdefault(".".join(vp[:3]), set())
                        new_alias = _gen_ip_alias(victim, vused)
                    else:
                        vg = ipaddress.IPv6Address(victim).exploded.split(":")
                        vused = used_suffixes.setdefault(":".join(vg[:4]), set())
                        new_alias = _gen_ipv6_alias(victim, vused)
                    logger.warning(
                        f"IP alias conflict repaired at runtime: alias '{ip}' "
                        f"for '{victim}' is now a known original — "
                        f"regenerated as '{new_alias}'")
                    entry["alias"] = new_alias
                    _new_lookup[victim] = new_alias
                    _seed_runtime(new_alias)
                    _ips.dirty = True

        for ip in missing:
            if ip in _new_lookup:          # double-check: another worker minted it
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if isinstance(addr, ipaddress.IPv4Address):
                parts = ip.split(".")
                if len(parts) != 4:
                    continue
                used = used_octets.setdefault(".".join(parts[:3]), set())
                alias = _gen_ip_alias(ip, used)
            else:
                try:
                    groups = ipaddress.IPv6Address(ip).exploded.split(":")
                    prefix = ":".join(groups[:4])
                except (ipaddress.AddressValueError, ValueError):
                    continue
                used = used_suffixes.setdefault(prefix, set())
                alias = _gen_ipv6_alias(ip, used)
            _new_lookup[ip] = alias
            _seed_runtime(alias)           # mark the minted alias used too
            _ips.entries.append({"original": ip, "alias": alias})
            _ips.dirty = True
            logger.info(f"Generated IP alias for '{ip}': '{alias}'")
        # FT: atomic reference swap — the single point where lock-free readers
        # transition from the old map to the new one. Must be the LAST in-lock
        # statement, after all mints, so no reader ever sees a partial build.
        _ips.lookup = _new_lookup
    return _ips.lookup


# ---------------------------------------------------------------------------
# Users / Domains / Hosts — simpler: counters instead of subnet sets.
# Their originals come from the FILE (not the prompt), so there are no
# "new at runtime" entries to mint — the file is the fixed table. That means
# these can be loaded once and served lock-free with NO miss path at all,
# preserving the original behavior (which only minted for blank-alias entries
# already present in the file). Minting still happens once, at load.
# ---------------------------------------------------------------------------

def _load_named_category(cat, config, path_key, default_path, root_key,
                         mint_fn):
    if cat.loaded:
        return cat.lookup
    with cat.lock:
        if cat.loaded:
            return cat.lookup
        path = config.get("paths", {}).get(path_key, default_path)
        data = _load_json(path, {root_key: []})
        entries = data.get(root_key, [])
        lookup, changed = mint_fn(entries)
        cat.path = path
        cat.entries = entries
        cat.lookup = lookup
        cat.dirty = changed
        cat.loaded = True
        return cat.lookup


def load_users(config):
    def _mint(entries):
        if not entries:
            return {}, False
        existing = [e.get("alias", "").strip() for e in entries]
        uc = _next_counter(existing, "user")
        dc = _next_counter(existing, "User")
        changed = False
        result = {}
        for entry in entries:
            name = entry.get("name", "").strip()
            alias = entry.get("alias", "").strip()
            if not name:
                continue
            if not alias:
                changed = True
                if "@" in name:
                    alias = _gen_user_email_alias(uc, name); uc += 1
                elif " " in name:
                    alias = f"User{dc} Display"; dc += 1
                else:
                    alias = _gen_user_alias(uc); uc += 1
                entry["alias"] = alias
                logger.info(f"Generated alias for user '{name}': '{alias}'")
            result[name] = alias
            if name.lower() != name:
                result[name.lower()] = alias
        return result, changed
    return _load_named_category(_users, config, "users_file", "users.json",
                                "users", _mint)


def load_domains(config):
    def _mint(entries):
        if not entries:
            return {}, False
        existing = [e.get("alias", "").strip() for e in entries]
        dc = _next_counter(existing, "corp")
        changed = False
        result = {}
        for entry in entries:
            name = entry.get("name", "").strip()
            alias = entry.get("alias", "").strip()
            if not name:
                continue
            if not alias:
                changed = True
                if name.isupper() and "." not in name:
                    alias = _gen_domain_netbios_alias(dc)
                elif name.startswith("ad."):
                    alias = f"ad.{_gen_domain_alias(dc)}"
                else:
                    alias = _gen_domain_alias(dc)
                dc += 1
                entry["alias"] = alias
                logger.info(f"Generated alias for domain '{name}': '{alias}'")
            result[name] = alias
            if name.lower() != name:
                result[name.lower()] = alias
        return result, changed
    return _load_named_category(_domains, config, "domain_file", "domain.json",
                                "domains", _mint)


def load_hosts_aliases(config):
    def _mint(entries):
        existing = [h.get("alias", "").strip() for h in entries]
        used_letters, used_numbers = set(), set()
        for alias in existing:
            if not alias or not alias.startswith("host-"):
                continue
            suf = alias[5:]
            if len(suf) == 1 and suf.isalpha():
                used_letters.add(suf.lower())
            elif suf.isdigit():
                try:
                    used_numbers.add(int(suf))
                except ValueError:
                    pass
        hc = 1
        while hc <= 26:
            if string.ascii_lowercase[hc - 1] not in used_letters:
                break
            hc += 1
        else:
            hc = max(27, max(used_numbers, default=26) + 1)
        changed = False
        result = {}
        for host in entries:
            name = host.get("name", "").strip()
            alias = host.get("alias", "").strip()
            if not name:
                continue
            if not alias:
                alias = _gen_host_alias(hc)
                host["alias"] = alias
                changed = True
                logger.info(f"Generated alias for host '{name}': '{alias}'")
                hc += 1
                while hc <= 26 and string.ascii_lowercase[hc - 1] in used_letters:
                    hc += 1
            result[name] = alias
            if name.lower() != name:
                result[name.lower()] = alias
        return result, changed
    return _load_named_category(_hosts, config, "hosts_file", "hosts.json",
                                "hosts", _mint)


# ---------------------------------------------------------------------------
# Alias generators + counter (preserved verbatim from original)
# ---------------------------------------------------------------------------

def load_anon_config(config):
    """Load anonymization.json master config."""
    path = config.get("paths", {}).get("anonymization_file", DEFAULT_ANON_PATH)
    return _load_json(path, {
        "hostnames": False,
        "users": False,
        "domain": False,
        "ips": False,
        "ip_mode": "all"
    })


# ---------------------------------------------------------------------------
# Alias generators
# ---------------------------------------------------------------------------

def _gen_user_alias(index):
    """Generate a user alias: user1, user2, etc."""
    return f"user{index}"


def _gen_user_email_alias(index, original):
    """Generate email alias based on original format."""
    if "@" in original:
        parts = original.split("@")
        domain_part = parts[1]
        # Keep domain structure but anonymize
        if "gmail" in domain_part:
            return f"user{index}@mail.example.com"
        elif ".edu" in domain_part:
            return f"user{index}@university.edu"
        else:
            return f"user{index}@example.com"
    return f"user{index}"


def _gen_domain_alias(index):
    """Generate domain alias: corp1.internal, CORP1, etc."""
    return f"corp{index}.internal"


def _gen_domain_netbios_alias(index):
    """Generate NetBIOS domain alias: CORP1."""
    return f"CORP{index}"


def _gen_host_alias(index):
    """Generate host alias: host-a, host-b, etc."""
    if index <= 26:
        return f"host-{string.ascii_lowercase[index-1]}"
    return f"host-{index}"


def _gen_ip_alias(original_ip, used_octets, max_attempts=500):
    """
    Generate within-subnet IPv4 alias with unique last octet.
    Raises RuntimeError if the subnet is exhausted (240+ aliases in one /24).

    TRUST BOUNDARY: Exhaustion must fail closed, not return the original IP.
    Returning the original would let the original IP leak through to the
    cloud LLM despite the operator opting into anonymization. The caller
    chain (load_ip_aliases → anonymize_prompt → _call_endpoint_inner) is
    set up to catch this exception and refuse the cloud call. See the
    anonymization-refused handler in llm_caller._call_endpoint_inner.
    """
    parts = original_ip.split(".")
    if len(parts) != 4:
        raise RuntimeError(
            f"IPv4 alias generation: '{original_ip}' is not a valid dotted-quad"
        )
    # Keep first three octets, randomize last
    for _ in range(max_attempts):
        new_last = random.randint(10, 250)
        candidate = f"{parts[0]}.{parts[1]}.{parts[2]}.{new_last}"
        if new_last not in used_octets and candidate != original_ip:
            used_octets.add(new_last)
            return candidate
    # Subnet is essentially full — fail closed. The cloud call will be
    # refused upstream.
    raise RuntimeError(
        f"IPv4 alias subnet exhausted for {original_ip} "
        f"(240+ aliases already in this /24) — refusing to anonymize"
    )


def _gen_ipv6_alias(original_ip, used_suffixes, max_attempts=500):
    """
    Generate an IPv6 alias by preserving the network prefix (first 4 hex
    groups) and randomizing the host suffix (last 4 hex groups).
    For compressed forms, expand first.

    Raises RuntimeError if generation fails. Same trust-boundary rationale
    as _gen_ip_alias: must fail closed to prevent original IP leakage.
    """
    import ipaddress
    try:
        addr = ipaddress.IPv6Address(original_ip)
    except (ipaddress.AddressValueError, ValueError) as e:
        raise RuntimeError(
            f"IPv6 alias generation: '{original_ip}' is not a valid IPv6 address: {e}"
        )

    # Get the expanded form as groups
    expanded = addr.exploded  # e.g. "fe80:0000:0000:0000:132f:9a14:f509:c011"
    groups = expanded.split(":")
    if len(groups) != 8:
        raise RuntimeError(
            f"IPv6 alias generation: unexpected expanded form for '{original_ip}'"
        )

    network_prefix = ":".join(groups[:4])
    for _ in range(max_attempts):
        new_suffix = ":".join(f"{random.randint(0, 0xffff):04x}" for _ in range(4))
        candidate = f"{network_prefix}:{new_suffix}"
        if new_suffix not in used_suffixes and candidate != original_ip:
            used_suffixes.add(new_suffix)
            # Return in compressed form for readability
            try:
                return str(ipaddress.IPv6Address(candidate).compressed)
            except (ipaddress.AddressValueError, ValueError):
                return candidate
    # Address space exhausted — fail closed.
    raise RuntimeError(
        f"IPv6 alias space exhausted for {original_ip} "
        f"(unable to generate a unique suffix in {max_attempts} attempts) — "
        f"refusing to anonymize"
    )


# ---------------------------------------------------------------------------
# Load and generate aliases
# ---------------------------------------------------------------------------

def _next_counter(existing_aliases, prefix):
    """
    Return the next available counter for aliases matching the given prefix.
    Scans existing aliases and returns max(index) + 1, or 1 if none match.
    Prevents new aliases from colliding with existing ones when generating
    aliases for newly-added entries.
    """
    max_idx = 0
    pat = re.compile(rf"^{re.escape(prefix)}(\d+)", re.IGNORECASE)
    for alias in existing_aliases:
        if not alias:
            continue
        m = pat.match(alias)
        if m:
            try:
                idx = int(m.group(1))
                if idx > max_idx:
                    max_idx = idx
            except ValueError:
                continue
    return max_idx + 1



# ---------------------------------------------------------------------------
# Substitution engine
# ---------------------------------------------------------------------------

def _substitute(text, lookup, case_sensitive=False):
    """
    Replace all occurrences of keys in lookup with their values, in a SINGLE
    regex pass over the text (one compile, one scan) instead of one
    compile+scan per key.

    PERFORMANCE: the previous implementation looped every key, compiling
    `\\b{key}\\b` and scanning the full prompt PER KEY — O(num_keys * prompt_len)
    with a fresh re.compile each call. For a category table with hundreds of
    aliases against a ~7KB prompt, run on every triaged alert, that was the
    dominant anon hot-path cost. This builds ONE alternation
    `\\b(k1|k2|...|kN)\\b` (keys escaped, sorted longest-first) compiled once,
    and a single re.sub whose replacement function looks the matched key up in
    a dict. One scan, regardless of table size.

    CORRECTNESS — every property the old version guaranteed is preserved:

    * Longest-first alternation order. Python re matches alternatives
      left-to-right and takes the FIRST that matches at a position, so for two
      keys where one is a prefix of the other (e.g. "host1" and "host10") the
      longer must come first or "host10" would match as "host1"+"0". Sorting
      alternatives by length descending guarantees the longest viable key wins.

    * Word boundaries \\b on both ends — the IP-corruption guard. Without them,
      key "52.107.246.2" matched the first 12 chars of an already-present
      "52.107.246.213" and produced "52.107.246.21413". A single \\b(...)\\b
      wrapper applies the same boundary to every alternative. (14 live
      key-prefix-of-alias hazards existed in the production ip_aliases.json.)
      \\b is safe for every category here — hostnames, users/emails, domains,
      IPs all start/end with word chars — and preserves desired substring
      behavior for domains inside FQDNs ("lesseklab.net" still matches inside
      "ad.home.lesseklab.net" because '.' is a non-word char) and port-suffixed
      IPs ("192.168.10.50:47578", ':' is non-word).

    * Single-pass is STRICTLY SAFER against re-substituting an inserted alias
      than the old sequential loop: re.sub consumes each match and advances
      past the replacement, so alias text inserted at one position is never
      re-scanned later in the same pass. The old loop relied on key ordering
      for this; the single pass gets it structurally.

    * Case-sensitivity honored via the same flag (domains and IPs pass
      case_sensitive=True; hostnames/users do not).

    * Literal alias insertion — the replacement is a function returning the
      alias string directly, so no backreference/escape interpretation of the
      alias text (matches the old lambda's intent).

    Returns (substituted_text, reverse_lookup)
    """
    reverse = {}

    # Filter out empty keys/aliases (old loop skipped these via `continue`).
    # Sort longest-first so prefix keys can't pre-empt longer keys in the
    # alternation (re takes the first matching alternative at each position).
    keys = [k for k in lookup
            if k and lookup.get(k)]
    if not keys:
        return text, reverse
    keys.sort(key=len, reverse=True)

    flags = 0 if case_sensitive else re.IGNORECASE

    # For case-insensitive categories, two distinct keys could differ only in
    # case and collide on the same match text. Build the replacement map with
    # the matched substring resolved back to the right alias by trying an exact
    # hit first, then a case-folded lookup. Keep a folded index for that.
    if case_sensitive:
        keymap = {k: lookup[k] for k in keys}
        folded = None
    else:
        keymap = {k: lookup[k] for k in keys}
        folded = {k.lower(): lookup[k] for k in keys}

    combined = re.compile(
        r"\b(" + "|".join(re.escape(k) for k in keys) + r")\b",
        flags,
    )

    def _repl(m):
        matched = m.group(1)
        alias = keymap.get(matched)
        if alias is None and folded is not None:
            alias = folded.get(matched.lower())
        if alias is None:
            # Shouldn't happen (the pattern was built from these keys), but if
            # it does, leave the text untouched rather than insert None.
            return matched
        reverse[alias] = matched
        return alias

    text = combined.sub(_repl, text)
    return text, reverse


def anonymize_prompt(prompt, config, endpoint_cfg):
    """
    Anonymize a prompt before sending to a cloud LLM endpoint.
    Returns (anonymized_prompt, reverse_lookup_dict)
    The reverse_lookup_dict is used to de-anonymize the response.
    """
    anon_cfg_path = config.get("paths", {}).get(
        "anonymization_file", DEFAULT_ANON_PATH)

    ep_anon = endpoint_cfg.get("anonymize", None)

    # Explicit False / missing / None means anonymization is not requested
    # for this endpoint — return the prompt unchanged.
    if ep_anon is None or ep_anon is False:
        return prompt, {}

    # Anonymization IS requested past this point. Load the master config
    # STRICTLY: a missing or unparseable anonymization.json must FAIL
    # CLOSED, not degrade to "no categories enabled". Before this guard,
    # `anonymize: true` with a missing/corrupt anonymization.json silently
    # sent the RAW prompt to the cloud — every category .get() defaulted
    # False, nothing substituted, nothing raised, and llm_caller's
    # anonymization-refused handler (which exists exactly for this) never
    # fired. Raising lands in that handler and the cloud call is refused,
    # which is the documented trust boundary.
    #
    # The read is now done ONCE and cached in memory (see
    # _get_anon_config_cached) instead of stat+open+json.load per call.
    # Fail-closed semantics are unchanged: a present-but-invalid file raises;
    # an absent file returns the sentinel and the per-ep_anon logic below
    # decides (true/{} with no file still fail closed; an explicit per-category
    # dict is allowed to proceed without the master file).
    cached = _get_anon_config_cached(anon_cfg_path)
    anon_cfg = None if cached is _ANON_CFG_MISSING else cached

    # Empty dict {} is almost certainly a config mistake — someone meant to
    # enable anonymization but left the config blank. Treat it as an opt-in
    # request to use the defaults from anonymization.json, and log loudly
    # so the user can see what's happening and fix their config if this
    # wasn't intentional.
    if isinstance(ep_anon, dict) and not ep_anon:
        ep_name = endpoint_cfg.get("name", "unknown")
        logger.warning(
            f"[{ep_name}] endpoint has 'anonymize: {{}}' (empty config) — "
            f"interpreting as 'use anonymization.json defaults'. "
            f"Set 'anonymize: true' explicitly, or specify per-category "
            f"settings, to silence this warning."
        )
        ep_anon = anon_cfg if anon_cfg is not None else {}
        if anon_cfg is None:
            raise RuntimeError(
                f"anonymization requested (anonymize: {{}}) but "
                f"{anon_cfg_path} is missing — no category settings exist "
                f"anywhere, refusing cloud call (fail closed)"
            )

    # If anonymize is just True (not a dict), use anonymization.json settings
    elif ep_anon is True:
        if anon_cfg is None:
            raise RuntimeError(
                f"anonymization requested (anonymize: true) but "
                f"{anon_cfg_path} is missing — no category settings exist "
                f"anywhere, refusing cloud call (fail closed)"
            )
        ep_anon = anon_cfg

    # Anything else that's truthy (e.g. a populated per-category dict) —
    # use as-is. The endpoint's own dict IS the spec in that case, so a
    # missing master file is acceptable (it only supplies ip_mode, which
    # has a safe default below). If it's a bogus type (a string, number,
    # list), fall through to the .get() calls below which will treat it
    # as falsy per-category.

    reverse_lookup = {}
    text = prompt

    # --- Hostnames ---
    if ep_anon.get("hostnames", False):
        host_aliases = load_hosts_aliases(config)
        if host_aliases:
            text, rev = _substitute(text, host_aliases)
            reverse_lookup.update(rev)

    # --- Users ---
    if ep_anon.get("users", False):
        user_aliases = load_users(config)
        if user_aliases:
            text, rev = _substitute(text, user_aliases)
            reverse_lookup.update(rev)

    # --- Domain ---
    if ep_anon.get("domain", False):
        domain_aliases = load_domains(config)
        if domain_aliases:
            text, rev = _substitute(text, domain_aliases, case_sensitive=True)
            reverse_lookup.update(rev)

    # --- IPs ---
    if ep_anon.get("ips", False):
        import ipaddress

        # IPv4: strict dotted-quad, bounded octets
        ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        )
        # IPv6: permissive capture for compressed and full forms. Validated
        # by ipaddress.ip_address below, so false positives are harmless.
        # Pattern strategy: match runs of hex-colon, with an optional
        # embedded "::" compression. Requires at least two colons to
        # avoid matching single hex-colon-hex runs that aren't IPs.
        ipv6_pattern = re.compile(
            r'(?<![\w:])'                           # not preceded by hex or colon
            r'[0-9a-fA-F:]*::[0-9a-fA-F:]+'         # compressed form with "::"
            r'|'
            r'(?<![\w:])'
            r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'  # full 8-group form
        )

        found_ips = set(ipv4_pattern.findall(text))

        # Validate v6 candidates with ipaddress. Anything that doesn't parse
        # as a valid IPv6 address is discarded.
        for candidate in ipv6_pattern.findall(text):
            # Strip zone id suffix (%eth0) if present
            bare = candidate.split("%")[0].strip()
            if not bare:
                continue
            # Require at least one colon to avoid matching arbitrary hex runs
            if ":" not in bare:
                continue
            try:
                addr = ipaddress.ip_address(bare)
                if isinstance(addr, ipaddress.IPv6Address):
                    # Skip v6 loopback and unspecified - rarely sensitive
                    if addr.is_loopback or addr.is_unspecified:
                        continue
                    found_ips.add(bare)
            except ValueError:
                continue

        ip_mode = (anon_cfg or {}).get("ip_mode", "all")
        if ip_mode != "all":
            # "all" is the only implemented mode. Before this guard, any
            # other value (a typo, or a mode from a future version) made
            # this branch silently SKIP IP substitution while ips:true was
            # set — original IPs leaked to the cloud with no warning.
            # Unknown mode + ips enabled = fail closed.
            raise RuntimeError(
                f"anonymization ips enabled but ip_mode '{ip_mode}' is not "
                f"supported (only 'all') — refusing cloud call (fail closed)"
            )

        if found_ips:
            ip_aliases = load_ip_aliases(config, target_ips=list(found_ips))
            if ip_aliases:
                text, rev = _substitute(text, ip_aliases, case_sensitive=True)
                reverse_lookup.update(rev)

    if reverse_lookup:
        logger.info(f"Anonymized {len(reverse_lookup)} identifier(s) in prompt")

    return text, reverse_lookup


def deanonymize_response(response_text, reverse_lookup):
    """
    Reverse anonymization in LLM response before storing.
    Returns de-anonymized response text.
    """
    if not reverse_lookup or not response_text:
        return response_text

    text = response_text
    # Sort longest alias first to avoid partial matches
    for alias in sorted(reverse_lookup.keys(), key=len, reverse=True):
        original = reverse_lookup[alias]
        if alias in text:
            text = text.replace(alias, original)

    return text


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    from ingest import load_config
    config = load_config("config.json")

    print("=== jrSOCtriage Anonymization Smoke Test ===\n")
    # NOTE: this smoke test MUTATES the alias lookup files — load_users /
    # load_domains / load_hosts_aliases generate-and-save aliases for any
    # blank entries (by design; aliases must be stable). It does NOT touch
    # .ingest_position (no read_new_alerts here), so it is safe to run
    # alongside a live pipeline.

    # Test user alias generation
    print("Loading users...")
    users = load_users(config)
    print(f"  {len(users)} user entries:")
    for k, v in users.items():
        print(f"    '{k}' -> '{v}'")

    print("\nLoading domains...")
    domains = load_domains(config)
    print(f"  {len(domains)} domain entries:")
    for k, v in domains.items():
        print(f"    '{k}' -> '{v}'")

    print("\nLoading host aliases...")
    hosts = load_hosts_aliases(config)
    print(f"  {len(hosts)} host entries with aliases:")
    for k, v in list(hosts.items())[:5]:
        print(f"    '{k}' -> '{v}'")

    # Test substitution
    test_prompt = """
Alert on host: mgmt-host-01
User: analyst logged in from 192.168.30.4
Domain: EXAMPLECORP
Email: analyst@example.com
"""
    print(f"\nTest prompt:\n{test_prompt}")

    fake_endpoint = {"anonymize": {"hostnames": True, "users": True, "domain": True, "ips": True}}
    anonymized, reverse = anonymize_prompt(test_prompt, config, fake_endpoint)
    print(f"Anonymized:\n{anonymized}")

    restored = deanonymize_response(anonymized, reverse)
    print(f"Restored:\n{restored}")

    print("=== Done ===")