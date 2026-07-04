#!/usr/bin/env python3
"""
jrSOCtriage - Ingestion Module
Reads Wazuh alerts.json, tracks position, yields new alerts.
"""

import json
import hashlib
import os
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(config_path="config.json"):
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    try:
        with open(path) as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"Config file {config_path} is not valid JSON "
            f"(line {e.lineno}, column {e.colno}): {e.msg}"
        ) from e
    logger.info(f"Config loaded from {config_path}")
    return config


def load_hosts(config):
    hosts_path = Path(config.get("paths", {}).get("hosts_file", "hosts.json"))
    if not hosts_path.exists():
        raise FileNotFoundError(f"Hosts file not found: {hosts_path}")
    with open(hosts_path) as f:
        hosts = json.load(f)
    logger.info(f"Hosts loaded from {hosts_path}")
    return hosts


def load_roles(config):
    """
    Load roles.json — the role-definition registry. Each role is a block
    of {name, description, notes}. A host's `role` field references role
    names; prompt_builder renders the matching description/notes as context
    so an admin writes "what's normal for this kind of host" ONCE per role
    instead of once per host.

    Unlike hosts.json, roles.json is OPTIONAL and missing is not an error:
    an existing deployment that predates the roles feature simply has no
    roles.json, and the pipeline must run fine without it (zero migration).
    A missing or unreadable file degrades to an empty registry — hosts with
    a `role` still render the bare role name, just without extra context.
    """
    roles_path = Path(config.get("paths", {}).get("roles_file", "roles.json"))
    if not roles_path.exists():
        logger.info(f"No roles file at {roles_path} — running without role context")
        return {"roles": []}
    try:
        with open(roles_path) as f:
            roles = json.load(f)
    except json.JSONDecodeError as e:
        logger.warning(
            f"Roles file {roles_path} is not valid JSON "
            f"(line {e.lineno}, column {e.colno}): {e.msg} — "
            f"running without role context"
        )
        return {"roles": []}
    logger.info(f"Roles loaded from {roles_path}")
    return roles


def build_role_lookup(roles_data):
    """
    Build a name -> role-block dict from roles.json for O(1) lookup by the
    role names referenced on hosts. Last definition wins on duplicate names
    (shouldn't happen — names are the unique key — but don't crash if it
    does). Case-insensitive keys to match host/role references leniently,
    consistent with how host name matching is case-insensitive.
    """
    lookup = {}
    for role in roles_data.get("roles", []):
        name = role.get("name", "")
        if name:
            lookup[name.lower()] = role
    return lookup


# ---------------------------------------------------------------------------
# Safe field access - any field may not exist
# ---------------------------------------------------------------------------

def safe_get(obj, *keys, default="N/A"):
    """
    Safely traverse nested dicts. Returns default if any key is missing,
    value is None, or value is empty string.
    """
    for key in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key, None)
        if obj is None:
            return default
    if obj == "":
        return default
    return obj


# ---------------------------------------------------------------------------
# Position tracker - remembers where we left off in alerts.json
# Default path is .ingest_position in the current working directory.
# Override via config.paths.position_file.
# ---------------------------------------------------------------------------

# Bytes of the file head used as a rotation signature. The leading
# bytes of a Wazuh alert line carry the timestamp, so a rotated file's
# first line differs; appends never touch them.
HEAD_BYTES = 40


def _position_file(config=None):
    """Resolve the position file path from config, with a sensible default."""
    if config:
        configured = config.get("paths", {}).get("position_file", "")
        if configured:
            return configured
    return os.path.join(os.getcwd(), ".ingest_position")


def load_position(config=None):
    """
    Return the saved position STATE from disk as a dict:
      {"offset": int, "head": str|None, "fresh": bool}
    where "head" is a signature of the file's first HEAD_BYTES bytes at
    save time. The authoritative rotation/truncation decision is made in
    read_new_alerts against the OPEN file (size + current head) — this
    only reports what's on disk. Three on-disk shapes are handled:
      - missing file          -> {"fresh": True}  (read_new_alerts starts
                                 at EOF: new alerts only — see _resolve_position)
      - JSON {head, offset}   -> full content-signature state
      - legacy bare integer   -> offset with head unknown (upgraded to
                                 JSON on the next save)
    """
    path = _position_file(config)
    if not os.path.exists(path):
        return {"fresh": True}
    with open(path) as f:
        raw = f.read().strip()
    if raw.startswith("{"):
        try:
            d = json.loads(raw)
            return {"offset": int(d.get("offset", 0)),
                    "head": d.get("head"), "fresh": False}
        except (ValueError, TypeError):
            return {"offset": 0, "head": None, "fresh": False}
    try:
        return {"offset": int(raw), "head": None, "fresh": False}
    except ValueError:
        return {"offset": 0, "head": None, "fresh": False}


def _head_signature(text):
    """Signature of a file's leading bytes, used to detect rotation."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _resolve_position(state, cur_head, size):
    """
    Decide the read offset from saved state and the current file's
    leading-content signature + size. Returns (position, reset);
    reset=True means we jumped to 0 and the caller must clear
    position-keyed retry state.

    Cases:
      1. fresh (no saved state)         -> EOF (size). First-run deploys
         skip a multi-hour backfill of historical alerts; LOAC test runs
         (harness deletes .ingest_position) start from a known state
         instead of being dominated by backfill.
      2. head matches, offset <= size   -> resume at offset (normal tail;
         appends never touch the leading bytes, so the head is stable)
      3. head matches, offset >  size    -> truncation in place; reset 0
      4. head DIFFERS                    -> rotation OR truncate-and-rewrite;
         reset 0 regardless of size. THIS is the launch-blocker fix: a
         downtime-spanning rotation whose new file already grew past the
         old offset has a different first line (newer timestamp), so we
         read it from the start instead of seeking mid-content and
         silently skipping. Works regardless of inode reuse, and also
         catches copytruncate-style rotation that inode comparison can't.
      5. legacy/unknown head (bare int)  -> one-cycle size heuristic (the
         old behavior); the next save upgrades the file to head-state.
    """
    if state.get("fresh"):
        logger.info(f"No position file found. Starting from end of "
                    f"alerts.json (offset={size}); new alerts only.")
        return size, False

    offset = state.get("offset", 0)
    shead = state.get("head")

    if shead is not None:
        if cur_head == shead:
            if offset <= size:
                return offset, False
            logger.warning(f"Offset {offset} exceeds size {size} with an "
                            f"unchanged file head - truncation. "
                            f"Resetting to 0.")
            return 0, True
        logger.warning("File head changed - rotation (or truncate-and-"
                        "rewrite). Reading the new file from the beginning.")
        return 0, True

    # Legacy bare-int state: no head recorded. Fall back to the old
    # size-only heuristic for this one cycle; save() rewrites head-state.
    if offset > size:
        logger.warning(f"Legacy position {offset} exceeds size {size} - "
                        f"rotation (size heuristic). Resetting to 0.")
        return 0, True
    return offset, False


def save_position(offset, head=None, config=None):
    """Persist position state atomically as JSON {path, head, offset}.

    Writes to a sibling tmp file then renames over the destination.
    A crash mid-write would otherwise leave the position file empty
    or partially written, which the loader can't parse — the pipeline
    would treat that as a fresh/zero state and reprocess. With atomic
    rename, the original position file stays intact through any partial
    write failure.

    head is a signature of the file's first HEAD_BYTES bytes at save
    time; on the next read a changed head means rotation (reset to 0)
    independent of size and independent of inode reuse — the rotation
    fix. It defaults to None only for transitional/legacy callers; the
    live read path always supplies it, which also upgrades any legacy
    bare-int file to JSON on the first save.
    """
    path = _position_file(config)
    alerts_file = ""
    if config:
        alerts_file = safe_get(config, "sources", "wazuh", "alerts_file",
                               default="") or ""
    state = {"path": alerts_file, "head": head, "offset": int(offset)}
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Alert reader
# ---------------------------------------------------------------------------

def read_alerts_batch(config, state, min_level=None, max_count=None):
    """
    Core reader: read up to max_count level-passing alerts starting from
    `state`, WITHOUT touching the position file. Returns
    (items, new_state) where:

      items     : list of (alert_dict, line_end_offset) tuples, in file
                  order. line_end_offset is the byte offset immediately
                  after the alert's line — i.e. the position value that,
                  if persisted, means "everything up to and including
                  this alert has been consumed."
      new_state : dict in the same shape load_position() returns
                  ({path, head, offset}) describing where the NEXT read
                  should resume. Suitable to pass straight back in on
                  the next call (in-memory continuation) and compatible
                  with _resolve_position's rotation detection.

    Position-file ownership is the CALLER's: the dedicated reader thread
    keeps new_state in memory and never writes the file; the submit side
    persists offsets at submit time (offset high-water). This is what
    decouples read cadence from submit/backpressure cadence — the reason
    this function exists. read_new_alerts() below wraps this for legacy
    callers (smoke tests) and preserves the old read-then-save behavior.

    state=None loads from the position file (process start / legacy).
    max_count=None uses config processing.max_batch_size (default 250).
    """
    alerts_file = safe_get(
        config, "sources", "wazuh", "alerts_file",
        default=None
    )

    if not alerts_file:
        logger.error("No wazuh alerts_file path in config")
        return [], state or {}

    if not os.path.exists(alerts_file):
        logger.error(f"Alerts file not found: {alerts_file}")
        return [], state or {}

    if min_level is None:
        min_level = config.get("filtering", {}).get("min_rule_level", 6)
    if max_count is None:
        max_count = config.get("processing", {}).get("max_batch_size", 250)
    max_batch = max_count

    if state is None:
        state = load_position(config)
    items = []
    count = 0

    # Track retry state across calls so a truly unparseable line eventually
    # gets skipped instead of freezing the pipeline forever. State lives on
    # the function object itself so it persists across calls within a
    # process without needing a module-level global.
    retry_state = _retry_state()
    max_retries = 5

    # errors="replace", NOT strict: a torn multibyte character at EOF
    # (Wazuh mid-write) makes readline() RAISE UnicodeDecodeError
    # before the partial-line defense below ever sees the line — and
    # a genuinely corrupt byte mid-file would raise at the same
    # position every cycle forever, freezing ingest exactly the way
    # the parse-retry cap was built to prevent. With replacement
    # decoding, both cases route into the defenses this loop already
    # has: torn-at-EOF becomes a newline-less line (partial-line
    # defense re-reads it clean next cycle), and corrupt-mid-file
    # becomes a JSON parse failure (retry cap skips it after 5).
    # Verified empirically against a torn UTF-8 sequence.
    with open(alerts_file, "r", errors="replace") as f:
        # Content-signature rotation/truncation detection. Read the
        # file's leading bytes from the SAME open handle (no second
        # open, no path stat — closes the TOCTOU window) and compare a
        # signature against the saved one. A changed head means the
        # file was rotated or truncated-and-rewritten, so we read from
        # 0 instead of seeking mid-content and silently skipping. This
        # keys on content, not inode, so it works regardless of inode
        # reuse and also catches copytruncate-style rotation. Appends
        # never touch the leading bytes, so a growing file keeps a
        # stable head and tails normally.
        size = os.fstat(f.fileno()).st_size
        f.seek(0)
        cur_head = _head_signature(f.read(HEAD_BYTES))
        position, reset = _resolve_position(state, cur_head, size)
        if reset:
            # Retry counters are keyed by FILE POSITION; pre-reset
            # entries must not inherit onto the new/truncated file's
            # offsets, or a fresh line at a previously-failing position
            # starts life with stale strikes and gets skipped early.
            retry_state.clear()
        new_position = position
        f.seek(position)
        while True:
            line_start_position = f.tell()
            line = f.readline()
            if not line:
                break
            line_end_position = f.tell()

            # Truly empty lines (whitespace only) - advance and continue.
            # These happen occasionally between log rotations and are harmless.
            stripped = line.strip()
            if not stripped:
                new_position = line_end_position
                continue

            # A line without a trailing newline is a partial write. Wazuh
            # is still writing this record. Leave position at line_start
            # so we re-read it on the next cycle once the write completes.
            if not line.endswith("\n"):
                logger.debug(
                    f"Partial line detected at position {line_start_position} "
                    f"(len={len(line)}) - will retry next cycle"
                )
                break

            # Attempt to parse. On failure, assume mid-write race (Wazuh
            # flushed a newline before the full record was buffered) and
            # retry next cycle WITHOUT advancing position. After max_retries
            # on the same position, skip the line and log a warning - this
            # protects against the theoretical "genuinely malformed line"
            # that would otherwise freeze the pipeline.
            try:
                alert = json.loads(stripped)
            except json.JSONDecodeError as e:
                retries = retry_state.get(line_start_position, 0) + 1
                retry_state[line_start_position] = retries
                if retries >= max_retries:
                    logger.warning(
                        f"Skipping line at position {line_start_position} "
                        f"after {retries} parse failures: {e}. "
                        f"Last {min(80, len(stripped))} chars: "
                        f"{stripped[:80]!r}"
                    )
                    # Clear this position from retry tracking and advance past it
                    del retry_state[line_start_position]
                    new_position = line_end_position
                    continue
                logger.debug(
                    f"Parse failed at position {line_start_position} "
                    f"(attempt {retries}/{max_retries}): {e} - will retry"
                )
                break  # do NOT advance - retry on next cycle

            # Success - clear any retry state for this position and advance
            retry_state.pop(line_start_position, None)
            new_position = line_end_position

            level = safe_get(alert, "rule", "level", default=0)
            try:
                level = int(level)
            except (ValueError, TypeError):
                level = 0

            if level >= min_level:
                # Stamp ingest-read time on the alert so
                # gelf_shipper can compute end-to-end pipeline latency
                # (process_time_s) at ship time. This is the truest
                # "received" timestamp from jrSOCtriage's perspective —
                # measures pipeline latency, not Wazuh's own delay.
                alert["_jrsoc_received_t"] = time.time()
                items.append((alert, line_end_position))
                count += 1
                if count >= max_batch:
                    logger.debug(
                        f"Batch limit {max_batch} reached, stopping read"
                    )
                    break

    # NO save_position here — position-file ownership is the caller's.
    # new_state mirrors the disk format so it round-trips through
    # _resolve_position on the next call (rotation detection included).
    new_state = {"path": alerts_file, "head": cur_head,
                 "offset": int(new_position)}
    return items, new_state


def read_new_alerts(config, min_level=None):
    """
    Legacy wrapper: reads new alerts since the persisted position,
    SAVES the position (read-time persistence, the pre-redesign
    behavior), and yields parsed alert dicts. Kept for standalone
    callers (module smoke tests, llm_caller's loader). The service
    main loop no longer uses this — it drives read_alerts_batch()
    from a dedicated reader thread and persists position at submit
    time instead.
    """
    items, new_state = read_alerts_batch(config, None, min_level=min_level)
    save_position(new_state.get("offset", 0), new_state.get("head"), config)
    logger.info(
        f"Read {len(items)} alerts at or above level "
        f"{min_level if min_level is not None else config.get('filtering', {}).get('min_rule_level', 6)}"
    )
    for alert, _offset in items:
        yield alert


def _retry_state():
    """
    Per-process retry counter for parse failures at specific file positions.
    Prevents the pipeline from freezing forever on a genuinely malformed
    line while still allowing transient partial-read races to recover.
    """
    if not hasattr(_retry_state, "_state"):
        _retry_state._state = {}
    return _retry_state._state


# ---------------------------------------------------------------------------
# Dedup key - built from whatever fields actually exist
# ---------------------------------------------------------------------------

def make_dedup_key(alert):
    """
    Build a dedup key from available fields.
    Absent fields are excluded so they don't create false uniqueness.

    Empty-key fallback: if every candidate field is "N/A" (a malformed
    alert with no usable identifying data — no rule.id, no agent.name,
    no IPs, no users), return a static "_malformed_" key. This collapses
    all such alerts to a single dedup bucket so a flood of malformed
    data gets suppressed by the silence window rather than each piece
    becoming its own storm. The key is explicit so operators searching
    journald for "_malformed_" find them.
    """
    candidates = [
        safe_get(alert, "rule", "id"),
        safe_get(alert, "agent", "name"),
        # Windows network alerts
        safe_get(alert, "data", "win", "eventdata", "ipAddress"),
        # Suricata/network alerts
        safe_get(alert, "data", "src_ip"),
        safe_get(alert, "data", "dest_ip"),
        # PAM/syslog alerts
        safe_get(alert, "data", "srcuser"),
        safe_get(alert, "data", "dstuser"),
    ]
    key_parts = [p for p in candidates if p != "N/A"]
    if not key_parts:
        return "_malformed_"
    return "|".join(key_parts)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    print("=== jrSOCtriage Ingestion Smoke Test ===\n")

    try:
        config = load_config("config.json")
        print(f"[OK] Config loaded")
        print(f"     Wazuh alerts file : {safe_get(config, 'sources', 'wazuh', 'alerts_file')}")
        print(f"     Min rule level    : {config.get('filtering', {}).get('min_rule_level', 6)}")
        print(f"     Max batch size    : {config.get('processing', {}).get('max_batch_size', 250)}")
        print()
    except FileNotFoundError as e:
        print(f"[FAIL] {e}")
        exit(1)

    try:
        hosts = load_hosts(config)
        host_count    = len(hosts.get("hosts", []))
        network_count = len(hosts.get("networks", []))
        print(f"[OK] Hosts file loaded")
        print(f"     Hosts    : {host_count}")
        print(f"     Networks : {network_count}")
        print()
    except FileNotFoundError as e:
        print(f"[FAIL] {e}")
        exit(1)

    print(f"[..] Reading alerts from Wazuh alerts file...")
    alerts = list(read_new_alerts(config))
    print(f"[OK] Found {len(alerts)} alert(s) at or above min level\n")

    for i, alert in enumerate(alerts[:3], 1):
        print(f"--- Alert {i} ---")
        print(f"  Timestamp   : {safe_get(alert, 'timestamp')}")
        print(f"  Rule ID     : {safe_get(alert, 'rule', 'id')}")
        print(f"  Level       : {safe_get(alert, 'rule', 'level')}")
        print(f"  Description : {safe_get(alert, 'rule', 'description')}")
        print(f"  Agent       : {safe_get(alert, 'agent', 'name')} ({safe_get(alert, 'agent', 'ip')})")
        print(f"  Dedup key   : {make_dedup_key(alert)}")
        print()

    print("=== Done ===")
