#!/usr/bin/env python3
"""
jrSOCtriage - Rules Engine Module

The policy layer that runs BEFORE the LLM decision. Reads rules.json
and evaluates per-rule behavior: first-seen detection, rate limiting,
force-escalation conditions, escalate-if conditions, never_escalate
overrides, and maintenance mode.

Design note: never_escalate creates permanent blind spots. Prefer the
"note" field (explain the rule to the LLM) over never_escalate. See
running_instructions.txt for the full philosophy.

Rule schema validation: the web interface enforces rules.json structure
at save time. If editing rules.json by hand, load it through the
interface once and Save to get the UI validation pass.
"""

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Default is relative to the pipeline working directory.
# Override via config.paths.rules_file.
DEFAULT_RULES_PATH = "rules.json"

# ReDoS protection: cap the input length passed to user-defined regex
# patterns. Pathological patterns ((a+)+, etc.) combined with long input
# can hang the worker thread. A length cap is a cheap, effective defense
# that costs nothing on real-world fields.
REGEX_INPUT_CAP = 2000


# ---------------------------------------------------------------------------
# Load rules
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Rules load cache
#
# main.py loads rules once at startup and passes them down the hot path,
# so today this cache mostly never re-fires. It exists as defense in
# depth: evaluate_rule() has a rules-is-None fallback that calls
# load_rules() per alert, and any future caller that forgets to pass
# rules through would silently re-read and re-parse rules.json from disk
# on every alert with no log evidence (found during the 2026-06-11 LOAC
# throughput investigation — the same silent-per-call pattern cost
# graylog ~24ms/alert). Keyed on (path, mtime): edits to rules.json are
# still picked up because a changed mtime invalidates the entry, so any
# future hot-reload semantics keep working.
# ---------------------------------------------------------------------------
import threading as _threading

# REG-22: lock-free rules read via a single published reference (copy-on-write).
# load_rules() is called per-alert on the escalation path, and the old design
# took `_rules_cache_lock` on EVERY read (a shared mutex per alert) even though
# rules.json is essentially static and the read is a near-always cache hit. That
# shared lock is a convoy serialization point. New design:
#   - `_rules_published` holds the current (ckey, rules_dict) as a SINGLE module
#     reference. Reading a Python global reference is atomic under both the GIL
#     and free-threading, so READERS take NO lock — they read the reference, the
#     cheap mtime stat, and compare ckeys. On a match they return immediately.
#   - Only the WRITER (cache miss / mtime change) takes `_rules_write_lock`, to
#     serialize the reload + atomic reference swap (one writer wins, others see
#     the freshly-published reference). This is the same off-the-read-path shape
#     as the async db-writer: contention only on the rare reload, never the hit.
# The cached rules dict is treated as IMMUTABLE after publication — load_rules
# builds a NEW dict each reload and swaps the reference; readers never mutate it
# (verified: evaluate_rule/record_rule_escalation/main only .get() off it). The
# read path STILL returns a defensive copy (dict(...)) — dropping that copy is a
# separate, caller-contract-changing optimization not needed for the lock removal
# and deliberately NOT done here.
_rules_published = None          # (ckey, rules_dict) — atomically swapped
_rules_write_lock = _threading.Lock()


def load_rules(config):
    """
    Load rules.json. Returns dict keyed by rule_id for fast lookup.
    Returns empty dict if file is missing or disabled.

    Malformed individual rules (missing rule_id, non-list escalate_if,
    etc.) are logged and skipped rather than crashing the pipeline.
    The web interface enforces structure at save time, so most hand-edit
    errors can be fixed by loading rules.json through the UI and saving.
    """
    global _rules_published  # REG-22: read (lock-free) + written (under lock) below
    rules_path = config.get("paths", {}).get("rules_file", DEFAULT_RULES_PATH)

    if not Path(rules_path).exists():
        logger.debug(f"rules.json not found at {rules_path} — rule engine inactive")
        return {}

    # Cache check — see the rules-load-cache comment above. mtime in the
    # key means an edited file is a miss and reloads naturally.
    try:
        _mtime = Path(rules_path).stat().st_mtime
    except OSError:
        _mtime = None
    _ckey = (str(rules_path), _mtime)
    if _mtime is not None:
        # REG-22: LOCK-FREE read. Grab the published reference once (atomic
        # global read), and if its ckey matches the current (path, mtime),
        # return a defensive copy. No lock on the hit path — the common case.
        _pub = _rules_published
        if _pub is not None and _pub[0] == _ckey:
            return dict(_pub[1])

    try:
        with open(rules_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to load rules.json: {e}")
        return {}

    # Accept the plain-array legacy format ([...] instead of
    # {"rules": [...]}). The web interface explicitly tolerates it on
    # read (api_rules GET unwraps both shapes), so the pipeline must
    # load what the interface advertises as readable — previously a
    # bare-array file raised AttributeError here and failed startup.
    # The interface normalizes to the wrapped form on every save, so
    # this only triggers on hand-made files.
    if isinstance(data, list):
        data = {"rules": data}

    rules = {}
    for entry in data.get("rules", []):
        rule_id = str(entry.get("rule_id", "")).strip()
        if not rule_id:
            logger.warning(f"rules.json entry missing rule_id, skipped: {entry}")
            continue

        # Light structural sanity check — catch common hand-edit errors
        # without pulling in a full schema validator.
        try:
            for list_field in ("escalate_if", "force_escalate_if", "host_notes"):
                val = entry.get(list_field)
                if val is None:
                    continue
                if list_field == "host_notes":
                    if not isinstance(val, dict):
                        raise ValueError(f"'{list_field}' must be an object")
                else:
                    if not isinstance(val, list):
                        raise ValueError(f"'{list_field}' must be a list")
            # Type checks for fields that would otherwise crash per-alert
            # at evaluation time (the condition evaluator's try/except does
            # not cover these paths):
            #   condition_logic reaches logic.upper() in evaluate_conditions
            #     -> AttributeError if not a string.
            #   max_escalations_per_hour reaches `count < max_per_hour` in
            #     database.check_rate_limit, OUTSIDE its fail-open try
            #     -> TypeError if not numeric (e.g. "4" as a string).
            # The web UI enforces types at save; this protects hand-editors.
            cl = entry.get("condition_logic")
            if cl is not None and not isinstance(cl, str):
                raise ValueError("'condition_logic' must be a string (\"AND\" or \"OR\")")
            mph = entry.get("max_escalations_per_hour")
            if mph is not None and isinstance(mph, bool):
                raise ValueError("'max_escalations_per_hour' must be a number")
            if mph is not None and not isinstance(mph, (int, float)):
                raise ValueError("'max_escalations_per_hour' must be a number")
        except ValueError as e:
            logger.warning(f"rules.json rule_id={rule_id} is malformed ({e}), skipped")
            continue

        # Detect duplicate rule_id. Hand-edited rules.json can end up with
        # two entries sharing a rule_id; without this check, the later
        # entry silently overwrites the earlier one and the operator sees
        # "my first rule isn't being applied" without any indication why.
        # The web interface enforces uniqueness on save, so this only
        # bites operators who hand-edit the file. Warn loudly so it
        # surfaces in pipeline startup logs and is searchable in journald.
        if rule_id in rules:
            logger.warning(
                f"rules.json contains duplicate rule_id={rule_id} — "
                f"the later entry overrides the earlier one. "
                f"Load and re-save through the web interface to deduplicate."
            )

        rules[rule_id] = entry

    logger.info(f"Loaded {len(rules)} rule entries from {rules_path}")
    if _mtime is not None:
        # REG-22: publish the freshly-built dict by atomically swapping the
        # module reference under the writer lock. Concurrent reloaders are
        # harmless (same mtime -> equivalent dict, last-write-wins), and after
        # this returns every lock-free reader sees the new (ckey, rules).
        with _rules_write_lock:
            _rules_published = (_ckey, rules)
    return dict(rules)


# ---------------------------------------------------------------------------
# Condition evaluator
# ---------------------------------------------------------------------------

def _get_field(enrichment, field):
    """
    Retrieve a field value from the enrichment dict.
    Supports dot notation for nested fields: "ips.all"
    Supports integer path segments for list indexing: "external_context.0.abuse_score"
    Returns None if the path cannot be resolved.
    """
    parts = field.split(".")
    val = enrichment
    for part in parts:
        if isinstance(val, dict):
            val = val.get(part)
        elif isinstance(val, list):
            # Integer path segment indexes into the list.
            try:
                idx = int(part)
            except ValueError:
                return None
            if idx < 0 or idx >= len(val):
                return None
            val = val[idx]
        else:
            return None
    return val


def _is_empty(val):
    """Return True if value is None, empty string, empty list, or 'N/A'."""
    if val is None:
        return True
    if isinstance(val, str) and val.strip() in ("", "N/A"):
        return True
    if isinstance(val, (list, dict)) and len(val) == 0:
        return True
    return False


def evaluate_condition(condition, enrichment):
    """
    Evaluate a single condition dict against the enrichment dict.
    Returns True if condition passes, False otherwise.

    Missing-field semantics:
      - "exists"     returns False when the field is missing.
      - "not_exists" returns True  when the field is missing.
      - "eq", "contains", "in", "gt/lt/gte/lte", "matches" all return
        False when the field is missing (can't compare what isn't there).
      - "not_eq", "not_in" return True  when the field is missing
        (consistent with not_exists — "it isn't X because it isn't
        anything"). If strict inequality is needed, pair with "exists".
    """
    field  = condition.get("field", "")
    op     = condition.get("op", "").lower()
    value  = condition.get("value")

    field_val = _get_field(enrichment, field)

    try:
        if op == "exists":
            return not _is_empty(field_val)

        elif op == "not_exists":
            return _is_empty(field_val)

        elif op == "eq":
            if _is_empty(field_val):
                return False
            return str(field_val).lower() == str(value).lower()

        elif op == "not_eq":
            if _is_empty(field_val):
                return True
            return str(field_val).lower() != str(value).lower()

        elif op == "contains":
            if _is_empty(field_val):
                return False
            return str(value).lower() in str(field_val).lower()

        elif op == "in":
            if _is_empty(field_val):
                return False
            if not isinstance(value, list):
                value = [value]
            return str(field_val).lower() in [str(v).lower() for v in value]

        elif op == "not_in":
            if _is_empty(field_val):
                return True
            if not isinstance(value, list):
                value = [value]
            return str(field_val).lower() not in [str(v).lower() for v in value]

        elif op in ("gte", "lte", "gt", "lt"):
            if _is_empty(field_val):
                return False
            try:
                num_field = float(field_val)
                num_value = float(value)
            except (ValueError, TypeError):
                return False
            if op == "gte": return num_field >= num_value
            if op == "lte": return num_field <= num_value
            if op == "gt":  return num_field >  num_value
            if op == "lt":  return num_field <  num_value
            return False  # defensive — should be unreachable

        elif op == "matches":
            if _is_empty(field_val):
                return False
            # ReDoS protection: cap input length so a pathological regex
            # cannot hang the worker thread on a long field value.
            field_str = str(field_val)
            if len(field_str) > REGEX_INPUT_CAP:
                logger.warning(
                    f"matches: field {field!r} exceeds {REGEX_INPUT_CAP} chars "
                    f"({len(field_str)}), truncating for regex evaluation"
                )
                field_str = field_str[:REGEX_INPUT_CAP]
            return bool(re.search(str(value), field_str, re.IGNORECASE))

        else:
            logger.warning(f"Unknown operator '{op}' in condition: {condition}")
            return False

    except Exception as e:
        logger.warning(f"Condition evaluation error {condition}: {e}")
        return False


def evaluate_conditions(conditions, enrichment, logic="AND"):
    """
    Evaluate a list of conditions against enrichment.
    logic="AND": all must pass. logic="OR": any must pass.
    Returns True if conditions pass, False otherwise.
    Empty conditions list returns True.
    """
    if not conditions:
        return True

    results = [evaluate_condition(c, enrichment) for c in conditions]

    if logic.upper() == "OR":
        return any(results)
    else:
        return all(results)


# ---------------------------------------------------------------------------
# Main rules engine decision
# ---------------------------------------------------------------------------

def evaluate_rule(rule_id, enrichment, config, conn, rules=None):
    """
    Main entry point. Evaluate rules.json for a specific rule_id.

    Returns dict:
    {
        "should_escalate":   bool,   # final escalation decision
        "force_escalate":    bool,   # overrides min_rule_level
        "reason":            str,    # human readable reason
        "rate_limit_hit":    bool,   # True if rate limit was the deciding factor
        "first_seen":        bool,   # True if first time this rule+host seen
        "maintenance_mode":  bool,   # True if host is in maintenance mode
    }
    """
    from database import (
        check_rate_limit, is_first_seen, is_in_maintenance_mode,
    )

    canonical_hostname = enrichment.get("canonical_hostname", "unknown")

    result = {
        "should_escalate":  None,   # None = defer to normal pipeline logic
        "force_escalate":   False,
        "reason":           "no rule entry",
        "rate_limit_hit":   False,
        "first_seen":       False,
        "maintenance_mode": False,
    }

    # --- Maintenance mode check ---
    if is_in_maintenance_mode(conn, canonical_hostname):
        result["maintenance_mode"] = True
        # In maintenance mode, suppress unless external IP present
        has_external = not _is_empty(_get_field(enrichment, "external_ips"))
        if not has_external:
            result["should_escalate"] = False
            result["reason"] = "maintenance mode active — no external IP"
            return result
        else:
            # External IP overrides maintenance mode — fall through so the
            # rest of the rule logic (first_seen, escalate_if, rate limits)
            # still applies. Do NOT short-circuit to escalate here.
            result["reason"] = "maintenance mode active but external IP present — escalating"

    # --- First-seen escalation ---
    filtering = config.get("filtering", {})
    if filtering.get("escalate_first_seen_rule", True):
        lookback = filtering.get("first_seen_lookback_days", 14)
        if is_first_seen(conn, rule_id, canonical_hostname, lookback_days=lookback):
            result["first_seen"] = True
            result["force_escalate"] = True
            result["should_escalate"] = True
            result["reason"] = f"first seen in {lookback}-day window — escalating"
            # Still apply rate limit even for first-seen
            # (prevents first-seen from being spammed on rule_id churn)

    # --- Look up rule entry ---
    if rules is None:
        rules = load_rules(config)

    rule_entry = rules.get(str(rule_id))

    if not rule_entry:
        # No rule entry — return first-seen result or defer
        if result["first_seen"]:
            return result
        result["reason"] = "no rule entry — defer to pipeline"
        return result

    # --- never_escalate (hard stop) ---
    if rule_entry.get("never_escalate", False):
        result["should_escalate"] = False
        result["force_escalate"]  = False
        result["reason"] = "never_escalate set in rules.json"
        return result

    # --- force_escalate_if ---
    force_conditions = rule_entry.get("force_escalate_if", [])
    if force_conditions:
        logic = rule_entry.get("condition_logic", "AND")
        if evaluate_conditions(force_conditions, enrichment, logic):
            result["force_escalate"]  = True
            result["should_escalate"] = True
            result["reason"] = "force_escalate_if conditions met"

    # --- escalate_if ---
    if not result["force_escalate"] and not result["first_seen"]:
        escalate_conditions = rule_entry.get("escalate_if", [])
        if escalate_conditions:
            logic = rule_entry.get("condition_logic", "AND")
            if not evaluate_conditions(escalate_conditions, enrichment, logic):
                result["should_escalate"] = False
                result["reason"] = "escalate_if conditions not met"
                return result
            else:
                result["should_escalate"] = True
                result["reason"] = "escalate_if conditions met"

    # --- Rate limit check ---
    # Note on first-seen interaction: if first-seen earlier set
    # should_escalate=True and force_escalate=True, the rate limit still
    # applies and CAN suppress the alert by setting should_escalate=False.
    # This is intentional — rule_id churn (e.g., a misconfigured rule
    # producing a stream of new rule_id values) would otherwise spam the
    # operator with a "first-seen" alert for every new ID. Rate limiting
    # caps that. The tradeoff: a genuine first-seen alert can be silenced
    # if rate limit is hit before it reaches the operator. Acceptable
    # because the rate limit is per-rule + per-host, so an actually-new
    # rule on an actually-new host gets its first alert through unless
    # max_escalations_per_hour is set absurdly low.
    max_per_hour = rule_entry.get("max_escalations_per_hour")
    if max_per_hour is not None and result["should_escalate"] is not False:
        scope = rule_entry.get("rate_limit_scope", "host")
        if not check_rate_limit(conn, rule_id, canonical_hostname, max_per_hour, scope):
            result["should_escalate"] = False
            result["rate_limit_hit"]  = True
            result["reason"] = (
                f"rate limit hit — max {max_per_hour}/hr "
                f"(scope={scope})"
            )
            return result

    # Final default — if nothing set should_escalate, defer to pipeline
    if result["should_escalate"] is None:
        result["reason"] = "rule entry found, no conditions — defer to pipeline"

    return result


# ---------------------------------------------------------------------------
# Record escalation after decision
# ---------------------------------------------------------------------------

def record_rule_escalation(conn, rule_id, canonical_hostname, rules=None, config=None):
    """
    Call this after a rule has been escalated to increment rate limit counter.
    """
    from database import record_escalation

    scope = "host"
    if rules and str(rule_id) in rules:
        scope = rules[str(rule_id)].get("rate_limit_scope", "host")

    record_escalation(conn, rule_id, canonical_hostname, scope=scope)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    from ingest import load_config

    print("=== jrSOCtriage Rules Engine Smoke Test ===\n")
    # NOTE: this smoke test is position-safe by construction — it uses
    # inline test enrichments and never calls read_new_alerts(), so it
    # does NOT advance .ingest_position and is safe to run against a
    # live pipeline. (Unlike the other module smoke tests — see their
    # KNOWN BUG comments.) Keep it that way.

    config = load_config("config.json")
    rules  = load_rules(config)

    print(f"Loaded {len(rules)} rule entries\n")

    # Test condition evaluation
    test_enrichment = {
        "canonical_hostname": "Laptop1",
        "gl2_rule_id": "550",
        "gl2_rule_level": 7,
        "external_ips": [],
        "internal_ips": ["10.6.0.4"],
        "gl2_abuse_score": "N/A",
    }

    print("Test: Laptop1 FIM alert, no external IP")
    print(f"  external_ips exists: {evaluate_condition({'field': 'external_ips', 'op': 'exists'}, test_enrichment)}")
    print(f"  external_ips not_exists: {evaluate_condition({'field': 'external_ips', 'op': 'not_exists'}, test_enrichment)}")

    test_enrichment2 = dict(test_enrichment)
    test_enrichment2["external_ips"] = ["50.116.26.161"]
    test_enrichment2["gl2_abuse_score"] = 100

    print("\nTest: dmz-web-01 alert, external IP with abuse score 100")
    print(f"  external_ips exists: {evaluate_condition({'field': 'external_ips', 'op': 'exists'}, test_enrichment2)}")
    print(f"  abuse_score gte 50: {evaluate_condition({'field': 'gl2_abuse_score', 'op': 'gte', 'value': 50}, test_enrichment2)}")

    print("\n=== Done ===")
