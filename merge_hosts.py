#!/usr/bin/env python3
"""
jrSOCtriage - hosts.json Merge Utility (standalone)

Folds a SOURCE hosts.json into a DESTINATION hosts.json so that hosts which
appear across security domains (relocated/mobile hosts, or servers everyone
talks to) carry their behavioral context when a *different* domain's sensors
alert on them.

This is a STANDALONE tool. It has no dependencies on a running jrSOCtriage
install and imports nothing from the pipeline - a corp admin can run it on any
machine with Python 3.

Merge rules (see hosts_instructions.txt for the hosts.json schema):
  - DESTINATION always wins a name collision. SOURCE can only ADD hosts the
    destination doesn't have; it never overwrites notes/roles you authored.
    Every collision is reported.
  - Networks merge on CIDR. Destination wins; a differing name on a matching
    CIDR is warned about.
  - By default, identifiers.ip is BLANKED on every host brought in from SOURCE.
    Merged hosts are cross-domain (mobile or talked-to); a blank IP resolves
    live and is correct for both mobile and static hosts. Use --keep-ips to
    preserve source IPs (rare).
  - The destination is written IN PLACE after an automatic timestamped backup,
    unless -o/--output redirects the result elsewhere.
  - Both inputs are validated as well-formed hosts.json BEFORE anything is
    backed up or written. Malformed input fails loudly and changes nothing.

Usage:
  sudo python3 merge_hosts.py test_management_hosts.json
      Merge test_management_hosts.json into ./hosts.json. Your hosts.json is
      updated in place; a timestamped backup of your original is written
      first (hosts.json.bak.<timestamp>). sudo is needed when your
      hosts.json is owner-only (mode 600).

  sudo python3 merge_hosts.py test_management_hosts.json -d /path/to/hosts.json
      Same, but point at your hosts.json explicitly instead of ./hosts.json.

  sudo python3 merge_hosts.py test_management_hosts.json --keep-ips
      Preserve the source hosts' identifiers.ip instead of blanking them.

The tool takes TWO inputs - the source (the sample/other-domain file you are
folding in) and your hosts.json - and writes the merged result back to your
hosts.json, after backing up your original.
"""

import argparse
import copy
import datetime
import json
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


class MergeError(Exception):
    """Raised for any condition that should stop the merge before writing."""
    pass


# --------------------------------------------------------------------------
# Load / validate
# --------------------------------------------------------------------------

def load_and_validate(path, label):
    """
    Load a hosts.json file and validate it is well-formed:
      - valid JSON
      - top-level object with 'hosts' and 'networks' keys, both lists
      - every host is an object with a non-empty 'name'
      - every network is an object with a non-empty 'cidr'
    Returns the parsed dict. Raises MergeError on any problem.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise MergeError(f"{label} file not found: {path}")
    except json.JSONDecodeError as e:
        raise MergeError(f"{label} file is not valid JSON ({path}): {e}")
    except OSError as e:
        raise MergeError(f"Could not read {label} file ({path}): {e}")

    if not isinstance(data, dict):
        raise MergeError(f"{label} ({path}): top level must be a JSON object.")

    for key in ("hosts", "networks"):
        if key not in data:
            raise MergeError(f"{label} ({path}): missing required '{key}' key.")
        if not isinstance(data[key], list):
            raise MergeError(f"{label} ({path}): '{key}' must be a list.")

    for i, host in enumerate(data["hosts"]):
        if not isinstance(host, dict):
            raise MergeError(f"{label} ({path}): hosts[{i}] is not an object.")
        name = host.get("name")
        if not isinstance(name, str) or not name.strip():
            raise MergeError(
                f"{label} ({path}): hosts[{i}] is missing a non-empty 'name'."
            )

    for i, net in enumerate(data["networks"]):
        if not isinstance(net, dict):
            raise MergeError(f"{label} ({path}): networks[{i}] is not an object.")
        cidr = net.get("cidr")
        if not isinstance(cidr, str) or not cidr.strip():
            raise MergeError(
                f"{label} ({path}): networks[{i}] is missing a non-empty 'cidr'."
            )

    return data


# --------------------------------------------------------------------------
# Merge
# --------------------------------------------------------------------------

def blank_host_ip(host):
    """
    Remove identifiers.ip from a host copy. If identifiers becomes empty as a
    result, drop the identifiers object entirely so the entry resolves live.
    Mutates and returns the passed-in host dict.
    """
    ident = host.get("identifiers")
    if isinstance(ident, dict) and "ip" in ident:
        del ident["ip"]
        if not ident:
            del host["identifiers"]
    return host


def merge(dest, source, keep_ips=False):
    """
    Merge source into a deep copy of dest and return (result, report).
    Destination wins every collision. Report is a dict of what happened.
    """
    result = copy.deepcopy(dest)
    report = {
        "hosts_added": [],
        "host_collisions": [],
        "networks_added": [],
        "network_collisions": [],
        "network_name_conflicts": [],
        "ips_blanked": 0,
    }

    # --- hosts: collision key is case-insensitive name ---
    dest_names = {h["name"].strip().lower() for h in result["hosts"]}

    for src_host in source["hosts"]:
        key = src_host["name"].strip().lower()
        if key in dest_names:
            report["host_collisions"].append(src_host["name"])
            continue
        new_host = copy.deepcopy(src_host)
        if not keep_ips:
            before = new_host.get("identifiers", {})
            had_ip = isinstance(before, dict) and "ip" in before
            blank_host_ip(new_host)
            if had_ip:
                report["ips_blanked"] += 1
        result["hosts"].append(new_host)
        dest_names.add(key)
        report["hosts_added"].append(new_host["name"])

    # --- networks: collision key is CIDR (normalized whitespace) ---
    dest_nets = {n["cidr"].strip(): n for n in result["networks"]}

    for src_net in source["networks"]:
        cidr = src_net["cidr"].strip()
        if cidr in dest_nets:
            report["network_collisions"].append(cidr)
            dest_name = (dest_nets[cidr].get("name") or "").strip()
            src_name = (src_net.get("name") or "").strip()
            if dest_name != src_name:
                report["network_name_conflicts"].append(
                    {"cidr": cidr, "dest_name": dest_name, "source_name": src_name}
                )
            continue
        result["networks"].append(copy.deepcopy(src_net))
        dest_nets[cidr] = src_net
        report["networks_added"].append(cidr)

    return result, report


# --------------------------------------------------------------------------
# Backup / write / report
# --------------------------------------------------------------------------

def backup_path_for(path):
    """Timestamped backup path: hosts.json -> hosts.json.bak.2026-06-30-142530"""
    stamp = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")
    return f"{path}.bak.{stamp}"


def write_json(path, data, mode=None):
    """
    Write data as pretty JSON to path. If mode is given (e.g. 0o600), the file
    is chmod'd to it after writing so a restrictive source file's permissions
    are not silently downgraded to the umask default on a fresh file (the
    backup) or a re-created one.
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    if mode is not None:
        try:
            import os
            os.chmod(path, mode)
        except OSError as e:
            logger.warning("Could not set permissions on %s: %s", path, e)


def get_mode(path):
    """Return the octal permission bits of an existing file, or None."""
    try:
        import os
        import stat as _stat
        return _stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


def print_report(report, dest_path, wrote_to, backup=None, keep_ips=False):
    logger.info("Merge complete.")
    logger.info("  Hosts added:        %d", len(report["hosts_added"]))
    for name in report["hosts_added"]:
        logger.info("      + %s", name)

    if report["host_collisions"]:
        logger.warning(
            "  Host name collisions (destination kept, source skipped): %d",
            len(report["host_collisions"]),
        )
        for name in report["host_collisions"]:
            logger.warning("      = %s (kept destination's entry)", name)

    logger.info("  Networks added:     %d", len(report["networks_added"]))
    for cidr in report["networks_added"]:
        logger.info("      + %s", cidr)

    if report["network_collisions"]:
        logger.warning(
            "  Network CIDR collisions (destination kept): %d",
            len(report["network_collisions"]),
        )
        for cidr in report["network_collisions"]:
            logger.warning("      = %s (kept destination's entry)", cidr)

    for conflict in report["network_name_conflicts"]:
        logger.warning(
            "  Network name differs on matching CIDR %s: destination='%s' source='%s' "
            "(kept destination's name)",
            conflict["cidr"], conflict["dest_name"], conflict["source_name"],
        )

    if keep_ips:
        logger.info("  IPs preserved (--keep-ips).")
    else:
        logger.info("  IPs blanked on merged hosts: %d", report["ips_blanked"])

    if backup:
        logger.info("  Backup of destination written: %s", backup)
    logger.info("  Result written to: %s", wrote_to)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Merge a source hosts.json (e.g. a sample from another "
                    "domain) into YOUR hosts.json. Your file is updated in "
                    "place; a timestamped backup of your original is made "
                    "first. Your file always wins on any collision."
    )
    parser.add_argument(
        "source",
        help="The source hosts.json to fold in (e.g. test_management_hosts.json)."
    )
    parser.add_argument(
        "-d", "--destination", default="hosts.json",
        help="YOUR hosts.json - the file that gets updated in place "
             "(default: ./hosts.json)."
    )
    parser.add_argument(
        "--keep-ips", action="store_true",
        help="Preserve identifiers.ip from source hosts (default: blank them)."
    )

    args = parser.parse_args()

    try:
        # Validate BOTH inputs before touching anything on disk.
        source = load_and_validate(args.source, "Source")
        dest = load_and_validate(args.destination, "Your hosts.json")

        result, report = merge(dest, source, keep_ips=args.keep_ips)

        # Preserve your file's permission bits so a restrictive file (e.g. 600)
        # does not get a world-readable backup or rewrite.
        dest_mode = get_mode(args.destination)

        # Back up your original first, then write the merged result in place.
        backup = backup_path_for(args.destination)
        write_json(backup, dest, mode=dest_mode)
        write_json(args.destination, result, mode=dest_mode)
        print_report(report, args.destination, wrote_to=args.destination,
                     backup=backup, keep_ips=args.keep_ips)

    except MergeError as e:
        logger.error(str(e))
        logger.error("No files were modified.")
        sys.exit(1)
    except Exception as e:  # noqa: BLE001 - last-resort guard for a CLI tool
        logger.error("Unexpected error: %s", e)
        logger.error("No files were modified.")
        sys.exit(1)


if __name__ == "__main__":
    main()
