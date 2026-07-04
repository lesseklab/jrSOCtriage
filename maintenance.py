#!/usr/bin/env python3
"""
jrSOCtriage - Maintenance Mode CLI
Set or clear maintenance mode for a host.

Usage:
  sudo python3 maintenance.py --host linuxlite --minutes 60
  sudo python3 maintenance.py --host linuxlite --clear
  sudo python3 maintenance.py --status
"""

import argparse
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="jrSOCtriage maintenance mode manager"
    )
    parser.add_argument("--host",    type=str, help="Canonical hostname")
    parser.add_argument("--minutes", type=int, help="Duration in minutes")
    parser.add_argument("--clear",   action="store_true", help="Clear maintenance mode for host")
    parser.add_argument("--status",  action="store_true", help="Show all hosts in maintenance mode")
    parser.add_argument("--config",  type=str, default="config.json", help="Path to config.json")

    args = parser.parse_args()

    from ingest import load_config
    from database import get_connection, set_maintenance_mode, clear_maintenance_mode, get_maintenance_status

    config = load_config(args.config)
    conn   = get_connection(config)

    try:
        if args.status:
            hosts = get_maintenance_status(conn)
            if not hosts:
                print("No hosts currently in maintenance mode.")
            else:
                print(f"{'HOST':<20} {'REMAINING':>12}  SET BY")
                print("-" * 45)
                for h in hosts:
                    print(f"{h['host']:<20} {h['remaining_minutes']:>10}m  {h['set_by']}")
            return

        if not args.host:
            parser.print_help()
            sys.exit(1)

        if args.clear:
            clear_maintenance_mode(conn, args.host)
            print(f"Maintenance mode cleared for {args.host}")
            return

        if args.minutes is None:
            print("Error: --minutes required when setting maintenance mode")
            sys.exit(1)
        if args.minutes <= 0:
            print(f"Error: --minutes must be a positive number (got {args.minutes})")
            sys.exit(1)

        set_maintenance_mode(conn, args.host, args.minutes)
        print(f"Maintenance mode set for {args.host} — {args.minutes} minutes")
        print(f"Non-external alerts will be suppressed from LLM triage.")
        print(f"All alerts still ship to Graylog.")
        print(f"Clear early with: sudo python3 maintenance.py --host {args.host} --clear")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
