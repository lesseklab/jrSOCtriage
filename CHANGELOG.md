# Changelog

All notable changes to jrSOCtriage are documented here.

---

## Unreleased

### Fixed

- **ntopng interface ID of `0` could not be set or kept through the web interface.**
  A falsy-zero bug in the interface meant a saved `ifid: 0` was displayed as `1`,
  and saving *any* ntopng setting afterwards wrote `1` back to the config —
  silently breaking ntopng enrichment. `0` is a perfectly ordinary id — ntopng
  assigns ids by an interface's position in its own interface list, so the value
  you get depends entirely on your ntopng configuration.

  **If you use ntopng enrichment:** check `config.sources.ntopng.ifid` against the
  id shown in ntopng's interfaces list. If a previous save rewrote it, set it back
  and restart the service. Note that ntopng interface ids are **not stable**: they
  are positional, so an ntopng upgrade, a config change, or a state reset can renumber
  your interface. Re-check the id after any ntopng maintenance.

### Changed

- Default ntopng `ifid` is now `0` (was `1`). Neither value is universally correct —
  the id depends on your ntopng interface list — but `1` was an arbitrary guess that
  the interface then made impossible to override with `0`.
- The ifid field's hint no longer claims the value is "usually 1 or 2". It now explains
  that the id is positional, points the operator at ntopng's interfaces list, and warns
  that the id can change after ntopng maintenance.

---

## [1.0.0] — 2026-07-02

Initial public release.

- Wazuh alert ingestion, including Wazuh-ingested Suricata detections.
- Heterogeneous context enrichment: Graylog logs, Zeek flows, ntopng L7 active flows,
  and per-indicator intelligence (AbuseIPDB reputation, WHOIS, reverse DNS, GeoIP).
- Deterministic pre-LLM rules for escalation, suppression, and routing.
- Deduplication with aggregated database writes.
- LLM triage against local or cloud inference endpoints, with automatic failover and
  prompt anonymization for cloud endpoints.
- GELF shipping to Graylog and email notification for escalated verdicts.
- Web interface for configuration, host and role context, rules, and diagnostics.
