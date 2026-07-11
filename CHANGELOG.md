# Changelog

All notable changes to jrSOCtriage are documented here.

---

## Unreleased

### Fixed

- **ntopng interface ID of `0` could not be set or kept through the web interface.**
  A falsy-zero bug in the interface meant a saved `ifid: 0` was displayed as `1`,
  and saving *any* ntopng setting afterwards wrote `1` back to the config —
  silently breaking ntopng enrichment. Because a single-interface ntopng
  commonly registers as id `0`, this affected the most typical deployment.

  **If you use ntopng enrichment:** check `config.sources.ntopng.ifid` against the
  id shown in ntopng's interfaces list. If a previous save rewrote it, set it back
  and restart the service. Note that ntopng interface ids are not stable — they can
  change after an ntopng upgrade or a state reset.

### Changed

- Default ntopng `ifid` is now `0` (was `1`). ntopng ids are 0-indexed and a single
  monitored interface commonly registers as `0`.
- The ifid field's hint no longer claims the value is "usually 1 or 2". It now points
  the operator at ntopng's interfaces list and warns that the id can change.

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
