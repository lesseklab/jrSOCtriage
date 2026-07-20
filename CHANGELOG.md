# Changelog

All notable changes to jrSOCtriage are documented here.

---

## [1.1.2] — 2026-07-20

### Fixed

- **The service could not start from a clean install.** `main.py` imports
  `lag_logger` unconditionally during startup, but the module was not included
  in the distribution, so the pipeline raised `ModuleNotFoundError: lag_logger`
  the moment the service was started.

  **This affected 1.0.0, 1.1.0, and 1.1.1.** It is distinct from the 1.1.1 fix
  and was not covered by it: the 1.1.1 issue failed at *module import*, while
  this one failed later, at *service start*, so a successful `import main` did
  not reveal it.

  `lag_logger.py` is now part of the distribution, where it belongs. It is
  product code rather than tooling: it provides the `NullLagState` object used
  on the default path when observability is disabled, and it implements the
  `[LAG]` diagnostic line documented in the configuration reference and the
  FAQ, controlled by `observability.lag_log_interval_seconds`.

  No configuration change is required. `[LAG]` output remains off by default.

---

## [1.1.1] — 2026-07-20

### Fixed

- **The pipeline could not start from a clean install.** `enrich.py`,
  `graylog_fetch.py`, and `ntopng_fetch.py` imported `perf_diag`, an internal
  diagnostic counter module that is deliberately not part of the distribution.
  A fresh clone therefore failed at import with
  `ModuleNotFoundError: perf_diag` before the service could start.

  **This affected 1.0.0 and 1.1.0.** It was invisible in development because
  the module is present there.

  The import is now guarded and falls back to a no-op stub covering the full
  call surface, so the absence of the diagnostic module can never stop the
  pipeline. Behavior is unchanged where the module is present.

  `perf_diag` remains excluded from the distribution deliberately: it takes a
  lock on the per-alert path when enabled, which is exactly the class of
  worker-serialization point removed during the concurrency hardening work.
  The instrumentation call sites stay in place as permanent hooks — dropping
  the module into an install enables them, and its absence disables them.

  No configuration change is required, and no configuration key is affected.

---

## [1.1.0] — 2026-07-19

### Added

- **Five per-indicator threat-intelligence sources**, each with its own config
  card, prompt section with interpretation guidance for the LLM, and flat
  Graylog fields for searching (see `graylog_searches.txt`, "Threat
  Intelligence Searches"). Every source supports the vendor's free tier and
  commercial tier through the same integration; per-source rate-limit
  warnings are off by default and can be enabled per card.
  - **GreyNoise** — is the source IP scanning the whole internet, or just
    you. `not_seen` (not mass-scanning) is the targeted-activity signal.
    Ships `gl2_greynoise_class`.
  - **CISA KEV** — is the alert's CVE confirmed actively exploited in the
    wild. Catalog cached locally (24h refresh, non-blocking, stale-serve
    with visible annotations when the CISA feed is unreachable). Ships
    `gl2_kev_listed`.
  - **EPSS** — modeled probability the CVE will be exploited in the next
    30 days; renders beside KEV so confirmed-past and likely-future
    exploitation are read together. Ships `gl2_epss_max`.
  - **VirusTotal** — antivirus engine detections for file hashes (FIM
    alerts) and external IPs, with a per-alert lookup cap for free-tier
    quota protection (over-cap hashes annotate `NOT_CHECKED`, never
    silently skipped). Ships `gl2_vt_malicious`.
  - **AlienVault OTX** — community threat reports (pulses) referencing the
    alert's hashes or external IPs. Works keyless at a lower rate ceiling;
    pulse names are unvetted community labels and the prompt says so.
    Ships `gl2_otx_pulses`.
- **Mentioned-IP intel fields.** External IPs that appear in an alert's
  raw log text (as opposed to the alert's structured source/destination
  parties) now ship their own worst-of Graylog fields:
  `gl2_mentioned_greynoise_worst` and `gl2_mentioned_abuse_max`. The
  party fields (`gl2_greynoise_class`, `gl2_abuse_score`) stay
  party-only by design — a domain controller alert whose log happens to
  contain a resolved malicious IP never ships a malicious class on the
  party fields, but the mention is now searchable in its own right.
  On hash-bearing alerts (and only those), VirusTotal and OTX also run
  on mentioned external IPs — IP reputation corroborating hash intel on
  the same record — rendering on the mentioned line and shipping
  `gl2_mentioned_vt_malicious` / `gl2_mentioned_otx_pulses`; hash-less
  alerts spend no VT/OTX quota on mentioned IPs.
- **Config tab split into two sub-tabs** — "Source & Enrich" and
  "Processing, LLM & Etc." — replacing the single thirteen-card panel.
  Sub-tab choice is deliberately not remembered between visits; settings in
  both sub-tabs save together exactly as before.

### Changed

- **AbuseIPDB rate-limit handling now fails loud.** A 429 during normal
  operation logs an operator WARNING naming the unchecked IP, annotates the
  record `RATE_LIMITED` instead of a silent `N/A`, and never caches the
  degraded result — the next alert re-asks as soon as quota recovers.
  Rationale: hitting a free-tier rate limit mid-operation often *is* the
  attack signal (elevated external-IP volume); silently skipping reputation
  lookups at that exact moment is the wrong behavior. All v1.1 sources
  inherit this contract.

- **The startup `[DIAG]` watchdog line prints only when the stall
  watchdog is actually enabled.** The watchdog is dormant, disabled by
  default, and undocumented; a startup log advertising
  `watchdog_enabled=False` for a subsystem no operator can find in any
  doc invited the wrong curiosity. Enabling it (an undocumented
  diagnostics setting) restores the line.

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

- Default ntopng `ifid` is now `0` (was `1`). Neither value is universally correct —
  the id depends on your ntopng interface list — but `1` was an arbitrary guess that
  the interface then made impossible to override with `0`.
- The ifid field's hint no longer claims the value is "usually 1 or 2". It now explains
  that the id is positional, points the operator at ntopng's interfaces list, and warns
  that the id can change after ntopng maintenance.
- **Two settings fields rejected server-valid values.** `min_baseline_days`
  and `first_seen_lookback_days` were bounded 1–30 and 1–90 in the web
  interface while the server accepts 0–365 for both. `0` is meaningful —
  for `min_baseline_days` it means "no baseline history required". The
  interface now permits the full server-declared range.
- **Six more settings fields could not hold a saved `0`** — the same
  falsy-zero bug class as the ntopng ifid fix above: a saved `0`
  displayed as the field's default, and any subsequent save wrote the
  default back. Affected: Graylog source context window and max results,
  Graylog output port, and per-endpoint priority, timeout, and max
  concurrent. Check these fields against your `config.json` if you ever
  set one to `0` and found it reverted.

### Removed

- **Dead "include full JSON" toggle removed from the Config tab.** It was
  wired to nothing — the pipeline never read it. If your `config.json`
  still contains an `include_full_json` key, it is inert and can be
  deleted or ignored.

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
