# jrSOCtriage Roadmap: v1.0 to v2.0

This document outlines the planned evolution of jrSOCtriage from the v1.0 single-host release to v2.0, a multi-tenant platform suitable for medium-sized businesses with multiple sites or independently-managed security segments.

The roadmap is incremental. Each release stands on its own and ships independently, but every step is chosen to move the architecture toward the v2.0 target. The goal is not just feature accretion — it is to make v2.0 a mechanical assembly of components proven across v1.x rather than a high-risk rewrite.

## Architectural through-line: multi-tenancy

The single decision that shapes every other step is **multi-tenancy as a first-class concept** — and the groundwork for it is already in place today, not deferred to a future release.

Medium-sized businesses are rarely monolithic. They have:
- Multiple physical sites networked together but managed semi-independently
- Segments where security is handled by different teams (corporate IT vs. R&D vs. plant operations)
- Acquired subsidiaries with their own infrastructure and policies
- Compliance scopes that need data isolation (PCI segment vs. non-PCI)

Each of these is a tenant. A tenant has its own:
- Hosts, networks, and roles
- Triage rules and analyst notes
- Anonymization mappings
- LLM endpoint configurations (different tenants may use different models or vendors)
- Operators and access controls
- Verdict history and audit trail

The multi-tenancy story arrives in three stages, each building on the last:

- **The tenant identifier is already shipping (v1.0).** Every deployment sets an `org` and a `security_domain`, stamped on every record as `jrsoc_org` / `jrsoc_security_domain`. That identifier is what lets many domains or client organizations share one Graylog and one console while staying cleanly separated — so multi-domain operation works *today* by running one lightweight install per domain (see "Running across many domains or clients" in the README). The tenant concept isn't a future idea; it's the operating model right now.

- **Local multi-tenancy** brings that identifier into a single tenant-aware interface: a tenant selector, role-based access control, per-tenant LLM configuration, and a per-tenant audit log — several orgs or domains managed from one interface on one install, on the existing storage, with no new database backend required.

- **Shared multi-tenancy (v2.0)** moves the tenant model onto a PostgreSQL backend with multi-host scale and per-tenant resource isolation, so tenants span infrastructure rather than living on a single install.

Multi-tenancy cannot be retrofitted cleanly onto a tenant-naive schema. Every config table needs a `tenant_id` column from the moment the configuration moves into a real database, every API endpoint needs a tenant context, and every prompt needs to scope its host inventory and rules to the relevant tenant. That is why the identifier ships first (v1.0), the SQLite configuration migration adds a `tenant_id` column to every table even while there is only one tenant, and the tenant-aware interface follows — so that becoming multi-tenant is a configuration change, not a schema change.

---

## v1.0 — Single-host, single-domain

**Status: shipped.**

Validated for home labs and small businesses. JSON-backed configuration, local SQLite for operational state. One Wazuh manager, one Graylog instance, one LLM endpoint chain, and a team of co-equal administrators sharing the install.

This release establishes the core value proposition: LLM-assisted triage that respects an administrator's time. Everything in v1.x and v2.0 builds on this foundation.

**Corp-enablement additions (shipped in v1.0):** two features that gate corporate / shared-infrastructure installs were pulled forward into v1.0 because they unblock that market without changing the single-tenant architecture:
- **Deployment identity** — operator-set `org` and `security_domain` in config, stamped on every shipped record as `jrsoc_org` / `jrsoc_security_domain`. Lets multiple orgs or security domains share one Graylog instance and filter/search only their own alerts. This is the tenant identifier the multi-tenancy through-line builds on; field names are chosen to stay consistent with the eventual tenant model.
- **Roles** — a `roles.json` registry of named, reusable host roles (`name` / `description` / `notes`). Hosts reference roles by name (single or multiple per host). Role context ("what's normal for this kind of host") is written once and applied to every host with that role, rendered to the LLM on the alert host. This is the per-host-config-burden reducer that makes deployments toward 50+ and 200+ hosts practical, and it establishes the role substrate that later per-role settings build on.
- **Team administration** — the interface supports multiple administrator accounts, so an install is run by a team of co-equal administrators rather than one person. In v1.0 all administrators are co-equal; the admin/analyst access split and, later, full multi-tenant RBAC build on this.

---

## v1.1 — Expanded threat-intelligence enrichment (current)

**Status: shipped 2026-07-19.**

All five sources described below are live: GreyNoise, CISA KEV, EPSS,
VirusTotal, and AlienVault OTX. Each was verified against its production API
before release, and each ships disabled by default — supply a key in the
interface to turn one on. Shodan, listed in an earlier revision of this page,
was cut during the release; EPSS was added in its place. See *Not in v1.1*
below for the reasoning on both.

**Goal: give the LLM and the analyst more *actionable* context per alert — context that can change a triage verdict — by adding per-indicator threat-intelligence lookups, without changing the architecture.**

Every alert jrSOCtriage triages carries indicators — IP addresses, domains, file hashes, CVEs. v1.0 already enriches IPs with AbuseIPDB reputation, geolocation, and reverse-DNS. This release adds more per-indicator lookups, each chosen because it answers a question the triage actually turns on: *is this scanner just internet background noise or is it aimed at me? Is this CVE being exploited in the wild right now? What does the wider community know about this indicator?*

Two design principles govern which sources are added:

- **Per-indicator lookups, not detection feeds.** jrSOCtriage sits *downstream* of detection. It enriches indicators from alerts that have already fired; it does not ingest blocklists to *generate* alerts. Bulk indicator feeds — the abuse.ch families (URLhaus, ThreatFox, Feodo Tracker) and similar malicious-URL and botnet-C2 lists — belong upstream in the detection layer (Suricata, Wazuh), not here. Only lookup-shaped sources, queried for a specific indicator, are integrated. Where a source offers both a bulk feed and a per-indicator lookup, only the lookup is used.
- **Bring your own key — free or commercial tier, your choice.** Each integration ships disabled by default; the operator supplies their own API key and jrSOCtriage uses whatever tier that key carries. A home lab can run every source below on its free tier — that floor is guaranteed, so no one is ever locked out for lack of budget — while a production or high-volume deployment uses the same integration on the vendor's paid/commercial tier for the rate limits, commercial-use rights, and richer data it provides. The operator's key and account tier govern their use of each service; jrSOCtriage is tier-agnostic and never charges for or brokers the third-party service, exactly as the existing AbuseIPDB integration already works.

### Sources being added, in order of how directly they change a verdict

- **GreyNoise (verdict-changing).** Per-IP: distinguishes benign internet-wide background scanning — the constant hum of mass scanners like Shodan and Censys and common services — from activity that is actually targeted. Among the most directly actionable signals available: an alert from a known mass-scanner can be de-prioritized with confidence while a non-noise source keeps its weight. Runs on the free GreyNoise Community API for home labs; commercial deployments use a paid GreyNoise Enterprise key on the same integration for higher volume and richer context. Bring your own key at either tier.
- **CISA KEV (verdict-changing).** Per-CVE: checks an alert's CVE against CISA's Known Exploited Vulnerabilities catalog — vulnerabilities confirmed to be actively exploited in the wild. Whether a vulnerability is merely present or is being exploited right now is a first-order triage question. Free, no key, no rate limit — the best effort-to-value ratio in the set.
- **EPSS (verdict-informing).** Per-CVE: FIRST.org's Exploit Prediction Scoring System — the modeled probability that the CVE will be exploited in the next 30 days. Pairs directly with KEV: KEV says a CVE *has* been exploited (confirmed past), EPSS says how likely it is *to be* (modeled forward), and the two render side by side so that pairing is read together. Free, no key. Added during the release, unplanned — the KEV work surfaced it and the effort-to-value ratio was too good to leave on the table.
- **VirusTotal (verdict-informing).** Per-indicator (hash, URL, domain, IP): multi-engine reputation — how many engines flag the indicator as malicious. Genuinely actionable. A home lab can use VirusTotal's free public API (non-commercial, 4 requests/minute, 500/day); a commercial deployment uses a paid VirusTotal Enterprise key on the same integration, which is required for commercial use and lifts the rate limits. Bring your own key at whichever tier fits — the operator's own account governs its use.
- **AlienVault OTX (verdict-informing).** Per-indicator lookup against the Open Threat Exchange community — association with known campaigns and adversary techniques (MITRE ATT&CK), pulled via the indicator-lookup endpoint (not the bulk pulse feed). Useful mainly for the analyst-facing side of the output, helping a human understand *what* an indicator might belong to. Free with an account.

### How this is framed

The value is *more actionable triage*, not *more integrations*. The headline is that jrSOCtriage can now tell targeted activity from internet noise (GreyNoise) and flag actively-exploited CVEs (CISA KEV) — decisions the pipeline could not make before — which cuts more false positives and sharpens what gets escalated. Every source rides the existing enrichment path, disabled by default and keyed by the operator; nothing about the architecture changes.

### Not in v1.1
- No detection feeds. Bulk blocklists (URLhaus, ThreatFox, Feodo, and the like) belong upstream in Suricata/Wazuh, not in jrSOCtriage.
- No architecture change, no storage-model change, no multi-tenancy.
- No source that lacks a free home-lab tier is added — the free tier is a guaranteed floor so a lab is never locked out — but every integration equally supports the vendor's paid/commercial tier for production use.
- **Shodan, listed in an earlier revision of this page, was cut during the release.** Evaluated against the shipped sources, per-alert exposure data on an external actor's box (its open ports and service banners) doesn't change triage verdicts — the sources above already answer who owns an IP, whether it's been reported, whether it mass-scans, its engine reputation, and its community attribution. The analyst deep-dive Shodan genuinely serves is better done on Shodan's own interface, pivoting from the `gl2_src_*` fields already shipped with every alert. EPSS — unplanned, surfaced by the KEV work — was added in its place, so the release ends ahead of the original list on verdict-relevant signal.

---

## v1.2 — Quality of life and security hardening

**Goal: make v1.0 deployable in environments with stricter security requirements, without changing the architecture.**

This release addresses the rough edges in v1.0 that block adoption in security-conscious deployments. Nothing here changes the storage model or the single-tenant assumption.

### Features
- **Adaptive surge handling.** v1.0 sizes for steady-state and lacks a control loop for surge: there is no automatic worker scale-out during high-volume periods, no queue-based backpressure, no dynamic widening of `dedup_silence_seconds` when the LLM-call rate spikes. v1.2 closes this gap with: (a) queue-depth monitoring that drives dynamic worker provisioning within configured min/max bounds, (b) backpressure signals from the worker pool back to ingest so the pipeline shapes its own intake rate during surge, and (c) surge-triggered dedup widening — when the LLM-call rate exceeds a threshold, `dedup_silence_seconds` automatically widens for the duration of the surge, collapsing more repeat-fire patterns and reducing peak LLM call rate without operator intervention. Effect: local-only SMB deployments become viable on modest hardware (a single 24GB GPU, optional second worker for headroom) where v1.0 would have recommended cloud fallback as primary. The architecture supports this without restructuring — the worker pool is already configurable, dedup is already a single tuning knob, queue depth is already observable — so the surge-aware control loop itself is the new code.
- **Adaptive LLM rotation.** Surge handling shapes the pipeline's intake rate during overload; adaptive rotation handles the complementary problem of recruiting additional LLM capacity temporarily. When queue depth crosses a configured high-water threshold, normally-disabled cloud endpoints (e.g., a fast cloud model) become active in the strategy chain. When queue depth falls below a low-water threshold, they go quiet again. Hysteresis between the two thresholds prevents thrashing, and operators get a per-hour cost ceiling as a guardrail. Shares queue-depth observability with surge handling — both features use the same plumbing, which is why they ship together. Together they cover the full overload story: recruit when you can, shed when you must.
- **Alert correlation rework.** v1.0's correlation logic folds brief context from a prior alert into a following alert's prompt, which tends to make the second call feel alarmed without enough context to reason — nudging it toward over-escalation. v1.2 separates the work: each alert gets its own clean triage prompt with no leakage, and a third prompt is constructed afterward that compares the two verdicts with trimmed context plus a purpose-built instruction set for evaluating correlation specifically. Effect: fewer false-positive NOTIFY emails on benign correlated activity, and explicit LLM reasoning about correlation rather than implicit nudging toward escalation. The correlation window can also be widened without prompt-bloat side effects, since each call is independently scoped.
- **Keyring-based credential storage** with one-shot migration from existing config.json. Plaintext credentials in a config file are the largest single security concern in the v1.0 documentation; closing it makes jrSOCtriage suitable for environments where audit reviews look at filesystem credentials.
- **Per-role context windows (`context_window_minutes`) with per-host override.** The Graylog, Zeek, and ntopng enrichment queries use a time window around each alert; in v1.0 that window is global — one value for every host. That is the wrong shape for a real deployment: a busy domain controller with heavy log and connection volume benefits from a *smaller* window (a narrow window already returns plenty; a wider one just bloats the prompt), while a quiet workstation benefits from a *larger* window (sparse events make a wider context useful). The natural axis for this tuning is role — hosts of the same kind have similar event volume — so the window setting lives on the role, with a per-host override for outliers. The override is field-scoped: the host inherits everything else from its role, only the overridden field changes, and clearing the override returns the host to the role default. This is an enrichment-tuning feature, not a storage feature; it rides on the role substrate that already shipped in v1.0, and its JSON fields migrate cleanly to SQLite columns alongside the rest of the role data when configuration moves to the database.
- **vLLM endpoint adapter.** A new endpoint type alongside the existing ollama / gemini / openai / anthropic options. vLLM is OpenAI-API-compatible, so the adapter is small, but explicit support means operators running vLLM internally for cost or privacy reasons can configure it as a first-class endpoint.
- **Email test and LLM ping tests in the GUI.** A one-click SMTP test sends a fixed message through the configured mail path with immediate success/failure feedback, removing the "did I configure SMTP correctly?" loop that otherwise requires waiting for a real NOTIFY. An LLM ping sends a fixed prompt to each configured endpoint and shows the response, helping diagnose endpoint, model, or auth misconfiguration before pipeline startup.
- **Configurable log rollover and retention.** The pipeline's full-stream log grows large under heavy use. v1.2 gives the operator UI control of its disk footprint — rollover size and retention — so the log never grows unbounded by surprise and the operator decides how much disk to spend on it.
- **Reverse proxy documentation** for nginx and Caddy, including proper `X-Forwarded-For` handling so the rate limiter sees real client IPs. The interface stays bound to localhost; TLS termination is the proxy's job.
- **Cookie hardening, bundled with the proxy/TLS docs.** SameSite=Strict, HttpOnly explicit, a Secure flag toggleable for proxy deployments, and a session-lifetime cap. v1.0 ships without these because the interface is localhost-only by design and the flags are no-ops there; v1.2 makes them meaningful for proxy-deployed scenarios.
- **GUI authentication user management.** Self-service password change preserving TOTP. v1.0 already supports creating and deleting administrator accounts (the basis for co-equal team administration); v1.2 adds the self-service password change that lets an administrator rotate their own credential without another admin's involvement.

### Security and robustness hardening

A module-by-module audit during v1.0 ship-prep produced a set of smaller, surgical fixes. Each is low-impact alone, but together they reduce footgun surface and raise the correctness floor — the kind of methodical hardening that makes the difference in a security-conscious deployment.

- **`validation.py` — centralized schema validation.** Per-section schema definitions for every config, host, rule, and anonymization key, replacing v1.0's narrower stopgap that only protected the most-impactful fields. Imported by the interface's POST handlers and by ingest at startup, it centralizes the validate-or-default logic previously scattered across the codebase. This is a resilience feature that protects against silent config corruption now — a UI bug or a mistyped API call quietly writing a malformed host/rule/anonymization file — and it front-loads the schema-definition work the later database migration needs (the in-memory shapes it formalizes are the blueprint for the SQLite tables). Because validation runs on the in-memory structures, it is agnostic to whether those were loaded from JSON or, later, from the database.
- **Client-side and per-handler validation.** GUI-layer checks reject an empty rule_id or a malformed IP before saving, and each POST handler shape-checks its payload before writing — closing the path where a browser bug or a malformed request could silently corrupt a config file. Numeric save helpers correctly preserve `0` (a value at the heart of a real silent-coercion bug) instead of falling through to a default, and text fields are trimmed on save across all forms so stray whitespace in host names, rule IDs, and IPs can't cause silent canonical-lookup misses.
- **Role-based access control on state-changing endpoints.** v1.0 carries a `role` field but does not enforce it — every administrator is co-equal. v1.2 adds an admin/analyst split on the state-changing routes: non-admin users get read access plus limited write to acknowledgements and notes. This is the single-install hardening step; the full multi-tenant RBAC lands with the tenant-aware interface later.
- **NIST-aligned password policy.** Replaces the older "mixed case" rule with the NIST SP 800-63B-aligned approach — minimum length with an optional breach-list check — since a mixed-case requirement is friction without security benefit when paired with TOTP 2FA.
- **Two-phase signal handling.** A first shutdown signal drains in-flight LLM calls; a second cancels the drain and exits fast — needed when an operator restarts because the pipeline is genuinely stuck rather than processing normally, instead of waiting out the full drain timeout.
- **Enrichment failure recording.** v1.0 drops an alert on any enrichment exception. v1.2 records it with an `enrichment_failed` marker, ships it to Graylog at a degraded confidence level, and surfaces it to the operator as a note rather than letting it vanish — consistent with the pipeline's "fail loud, not silent" stance.
- **LLM endpoint health watchdog.** v1.0 surfaces an endpoint problem only after an alert has already produced a synthetic FAILED verdict — by which time real alerts may already be flowing through unprocessed. v1.2 adds a separate timer that pings each configured endpoint on an interval and raises an operator alert on persistent failure, independent of alert volume, so an outage is caught before it silently degrades triage.
- **Retry policy for transient failures.** Local LLM endpoints get a single short retry on fast front-end failures only (connection refused, host unreachable, model mid-reload) and explicitly *not* after a timeout — a timeout means the model already consumed its full budget, so retrying would double the latency and mask a real problem, while a connection error fails in milliseconds and one retry cheaply catches the genuine transient. The Graylog and ntopng fetchers get the same single-retry treatment for transient blips. Cloud endpoints already carry their own retry policy.
- **Baseline and enrichment correctness fixes.** Low-volume rules no longer falsely flag as anomalous (a rule that fires twice in two weeks trivially exceeds a tiny average) — the flag is suppressed at source when the average is near zero, rather than patched at the prompt. A configurable past-timestamp tolerance lets spiky environments with quarterly maintenance windows keep legitimate old alerts from being clamped. Rate-limit bookkeeping surfaces persistent database-write failures instead of failing open silently. And an ntopng coverage metric reports how many of an alert's IPs actually returned flow data, elevating to a warning below a configurable threshold so a misconfigured sensor (wrong interface, SPAN port not seeing the segment) is visible instead of looking like normal sparse responses.
- **Timezone and lookback correctness.** The Wazuh manager's timezone is read from config where present, so non-UTC deployments don't see their enrichment windows shift by hours, and the syscheck lookback becomes a configurable knob for sites running longer scan intervals.
- **Duplicate rule_id auto-merge.** v1.0 warns on duplicate rule IDs and directs the operator to a manual GUI step; v1.2 auto-merges them on load with a notification. This is a data-integrity fix that doesn't depend on the database — the same reasoning as merging host inventories — so it lands now rather than waiting.

### Not in v1.2
- No schema migration. Hosts, rules, and anonymization mappings stay in JSON.
- No multi-tenancy. There is one implicit tenant.
- No database for configuration.

---

## v1.3 — Configuration in SQLite, Falcon alert source, and ELK backend support

**Goal: move configuration into SQLite (carrying the existing tenant identity into the store), add CrowdStrike Falcon as the first non-Wazuh alert source through a pluggable ingest contract, and support Elasticsearch/ELK as a log-evidence backend and a Graylog-alternative sink.**

This is the foundational storage release, and it does several things that reinforce each other. It moves configuration from JSON files into a structured local database, carrying the tenant identity that *already exists* — the `org` and `security_domain` stamped on every record since v1.0 — down into the configuration store as a `tenant_id` column on every table. It adds the first non-Wazuh **alert source**, CrowdStrike Falcon, through a documented pluggable ingest contract. And it adds Elasticsearch/ELK support on two fronts that have nothing to do with where alerts originate: as a **log-evidence backend** jrSOCtriage reads context from during enrichment, and as a **sink** that can receive enriched verdicts in place of (or alongside) Graylog. Tenancy and a broader integration surface belong together: an MSSP with a mixed client base is exactly the operator who needs both a tenant-partitioned config store and the ability to triage Falcon-sourced alerts and ship results into whatever backend each client runs.

### Configuration in SQLite, tenant-ready
- **Hosts, networks, roles, rules, and anonymization mappings move to a local SQLite database.** Same data, structured tables instead of JSON files. On first run the existing JSON files are imported and marked as archives. Operators can still export to JSON, hand-edit, and re-import, so backup and version-control patterns continue to work.
- **The existing tenant identity becomes a `tenant_id` column on every config table.** The `org` / `security_domain` identity already stamped on every record moves into the configuration store: each config table gains a `tenant_id` column, so hosts, rules, roles, and the rest are partitioned by tenant in the store, not just tagged on output. A default tenant is created automatically; the interface still operates as if there is one, with the selector hidden and all reads and writes scoped to it. This is invisible to a single-tenant install but means the tenant-aware interface later is a configuration change, not a schema migration.
- **Foreign-key constraints and atomic edits.** A host that references a non-existent role now fails at write time instead of silently at prompt time, and transactional edits replace the read-modify-write JSON pattern so two concurrent admin sessions stop being a footgun.
- **Configuration change audit log.** A new audit table records every config change — who, when, what — visible in the GUI and foundational for the compliance scenarios the tenant-aware interface builds on.
- **Per-role context windows materialize as columns.** The per-role `context_window_minutes` fields introduced in v1.2 move from JSON into the structured store alongside the rest of the role data, unchanged in behavior.

### Falcon alert source and ELK backend
- **Pluggable alert-source contract.** v1.0 and v1.2 treat Wazuh as the alert source; v1.3 makes the alert source a documented, stable plugin interface so alerts can originate from more than one product. The contract is what makes jrSOCtriage source-agnostic: whatever fires the alert, the triage record and the prompt builder downstream are unchanged.
- **CrowdStrike Falcon as the first non-Wazuh alert source.** Falcon is the most widely-supported commercial platform across the managed-service market, which makes it the priority alert source to add. The work is a Falcon adapter plus normalization: because Falcon detections are not fronted by Wazuh (which today normalizes sources like Suricata into a common severity scheme for free), jrSOCtriage owns the mapping from Falcon's native detection semantics into its own decision scale. **To be clear about positioning: jrSOCtriage is not trying to compete with CrowdStrike's own AI on Falcon-native alerts. On Falcon's home turf, with CrowdStrike's full telemetry and threat intelligence, their agent has advantages jrSOCtriage does not claim to beat.** What jrSOCtriage offers instead is flexibility and cost: it is source-agnostic and inexpensive, and its advantage on a Falcon alert is breadth of correlated context — fusing the Falcon detection with network-flow evidence (ntopng, Zeek), log evidence (Graylog or ELK), and host and role context into a single triage record, the kind of cross-source correlation a single-vendor agent's native-only view doesn't assemble. That is a capability advantage (what gets pulled into the triage), not a claim to out-reason anyone. Wazuh and Falcon can feed a single security domain concurrently, which is the demanding case the normalization contract is built for.
- **Elasticsearch/ELK as a log-evidence backend and a Graylog-alternative sink (`elastic_fetch`).** ELK is not an alert source — alerts still originate from Wazuh or Falcon. Instead, ELK slots into the roles Graylog fills today: jrSOCtriage can read log evidence from an ELK stack during enrichment (the same way it reads Graylog), and it can ship enriched verdicts *to* Elasticsearch as an alternative or addition to the Graylog/GELF output path. The work is a generic Elasticsearch module — authentication, date-rolled index patterns, pagination, retry and error handling, time-window normalization — plus a write path that indexes structured verdicts straight to Elasticsearch with an explicit ECS mapping rather than routing through a separate parsing layer. For shops standardized on Elastic rather than Graylog, this lets jrSOCtriage fit their existing backend instead of requiring them to run Graylog alongside it.
- **Per-source severity normalization.** Because different alert sources speak different severity languages, each source's native severity maps into jrSOCtriage's common decision scale — extending the approach that already works for Wazuh-fronted sources. A single flexible threshold with per-vendor documentation is deliberately *not* the model, because it cannot express multiple sources' severity conventions at once in one domain; normalization to a common scale is what makes concurrent multi-source triage coherent.

### Enrichment and scaling groundwork
- **Provider-agnostic GeoIP backend.** GeoIP moves from a single hardwired provider to a backend abstraction supporting several online providers and a local MaxMind database, so high-volume operators can avoid rate limits entirely.
- **Concurrent external-IP enrichment.** The per-IP reputation, geo, and reverse-DNS lookups that run sequentially today run concurrently, reducing worst-case cold-cache lookup time from roughly the sum of the timeouts to roughly the longest single one.
- **Indexed host-by-IP lookup.** The linear scan that is fine up to about a hundred hosts becomes an O(1) dictionary built at load time, which matters at a few thousand hosts under burst load.
- **Prompt-size telemetry.** Per-cycle prompt-size statistics (average, peak, count over threshold) surface in the GUI so operators tune per-role and per-host windows from data rather than guessing — particularly useful for larger deployments where home-lab calibration numbers may not apply.

### Code-hygiene pass
A set of deferred, low-risk cleanups ride along with the v1.3 work rather than gating the v1.2 security release: an inline-import consolidation across the pipeline modules, removal of a vestigial parameter, replacing stale hardcoded test IPs in a smoke test with a real code path that fails loudly when it has no data, and a couple of cosmetic idiom cleanups. Individually cosmetic; collectively they keep the codebase legible as it grows.

### Architectural progression
- The configuration schema is now what v2.0 will use; substituting PostgreSQL for SQLite later is a connection-string change behind a repository abstraction, not a redesign.
- The pipeline now queries configuration through a repository abstraction rather than reading JSON files — the seam for both the eventual PostgreSQL swap and tenant-context plumbing.
- The alert-source plugin contract and the ELK backend/sink support make heterogeneous-stack integration a configuration matter rather than new code for each addition, which is what jrSOCtriage's fit-into-your-stack flexibility depends on.
- Audit logging begins collecting data immediately, so by the time the tenant-aware interface exposes it there is real history to show.

### Not in v1.3
- No multi-tenant UI yet — the schema is ready, but the tenant selector and RBAC come next.
- No PostgreSQL — single-host SQLite only.
- No HA. One pipeline, one interface.

---

## v1.4 — Local multi-tenancy: the tenant-aware interface

**Goal: bring the tenant identifier that already exists into a single tenant-aware interface, so several orgs or domains are managed from one place on one install.**

This is where multi-tenancy becomes a first-class part of the interface rather than a deployment pattern. The identifier has shipped since v1.0 and the schema has carried a `tenant_id` column since v1.3; this release makes tenancy visible and manageable — on the existing storage, with no new database backend. It is **local** multi-tenancy: many tenants, one interface, one install. Shared multi-tenancy across infrastructure comes at v2.0.

### Features
- **Tenant selector in the interface.** An operator with access to more than one tenant picks one at login; the whole interface — configuration, journal, lookups, everything — scopes to it. Operators with access to a single tenant see it selected automatically.
- **Role-based access control.** Three roles — admin (full configuration), analyst (view and acknowledge alerts, edit rules and notes, no infrastructure config), and auditor (read-only, including the audit log) — assigned per tenant. This is the full multi-tenant RBAC that the admin/analyst split in v1.2 anticipated.
- **Optional single sign-on via OIDC.** Operators can authenticate through an existing identity provider (Keycloak, Okta, Authentik, Entra ID) with local auth as the fallback, and per-tenant role assignments mapping from provider claims.
- **Audit log in the GUI.** The configuration-change history collected since v1.3 becomes actionable: filter by user, time range, and change type, per tenant.
- **Per-tenant LLM endpoint configuration.** A tenant in a regulated industry can be restricted to on-prem inference while another tenant in the same deployment uses a cloud model — always supportable in the schema, surfaced here.
- **Persistent verdict history with retention.** The recent-verdict window expands to configurable retention (default 90 days), becoming the source of truth for audit queries and for replay.
- **Replay tooling.** When an operator sees a wrong verdict, they copy the Graylog message ID of the record, paste it into the replay tool, and the tool re-triages that exact alert against the *current* rules and notes — reusing the original enrichment context stored on the record rather than re-gathering it. Holding enrichment fixed isolates the note change as the only variable (re-gathering would drift, since sources like ntopng only expose current flow state), turning note-tuning from edit-and-wait-days into an interactive seconds-long loop. It doubles as a regression harness for prompt and rule changes.

### Architectural progression
- Tenant context is now first-class throughout the application: every endpoint receives and enforces a `(user_id, tenant_id)` pair, and the RBAC plumbing lets v2.0 add finer-grained permissions without rewriting authentication.
- The audit log makes compliance certification (SOC 2, ISO 27001) practical for buyers who need it.
- Persistent verdict history and replay have standalone value now and become debugging tools when shared multi-tenant deployments need issues reproduced safely later.

### Not in v1.4
- Still single-host. The pipeline runs on one machine.
- Still SQLite. PostgreSQL comes with shared multi-tenancy at v2.0.
- Tenants share one pipeline runtime — no per-tenant CPU or memory isolation yet.

---

## v1.5 — High-availability hooks and source flexibility

**Goal: prepare for the multi-host topology that v2.0 requires, while still shipping as a single-host deployment.**

v1.5 doesn't deliver HA — it delivers the hooks that make HA possible without further refactoring. Operators running it single-host see incremental improvements; v2.0 reuses these hooks across multiple nodes.

### Features
- **Stateless interface.** Session state moves from memory into the database, so an interface restart no longer terminates sessions and two interfaces can share one database (load-balanced or active/passive).
- **Position tracking by source instance.** The single ingest-offset model generalizes to per-source-instance tracking, each source identified by `(tenant_id, source_type, source_instance)`. This allows multiple Wazuh managers per tenant and shared-source-across-tenants configurations — and it builds directly on the pluggable-source contract from v1.3.
- **Health and readiness endpoints.** A liveness endpoint (the process is up) and a readiness endpoint (database reachable, last alert processed within N seconds, LLM endpoint responding) — standard for any service that goes behind a load balancer.

### Architectural progression
- Stateless components are the precondition for horizontal scaling; v1.5 makes them capable of it without yet deploying them that way.
- With the source contract already in place from v1.3, v1.5's per-source-instance position tracking is what lets a later release run heterogeneous sources across a multi-host topology.

### Not in v1.5
- Still SQLite, still single-host, still single-pipeline. HA remains a set of preconditions, not a deployment.

---

## v1.6 — Security Onion as a composite source

**Goal: integrate cleanly with Security Onion deployments by treating Onion as a single composite enrichment source, reusing the Elastic query layer built in v1.3.**

A typical Security Onion deployment already centralizes much of what jrSOCtriage otherwise fetches from separate sources: Onion runs Zeek, aggregates flow data, and indexes everything into its own Elasticsearch backend. For Onion shops, the default deployment story would otherwise be "stand up Graylog, Zeek, and ntopng alongside your existing Onion" — duplicative and painful. v1.6 collapses those into a single Onion adapter.

The framing is not "Onion as another source" but **Onion as the composite source that replaces the separate Zeek, Graylog, and ntopng fetches for Onion-running deployments**, while non-Onion deployments use their original sources unchanged. It is config-driven and opt-in, and the prompt builder doesn't change.

Because the generic Elasticsearch query layer already exists from v1.3's multi-source work, v1.6 is largely a matter of an Onion-specific mapping — which indexes hold what, where the source IP and timestamp live, which datasets exist — returning evidence in the shapes the prompt builder already consumes. Security Onion is a natural fit for jrSOCtriage and its users tend to value exactly this kind of deterministic, deployable triage; adding it once the Elastic foundation is in place is inexpensive.

### Features
- **Onion adapter over the v1.3 Elastic layer.** A configuration mapping that tells the Elasticsearch module how to read an Onion deployment's indexes, returning Zeek, flow, and log evidence in a single coordinated fetch. When enabled, the separate Zeek, Graylog, and ntopng fetches are skipped for that deployment.
- **Verdict writeback to Onion** *(stretch goal).* Ship NOTIFY/NOTE verdicts back to Onion's case management for analyst visibility. Source-only is already a complete release; writeback is the enhancement.

### Not in v1.6
- No change to the alert source. Wazuh (and, from v1.3, Falcon) remain the alert sources; Onion is an enrichment source here.
- No multi-tenancy changes — Onion configuration is per-tenant using the schema already in place.

---

## v1.7 — Cross-domain frequency sync (shared-state preview)

**Goal: give roaming hosts a correct baseline across security domains by periodically sharing per-host frequency data through SQL — and prove the shared-state pattern that v2.0 generalizes.**

A host that lives in one security domain most of the time and appears in another only occasionally creates a subtle false-positive problem. Each domain builds its frequency baseline from its own observations, including all the periods the host is absent, so the rarely-visited domain's baseline is deflated — and the host's occasional real activity there reads as a large spike against that absence-diluted average, escalating for nothing. The same situation arises whenever a host can be routed between domains — including Wazuh's own manager-failover feature, where an agent configured with a list of managers can, on losing its connection, connect to a manager in a different domain.

v1.7 fixes this by having each security domain periodically write out the frequency data for its roaming-designated hosts to a shared SQL store the other domains read. Every domain then holds a current-enough real baseline for each roaming host and judges an occasional visitor against its true activity level rather than its own you're-usually-absent average. It keys off the roaming/mobile designation, not every host, and the interval is a tunable knob (short enough that a roaming host can't accumulate a spike-looking window before the next sync refreshes the shared baseline).

This is a deliberately small, bounded piece of shared state — frequency data only, shared on a schedule, fire-and-forget. A missed sync means a slightly staler baseline, not a failure. It requires no always-on shared dependency queried at triage time; it is a periodic push of a little data. That is exactly why it is the right first proof of the pattern: it demonstrates independent installs sharing state through SQL, at low risk, before v2.0 builds shared state as a full platform capability.

### Architectural progression
- The roaming-host baseline is a real correctness fix on its own, and it is the first concrete instance of installs sharing operational state through the database — the pattern v2.0 generalizes into a shared multi-tenant backend.
- Deduplication stays local by design: a host can only be in one place at a time, so only frequency baselines benefit from sharing. Keeping the shared surface to frequency-only keeps this release small and its failure modes benign.

### Not in v1.7
- Still single-host per domain; the sync is between independent installs, not a shared runtime.
- Still SQLite. The shared store is a bounded, periodic-sync mechanism, not the full shared backend that comes with v2.0.

---

## v2.0 — Shared multi-tenancy: the platform

**Goal: take the architecture proven across the v1.x single-host line and run it as a horizontally-scalable, shared multi-tenant platform.**

By v2.0, every component has been engineered for multi-tenancy and stateless operation, and each hard piece has been proven in a smaller earlier release. This release moves the tenant model onto shared infrastructure and swaps the single-host pieces for distributed equivalents. The emphasis is on **substitution, not redesign** — the abstractions are already in place.

### Substitutions
- **SQLite → PostgreSQL** for the configuration database (the one already carrying `tenant_id` columns since v1.3), with high availability via streaming replication or a managed service. Behind the repository abstraction, this is a connection-string change rather than code churn.
- **SQLite → PostgreSQL** for the cold-path operational state (verdict history, anonymization mappings, audit log), moving the durable state onto the shared backend.
- **Single pipeline process → a worker pool across multiple hosts**, with the persistent queue substrate that the shared backend provides.
- **Single ingest → multiple ingest workers with leader election**, one leader per source instance with warm standbys; shared position tracking means a leader failure doesn't lose alerts.
- **Single interface → multiple interfaces behind a load balancer**, made trivial by the stateless interface from v1.5.

### New work specific to v2.0
- **Per-tenant resource isolation.** A storm in one tenant cannot starve the others: per-tenant queue limits, endpoint isolation, and rate limits. This extends the single-tenant backpressure mechanism built in v1.2 with per-tenant quotas.
- **Full shared state.** The cross-domain frequency sync proven in v1.7 generalizes: tenants sharing state across infrastructure through the shared backend, not just periodic frequency pushes between independent installs.
- **Tenant onboarding workflow.** Provisioning a new tenant — namespace creation, default configuration, an initial admin user, and usage-tracking integration points.
- **Cross-tenant isolation guarantees.** Negative testing that a malicious or compromised tenant cannot read another tenant's data, modify another tenant's configuration, or exhaust shared resources.
- **Production deployment artifacts.** A Helm chart for Kubernetes, Docker Compose for smaller deployments, and a Terraform module for cloud provisioning. The v1.x line ships as a tarball plus systemd; v2.0 ships as deployable infrastructure.
- **Performance characterization.** Documented capacity per worker, per database, and per LLM endpoint, so operators can size a deployment without guessing.

### What v2.0 deliberately does not include
- **Multi-region.** A single-region deployment is the v2.0 target; geographic distribution brings its own consistency challenges and is later work.
- **Embedded LLM hosting.** v2.0 still uses external LLM endpoints (local or cloud); hosting the model itself remains out of scope.

---

## Why this ordering

Every release on the path delivers value to single-host operators on its own, while proving one specific piece that the shared multi-tenant platform later assembles. The sequence is a deliberate de-risking of v2.0: by the time the platform release arrives, none of its hard parts are new.

- **v1.1** deepens the triage itself: new per-indicator threat-intelligence lookups — GreyNoise (internet-noise vs. targeted), CISA KEV (actively-exploited CVEs), EPSS (exploitation probability), VirusTotal, and AlienVault OTX — that give the model and the analyst context capable of changing a verdict. It ships first because it is the lowest-risk, most immediately useful improvement — it rides the existing enrichment path, changes no architecture, and directly reinforces the product's core job of cutting alert noise.
- **v1.2** makes v1.0 deployable in stricter environments — surge handling for local-only viability, credential hardening, and a methodical correctness pass — while establishing the role and credential abstractions later releases build on.
- **v1.3** lays the foundations: configuration in SQLite, carrying the existing tenant identity into the store as a `tenant_id` column on every table; a pluggable alert-source contract with Falcon as its first non-Wazuh implementation; and ELK support as a log-evidence backend and Graylog-alternative sink. This is where both through-lines — tenancy and a broader integration surface — get their real substrate.
- **v1.4** proves the tenant model: a tenant-aware interface, RBAC, and per-tenant configuration, all on the existing storage. Multi-tenancy becomes real and manageable before any backend change.
- **v1.5** proves the stateless, load-balanceable shape the platform needs, without yet deploying it across hosts.
- **v1.6** adds Security Onion cheaply, on the Elastic foundation already built, broadening reach with little new code.
- **v1.7** proves the shared-state pattern on one small, bounded piece — cross-domain frequency sync through SQL — the low-risk precursor to the platform's shared backend.
- **v2.0** is then a mechanical assembly: the tenant model (proven in v1.4), the stateless topology (v1.5), the shared-state pattern (v1.7), and the multi-source ingest (v1.3) come together on a PostgreSQL backend across multiple hosts. Each substitution replaces a single-host piece with a distributed one whose behavior is already understood.

The single most important early commitment is shipping the tenant identifier in v1.0 and the `tenant_id` schema in v1.3 before anything depends on the old shape. Everything else flows from there.

| Release | User-visible value | Platform foundation it proves |
|---|---|---|
| v1.1 | More actionable triage via new per-indicator lookups — GreyNoise (noise vs. targeted), CISA KEV (actively-exploited CVEs), EPSS (exploitation probability), VirusTotal, AlienVault OTX — bring-your-own-key on the free or the commercial tier, with a free home-lab tier guaranteed | Per-indicator enrichment lookup pattern; downstream-of-detection boundary |
| v1.2 | Local-only SMB viability (surge handling), credential and correctness hardening, per-role context windows, GUI diagnostics, self-service password change | Role and credential abstractions; queue-depth control loop |
| v1.3 | Configuration in SQLite with audit log; Falcon alert source; ELK as evidence backend and Graylog-alternative sink | Tenant-partitioned config store and repository abstraction; alert-source plugin contract and normalization |
| v1.4 | Tenant-aware interface, RBAC, SSO, per-tenant LLM config, verdict history and replay | Tenant context enforced throughout the application |
| v1.5 | Stateless interface, per-source-instance position tracking, health/readiness | Horizontal-scaling preconditions |
| v1.6 | Security Onion as a single composite source | Reuse of the Elastic adapter pattern |
| v1.7 | Correct roaming-host baselines across domains | Shared-state pattern (frequency sync through SQL) |
| v2.0 | Shared multi-tenant platform across multiple hosts | All previous work compounds into a mechanical assembly |

---

## Open questions

These decisions influence v2.0 but do not need to be made until the relevant release approaches.

1. **Tenant data isolation level.** Logical isolation (one PostgreSQL, `tenant_id` in every query, application-enforced filtering) versus physical isolation (a schema or database per tenant). Logical is simpler; physical is easier to certify for regulated industries.
2. **Pipeline-to-tenant binding.** One shared worker pool across all tenants with quotas, or per-tenant worker pools with more isolation and more idle capacity. Likely starts shared, with per-tenant pools a possible higher-tier option.
3. **LLM endpoint sharing.** Two tenants both using the same cloud model — one shared key and bill, or separate. The configuration model needs to support both.
4. **Migration tooling for tenants.** A v1.x deployment becoming the first tenant in a v2.0 deployment needs a migration path; the HA-hooks release should leave migration hooks in place before the migrator is built.
5. **Observability stack.** Single-host v1.x ships logs to Graylog; a multi-host platform wants metrics, distributed tracing, and correlation IDs across the pipeline. Whether that lands late in v1.x or in v2.0 is open.

These can be deferred. The roadmap above does not depend on resolving them now.
