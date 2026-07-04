# jrSOCtriage

jrSOCtriage is a SOC context aggregation pipeline. It collects evidence from across Wazuh, Graylog, Zeek, ntopng, and threat intelligence sources for every alert, builds a unified record of everything a human analyst would have gathered manually, and uses an LLM to triage and direct investigation — preserving visibility into low-severity signals that traditional suppression-based approaches lose.

**License:** Custom source-available — free for personal, educational, research, and internal organizational use (including for-profit companies protecting their own systems). For hosting-as-a-service, MSSP/MDR use, embedding in commercial products, public forking, or distribution of modified versions, a separate commercial license is required. See the `LICENSE` file for terms.

---

## What it does

A typical SOC analyst handling a single Wazuh alert pivots between six or seven tools — Wazuh, Graylog, Zeek, ntopng, AbuseIPDB, Whois, reverse DNS — and spends five to ten minutes building context before they can even decide whether the alert matters. jrSOCtriage collapses that work into a single record per alert.

Every alert gets enriched with:

- The alert itself (Wazuh rule data + raw event)
- System logs from Graylog (windowed around the alert time)
- Zeek network flows (connections, DNS, NTLM)
- ntopng active flow data (including L7 protocol labels)
- AbuseIPDB scores, reverse DNS, and Whois enrichment for external IPs
- Frequency baseline (last hour / last 24h / last 7d) — was this alert a spike or routine?
- Host inventory context, network notes, sensor caveats, and per-rule guidance

That aggregated record is then handed to an LLM, which produces:

- A verdict: `NOTIFY`, `NOTE`, or `SUPPRESS`
- A confidence level
- A one-sentence summary
- Reasoning citing specific evidence
- Suggested investigation commands when applicable

`NOTIFY` and `NOTE` outcomes can be emailed. All outcomes are shipped to Graylog, where they are searchable and dashboardable.

The result: where a human analyst would spend five to ten minutes per alert, jrSOCtriage produces an analyst-ready record in seconds. In this project's home lab, that compresses ~29,000 raw Wazuh alerts per day (with observed bursts up to ~43,000 on storm days) down to ~0-2 NOTIFY and ~10-80 NOTE notifications a day (NOTIFY at the steady state reached after sustained tuning; the NOTE range depending on configuration — tighter rules and host notes drive it down, escalate-everything mode drives it up). See *Design philosophy* below for the full funnel and what "tuned" means.

And it scales far past a home lab. jrSOCtriage was designed for a target of roughly 900,000 alerts per day — and blew past it by more than 30×. Across about three hours of sustained load testing, the full pipeline — enrichment, dedup, rules, LLM triage, and Graylog shipping — processed everything it was handed cleanly, at input rates ranging up to **~29.8 million alerts per day**, with zero ingest loss and zero abandoned work, on a single modest server with a cloud LLM endpoint handling the triage calls. Crucially, that load was not fabricated: the test multiplies *real alerts from this project's live environment* across synthetic host identities, preserving real rule IDs, field structure, and enrichment-triggering content — so the rate each hour reflects real, organic alert volume scaled up, and every stage did its genuine work at that volume, not a microbenchmark on throwaway JSON. That ~29.8M/day is on the order of **1,000× this project's real production volume** — and it is simply the most the multiplied load ever produced, not a ceiling the pipeline reached, so the true limit sits higher still. The test was also deliberately harder than a real enterprise on three independent axes: the source network was minimally hardened (configuration problems left generating alerts), atypically noisy with chaotic unmanaged consumer-IoT traffic (harder to triage than managed corporate endpoints), and run with **zero Wazuh-side filtering of any kind** — the full unfiltered firehose reached the pipeline, where a real deployment trims most of its volume at the manager before triage ever sees it. Worst-case cloud cost at that rate was about **$8/hour** (on the low-cost cloud model, and even that includes a large share of repetitive self-monitoring traffic a normal deployment won't generate). A real install runs an easier environment at a fraction of the volume — so the practical ceiling sits far above anything a real deployment will reach. See *Scale and limits* for the full numbers, the per-source detail, and the honest caveats.

---

## How it works

```
Wazuh alerts.json
       │
       ▼
   ingest ──► dedup ──► enrich + baseline
                              │
                              ▼
                      Graylog logs +
                      Zeek flows +
                      ntopng flows +
                      AbuseIPDB / RDNS / Whois
                              │
                              ▼
                        rules engine
                              │
                              ├─► escalate to LLM?
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
        anonymize (cloud only)     ship to Graylog
                │                  (no LLM verdict)
                ▼
            LLM endpoint
       (Ollama / Anthropic /
        OpenAI / Gemini / llama.cpp)
                │
                ▼
        de-anonymize response
                │
                ▼
        ship to Graylog
        (with LLM verdict)
                │
                ▼
        email if NOTIFY/NOTE
```

The LLM runs in **goldfish mode**: each alert is one prompt, with no memory between alerts. The LLM does not learn the network — instead, the network is described to it on every call via Sensor Context, Network Notes, Host Notes, and Rule Notes. This makes the system deterministic in the prompt-quality sense: the same alert with the same context produces the same verdict, regardless of what happened earlier in the day.

This is a deliberate design choice. Stateful LLM agents introduce nondeterminism that is hard to debug. Goldfish mode keeps the system auditable: every verdict is fully traceable back to the prompt that produced it.

That said, the NOTIFY-versus-NOTE line is a judgment call on genuinely borderline alerts, and the same alert can reasonably land either way — the operator shapes where that line falls by telling the LLM what matters in their specific environment through Host Notes and Rule Notes.

---

## Running across many domains or clients

The deployment model for a corporation or an MSSP is simple — **one shared Graylog, multiple jrSOCtriage installs, one per security domain or client org.** The installs are lightweight; several can run on the same VM. Each install is tagged with its own `jrsoc_org` and `jrsoc_security_domain`, and because that tag travels with every NOTIFY, the shared Graylog becomes a single console where every escalation is cleanly attributed to the right org and domain. That org/domain tag is effectively a tenant identifier, built in from the start — which is why you don't need a multi-tenant architecture to run many domains cleanly. jrSOCtriage v1.0 is a single-domain deployment (one install, one domain, a team of co-equal administrators sharing it), and you simply run one per domain: the tenant tag does the separation, the shared Graylog does the aggregation.

This tells two stories with the same mechanism. For a **corporation**, one company runs multiple internal security domains (workstations, servers, DMZ, cloud, a subsidiary, the lab) — each its own install with its own enrichment context, all feeding one shared Graylog, so the security team sees every domain's escalations in one place, each tagged to its domain. For an **MSSP**, one provider serves many client organizations, where `org` is the client identifier (Client A, Client B, Client C) with security domains subdividing within each client. The MSSP's analysts never log into each client's environment; NOTIFYs from every client's install land in the MSSP's one shared Graylog, tagged by client and domain, as a single aggregated console across the entire client base.

Four capabilities carry the operational load so running many installs scales without per-install drudgery. **Import hosts from Wazuh** populates an install's whole inventory straight from its Wazuh agents in one step, verified against DNS and re-runnable, instead of hand-typing hundreds or thousands of hosts. **Renumber / re-verify** keeps an inventory correct as an environment changes without rebuilding it by hand. **Roles** let you write context once and apply it to many: define a role like `sales_laptop` or `domain_controller` once and every host tagged with it carries that context into triage, maintained in one place instead of copied into hundreds of host notes — and for an MSSP this compounds, since a role written once is reused across the entire client base, so onboarding the next client is cheap because the role library already exists. **Merge inventory across domains** brings one domain's host context into another so a host seen in more than one place (a roaming laptop, a shared server, a failover-routed agent) carries its context wherever it is triaged. (Setting these up — Wazuh API credentials, endpoints, and the step-by-step — is covered in `running_instructions.txt`; this section is about the shape of the deployment, that file is about wiring it up.)

**Where this goes next — local then shared multi-tenancy:** the tenant identifier is already present today, and the roadmap extends it in two steps. First comes **local multi-tenancy**: a tenant-aware interface on the existing storage — a tenant selector in the GUI, role-based access control (admin / analyst / auditor), per-tenant LLM endpoint configuration, and a per-tenant audit log — so several orgs or domains are managed from one interface on one install, no new database backend required. Then comes **shared multi-tenancy** at v2.0: a PostgreSQL backend with multi-host scale and per-tenant resource isolation, where the tenant model spans infrastructure rather than living on a single install. Both steps build on the identifier that already exists rather than bolting on a new model. Multi-domain operation works now; local multi-tenancy makes managing it from one interface easier; shared multi-tenancy scales it across hosts. See `roadmap.md` for the current version sequence.

---

## Design philosophy

**Explain noise, don't suppress it.** A suppressed Wazuh rule never fires — you lose all visibility into that rule's events forever. An *explained* rule still fires, gets evaluated by the LLM with the explanation as context, and gets a `SUPPRESS` verdict if conditions match. If something abnormal happens that doesn't match the explanation, the LLM still surfaces it. This costs more LLM tokens than hard suppression but keeps the system honest.

A hybrid is supported: hard-suppress in Wazuh what is genuinely irrelevant noise (legitimate static rules), and explain in jrSOCtriage what is contextual noise (rules that are noisy in some situations and meaningful in others).

**Context aggregation > per-tool pivoting.** The product isn't the LLM. The product is a record that contains everything a human analyst would have gathered manually, plus an LLM verdict. Even if the LLM is wrong, the record is still more useful than a raw Wazuh alert.

This approach is what makes the triage layer actually triage rather than just relay. In this project's home lab, ~29,000-30,000 raw Wazuh alerts per day are reduced to ~2,400 after deduplication (dedup — collapsing repeat fires of the same rule on the same host within a short window into a single record; it runs before any LLM sees an alert) — a ~12:1 collapse ratio. Deduplication does not discard the collapsed alerts: the count of how many raw alerts fell into the dedup window is preserved on the record and passed to the LLM as context, so the model knows whether it is looking at a one-off event or a burst that fired hundreds of times. Note that this is deduplication, not a frequency threshold: dedup fires the first occurrence of a signature immediately and suppresses only the repeats, so you are never blind to a new condition while waiting for a count to be reached. For this reason dedup is preferred to Wazuh frequency-threshold gating — it reduces volume the same way without delaying first detection, and it keeps the occurrence count that a threshold would discard. The dominant tuning variables here are `dedup_silence_seconds` (longer windows collapse high-frequency repeat-fire patterns more aggressively; this project runs 240s) and `always_include` networks — an optional, manually-configured list of CIDRs where every alert bypasses dedup and goes straight to LLM regardless of rule level (typically used for high-value hosts like DMZ web servers, domain controllers, or VPN gateways). always_include is empty by default; operators add networks deliberately. In this project's lab the DMZ web server's CIDR is in always_include, so reducing that host's exposure to external scanners (firewall hardening, blocking aggressive scanner IPs upstream) directly reduces LLM volume. From there, two operating modes have been validated:

- **Escalate everything to the LLM** (min_rule_level lowered, no rule-level filtering): all ~2,400/day are sent to the LLM. This has been this project's mode for all but a week of the development period, and is the mode used for the sustained-load characterization documented under *Scale and limits*. It is practical here because the lab's LLM is local (no per-call cost); a deployment paying per cloud call, or conserving a shared GPU, will normally prefer the filtered mode below.
- **Level 6 + rule filters** (default min_rule_level, `rules.json` populated with site-specific suppressions for chatty rules): ~240/day reach the LLM. min_rule_level=6 is the biggest cut, with rules.json's pre-LLM mechanisms (`never_escalate`, severity downgrades, conditional filters, rate limits) suppressing chatty rules before they consume an LLM call. rules.json also has post-LLM functions (rule notes and per-host rule notes that inform the verdict) which don't affect LLM call volume. `hosts.json` operates entirely downstream of the LLM — it informs the verdict (known-benign host context makes SUPPRESS more likely) and suppresses NOTIFY emails for hosts in always-suppress lists, but does NOT reduce LLM call volume. Pre-LLM filtering saves cost and capacity; post-LLM context (hosts.json notes plus rules.json rule notes) improves verdict quality and saves operator attention.

In either mode, the operator typically sees **~0-2 NOTIFY emails per day** at the home-lab volumes documented here, after sustained tuning — that's the high-priority bucket where an analyst is being asked to act. NOTE volume is separate and depends on the operating mode: escalate-everything produces ~50-80 NOTE/day (broader visibility into low-severity signals — CVEs on internal hosts, unusual but explainable traffic, etc.); level-6-plus-filters produces ~10-15 NOTE/day. NOTIFY is comparable across modes because the LLM applies the same severity logic whether it's seeing 240 or 2,400 alerts.

A fresh deployment's day-one numbers depend on what Wazuh-side filtering you already have in place upstream. An operator with a heavily-tuned Wazuh deployment may land at or below 240 alerts/day to the LLM on day one; an operator with default Wazuh rules and no custom suppression may land much higher. The 240/day figure is what this project's home-lab Wazuh configuration produces after dedup, level-6 filtering, and the populated `rules.json` (pre-LLM rule suppression) — your starting point will depend on how much filtering your upstream Wazuh is already doing. `hosts.json` does not reduce LLM call volume; it affects the verdict the LLM produces and the NOTIFY-email behavior after triage.

For reference, this project's home-lab environment produced **~5-10 NOTIFY/day before any `rules.json`, `hosts.json`, or site-specific note context tuning had been done** — using only Wazuh's default filtering, dedup, and level-6 baseline. That's the realistic operator load for the first week or two of a new deployment in an environment broadly similar to this one. NOTIFY volume then drops as tuning accumulates: after a couple weeks of tuning it settled to ~2-3/day, and after a month or more of continued tuning (note contexts accumulating, plus refinement of host and rule context through the kind of LLM-conversation-driven note-writing described in writing_notes.md) it reached the current ~0-2/day steady state. The tuning is a continuing curve, not a one-time step — each note that explains a recurring benign pattern moves one more class of alert off the NOTIFY pile.

The pipeline is designed to operate as a feedback loop, and the loop runs on operator attention: when a NOTIFY or NOTE arrives that you can immediately explain in your environment ("oh, that's just the nightly backup", "that's the WSUS server checking in", "that's the kid's gaming PC shutting down"), the explanation you would have given to a human analyst is exactly what the LLM needed to make a better verdict. Write that explanation into a note, and the next time the same pattern fires the LLM has the context to either downgrade NOTIFY → NOTE or NOTE → SUPPRESS without operator involvement. Each NOTIFY-or-NOTE you successfully explain converts into reduced future workload.

The flip side: alerts that fire repeatedly with the same SUPPRESS verdict are already silent — they're not costing attention. Wrongly-suppressed alerts are real in principle (a SUPPRESS verdict that should have been NOTIFY or NOTE is a missed signal), but detecting them is hard: by definition, they're not in front of you, and finding one requires knowing in advance which alerts should have escalated. In this lab's continuous gemma4:26b production operation, no observable wrong-SUPPRESS has been identified — that's absence of evidence, not evidence of absence, but it's reason not to prioritize SUPPRESS-sampling as routine work. Tune what reaches you, not what doesn't.

Three intervention layers, ordered by effect on LLM volume:

1. **`rules.json` pre-LLM suppression** (`never_escalate`, severity downgrades, `escalate_if` filters) — suppresses or downgrades the rule before it reaches the LLM. Reduces LLM call volume and cost. Use when the rule is genuinely uninformative everywhere — almost no real deployment has many of these.
2. **`rules.json` rule notes** (`note` and per-host `host_notes` for the rule) — leaves LLM call volume unchanged but informs the LLM about why the rule fires and what evidence to weigh. Improves verdict quality and downgrades over-escalations. This is the most common feedback-loop action.
3. **`hosts.json` host notes** — leaves LLM call volume unchanged but provides host-specific context the LLM uses when reasoning about alerts on that host. Improves verdict quality across all alerts on the host.

Which layer to use depends on intent: pre-LLM suppression when you're confident the rule is noise everywhere (rare); rule notes when the rule is genuinely informative but needs site-specific context (the common case); host notes when the same rule means different things on different hosts (also common).

**A subtlety worth knowing:** there is less friction in writing a `hosts.json` note (one place, one host, done) than in writing a per-host rule note inside `rules.json` (find the rule entry, add the host key, write the note). Operators naturally reach for the easier tool — but the per-host rule note is frequently the right tool because it's surgical. A `hosts.json` note expands the prompt for **every alert on that host**, regardless of rule. A per-host rule note inside `rules.json` only expands the prompt when **that specific rule fires on that specific host**. For a busy host that generates many different alerts daily, this is the difference between paying the note's token cost on every alert versus paying it only on the alerts where it actually matters. When a recurring over-escalation pattern is rule-specific (rule X fires repeatedly on host Y because of a known cause), put the explanation in `rules.json` host_notes, not `hosts.json`. Reserve `hosts.json` for host-wide context that applies regardless of which rule fired.

See `writing_notes.md` for guidance on building the note contexts (covers both host notes and rule notes).

**Implication for SMB scaling:** an environment 10× the size of this project's test lab (roughly 290,000-300,000 raw Wazuh alerts per day) would, with **normal Wazuh-side filtering active** (min_rule_level, agent groups, rule exclusions — the configuration almost every real deployment runs), land at approximately 2,400 alerts/day reaching the LLM at the *steady-state mean*. That's the same daily total this project's single RTX 3090 has handled comfortably in continuous operation.

However, **mean throughput is not the binding constraint at SMB scale; surge behavior is.** Home-lab steady-state numbers: raw alert rate averages ~21/min (30,000/day ÷ 1,440 min); LLM call rate averages ~1.6/min (2,400/day ÷ 1,440 min). A single 3090 worker at parallel 1 has a theoretical peak that depends on the inference engine: ~4 LLM calls/min on Ollama (~15s mean response) or ~5.3/min on llama.cpp (~11.4s mean). Against the ~1.6/min steady-state load that is roughly 2×+ operational headroom on Ollama and ~3× on llama.cpp — the faster engine simply leaves more margin. After reserving ~40% capacity to absorb p95-vs-mean variance and surge, both still sit comfortably above steady-state.

At 10× raw scale (SMB ~300k raw/day) with normal Wazuh-side filtering: raw rate becomes ~210/min, but **LLM call rate stays at the same ~1.6/min as home-lab escalate-everything** because the filtering layer scales proportionally — this home lab's filtered mode produces 240 LLM calls/day from 30k raw (a 1:125 raw-to-LLM ratio); the same filtering aggressiveness applied to 300k raw produces 2,400 LLM calls/day (same 1:125 ratio). The math: 10× raw × normal filtering = same LLM-call volume as this home lab generates in escalate-everything mode, which is exactly what the single 3090 has been handling continuously. The filtered-SMB case therefore has the same operational headroom on a single 3090 as this home lab does — ~2×+ on Ollama, ~3× on llama.cpp, against ~1.6 calls/min actual. **Steady-state sizing is not the SMB problem in filtered mode.**

Surge behavior is the SMB problem. Storms — Wazuh agent restarts, scheduled scans, correlated network events — push peak LLM call rate higher temporarily, and at 10× raw scale the surge envelope is also ~10× larger. How much higher peak LLM-call rate climbs during surge depends on whether the surge alerts are mostly repeat-fire patterns (dedup collapses them efficiently, modest LLM-call bump) or genuinely diverse alerts (dedup doesn't help much, larger LLM-call bump). This project has not characterized peak LLM-call rate during surge in production; it is left as a v1.1 measurement target.

Realistic SMB sizing therefore depends on operating mode and surge characteristics:
- **Filtered SMB, low surge** (typical office, no unusual alert-generating events): single 3090 is likely sufficient with the same ~2× headroom this home lab demonstrates. Cloud fallback recommended for tail absorption but not strictly required.
- **Filtered SMB, high surge** (large environments with frequent scheduled scans, agent fleet churn, or active networks): cloud fallback as primary is the operationally simplest path. Adding a second local worker provides additional buffer.
- **Escalate-everything mode at SMB scale** (deliberately atypical, like this home lab): LLM call rate scales linearly with raw volume — at 10× that's ~16 calls/min steady-state, exceeding a single 3090's ~3 calls/min operational capacity by ~5×. Multi-worker or cloud-primary required.
- **dedup_silence_seconds tuning** — widening the window shifts surge into dedup collapse, reducing peak LLM call rate; SMBs facing surge-bound sizing should tune dedup_silence_seconds before adding hardware.
- **max_batch_size scaling** — at SMB raw alert volumes, the default `max_batch_size=250` becomes a real constraint that fails *silently* if undersized. The pipeline must absorb burst arrival patterns, not just steady-state rate. This lab measured an 8% drop rate at `max_batch_size=100` (10× steady-state floor) and 0% drops at the current default of 250 (25× steady-state floor) — establishing 25× steady-state as the measured operational floor for bursty real-world traffic. At 10× home-lab raw volume, the 25× target is ~2,600 alerts per cycle; the default of 250 would be only ~2.4× SMB steady-state (worse than the home-lab case that already lost 8%), so SMB drop rate at the default would be substantially higher than 8% — likely 30-50%+. At 30× raw volume the 25× target is ~7,500. Raise `max_batch_size` aggressively for SMB deployments or shorten `poll_interval_seconds` to compensate — see `running_instructions.txt` → MAX_BATCH_SIZE section for the formula, the measured 8% drop evidence, worked examples, and diagnostic check.

**Honest caveat on local-only SMB deployments at v1.0:** v1.0 does not implement *adaptive* surge handling — there is no automatic worker scale-out, no queue-based backpressure, no dynamic dedup-window widening during high-volume periods. That adaptive control loop is a v1.1 target. But adaptive scaling is not required to handle surges in v1.0, because the same problem has a simpler static solution available today: **provision more workers than your average load needs.** Extra workers don't raise your average throughput (that's capped by arrival rate) — they raise your peak capacity, so a burst drains in parallel instead of queueing behind one worker. Sizing the worker pool above the average-load floor turns surge headroom into a fixed property of the deployment rather than something that has to be reacted to dynamically. (See the worker-sizing discussion below for the math.) So a local-only SMB deployment at v1.0 has three workable paths: (a) over-provision the local worker pool for burst headroom — the recommended and simplest approach; (b) configure cloud fallback as primary so surge gets absorbed by cloud capacity; or (c) wait for v1.1's adaptive surge handling (dynamic worker provisioning, queue-aware backpressure, surge-triggered dedup widening) if you want the pipeline to manage headroom automatically rather than provisioning it up front. The architecture already supports the static approach fully — the worker pool is configurable and dedup is a single tuning knob; only the *automatic* control loop is deferred to v1.1.

`dedup_silence_seconds` is the single most powerful tuning variable for LLM volume control after Wazuh-side filtering. This project's dedup window was originally 30s producing ~4,000 LLM calls/day in escalate-everything mode; widening to 240s collapsed high-frequency repeat-fire patterns more aggressively and reduced LLM volume to ~2,400/day with no loss of operationally-meaningful coverage. SMB operators tuning their own deployment should treat dedup_silence_seconds as a primary cost-control AND surge-control knob.

The relationships across deployment scale and operating mode summarized:

| Deployment                         | Raw alerts/day | LLM calls/day | NOTIFY/day |
|------------------------------------|----------------|---------------|------------|
| Home lab, filtered (level 6+)      | ~30k           | ~240          | ~0-2       |
| Home lab, escalate-everything      | ~30k           | ~2,400        | ~0-2       |
| SMB ~10×, filtered (estimated)     | ~300k          | ~2,400        | ~20-30     |
| SMB ~10×, escalate-everything (estimated) | ~300k   | ~24,000       | ~20-30     |

Key observations from the table:
- **LLM-call volume tracks operating mode and raw volume**: filter aggressiveness determines how many alerts the LLM actually sees.
- **NOTIFY volume tracks raw alert volume, not LLM-call volume**: a 10× larger environment generates ~10× more genuinely-actionable security events regardless of how aggressively you pre-filter. The LLM still produces ~the same NOTIFY rate from a given real-world activity level.
- **LLM-call rate determines hardware sizing**; NOTIFY rate determines analyst load. They scale on different axes.
- SMB numbers are estimated by extrapolation from home-lab measurements. The pipeline's raw *capacity* to absorb SMB-scale volume is not in question — sustained load testing has run the full pipeline clean at rates up to ~29.8M alerts/day, far above any SMB — so what the SMB estimates project is the steady-state LLM-call and analyst load at that scale, not whether the pipeline can keep up.

At that scale, NOTIFY volume scales with alert volume — roughly **20-30 NOTIFY/day at steady state** (after tuning) and **50-100 NOTIFY/day pre-tuning** (the first 1-2 weeks of operation, extrapolating from this lab's measured 5-10/day pre-tuning rate). Note that this home lab's ~0-2/day floor is NOT a realistic SMB steady-state target: that floor was reached by hand-writing per-host note context for roughly a dozen hosts. v1.0's `hosts.json` applies notes per individual host with no role-based notes (a note that applies to all hosts of a given role), so reaching the same noise reduction across hundreds of SMB hosts would mean manually writing and pasting near-identical notes host-by-host — impractically labor-intensive at scale. The ~20-30/day SMB estimate reflects what's realistically reachable given that constraint, not a pipeline limit. (The v1.1 roles abstraction on the roadmap — `roles.json` with shared per-role LLM context that hosts reference by name, and `role_notes` in `rules.json` — directly addresses this: it lets one note apply to every host of a given role instead of being pasted host-by-host, which is what would make the home-lab tuning result achievable at SMB scale. See roadmap.md.) At 5-10 minutes of analyst time per NOTIFY to actually investigate and respond, steady-state load is 2-5 hours/day of focused triage work — meaningful workload for a dedicated security analyst, but not overwhelming. Pre-tuning load could briefly reach 4-10 hours/day until rules and host notes settle, which is something to plan for in the rollout (consider running level-6-plus-filters from day one in SMB deployments rather than escalate-everything, since the 10× extrapolation assumes the tuned filter is in place). This is the scale at which jrSOCtriage's value proposition shifts from "hobby project that makes home lab alerts more legible" to "infrastructure that gives an SMB security analyst a usable, prioritized worklist."

The SMB *analyst-load and LLM-volume* figures are an extrapolation from home-lab measurements, not a direct SMB measurement — but the underlying pipeline throughput they ride on is demonstrated, not assumed: the full pipeline has been load-tested clean well above SMB scale. The extrapolation is about workload at scale, grounded in real throughput, not about untested capacity.

**Fail loudly, fail visibly.** When all LLM endpoints fail, the pipeline emits a synthetic `VERDICT: FAILED` record with a structured reason. Operators can search Graylog for `gl2_llm_verdict:FAILED` and alert on rate. There are no silent failures.

**Anonymization is fail-closed.** When sending prompts to cloud LLMs, hostnames, IPs, usernames, and domains are mapped to aliases. If anonymization fails for any reason, the call is **refused** rather than sent in cleartext. Local LLMs (Ollama, llama.cpp) skip anonymization since the data never leaves the lab.

---

## A working example

During testing, jrSOCtriage was running on a host with a particular network driver state issue. A Suricata signature on the SPAN sensor caught failed three-way handshakes and forwarded the alert through Wazuh into the pipeline.

When that alert was enriched, the system logs Graylog returned for the host included NIC driver TX error messages — messages that Wazuh itself had no rule matching, so they would never have surfaced as alerts on their own.

The LLM, reading the Suricata alert (the 3-way handshake failures) alongside the host's system logs (the TX errors), produced a `NOTIFY` verdict identifying the NIC driver as the root cause of the failed handshakes.

**The system diagnosed its own host's hardware problem** — by correlating a network-layer alert with kernel-layer telemetry that no single tool had connected.

This is exactly the kind of cross-source correlation that takes a human analyst three or four pivots between tools. The pipeline produced it in one record, in seconds.

---

## Guardrails for LLM escalation

Not every alert needs an LLM verdict. The system provides several guardrails configurable via the web interface or directly in `config.json`:

- **Minimum rule level.** Only alerts at or above a configurable Wazuh rule level escalate to the LLM by default.
- **Always-include networks.** Critical networks (DMZ, domain controllers, VPN gateways) can be configured to always escalate regardless of rule level.
- **Always-include hosts.** Same idea, host-specific.
- **Per-rule overrides.** Specific noisy rules can be excluded; specific quiet rules can be force-escalated.
- **Deduplication windows.** Repeated alerts within the dedup window collapse into one for triage purposes.
- **Escalation conditions.** Per-rule conditions like "AbuseIPDB score > 50" or "count > 4× daily baseline" can override the default suppress.

These guardrails are not a replacement for Wazuh-side filtering. Wazuh remains the right place for hard, static noise removal. jrSOCtriage's guardrails handle the contextual stuff.

See `running_instructions.txt` and `rules_instructions.txt` for the full configuration reference.

---

## Quick start

Minimum viable deployment requires:

- A Linux host with Python 3.13 or 3.14. The pipeline and interface have been validated on Python 3.13 (currently running on the management host) and on Python 3.14 across two sequential host migrations during development (one host on Python 3.14, then a later host on Python 3.14.4).
- Network access to a Wazuh manager's `alerts.json` (local or NFS)
- A working Graylog instance with API access
- A Graylog GELF input configured to receive enriched alert records

Optional but recommended:

- Zeek with current and archived logs accessible
- ntopng with Lua REST API enabled
- Suricata feeding into Wazuh
- AbuseIPDB API key (free tier available)
- Either a local LLM (Ollama or llama.cpp) or a cloud API key (Anthropic/OpenAI/Gemini)

In this mode, jrSOCtriage will aggregate alerts with system logs and feed them back into Graylog without LLM triage. Adding LLM support unlocks the full pipeline.

`setup.sh` handles the Python venv for the web interface and initializes working state files. The repository ships with `*.json.sample` files (config, hosts, rules, users, domain, anonymization) as reference templates. On first run, `setup.sh` copies each sample to its working `.json` filename. The sample files remain in place after copying — they stay available as on-disk references for recovery scenarios. Rerunning `setup.sh` later checks for existing working files and skips the copy if one is present, so re-runs never overwrite operator changes.

After running `setup.sh`, see `getting_started.md` for the step-by-step setup walkthrough. The web interface (`interface.py`) is the recommended way to edit configuration once it's running. If a working file becomes corrupt, stop the relevant service, copy the corresponding `.json.sample` over it (for example, `cp hosts.json.sample hosts.json`), and restart. For `rules.json` specifically, an optional `rules.json.kevin` starter pack is also included — see `rules_instructions.txt` for what it contains and how to use it. See `running_instructions.txt` for full installation, systemd setup, and operational details.

---

## Sample output

The pipeline produces three verdict types: `NOTIFY` (act now), `NOTE` (worth tracking), and `SUPPRESS` (confirmed noise). Real verdicts from the production lab below (slightly trimmed for readability).

The samples below show the verdict, summary, reasoning, and investigation steps. **The actual emails sent to analysts contain the full LLM prompt** — the complete Wazuh alert, all enrichment data (Graylog logs, Zeek flows, ntopng flows, AbuseIPDB/RDNS/Whois lookups), the host inventory and rule context that fed the verdict, and the LLM's full response. The analyst opening a NOTIFY email has every piece of evidence the LLM saw, not just the conclusion. The condensed format below is for readability in the README, not what the operator receives.

### NOTIFY — anti-forensic technique with concrete investigation path

A registry-modification alert on a workstation, escalated as anti-forensic activity:

```
Host: Workstation1
Rule: [5] Registry Value Entry Deleted

SUMMARY: A registry entry in the Background Activity Moderator (BAM)
for `wevtutil.exe` was deleted, which is a known technique for
hiding the execution of log-clearing utilities.

REASONING: The deletion of BAM entries for `wevtutil.exe` is a
specific indicator of anti-forensic activity (T1070.004) used to
erase the history of tool execution. While the associated registry
"Add" and "Change" events suggest routine system-driven registry
churn, the presence of a known log-manipulation utility in the
deleted path warrants immediate verification of log integrity.

MITRE: Defense Evasion, Impact (T1070.004)

MISSING INFO: Investigation is required to determine if
`wevtutil.exe` was actually executed or if event logs were cleared
around the time of the alert.
  Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 1102}
  Check Sysmon/Security logs for recent wevtutil.exe process creation
  Review Windows Security and System logs for unexplained gaps in
  the event timeline
```

Note what the LLM did here: given the Wazuh alert (which already included the MITRE technique classification), the LLM explained *why* this particular registry path matters versus the surrounding benign registry churn, articulated the specific risk (log integrity verification), and produced concrete PowerShell to verify whether the suspected behavior actually occurred. The MITRE attribution came from Wazuh's rule metadata; the contextual reasoning and actionable investigation steps are what the LLM added on top.

### NOTIFY — actionable, immediate attention

Email subject and body produced for a Suricata-flagged inbound connection from a blacklisted external IP to a DMZ web server:

```
Host: dmz-web-01
Rule: [3] Suricata: Alert - SURICATA Applayer Detect protocol only
      one direction

SUMMARY: A blacklisted external IP attempted a connection to the DMZ
web server with significant protocol discrepancies (detected as HTTP
by Suricata and RDP by ntopng), resulting in a TCP reset.

REASONING: The source IP is blacklisted and the protocol mismatch is
characteristic of a scanning or fuzzing attempt targeting the web
service. While Zeek logs a connection reset (RSTO), the presence of
a known-malicious actor with application-layer anomalies on a DMZ
host requires verification that the web service is not being
successfully probed or bypassed.

MISSING INFO: Web server access and error logs are required to
determine if the malformed request reached the application layer or
was dropped by the web server.
  sudo tail -n 50 /var/log/nginx/access.log
  sudo tail -n 50 /var/log/apache2/access.log

BASELINE: Last hour: 1 (avg 0.54/hr) | Last 24h: 8 (avg 12.91/day)
          | Last 7d: 84
```

Note the cross-source correlation: Suricata's protocol detection, ntopng's L7 label disagreement, AbuseIPDB's blacklist hit, and Zeek's connection state all feed into one verdict with concrete investigation commands.

### NOTE — operational issue worth tracking

A Windows Error Reporting alert on a domain controller:

```
SUMMARY: Windows Error Reporting on Domain_Controller indicates a recurring
failure in the Windows Update/Store Agent scanning process
(Error 80248007).

REASONING: The error code 80248007 and the high volume of `.etl`
logs indicate a functional failure of the Windows Update client
during a routine scan. No malicious activity is present, as network
flows are limited to legitimate DNS and known service infrastructure
(Google, Akamai), but the failure indicates a maintenance issue on a
critical host.

MISSING INFO: The specific cause of the update failure within the
Windows Update operational logs.
  Get-Service wuauserv
  Get-WindowsUpdateLog
```

This kind of operational-but-not-urgent signal is exactly what the `NOTE` verdict exists for. A traditional SOC alert pipeline would likely surface this as a generic "Windows Error Reporting" alert with no useful context. The LLM connected the error code to its specific failure mode, ruled out malicious activity using the network evidence, and produced PowerShell commands to investigate further.

### SUPPRESS — confirmed noise with traceable reasoning

A `netstat listening ports` change alert on a hypervisor:

```
VERDICT: SUPPRESS
CONFIDENCE: HIGH
SUMMARY: Port listening state changed due to cupsd process ID change
(312009 -> 340130), a benign artifact of service restart on a
hypervisor running automatic unattended updates.

REASONING: The only substantive difference between previous and
current netstat output is cupsd's PID change on TCP 127.0.0.1:631.
All other listening ports remain identical. Host is documented as a
hypervisor running automatic unattended updates, making service
restarts expected. The alert has fired 3 times in 13 days
(0.56/hr baseline), consistent with periodic service lifecycle
events. No suspicious ports opened, no external listening services,
and no corroborating evidence of compromise in Zeek flows (normal
DNS, HTTP to Ubuntu connectivity-check, internal syslog) or host
logs (only libusb and WiFi driver messages).

MISSING INFO: None.
```

The `SUPPRESS` verdict cites specific evidence: the exact diff (cupsd PID), the host's documented role (hypervisor with auto-updates), the baseline frequency, and the absence of corroborating evidence. That citation discipline is enforced by the prompt template — the LLM is required to show its reasoning, not just state a conclusion. Suppressed alerts remain searchable in Graylog with full reasoning attached.

---

## LLM support

Five LLM types are supported: Ollama, llama.cpp, Anthropic, OpenAI, Gemini. Endpoints can be combined with fallback or round-robin strategies, with automatic retry on transient cloud-API errors.

### Models tested — what works, what doesn't

The single most important configuration decision for this project is which LLM you point at it. Triage quality varies enormously across models, and a model that produces confident-sounding wrong answers is **operationally worse than no triage at all** — it consumes analyst attention without earning it, and erodes trust in the pipeline's verdicts as a whole.

**Tested and recommended:**

| Model | Setup | Notes |
|---|---|---|
| gemma4:26b (Q4_K_M via ollama) | Local, RTX 3090 / 4090 / 5090 (24GB+ VRAM) | Production daily driver in continuous operation since April 14, 2026. Steady-state rate ~2,400 LLM calls/day in escalate-everything mode at current tuning. 4,895-call production sample: mean 15.0s, median 14.0s, p95 22.8s, max 59.6s, min 7.3s. Consistent multi-section synthesis across host inventory, alert content, and network evidence. Q4_K_M is the ollama default; confirm with `ollama show gemma4:26b`. Developer note for forks: do NOT add `num_predict` to the ollama options block for thinking-capable models — doing so caps the reasoning budget and produces empty responses on a small fraction of calls. The same principle applies to llama.cpp's `max_tokens` (see thinking-model section below). |
| gemma4:26b (Q4_K_M via llama.cpp) | Local, RTX 3090 / 4090 / 5090 (24GB+ VRAM) | Same model, same quantization, validated against the same prompts. **Faster than ollama on identical workload across every percentile** — 93-call one-hour production sample at --parallel 4: mean 11.4s, median 11.2s, p95 16.6s, max 21.1s, min 6.9s. Mean ~24% faster, p95 ~27% faster, max dramatically tighter (21.1s vs ollama's 59.6s). Caveat: sample sizes are uneven (4895 vs 93) — llama.cpp's window may not yet have caught a worst-case outlier comparable to ollama's. Same quality and parse stability as ollama. Requires `/v1/chat/completions` endpoint (not `/v1/completions`). See running_instructions for the verified launch command. |
| Claude Haiku 4.5 (`claude-haiku-4-5-20251001`) | Anthropic API | Validated. ~4.5 sec/call against jrSOCtriage's 13-21k character prompts. **Highest-quality triage output observed in this project** — verdicts averaged about one more concrete recommended action per NOTIFY (sometimes an investigative next step, sometimes a remediation step) than the pooled average of GPT-4.1 mini, local gemma4:26b, and Gemini 3 Flash Preview, i.e. more thorough, more actionable output (it even edges out the local daily-driver gemma4 on actionable depth). Choose Haiku when triage-output quality is the priority; choose GPT-4o mini when cost is (see below). |
| GPT-4.1 mini (`gpt-4.1-mini`) | OpenAI API | Validated. Fast few-second cloud endpoint — clean current sample measures ~2.1s median, 2.2s mean (max 3.7s, 15 calls). GPT-4o mini matches it on speed and quality at under half the cost and is the recommended default — see below. (An early ~3.1s figure was measured during an OpenAI service-degradation period; the ~2.1s median is the clean number.) |
| GPT-4o mini (`gpt-4o-mini`) | OpenAI API | Validated. Same speed as GPT-4.1 mini (both ~2.1-2.2s median on this project's full-fat prompts, confirmed head-to-head in clean current samples) and same triage output quality, at markedly lower cost — the recommended default cloud endpoint (and cheap fallback). Measured latency ~2.0-2.2s median across two clean 19-call samples (use the median: at small sample sizes one outlier drags the mean; observed max ranged 3.5-11.6s depending on whether the sample caught a slow call). Measured ~$0.0007/call; token pricing $0.15/1M input, $0.60/1M output (as of mid-2026), roughly 0.375× GPT-4.1 mini's $0.40/$1.60 — well under half the cost. 128k context, 16k max output — ample for jrSOCtriage's prompt and verdict sizes. Cloud latency varies with provider conditions — measure your own over a representative window rather than trusting any single quoted figure. |
| Gemini 3 Flash Preview (`gemini-3-flash-preview`) | Gemini API | Validated. Currently the most reliable Gemini option (see below). Higher per-token cost than 2.5 Flash but worth it for the reliability gap. Preview models can have behavior changes between revisions. |
| GPT-4o (`gpt-4o`) | OpenAI API | Validated. Worked well, less cost-effective than gpt-4.1-mini. |

**Tested but availability-limited:**

| Model | Setup | Issue |
|---|---|---|
| Gemini 2.5 Flash (`gemini-2.5-flash`) | Gemini API | Produces correct triage output when it works. However, even at paid tier this model 503s frequently — Google routes Flash traffic onto shared/burstable capacity that does not guarantee per-request availability. Observed periods of being effectively unusable for stretches of minutes to hours. Pipeline retry/fallback handles this, but if Gemini Flash is your only cloud option, expect intermittent reliance on whatever else you've configured. Prefer `gemini-3-flash-preview` or use a non-Gemini cloud endpoint. |

**Tested and NOT recommended:**

| Model | Setup | Failure mode |
|---|---|---|
| phi-4 14B (any quantization) | Local, 16GB GPU | Ignores host inventory notes; reasoning often addresses the wrong question entirely (e.g., describing network traffic when the alert is about authentication); generic "looks normal" reasoning regardless of alert content. |
| gemma4:26b (Q4_0, Q3_K_M, or lower) | Local, 16GB GPU | Heavy hallucination, escalates routine activity as suspicious. Q4_K_M (the ollama default) IS the validated configuration; aggressive quantization below that breaks reasoning. |
| OpenAI nano models (any `*-nano` tier, e.g. `gpt-4.1-nano`) | OpenAI API | No OpenAI nano model produced output of high enough quality for reliable triage — reasoning too shallow/inconsistent for the multi-source synthesis triage requires. The nano tier is below the quality floor for this task; use GPT-4o mini (the cheapest tier that IS validated) instead. |
| Any model via free/cheap-tier cloud APIs (e.g., gemma4:31b on Gemini free tier) | Cloud API | Free and cheap-tier cloud APIs frequently impose silent prompt-context limits well below the model's advertised capacity. When prompts exceed that hidden limit, the API truncates without warning — the model then generates output based on partial input, including hallucinated values that look plausible (invented IPs matching the host inventory shape) and broken response format (missing VERDICT/CONFIDENCE/SUMMARY structure). **The failure is the API's silent truncation, not the model's reasoning.** Diagnostic symptom: hallucinated context-shaped values plus missing structural output. Operators seeing this should reduce `sources.graylog.context_window_minutes` to shrink prompts, move to a paid tier with documented larger context windows, or use a local model. |

**The pattern:** smaller models, and even larger models on quantization or context budgets too tight to handle real triage prompts, do not produce output worth shipping to an analyst. **Do not run jrSOCtriage with a model that fits comfortably on a 16GB GPU**, and **do not assume "paid API access" means your prompts will fit** — verify by checking that responses follow the documented VERDICT/CONFIDENCE/SUMMARY/REASONING/MISSING INFO structure.

### Rate-limit headroom and deployment sizing

All three validated cloud providers have RPM headroom for home-lab scale. The meaningful differentiator is **maximum sustainable LLM escalations per day** before hitting the rate-limit ceiling:

| Provider | Tier 1 RPM | Max LLM escalations/day | Tier 1 TPM (token cost ceiling) |
|---|---|---|---|
| OpenAI gpt-4.1-mini | 500 | **720,000** | 200,000 |
| Gemini 3 Flash Preview | 150 | 216,000 | not header-exposed |
| Anthropic Haiku 4.5 | 50 | 72,000 | 60,000 combined |

(RPM × 60 × 24, assuming sustained throughput at the documented ceiling. These extreme volumes are cloud-provider rate-limit ceilings, not benchmarked sustained rates; a future load-harness campaign will replace them with measured numbers.)

**Plan for the ceiling at 60% utilization**, not 100%. Alert traffic is bursty — a single triggering event (login storm, scanner sweep, service flap) can spike multiple alerts into the LLM queue within seconds. Sustained operation at 100% leaves no headroom for these bursts and will produce rate-limit failures during exactly the events that most need triage. The 60% guideline gives roughly 1.67× burst capacity:

| Provider | Recommended sustained max LLM escalations/day (60% of ceiling) |
|---|---|
| OpenAI gpt-4.1-mini | **432,000** |
| Gemini 3 Flash Preview | 129,600 |
| Anthropic Haiku 4.5 | 43,200 |

For reference, this README's home-lab baseline runs ~2,400 LLM escalations/day in escalate-everything mode — far below all three recommended sustained maxes. The ceiling matters at SMB scale where alert volume and host inventory grow with deployment size. TPM is the secondary constraint and is more cost-shaped than performance-shaped — it governs how much spend you can burn through before being rate-limited at Tier 1 budget caps.

### Recommended deployment configurations

**Home-lab (recommended):** local gemma4:26b (Q4_K_M, the ollama default quantization) on a 24GB+ GPU as primary, with a validated cloud model as fallback. Either ollama or llama.cpp as the local engine — both validated, identical verdict quality. The choice involves a real tradeoff:

- **Ollama** is easier to set up and operate, gentler on the GPU (moderate sustained thermal and memory bandwidth load), with a measured 1-2 FAILED per day in this project's reference deployment. Cloud fallback cost at that rate: approximately $1/year on GPT-4.1-mini (measured at $0.0023/call against this project's full-fat prompts; other validated cloud models priced separately).

- **llama.cpp** is ~25-30% faster per call (mean ~11s vs ~15s), at the cost of more setup work (build from source, manage the server process, response-handling quirks documented in `running_instructions.txt`). Tighter scheduling — no idle recovery windows between calls — produces higher sustained GPU thermal and memory bandwidth load than Ollama, which may produce more FAILED-to-converge events on hardware with limited thermal margin. This project's reference deployment has observed 1-10 FAILED per day on llama.cpp across different conditions on consumer-grade hardware (RTX 3090). Cloud fallback cost at the upper end of that range: approximately $8/year on GPT-4.1-mini (measured rate; other validated cloud models priced separately). Still trivial against the per-call latency improvement.

For the cloud fallback, **Claude Haiku 4.5 and GPT-4.1 mini are both strong recommendations** — pick based on whichever API you already have a relationship with. Gemini 3 Flash Preview also works as a fallback. **Avoid Gemini 2.5 Flash as sole cloud fallback** due to its availability issues at paid tier.

Either local engine paired with cloud fallback produces effectively 100% reliable verdict production at near-zero cloud cost. The cost difference between them ($1 vs $8/year on GPT-4.1-mini at measured rate) is negligible against the operational characteristics. Pick Ollama for simplicity and lighter GPU stress; pick llama.cpp for faster happy-path latency if your hardware can sustain it. Anonymization is applied automatically to anything sent to the cloud endpoint.

**Why local-primary, not cloud-primary at home-lab scale:** beyond cost, local inference protects against the silent prompt-truncation failure mode documented above. Cloud APIs do not currently provide a reliable way to detect that your prompt was truncated before the model generated output; you only see the symptoms after the fact. Local engines process the prompt you sent.

**SMB scale (50-500 endpoints, ~2,400-12,000 LLM escalations/day with appropriate filtering applied — see running_instructions.txt sizing math):** local-primary with cloud fallback remains the most cost-effective configuration if LLM call rate after filtering stays within local capacity (single RTX 3090 sustained: ~3 calls/min operational ceiling, ~4,000-5,000 calls/day; multi-worker local extends this further). Cloud-primary is the right choice when filtered call rate exceeds local capacity, when no local GPU is available, or when operational simplicity outweighs cost. At cloud-primary configurations, GPT-4.1 mini is the recommended primary at this scale — highest RPM ceiling and TPM headroom of the validated cloud endpoints, plus OpenAI's auto-tier-up behavior means sustained usage grows your ceiling without explicit upgrade requests. Claude Haiku 4.5 or Gemini 3 Flash Preview work but will require explicit Tier 2 upgrades sooner. **Load testing against your environment is strongly recommended before production deployment — the SMB-scale numbers above are derived from extrapolation of validated home-lab measurements. The synthetic load harness that ran the May 2026 tests exists; what remains future work is a broader validation campaign across SMB-shaped host counts and worker configurations, so treat the SMB figures as extrapolation until you've measured your own deployment.**

**Quick start / no local hardware at home-lab scale:** Claude Haiku 4.5, GPT-4.1 mini, or GPT-4o mini as primary, no local LLM. All are validated and produce high-quality verdicts at low per-call cost. Two axes to pick on: GPT-4o mini is the cheapest (~$0.0007/call at this project's prompt sizes) at solid triage quality; Claude Haiku 4.5 is the highest-quality of the cheap models (averaged ~1 more concrete recommended action per NOTIFY) if you'd rather optimize triage depth than cost.

For evaluating the project, or for deployments without local GPU capacity, a cloud-only configuration works. Claude Haiku 4.5, GPT-4.1 mini, GPT-4o mini, and Gemini 3 Flash Preview are all validated. Pick whichever your team already has API access to. At typical home lab volumes with default filtering (rules engine active, dedup at 240 seconds, min_rule_level at 6, ~240 LLM calls/day at this lab's raw alert volume), expect roughly $200/year in API cost on GPT-4.1-mini (measured at $0.0023/call against this project's full-fat prompts of 13-21k characters with full enrichment). GPT-4o mini is the cheaper option at comparable triage quality — measured ~$0.0007/call at the same prompt sizes (roughly 0.375× GPT-4.1-mini's per-token pricing), which brings the same ~240 calls/day filtered volume to roughly $60/year. Claude Haiku 4.5 and Gemini 3 Flash Preview have not been measured at the same prompt sizes by this project — their pricing differs per provider, so verify your specific provider's per-token cost for your expected volume. Anonymization should be enabled. Cloud-as-primary at full firehose ("escalate everything" mode, ~2,400 LLM calls/day at this lab's raw alert volume) is significantly more expensive — roughly $2,000/year sustained on GPT-4.1-mini (or roughly $600/year on GPT-4o mini) — so this configuration assumes disciplined filtering. Monitor verdicts for the truncation symptom (hallucinated values, missing VERDICT structure) and reduce `context_window_minutes` if observed.

**Privacy-sensitive deployments:** local primary only, no cloud fallback.

Operators who don't want any alert data leaving their network even with anonymization should run local-only. Accept the 1-2 FAILED verdicts per day as the cost of strict privacy. Failover behavior is documented; FAILED states are not silent.

**Enrichment-only mode:** no LLM at all.

Set `llm.enabled: false` (or untick "Enable LLM triage" in the LLM Endpoints card) to run the pipeline without LLM verdicts. Alerts are still enriched with host inventory, IP reputation, geo, MITRE mapping, baseline frequency, Zeek and ntopng context, and shipped to Graylog with all enrichment fields. No LLM call is made and no email is sent. Useful when:

- Evaluating the enrichment value before committing to LLM cost
- A separate SIEM, SOAR, or analyst workflow consumes the enriched alerts and does its own analysis
- An MSSP arrangement where jrSOCtriage feeds an upstream system
- Privacy-sensitive environments where even local LLM inference is too much

Note: Graylog stream rules that filter on `_gl2_triage_complete:true` will not match in this mode. Stream rules need to key off other enrichment fields (e.g., `_gl2_abuse_score`, `wazuh_rule_level`, host/IP fields) instead.

### Hardware

Validated hardware for local primary:

- **RTX 3090 (24GB)** — used market, ~$700-900. The card the project's production data was generated on. Validated for sustained ~2,400 alerts/day with gemma4:26b at Q4_K_M/Q4_K_L quantization.
- **RTX 4090 (24GB)** — current generation. Faster than 3090 at the same workload.
- **RTX 5090 (32GB)** — current generation, best future-proofing. Recommended for new purchases.

Sub-24GB GPUs are not recommended. Quantizing gemma4:26b down to fit on 16GB GPUs has been tested and produces unacceptable verdict quality. Running a smaller model that natively fits on 16GB has also been tested and produces unacceptable verdict quality. Either work around this constraint with cloud, or invest in 24GB+ VRAM.

See `running_instructions.txt` → MODEL SELECTION for the full evidence base, cost methodology, and configuration guidance.

---

## Scale and limits

The development environment generates approximately 29,000-30,000 raw Wazuh alerts/day (with observed bursts up to ~43,000 on storm days). This project's home lab runs in escalate-everything mode (no Wazuh-side filtering, level 0+, everything sent to jrSOCtriage for development visibility) — deliberately atypical and chosen to stress-test the pipeline. The reason this mode is practical here is that the lab runs a **local LLM (gemma4:26b on an RTX 3090), so each escalation has no per-call cost** — escalating everything buys maximum visibility for free, which is exactly what you want when developing and characterizing the system. A typical deployment will not run this way: on a cloud LLM every escalation costs money, and even on a shared local GPU you may want to conserve capacity, so the sensible production posture is to filter — either upstream at Wazuh (min_rule_level, agent groups, rule exclusions) or with jrSOCtriage's own level-6 cutoff plus rules.json. In short, **escalate-everything is the lab's mode because its inference is free; filtering is the right default for anyone paying per call or sharing a GPU.** It is worth noting, though, that an organization with its own LLM capacity may run escalate-everything by deliberate choice rather than constraint: the low-severity visibility it preserves (see above) is exactly where low-impact config issues and stealthy, deliberately-below-threshold intrusion activity live — the signals reasonable severity filters drop by definition. After deduplication (configurable window, currently 240 seconds; was 30 seconds earlier in development), that drops to about 2,400 unique alerts/day reaching the LLM — a ~12:1 collapse ratio. In level-6-plus-filters mode (default min_rule_level=6 with populated rules.json and hosts.json), the same dedup-and-rules layering brings this down to roughly 240 alerts/day actually escalated to the LLM — a further ~10× reduction. A normal SMB deployment runs Wazuh-side filtering and would land at similar LLM volumes even at substantially higher raw alert volumes, because the Wazuh-side filters do the upstream heavy lifting that this project's lab deliberately skips. The dedup window is the dominant lever within jrSOCtriage itself: widening from 30s to 240s during development reduced LLM volume proportionally in both modes, because the additional collapses happened on high-frequency repeat-fire patterns (DC logon storms, AppArmor docker noise, etc.).

**Confirmed working:** sustained ~2,400 LLM-triaged alerts/day on a single Ollama node (gemma4:26b on RTX 3090) in continuous operation since April 14, 2026. No backlog, no queue saturation, no endpoint timeouts. The dedup window was widened from 30s to 240s during development; this reduced LLM volume from ~4,000/day to ~2,400/day while the underlying raw alert volume (29,000-30,000/day) stayed constant. The lower number was not separately re-validated through a fresh sustained-load run — but the pipeline has been running continuously at the lower volume since the dedup change with the same hardware and no observed degradation.

**What "confirmed working" does NOT mean:** this measurement is for home-lab scale and steady-state operation. It does not establish that a single 3090 can absorb SMB-scale alert storms or sustained higher rates. See the SMB scaling implication discussion above for the surge-handling caveat — local-only SMB deployments at v1.0 should configure cloud fallback as primary, or wait for v1.1's adaptive surge handling.

**Storm handling:** alert storms — bursts of thousands of alerts in minutes, or days at multiples of baseline volume — have occurred many times in production. Only the very first one caused trouble, on a roughly week-old version of the system before the current defenses existed; it surfaced weaknesses in the original dedup design and directly motivated the `rules.json` engine (per-rule hourly caps) and the longer 240-second dedup window. Every storm since has been absorbed by the configuration without operator-visible degradation. Two reasons: storms are usually repeat-offenders (the same rule firing on the same host), which is exactly what dedup collapses before the LLM ever sees them — one observed 10,866-alert burst became a single LLM call; and the LLM stage normally runs with several times more headroom than steady-state load, so volume can multiply before it approaches saturation. The system has been run in "escalate everything" mode (every alert sent to the LLM) on a single local Ollama endpoint with no cloud fallback for an extended sustained run with throughput, dedup, email, Graylog shipping, and resource use all stable. It has not been formally stress-tested at peak rates beyond what production has organically produced — see running_instructions.txt for the full storm history and the measured load tests.

**Single-endpoint reliability under sustained load varies by local engine.**

**Ollama (gemma4:26b, Q4_K_M default):** Continuous "escalate everything" operation on this project's RTX 3090 reference deployment produces roughly 1-2 VERDICT: FAILED records per day against ~2,400 LLM-triaged alerts/day below ~74°F office ambient, rising to ~4-5/day at ~74°F and above — a per-call failure rate of roughly 0.04-0.21%. The temperature correlation was narrowed down over a couple of days of investigation; warmer ambient pushes the GPU into thermal conditions that occasionally fail a local call. With cloud fallback configured these failed local calls fall back to the cloud endpoint rather than producing a FAILED verdict, so the operator impact is negligible — it shows up as a small increase in cloud calls on warm days, not as lost triage. Ollama's scheduler provides idle recovery windows between calls that keep GPU memory and compute stress moderate. The practical takeaway: local GPU inference is sensitive to ambient temperature; adequate cooling (or a cloud fallback) matters more than the raw failure numbers suggest.

**llama.cpp (same model, same quantization):** Same verdict quality and ~25-30% faster per-call inference (mean ~11s vs ~15s), but tighter scheduling — no idle recovery windows between calls. This produces noticeably higher sustained GPU memory bandwidth and thermal load than Ollama under continuous operation. On this project's reference hardware (consumer-grade RTX 3090), FAILED-to-converge rates have been observed from approximately 1 to 10 per day depending on ambient temperature and active operational load. Overnight at cool ambient: near zero. Daytime at warmer ambient under active use: substantially higher. The mechanism has not been fully isolated — potentially thermal margin, load-correlated GPU resource contention, model convergence variability, or some combination. Other operators with newer GPUs, better cooling, lower ambient temperatures, or different workload patterns should expect different rates.

**FAILED is by design a triage signal handled by the architecture, not a failure mode.** The alerts that exceed the per-call timeout are *by definition* the hardest — the ones where the local model's reasoning budget was insufficient to reach a confident verdict within the time budget. This is exactly where a smarter, faster cloud LLM adds the most value: a Haiku-tier or GPT-4.1-mini-tier model handles these in 4-6 seconds with a clean verdict. The cloud-fallback architecture isn't redundancy; it's *specialist escalation*. Local model handles the bulk efficiently; cloud handles the genuinely-hard cases at pennies per call. Operators running with cloud fallback configured should expect very few FAILED surfaced operationally (each is immediately covered by the failover); operators running single-endpoint should expect the per-day rate visible in Graylog (`gl2_llm_verdict:FAILED`) and alert if it climbs substantially.

**Cloud-LLM scaling potential (estimated, not measured at the specific worker counts below):** the 2,400/day figure above is anchored on local-LLM inference being the bottleneck at home-lab scale. With cloud LLM endpoints (Haiku-tier, measured at 4-6 sec/call against jrSOCtriage's 13-21k character prompts), the LLM stage stops dominating end-to-end latency. Reading the code and reasoning about the serial path per alert produces estimates of roughly 9-12 alerts/min sustained per worker, scaling to ~400-600/min at 50 workers before per-worker enrichment overhead, the single-threaded ingest loop reading alerts.json, or upstream API rate limits become the binding constraint. **These per-worker throughput numbers have not been verified by load testing at the worker counts shown.** End-to-end load testing has since confirmed the pipeline holds far above those early figures — clean at rates up to ~29.8M raw alerts/day in level-6 mode across about three hours of testing, and clean in escalate-everything mode to ~6.8–7.2M raw alerts/day — all with zero ingest loss and zero abandoned work (see `running_instructions.txt` → WORKED EXAMPLE for full numbers). Those are whole-pipeline throughput results; the specific per-worker counts in the table below remain reasoned ballpark guidance, not directly measured at each worker count. (The load wasn't random JSON: the harness multiplies *real* alerts from the development environment across synthetic host identities, preserving real rule IDs and field shape, with timestamps spread over a configurable window so the load arrives over time rather than as one impossible same-timestamp burst. It exercises the whole pipeline — dedup, enrichment, Graylog round-trips, LLM, GELF shipping — the way real traffic would.) These per-worker estimates would be refined by a more extensive load-harness campaign across many worker counts, which remains future work. For most home-lab and small-team deployments, cost is the binding constraint long before throughput is — see `running_instructions.txt` → DON'T OVER-PROVISION for the cost/quality tradeoff.

**Where the architecture would actually break:** in rough order of which limit hits first under sustained load — single-threaded ingest loop reading alerts.json sequentially, then per-alert enrichment overhead (Python GIL on enrichment fan-out), then upstream API stress (Graylog, ntopng), then **Graylog round-trip throughput** (each Stream 2 alert both reads a context-window query from Graylog — up to ~100 messages, the larger flow — and writes back an enriched GELF record; when Graylog and jrSOCtriage are colocated this all goes via loopback and the network is essentially free, leaving Graylog's own query/ingest capacity as the constraint; for separate hosts on 1 Gbps the read-dominated round trip caps a single node around a few hundred thousand to ~1M enriched alerts/day, single-digit-million raw/day; 10 Gbps multiplies by ~10; multi-node Graylog clusters scale further), then AbuseIPDB rate limits, then cloud LLM API rate limits. **SQLite is not on this list.** The disk-bound theoretical ceiling on reference hardware (consumer NVMe at ~5,200 fdatasync ops/sec, ~1 fsync per dedup-passing alert in v1.0) is on the order of hundreds of millions of alerts per day — orders of magnitude above any realistic deployment, and a direct stress test confirmed it in practice: on-disk single-disk SQLite ran clean to ~30.9M raw alerts/day (~1000× this lab's normal volume) on a fully shared consumer NVMe with zero database-lock contention, no ceiling reached. You do not need special storage for the database; on-disk is the recommended default. For larger installations today, pre-filtering at the Wazuh layer and adding workers remains the cleanest path. The built-in rules engine and decision guardrails handle most home-lab and small-business scenarios. The Graylog round-trip figures above are order-of-magnitude estimates that have not been load-tested; the biggest lever on the read side is the configurable context-window setting (default 30s each side of the alert, wider windows pull proportionally more per query), so measure your own deployment before making a sizing decision based on them.

**Not currently in scope:**

- Enterprise SIEM features: role-based access, distributed log management, compliance reporting, formal SLA support contracts. jrSOCtriage's throughput handles enterprise-scale alert volumes (load-tested well beyond hundreds of thousands of alerts/day) — what it lacks is the operational and organizational tooling enterprises expect from a SIEM platform.
- Adaptive burst capacity (queue-depth-aware cloud activation) — planned roadmap feature
- Hardware token / keyring-based credential storage (current model is plaintext config.json, root-owned, mode 600)

---

## Known limitations

- **Credentials are plaintext** in `config.json`. Restrict file permissions accordingly. See `running_instructions.txt` → SECURITY: FILE PROTECTION.
- **Failover is per-call**, not queue-depth-aware. If your local LLM is keeping up but slow, alerts queue serially rather than dispatching to cloud.
- **No native horizontal scaling.** Single-node design.
- **Designed for labs and businesses up to medium-sized.** In testing the pipeline handled substantially higher volumes than that; how much higher hasn't been mapped, since the goal was to establish what works rather than find the breaking point. Will operate beyond the designed scope but was not designed for it.
- **Authentication user management is terminal-based in v1.** First-run setup, adding users (`interface.py --add-user`), and password changes happen at the terminal. A web-based flow for these is planned for a future release.
- **Flat (no-roles-yet) auth model.** v1.0 supports multiple administrator accounts, but treats every authenticated user as having full configuration access — there is no role-based separation between admin and standard users yet. The `role` field exists in the auth schema for forward compatibility but is not enforced in v1.0. In practice this means v1.0 is fine for a team of administrators who all share full trust (each can see and change all config); what it does not yet support is differentiated roles — a read-only analyst, a config-only admin, scoped access per user. Role enforcement is on the roadmap for a later release. Until then, only grant accounts to people you would trust with full configuration access, since every account effectively has it.

---

## Tested environments

### Operating systems
- Ubuntu 25.10 (questing) — jrSOCtriage host VM
- Ubuntu 26.04 LTS — jrSOCtriage host VM
- Fedora 43 — LLM host running Ollama; also validated as a bare-metal jrSOCtriage host

### Python
- Python 3.13 (current production on management host, Ubuntu 25.10)
- Python 3.14 and 3.14.4 (validated sequentially on two different hosts during development; required explicit resource lifecycle management — under 3.14.x, implicit cleanup of sqlite connections and sockets allowed file-descriptor accumulation in hot paths; see `running_instructions.txt` for FD lifecycle notes)
- Python 3.12 has not been formally tested. The codebase is unlikely to use 3.13-specific syntax, but no test runs have been performed on 3.12.

### Wazuh
- Wazuh manager 4.x with file-based alert output (`alerts.json`)

### Graylog
- Graylog 5.x with GELF UDP input
- Both HTTP and HTTPS endpoints supported

### Hypervisor / VM platform
- VMware (host VM for the jrSOCtriage management host)
- Bare-metal Linux (LLM host)

### Network sensors
- Zeek 8.0.5 (current and rotated archive logs, two-path configuration). Older Zeek versions are likely fine — the integration uses standard log fields (conn.log, dns.log, ntlm.log) that have been stable for years. Newer versions have not been tested.
- Suricata: tested with whatever ships in the Ubuntu 26.04 LTS repository. Specific version not recorded. Older Suricata versions are likely fine — the integration uses Wazuh's normalized rule output, not Suricata's native eve.json, so Suricata version drift is buffered by Wazuh.
- ntopng: tested with both 5.2.250226 Community build (older) and whatever ships in Ubuntu 26.04 LTS (newer). Specific newer version not recorded. The integration uses the Lua REST v2 API (`/lua/rest/v2/get/host/data.lua` and related endpoints). Very old ntopng versions that lack the v2 REST API will not work; v2-capable versions in either direction should work.

### LLM hardware
- NVIDIA RTX 3090 (24GB) — sustained ~2,400 alerts/day with gemma4:26b (Q4_K_M quantization) local inference. Validated in continuous operation.
- NVIDIA RTX 4090 (24GB) and RTX 5090 (32GB) — current-generation cards in the same VRAM class are expected to work; recommended for new purchases.
- Sub-24GB GPUs are not recommended. See "Models tested — what works, what doesn't" above for the full reasoning.

### Production deployment shape
- 19-host segmented home lab
- Multiple VLANs (clients, Windows servers, Linux management, DMZ, attack/defend)
- Mixed Linux and Windows endpoints, Active Directory domain controllers
- WireGuard VPN, multiple network sensors
- ~29,000-30,000 raw Wazuh alerts/day → ~2,400 deduplicated → 0-2 NOTIFY + ~50-80 NOTE outcomes daily under "send everything to LLM" configuration (NOTIFY at the steady state reached after sustained tuning)
- Sustained over multi-day continuous runs

### Not yet tested
- Multi-tenant or multi-site deployments
- Sustained alert storms at peak rates substantially above one hour at the historical pre-fix volume — the specific reproduced storm was handled cleanly post-fix, but the upper bound has not been formally probed
- Loads materially above 2,400 LLM-triaged alerts/day on local-LLM-only deployments (single-3090 capacity has not been pushed beyond this since the dedup window change; earlier 4,000/day single-3090 escalate-everything operation pre-dedup-change is consistent with this hardware handling 2-4× the current rate, but has not been re-validated at higher rates with current code)
- Cloud-primary mode at scales above the home-lab volume (estimates exist but no load testing has been performed)
- Adaptive cloud burst capacity (planned roadmap feature)
- Hardware-token or keyring-based credential storage

---

## Documentation

- `running_instructions.txt` — installation, systemd setup, operational reference, security guidance, troubleshooting
- `interface_guide.txt` — web interface reference, tab-by-tab field documentation
- `rules_instructions.txt` — rules engine configuration, per-rule overrides, escalation conditions
- `graylog_searches.txt` — useful Graylog queries for triaged alerts
- `info.txt` — high-level architecture overview

---

## Author

Built by Kevin Lessek to solve a real workflow problem in his home lab, deployed and refined across 19 hosts over an extended development period. The project also serves as a portfolio piece, but the goal was the work, not the resume bullet point.

### Development approach

This project was developed using LLM-assisted coding in an iterative, module-by-module process — but the core discipline was function-by-function code audit with deliberate repetition. Every function in every module was reviewed against the actual deployed behavior, not just at first write but at multiple passes after weeks of production observation. Findings were captured as numbered pins, triaged for severity, and addressed in small focused batches. Modules that had been "complete" weeks earlier were revisited and re-audited as new patterns emerged from production data — silent coercion bugs, atomicity gaps, drift between docs and behavior. Each pass tightened the codebase further.

The result is a codebase where the same function may have been read carefully five or six times across the development period, each time looking for a different class of issue: correctness on first pass, error handling on second, boundary conditions on third, security posture on fourth, durability on fifth. This is slower than write-once development but produces meaningfully fewer surprises in production, which mattered for a project intended to run unattended on a security-critical pipeline.

The repetition was not busywork. Production behavior taught lessons that no amount of upfront design caught — a silent coercion bug in the configuration save path that turned a deliberate operator setting back into the default, a gap in storm tracking that motivated reworking the deduplication cache, drift in the restart UI between what was logged and what got displayed. Each surfaced after its respective module had been "done" and shipped. Going back through a module already in production with the perspective of "this is how it actually behaves under load" was where most of the v1.0 hardening came from.

---

## License

jrSOCtriage is released under a **custom source-available license**. See the `LICENSE` file in this repository for the complete terms.

**Quick summary** (the LICENSE file is authoritative — read it for the binding terms):

- **You may** use this software for personal, educational, or research purposes, and inside your own organization to protect your own systems, networks, employees, and data — even if your organization is a for-profit company. You may modify it for your own use, make backups (including encrypted backups), and maintain a private fork. Production deployment is permitted.
- **You may NOT** offer it as a hosted, managed, or SaaS service to anyone else, deliver SOC/MDR/monitoring or alert-triage services to other organizations using it, sell or sublicense it, embed it in any product or service you sell, publicly fork or republish it (on GitHub or elsewhere), or distribute your modified version outside your organization — without a separate commercial license.
- **Consultants and integrators** can install, configure, and provide initial setup of jrSOCtriage for a client at no additional cost, provided the client then runs it for their own internal operations. A commercial license is only required when a third party (such as an MSSP) operates the software on behalf of the client as part of an ongoing service.
- **Contributions** are not accepted at this time. Pull requests and patches will be closed without merge. You are welcome to fork privately for your own use and to suggest changes via issue reports.

This is not a standard open-source license. Before deploying jrSOCtriage in your environment, review the LICENSE file carefully. If your intended use is unclear, reach out before proceeding.

For commercial licensing inquiries: see the contact information in the LICENSE file.
