# Writing Notes That Improve LLM Triage

This document explains why notes in `hosts.json` and `rules.json` matter
as much as the data they annotate, with concrete before-and-after
examples from production.

jrSOCtriage has two places where operator-written notes shape every
prompt the LLM sees:

- **Host notes** in `hosts.json` — context that applies to every alert
  on a specific host
- **Rule notes** in `rules.json` — context that applies to every alert
  matching a specific Wazuh rule, across all hosts (or scoped per-host
  via per-host rule notes)

Both work the same way mechanically: the operator writes free-form
text, the pipeline injects it into the prompt at triage time, the LLM
uses it as guidance. Different scopes solve different problems.

If you take one thing from this document: **a good note is the
difference between your phone ringing at 4am and not ringing at 4am.**
Read on for the evidence.

---

## What a note is, and what it isn't

A note is the operator's hand-off to the LLM about how to think about
alerts. It is not:

- A description of what the host or rule does (host metadata fields and
  rule descriptions already capture that)
- A list of installed software or rule technical details (the LLM
  doesn't need an inventory)
- A purpose statement in business terms (the LLM is triaging alerts,
  not doing risk modeling)

A note IS:

- Operational nuance — what's normal here that would look anomalous in
  a textbook
- Investigation directives — when an alert fires, look at X first,
  weight Y heavily, treat Z as expected
- Pattern recognition shortcuts — "alerts of this shape are caused by
  this specific thing"
- Conditional decision procedures — "expected when correlated with X,
  investigate if Y"

The LLM has the alert, the network context, the host inventory
metadata, the Zeek flows, and the Graylog logs. What it lacks is
**operator knowledge of what's actually going on day-to-day**. Notes
are where that knowledge lives.

---

# Part 1: Host notes

Host notes apply to every alert involving a specific host. They live
in the `notes` field of each entry in `hosts.json`, and they appear in
the HOST INVENTORY section of every triage prompt for alerts touching
that host.

---

## Concrete example: dmz-web-01 (DMZ web server)

This is a real production example from jrSOCtriage. The same alert
signature fired against the same host one week apart, with a different
note in `hosts.json` between the two. The verdicts are dramatically
different — and the difference is the note, not the alert.

### Before — note v1 (May 2, 2026)

```
dmz-web-01 | web_server | debian | [DMZ host] | Note: Minimum Debian install
in DMZ. Port 443 only, inbound forwarded from pfSense. No DNS A record.
Any unexpected outbound, non-443 traffic, or internal network contact
is suspicious.
```

This is a competent note. It describes the host's posture and what
would be anomalous. It doesn't tell the LLM anything about how to
investigate when an alert fires.

**Alert that fired:** Suricata "HTTP missing Host header" — an external
IP with abuse_score=100 sent a malformed HTTP request. Fired 79 times
that week.

**LLM verdict:**
- VERDICT: NOTIFY
- CONFIDENCE: HIGH
- REASONING: "The high frequency of the alert (79 occurrences) and the
  high-risk source IP indicate an active, automated scanning campaign.
  It is necessary to verify that these malformed requests did not result
  in a successful breach or trigger any unauthorized outbound traffic
  from the DMZ host."
- MISSING INFO:
  - `grep "185.189.182.234" /var/log/nginx/access.log`
  - `grep "185.189.182.234" /var/log/apache2/access.log`
  - `grep "192.168.40.10" /var/log/pfSense/filter.log`

**Operator experience:** Email at 14:21. Operator opens it, reads three
grep commands, runs them, sees that the malformed requests got 400
responses, decides this is a routine scanner, closes the ticket. Total
time to resolve: maybe 5 minutes plus the context-switch cost. The
verdict was *correct in escalating* (a 100-abuse-score scanner deserves
a look) but the resolution required operator legwork.

### After — note v2 (May 9, 2026)

```
dmz-web-01 | web_server | debian | [DMZ host] | Note: Minimum Debian install
in DMZ. Port 443 only, inbound forwarded from pfSense. No DNS A record.
Any unexpected outbound, non-443 traffic, or internal network contact
is suspicious.  nginx access.log and error.log should be in the output.
If the logs are blank than nothing logged to access.log.  When triaging
dmz-web-01 alerts, examine the nginx access.log entries shipped in HOST LOGS.
The HTTP method, requested URL, status code, and User-Agent are the
highest-signal fields. Suricata signatures describe what was detected
at the network layer; access.log shows what nginx actually saw and how
it responded. Consider these together rather than separately.
```

The added text is investigative directive. It tells the LLM:

- Where to look (HOST LOGS section, nginx access.log)
- What fields matter (method, URL, status, User-Agent)
- How to combine evidence (Suricata = network layer, access.log =
  application layer, treat them as corroborating not separate)

**Alert that fired:** Same Suricata "HTTP missing Host header" signature.
Different external IP (Indonesia, abuse_score=0). Different prompt
context — the new pipeline ships nginx access.log entries in HOST LOGS.

**LLM verdict:**
- VERDICT: NOTE
- CONFIDENCE: HIGH
- REASONING: "The alert is an informational protocol anomaly consistent
  with routine internet scanning. Nginx logs corroborate that the server
  correctly identified the malformed request and terminated the
  transaction with a 400 error, resulting in no impact."
- MISSING INFO: None.

**Operator experience:** No email. NOTE verdicts only email when a
note_address is configured separately. The verdict ships to Graylog and
sits in the timeline; if the operator wants to review NOTE-level
activity, they go look. **Phone doesn't ring.**

### What changed, in three sentences

The note didn't add facts about the host. It added directives for how
to use evidence already present in the prompt. The LLM followed the
directive and produced a verdict that was self-completing — no follow-up
investigation needed.

The abuse_score difference (100 vs 0) is a confounder; a 100-score
scanner might still warrant a NOTIFY. But the *structure* of the
reasoning changed: from "we should verify" to "we did verify, here's
the evidence." That structural shift is what the note bought.

---

## A second example: mgmt-host-01 (out-of-band management host)

This example shows the strongest measurable impact: a note that
eliminated 4-5 false-positive NOTIFY emails per day.

```
mgmt-host-01 | linux_management | debian | Note: Out-of-band management host.
Runs jrSOCtriage pipeline. AppArmor Docker audit events firing every
10s are normal container activity. SMTP/TLS connections to
smtp.gmail.com (port 587) generate Suricata applayer alerts — SPAN
artifact on encrypted SMTP. Not anomalous.
```

Two specific patterns documented as expected:

1. **AppArmor Docker audit events every 10 seconds.** Wazuh's default
   ruleset escalates audit events. Without the note, the LLM sees a
   high-frequency security audit event and reasonably concludes "this
   is a steady stream of policy violations, investigate." With the
   note, the LLM recognizes this as expected container telemetry and
   suppresses.

2. **SMTP/TLS to gmail port 587.** Suricata fires an applayer alert on
   the TLS handshake to encrypted SMTP because it can't decode the
   payload to verify protocol compliance. Without the note, this looks
   like a TLS-anomaly inside SMTP, which is a legitimate concern. With
   the note, the LLM recognizes "SPAN artifact on encrypted SMTP" as
   the cause and suppresses.

**Measurable impact:** Before the note, mgmt-host-01 produced 4-5 NOTIFY-level
emails per day from these two patterns. After the note, those alerts
correctly resolved as SUPPRESS or NOTE — they still show up in Graylog
for visibility, but they stop interrupting the operator.

That's roughly 30 fewer phone-buzzes per week from one host. Multiply
across the host inventory, and the cumulative reduction is the
difference between an alert system that's manageable and one that's
exhausting.

---

## A third example: compute-server-01 (compute / SMB server)

```
compute-server-01 | linux_management | fedora | Note: Primary SOC workstation.
Runs Ollama (gemma4:26b) for LLM triage. Samba server — high SMB
traffic from Workstation1 is normal mapped drive activity.
```

This note prevents a different category of false positive: the
"unusually high traffic between two internal hosts" alert that triggers
on legitimate file-sharing patterns.

Without the note, sustained SMB traffic from a workstation to a server
looks like exfiltration or lateral movement — both legitimate concerns
in the abstract. With the note, the LLM sees the named relationship
(Workstation1 ↔ compute-server-01 SMB is mapped drive activity), checks the traffic against
that expectation, and clears it.

The pattern this note encodes:
**"X talking to Y in volume W via protocol Z is normal because reason R."**

Any time you have an internal communication pattern that would look
suspicious to a stranger, a note like this prevents the LLM from being
that stranger.

---

# Part 2: Rule notes

Rule notes apply to alerts matching a specific Wazuh rule. They live
in `rules.json` and appear in the RULE CONTEXT section at the top of
every triage prompt for matching rules.

`rules.json` provides two related fields, used together or separately:

- **`note`** — global rule note. Appended to the prompt for every
  alert matching this rule_id, regardless of which host triggered it.
  Use when the rule means roughly the same thing across the host
  inventory.

- **`host_notes`** — a dict keyed by canonical hostname. When the
  rule fires on a matching host, that host's text is appended *in
  addition to* the global note. Use when a single rule means
  meaningfully different things on different hosts.

The combination is the operator's main lever for getting rule-shaped
context into prompts:

- Rule means the same thing everywhere → use `note` only
- Rule means different things on different hosts → use `host_notes`
- Rule has a global truth plus host-specific additions → use both
  (they compose; they don't override each other)

Compared to host notes (Part 1), the scope difference:

- **Host note** = "things to know about THIS HOST, regardless of which
  rule fired"
- **Rule note (`note`)** = "things to know about THIS RULE, regardless
  of which host triggered it"
- **Per-host rule note (`host_notes`)** = "things to know about THIS
  RULE on THIS HOST specifically"

You'll often want a combination. A host note tells the LLM about
dmz-web-01's nginx logs; a rule note tells the LLM about how Suricata
HTTP-anomaly rules fire on SPAN; a per-host rule note tells the LLM
that rule 504 on the MediaPC1 means "powered off." All three compose into
a single prompt where the LLM has multiple angles of context.

---

## Concrete example: MediaPC1 + Wazuh rule 504 (per-host rule note)

Wazuh rule 504 is "Wazuh agent disconnected." It fires whenever an
agent stops checking in with the manager. Across the host inventory,
this rule means very different things:

- On a domain controller: alarming, possible compromise or crash
- On a production hypervisor: alarming, immediate investigation
- On a travel laptop: usually expected when off-VPN or asleep
- On a home theater PC: routine, fires every time the TV turns off

This is the textbook case for per-host rule notes. A single `note`
field can't capture all four interpretations; it'd have to either
over-suppress (treat all 504s as routine and miss real incidents on
servers) or over-escalate (treat all 504s as critical and wake the
operator every time the MediaPC1 powers down).

### The per-host rule note

In `rules.json`, the rule entry for 504 has a `host_notes` dict.
The MediaPC1's entry inside that dict:

```
"MediaPC1": "Home theater PC that is frequently powered off when not in
use. Wazuh agent disconnection may occur when the system is shut
down. However, other systems in the environment do not consistently
generate this alert when powered off. Treat this as expected only
when correlated with known shutdown activity. If the system is
powered on or the behavior becomes more frequent or inconsistent,
investigate for agent instability, shutdown behavior differences,
or network issues."
```

This text is appended to the prompt only when:
- rule_id == 504 (the rule fires)
- canonical_hostname == "MediaPC1" (the alert is on this specific host)

The global `note` for rule 504, if one exists, also appears in the
prompt — both fields compose, they don't fall back. For a MediaPC1 504,
the prompt's RULE CONTEXT section contains the global note (if any)
followed by MediaPC1's per-host text. For a Domain_Controller 504, the same global
note appears, followed by Domain_Controller's per-host text (if any). Per-host
text doesn't replace the global note; it adds host-specific
commentary on top.

What this note does that a generic suppression wouldn't:

1. **It documents the cause** ("MediaPC1 frequently powered off"), so the
   LLM understands WHY this rule fires expectedly here.

2. **It anchors the suppression to evidence** ("expected only when
   correlated with known shutdown activity"). The LLM doesn't blanket-
   suppress; it looks for shutdown-related signal before deciding.

3. **It defines the escalation conditions explicitly**:
   - System reportedly powered on while disconnected → investigate
   - More frequent than usual → investigate
   - Inconsistent pattern → investigate

   This is a decision procedure, not a label. The LLM applies it.

4. **It acknowledges the asymmetry** ("other systems in the
   environment do not consistently generate this alert when powered
   off"). This prevents a future LLM from over-generalizing "agent
   disconnection is normal at shutdown" to other hosts where it
   wouldn't be normal.

### The result

Before this per-host rule note: 2-3 NOTIFY-level alerts per day from
rule 504 on the MediaPC1, every one corresponding to "the operator turned
off the TV." Phone buzzed two or three times daily for a non-event.

After: the LLM correctly resolves these to NOTE or SUPPRESS based on
correlation with shutdown signals. No phone buzzes for routine MediaPC1
shutdowns. Genuine anomalies (MediaPC1 reportedly powered on but agent
disconnected) still escalate because the conditional decision
procedure is intact.

Roughly 14-21 phone-buzzes per week eliminated from one rule on one
host.

### Why this is per-host rule, not host-only

A host note on MediaPC1 saying "this host is frequently powered off"
would help the LLM understand the host *generally*, but it'd be in
the HOST INVENTORY section of the prompt — far from the RULE CONTEXT
where the LLM is reasoning about "what does rule 504 mean here."

The per-host rule note is co-located with the rule. When the LLM is
reading "Rule 504 - Wazuh agent disconnected," the next thing it
reads is "on this specific host, here's what that means." That
proximity matters for the model's reasoning. The mechanism puts the
right context next to the right question.

**The token-cost argument:** there is less friction in writing a
hosts.json note (one place, one host, done) than in writing a
per-host rule note inside rules.json (find the rule entry, add the
host key, write the note). Operators naturally reach for the easier
tool — but the per-host rule note is frequently the right tool
because it's surgical in token use as well as scope. A hosts.json
note expands the prompt for **every alert on that host**, regardless
of rule. A per-host rule note inside rules.json only expands the
prompt when **that specific rule fires on that specific host**. For
a busy host that generates many different alerts daily, this is the
difference between paying the note's token cost on every alert
versus paying it only on the alerts where it actually matters.
Reserve hosts.json for context that genuinely applies to most or
all alerts on the host. Put rule-specific explanations in the
rule's host_notes.

### Why this is per-host rule, not global rule

Putting "expected at shutdown" in the global `note` field for rule
504 would be wrong — most hosts in the inventory should NOT silently
disconnect. Domain controllers, servers, the pipeline host itself —
disconnect on those is a real signal. Per-host scoping preserves that
escalation capability for the hosts where it matters.

The general principle: **scope the suppression to where it's
correct.** Per-host rule notes make this exact.

---

## When to use a global rule note instead

Some Wazuh rules have meanings that ARE consistent across hosts.
Those go in the global `note` field of the rule.

Example:

```
"rule_id": "60608",
"note": "Rule 60608 is Windows Error Reporting (WER). Common benign
sources: Dell management agents, Edge updater, .NET runtime failures.
Recurring crashes on the same process are worth tracking as NOTEs.
Flag unfamiliar processes or ones related to security tooling."
```

WER firing means the same thing on Workstation1, Domain_Controller, or any other Windows
host: a process crashed and Windows reported it. The note captures
the universal context (typical benign sources, what to watch for)
without needing per-host overrides. If WER fires on a host with no
documented benign source, the LLM should still investigate — and the
note's "flag unfamiliar processes" directive supports that.

The decision rule:

- Same meaning across hosts → global `note`
- Different meaning per host → `host_notes` with per-host entries
- Both a global truth and host-specific additions → both fields. They
  compose into the prompt; the global note appears followed by any
  matching host-specific text.

---

## Patterns that work

Four categories of useful note content, with examples from above. The
patterns apply to both host notes and rule notes; the choice between
them is about scope (one host vs one rule).

### 1. Investigation directives (the dmz-web-01 pattern)

Tell the LLM where to look first and how to weight the evidence.

- "When alerts fire here, examine [specific log/data source] first."
- "Treat [field A] and [field B] as corroborating evidence rather than
  separate observations."
- "The most important signal is [specific field]; secondary signals are
  [other fields]."

Use this pattern when the host (or rule) has an authoritative log/data
source that the LLM should anchor on.

### 2. Background pattern documentation (the mgmt-host-01 pattern)

Tell the LLM what's normal so it doesn't escalate.

- "[Specific signature/event] firing at [frequency] is normal because
  [cause]."
- "[Pattern] is a known [SPAN artifact / monitoring overhead /
  scheduled task] and not anomalous."
- "This host generates [specific alert type] as a side effect of
  [legitimate activity]."

Use this pattern when there's a known source of noise that has been
previously investigated and confirmed benign. Be specific about the
cause so the LLM can corroborate when the same pattern appears.

### 3. Expected relationships (the compute-server-01 pattern)

Tell the LLM what cross-host traffic is normal.

- "High [protocol] traffic from [other host] is normal [activity
  type]."
- "[Internal IP range] frequently talks to this host because [reason]."
- "[Service] running here is consumed by [client list]; their
  connection patterns are expected."

Use this pattern when the host participates in known internal
communication flows that would look suspicious without context.

### 4. Conditional decision procedures (the workstation pattern)

Give the LLM a decision tree, not a label.

- "Treat as expected ONLY when correlated with [specific signal]."
- "Suppress if [condition]; investigate if [other condition]."
- "Normal during [time window or activity]; anomalous outside that
  window."
- "This pattern is benign at frequency X; investigate at frequency
  >Y."

Use this pattern when the alert/host has a behavior that's sometimes
expected and sometimes not, with a clear distinguishing signal. This
is the most powerful note pattern because it preserves real escalation
capability — the LLM still investigates when conditions are violated.

---

## Patterns that don't work

A few common note mistakes to avoid:

### Generic security postures

Bad: "This is a security-critical host, treat all alerts as high
priority."

Why it doesn't work: Every host is security-relevant in some sense.
This kind of note doesn't tell the LLM anything specific to this host
and tends to over-escalate. If everything is critical, nothing is.

Better: Identify the *specific* attack patterns or alert types that
matter most for this host's role, and say what evidence to look for.

### Generic technical descriptions

Bad: "Linux host running standard services."

Why it doesn't work: The role and OS fields already capture this. The
note is wasted space, and the LLM has no operational insight to apply.

Better: Document a specific operational quirk, even if small. "syslog
ships to graylog, expect outbound 514/tcp" is more useful than "Linux
server."

### Long lists of installed software

Bad: "Runs nginx, postfix, fail2ban, ufw, unattended-upgrades, Docker,
docker-compose, Wazuh agent, Zeek, Suricata..."

Why it doesn't work: An inventory doesn't help triage. The LLM doesn't
care that nginx is installed; it cares whether nginx logs are
authoritative for HTTP alerts on this host.

Better: For each piece of software that the LLM should pay attention
to, say *why* and *how*. "nginx access.log is the authoritative source
for HTTP request triage on this host" is more useful than "runs nginx."

### Promising things the prompt doesn't deliver

Bad: "Check the systemd journal for context."

Why it doesn't work: The LLM doesn't have access to the systemd journal
unless something explicitly ships it into the HOST LOGS section. Telling
it to "check" something it can't see produces verdicts that say "I'd
need to check X" rather than completing.

Better: Match notes to evidence the prompt actually contains. "When the
HOST LOGS section includes nginx access.log entries, those are the
primary signal" anchors the LLM to data that's actually present.

---

## How to evolve a note

Notes are not write-once. The dmz-web-01 example above is exactly one cycle
of evolution: the v1 note was reasonable, the v2 note is better, the
v3 note (when there's something to add) will be better still.

The feedback loop runs on operator attention. When a NOTIFY or NOTE
lands in your inbox that you can immediately explain in your environment
("oh, that's just X" — backup window, expected reboot, scheduled scan,
WSUS check-in, kid powering off the workstation), the explanation you
would have given to a human analyst is exactly what the LLM needed to
produce a better verdict. Capture that explanation as a note, and the
next time the pattern fires the LLM has the context to downgrade
NOTIFY → NOTE or NOTE → SUPPRESS without your involvement. Each
NOTIFY-or-NOTE you successfully explain converts into reduced future
workload.

The cycle:

1. Write an initial note with the best information you have at install
   time.
2. Watch the alerts that reach you for a week or two — specifically
   the NOTIFY-and-NOTE alerts that cost you attention.
3. When you can immediately explain an alert in environmental terms
   ("this is normal because X"), that's a signal the note has a gap.
   The LLM didn't have access to your environmental knowledge; you
   just demonstrated what it needed.
4. Update the note to give the LLM the explanation you would have
   given a human analyst. Save through the GUI (no service restart
   needed for hosts.json — it reloads dynamically).
5. The next alert that matches that pattern will land differently —
   ideally downgraded to NOTE or SUPPRESS, no longer interrupting you.

This evolution is the operator's primary lever. The pipeline doesn't
get smarter; the pipeline + the notes you write get smarter together.

Note: alerts that fire repeatedly with the same SUPPRESS verdict are
already silent — they're not costing you attention. Wrongly-suppressed
alerts are real in principle (a SUPPRESS that should have been NOTIFY
or NOTE is a missed signal), but detecting them is hard: by definition
they're not in front of you. In this lab's approximately one month of
continuous gemma4:26b production operation, no observable wrong-
SUPPRESS has been identified — absence of evidence, not evidence of
absence, but enough reason not to prioritize SUPPRESS-sampling as
routine work. Tune what reaches you, not what doesn't.

---

## A note on note length

Longer is not better. The notes above range from 2 lines (mgmt-host-01) to 6
lines (dmz-web-01 v2). The directive content has to be specific enough to
act on, but every word in a note is a word in every prompt for that
host — token cost adds up at scale.

A useful test: read the note as if you were the LLM seeing it for the
first time. Does each sentence change how you'd evaluate an alert? If
yes, keep it. If no, cut it.

---

## Where notes live operationally

**Host notes:**
- File: `hosts.json` — the `notes` field on each host entry
- Edit through: the Hosts tab in the jrSOCtriage web interface
  (recommended) or by hand
- Reload: dynamic. hosts.json is reloaded on each pipeline cycle; no
  service restart needed.
- Visible in prompts: the HOST INVENTORY section of every alert prompt,
  restricted to alert-relevant hosts only (the pipeline filters to
  hosts mentioned in the alert to keep prompt size reasonable).

**Rule notes:**
- File: `rules.json` — the `note` field on each rule entry, plus the
  optional `host_notes` field for per-host overrides
- Edit through: the Rules tab in the jrSOCtriage web interface
  (recommended) or by hand
- Reload: requires pipeline restart (rules.json is loaded once at
  startup). Use the Restart button in the Restart tab; expect 1-3
  minutes for graceful drain.
- Visible in prompts: the RULE CONTEXT section at the top of every
  alert prompt where the rule_id matches.

The reload difference is the main operational gotcha. Host note edits
take effect on the next alert; rule note edits take effect after a
pipeline restart. If you're iterating quickly on rule notes, batch the
changes and restart once at the end.

---

## Closing

The host inventory and rules engine in jrSOCtriage are not passive
datasets. They're an active conversation between operator and LLM
that happens silently in the background of every alert. A blank note
is silence; a thoughtful note is institutional knowledge made
portable.

Time spent writing good notes is time the operator never spends again
investigating the same false positive. The four examples above produce
roughly:

- dmz-web-01 (host note v2): NOTIFY → NOTE shift on most scanner traffic,
  no more 4am wake-ups for routine probing
- mgmt-host-01 (host note): 4-5 NOTIFY/day eliminated from AppArmor + SMTP-TLS
  patterns
- compute-server-01 (host note): SMB-from-Workstation1 traffic correctly recognized as
  mapped drive activity
- MediaPC1 (per-host rule note on rule 504): 2-3 NOTIFY/day eliminated
  from routine shutdowns

That's on the order of 60-80 phone-buzzes per week eliminated through
four well-written notes. The compounding return is what makes this
kind of triage system actually viable for a solo operator.

If you've just installed jrSOCtriage and you're looking at the Hosts
tab or Rules tab wondering whether to fill out notes: yes. Start with
the hosts and rules that produce the most alert volume. Watch verdicts
for a week. Iterate. The phone-buzz reduction is real.
