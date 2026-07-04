# jrSOCtriage — Frequently Asked Questions

Seeing something in the logs that looks wrong? Most "weird" behaviors are
expected. This page explains the common ones, scannable by symptom — search
the page for the term you saw in the logs.

---

### How do I stop jrSOCtriage from starting where I left off after extended downtime?

Delete the `.ingest_position` file. On the next start the pipeline begins at
end-of-file — new alerts only — and the downtime is intentionally skipped
rather than replayed. The position file defaults to `.ingest_position` and is
configurable via `paths.position_file` in your config.

---

### I just started it — how do I know it's working?

Watch the live log first:

```
sudo journalctl -u jrsoctriage -f
```

That shows you what the pipeline is actually doing in real time. From there:

1. **Look for errors** in the live output — anything failing to connect or
   parse will show up here.
2. **Confirm you have a live `alerts.json`** — that Wazuh is actively writing
   new alerts to the file the pipeline is reading. The pipeline starts at
   end-of-file and triages *new* alerts as they arrive, so if Wazuh isn't
   currently writing anything, there is nothing to triage yet and the pipeline
   will simply wait. A quiet pipeline with a live `alerts.json` and no errors is
   healthy — it is caught up and waiting for new alerts.

---

### How much does it cost to run?

It depends on your alert volume and escalation mode, and the dominant cost is
cloud LLM API calls (a local model is free per call — you only pay for the
hardware you already own). For a realistic level-6-plus-filters deployment on
the low-cost cloud model, costs run roughly a few hundred to a couple thousand
US dollars per year at typical SMB volumes, scaling with how many alerts survive
filtering to reach the LLM. Running a local model instead makes per-call cost
zero. See the cost section in the running instructions for the full breakdown,
the per-volume table, and the local-vs-cloud tradeoff.

---

### During 100% dedup, it looks like alerts aren't being processed. What's happening?

They have already been processed. The `[DEDUP]` line is retrospective: it
reports the ingest cycle that just *closed*, not one that is starting now. The
`[DEDUP_NOTE]` line states this inline. Nothing is being held or skipped — you
are reading a summary of work that is already done.

---

### Why does `[DEDUP]` show `rate_pct=100` for several cycles?

Because the incoming traffic for that period is highly correlated or repeating.
Common causes: a SPAN reconfiguration that reduced uncorrelated noise, proxy
blocks cutting scan noise, scheduled bursts, or normal business-hour patterns.
A high dedup rate is the pipeline working as designed — it is collapsing
repetitive alerts so the LLM only judges novel ones. Not a problem.

---

### Does a 4-minute dedup window mean the pipeline is 4 minutes behind real time?

No. The first alert in a dedup window is processed and shipped immediately. The
window governs how long repeats are collapsed together, not how long an alert
waits — the pipeline is never "a window" behind real time.

---

### Why am I seeing ntopng errors — sometimes a red error saying ntopng didn't respond?

Because ntopng has no data for that host, so the alert completes without ntopng
context — typically an external IP that ntopng never saw a local flow for.
Newer versions of ntopng changed this behavior: instead of returning an empty
HTTP 200, ntopng now closes the connection, which the pipeline surfaces as a red
"did not respond" error. It is isolated to ntopng — Graylog and Zeek for the
same host in the same cycle complete fine, which is how you can tell it is not a
network problem. The alert is still fully triaged; it just proceeds without the
ntopng enrichment for that host. Not a problem.

---

### What is `[LAG]` and why don't I see it in my logs?

`[LAG]` is diagnostic-only output logged at DEBUG level, hidden by default.
Enable the Debug toggle to see it while troubleshooting. It is suggestive, not
authoritative: for example, `stall_state=suspect` in a `[LAG]` line is the
passive lag logger labeling a queue that has aged past a threshold — usually a
normal burst draining. It is not a stall and it is not an active intervention.

---

### The pipeline says `abandoned=N` at shutdown — did I lose alerts?

No. `abandoned=0` is normal at a clean shutdown. `abandoned>0` only means the
graceful-drain budget elapsed while some workers were still mid-LLM-call
(shutdown during a heavy batch); those workers finish their HTTP calls during
teardown and still ship their results to Graylog, and the Final stats line
reflects those late completions.

If you *regularly* see `abandoned>0` at shutdown, it usually means the pipeline
is running further behind than the drain budget can clear in time — a sign the
LLM stage is the bottleneck. Consider adding more LLM endpoints so the queue
drains faster (see the endpoint and provisioning guidance in the running
instructions).

---

### Why is `process_time_s` sometimes very high?

It is end-to-end pipeline latency for that alert, and it is usually one of two
things: backpressure (the worker pool is full) or LLM slowness. Check `[BATCH]`
`backpressure_waits` and your LLM response times to see which. It is a latency
figure, not an error.

---

### Why does the pipeline keep running for minutes after I asked systemd to stop it?

Worker threads finish their in-flight HTTP calls until those calls return,
rather than being killed mid-request. This is bounded by systemd's
`TimeoutStopSec=300` and a graceful drain budget of 60 seconds. Any completions
during that drain still ship to Graylog, so nothing in flight is lost.
