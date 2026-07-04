#!/usr/bin/env python3
"""
jrSOCtriage - Email Sender Module
Sends alert notification emails via SMTP.
Only called when VERDICT == NOTIFY and CONFIDENCE >= min_confidence_to_email.
"""

import html
import logging
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Email decision
# ---------------------------------------------------------------------------
# should_email() lives in llm_caller.py — see that module for the production
# implementation. It was previously also defined here, but the two versions
# drifted (this module's version returned "note" even when note_address was
# not configured, which would cause send_email to fail later). The duplicate
# was removed to eliminate that bug class. Smoke test below imports the
# canonical version.


# ---------------------------------------------------------------------------
# Email builder
# ---------------------------------------------------------------------------

def build_email(alert, enrichment, baseline, llm_result, config, prompt=None):
    """
    Build a plain text + HTML email for a NOTIFY alert.
    Returns (subject, plain_text, html_text).
    """
    from ingest import safe_get

    email_cfg  = config.get("email", {})
    verdict    = (llm_result.get("verdict", "NOTIFY") or "NOTIFY").upper()
    if verdict == "NOTE":
        prefix = email_cfg.get("subject_prefix_note", "[jrSOC NOTE]")
        verdict_label = "NOTE"
    else:
        prefix = email_cfg.get("subject_prefix_notify", 
                 email_cfg.get("subject_prefix", "[jrSOC ALERT]"))
        # Use the label from the prefix (e.g. [jrSOC ALERT] → ALERT)
        verdict_label = prefix.strip("[]").replace("jrSOC ", "").strip()
    confidence = llm_result.get("confidence", "?")
    summary    = llm_result.get("summary",    "No summary provided")
    reasoning  = llm_result.get("reasoning",  "No reasoning provided")
    missing    = llm_result.get("missing_info", "None")

    rule_level  = safe_get(alert, "rule", "level", default="?")
    rule_desc   = safe_get(alert, "rule", "description", default="Unknown")
    agent_name  = safe_get(alert, "agent", "name", default="unknown")
    timestamp   = safe_get(alert, "timestamp", default="?")
    canonical   = enrichment.get("canonical_hostname", agent_name)
    mitre       = enrichment.get("mitre", {})
    tactics     = mitre.get("tactics", "N/A")
    dedup_key   = enrichment.get("dedup_key", "?")
    baseline_note = baseline.get("baseline_note", "N/A") if baseline else "N/A"

    endpoint = llm_result.get("endpoint", "")
    model    = llm_result.get("model", "")
    triage_by = f" — {model} ({endpoint})" if endpoint else ""
    subject = f"{prefix} [{confidence}] {rule_desc} on {canonical}{triage_by}"

    # --- Plain text ---
    prompt_section = f"""

FULL PROMPT
-----------
{prompt}
""" if prompt else ""

    plain = f"""
jrSOC TRIAGE {verdict_label}
==================

VERDICT    : {verdict}
CONFIDENCE : {confidence}
TIMESTAMP  : {timestamp}
HOST       : {canonical} ({agent_name})
RULE       : [{rule_level}] {rule_desc}
MITRE      : {tactics}

SUMMARY
-------
{summary}

REASONING
---------
{reasoning}

MISSING INFO
------------
{missing}

BASELINE
--------
{baseline_note}

DEDUP KEY : {dedup_key}{prompt_section}
""".strip()

    # --- HTML ---
    # SECURITY: HTML-escape every field that may contain LLM output or
    # alert content before interpolating into HTML. LLM-controlled fields
    # (summary, reasoning, missing_info) and alert-controlled fields
    # (rule_desc, prompt) are the obvious attack surface — if an attacker
    # gets content into a Wazuh alert that the LLM paraphrases, unescaped
    # HTML reaches the operator's inbox. Modern clients strip <script>
    # but allow <a href="malicious">benign-text</a>, which is the realistic
    # link-injection risk against a security operator. Programmatic fields
    # (timestamp, baseline_note, etc.) are escaped too for defense-in-depth.
    e_verdict_label = html.escape(str(verdict_label))
    e_confidence    = html.escape(str(confidence))
    e_canonical     = html.escape(str(canonical))
    e_agent_name    = html.escape(str(agent_name))
    e_rule_level    = html.escape(str(rule_level))
    e_rule_desc     = html.escape(str(rule_desc))
    e_timestamp     = html.escape(str(timestamp))
    e_tactics       = html.escape(str(tactics))
    e_summary       = html.escape(str(summary))
    e_reasoning     = html.escape(str(reasoning))
    e_missing       = html.escape(str(missing))
    e_baseline_note = html.escape(str(baseline_note))
    e_dedup_key     = html.escape(str(dedup_key))
    e_prompt        = html.escape(str(prompt)) if prompt else ""

    # Color based on confidence
    confidence_color = {
        "HIGH":   "#d32f2f",
        "MEDIUM": "#f57c00",
        "LOW":    "#388e3c",
    }.get(confidence, "#555555")

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body {{ font-family: monospace; font-size: 13px; color: #222; background: #f9f9f9; padding: 20px; }}
  .header {{ background: #1a1a2e; color: #e0e0e0; padding: 16px 20px; border-radius: 6px 6px 0 0; }}
  .header h2 {{ margin: 0; font-size: 16px; letter-spacing: 1px; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px;
            background: {confidence_color}; color: white; font-weight: bold;
            font-size: 12px; margin-left: 8px; }}
  .body {{ background: white; border: 1px solid #ddd; border-top: none;
           padding: 20px; border-radius: 0 0 6px 6px; }}
  .field {{ margin-bottom: 12px; }}
  .label {{ font-weight: bold; color: #555; font-size: 11px;
            text-transform: uppercase; letter-spacing: 0.5px; }}
  .value {{ margin-top: 3px; color: #222; }}
  .section {{ margin: 16px 0; padding: 12px; background: #f5f5f5;
              border-left: 3px solid {confidence_color}; border-radius: 0 4px 4px 0; }}
  .meta {{ margin-top: 16px; font-size: 11px; color: #888; border-top: 1px solid #eee; padding-top: 10px; }}
</style>
</head>
<body>
<div class="header">
  <h2>⚠ jrSOC TRIAGE {e_verdict_label} <span class="badge">{e_confidence}</span></h2>
</div>
<div class="body">
  <div class="field">
    <div class="label">Host</div>
    <div class="value">{e_canonical} ({e_agent_name})</div>
  </div>
  <div class="field">
    <div class="label">Rule</div>
    <div class="value">[{e_rule_level}] {e_rule_desc}</div>
  </div>
  <div class="field">
    <div class="label">Timestamp</div>
    <div class="value">{e_timestamp}</div>
  </div>
  <div class="field">
    <div class="label">MITRE Tactics</div>
    <div class="value">{e_tactics}</div>
  </div>

  <div class="section">
    <div class="label">Summary</div>
    <div class="value">{e_summary}</div>
  </div>

  <div class="section">
    <div class="label">Reasoning</div>
    <div class="value">{e_reasoning}</div>
  </div>

  <div class="section">
    <div class="label">Missing Info</div>
    <div class="value">{e_missing}</div>
  </div>

  <div class="field">
    <div class="label">Baseline</div>
    <div class="value">{e_baseline_note}</div>
  </div>

  <div class="meta">
    Dedup key: {e_dedup_key} &nbsp;|&nbsp; Generated by jrSOCtriage
  </div>
  {"" if not prompt else f'''
  <div style="margin-top:20px;">
    <div class="label">Full Prompt</div>
    <pre style="font-size:11px;background:#f5f5f5;padding:12px;border-radius:4px;
                overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;
                border:1px solid #ddd;color:#333;">{e_prompt}</pre>
  </div>'''}
</div>
</body>
</html>
""".strip()

    return subject, plain, html_body


# ---------------------------------------------------------------------------
# SMTP sender
# ---------------------------------------------------------------------------

def send_email(alert, enrichment, baseline, llm_result, config, prompt=None):
    """
    Send a triage notification email.
    Only call this after should_email() returns True.
    Returns True on success, False on failure.
    """
    email_cfg = config.get("email", {})

    if not email_cfg.get("enabled", False):
        logger.info("Email disabled in config")
        return False

    smtp_host    = email_cfg.get("smtp_host", "")
    smtp_port    = email_cfg.get("smtp_port", 587)
    use_tls      = email_cfg.get("use_tls", True)
    username     = email_cfg.get("username", "")
    password     = email_cfg.get("password", "")
    from_address = email_cfg.get("from_address", username)
    # Route NOTE verdicts to note_address, NOTIFY to to_address
    verdict = (llm_result.get("verdict", "NOTIFY") or "NOTIFY").upper()
    if verdict == "NOTE":
        to_address = email_cfg.get("note_address",
                     email_cfg.get("to_address", username))
    else:
        to_address = email_cfg.get("to_address", username)

    if not smtp_host or not username or not password:
        logger.error("Email config incomplete - check smtp_host, username, password")
        return False

    # Connection security mode. Explicit `smtp_security` wins; absent it,
    # fall back to the legacy `use_tls` boolean so existing configs are
    # unchanged (use_tls True -> starttls, the prior default; False -> none).
    #   starttls : plaintext connect, then STARTTLS upgrade (port 587). Default.
    #   ssl      : implicit TLS from the first byte via SMTP_SSL (port 465).
    #   none     : no transport encryption.
    smtp_security = email_cfg.get("smtp_security")
    if smtp_security:
        smtp_security = str(smtp_security).strip().lower()
    else:
        smtp_security = "starttls" if use_tls else "none"
    if smtp_security not in ("starttls", "ssl", "none"):
        logger.error(
            f"Unknown smtp_security '{smtp_security}' - expected starttls, ssl, or none"
        )
        return False

    subject, plain, html_body = build_email(
        alert, enrichment, baseline, llm_result, config, prompt=prompt
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_address
    msg["To"]      = to_address

    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html_body,  "html"))

    try:
        logger.info(f"Sending email: {subject}")
        if smtp_security == "ssl":
            # Implicit TLS (SMTPS): the socket is encrypted from the first
            # byte, so there is no STARTTLS upgrade. SMTP_SSL verifies the
            # server certificate via ssl.create_default_context() by default.
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
                server.login(username, password)
                server.sendmail(from_address, to_address, msg.as_string())
        else:
            # starttls or none. This branch issues the same calls as the
            # original 587 path: `if smtp_security == "starttls"` is exactly
            # equivalent to the prior `if use_tls` for any legacy config
            # (use_tls True -> starttls here; False -> none, no upgrade).
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                if smtp_security == "starttls":
                    server.starttls()
                server.login(username, password)
                server.sendmail(from_address, to_address, msg.as_string())
        logger.info("Email sent successfully")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("Email auth failed - check username and app password")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
        return False
    except (OSError, TimeoutError) as e:
        logger.error(f"Email connection error: {e}")
        return False


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    # Self-contained: this smoke test builds a fully synthetic alert and
    # sends it through the real build_email/send_email path. It does NOT
    # read the live alert stream or touch the database, so it is safe to
    # run against a running pipeline and works regardless of whether any
    # alerts are currently pending. It tests email formatting + the SMTP
    # send path (whatever smtp_security mode config.json selects), nothing
    # upstream of that. It deliberately imports ONLY load_config — not
    # llm_caller/should_email — so it carries no LLM/requests dependency
    # and runs under any interpreter (including the web interface's, which
    # has no `requests`). send_email() still honors email.enabled.
    from ingest import load_config

    print("=== jrSOCtriage Email Sender Smoke Test ===\n")

    config    = load_config("config.json")
    email_cfg = config.get("email", {})
    print(f"SMTP host     : {email_cfg.get('smtp_host')}")
    print(f"SMTP port     : {email_cfg.get('smtp_port')}")
    print(f"SMTP security : {email_cfg.get('smtp_security') or ('starttls' if email_cfg.get('use_tls', True) else 'none')}")
    print(f"From          : {email_cfg.get('from_address')}")
    print(f"To            : {email_cfg.get('to_address')}")
    print(f"Enabled       : {email_cfg.get('enabled', False)}\n")

    # Synthetic NOTIFY/HIGH result, alert, enrichment, and baseline. These
    # exercise every field build_email reads without depending on live data.
    fake_llm_result = {
        "verdict":      "NOTIFY",
        "confidence":   "HIGH",
        "summary":      "Test alert - verifying jrSOCtriage email pipeline is working correctly.",
        "reasoning":    "This is a smoke test of the email sender module. "
                        "No actual threat was detected. "
                        "If you received this email the pipeline is configured correctly.",
        "missing_info": "None - this is a test.",
        "endpoint":     "smoke-test",
        "model":        "n/a",
    }
    fake_alert = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule":  {"level": 10, "description": "jrSOCtriage email smoke test"},
        "agent": {"name": "smoke-test-host"},
    }
    fake_enrichment = {
        "canonical_hostname": "smoke-test-host",
        "mitre":      {"tactics": "N/A"},
        "dedup_key":  "0|smoke-test-host",
    }
    fake_baseline = {"baseline_note": "Smoke test - no baseline."}

    # Forced send-path test: deliberately not gated on should_email() (the
    # verdict/confidence threshold). You clicked "send a test", so send.
    # send_email() still refuses if email.enabled is false.
    print("[..] Sending test email...")
    success = send_email(
        fake_alert, fake_enrichment, fake_baseline,
        fake_llm_result, config
    )
    if success:
        print(f"[OK] Email sent to {email_cfg.get('to_address')}")
        print("     Check your inbox!")
    else:
        print("[FAIL] Email send failed - check logs above (is email.enabled true?)")

    print("\n=== Done ===")
