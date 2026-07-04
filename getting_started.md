# Getting Started with jrSOCtriage

This guide walks through a fresh installation of jrSOCtriage from "I just downloaded the code" to "alerts are being triaged and shipped to Graylog." Each section explains what is being set up and why, then gives the concrete steps.

The guide assumes a moderate level of technical comfort: you know your way around a Linux shell, you can run `sudo` commands, and you have administrative access to the systems jrSOCtriage will integrate with. Detailed explanations are included where they help — experienced operators may skip ahead.

If you want the full reference for any setting touched on here, see `running_instructions.txt` for the config schema and `interface_guide.txt` for the web interface.

---

## Section 1: Prerequisites

### What we are checking, and why

jrSOCtriage sits on top of your existing security stack. It does not replace your SIEM, IDS, or log collector; it reads alerts from them and decides which ones deserve attention. It uses an LLM to decide. Before you start, the upstream pieces need to exist and produce alerts.

Confirm the following are running and reachable from the host where jrSOCtriage will live:

- **Wazuh manager** — required. jrSOCtriage reads `alerts.json` from the Wazuh manager. jrSOCtriage reads only alerts written to alerts.json. Logs that do not trigger Wazuh rules will not enter the pipeline. For system logs jrSOCtriage uses graylog.  At a high level, the pipeline is: Wazuh → jrSOCtriage → Graylog, with optional context from Graylog, Zeek, and ntopng. If your Wazuh runs on a different host, you will need shared storage or a sync mechanism to make that file readable from the jrSOCtriage host.
- **Graylog server** — required. Used for both context logs (input) and verdict logging (output). JrSOCtriage without Graylog works, but jrSOCtriage without Graylog produces no audit trail for SUPPRESS verdicts and very limited operational visibility.
- **Linux host with Python 3.13 or 3.14** — required. The jrSOCtriage host. Tested on Ubuntu 25.10 and 26.04 LTS. The `whois` command-line tool must be installed (`sudo apt install whois` or `sudo dnf install whois`) — jrSOCtriage shells out to it for external IP enrichment. If `whois` is not available, those enrichments are silently skipped and the operator may not realize why org/netname fields are blank.
- **An LLM endpoint** — required. Either a local Ollama instance with a capable model (gemma4:26b on a 24GB GPU is the reference configuration) OR a paid API key for one of the supported cloud LLMs (Anthropic Claude, OpenAI GPT, Google Gemini).
- **Outbound network access** if using cloud LLMs and AbuseIPDB enrichment.

Optional but recommended infrastructure:

- **Zeek** — running on a SPAN/mirror port. Provides network flow context (DNS queries, connection records) that significantly improves LLM verdict quality.
- **ntopng** — running on the same SPAN port as Zeek. Provides L7 protocol context (TLS.Azure, HTTP.Google, etc.) for active flows.
- **SMTP server or relay** — if you want email notifications for NOTIFY-grade alerts.

If any of the required pieces above are not yet running, install them first using their vendor documentation. jrSOCtriage cannot configure them.

---

## Section 2: Getting the Code

### What we are doing, and why

jrSOCtriage ships as a directory of Python files plus configuration schemas and helper scripts. There is no compiled binary and no package manager entry. You drop the directory onto your host, run a setup script, and you are ready to configure.

### Steps

1. Choose an install location on the jrSOCtriage host. The recommended location is `/mnt/appdata/jrsoctriage`, but any path works. The provided systemd unit files default to `/mnt/appdata/jrsoctriage`; if you choose a different path, `setup.sh` will update them automatically.

2. Clone or download the jrSOCtriage source into that directory:

   ```bash
   sudo mkdir -p /mnt/appdata/jrsoctriage
   sudo chown $USER:$USER /mnt/appdata/jrsoctriage
   cd /mnt/appdata/jrsoctriage
   git clone <repository-url> .
   ```

   If you received the source as a tarball, extract it instead:

   ```bash
   tar -xzf jrsoctriage-1.0.tar.gz -C /mnt/appdata/jrsoctriage --strip-components=1
   cd /mnt/appdata/jrsoctriage
   ```

3. Verify the directory contains `setup.sh`, `interface.py`, `main.py`, `requirements.txt`, `interface_requirements.txt`, and the two `.service` files:

   ```bash
   ls
   ```

   You should see those files plus the various Python modules. If anything is missing, the next steps will fail.

---

## Section 3: First-Time Setup

### What we are doing, and why

The pipeline (`main.py`) needs two third-party Python packages: `requests` (HTTP client) and `dnspython` (thread-safe reverse DNS lookups). Both get installed system-wide so the systemd service can find them when running as root. The web interface (`interface.py`) needs Flask, bcrypt, pyotp, and qrcode — these get installed into a Python virtual environment so they do not pollute your system Python. `setup.sh` handles all of this in one run.

`setup.sh` also patches the systemd unit files to match your install directory and locks down permissions on any existing config files.

### Steps

1. From the install directory, make `setup.sh` executable:

   ```bash
   sudo chmod +x setup.sh
   ```

2. Run setup:

   ```bash
   sudo ./setup.sh
   ```

   The script will print progress as it works. If anything fails, the error message tells you what is wrong. Re-running `setup.sh` is safe — it skips work that is already done.

3. When `setup.sh` finishes, run the interface manually for first-run user creation. **This step is required because the first admin user is created interactively. The systemd service cannot perform this step.** The interface uses a terminal-based flow to create the first admin user (username, password, TOTP authenticator pairing). Systemd has no terminal, so you cannot do this through the systemd service. Run it directly first:

   ```bash
   sudo ./venv/bin/python3 interface.py
   ```

4. The interface will prompt you in the terminal:
   - For a username (case-sensitive — pick one and remember its capitalization)
   - For a password (minimum 8 characters, must include both uppercase and lowercase letters)
   - To scan a TOTP QR code printed in the terminal with an authenticator app (Google Authenticator, Authy, 1Password, Bitwarden, etc.)
   - To verify the TOTP by entering a current code

5. Once the user is created, the interface starts serving on `127.0.0.1:9090`. **Do not stop it yet** — leave the interface running for the next sections. You will configure jrSOCtriage through the web UI.

6. From a workstation with browser access to the host, open an SSH tunnel:

   ```bash
   ssh -L 9090:127.0.0.1:9090 youruser@your-jrsoctriage-host
   ```

   Then open `http://127.0.0.1:9090` in your browser. The interface binds to localhost only (it is not network-accessible directly), so the tunnel is required from any other machine.

7. Log in with the username, password, and TOTP code you just created.

---

## Section 4: Configure Wazuh as the Alert Source

### What we are doing, and why

jrSOCtriage's primary input is the Wazuh `alerts.json` file. Wazuh writes one JSON object per line as it generates alerts, and jrSOCtriage tails this file. Without this configured, no alerts flow into the pipeline.

### Steps

1. On the Wazuh manager, locate the `alerts.json` file. The standard location is `/var/ossec/logs/alerts/alerts.json`. Verify it exists and is being written:

   ```bash
   sudo tail -f /var/ossec/logs/alerts/alerts.json
   ```

   You should see new alerts appear as Wazuh agents report events. If nothing appears, your Wazuh deployment is not generating alerts and that needs to be addressed before continuing.

2. If the jrSOCtriage host is the same as the Wazuh manager, you can skip the next sub-step. Otherwise, make `alerts.json` readable from the jrSOCtriage host. The simplest approach is an NFS mount or rsync. The path must be readable from the jrSOCtriage host exactly as configured. If jrSOCtriage runs on a different system, ensure the file is mounted and accessible at the same path used in the configuration. The path it appears as on the jrSOCtriage host is what you will configure below.

3. In the web interface, on the **Config** tab, in the **Sources** card, in the **Wazuh** section:
   - Confirm the **Enabled** toggle is on (it should be by default).
   - In the **Alerts File** field, enter the absolute path to `alerts.json` as it appears on the jrSOCtriage host. For an on-host install: `/var/ossec/logs/alerts/alerts.json`. For a remote-mounted Wazuh: whatever path you mounted it to.

4. Scroll to the bottom of the Config tab and click **Save Config**. You should see a green confirmation. If you see an error, the path is wrong or the file is not readable by root.

5. Navigate to the **Restart** tab and restart the service. The pipeline must be restarted for new LLM endpoint settings to take effect.

---

## Section 5: Configure Host Inventory

### What we are doing, and why

Host inventory (`hosts.json`) tells the LLM what each host on your network is for: its role (DC, web server, workstation), its operating system, its VLAN, and any operator-supplied notes about expected behavior. Without this context, the LLM gets generic prompts and cannot distinguish "Windows Update on a workstation" from "unexpected outbound traffic from a print server."

The interface manages this through the Hosts tab. You can also edit `hosts.json` directly, but the GUI is faster for normal operations.

### Steps

1. In the web interface, click the **Hosts** tab.

2. For each host on your network you want jrSOCtriage to know about, click **Add Host** and fill in:
   - **Name**: a short identifier (e.g., `Domain_Controller`, `web01`, `analyst-laptop`). Used in alerts and in the LLM prompt.
   - **Role**: a short description of what the host does (`Domain Controller`, `Web Server`, `User Workstation`, `Print Server`).
   - **OS**: operating system family (`Windows Server 2022`, `Ubuntu 24.04`, `Fedora 41`).
   - **VLAN**: the VLAN ID this host lives on. Used for context in alerts.
   - **IP**: the host's primary IP address. The pipeline uses this for canonical hostname resolution when alerts come in by IP.
   - **Tags**: optional list of tags for grouping (`production`, `dev`, `dmz`). Free-form.
   - **Notes**: free-form description of expected behavior. This is the most important field for triage quality. Examples:
     - "Hosts the company website. Expected to receive HTTP traffic from anywhere on the internet."
     - "Domain controller. Should only accept connections from internal networks (10.0.0.0/8)."
     - "Backup server. Runs nightly rsync at 2am UTC. High network volume during that window is normal."

3. Also under the Hosts tab is a **Networks** section. Add network ranges you want jrSOCtriage to recognize as internal:
   - **Name**: a short identifier (e.g., `client_vlan`, `dmz`, `mgmt`).
   - **CIDR**: the network range (e.g., `192.168.10.0/24`, `10.0.0.0/8`).
   - **Notes**: optional description.

4. Click **Save Hosts** at the bottom of the tab. Changes to `hosts.json` are picked up dynamically by the running pipeline — no restart needed.

The more accurate this inventory is, the better the LLM's verdicts will be. You can come back and add or refine entries at any time.

---

## Section 6: Configure the LLM Endpoint

### What we are doing, and why

jrSOCtriage uses an LLM to decide whether each alert is NOTIFY-worthy, NOTE-worthy, or SUPPRESS-able. Without an LLM endpoint configured, the pipeline cannot triage anything — it would dedup and pass alerts through but not assign verdicts.

You can configure one or more endpoints. Multiple endpoints chain together as a failover sequence or multi-threaded round robin.  In fail-over if the first endpoint fails, the next is tried. In round robin, each endpoint multiplied by the max concurrent (within the limit for max LLM Workers)fires before moving to the next endpoint.  The recommended starting configuration is one local Ollama endpoint and one cloud endpoint as backup.

### Steps

1. In the web interface, on the **Config** tab, in the **LLM** card, click **Add Endpoint**.

2. For a local Ollama endpoint:
   - In the **Type** dropdown, select `ollama`.
   - In the **Endpoint** field, enter the URL of your Ollama server (e.g., `http://192.168.30.30:11434`).
   - In the **Model** field, enter the model name (e.g., `gemma4:26b`).
   - Leave **API Key** empty.
   - In the **Timeout** field, leave the default (typically 90 seconds, sufficient for a 27b model on a 24GB GPU).

3. To add a cloud failover endpoint, click **Add Endpoint** again:
   - For Anthropic: Type `anthropic`, Endpoint `https://api.anthropic.com/v1/messages`, Model `claude-haiku-4-5-20251001`, API Key `<your-anthropic-key>`.
   - For OpenAI: Type `openai`, Endpoint `https://api.openai.com/v1/chat/completions`, Model `gpt-4o-mini`, API Key `<your-openai-key>`.
   - For Gemini: Type `gemini`, Endpoint `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent`, API Key `<your-gemini-key>`.

4. Order matters.  Within the config tab, on the LLM endpoints card, set the priority for each endpoint to set the order for fail-over or round robin.   

5. In the **Strategy** dropdown above the endpoint list, leave the default (`round_robin` or `failover` depending on your version or preference).

6. Click **Save Config** at the bottom of the tab.

7. Navigate to the **Restart** tab and restart the service. The pipeline must be restarted for new LLM endpoint settings to take effect. 

The LLM endpoint will be exercised for real when the pipeline processes its first alert in Section 12. There is no standalone "test endpoint" feature in the current release — verification happens by watching real triage activity in the Journal tab. If you need to verify endpoint reachability separately before that, you can hit the endpoint with `curl` from the jrSOCtriage host. If no context logs appear during triage, verify Graylog connectivity and credentials.

---

## Section 7: Configure Graylog (Input — Context Logs)

### What we are doing, and why

When an alert fires, jrSOCtriage queries Graylog for log entries from the affected host within a configurable time window before and after the alert timestamp. These logs go into the LLM prompt as context. Without this, the LLM has only the Wazuh alert itself — no surrounding system events, no application logs, no correlated activity.

This is the INPUT side of Graylog. The OUTPUT side (where verdicts go) is configured in Section 8.

### Steps

1. In Graylog, create or identify an API user with read access to the streams jrSOCtriage will query. The default `admin` account works for testing; for production, create a dedicated read-only user.

2. In the web interface, on the **Config** tab, in the **Sources** card, in the **Graylog** section (the one labeled "context logs"):
   - Toggle **Enabled** on.
   - In the **Endpoint** field, type the full URL of your Graylog API (e.g., `http://graylog.lab.local:9000`).
   - In the **Verify SSL** toggle, enable if Graylog uses a valid TLS certificate; disable for self-signed or HTTP.
   - In the **Context Window (minutes)** field, leave the default (`0.5` — 30 seconds before and after the alert). Increase if your environment has slow log ingestion or the default window misses relevant context.
   - In the **Max Results** field, leave the default (`100`). This caps how many log lines per alert are pulled into context.
   - In the **Username** field, enter the API user's username.
   - In the **Password** field, enter the API user's password.

3. Click **Save Config**.

The Graylog input will be exercised when the pipeline processes its first alert with logs available in the configured time window. Verification happens in Section 12. If you need to verify Graylog API reachability before that, you can hit the API with `curl` from the jrSOCtriage host.

---

## Section 8: Configure Graylog Output (GELF Shipper)

### What we are doing, and why

After jrSOCtriage assigns a verdict to an alert, it ships the alert plus the verdict to Graylog as a GELF UDP message. This gives you a single searchable record in Graylog of every alert and what jrSOCtriage decided about it. Without this, SUPPRESS verdicts have no paper trail, and your only visibility into the pipeline is email notifications and the local log file.

This is not optional for any production deployment. You need this audit trail.

The destination is a separate Graylog input from the API endpoint configured in Section 7. The API is HTTP and is for reading. The GELF input is UDP and is for writing.

### Steps

1. In Graylog, create a GELF UDP input. Go to **System** → **Inputs** → **Launch new input** → select **GELF UDP** from the dropdown → **Launch**. Give it a title (`jrSOCtriage-input` is fine), leave the bind address as `0.0.0.0`, and set the port. The default GELF UDP port is `12201`. Click **Save**. The new input should show as "RUNNING".

2. Note the IP address and port of the Graylog server. The IP is whatever resolves to your Graylog host from the jrSOCtriage host's network. The port is `12201` unless you changed it.

3. In the web interface, on the **Config** tab, in the **Sources** card, in the **Graylog Output** section (the one labeled "ship verdicts as GELF"):
   - Toggle **Enabled** on.
   - In the **GELF Host** field, type the IP address or hostname of the Graylog server.
   - In the **GELF Port** field, type the port number (`12201` unless changed).

4. Click **Save Config**.

5. After the pipeline starts in Section 12, verify shipping by going to Graylog's **Search** view and searching for `application:jrsoctriage`. Alerts should appear there as the pipeline processes them.

---

## Section 9: Configure Email Notifications

### What we are doing, and why

For NOTIFY-grade alerts (verdicts the LLM thinks need a human's attention), jrSOCtriage can send email notifications. NOTE-grade alerts (operationally interesting but not urgent) can also email but most operators leave that off and use Graylog saved searches instead. SUPPRESS verdicts never email.

You need an SMTP server or relay reachable from the jrSOCtriage host. Common options: a self-hosted Postfix or Exim, an internal corporate SMTP relay, or a transactional email service like Mailgun, Sendgrid, or Amazon SES. 

### Steps

1. Gather your SMTP details:
   - Server hostname or IP
   - Port (typically `25`, `465`, or `587`)
   - Username and password (if your SMTP requires auth)
   - From-address (the address jrSOCtriage will send as)
   - To-addresses (where NOTIFY emails should go)

2. In the web interface, on the **Config** tab, in the **Email** card:
   - Toggle **Enabled** on.
   - In the **SMTP Host** field, type the SMTP server hostname or IP.
   - In the **SMTP Port** field, type the port.
   - In the **SMTP Username** field, type the username (leave blank if no auth).
   - In the **SMTP Password** field, type the password (leave blank if no auth).
   - In the **Use TLS** toggle, enable for ports 465/587 (most common).
   - In the **From Address** field, type the sender address.
   - In the **To Address (NOTIFY)** field, type the recipient address for NOTIFY alerts. For multiple recipients, comma-separate.
   - In the **To Address (NOTE)** field, leave blank to disable NOTE emails (recommended), or enter an address for verbose mode.
   - In the **Subject Prefix (NOTIFY)** field, leave the default `[jrSOC ALERT]` or customize.
   - In the **Subject Prefix (NOTE)** field, leave the default `[jrSOC NOTE]` or customize.

3. Click **Save Config**.

Email will be exercised for real when the first NOTIFY-grade alert is processed in Section 12. There is no standalone email test feature in the current release. If you want to verify SMTP works before relying on a real alert, use a separate tool like `swaks` from the jrSOCtriage host:

```bash
swaks --to your-notify-address@example.com --from jrsoc@yourdomain --server your-smtp-host:port
```

If `swaks` reaches the destination, jrSOCtriage with the same SMTP settings will too.

---

## Section 10: Optional — Configure Zeek and ntopng

### What we are doing, and why

Zeek and ntopng are optional but highly recommended. Zeek provides per-flow records (connection details, DNS queries, NTLM events) that the LLM can correlate with alerts. ntopng provides L7 protocol identification for active flows (TLS.Azure, HTTP.Google) which helps the LLM distinguish "destination is a known cloud service" from "destination is an unknown IP."

Both run on a SPAN/mirror port that sees your network traffic. You configure them once at the network level, then point jrSOCtriage at their outputs.

If you have not deployed Zeek or ntopng, skip this section. You can always add them later.

### Steps for Zeek

1. Verify Zeek is running and writing logs. The standard log directory is `/opt/zeek/logs/current` for current logs and `/opt/zeek/logs/<date>/` for archived logs. Adjust paths if your install differs.

2. In the web interface, on the **Config** tab, in the **Sources** card, in the **Zeek** section:
   - Toggle **Enabled** on.
   - In the **Current Log Directory** field, type the path to the directory containing live Zeek logs (e.g., `/opt/zeek/logs/current`).
   - In the **Archive Log Directory** field, type the parent directory containing dated subdirectories (e.g., `/opt/zeek/logs`). Leave blank to default to the parent of the current directory.

3. Click **Save Config**.

### Steps for ntopng

1. Verify ntopng is running. Identify the interface ID (`ifid`) for the SPAN interface. In ntopng's web UI, this is shown next to each interface name. Common values are 1 or 2.

2. Create an ntopng API user (or use an existing one). The default `admin` user works for testing.

3. In the web interface, on the **Config** tab, in the **Sources** card, in the **ntopng** section:
   - Toggle **Enabled** on.
   - In the **Endpoint** field, type the ntopng web URL (e.g., `http://ntopng.lab.local:3000`).
   - In the **Interface ID** field, type the SPAN interface ID number.
   - In the **Username** field, type the ntopng username.
   - In the **Password** field, type the ntopng password.
   - In the **Verify SSL** toggle, enable for valid TLS certs; disable otherwise.

4. Click **Save Config**.

---

## Section 11: Optional — Configure Anonymization

### What we are doing, and why

If you use cloud LLMs (Anthropic, OpenAI, Gemini) and your alerts contain identifying information (real usernames, internal hostnames, internal IPs), anonymization replaces those identifiers with aliases before the prompt is sent. After the LLM responds, the aliases are mapped back to real values for your records.

This is recommended for any deployment using cloud LLMs in environments with privacy or compliance concerns. For pure-local Ollama deployments, it is unnecessary overhead.

### Steps

1. In the web interface, click the **Anonymization** tab.

2. Toggle **Enabled** on at the top.

3. Choose anonymization granularity:
   - **Anonymize Usernames**: replaces real usernames with `user-1`, `user-2`, etc.
   - **Anonymize Internal IPs**: replaces real internal IPs with `10.6.0.x` aliases.
   - **Anonymize Hostnames**: replaces real hostnames with `host-1`, `host-2`, etc.

4. The mappings are persisted in `users.json`, `domain.json`, and `ip_aliases.json` so aliases are stable across pipeline runs. View and edit them on the **Users**, **Networks**, and other sub-tabs of the Anonymization tab.

5. Click **Save Anonymization**.

6. The pipeline will pick up changes on the next alert. You can verify alias substitution worked by examining the prompt log if `logging.prompt_log_mode` is set to `anonymized`.

---

## Section 12: Verify the Pipeline Works

### What we are doing, and why

Before promoting to systemd, you should verify the pipeline runs correctly with your configuration. Run it manually first, watch the logs, and confirm alerts are being processed end-to-end.

### Steps

1. Open a second SSH session to the jrSOCtriage host (keep the interface running in the first one).

2. In the second session, change to the install directory and start the pipeline:

   ```bash
   cd /mnt/appdata/jrsoctriage
   sudo python3 main.py
   ```

3. Watch the output. Within a few seconds you should see log lines like:

   ```
   [INFO] ingest: Read N alerts at or above level 0
   [INFO] enrich: Enriching alert ...
   [INFO] llm_caller: Sending prompt to ...
   [INFO] llm_caller: Verdict: SUPPRESS / NOTE / NOTIFY
   [INFO] gelf_shipper: Shipped to Graylog: RULE|HOST
   ```

4. In another session, watch live triage activity through the interface. In the web interface, click the **Journal** tab and click **Start**. Live log lines stream into the panel as the pipeline processes alerts.

5. Trigger a test alert to verify NOTIFY → email path. The simplest test: SSH into a host with a Wazuh agent and run a deliberately-failing login or another action that triggers a known rule. Within a minute, you should see:
   - The alert appear in the Journal tab
   - A NOTIFY email arrive at your configured address (if the LLM verdict was NOTIFY)
   - The alert appear in Graylog under `application:jrsoctriage`

6. If everything works, stop the manual pipeline run with `Ctrl+C`. You are ready for systemd.

7. If something does not work, the Journal tab and the systemd journal (`sudo journalctl -u jrsoctriage -f`) are your primary debugging tools. See `running_instructions.txt` → TROUBLESHOOTING for common issues.

---

## Section 13: Promote to Systemd

### What we are doing, and why

Running the pipeline manually is fine for testing but not for production. Systemd handles automatic startup on boot, automatic restart on crash, and proper logging to the system journal. The setup script has already updated the unit files with your install paths, so this section is mostly copy commands.

### Steps

1. Stop any manually-running instances. In the SSH sessions where you started `interface.py` and `main.py` manually, press `Ctrl+C`.

2. Copy the unit files to systemd's directory:

   ```bash
   sudo cp jrsoctriage.service /etc/systemd/system/
   sudo cp jrsoctriage-interface.service /etc/systemd/system/
   ```

3. Reload systemd to pick up the new units:

   ```bash
   sudo systemctl daemon-reload
   ```

4. Enable both services to start on boot:

   ```bash
   sudo systemctl enable jrsoctriage jrsoctriage-interface
   ```

5. Start the interface service first:

   ```bash
   sudo systemctl start jrsoctriage-interface
   ```

   Verify it is running:

   ```bash
   sudo systemctl status jrsoctriage-interface
   ```

   Then access the web interface again via SSH tunnel to confirm.

6. Start the pipeline service:

   ```bash
   sudo systemctl start jrsoctriage
   ```

   Verify it is running:

   ```bash
   sudo systemctl status jrsoctriage
   ```

7. Tail the journal to confirm normal operation:

   ```bash
   sudo journalctl -u jrsoctriage -f
   ```

   You should see the same log lines you saw when you ran `main.py` manually. Both services will now restart automatically on boot or crash.

---

## Section 14: Day-2 Operations

### What we are doing, and why

After initial setup, normal operation involves adding hosts as your network changes, refining rules as you learn what to suppress, and watching the journal for unexpected behavior. This section is a quick reference, not a deep dive.

### Adding hosts

1. In the web interface, click the **Hosts** tab.
2. Click **Add Host**.
3. Fill in the fields and click **Save Hosts**.
4. No restart needed — the pipeline picks up `hosts.json` changes dynamically.

### Editing rules

1. In the web interface, click the **Rules** tab.
2. Click **Add Rule** to suppress a noisy alert pattern, or **Edit** an existing rule.
3. Click **Save Rules**.
4. **Restart the pipeline** to apply rule changes:

   ```bash
   sudo systemctl restart jrsoctriage
   ```

   Or use the Restart button on the **Restart** tab in the interface.

### Adding interface users

The current release supports terminal-based user management for the web interface:

```bash
cd /path/to/jrsoctriage
sudo ./venv/bin/python3 interface.py --add-user
```

This prompts for username, password, and TOTP setup, appending to the existing auth file. GUI-based user management is planned for a future release.

### Watching the pipeline

- **Journal tab** in the web interface: live tail of the pipeline log with filter controls.
- **Restart tab**: the **Restart jrsoctriage** button captures the first 60 lines of startup output, useful when debugging service start issues.
- `sudo journalctl -u jrsoctriage -f` from the command line for the same data as the Journal tab.

### Updating jrSOCtriage

When a new release is available:

```bash
cd /path/to/jrsoctriage
git pull          # if installed from git
sudo bash setup.sh  # safe to re-run; updates dependencies
sudo systemctl restart jrsoctriage jrsoctriage-interface
```

If `interface.py` or any pipeline module changed, both services need restart. Configuration changes through the web interface do not need a restart unless they touch rules.json, the LLM endpoints, or other restart-required settings (see the NOTE in `running_instructions.txt`).

---

## Where to go next

- `readme.md` — project overview and design philosophy
- `running_instructions.txt` — full config schema, troubleshooting, advanced topics
- `interface_guide.txt` — tab-by-tab reference for every field in the web interface
- `LICENSE` — usage terms (this is source-available, not open-source — read before deploying commercially)
