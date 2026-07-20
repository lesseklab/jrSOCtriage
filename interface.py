#!/usr/bin/env python3
"""
jrSOCtriage Web Interface
=========================
A browser-based configuration and monitoring interface for jrSOCtriage.

Usage:
  sudo python3 interface.py [--port 9090] [--config /path/to/config.json]

Access:
  Local:  http://127.0.0.1:9090
  Remote: SSH tunnel: ssh -L 9090:127.0.0.1:9090 user@host
          then open http://127.0.0.1:9090 in your browser

Tabs:
  Config         - Processing, filtering, LLM endpoints, email, paths
  Hosts          - Host inventory with notes and anonymization aliases
  Rules          - Per-rule escalation control and rate limiting
  Anonymization  - Identity masking switches, users, domains, IP aliases
  Networks       - CIDR ranges shown as context in every LLM prompt
  Journal        - Live log stream from jrsoctriage.service
  Restart        - Restart service and capture startup output

Important:
  - Run as sudo (required for systemctl restart)
  - LOCKED OUT? (lost password/2FA, or interface_auth.json corrupt):
    SSH to the host, then either restore interface_auth.json from
    backup, or delete it and restart the interface — it will run
    first-run setup and prompt for a new admin user. Deleting the
    auth file removes ALL users; recreate the others with
    `sudo python3 interface.py --add-user` or via the Users tab.
  - Changes take effect only after restarting jrsoctriage
  - Binds to 127.0.0.1 only — not accessible from network without SSH tunnel
  - Requires Flask: sudo pip install flask --break-system-packages
"""

import argparse
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import bcrypt
import pyotp
import qrcode
from flask import Flask, Response, jsonify, redirect, render_template_string, request, session, url_for

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Session signing key — regenerated each run
# Explicit cookie security flags — do not rely on browser defaults.
# SameSite=Lax means the session cookie is NOT sent on cross-site POSTs,
# which is the CSRF defense for cookie-authenticated state-changing routes
# (/api/restart takes a bodyless POST — exactly the shape a malicious page
# could otherwise fire at http://127.0.0.1:9090 from the operator's own
# browser). Chrome treats an unset SameSite as Lax; other browsers have
# lagged — setting it makes the protection deterministic everywhere.
# HttpOnly keeps the cookie out of reach of any injected/extension JS.
# SESSION_COOKIE_SECURE is deliberately NOT set: the documented deployment
# is http:// over loopback/SSH tunnels and Secure would break it.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True


class _KeepaliveLogFilter(logging.Filter):
    # Drop the session-keepalive requests from werkzeug's request log.
    # The page pings /api/auth/check every 5 seconds (session-death and
    # outage detection - see SESSION_CHECK_INTERVAL_MS in the template).
    # Without this filter that is 12 log lines per minute per open tab
    # in the interface unit's journal, burying everything useful. Only
    # the keepalive endpoint is filtered; all other requests still log.
    def filter(self, record):
        return "/api/auth/check" not in record.getMessage()


logging.getLogger("werkzeug").addFilter(_KeepaliveLogFilter())

# Module logger — output goes to systemd journal when run as a service,
# or to stdout when run from a terminal. Used for audit trail of state-
# changing operations like maintenance set/clear.
logger = logging.getLogger("interface")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

DEFAULT_PORT = 9090
AUTH_FILENAME = "interface_auth.json"
# Default session idle timeout if not set in config (minutes).
DEFAULT_SESSION_TIMEOUT_MINUTES = 30
# Default config: look in the directory interface.py is run from
DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# ---------------------------------------------------------------------------
# Auth system — bcrypt passwords + TOTP 2FA
# ---------------------------------------------------------------------------

AUTH_PATH = None  # Set at startup based on config location

def get_auth_path():
    """Return path to auth file, adjacent to config.json."""
    base = str(Path(CONFIG_PATH).parent)
    return os.path.join(base, AUTH_FILENAME)

def load_auth():
    """Load auth file. Returns {"users": [...]}.

    Distinguishes three cases:
      - File does not exist: returns empty users list (triggers first-run setup).
      - File exists and is valid JSON: returns parsed contents.
      - File exists but is corrupt or unreadable: raises RuntimeError.

    The corrupt-file case is critical: silently treating a corrupt auth file
    as "no users configured" would invite an attacker to corrupt the file
    and trigger setup_first_user, allowing creation of a new admin account.
    Failing loudly forces operator intervention (restore from backup or
    delete the file deliberately).
    """
    path = get_auth_path()
    if not os.path.exists(path):
        return {"users": []}
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise RuntimeError(
            f"Auth file at {path} is unreadable or corrupt: {e}. "
            f"Refusing to start. To force first-user setup, delete the "
            f"file deliberately. To recover, restore from backup."
        ) from e
    # Sanity check: must be a dict with users key.
    if not isinstance(data, dict) or "users" not in data:
        raise RuntimeError(
            f"Auth file at {path} has unexpected structure (missing 'users'). "
            f"Refusing to start. Delete or restore from backup."
        )
    return data

def save_auth(data):
    """Save auth file with restrictive permissions (mode 600), atomically.

    The auth file holds bcrypt password hashes and TOTP secrets. The TOTP
    secrets in particular are sensitive — anyone who reads them can
    generate valid 2FA codes. We chmod 600 after writing to ensure only
    the file owner (typically root, since the interface runs as root) can
    read the file. New file creation respects umask, which on most systems
    leaves the file world-readable; chmod fixes that.

    Atomicity: writes to a sibling tmp file, fsyncs, chmods 600, then
    renames atomically over the destination. A crash mid-write leaves
    the original auth file intact — losing auth state is much worse
    than the original write being lost, because if auth.json becomes
    empty or malformed, no one can log in.
    """
    path = get_auth_path()
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError as e:
            # Permissions change failed (very unusual). Log a warning so the
            # operator knows the file may be readable by others; do not abort.
            print(f"WARNING: could not chmod 600 on {tmp}: {e}")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def get_user(username):
    """Find user by username."""
    auth = load_auth()
    for u in auth.get("users", []):
        if u["username"] == username:
            return u
    return None

def _check_password_complexity(password):
    """Validate password complexity. Returns (ok, message).

    Requires minimum 8 characters with at least one uppercase and one
    lowercase letter. This is a low-friction baseline — it rejects the
    most obviously-weak passwords ("admin", "password", "12345678") while
    leaving meaningful choice to the operator. TOTP 2FA provides the
    second factor against guessing attacks; the password baseline is
    primarily there to defeat single-factor attacks if the TOTP secret
    is ever exposed.
    """
    if not password:
        return False, "Password cannot be empty."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    return True, None


# Module-level dummy bcrypt hash for constant-time username enumeration
# defense. Computed once at import. When verify_login() is called with a
# username that doesn't exist, we still run a bcrypt.checkpw against this
# dummy hash so the response time matches the case where a real user
# exists but the password is wrong. Without this, an attacker can time
# /login responses and learn which usernames are valid.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"jrsoctriage_dummy", bcrypt.gensalt()).decode()


# --- TOTP replay guard ---------------------------------------------------
# RFC 6238 §5.2: a verifier MUST NOT accept the same OTP twice. Without
# this, anyone who observes a valid code (shoulder-surf, the plain-HTTP
# hop inside the tunnel) can replay it for ~90s to mint a second session.
# We track the last ACCEPTED timestep per username and reject any code
# whose matched timestep is <= that. In-memory is correct here: a restart
# wipes the table, but restart also rotates app.secret_key and kills every
# session, so the guarantees reset together.
_TOTP_INTERVAL_SECONDS = 30  # pyotp default; TOTP() below uses defaults
_last_totp_step: dict = {}   # username -> last accepted timestep (int)
_last_totp_step_lock = threading.Lock()


def _verify_totp_no_replay(username, totp_secret, totp_code):
    """Verify a TOTP code with valid_window=1 semantics AND replay
    rejection. Returns True only if the code matches one of the three
    candidate timesteps (prev/current/next, mirroring valid_window=1)
    and that timestep is strictly newer than the last accepted one for
    this username.

    We probe each offset individually (valid_window=0 per probe) because
    pyotp's windowed verify() does not report WHICH step matched — and
    without that, a skew-tolerant acceptance at step S cannot stop the
    same code being accepted again at step S+1. Cost is the same three
    HMACs a single valid_window=1 verify performs internally.
    """
    totp = pyotp.TOTP(totp_secret)
    now = time.time()
    matched_step = None
    for offset in (-1, 0, 1):
        probe_time = now + (offset * _TOTP_INTERVAL_SECONDS)
        if totp.verify(totp_code, for_time=probe_time, valid_window=0):
            matched_step = int(probe_time) // _TOTP_INTERVAL_SECONDS
            break
    if matched_step is None:
        return False
    with _last_totp_step_lock:
        last = _last_totp_step.get(username, -1)
        if matched_step <= last:
            logger.warning(
                f"TOTP replay rejected for user '{username}' "
                f"(code for timestep {matched_step} already used)"
            )
            return False
        _last_totp_step[username] = matched_step
    return True


def verify_login(username, password, totp_code):
    """Verify username, password, and TOTP. Returns (ok, error_message).

    Designed to be timing-resistant against username enumeration and
    against learning which factor (password vs TOTP) failed:
      - When the username doesn't exist, we still run bcrypt against a
        dummy hash so the response time matches the password-mismatch case.
      - When the password is wrong, we still run TOTP verification so the
        response time matches the TOTP-mismatch case.
      - All three failure modes return the same generic error string.
    Both checks must pass for a successful login.
    """
    user = get_user(username)
    if user is None:
        # Burn the bcrypt cycles so timing doesn't reveal nonexistent user.
        bcrypt.checkpw(b"jrsoctriage_dummy", _DUMMY_PASSWORD_HASH.encode())
        # Also burn TOTP cycles for consistency with the password-failure
        # branch below. pyotp.TOTP construction is cheap; verify() against
        # a known-bad code does the HMAC dance.
        pyotp.TOTP(pyotp.random_base32()).verify(totp_code or "000000", valid_window=1)
        return False, "Invalid credentials"

    password_ok = bcrypt.checkpw(password.encode(), user["password_hash"].encode())
    # Always evaluate TOTP, even when password was wrong, so an attacker
    # can't distinguish "right password / wrong TOTP" from "wrong password"
    # by response time. Both fall through to the same generic error below.
    # Replay note: the guard records the accepted timestep even when the
    # password turns out wrong. That is the conservative direction — a
    # captured code burned against a bad password cannot be replayed
    # later with the right one.
    totp_ok = _verify_totp_no_replay(username, user["totp_secret"], totp_code)

    if not (password_ok and totp_ok):
        return False, "Invalid credentials"
    return True, None


# ---------------------------------------------------------------------------
# Login rate limiting — in-memory, per (client IP, username)
# ---------------------------------------------------------------------------
#
# Two protections layered:
#   1. Cooldown: 4 seconds between login attempts on the same bucket.
#      Defeats automated credential-stuffing tools that rely on parallelism.
#   2. Lockout: after 3 failed attempts within the lockout window, reject
#      all attempts on that bucket for 3 minutes. Defeats slow-and-steady
#      password guessing.
#
# KEYING: buckets are (client_ip, username-lowercased), not IP alone.
# In the documented deployment every user arrives through their own SSH
# tunnel, so request.remote_addr is 127.0.0.1 for EVERYONE — per-IP-only
# keying would make this one global bucket: any user's three typos would
# lock all users out, and two users logging in within the 4s cooldown of
# each other would collide. Per-(IP, username) keeps the anti-guessing
# properties per account while isolating users from each other. The
# username half is lowercased for keying only (login itself stays
# case-sensitive) so case-twiddling can't mint fresh buckets.
#
# Storage is in-memory (module-level dict). State is lost on server restart,
# which is acceptable: restart already invalidates all sessions and forces
# re-auth, so a determined attacker mid-attempt loses their progress
# anyway. In-memory storage also avoids a disk-based attack surface.
# Because the username half of the key is attacker-controlled, the table
# is pruned of stale entries once it grows past a modest cap.
#
# Successful login clears the bucket's failure counter — legitimate users
# who fat-finger their TOTP twice and then succeed are not penalized.

_LOGIN_COOLDOWN_SECONDS = 4
_LOGIN_LOCKOUT_THRESHOLD = 3        # failures before lockout kicks in
_LOGIN_LOCKOUT_DURATION_SECONDS = 180  # 3 minutes
_LOGIN_TABLE_PRUNE_THRESHOLD = 256  # prune stale buckets past this size

# Keyed by (client IP, lowercased username). Value is dict with
# last_attempt (epoch seconds), fail_count (int), locked_until
# (epoch seconds, 0 if not locked).
_login_attempts: dict = {}
_login_attempts_lock = threading.Lock()


def _login_rate_key(client_ip, username):
    """Build the rate-limit bucket key. See keying note above."""
    return (client_ip, (username or "").strip().lower())


def _check_login_rate_limit(rate_key):
    """Check whether this bucket (client IP, username) may attempt a login now.

    Returns (allowed, error_message). If allowed, the caller should record
    the attempt result by calling _record_login_result().
    """
    now = time.monotonic()
    with _login_attempts_lock:
        record = _login_attempts.get(rate_key, {
            "last_attempt": 0.0,
            "fail_count": 0,
            "locked_until": 0.0,
        })

        # Lockout check first — most restrictive.
        if record["locked_until"] > now:
            remaining = int(record["locked_until"] - now)
            return False, (
                f"Too many failed attempts. Try again in "
                f"{remaining} seconds."
            )

        # Cooldown check — applies between any two attempts, success or fail.
        elapsed = now - record["last_attempt"]
        if elapsed < _LOGIN_COOLDOWN_SECONDS and record["last_attempt"] > 0:
            wait = int(_LOGIN_COOLDOWN_SECONDS - elapsed) + 1
            return False, f"Please wait {wait} seconds between login attempts."

        return True, None


def _record_login_result(rate_key, success):
    """Record the result of a login attempt. Call after _check_login_rate_limit
    returned allowed=True and after attempting verify_login.

    Successful logins clear the bucket's failure counter. Failures increment
    it and trigger lockout once the threshold is reached. The table is pruned
    of stale buckets past _LOGIN_TABLE_PRUNE_THRESHOLD because the username
    half of the key is attacker-controlled (memory-growth hygiene).
    """
    now = time.monotonic()
    with _login_attempts_lock:
        record = _login_attempts.get(rate_key, {
            "last_attempt": 0.0,
            "fail_count": 0,
            "locked_until": 0.0,
        })
        record["last_attempt"] = now
        if success:
            # Clear failure tracking on success — legitimate user.
            record["fail_count"] = 0
            record["locked_until"] = 0.0
        else:
            record["fail_count"] += 1
            if record["fail_count"] >= _LOGIN_LOCKOUT_THRESHOLD:
                record["locked_until"] = now + _LOGIN_LOCKOUT_DURATION_SECONDS
                # Reset count after triggering lockout, so the next batch
                # of failures after lockout-expiry starts fresh.
                record["fail_count"] = 0
        _login_attempts[rate_key] = record
        # Prune stale buckets: not locked, and idle past the longer of the
        # two protection windows. Bounded work, only runs past the cap.
        if len(_login_attempts) > _LOGIN_TABLE_PRUNE_THRESHOLD:
            stale_cutoff = now - max(_LOGIN_LOCKOUT_DURATION_SECONDS,
                                     _LOGIN_COOLDOWN_SECONDS) * 2
            for k in [k for k, r in _login_attempts.items()
                      if r["locked_until"] <= now
                      and r["last_attempt"] < stale_cutoff]:
                del _login_attempts[k]

def is_authenticated():
    """Check if current session is authenticated AND not idle-expired.

    A session is valid only if:
      1. The Flask-signed session cookie says authenticated=True (validated
         server-side by Flask using app.secret_key).
      2. The last_activity timestamp in the session is within the configured
         idle timeout window.

    Both checks must pass. The idle-timeout check exists to invalidate
    walked-away-from-keyboard sessions independent of server restart.
    Server restart already invalidates all sessions because secret_key
    regenerates each launch.
    """
    if session.get("authenticated") is not True:
        return False
    last = session.get("last_activity")
    if not last:
        # Session is missing the activity marker — treat as expired.
        # This handles upgrade case where pre-timeout sessions exist
        # without last_activity set, and any tampered cookies that lack it.
        return False
    try:
        last_dt = datetime.fromisoformat(last)
    except (ValueError, TypeError):
        return False
    timeout_minutes = _get_session_timeout_minutes()
    elapsed_seconds = (datetime.now(timezone.utc) - last_dt).total_seconds()
    if elapsed_seconds > (timeout_minutes * 60):
        return False
    return True


def _get_session_timeout_minutes():
    """Read session timeout from config, with fallback to default."""
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        val = cfg.get("interface", {}).get("session_timeout_minutes")
        if val is None:
            return DEFAULT_SESSION_TIMEOUT_MINUTES
        # Clamp to reasonable bounds: minimum 1 minute, maximum 24 hours.
        # Below 1 minute is unusable; above 24 hours defeats the purpose.
        val = int(val)
        return max(1, min(val, 24 * 60))
    except (FileNotFoundError, json.JSONDecodeError, ValueError, TypeError):
        return DEFAULT_SESSION_TIMEOUT_MINUTES


def _touch_session():
    """Update last_activity timestamp on the session.

    Called from before_request after auth check passes, to bump the idle
    timer on each request. Stored as ISO-format UTC timestamp string for
    JSON-serializable session storage.
    """
    session["last_activity"] = datetime.now(timezone.utc).isoformat()


def require_auth(f):
    """Decorator to require authentication.

    Beyond the session-cookie check, this consults the auth FILE on
    every request, making it the per-request source of truth:
      - If the session's user no longer exists in the file (deleted via
        the Users tab or by hand), the session dies NOW — not at idle
        timeout or interface restart. "Delete user" means delete user.
      - If the user's record carries force_password_change, every page
        is redirected to /change-password and every API call returns a
        flagged 403, until the password is changed. /change-password
        and /logout are exempt so the gate cannot strand anyone.
    The auth file is a few hundred bytes and load is one read — the
    per-request cost is negligible, and it is what makes user-record
    changes take effect immediately.

    Recovery note: because the auth file is authoritative, a corrupt or
    deleted file ends all sessions immediately (load_auth fails loudly
    by design). The way back in is the SSH path documented in the module
    docstring: restore the file, or delete it and restart the interface
    for first-run setup. SSH access is a precondition of reaching this
    interface at all, so that path is always available.
    """
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_authenticated():
            # Distinguish API requests from page navigation requests.
            # API requests (XHR/fetch from JS) need a JSON 401 response so
            # the client can detect auth failure and redirect itself.
            # A 302 redirect would be silently followed by fetch() and
            # the client would receive the login page HTML as a "successful"
            # response body, which it then tries to parse as JSON and fails
            # silently — producing the worst possible UX where saves appear
            # to succeed but actually do nothing.
            #
            # Heuristic: if the path starts with /api/ OR the request
            # explicitly accepts JSON, treat as API. Everything else is
            # treated as page navigation and gets the redirect.
            wants_json = (
                request.path.startswith("/api/")
                or "application/json" in request.headers.get("Accept", "")
            )
            if wants_json:
                return jsonify({
                    "ok": False,
                    "error": "Authentication required or session expired",
                    "auth_required": True,
                }), 401
            return redirect("/login")
        # Session cookie is valid — now consult the auth file (source of
        # truth; see docstring).
        user = get_user(session.get("username", ""))
        wants_json = (
            request.path.startswith("/api/")
            or "application/json" in request.headers.get("Accept", "")
        )
        if user is None:
            # User was deleted while this session was live. Kill it now.
            session.clear()
            if wants_json:
                return jsonify({
                    "ok": False,
                    "error": "Account no longer exists",
                    "auth_required": True,
                }), 401
            return redirect("/login")
        if (user.get("force_password_change", False)
                and request.path not in ("/change-password", "/logout")):
            if wants_json:
                return jsonify({
                    "ok": False,
                    "error": "Password change required before continuing",
                    "password_change_required": True,
                }), 403
            return redirect("/change-password")
        # Bump the idle timer for any successful authenticated request.
        # before_request would also catch this, but doing it here too means
        # the timer tracks per-route activity even if before_request order
        # changes in future Flask versions.
        _touch_session()
        return f(*args, **kwargs)
    return decorated

def _interactive_create_user(existing_usernames=None):
    """
    Shared interactive flow for creating a new auth user. Prompts for
    username, password, generates TOTP, prints QR, and verifies the
    authenticator.

    Returns the new user dict (not yet saved). Caller is responsible for
    appending to the auth file.

    existing_usernames: optional set of usernames to reject (prevents
    creating duplicate usernames in append mode).
    """
    import getpass
    if existing_usernames is None:
        existing_usernames = set()

    # Username — must be unique within the auth file
    while True:
        username = input("  Username: ").strip()
        if not username:
            print("  Username cannot be empty.")
            continue
        if username in existing_usernames:
            print(f"  Username '{username}' already exists. Choose another.")
            continue
        break

    # Password — minimum 8 characters with mixed case
    while True:
        password = getpass.getpass("  Password: ")
        confirm  = getpass.getpass("  Confirm password: ")
        ok, msg = _check_password_complexity(password)
        if not ok:
            print(f"  {msg}")
        elif password != confirm:
            print("  Passwords do not match.")
        else:
            break

    # Generate TOTP
    totp_secret = pyotp.random_base32()
    totp        = pyotp.TOTP(totp_secret)
    otp_uri     = totp.provisioning_uri(name=username, issuer_name="jrSOCtriage")

    # Print QR code to terminal
    print("\n  Scan this QR code with your authenticator app:\n")
    qr = qrcode.QRCode()
    qr.add_data(otp_uri)
    qr.make()
    qr.print_ascii(invert=True)
    print(f"\n  Manual entry key: {totp_secret}")
    print(f"  Account name    : {username} (jrSOCtriage)\n")

    input("  Press Enter after scanning the QR code...")

    # Verify TOTP is working
    while True:
        code = input("  Enter the 6-digit code from your app to verify: ").strip()
        if totp.verify(code, valid_window=1):
            print("  [OK] Authenticator verified!\n")
            break
        print("  [!!] Invalid code. Try again.")

    # Hash password and build user record
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return {
        "username":              username,
        "password_hash":         pw_hash,
        "totp_secret":           totp_secret,
        "totp_verified":         True,
        "force_password_change": False,
        # NOTE: role is informational in v1.0 — nothing enforces it yet.
        # All v1.0 users have full access; RBAC is a later UI progression.
        "role":                  "admin",
    }


def setup_first_user():
    """
    First-run setup. Called when no auth file exists.
    Prompts for username/password, generates TOTP, saves auth file.
    """
    print("\n" + "="*60)
    print("  jrSOCtriage Web Interface — First Run Setup")
    print("="*60)
    print("  No auth file found. Creating first admin user.")
    print("  You will need Google Authenticator or any TOTP app.")

    user = _interactive_create_user()
    auth = {"users": [user]}
    save_auth(auth)
    print(f"  Auth saved. Starting interface...\n")


def add_user_cli():
    """
    Append a new user to the existing auth file via terminal flow.
    Invoked by the --add-user CLI flag. Refuses to run if the auth file
    is missing or unreadable; first-run setup handles those cases.
    """
    print("\n" + "="*60)
    print("  jrSOCtriage Web Interface — Add User")
    print("="*60)

    auth_path = get_auth_path()
    if not os.path.exists(auth_path):
        print(f"  No auth file found at {auth_path}.")
        print(f"  Run interface.py without --add-user to perform first-run setup.")
        return 1

    try:
        auth = load_auth()
    except RuntimeError as e:
        print(f"  ERROR: {e}")
        return 1

    existing = {u["username"] for u in auth.get("users", [])}
    print(f"  Existing users: {', '.join(sorted(existing)) if existing else '(none)'}")
    print(f"  You will need Google Authenticator or any TOTP app.\n")

    user = _interactive_create_user(existing_usernames=existing)
    auth["users"].append(user)
    save_auth(auth)
    print(f"  User '{user['username']}' added. Total users: {len(auth['users'])}\n")
    return 0

# ---------------------------------------------------------------------------
# Login page HTML
# ---------------------------------------------------------------------------

LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>jrSOCtriage — Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #161b22; border: 1px solid #21262d; border-radius: 8px;
            padding: 40px; width: 360px; }
    .logo { font-family: monospace; font-size: 13px; color: #3fb950; letter-spacing: 2px;
            text-transform: uppercase; margin-bottom: 8px; }
    .subtitle { color: #8b949e; font-size: 12px; margin-bottom: 32px; }
    label { display: block; font-size: 12px; color: #8b949e; margin-bottom: 6px;
            text-transform: uppercase; letter-spacing: 1px; }
    input { width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 4px;
            color: #c9d1d9; font-size: 14px; padding: 10px 12px; margin-bottom: 20px; }
    input:focus { outline: none; border-color: #3fb950; }
    button { width: 100%; background: #238636; border: none; border-radius: 4px;
             color: #fff; font-size: 14px; font-weight: 600; padding: 12px;
             cursor: pointer; letter-spacing: 1px; }
    button:hover { background: #2ea043; }
    .error { background: rgba(248,81,73,0.1); border: 1px solid rgba(248,81,73,0.4);
             border-radius: 4px; color: #f85149; font-size: 13px; padding: 10px 12px;
             margin-bottom: 20px; }
    .hint { color: #8b949e; font-size: 11px; margin-top: 20px; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">// jrSOCtriage</div>
    <div class="subtitle">Web Interface — Authentication Required</div>
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="username" autocomplete="username" autofocus>
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password">
      <label>Authenticator Code</label>
      <input type="text" name="totp" maxlength="6" pattern="[0-9]{6}"
             placeholder="6-digit code" autocomplete="one-time-code" inputmode="numeric">
      <button type="submit">Sign In</button>
    </form>
    <div class="hint">Delete interface_auth.json to reset credentials</div>
  </div>
  <div class="scroll-btns" id="scroll-btns" style="display:none">
    <button class="scroll-btn" onclick="window.scrollTo({top:0,behavior:'smooth'})" title="Top">▲</button>
    <button class="scroll-btn" onclick="window.scrollTo({top:document.body.scrollHeight,behavior:'smooth'})" title="Bottom">▼</button>
  </div>

</body>
</html>"""


# ---------------------------------------------------------------------------
# HTML Template — single-page app served at /
# ---------------------------------------------------------------------------

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>jrSOCtriage</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  :root {
    --bg:       #0a0c0f;
    --bg2:      #0f1318;
    --bg3:      #151b22;
    --border:   #1e2a35;
    --green:    #00ff88;
    --green2:   #00cc6a;
    --amber:    #ffaa00;
    --red:      #ff4455;
    --blue:     #0088ff;
    --dim:      #3a4a5a;
    --text:     #c8d8e8;
    --textdim:  #607080;
    --mono:     'Share Tech Mono', monospace;
    --mono-read:'JetBrains Mono', 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    --sans:     'Rajdhani', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 15px;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }

  /* Header */
  header {
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 0 24px;
    display: flex;
    align-items: center;
    gap: 32px;
    height: 52px;
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    font-family: var(--mono);
    font-size: 13px;
    color: var(--green);
    letter-spacing: 2px;
    text-transform: uppercase;
    white-space: nowrap;
  }

  .logo span { color: var(--textdim); }

  nav { display: flex; gap: 4px; flex: 1; }

  nav button {
    background: none;
    border: none;
    color: var(--textdim);
    font-family: var(--sans);
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 6px 14px;
    cursor: pointer;
    border-radius: 3px;
    transition: all 0.15s;
    white-space: nowrap;
  }

  nav button:hover { color: var(--text); background: var(--bg3); }
  nav button.active { color: var(--green); background: var(--bg3); border-bottom: 2px solid var(--green); border-radius: 3px 3px 0 0; }

  .header-actions { display: flex; gap: 8px; margin-left: auto; }

  /* Main layout */
  main { flex: 1; padding: 24px; max-width: 1100px; margin: 0 auto; width: 100%; }

  /* Panels */
  .panel { display: none; }
  .panel.active { display: block; }

  /* Config sub-tabs — folder-style tabs seated on a baseline rule, pinned
     under the 52px header. Boxed chrome so they unmistakably read as tabs;
     the active tab opens into the content below it. */
  .config-subnav {
    display: flex;
    gap: 6px;
    position: sticky;
    top: 52px;
    z-index: 90;
    background: var(--bg);
    padding: 8px 0 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 16px;
  }
  .config-subnav button {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-bottom: none;
    color: var(--textdim);
    font-family: var(--sans);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 7px 18px;
    cursor: pointer;
    border-radius: 5px 5px 0 0;
    transition: all 0.15s;
    white-space: nowrap;
    position: relative;
    top: 1px;
  }
  .config-subnav button:hover { color: var(--text); background: var(--bg3); }
  .config-subnav button.active {
    color: var(--green);
    background: var(--bg3);
    border-top: 2px solid var(--green);
    border-bottom: 1px solid var(--bg3);
  }
  .config-subpanel { display: none; }
  .config-subpanel.active { display: block; }
  .config-subtab-prompt { color: var(--textdim); font-family: var(--mono); font-size: 13px; padding: 24px 0; }

  /* Section header */
  .section-header {
    display: flex;
    align-items: baseline;
    gap: 12px;
    margin-bottom: 20px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
  }

  .section-title {
    font-family: var(--mono);
    font-size: 13px;
    color: var(--green);
    letter-spacing: 3px;
    text-transform: uppercase;
    font-weight: bold;
  }

  .section-desc { color: var(--textdim); font-size: 13px; }

  /* Cards */
  .card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 20px;
    margin-bottom: 16px;
  }

  .card-title {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--amber);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    font-weight: bold;
  }
  .src-title {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--amber);
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }

  .card-subhead {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--textdim);
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-top: 12px;
    margin-bottom: 12px;
    padding-bottom: 6px;
    border-bottom: 1px dashed var(--border);
    font-weight: bold;
  }

  /* Form fields */
  .field { margin-bottom: 16px; }

  .field label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--textdim);
    margin-bottom: 6px;
  }

  .field .hint {
    font-size: 12px;
    color: var(--dim);
    margin-bottom: 6px;
    font-style: italic;
  }

  .field input[type=text],
  .field input[type=number],
  .field input[type=password],
  .field select,
  .field textarea {
    width: 100%;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 3px;
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    padding: 8px 12px;
    outline: none;
    transition: border-color 0.15s;
  }

  .field textarea {
    font-family: var(--mono-read);
    font-size: 13px;
    line-height: 1.5;
    padding: 10px 12px;
  }

  .field input:focus,
  .field select:focus,
  .field textarea:focus { border-color: var(--green); }

  .field textarea { resize: vertical; min-height: 80px; }

  .field select option { background: var(--bg3); }

  .toggle-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }

  .toggle-row label { margin-bottom: 0; font-size: 13px; text-transform: none; letter-spacing: 0; color: var(--text); }

  /* Toggle switch */
  .toggle { position: relative; width: 40px; height: 22px; flex-shrink: 0; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .toggle-slider {
    position: absolute; inset: 0;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 22px;
    cursor: pointer;
    transition: 0.2s;
  }
  .toggle-slider:before {
    content: '';
    position: absolute;
    width: 16px; height: 16px;
    left: 2px; top: 2px;
    background: var(--dim);
    border-radius: 50%;
    transition: 0.2s;
  }
  .toggle input:checked + .toggle-slider { background: var(--bg3); border-color: var(--green); }
  .toggle input:checked + .toggle-slider:before { background: var(--green); transform: translateX(18px); }

  /* Segmented 3-way control (e.g. SMTP security mode) */
  .seg { display: inline-flex; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
  .seg label { margin: 0; cursor: pointer; }
  .seg label > span { display: block; padding: 7px 16px; font-size: 13px; color: var(--textdim);
                      background: var(--bg2); border-right: 1px solid var(--border);
                      text-transform: none; letter-spacing: 0; user-select: none; }
  .seg label:last-child > span { border-right: none; }
  .seg input { position: absolute; opacity: 0; width: 0; height: 0; pointer-events: none; }
  .seg input:checked + span { background: var(--bg3); color: var(--green); font-weight: bold; }

  /* Grid */
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .grid3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }

  /* Buttons */
  .btn {
    font-family: var(--sans);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    padding: 8px 20px;
    border: 1px solid;
    border-radius: 3px;
    cursor: pointer;
    transition: all 0.15s;
  }

  .btn-green { background: transparent; border-color: var(--green); color: var(--green); }
  .btn-green:hover { background: var(--green); color: var(--bg); }
  .btn-amber { background: transparent; border-color: var(--amber); color: var(--amber); }
  .btn-amber:hover { background: var(--amber); color: var(--bg); }
  .btn-red { background: transparent; border-color: var(--red); color: var(--red); }
  .btn-red:hover { background: var(--red); color: var(--bg); }
  .btn-dim { background: transparent; border-color: var(--dim); color: var(--textdim); }
  .btn-dim:hover { border-color: var(--text); color: var(--text); }

  .btn-row { display: flex; gap: 10px; margin-top: 20px; align-items: center; }

  /* Status bar */
  #status-bar {
    font-family: var(--mono);
    font-size: 12px;
    padding: 6px 12px;
    border-radius: 3px;
    display: none;
    margin-left: auto;
  }

  #status-bar.ok { background: rgba(0,255,136,0.1); border: 1px solid var(--green); color: var(--green); display: block; }
  #status-bar.err { background: rgba(255,68,85,0.1); border: 1px solid var(--red); color: var(--red); display: block; }
  #status-bar.info { background: rgba(0,136,255,0.1); border: 1px solid var(--blue); color: var(--blue); display: block; }

  /* Journal */
  #journal-box {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.6;
    padding: 16px;
    height: 480px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .log-info    { color: var(--text); }
  .log-warning { color: var(--amber); }
  .log-error   { color: var(--red); }
  .log-green   { color: var(--green); }
  .log-dim     { color: var(--textdim); }

  /* Endpoint cards */
  .endpoint-card {
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 16px;
    margin-bottom: 12px;
    position: relative;
  }

  .endpoint-card .ep-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }

  .ep-type-badge {
    font-family: var(--mono);
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 2px;
    letter-spacing: 1px;
  }

  .ep-ollama { background: rgba(0,136,255,0.15); border: 1px solid var(--blue); color: var(--blue); }
  .ep-gemini { background: rgba(0,255,136,0.15); border: 1px solid var(--green); color: var(--green); }
  .ep-llamacpp { background: rgba(255,170,0,0.15); border: 1px solid var(--amber); color: var(--amber); }
  .ep-openai    { background: rgba(0,255,255,0.1);  border: 1px solid #00ffff;       color: #00ffff; }
  .ep-anthropic { background: rgba(204,120,92,0.15); border: 1px solid #cc785c;       color: #cc785c; }

  /* List editor */
  .list-item {
    display: flex;
    gap: 8px;
    margin-bottom: 8px;
    align-items: center;
  }

  .list-item input { flex: 1; }

  .btn-icon {
    background: none;
    border: 1px solid var(--border);
    color: var(--textdim);
    width: 28px; height: 28px;
    border-radius: 3px;
    cursor: pointer;
    font-size: 14px;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
    transition: all 0.15s;
  }

  .btn-icon:hover { border-color: var(--red); color: var(--red); }
  .btn-icon.add:hover { border-color: var(--green); color: var(--green); }

  /* Floating scroll buttons */
  .scroll-btns { position: fixed; bottom: 24px; right: 24px; display: flex; flex-direction: column; gap: 8px; z-index: 999; }
  .scroll-btn { background: var(--bg2); border: 1px solid var(--border); border-radius: 4px;
                color: var(--textdim); cursor: pointer; font-size: 18px; width: 36px; height: 36px;
                display: flex; align-items: center; justify-content: center; transition: all 0.15s; }
  .scroll-btn:hover { color: var(--green); border-color: var(--green); }

  /* Restart panel */
  .restart-output {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.7;
    padding: 16px;
    height: 360px;
    overflow-y: auto;
    white-space: pre-wrap;
    margin-top: 16px;
  }

  /* Divider */
  .divider { border: none; border-top: 1px solid var(--border); margin: 20px 0; }

  /* Anon table */
  .anon-table { width: 100%; border-collapse: collapse; }
  .anon-table th {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 1px;
    color: var(--textdim);
    text-align: left;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
  }
  .anon-table td { padding: 6px 12px; border-bottom: 1px solid var(--bg3); }
  .anon-table tr:last-child td { border-bottom: none; }
  .anon-table input { width: 100%; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--dim); }
</style>
</head>
<body>

<header>
  <div class="logo">jr<span>SOC</span>triage <span>// config</span></div>
  <nav>
    <button class="active" onclick="showPanel('config', this)">Config</button>
    <button onclick="showPanel('hosts', this)">Hosts</button>
    <button onclick="showPanel('roles', this)">Roles</button>
    <button onclick="showPanel('rules', this)">Rules</button>
    <button onclick="showPanel('anon', this)">Anonymization</button>
    <button onclick="showPanel('journal', this)">Journal</button>
    <button onclick="showPanel('networks', this)">Networks</button>
    <button onclick="showPanel('users', this)">Users</button>
    <button onclick="showPanel('lookup', this)">Lookup</button>
    <button onclick="showPanel('maintenance', this)">Maintenance</button>
    <button onclick="showPanel('restart', this)">Restart</button>
    <button onclick="doLogout()" style="margin-left:auto;background:rgba(248,81,73,0.15);border-color:rgba(248,81,73,0.4);color:#f85149">Logout</button>
  </nav>
  <div id="status-bar"></div>
</header>

<main>

<!-- CONFIG PANEL -->
<div id="panel-config" class="panel active">
  <div class="section-header">
    <span class="section-title">// config.json</span>
    <span class="section-desc">Core pipeline settings</span>
  </div>

  <!-- Config sub-tabs: hard separation — cards render only on explicit choice -->
  <div class="config-subnav">
    <button id="subtab-btn-src" onclick="showConfigSubTab('src', this)">Source &amp; Enrich</button>
    <button id="subtab-btn-proc" onclick="showConfigSubTab('proc', this)">Processing, LLM &amp; Etc.</button>
  </div>

  <!-- Panel-level status: visible in the empty state (loadConfig error path) -->
  <div id="status-bar-config" style="font-family:var(--mono);font-size:12px;padding:6px 12px;border-radius:3px;display:none;"></div>

  <div id="config-subtab-prompt" class="config-subtab-prompt">Select a settings group above</div>

  <div id="config-sub-src" class="config-subpanel">
  <div class="section-header">
    <span class="section-title">// Source &amp; Enrich</span>
    <span class="section-desc">Core alert and data sources</span>
  </div>

  <div class="card">
    <div class="card-title">Data Sources</div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">
      Where jrSOCtriage reads alerts, logs, and enrichment data from. Enable only what you have deployed.
    </div>

    <div style="padding-top:8px">
      <div class="src-title">Wazuh <span style="color:var(--textdim);font-size:10px;text-transform:none;letter-spacing:0">(alert source)</span></div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="src_wazuh_enabled"><span class="toggle-slider"></span></label>
        <label for="src_wazuh_enabled">Enabled</label>
      </div>
      <div class="field">
        <label>Alerts File</label>
        <input type="text" id="src_wazuh_file" placeholder="/path/to/wazuh/alerts/alerts.json">
      </div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">Zeek <span style="color:var(--textdim);font-size:10px;text-transform:none;letter-spacing:0">(network flows)</span></div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="src_zeek_enabled"><span class="toggle-slider"></span></label>
        <label for="src_zeek_enabled">Enabled</label>
      </div>
      <div class="field">
        <label>Current Log Directory <span style="color:var(--textdim);font-size:10px;font-weight:400">(where live logs are written)</span></label>
        <input type="text" id="src_zeek_current_dir" placeholder="/opt/zeek/logs/current">
      </div>
      <div class="field">
        <label>Archive Log Directory <span style="color:var(--textdim);font-size:10px;font-weight:400">(parent of dated rollover subdirs; leave blank to use parent of current)</span></label>
        <input type="text" id="src_zeek_archive_dir" placeholder="/var/log/zeek-archive">
      </div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">Graylog <span style="color:var(--textdim);font-size:10px;text-transform:none;letter-spacing:0">(context logs)</span></div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="src_graylog_enabled"><span class="toggle-slider"></span></label>
        <label for="src_graylog_enabled">Enabled</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="src_graylog_verify_ssl"><span class="toggle-slider"></span></label>
        <label for="src_graylog_verify_ssl">Verify SSL</label>
      </div>
      <div class="grid2">
        <div class="field">
          <label>Endpoint</label>
          <input type="text" id="src_graylog_endpoint" placeholder="http://graylog:9000">
        </div>
        <div class="field">
          <label>Context Window (minutes)</label>
          <div class="hint">Window around alert to pull logs. 0.5 = 30s before and after.</div>
          <input type="number" id="src_graylog_window" step="0.1" min="0.1" max="10">
        </div>
      </div>
      <div class="grid2">
        <div class="field">
          <label>Max Results</label>
          <input type="number" id="src_graylog_max" min="1" max="1000">
        </div>
      </div>
      <div class="grid2">
        <div class="field">
          <label>Username</label>
          <input type="text" id="src_graylog_user">
        </div>
        <div class="field">
          <label>Password</label>
          <input type="password" id="src_graylog_pass">
        </div>
      </div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">Graylog Output <span style="color:var(--textdim);font-size:10px;text-transform:none;letter-spacing:0">(ship verdicts as GELF)</span></div>
      <div class="hint" style="margin-bottom:8px">Ships triaged alerts to Graylog as GELF UDP messages. Used for dashboards, search, and stream rules. The destination Graylog input must be a "GELF UDP" input (separate from the API endpoint above).</div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="out_graylog_enabled"><span class="toggle-slider"></span></label>
        <label for="out_graylog_enabled">Enabled</label>
      </div>
      <div class="grid2">
        <div class="field">
          <label>GELF Host</label>
          <div class="hint">Hostname or IP of the Graylog GELF UDP input. Often the same host as the API but on a different port.</div>
          <input type="text" id="out_graylog_host" placeholder="127.0.0.1">
        </div>
        <div class="field">
          <label>GELF Port</label>
          <div class="hint">UDP port the GELF input listens on. Graylog default is 12201.</div>
          <input type="number" id="out_graylog_port" min="1" max="65535" placeholder="12201">
        </div>
      </div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">ntopng <span style="color:var(--textdim);font-size:10px;text-transform:none;letter-spacing:0">(L7 active flows)</span></div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="src_ntopng_enabled"><span class="toggle-slider"></span></label>
        <label for="src_ntopng_enabled">Enabled</label>
      </div>
      <div class="grid2">
        <div class="field">
          <label>Endpoint</label>
          <input type="text" id="src_ntopng_endpoint" placeholder="http://ntopng:3001">
        </div>
        <div class="field">
          <label>Interface ID (ifid)</label>
          <div class="hint">ntopng assigns this id by an interface's position in its own interface list, so the value depends on your ntopng config and can change after an upgrade, a config change, or a state reset. Read the current id from ntopng's interfaces list.</div>
          <input type="number" id="src_ntopng_ifid" min="0">
        </div>
      </div>
      <div class="grid2">
        <div class="field">
          <label>Username</label>
          <input type="text" id="src_ntopng_user">
        </div>
        <div class="field">
          <label>Password</label>
          <input type="password" id="src_ntopng_pass">
        </div>
      </div>
      <div class="toggle-row" style="margin-top:6px">
        <label class="toggle"><input type="checkbox" id="src_ntopng_verify_ssl"><span class="toggle-slider"></span></label>
        <label for="src_ntopng_verify_ssl">Verify SSL <span style="color:var(--textdim);font-size:10px;font-weight:400">(uncheck for self-signed certs behind a reverse proxy)</span></label>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Enrichment</div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">
      External data sources that enrich alerts before the LLM sees them.
      All are safe to disable if not needed.
    </div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="enr_host_lookup"><span class="toggle-slider"></span></label>
      <label for="enr_host_lookup">Host inventory lookup</label>
    </div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="enr_network_lookup"><span class="toggle-slider"></span></label>
      <label for="enr_network_lookup">Network CIDR lookup</label>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">GeoIP (ip-api.com)</div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="geo_enabled"><span class="toggle-slider"></span></label>
        <label for="geo_enabled">Enabled</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="geo_skip_private"><span class="toggle-slider"></span></label>
        <label for="geo_skip_private">Skip private IPs</label>
      </div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">WHOIS</div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="whois_enabled"><span class="toggle-slider"></span></label>
        <label for="whois_enabled">Enabled</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="whois_skip_private"><span class="toggle-slider"></span></label>
        <label for="whois_skip_private">Skip private IPs</label>
      </div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">Reverse DNS</div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="rdns_enabled"><span class="toggle-slider"></span></label>
        <label for="rdns_enabled">Enabled</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="rdns_skip_private"><span class="toggle-slider"></span></label>
        <label for="rdns_skip_private">Skip private IPs</label>
      </div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">AbuseIPDB</div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="abuse_enabled"><span class="toggle-slider"></span></label>
        <label for="abuse_enabled">Enabled</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="abuse_skip_private"><span class="toggle-slider"></span></label>
        <label for="abuse_skip_private">Skip private IPs</label>
      </div>
      <div class="grid2" style="margin-top:8px">
        <div class="field">
          <label>API Key</label>
          <input type="password" id="abuse_api_key" placeholder="abuseipdb.com API key">
        </div>
        <div class="field">
          <label>Score Threshold (annotation)</label>
          <div class="hint">Scores at or above this are flagged in the prompt</div>
          <input type="number" id="abuse_annotate_threshold" min="0" max="100">
        </div>
      </div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">CISA KEV (Known Exploited Vulnerabilities)</div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="kev_enabled"><span class="toggle-slider"></span></label>
        <label for="kev_enabled">Enabled</label>
      </div>
      <div class="hint">Matches CVEs found in alerts against CISA's KEV catalog. Free, no API key, no rate limit. Catalog fetched from cisa.gov at most once per 24h, and only when an alert actually contains a CVE. Results add a KEV STATUS block (with interpretation guidance) to the LLM prompt and a gl2_kev_listed field to Graylog.</div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">GreyNoise</div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="greynoise_enabled"><span class="toggle-slider"></span></label>
        <label for="greynoise_enabled">Enabled</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="greynoise_skip_private"><span class="toggle-slider"></span></label>
        <label for="greynoise_skip_private">Skip private IPs</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="greynoise_rate_limit_warnings"><span class="toggle-slider"></span></label>
        <label for="greynoise_rate_limit_warnings">Rate-limit warnings</label>
      </div>
      <div class="grid2" style="margin-top:8px">
        <div class="field">
          <label>API Key (optional)</label>
          <input type="password" id="greynoise_api_key" placeholder="commercial or trial key">
        </div>
      </div>
      <div class="hint">Classifies external source IPs: known internet-wide mass scanners and background noise (opportunistic activity) vs IPs not seen scanning the internet (activity plausibly targeted at this network). Works without a key at very low volume (~10 lookups/day); a commercial or trial key is needed for real deployments. Results add a GREYNOISE block (with interpretation guidance) to the LLM prompt and a gl2_greynoise_class field to Graylog. Rate-limit warnings: log an operator warning when a lookup is rate-limited — leave on when running with a key (a 429 during normal operation can signal elevated external-IP volume); turn off when running keyless, where rate-limiting is routine. Rate-limited lookups are annotated in the record either way.</div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">EPSS</div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="epss_enabled"><span class="toggle-slider"></span></label>
        <label for="epss_enabled">Enabled</label>
      </div>
      <div class="hint">Scores CVEs found in alerts with FIRST.org's Exploit Prediction Scoring System: the modeled probability (updated daily) that each CVE will be exploited in the wild within 30 days, plus its percentile rank. Free, no API key. Only fires on CVE-bearing alerts — one batched lookup per alert covering all its CVEs, cached 24h per CVE. Complements CISA KEV: KEV confirms past exploitation, EPSS estimates forward likelihood. Results add an EPSS SCORES block (with interpretation guidance) to the LLM prompt and a numeric gl2_epss_max field to Graylog (searchable with range queries, e.g. gl2_epss_max:&gt;0.5).</div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">VirusTotal</div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="vt_enabled"><span class="toggle-slider"></span></label>
        <label for="vt_enabled">Enabled</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="vt_skip_private"><span class="toggle-slider"></span></label>
        <label for="vt_skip_private">Skip private IPs</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="vt_rate_limit_warnings"><span class="toggle-slider"></span></label>
        <label for="vt_rate_limit_warnings">Rate-limit warnings</label>
      </div>
      <div class="grid2" style="margin-top:8px">
        <div class="field">
          <label>API Key (required)</label>
          <input type="password" id="vt_api_key" placeholder="VirusTotal API key">
        </div>
        <div class="field">
          <label>Per-alert lookup cap</label>
          <input type="number" id="vt_per_alert_cap" min="1" step="1" placeholder="4">
        </div>
      </div>
      <div class="hint">Checks file hashes (from Wazuh FIM/syscheck alerts and hash-bearing rules) and external source IPs against VirusTotal's ~76 antivirus engines. Hash results are the headline: "config file changed" is noise, but "changed and the new content is 65/74 known malware" — or "the content just overwritten was" — is a verdict. Current-file hashes are checked first; previous-content hashes use remaining budget. Hash results cached 24h, IPs 30min. Results add a VIRUSTOTAL block (with interpretation guidance) to the LLM prompt and a numeric gl2_vt_malicious field to Graylog (range-searchable, e.g. gl2_vt_malicious:&gt;5). Per-alert lookup cap: with a free key leave this at 4 — free VirusTotal keys are limited to 4 lookups/min and 500/day, and are licensed for non-commercial use only (commercial deployments require a VT premium key, which may warrant a higher cap). Rate-limit warnings: off by default — quota bounces are routine on free keys; rate-limited lookups are annotated RATE_LIMITED in the record either way.</div>
    </div>

    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div class="src-title">AlienVault OTX</div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="otx_enabled"><span class="toggle-slider"></span></label>
        <label for="otx_enabled">Enabled</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="otx_skip_private"><span class="toggle-slider"></span></label>
        <label for="otx_skip_private">Skip private IPs</label>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="otx_rate_limit_warnings"><span class="toggle-slider"></span></label>
        <label for="otx_rate_limit_warnings">Rate-limit warnings</label>
      </div>
      <div class="grid2" style="margin-top:8px">
        <div class="field">
          <label>API Key (optional)</label>
          <input type="password" id="otx_api_key" placeholder="raises rate ceiling">
        </div>
      </div>
      <div class="hint">Checks file hashes and external source IPs against AlienVault OTX community pulses — analyst-contributed IOC collections for campaigns, malware families, and attacker infrastructure. Adds the fourth intelligence axis: engine detections say WHAT a file is; pulses say WHO has reported it and in connection with what. Renders pulse count, latest-reference date, and top pulse names — note that pulse names are unvetted community labels (training-lab and auto-generated pulses are common), so treat them as leads, not attribution. Free with an OTX account; works keyless at a lower rate ceiling. OTX does not confirm key validity on lookups — a mistyped key silently behaves as keyless; verify your key at otx.alienvault.com if in doubt. Hash results cached 24h, IPs 30min. Results add an OTX COMMUNITY INTELLIGENCE block (with interpretation guidance) to the LLM prompt and a numeric gl2_otx_pulses field to Graylog (range-searchable, e.g. gl2_otx_pulses:&gt;0).</div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Email</div>
    <div class="grid2">
      <div class="field">
        <label>SMTP Host</label>
        <input type="text" id="smtp_host" placeholder="smtp.gmail.com">
      </div>
      <div class="field">
        <label>SMTP Port</label>
        <input type="number" id="smtp_port" min="1" max="65535">
      </div>
    </div>
    <div class="grid2">
      <div class="field">
        <label>Username</label>
        <input type="text" id="email_username">
      </div>
      <div class="field">
        <label>Password</label>
        <input type="password" id="email_password">
      </div>
    </div>
    <div class="grid2">
      <div class="field">
        <label>From Address</label>
        <input type="text" id="email_from">
      </div>
      <div class="field">
        <label>NOTIFY Address (to_address)</label>
        <input type="text" id="email_to">
      </div>
    </div>
    <div class="grid2">
      <div class="field">
        <label>NOTE Address</label>
        <div class="hint">Separate address for [jrSOC NOTE] emails. Defaults to NOTIFY address.</div>
        <input type="text" id="email_note_addr">
      </div>
      <div class="field">
        <label>Min Confidence to Email (NOTIFY)</label>
        <select id="min_confidence">
          <option value="LOW">LOW</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="HIGH">HIGH</option>
        </select>
      </div>
    </div>
    <div class="grid2">
      <div class="field">
        <label>NOTIFY Subject Prefix</label>
        <input type="text" id="subject_prefix_notify" placeholder="[jrSOC ALERT]">
      </div>
      <div class="field">
        <label>NOTE Subject Prefix</label>
        <input type="text" id="subject_prefix_note" placeholder="[jrSOC NOTE]">
      </div>
    </div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="email_enabled"><span class="toggle-slider"></span></label>
      <label for="email_enabled">Email enabled</label>
    </div>
    <div class="field" style="margin-top:10px;">
      <label>SMTP Security</label>
      <div class="hint">STARTTLS: upgrade on port 587 (default). SSL: implicit TLS on port 465. None: no encryption.</div>
      <div class="seg" id="smtp_security">
        <label><input type="radio" name="smtp_security" value="starttls"><span>STARTTLS</span></label>
        <label><input type="radio" name="smtp_security" value="ssl"><span>SSL</span></label>
        <label><input type="radio" name="smtp_security" value="none"><span>None</span></label>
      </div>
    </div>
    <div style="margin-top:16px;">
      <button class="btn" onclick="testEmail()">Send Test Email</button>
      <div class="hint" style="margin-top:6px;">Sends a synthetic NOTIFY through the <b>saved</b> config. Save first to test new settings.</div>
      <div id="test-email-output" class="restart-output" style="display:none;margin-top:10px;"></div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Paths</div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">
      File paths for all jrSOCtriage data files. If left empty, the pipeline defaults to its working directory.
      Click <strong style="color:var(--green)">Generate Paths</strong> to auto-populate based on the interface running directory.
    </div>
    <div id="paths-container">
      <div class="grid2">
        <div class="field"><label>Hosts File</label><input type="text" id="path_hosts" placeholder="auto"></div>
        <div class="field"><label>Rules File</label><input type="text" id="path_rules" placeholder="auto"></div>
      </div>
      <div class="grid2">
        <div class="field"><label>Database File</label><input type="text" id="path_db" placeholder="auto"></div>
        <div class="field"><label>Users File</label><input type="text" id="path_users" placeholder="auto"></div>
      </div>
      <div class="grid2">
        <div class="field"><label>Domain File</label><input type="text" id="path_domain" placeholder="auto"></div>
        <div class="field"><label>Anonymization File</label><input type="text" id="path_anon" placeholder="auto"></div>
      </div>
      <div class="grid2">
        <div class="field"><label>IP Aliases File</label><input type="text" id="path_ipaliases" placeholder="auto"></div>
        <div class="field"><label>Log File</label><input type="text" id="path_log" placeholder="auto"></div>
      </div>
      <div class="grid2">
        <div class="field">
          <label>Position File</label>
          <div class="hint">Tracks byte offset in Wazuh alerts.json for resume-across-restart. Default filename is <code style="color:var(--amber)">.ingest_position</code> (hidden). Leave blank to default to <code style="color:var(--amber)">.ingest_position</code> in the pipeline working directory, or specify a full path like <code style="color:var(--amber)">/mnt/appdata/jrsoctriage/.ingest_position</code>.</div>
          <input type="text" id="path_position" placeholder="auto (.ingest_position in working dir)">
        </div>
      </div>
    </div>
    <div class="btn-row" style="margin-top:8px">
      <button class="btn btn-dim" onclick="generatePaths()">Generate Paths</button>
      <button class="btn btn-dim" onclick="clearPaths()">Clear Paths</button>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Prompt Customization</div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">
      These sections are injected into every LLM prompt. Edit to match your environment.
      Changes take effect after restart.
    </div>
    <div class="field" style="margin-bottom:16px">
      <label>Sensor Context <span style="color:var(--textdim);font-size:10px;font-weight:400">(one item per line)</span></label>
      <textarea id="prompt_sensor_context" rows="6" style="width:100%;font-family:var(--mono-read);font-size:13px;line-height:1.5;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:10px;resize:vertical"></textarea>
    </div>
    <div class="field" style="margin-bottom:16px">
      <label>Triage Guidance <span style="color:var(--textdim);font-size:10px;font-weight:400">(one item per line)</span></label>
      <textarea id="prompt_triage_guidance" rows="6" style="width:100%;font-family:var(--mono-read);font-size:13px;line-height:1.5;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:10px;resize:vertical"></textarea>
    </div>
    <div class="field">
      <label>Network Notes <span style="color:var(--textdim);font-size:10px;font-weight:400">(one item per line)</span></label>
      <textarea id="prompt_network_notes" rows="4" style="width:100%;font-family:var(--mono-read);font-size:13px;line-height:1.5;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:10px;resize:vertical"></textarea>
    </div>
    <div class="field" style="margin-top:16px;padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:4px">
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:6px">
        <input type="checkbox" id="prompt_strip_redundant_fields" style="cursor:pointer">
        <span>Abridge alert JSON in prompt (recommended)</span>
      </label>
      <div style="color:var(--textdim);font-size:11px;line-height:1.5;margin-left:24px">
        Strip redundant fields (rule.level, rule.description, agent name, compliance metadata, internal IDs) from the alert JSON sent to the LLM. The fields are already shown in the structured ALERT SUMMARY block above the JSON, so including them again wastes tokens. Saves roughly 60-170 tokens per alert. The full alert still ships to Graylog and is recorded in the database — only the prompt is abridged. Disable if a custom workflow depends on the stripped fields, or to A/B test verdict quality.
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Database</div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">
      When OFF, jrSOCtriage runs fully stateless: no DB writes (no alert history or escalation log) and all DB reads fail open (no baseline frequency context; rule rate-limiting and maintenance-mode suppression disabled). In-memory dedup is UNAFFECTED — core noise suppression still works. Because there is no write path, DB-related failure modes are removed entirely. Recommended for high-alert-volume deployments that prefer to remove DB write pressure as a reliability variable. Expect higher LLM call volume (rate-limiting fails open). Leave ON for full stateful features.
    </div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="db_enabled"><span class="toggle-slider"></span></label>
      <label for="db_enabled">Database enabled <span style="color:var(--textdim);font-size:10px;font-weight:400">(off = stateless, corruption-proof, higher LLM volume)</span></label>
    </div>
  </div>

  <div class="btn-row">
    <button class="btn btn-green" onclick="saveConfig()">Save Config</button>
    <button class="btn btn-dim" onclick="loadDefaults()">Load Defaults</button>
    <div id="status-bar-config-src" style="font-family:var(--mono);font-size:12px;padding:6px 12px;border-radius:3px;display:none;"></div>
    <div class="hint" style="color:var(--textdim);font-size:11px;align-self:center">Save Config writes the whole config.json &mdash; fields from both sub-tabs are saved together.</div>
  </div>
  </div>

  <div id="config-sub-proc" class="config-subpanel">
  <div class="section-header">
    <span class="section-title">// Processing, LLM &amp; Etc.</span>
    <span class="section-desc">Alert processing, filtering, analysis, and logging</span>
  </div>

  <div class="card">
    <div class="card-title">Deployment</div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">
      This is for deployment identity in Graylog.
    </div>
    <div class="grid2">
      <div class="field">
        <label>jrsoc_org</label>
        <div class="hint">This is the name of the organization being monitored</div>
        <input type="text" id="deploy_org">
      </div>
      <div class="field">
        <label>jrsoc_security_domain</label>
        <div class="hint">This is the part of the organization being monitored</div>
        <input type="text" id="deploy_security_domain">
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Timezone</div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">
      Zeek logs in UTC. This is used to convert to local time for alert context windows.
    </div>
    <div class="grid2">
      <div class="field">
        <label>Local TZ Offset (hours from UTC)</label>
        <div class="hint">e.g. -6 for CST, -5 for CDT, 0 for UTC</div>
        <input type="number" id="tz_offset" step="1" min="-12" max="14">
      </div>
      <div class="field">
        <label>Local TZ Name</label>
        <div class="hint">Display label only. e.g. CST, CDT, EST</div>
        <input type="text" id="tz_name" placeholder="CST">
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Processing</div>
    <div class="grid3">
      <div class="field">
        <label>Poll Interval (seconds)</label>
        <div class="hint">How often to check for new alerts</div>
        <input type="number" id="poll_interval" min="5" max="300">
      </div>
      <div class="field">
        <label>Dedup Silence (seconds)</label>
        <div class="hint">Suppress duplicate alerts for this long</div>
        <input type="number" id="dedup_silence" min="0">
      </div>
      <div class="field">
        <label>Max Batch Size</label>
        <div class="hint">Max alerts to process per cycle</div>
        <input type="number" id="max_batch" min="1" max="1000">
      </div>
    </div>
    <div class="card-subhead">// Frequency Thresholds</div>
    <div class="grid3">
      <div class="field">
        <label>Baseline Multiplier</label>
        <div class="hint">Deviation multiplier for baseline alerts (e.g. 2.0 = 2x average)</div>
        <input type="number" id="baseline_mult" min="1" max="10" step="0.1">
      </div>
      <div class="field">
        <label>Min Baseline Days</label>
        <div class="hint">Days of data needed before baseline is active</div>
        <input type="number" id="min_baseline_days" min="0" max="365">
      </div>
      <div class="field">
        <label>Escalation Multiplier</label>
        <div class="hint">Deviation multiplier to force escalation</div>
        <input type="number" id="escalation_mult" min="1" max="20" step="0.1">
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Filtering</div>
    <div class="grid2">
      <div class="field">
        <label>Min Rule Level</label>
        <div class="hint">Wazuh alert levels 0-15. Alerts below this are ignored (unless escalated)</div>
        <input type="number" id="min_rule_level" min="0" max="15">
      </div>
      <div class="field">
        <label>Abuse Score Threshold</label>
        <div class="hint">AbuseIPDB score above this triggers escalation regardless of rule level</div>
        <input type="number" id="abuse_threshold" min="0" max="100">
      </div>
    </div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="escalate_first_seen"><span class="toggle-slider"></span></label>
      <label for="escalate_first_seen">Escalate first-seen rules (new rule IDs on a host)</label>
    </div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="frequency_escalation_enabled"><span class="toggle-slider"></span></label>
      <label for="frequency_escalation_enabled">Escalate frequency anomalies (count > multiplier × daily baseline)</label>
    </div>
    <div class="field">
      <label>First Seen Lookback (days)</label>
      <div class="hint">How many days back to check for "first seen" rule detection</div>
      <input type="number" id="first_seen_days" min="0" max="365" style="max-width:160px">
    </div>
    <div class="field" style="margin-top:12px">
      <label>Always Include Networks <span style="color:var(--textdim);font-size:10px;font-weight:400">(one CIDR per line, always escalates alerts involving these ranges)</span></label>
      <textarea id="always_include_networks" rows="3" style="width:100%;font-family:var(--mono-read);font-size:13px;line-height:1.5;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:10px;resize:vertical"></textarea>
    </div>
    <div class="field" style="margin-top:8px">
      <label>Always Include Hosts <span style="color:var(--textdim);font-size:10px;font-weight:400">(one hostname per line)</span></label>
      <textarea id="always_include_hosts" rows="3" style="width:100%;font-family:var(--mono-read);font-size:13px;line-height:1.5;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:10px;resize:vertical"></textarea>
    </div>
  </div>

  <div class="card">
    <div class="card-title">LLM Endpoints</div>
    <div class="field" style="margin-bottom:16px;padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:4px">
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:6px">
        <input type="checkbox" id="llm_enabled" style="cursor:pointer">
        <span>Enable LLM triage</span>
      </label>
      <div style="color:var(--textdim);font-size:11px;line-height:1.5;margin-left:24px">
        When enabled (default), every alert that passes filtering goes to a configured LLM endpoint for verdict generation, and triaged results are emailed if confidence thresholds are met. When disabled, the pipeline runs in <strong>enrichment-only mode</strong>: alerts are still enriched (host inventory, IP reputation, geo, MITRE, baseline) and shipped to Graylog with all enrichment fields, but no LLM call is made and no email is sent. Useful for evaluation phases, deployments where a separate SIEM or SOAR consumes the enriched alerts, or privacy-sensitive environments where even local LLM inference is too much. Graylog stream rules that filter on <code>_gl2_triage_complete:true</code> will not match in this mode.
      </div>
    </div>
    <div class="grid2" style="margin-bottom:16px">
      <div class="field">
        <label>Global Max Workers <span style="color:var(--textdim);font-size:10px;font-weight:400;text-transform:none;letter-spacing:0">(Processing)</span></label>
        <div class="hint">Concurrent pipeline workers across all stages — enrichment, database writes, LLM calls, and GELF shipping, not just the LLM. 1 = serial. Each worker carries one alert through the whole pipeline. You can run more workers than you have LLM endpoints/instances (extra workers raise burst capacity for the non-LLM stages and queue for an LLM slot when one is busy), but do not configure more concurrent LLM instances than workers — an LLM instance with no worker to feed it does nothing.</div>
        <input type="number" id="max_workers" min="1" max="32" style="max-width:120px">
      </div>
    </div>
    <div id="endpoints-container"></div>
    <div class="btn-row" style="margin-top:4px;margin-bottom:16px">
      <button class="btn btn-dim" onclick="addEndpoint('ollama')">+ Ollama</button>
      <button class="btn btn-dim" onclick="addEndpoint('gemini')">+ Gemini</button>
      <button class="btn btn-dim" onclick="addEndpoint('llamacpp')">+ llama.cpp</button>
      <button class="btn btn-dim" onclick="addEndpoint('openai')">+ OpenAI</button>
      <button class="btn btn-dim" onclick="addEndpoint('anthropic')">+ Anthropic</button>
    </div>
    <div class="field" style="margin-top:4px">
      <label>Strategy</label>
      <select id="llm_strategy" style="max-width:200px">
        <option value="round_robin">Round Robin</option>
        <option value="fallback">Fallback (priority order)</option>
      </select>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Logging</div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">
      Controls what jrSOCtriage logs and ships to Graylog.
    </div>
    <div class="field">
      <label>Prompt Log Mode <span style="color:var(--textdim);font-size:10px;font-weight:400">(what to ship to gl2_llm_prompt)</span></label>
      <select id="log_prompt_mode" style="max-width:320px">
        <option value="anonymized">Anonymized (default, matches what was sent to API)</option>
        <option value="deanonymized">Deanonymized (real values, easier to read during triage)</option>
        <option value="none">None (do not ship prompt field to Graylog)</option>
      </select>
      <div class="hint" style="margin-top:6px;color:var(--amber)">Does not affect what is sent to the LLM — only affects what appears in Graylog. If per-endpoint anonymization is enabled, the LLM still receives the anonymized prompt regardless of this setting.</div>
    </div>
    <div class="toggle-row" style="margin-top:12px">
      <label class="toggle"><input type="checkbox" id="log_debug_llm_payload"><span class="toggle-slider"></span></label>
      <label for="log_debug_llm_payload">Debug LLM payload <span style="color:var(--textdim);font-size:10px;font-weight:400">(logs full prompt sent + raw response received before deanon — use for audit only, produces large log volume)</span></label>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Observability</div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">
      Periodic pipeline-health telemetry. Emits a single [LAG] line to the main jrSOCtriage log at the configured interval with queue depth, oldest-queued-alert age, last-processed-alert age, cycle duration, LLM in-flight count, and rolling LLM latency. Grep-friendly: <code>journalctl -u jrsoctriage | grep '[LAG]'</code>. Useful for spotting surge behavior, falling-behind conditions, and LLM endpoint slowdowns.
    </div>
    <div class="field">
      <label>Lag log interval (seconds) <span style="color:var(--textdim);font-size:10px;font-weight:400">(0 disables)</span></label>
      <input type="number" id="obs_lag_log_interval_seconds" min="0" max="3600" step="1" style="max-width:160px">
      <div class="hint" style="margin-top:6px;color:var(--textdim)">Recommended: 30. Fine-grained enough to catch surge behavior, coarse enough to avoid log bloat. Set to 0 to disable [LAG] emission entirely.</div>
    </div>
    <div class="field" style="margin-top:14px">
      <label>Debug</label>
      <label class="toggle"><input type="checkbox" id="obs_debug_logging"><span class="toggle-slider"></span></label>
      <label for="obs_debug_logging">Debug logging <span style="color:var(--textdim);font-size:10px;font-weight:400">(sets logging.level to debug)</span></label>
      <div class="hint" style="margin-top:6px;color:var(--textdim)">[LAG] lines and other diagnostics are emitted at DEBUG level, so they are hidden at the default info level. Turn this on (and restart the service) to see them in the journal during active troubleshooting; turn it back off when done — debug level produces significantly more log volume. Takes effect on the next service restart.</div>
    </div>
  </div>

  <div class="btn-row">
    <button class="btn btn-green" onclick="saveConfig()">Save Config</button>
    <button class="btn btn-dim" onclick="loadDefaults()">Load Defaults</button>
    <div id="status-bar-config-proc" style="font-family:var(--mono);font-size:12px;padding:6px 12px;border-radius:3px;display:none;"></div>
    <div class="hint" style="color:var(--textdim);font-size:11px;align-self:center">Save Config writes the whole config.json &mdash; fields from both sub-tabs are saved together.</div>
  </div>
  </div>
</div>

<!-- HOSTS PANEL -->
<div id="panel-hosts" class="panel">
  <div class="card">
    <div class="card-title">Wazuh API for Agent Host names</div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">
      Connection to the Wazuh management API, used to pull the agent list for importing hosts. This is separate from the Wazuh <strong>alert source</strong> (the alerts.json file) configured on the Config tab.
    </div>
    <div class="grid2">
      <div class="field">
        <label>API URL</label>
        <div class="hint">Wazuh API endpoint, e.g. <code style="color:var(--amber)">https://192.168.30.10:55000</code></div>
        <input type="text" id="wazuh_api_url" placeholder="https://host:55000">
      </div>
      <div class="field">
        <label>Custom DNS server (optional)</label>
        <div class="hint">Resolver used to verify agent names/IPs. Leave blank to use this host's default DNS. Set it when the agents resolve on a different DNS server (split-horizon networks).</div>
        <input type="text" id="wazuh_api_dns" placeholder="e.g. 192.168.30.1">
      </div>
    </div>
    <div class="grid2">
      <div class="field">
        <label>Username</label>
        <input type="text" id="wazuh_api_user">
      </div>
      <div class="field">
        <label>Password</label>
        <input type="password" id="wazuh_api_pass">
      </div>
    </div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="wazuh_api_verify_ssl"><span class="toggle-slider"></span></label>
      <label for="wazuh_api_verify_ssl">Verify SSL <span style="color:var(--textdim);font-size:10px;font-weight:400">(uncheck for self-signed certs)</span></label>
    </div>
    <div class="btn-row" style="margin-top:12px">
      <button class="btn btn-green" onclick="saveHosts()">Save Wazuh Settings</button>
      <button class="btn btn-dim" onclick="openWazuhImport()">Import Agents from Wazuh</button>
    </div>
    <div style="margin-top:10px;padding:10px;border:1px solid var(--border);border-radius:5px">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <button class="btn btn-dim" onclick="openWazuhRenumber()">Re-verify IPs (Renumber)</button>
        <label style="display:flex;align-items:center;gap:7px;cursor:pointer">
          <span class="toggle"><input type="checkbox" id="wz_renum_blank"><span class="toggle-slider"></span></span>
          <span style="font-size:11px;color:var(--textdim)">Include blank hosts</span>
        </label>
      </div>
      <div style="font-size:10px;color:var(--textdim);margin-top:6px">Re-checks each host's stored IP against Wazuh + DNS and offers to fix drift. Tick "Include blank hosts" only after moving hosts to static / MAC-reserved addressing (to pin IPs where they were previously blank).</div>
    </div>
  </div>

  <div class="section-header">
    <span class="section-title">// hosts.json</span>
    <span class="section-desc">Host inventory and notes</span>
  </div>
  <div id="hosts-container"></div>
  <div class="btn-row">
    <button class="btn btn-green" onclick="saveHosts()">Save Hosts</button>
    <button class="btn btn-dim" onclick="addHost()">+ Add Host</button>
  </div>

</div>

<!-- Shared datalist of role names, populated from roles.json. Every host
     role combobox references this so you can pick an existing role or type
     a new one (typing a new one auto-stubs it on save). -->
<datalist id="roles-datalist"></datalist>

<!-- ROLES PANEL -->
<div id="panel-roles" class="panel">
  <div class="section-header">
    <span class="section-title">// roles.json</span>
    <span class="section-desc">Reusable host roles — write context once per role, attach to many hosts</span>
  </div>
  <div class="card" style="background:rgba(0,136,255,0.05);border-color:rgba(0,136,255,0.2);margin-bottom:20px">
    <div style="font-size:12px;color:var(--textdim);line-height:1.7">
      A role lets you write "what's normal for this kind of host" once and attach it to every host that fills that role, instead of repeating notes on each host.<br>
      <strong style="color:var(--blue)">Description</strong> — short label of what the role is (e.g. "Sales-team laptop"). Shown to the LLM as host context.<br>
      <strong style="color:var(--blue)">Notes</strong> — the reusable triage context: what traffic/behavior is normal for this kind of host. Add it once you've seen what's normal; can be left blank at first.<br>
      A role with both Description and Notes blank shows as <strong style="color:var(--amber)">New</strong> — these are usually auto-created when a host references a role that doesn't exist yet.
    </div>
  </div>
  <div id="roles-container"></div>
  <div class="btn-row">
    <button class="btn btn-green" onclick="saveRoles()">Save Roles</button>
    <button class="btn btn-dim" onclick="addRole()">+ Add Role</button>
  </div>
</div>

<!-- RULES PANEL -->
<div id="panel-rules" class="panel">
  <div class="section-header">
    <span class="section-title">// rules.json</span>
    <span class="section-desc">Per-rule escalation control, rate limiting, and condition evaluation</span>
  </div>
  <div class="card" style="background:rgba(0,136,255,0.05);border-color:rgba(0,136,255,0.2);margin-bottom:20px">
    <div style="font-size:12px;color:var(--textdim);line-height:1.7">
      <strong style="color:var(--blue)">never_escalate</strong> — Hard suppress, never reaches LLM regardless of other settings.<br>
      <strong style="color:var(--blue)">escalate_if</strong> — Normal path gating. ALL conditions must pass (or OR logic) for the alert to escalate.<br>
      <strong style="color:var(--blue)">force_escalate_if</strong> — Bypass min_rule_level. If conditions met, always escalates regardless of escalate_if.<br>
      <strong style="color:var(--blue)">Condition fields</strong>: external_ips, abuse_score, rule_level, canonical_hostname, agent_ip, and any enrichment field.
    </div>
  </div>
  <div id="rules-container"></div>
  <div class="btn-row">
    <button class="btn btn-green" onclick="saveRules()">Save Rules</button>
    <button class="btn btn-dim" onclick="addRule()">+ Add Rule</button>
  </div>
</div>

<!-- ANONYMIZATION PANEL -->
<div id="panel-anon" class="panel">
  <div class="section-header">
    <span class="section-title">// anonymization</span>
    <span class="section-desc">Identity masking for cloud LLM endpoints</span>
  </div>

  <div class="card">
    <div class="card-title">Master Switches</div>
    <div class="hint" style="margin-bottom:16px;color:var(--textdim)">Controls which layers are anonymized when sent to cloud endpoints. Local endpoints are never anonymized. IP aliases are auto-generated and stored in <code style="color:var(--amber)">ip_aliases.json</code> — within-subnet randomization, stable across restarts.</div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="anon_hostnames"><span class="toggle-slider"></span></label>
      <label>Anonymize hostnames</label>
    </div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="anon_users"><span class="toggle-slider"></span></label>
      <label>Anonymize users</label>
    </div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="anon_domain"><span class="toggle-slider"></span></label>
      <label>Anonymize domain names</label>
    </div>
    <div class="toggle-row">
      <label class="toggle"><input type="checkbox" id="anon_ips"><span class="toggle-slider"></span></label>
      <label>Anonymize IP addresses</label>
    </div>
    <div class="btn-row" style="margin-top:12px">
      <button class="btn btn-green" onclick="saveAnon()">Save</button>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Users <span style="color:var(--textdim);font-size:11px;font-weight:400">— users.json</span></div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">Leave alias blank to auto-generate on next pipeline start.</div>
    <table class="anon-table">
      <thead><tr><th>Name / Email</th><th>Alias</th><th></th></tr></thead>
      <tbody id="users-tbody"></tbody>
    </table>
    <div class="btn-row">
      <button class="btn btn-dim" onclick="addAnonUser()">+ Add User</button>
      <button class="btn btn-green" onclick="saveUsers()">Save Users</button>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Domains <span style="color:var(--textdim);font-size:11px;font-weight:400">— domain.json</span></div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">Leave alias blank to auto-generate on next pipeline start.</div>
    <table class="anon-table">
      <thead><tr><th>Domain Name</th><th>Alias</th><th></th></tr></thead>
      <tbody id="domains-tbody"></tbody>
    </table>
    <div class="btn-row">
      <button class="btn btn-dim" onclick="addDomain()">+ Add Domain</button>
      <button class="btn btn-green" onclick="saveDomains()">Save Domains</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title">Anonymization Audit</div>
    <div class="hint" style="color:var(--textdim);margin-bottom:12px">
      Use these Graylog searches to audit anonymization activity.
      The <code style="color:var(--amber)">gl2_anon</code> field is set on every triaged alert.
    </div>
    <table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px">
      <tr style="border-bottom:1px solid var(--border)">
        <td style="padding:8px 12px;color:var(--green)">All anonymized (cloud) alerts</td>
        <td style="padding:8px 12px;color:var(--textdim)">gl2_anon:"true"</td>
      </tr>
      <tr style="border-bottom:1px solid var(--border)">
        <td style="padding:8px 12px;color:var(--green)">Local (non-anonymized) alerts</td>
        <td style="padding:8px 12px;color:var(--textdim)">gl2_anon:"false" AND gl2_triage_complete:"true"</td>
      </tr>
      <tr style="border-bottom:1px solid var(--border)">
        <td style="padding:8px 12px;color:var(--green)">Cloud NOTIFY verdicts</td>
        <td style="padding:8px 12px;color:var(--textdim)">gl2_anon:"true" AND gl2_llm_verdict:NOTIFY</td>
      </tr>
      <tr>
        <td style="padding:8px 12px;color:var(--green)">Verify no PII in cloud prompts</td>
        <td style="padding:8px 12px;color:var(--textdim)">gl2_anon:"true" AND _exists_:gl2_llm_prompt</td>
      </tr>
    </table>
  </div>

  <div class="card">
    <div class="card-title">IP Aliases <span style="color:var(--textdim);font-size:11px;font-weight:400">— ip_aliases.json</span></div>
    <div class="hint" style="margin-bottom:12px;color:var(--textdim)">Within-subnet IP randomization. Auto-generated when IPs are encountered. You can override any alias manually. Same IP always maps to same alias across restarts.</div>
    <table class="anon-table">
      <thead><tr><th>Original IP</th><th>Alias IP</th><th></th></tr></thead>
      <tbody id="ipaliases-tbody"></tbody>
    </table>
    <div class="btn-row">
      <button class="btn btn-dim" onclick="addIpAlias()">+ Add Entry</button>
      <button class="btn btn-green" onclick="saveIpAliases()">Save IP Aliases</button>
    </div>
  </div>
</div>

<!-- NETWORKS PANEL -->
<div id="panel-networks" class="panel">
  <div class="section-header">
    <span class="section-title">// networks</span>
    <span class="section-desc">CIDR ranges shown in every LLM prompt as network context</span>
  </div>
  <div id="networks-container"></div>
  <div class="btn-row">
    <button class="btn btn-green" onclick="saveNetworks()">Save Networks</button>
    <button class="btn btn-dim" onclick="addNetwork()">+ Add Network</button>
  </div>
</div>

<!-- JOURNAL PANEL -->
<div id="panel-journal" class="panel">
  <div class="section-header">
    <span class="section-title">// journal</span>
    <span class="section-desc">Live log stream from jrsoctriage.service</span>
  </div>
  <div class="btn-row" style="margin-bottom:12px;margin-top:0">
    <button class="btn btn-green" id="journal-btn" onclick="toggleJournal()">Start Stream</button>
    <button class="btn btn-dim" onclick="clearJournal()">Clear</button>
    <div class="field" style="margin:0;display:flex;align-items:center;gap:8px">
      <label style="margin:0;white-space:nowrap">Filter:</label>
      <input type="text" id="journal-filter" placeholder="e.g. gemini, ERROR, triage" style="width:220px">
    </div>
  </div>
  <div id="journal-box"></div>
</div>

<!-- LOOKUP PANEL -->
<div id="panel-lookup" class="panel">
  <div class="section-header">
    <span class="section-title">// lookup</span>
    <span class="section-desc">Reverse lookup anonymized aliases to real identifiers</span>
  </div>
  <div class="card" style="margin-bottom:20px">
    <div class="card-title">Search</div>
    <div class="grid2">
      <div class="field">
        <label>Alias or Real Value</label>
        <input type="text" id="lookup-query" placeholder="e.g. host-f, user-3, 10.0.0.x, corp1.internal" oninput="runLookup()">
      </div>
      <div class="field">
        <label>Results</label>
        <div id="lookup-result" style="font-family:var(--mono);font-size:12px;color:var(--green);padding:8px 0;min-height:32px"></div>
      </div>
    </div>
  </div>

  <div class="grid2" style="gap:16px">
    <div class="card">
      <div class="card-title">Host Aliases</div>
      <table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px" id="lookup-hosts-table">
        <tr style="border-bottom:1px solid var(--border)">
          <th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Real Hostname</th>
          <th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Alias</th>
        </tr>
      </table>
    </div>
    <div class="card">
      <div class="card-title">User Aliases</div>
      <table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px" id="lookup-users-table">
        <tr style="border-bottom:1px solid var(--border)">
          <th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Real Username</th>
          <th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Alias</th>
        </tr>
      </table>
    </div>
    <div class="card">
      <div class="card-title">Domain Aliases</div>
      <table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px" id="lookup-domains-table">
        <tr style="border-bottom:1px solid var(--border)">
          <th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Real Domain</th>
          <th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Alias</th>
        </tr>
      </table>
    </div>
    <div class="card">
      <div class="card-title">IP Aliases</div>
      <table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px" id="lookup-ips-table">
        <tr style="border-bottom:1px solid var(--border)">
          <th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Real IP</th>
          <th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Alias</th>
        </tr>
      </table>
    </div>
  </div>
</div>

<!-- USERS PANEL -->
<div id="panel-users" class="panel">
  <div class="section-header">
    <span class="section-title">// users</span>
    <span class="section-desc">Web interface authentication — username, password, and TOTP 2FA</span>
  </div>
  <div class="card" style="background:rgba(248,81,73,0.05);border-color:rgba(248,81,73,0.2);margin-bottom:20px">
    <div style="font-size:12px;color:var(--textdim);line-height:1.7">
      Delete <code style="color:var(--amber)">interface_auth.json</code> and restart to reset all credentials.
      New users receive a temporary password and must scan a QR code on first login.
    </div>
  </div>
  <div id="users-container"></div>
  <div class="btn-row">
    <button class="btn btn-green" onclick="addUser()">+ Add User</button>
    <div id="status-bar-users" style="font-family:var(--mono);font-size:12px;padding:6px 12px;border-radius:3px;display:none;"></div>
  </div>
  <div id="add-user-form" style="display:none" class="card" style="margin-top:16px">
    <div class="card-title">New User</div>
    <div class="grid2">
      <div class="field"><label>Username</label><input type="text" id="new_username"></div>
      <div class="field"><label>Temporary Password</label><input type="password" id="new_password"></div>
    </div>
    <div id="new-user-qr" style="display:none;margin-top:12px">
      <div class="hint" style="color:var(--green);margin-bottom:8px">Scan this QR code with the new user's authenticator app:</div>
      <img id="qr-image" style="border:4px solid white;border-radius:4px;max-width:200px">
      <div class="field" style="margin-top:12px"><label>Manual Secret Key</label><input type="text" id="totp-secret-display" readonly></div>
    </div>
    <div class="btn-row" style="margin-top:12px">
      <button id="create-user-btn" class="btn btn-green" onclick="createUser()">Create User</button>
      <button id="create-user-cancel-btn" class="btn btn-dim" onclick="cancelAddUser()">Cancel</button>
      <button id="create-user-done-btn" class="btn btn-green" style="display:none" onclick="cancelAddUser()">Done</button>
    </div>
  </div>
</div>

<!-- MAINTENANCE PANEL -->
<div id="panel-maintenance" class="panel">
  <div class="section-header">
    <span class="section-title">// maintenance mode</span>
    <span class="section-desc">Suppress non-external alerts from LLM triage for a host. All alerts still ship to Graylog.</span>
  </div>

  <div id="status-bar-maint" style="font-family:var(--mono);font-size:12px;padding:8px 14px;border-radius:3px;display:none;margin-bottom:16px;"></div>

  <div class="card" style="margin-bottom:20px">
    <div class="card-title">Currently In Maintenance</div>
    <div id="maint-active-list" style="font-family:var(--mono);font-size:12px"></div>
  </div>

  <div class="card">
    <div class="card-title">Set Maintenance Mode</div>
    <div class="grid2">
      <div class="field">
        <label>Host</label>
        <select id="maint-host" style="font-family:var(--mono)">
          <option value="">-- select host --</option>
        </select>
      </div>
      <div class="field">
        <label>Duration</label>
        <select id="maint-minutes" style="font-family:var(--mono)">
          <option value="15">15 minutes</option>
          <option value="30">30 minutes</option>
          <option value="60" selected>60 minutes</option>
          <option value="120">2 hours</option>
          <option value="240">4 hours</option>
          <option value="480">8 hours</option>
        </select>
      </div>
    </div>
    <div class="btn-row" style="margin-top:12px">
      <button class="btn btn-amber" onclick="setMaintenance()">Set Maintenance</button>
    </div>
  </div>
</div>

<!-- RESTART PANEL -->
<div id="panel-restart" class="panel">
  <div class="section-header">
    <span class="section-title">// service control</span>
    <span class="section-desc">Restart jrsoctriage and capture startup output</span>
  </div>

  <div class="card">
    <div class="card-title">Service Control</div>
    <p style="color:var(--textdim);font-size:13px;margin-bottom:12px">
      Restart the jrsoctriage service and capture the first 60 lines of startup output.
      Changes to config files take effect after restart.
    </p>
    <p style="color:var(--amber);font-size:12px;margin-bottom:16px;padding:8px 12px;background:rgba(255,170,0,0.06);border-left:2px solid var(--amber);border-radius:2px">
      <strong>Restart can take 1-3 minutes.</strong> The pipeline waits for in-flight LLM
      calls to finish before exiting (graceful drain). 30-90 seconds is typical;
      a busy pipeline with cloud-fallback retries can stretch toward 3 minutes.
      The output below will populate once the new instance starts logging.
    </p>
    <div class="btn-row" style="margin-top:0">
      <button class="btn btn-amber" onclick="restartService()">Restart jrsoctriage</button>
      <button class="btn btn-dim" onclick="serviceStatus()">Check Status</button>
    </div>
    <div id="restart-output" class="restart-output" style="display:none"></div>
  </div>
</div>

</main>

<script>
// ---------------------------------------------------------------------------
// State — tracks loaded data for all panels
// ---------------------------------------------------------------------------
let config = {};
let hosts = {};
let rules = [];
let anonCfg = {};
let users = [];
let domains = [];
let journalEs = null;
let journalRunning = false;

// ---------------------------------------------------------------------------
// authFetch — fetch wrapper that handles auth expiry and non-2xx errors
// ---------------------------------------------------------------------------
//
// The native fetch() silently follows redirects. If the server returned a
// 302 to /login on auth expiry, fetch() would return the login page HTML
// as a "successful" response body. await res.json() would then throw
// silently, leaving the caller hanging mid-action with no error feedback.
//
// require_auth on the server now returns a JSON 401 for /api/* requests.
// This wrapper detects 401 (plus any other non-2xx) and surfaces it
// cleanly: 401 redirects the page to /login, anything else throws an
// Error that callers can handle.
//
// Use this wrapper for every /api/* call from JS. Direct fetch() should
// only be used for non-API resources where redirect-following is correct.
// Chokepoint error visibility for authFetch. authFetch THROWS on any
// non-2xx and on network failure; callers without try/catch previously
// let that rejection vanish into the console, so a failed save looked
// exactly like a successful one ("the button did nothing"). Rather than
// wrapping all ~27 call sites, surface the error here in a small toast
// before throwing. The throw still aborts caller logic exactly as
// before; refresh-the-page remains the authoritative way to verify a
// save landed — the toast is a tripwire, not a receipt.
// ---- Outage mode -----------------------------------------------------
// When the interface itself is unreachable (stopped, crashed, tunnel
// down), a page that still accepts clicks is lying: client-side
// navigation and forms keep "working" while every server call dies.
// Outage mode fails loudly instead — a full-screen overlay blocks ALL
// input and probes /api/auth/check every 5 seconds:
//   - probe gets 401  -> the interface is back with a fresh secret_key
//                        (the normal restart case); session is dead,
//                        redirect to /login.
//   - probe gets 200  -> transient blip, same process, session still
//                        valid; dismiss the overlay and resume in place.
//   - probe fails     -> still down; keep counting.
// Entry points: any authFetch network-level failure, including the
// session keepalive (SESSION_CHECK_INTERVAL_MS, 5s) — so an idle page
// locks within one heartbeat (or instantly on tab refocus via the
// existing focus listeners), and an active page locks on its first
// failed call.
var _outageTimer = null;
var _outageStart = 0;

function enterOutageMode() {
  if (_outageTimer) return; // already locked
  _outageStart = Date.now();
  var el = document.createElement('div');
  el.id = 'outage-overlay';
  el.style.position = 'fixed';
  el.style.top = '0';
  el.style.left = '0';
  el.style.right = '0';
  el.style.bottom = '0';
  el.style.background = 'rgba(5,8,10,0.93)';
  el.style.zIndex = '99999';
  el.style.display = 'flex';
  el.style.flexDirection = 'column';
  el.style.alignItems = 'center';
  el.style.justifyContent = 'center';
  el.style.cursor = 'not-allowed';
  var title = document.createElement('div');
  title.textContent = 'INTERFACE UNREACHABLE';
  title.style.font = '700 22px monospace';
  title.style.color = '#f85149';
  title.style.letterSpacing = '3px';
  title.style.marginBottom = '14px';
  var sub = document.createElement('div');
  sub.id = 'outage-elapsed';
  sub.style.font = '13px monospace';
  sub.style.color = '#8b949e';
  el.appendChild(title);
  el.appendChild(sub);
  document.body.appendChild(el);
  _outageProbe();
  _outageTimer = setInterval(_outageProbe, 5000);
}

function exitOutageMode() {
  if (_outageTimer) { clearInterval(_outageTimer); _outageTimer = null; }
  var el = document.getElementById('outage-overlay');
  if (el) el.remove();
}

function _outageProbe() {
  var secs = Math.floor((Date.now() - _outageStart) / 1000);
  var sub = document.getElementById('outage-elapsed');
  if (sub) sub.textContent = 'Input blocked. Down ' + secs + 's - retrying every 5s...';
  fetch('/api/auth/check').then(function (r) {
    if (r.status === 401) {
      window.location.href = '/login';
    } else if (r.ok) {
      exitOutageMode();
    }
    // Any other status (e.g. a proxy 502): treat as still down.
  }).catch(function () { /* still down */ });
}

var _fetchErrLast = '';
var _fetchErrAt = 0;
function showFetchError(msg) {
  // Dedupe identical messages within 5s so a flapping endpoint or a
  // background timer cannot stack toasts (e.g. during a restart).
  var now = Date.now();
  if (msg === _fetchErrLast && (now - _fetchErrAt) < 5000) return;
  _fetchErrLast = msg;
  _fetchErrAt = now;
  var el = document.getElementById('global-fetch-error');
  if (!el) {
    el = document.createElement('div');
    el.id = 'global-fetch-error';
    el.style.position = 'fixed';
    el.style.bottom = '16px';
    el.style.right = '16px';
    el.style.maxWidth = '420px';
    el.style.zIndex = '9999';
    el.style.background = 'rgba(40,12,12,0.97)';
    el.style.border = '1px solid rgba(248,81,73,0.6)';
    el.style.borderRadius = '4px';
    el.style.color = '#f85149';
    el.style.font = '12px monospace';
    el.style.padding = '10px 14px';
    document.body.appendChild(el);
  }
  el.textContent = '[ERR] ' + msg;
  el.style.display = 'block';
  clearTimeout(el._hideTimer);
  el._hideTimer = setTimeout(function () { el.style.display = 'none'; }, 6000);
}

async function authFetch(url, options) {
  var method = (options && options.method) || 'GET';
  var res;
  try {
    res = await fetch(url, options);
  } catch (netErr) {
    // Network-level failure: interface unreachable (stopped, crashed,
    // tunnel down). No toast — enter outage mode, which blocks all
    // input and owns the recovery flow (see block above). This includes
    // the session keepalive, which is the ambient detector for idle
    // pages.
    enterOutageMode();
    throw netErr;
  }
  if (res.status === 401) {
    // Session expired or never authenticated. Redirect the whole page
    // (not just the fetch) so the operator sees the login form. No
    // toast — the redirect IS the visibility.
    window.location.href = '/login';
    // Throw to abort whatever caller logic was about to run on the
    // assumption of a successful response.
    throw new Error('Authentication required');
  }
  if (!res.ok) {
    // Try to extract a JSON error message; fall back to status text.
    let msg = res.statusText || ('HTTP ' + res.status);
    try {
      const body = await res.clone().json();
      if (body && body.error) msg = body.error;
    } catch (_) { /* response was not JSON; use statusText */ }
    showFetchError(method + ' ' + url + ': ' + msg);
    throw new Error(msg);
  }
  return res;
}

// Logout via POST. The /logout endpoint is POST-only to defeat CSRF
// logout (someone embedding <img src="...:9090/logout"> in a page
// can't log the user out). On any outcome we navigate to /login so
// the user sees the login form even if the network call hiccupped.
async function doLogout() {
  try {
    await fetch('/logout', { method: 'POST' });
  } catch (_) { /* best-effort; redirect anyway */ }
  window.location.href = '/login';
}

// Minimal HTML-escape for safely rendering user-provided strings in
// dynamically-built innerHTML. Use whenever interpolating values that
// originated from outside the interface (host names, usernames, etc).
function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---------------------------------------------------------------------------
// Panel switching — loads data lazily on first visit
// ---------------------------------------------------------------------------
function showPanel(name, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
  btn.classList.add('active');
  // Hard separation: every entry to Config starts with no sub-tab selected
  if (name === 'config') resetConfigSubTabs();
  if (name === 'config' && !config.processing) loadConfig();
authFetch('/api/auth/me').then(r => r.json()).then(d => { currentUser = d.username || ''; }).catch(() => {});
  if (name === 'hosts' && !hosts.hosts) loadHosts();
  // Hosts tab role comboboxes read the roles datalist — make sure roles are
  // loaded so the picker has suggestions even if the Roles tab wasn't opened.
  if (name === 'hosts' && !roles.roles.length) loadRoles();
  if (name === 'roles' && !roles.roles.length) loadRoles();
  if (name === 'rules' && !rules.length) loadRules();
  if (name === 'anon') loadAnon();
  if (name === 'networks') loadNetworks();
  if (name === 'users') loadUsers();
  if (name === 'lookup') loadLookup();
  // Maintenance tab: lazy-load + start auto-refresh while tab is active
  if (name === 'maintenance') {
    loadMaintenance();
    startMaintenanceRefresh();
  } else {
    stopMaintenanceRefresh();
  }
  // Show scroll buttons on panels that get long
  const scrollPanels = ['hosts', 'roles', 'rules', 'users', 'anon', 'config', 'lookup'];
  const scrollBtns = document.getElementById('scroll-btns');
  if (scrollBtns) scrollBtns.style.display = scrollPanels.includes(name) ? 'flex' : 'none';
  window.scrollTo({top: 0, behavior: 'instant'});
}

// ---------------------------------------------------------------------------
// Config sub-tabs — hard separation: cards render only on explicit choice.
// This interaction pattern is the model for the future multi-tenant selector.
// ---------------------------------------------------------------------------
let activeConfigSubTab = null;

function showConfigSubTab(name, btn) {
  activeConfigSubTab = name;
  document.getElementById('config-sub-src').classList.toggle('active', name === 'src');
  document.getElementById('config-sub-proc').classList.toggle('active', name === 'proc');
  document.getElementById('subtab-btn-src').classList.toggle('active', name === 'src');
  document.getElementById('subtab-btn-proc').classList.toggle('active', name === 'proc');
  document.getElementById('config-subtab-prompt').style.display = 'none';
}

function resetConfigSubTabs() {
  activeConfigSubTab = null;
  ['config-sub-src', 'config-sub-proc'].forEach(id => document.getElementById(id).classList.remove('active'));
  ['subtab-btn-src', 'subtab-btn-proc'].forEach(id => document.getElementById(id).classList.remove('active'));
  document.getElementById('config-subtab-prompt').style.display = 'block';
}

// Config status messages route to the ACTIVE sub-tab's bar (each sub-panel
// carries its own, since duplicate IDs are invalid). Falls back to the
// panel-level bar when no sub-tab is selected.
function activeConfigStatusId() {
  if (activeConfigSubTab === 'src') return 'status-bar-config-src';
  if (activeConfigSubTab === 'proc') return 'status-bar-config-proc';
  return 'status-bar-config';
}

// ---------------------------------------------------------------------------
// Status bar — shows save/error messages per panel
// ---------------------------------------------------------------------------
function showStatus(msg, type, panelId) {
  const id = panelId || 'status-bar';
  const el = document.getElementById(id);
  if (!el) { console.log(msg); return; }
  el.textContent = msg;
  el.className = type;
  el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; }, 4000);
}

// ---------------------------------------------------------------------------
// Config panel — processing, filtering, LLM endpoints, email, paths
// ---------------------------------------------------------------------------
async function loadConfig() {
  const res = await authFetch('/api/config');
  config = await res.json();

  if (config._error) {
    showStatus('[ERR] ' + config._error, 'err', 'status-bar-config');
    document.getElementById('status-bar-config').style.display = 'block';
    return;
  }

  populateConfigFields(config);
}

function populateConfigFields(config) {
  const p = config.processing || {};
  const f = config.filtering || {};
  const e = config.email || {};
  const l = config.llm || {};

  document.getElementById('poll_interval').value = p.poll_interval_seconds ?? 30;
  document.getElementById('max_workers').value = p.max_workers ?? 1;
  document.getElementById('dedup_silence').value = p.dedup_silence_seconds ?? 240;
  document.getElementById('max_batch').value = p.max_batch_size ?? 250;
  document.getElementById('baseline_mult').value = p.baseline_multiplier ?? 2.0;
  document.getElementById('min_baseline_days').value = p.min_baseline_days ?? 3;
  document.getElementById('escalation_mult').value = p.escalation_multiplier ?? 4.0;

  document.getElementById('min_rule_level').value = f.min_rule_level ?? 6;
  document.getElementById('abuse_threshold').value = f.abuse_escalation_threshold ?? 50;
  document.getElementById('escalate_first_seen').checked = f.escalate_first_seen_rule ?? false;
  document.getElementById('frequency_escalation_enabled').checked = f.frequency_escalation_enabled ?? true;
  document.getElementById('first_seen_days').value = f.first_seen_lookback_days ?? 14;

  document.getElementById('smtp_host').value = e.smtp_host ?? '';
  document.getElementById('smtp_port').value = e.smtp_port ?? 587;
  document.getElementById('email_username').value = e.username ?? '';
  document.getElementById('email_password').value = e.password ?? '';
  document.getElementById('email_from').value = e.from_address ?? '';
  document.getElementById('email_to').value = e.to_address ?? '';
  document.getElementById('email_note_addr').value = e.note_address ?? '';
  document.getElementById('min_confidence').value = e.min_confidence_to_email ?? 'MEDIUM';
  document.getElementById('subject_prefix_notify').value = e.subject_prefix_notify || e.subject_prefix || '[jrSOC ALERT]';
  document.getElementById('subject_prefix_note').value = e.subject_prefix_note ?? '[jrSOC NOTE]';
  document.getElementById('email_enabled').checked = e.enabled ?? false;
  // Derive the security mode the same way the backend does: explicit
  // smtp_security wins; absent it, fall back to legacy use_tls (false -> none,
  // otherwise starttls). Keeps an existing use_tls:true config showing STARTTLS.
  const _sec = e.smtp_security ?? (e.use_tls === false ? 'none' : 'starttls');
  const _secEl = document.querySelector('#smtp_security input[value="' + _sec + '"]');
  if (_secEl) _secEl.checked = true;
  document.getElementById('llm_strategy').value = l.strategy ?? 'round_robin';
  document.getElementById('llm_enabled').checked = (l.enabled !== false);

  renderEndpoints(l.endpoints || []);
  loadPathFields(config.paths || {}, config.logging || {});

  // Sources
  const src = config.sources || {};
  const wz = src.wazuh || {};
  document.getElementById('src_wazuh_enabled').checked = wz.enabled !== false;
  document.getElementById('src_wazuh_file').value      = wz.alerts_file || '';
  const zk = src.zeek || {};
  document.getElementById('src_zeek_enabled').checked  = zk.enabled !== false;
  // Prefer new fields, fall back to legacy log_dir for backward compat
  document.getElementById('src_zeek_current_dir').value = zk.current_log_dir || zk.log_dir || '';
  document.getElementById('src_zeek_archive_dir').value = zk.archive_log_dir ?? '';
  const gl = src.graylog || {};
  const glAuth = gl.auth || {};
  document.getElementById('src_graylog_enabled').checked    = gl.enabled || false;
  document.getElementById('src_graylog_verify_ssl').checked = gl.verify_ssl !== false;
  document.getElementById('src_graylog_endpoint').value     = gl.endpoint || '';
  document.getElementById('src_graylog_window').value       = gl.context_window_minutes ?? 0.5;
  document.getElementById('src_graylog_max').value          = gl.max_results ?? 100;
  document.getElementById('src_graylog_user').value         = glAuth.username || '';
  document.getElementById('src_graylog_pass').value         = glAuth.password || '';

  // GELF output (output.graylog) — separate from the input Graylog above
  const outGl = (config.output || {}).graylog || {};
  document.getElementById('out_graylog_enabled').checked = outGl.enabled ?? false;
  document.getElementById('out_graylog_host').value      = outGl.host || '';
  document.getElementById('out_graylog_port').value      = outGl.port ?? 12201;

  const nt = src.ntopng || {};
  const ntAuth = nt.auth || {};
  document.getElementById('src_ntopng_enabled').checked = nt.enabled ?? false;
  document.getElementById('src_ntopng_endpoint').value  = nt.endpoint || '';
  // ifid 0 is a VALID interface id — ntopng assigns ids by position in its
  // own interface list, and 0 is an ordinary value. `||` treats 0 as falsy and would silently display a
  // saved 0 as the default, and a subsequent save would then write that
  // wrong value back to config. `??` only falls back on null/undefined.
  document.getElementById('src_ntopng_ifid').value      = nt.ifid ?? 0;
  document.getElementById('src_ntopng_user').value      = ntAuth.username || '';
  document.getElementById('src_ntopng_pass').value      = ntAuth.password || '';
  document.getElementById('src_ntopng_verify_ssl').checked = nt.verify_ssl !== false;

  // Deployment identity (jrsoc_org / jrsoc_security_domain → GELF fields)
  const deploy = config.deployment || {};
  document.getElementById('deploy_org').value = deploy.org || '';
  document.getElementById('deploy_security_domain').value = deploy.security_domain || '';

  // Timezone — fallback to browser's local TZ if config has no timezone
  // section at all. Normal case: the merge from server fills in the host's
  // detected TZ before this code runs, so these fallbacks rarely fire.
  const tz = config.timezone || {};
  const browserOffsetHours = -(new Date().getTimezoneOffset() / 60);
  document.getElementById('tz_offset').value = tz.zeek_local_tz_offset !== undefined ? tz.zeek_local_tz_offset : browserOffsetHours;
  document.getElementById('tz_name').value   = tz.zeek_local_tz_name || 'local';

  // Always include
  const ai = f.always_include || {};
  document.getElementById('always_include_networks').value = (ai.networks ?? []).join('\\n');
  document.getElementById('always_include_hosts').value    = (ai.hosts    || []).join('\\n');

  // Enrichment
  const enr = config.enrichment || {};
  document.getElementById('enr_host_lookup').checked    = enr.enable_host_lookup !== false;
  document.getElementById('enr_network_lookup').checked = enr.enable_network_lookup !== false;
  const geo = enr.geo_ip || {};
  document.getElementById('geo_enabled').checked        = geo.enabled !== false;
  document.getElementById('geo_skip_private').checked   = geo.skip_private !== false;
  const whois = enr.whois || {};
  document.getElementById('whois_enabled').checked      = whois.enabled !== false;
  document.getElementById('whois_skip_private').checked = whois.skip_private !== false;
  const rdns = enr.rdns || {};
  document.getElementById('rdns_enabled').checked       = rdns.enabled !== false;
  document.getElementById('rdns_skip_private').checked  = rdns.skip_private || false;
  const abuse = enr.abuseipdb || {};
  document.getElementById('abuse_enabled').checked       = abuse.enabled || false;
  document.getElementById('abuse_skip_private').checked  = abuse.skip_private !== false;
  document.getElementById('abuse_api_key').value         = abuse.api_key || '';
  document.getElementById('abuse_annotate_threshold').value = abuse.score_threshold ?? 25;
  const kev = enr.cisa_kev || {};
  document.getElementById('kev_enabled').checked          = kev.enabled || false;
  const gn = enr.greynoise || {};
  document.getElementById('greynoise_enabled').checked             = gn.enabled || false;
  document.getElementById('greynoise_skip_private').checked        = gn.skip_private !== false;
  document.getElementById('greynoise_rate_limit_warnings').checked = gn.rate_limit_warnings !== false;
  document.getElementById('greynoise_api_key').value               = gn.api_key || '';
  const epss = enr.epss || {};
  document.getElementById('epss_enabled').checked         = epss.enabled || false;
  const vt = enr.virustotal || {};
  document.getElementById('vt_enabled').checked             = vt.enabled || false;
  document.getElementById('vt_skip_private').checked        = vt.skip_private !== false;
  document.getElementById('vt_rate_limit_warnings').checked = vt.rate_limit_warnings === true;
  document.getElementById('vt_api_key').value               = vt.api_key || '';
  // ?? not || (the ifid lesson): a cap of small integers must load
  // faithfully; || would be safe here only by accident of min="1".
  document.getElementById('vt_per_alert_cap').value         = vt.per_alert_cap ?? 4;
  const otx = enr.otx || {};
  document.getElementById('otx_enabled').checked             = otx.enabled || false;
  document.getElementById('otx_skip_private').checked        = otx.skip_private !== false;
  document.getElementById('otx_rate_limit_warnings').checked = otx.rate_limit_warnings === true;
  document.getElementById('otx_api_key').value               = otx.api_key || '';

  const pc = config.prompt_customization || {};
  document.getElementById('prompt_sensor_context').value = (pc.sensor_context ?? []).join('\\n');
  document.getElementById('prompt_triage_guidance').value = (pc.triage_guidance ?? []).join('\\n');
  document.getElementById('prompt_network_notes').value   = (pc.network_notes  || []).join('\\n');
  // strip_redundant_fields: default true if missing or non-boolean. Treat
  // explicit false as the only off state — anything else means abridge.
  document.getElementById('prompt_strip_redundant_fields').checked = pc.strip_redundant_fields !== false;

  // Logging
  const lg = config.logging || {};
  document.getElementById('log_prompt_mode').value        = lg.prompt_log_mode || 'anonymized';
  document.getElementById('log_debug_llm_payload').checked = lg.debug_llm_payload ?? false;
  // Debug-logging toggle reflects logging.level. Only info/debug are
  // exposed in the UI; a hand-set warning/error level shows as
  // unchecked and will be normalized to info on the next save.
  document.getElementById('obs_debug_logging').checked = (lg.level || 'info').toLowerCase() === 'debug';

  // Observability
  // lag_log_interval_seconds: 0 disables emission. Default to 30 in
  // the UI when missing from config — matches the doctrinally
  // recommended value. The actual code respects 0 / missing as
  // disabled, so showing 30 here doesn't activate anything until
  // the user saves.
  const obs = config.observability || {};
  document.getElementById('obs_lag_log_interval_seconds').value = obs.lag_log_interval_seconds ?? 30;

  // Database. enabled defaults TRUE (stateful) — a config with no
  // database section, or no enabled key, shows the toggle ON, which
  // matches database.enabled's default in get_connection(). Only an
  // explicit false turns it off.
  const db = config.database || {};
  document.getElementById('db_enabled').checked = db.enabled !== false;

  // Wazuh API card lives on the Hosts tab but reads from config.json's
  // top-level wazuh_api block, so populate it here when config loads.
  populateWazuhApi(config);
}
let currentEndpoints = [];

function addEndpoint(type) {
  const defaults = {
    ollama:   { name: 'new-ollama', type: 'ollama', model: 'gemma4:26b', url: 'http://127.0.0.1:11434', enabled: true, priority: currentEndpoints.length + 1, timeout_seconds: 60, keep_alive: -1, anonymize: false, max_concurrent: 1 },
    gemini:   { name: 'gemini-2.5-flash', type: 'gemini', model: 'gemini-2.5-flash', api_key: '', enabled: true, priority: currentEndpoints.length + 1, timeout_seconds: 60, anonymize: true, max_concurrent: 3 },
    llamacpp: { name: 'new-llamacpp', type: 'llamacpp', model: 'gemma4:26b', url: 'http://127.0.0.1:8080', enabled: true, priority: currentEndpoints.length + 1, timeout_seconds: 60, anonymize: false },
    openai:     { name: 'gpt-4o', type: 'openai', model: 'gpt-4o', api_key: '', enabled: true, priority: currentEndpoints.length + 1, timeout_seconds: 60, anonymize: true, max_concurrent: 2 },
    anthropic:  { name: 'claude-haiku', type: 'anthropic', model: 'claude-haiku-4-5', api_key: '', enabled: true, priority: currentEndpoints.length + 1, timeout_seconds: 60, anonymize: true, max_concurrent: 3 },
  };
  currentEndpoints.push(defaults[type] || defaults.ollama);
  renderEndpoints(currentEndpoints);
}

function removeEndpoint(i) {
  if (!confirm('Remove this endpoint?')) return;
  currentEndpoints.splice(i, 1);
  renderEndpoints(currentEndpoints);
}

function renderEndpoints(endpoints) {
  currentEndpoints = endpoints;
  const container = document.getElementById('endpoints-container');
  container.innerHTML = '';
  endpoints.forEach((ep, i) => {
    const type = ep.type || 'ollama';
    const badgeClass = 'ep-' + type.toLowerCase();
    container.innerHTML += `
    <div class="endpoint-card">
      <div class="ep-header">
        <span class="ep-type-badge ${escapeHtml(badgeClass)}">${escapeHtml(type.toUpperCase())}</span>
        <strong style="font-size:14px">${escapeHtml(ep.name || 'endpoint-' + i)}</strong>
        <button class="btn btn-red" style="font-size:10px;padding:3px 10px;margin-left:auto;margin-right:12px" onclick="removeEndpoint(${i})">Remove</button>
        <label class="toggle">
          <input type="checkbox" id="ep_enabled_${i}" ${ep.enabled !== false ? 'checked' : ''}>
          <span class="toggle-slider"></span>
        </label>
        <label for="ep_enabled_${i}" style="font-size:12px;color:var(--textdim)">Enabled</label>
      </div>
      <div class="grid2">
        <div class="field">
          <label>Name</label>
          <input type="text" id="ep_name_${i}" value="${escapeHtml(ep.name || '')}">
        </div>
        <div class="field">
          <label>Type</label>
          <select id="ep_type_${i}">
            <option value="ollama" ${type==='ollama'?'selected':''}>Ollama</option>
            <option value="gemini" ${type==='gemini'?'selected':''}>Gemini</option>
            <option value="openai" ${type==='openai'?'selected':''}>OpenAI</option>
            <option value="anthropic" ${type==='anthropic'?'selected':''}>Anthropic</option>
            <option value="llamacpp" ${type==='llamacpp'?'selected':''}>llama.cpp</option>
          </select>
        </div>
      </div>
      <div class="grid2">
        <div class="field">
          <label>Model</label>
          <input type="text" id="ep_model_${i}" value="${escapeHtml(ep.model || '')}">
        </div>
        <div class="field">
          <label>${(type==='gemini'||type==='openai'||type==='anthropic') ? 'API Key' : 'URL'}</label>
          <input type="${(type==='gemini'||type==='openai'||type==='anthropic')?'password':'text'}" id="ep_url_${i}" value="${escapeHtml((type==='gemini'||type==='openai'||type==='anthropic') ? (ep.api_key||'') : (ep.url||''))}">
        </div>
      </div>
      <div class="grid3">
        <div class="field">
          <label>Priority</label>
          <input type="number" id="ep_priority_${i}" value="${escapeHtml(ep.priority ?? i+1)}" min="1" max="10">
        </div>
        <div class="field">
          <label>Timeout (seconds)</label>
          <input type="number" id="ep_timeout_${i}" value="${escapeHtml(ep.timeout_seconds ?? 60)}" min="5" max="300">
        </div>
        <div class="field">
          <label>Max Concurrent</label>
          <div class="hint" style="font-size:10px">API rate limit throttle</div>
          <input type="number" id="ep_concurrent_${i}" value="${escapeHtml(ep.max_concurrent ?? 1)}" min="1" max="20">
        </div>
      </div>
      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="ep_anon_${i}" ${ep.anonymize ? 'checked' : ''}>
        <span class="toggle-slider"></span></label>
        <label>Anonymize prompts sent to cloud endpoint</label>
      </div>
    </div>`;
  });
  // Store endpoint count for save
  container.dataset.count = endpoints.length;
}

async function generatePaths() {
  const res = await authFetch('/api/genpaths');
  const paths = await res.json();
  document.getElementById('path_hosts').value = paths.hosts_file ?? '';
  document.getElementById('path_rules').value = paths.rules_file ?? '';
  document.getElementById('path_db').value = paths.db_file ?? '';
  document.getElementById('path_users').value = paths.users_file ?? '';
  document.getElementById('path_domain').value = paths.domain_file ?? '';
  document.getElementById('path_anon').value = paths.anonymization_file ?? '';
  document.getElementById('path_ipaliases').value = paths.ip_aliases_file ?? '';
  document.getElementById('path_position').value = paths.position_file ?? '';
  document.getElementById('path_log').value = paths.log_file ?? '';
  showStatus('[OK] Paths generated - click Save Config to apply', 'info', activeConfigStatusId());
}

function clearPaths() {
  ['path_hosts','path_rules','path_db','path_users','path_domain','path_anon','path_ipaliases','path_position','path_log']
    .forEach(id => document.getElementById(id).value = '');
  showStatus('[OK] Paths cleared', 'info', activeConfigStatusId());
}

function loadPathFields(paths, logging) {
  paths = paths || {};
  logging = logging || {};
  document.getElementById('path_hosts').value = paths.hosts_file ?? '';
  document.getElementById('path_rules').value = paths.rules_file ?? '';
  document.getElementById('path_db').value = paths.db_file ?? '';
  document.getElementById('path_users').value = paths.users_file ?? '';
  document.getElementById('path_domain').value = paths.domain_file ?? '';
  document.getElementById('path_anon').value = paths.anonymization_file ?? '';
  document.getElementById('path_ipaliases').value = paths.ip_aliases_file ?? '';
  document.getElementById('path_position').value = paths.position_file ?? '';
  // log_file lives under logging.log_file in config, NOT paths.log_file
  document.getElementById('path_log').value = logging.log_file ?? '';
}

async function loadDefaults() {
  if (!confirm('Load default config template? This resets the ENTIRE config.json to defaults - the fields on BOTH sub-tabs, AND the Wazuh API settings shown on the Hosts tab. The defaults are generic placeholders; many settings (endpoints, paths, keys, email) will not work until edited for your environment. Nothing is written until you click Save Config.')) return;
  const res = await authFetch('/api/config/default');
  config = await res.json();
  populateConfigFields(config);
  showStatus('[OK] Defaults loaded - review and click Save Config', 'info', activeConfigStatusId());
}

async function saveConfig() {
  const epCount = currentEndpoints.length;
  const endpoints = [];
  for (let i = 0; i < epCount; i++) {
    const type = document.getElementById(`ep_type_${i}`)?.value || 'ollama';
    const ep = {
      name: document.getElementById(`ep_name_${i}`)?.value,
      type: type,
      model: document.getElementById(`ep_model_${i}`)?.value,
      enabled: document.getElementById(`ep_enabled_${i}`)?.checked,
      priority: parseInt(document.getElementById(`ep_priority_${i}`)?.value || 1),
      timeout_seconds: parseInt(document.getElementById(`ep_timeout_${i}`)?.value || 60),
      max_concurrent: parseInt(document.getElementById(`ep_concurrent_${i}`)?.value || 1),
      anonymize: document.getElementById(`ep_anon_${i}`)?.checked || false,
    };
    if (['gemini','openai','anthropic'].includes(type)) {
      ep.api_key = document.getElementById(`ep_url_${i}`)?.value;
    } else {
      ep.url = document.getElementById(`ep_url_${i}`)?.value;
      ep.keep_alive = -1;
    }
    endpoints.push(ep);
  }

  config.processing = {
    poll_interval_seconds: parseInt(document.getElementById('poll_interval').value),
    max_workers: parseInt(document.getElementById('max_workers').value || 1),
    dedup_silence_seconds: parseInt(document.getElementById('dedup_silence').value),
    max_batch_size: parseInt(document.getElementById('max_batch').value),
    baseline_multiplier: parseFloat(document.getElementById('baseline_mult').value),
    min_baseline_days: parseInt(document.getElementById('min_baseline_days').value),
    escalation_multiplier: parseFloat(document.getElementById('escalation_mult').value),
  };
  const _smtpSec = (document.querySelector('#smtp_security input:checked') || {}).value || 'starttls';
  config.email = {
    ...config.email,
    enabled: document.getElementById('email_enabled').checked,
    smtp_host: document.getElementById('smtp_host').value,
    smtp_port: parseInt(document.getElementById('smtp_port').value),
    smtp_security: _smtpSec,
    use_tls: _smtpSec !== 'none',
    username: document.getElementById('email_username').value,
    password: document.getElementById('email_password').value,
    from_address: document.getElementById('email_from').value,
    to_address: document.getElementById('email_to').value,
    note_address: document.getElementById('email_note_addr').value,
    min_confidence_to_email: document.getElementById('min_confidence').value,
    subject_prefix_notify: document.getElementById('subject_prefix_notify').value,
    subject_prefix_note: document.getElementById('subject_prefix_note').value,
    subject_prefix: document.getElementById('subject_prefix_notify').value,
  };
  config.llm = {
    ...config.llm,
    enabled: document.getElementById('llm_enabled').checked,
    strategy: document.getElementById('llm_strategy').value,
    endpoints
  };

  // Build paths section — only include non-empty values
  const pathFields = {
    hosts_file:         document.getElementById('path_hosts').value,
    rules_file:         document.getElementById('path_rules').value,
    db_file:            document.getElementById('path_db').value,
    users_file:         document.getElementById('path_users').value,
    domain_file:        document.getElementById('path_domain').value,
    anonymization_file: document.getElementById('path_anon').value,
    ip_aliases_file:    document.getElementById('path_ipaliases').value,
    position_file:      document.getElementById('path_position').value,
  };
  const logFile = document.getElementById('path_log').value;
  config.paths = Object.fromEntries(Object.entries(pathFields).filter(([k,v]) => v.trim()));
  if (logFile.trim()) config.logging = { ...config.logging, log_file: logFile };

  const splitLines = id => document.getElementById(id).value.split('\\n').map(s=>s.trim()).filter(Boolean);
  config.prompt_customization = {
    ...(config.prompt_customization || {}),
    sensor_context:  splitLines('prompt_sensor_context'),
    triage_guidance: splitLines('prompt_triage_guidance'),
    network_notes:   splitLines('prompt_network_notes'),
    strip_redundant_fields: document.getElementById('prompt_strip_redundant_fields').checked,
  };

  // Logging
  config.logging = {
    ...(config.logging || {}),
    prompt_log_mode:   document.getElementById('log_prompt_mode').value,
    debug_llm_payload: document.getElementById('log_debug_llm_payload').checked,
    level:             document.getElementById('obs_debug_logging').checked ? 'debug' : 'info',
  };

  // Observability
  // Parse as integer; clamp to >= 0 server-side. Empty / NaN
  // falls through to 0 (disabled), which is the safer-fail value
  // than silently defaulting to 30 — operator who explicitly
  // clears the field probably means "off."
  const lagIntervalRaw = document.getElementById('obs_lag_log_interval_seconds').value;
  const lagInterval = parseInt(lagIntervalRaw, 10);
  config.observability = {
    ...(config.observability || {}),
    lag_log_interval_seconds: (isNaN(lagInterval) || lagInterval < 0) ? 0 : lagInterval,
  };

  // Database on/off. Plain boolean from the toggle; preserves any
  // other keys a future version might add under database.
  config.database = {
    ...(config.database || {}),
    enabled: document.getElementById('db_enabled').checked,
  };

  // Sources
  config.sources = {
    ...(config.sources || {}),
    wazuh: {
      ...((config.sources || {}).wazuh || {}),
      enabled: document.getElementById('src_wazuh_enabled').checked,
      alerts_file: document.getElementById('src_wazuh_file').value,
    },
    zeek: {
      ...((config.sources || {}).zeek || {}),
      enabled: document.getElementById('src_zeek_enabled').checked,
      current_log_dir: document.getElementById('src_zeek_current_dir').value,
      archive_log_dir: document.getElementById('src_zeek_archive_dir').value,
      log_dir: undefined,  // drop legacy field on save - new fields are authoritative
    },
    graylog: {
      ...((config.sources || {}).graylog || {}),
      enabled: document.getElementById('src_graylog_enabled').checked,
      verify_ssl: document.getElementById('src_graylog_verify_ssl').checked,
      endpoint: document.getElementById('src_graylog_endpoint').value,
      context_window_minutes: parseFloat(document.getElementById('src_graylog_window').value || 0.5),
      max_results: parseInt(document.getElementById('src_graylog_max').value || 100),
      auth: {
        username: document.getElementById('src_graylog_user').value,
        password: document.getElementById('src_graylog_pass').value,
      },
    },
    ntopng: {
      ...((config.sources || {}).ntopng || {}),
      enabled: document.getElementById('src_ntopng_enabled').checked,
      endpoint: document.getElementById('src_ntopng_endpoint').value,
      // ifid 0 is valid — do not use `||` (0 is falsy in JS and would be
      // rewritten to the fallback). Empty field -> parseInt gives NaN, so
      // fall back explicitly rather than writing NaN into config.
      ifid: (() => {
        const v = parseInt(document.getElementById('src_ntopng_ifid').value, 10);
        return Number.isInteger(v) ? v : 0;
      })(),
      verify_ssl: document.getElementById('src_ntopng_verify_ssl').checked,
      auth: {
        username: document.getElementById('src_ntopng_user').value,
        password: document.getElementById('src_ntopng_pass').value,
      },
    },
  };

  // GELF output (output.graylog) — preserves any keys set elsewhere on save
  config.output = {
    ...(config.output || {}),
    graylog: {
      ...((config.output || {}).graylog || {}),
      enabled: document.getElementById('out_graylog_enabled').checked,
      host: document.getElementById('out_graylog_host').value,
      port: parseInt(document.getElementById('out_graylog_port').value || 12201),
    },
  };

  // Deployment identity (jrsoc_org / jrsoc_security_domain → GELF fields)
  config.deployment = {
    ...(config.deployment || {}),
    org: document.getElementById('deploy_org').value,
    security_domain: document.getElementById('deploy_security_domain').value,
  };

  // Timezone
  config.timezone = {
    zeek_local_tz_offset: parseInt(document.getElementById('tz_offset').value),
    zeek_local_tz_name: document.getElementById('tz_name').value,
  };

  // Always include
  config.filtering = {
    ...(config.filtering || {}),
    min_rule_level: parseInt(document.getElementById('min_rule_level').value),
    abuse_escalation_threshold: parseInt(document.getElementById('abuse_threshold').value),
    escalate_first_seen_rule: document.getElementById('escalate_first_seen').checked,
    frequency_escalation_enabled: document.getElementById('frequency_escalation_enabled').checked,
    first_seen_lookback_days: parseInt(document.getElementById('first_seen_days').value),
    always_include: {
      networks: splitLines('always_include_networks'),
      hosts:    splitLines('always_include_hosts'),
    },
  };

  // Enrichment
  config.enrichment = {
    ...(config.enrichment || {}),
    enable_host_lookup:    document.getElementById('enr_host_lookup').checked,
    enable_network_lookup: document.getElementById('enr_network_lookup').checked,
    geo_ip: {
      ...((config.enrichment || {}).geo_ip || {}),
      enabled:      document.getElementById('geo_enabled').checked,
      skip_private: document.getElementById('geo_skip_private').checked,
    },
    whois: {
      ...((config.enrichment || {}).whois || {}),
      enabled:      document.getElementById('whois_enabled').checked,
      skip_private: document.getElementById('whois_skip_private').checked,
    },
    rdns: {
      ...((config.enrichment || {}).rdns || {}),
      enabled:      document.getElementById('rdns_enabled').checked,
      skip_private: document.getElementById('rdns_skip_private').checked,
    },
    abuseipdb: {
      ...((config.enrichment || {}).abuseipdb || {}),
      enabled:         document.getElementById('abuse_enabled').checked,
      skip_private:    document.getElementById('abuse_skip_private').checked,
      api_key:         document.getElementById('abuse_api_key').value,
      score_threshold: parseInt(document.getElementById('abuse_annotate_threshold').value || 25),
    },
    cisa_kev: {
      ...((config.enrichment || {}).cisa_kev || {}),
      enabled: document.getElementById('kev_enabled').checked,
    },
    greynoise: {
      ...((config.enrichment || {}).greynoise || {}),
      enabled:             document.getElementById('greynoise_enabled').checked,
      skip_private:        document.getElementById('greynoise_skip_private').checked,
      api_key:             document.getElementById('greynoise_api_key').value,
      rate_limit_warnings: document.getElementById('greynoise_rate_limit_warnings').checked,
    },
    epss: {
      ...((config.enrichment || {}).epss || {}),
      enabled: document.getElementById('epss_enabled').checked,
    },
    virustotal: {
      ...((config.enrichment || {}).virustotal || {}),
      enabled:             document.getElementById('vt_enabled').checked,
      skip_private:        document.getElementById('vt_skip_private').checked,
      api_key:             document.getElementById('vt_api_key').value,
      rate_limit_warnings: document.getElementById('vt_rate_limit_warnings').checked,
      per_alert_cap:       (() => {
        const v = parseInt(document.getElementById('vt_per_alert_cap').value, 10);
        return (Number.isInteger(v) && v >= 1) ? v : 4;
      })(),
    },
    otx: {
      ...((config.enrichment || {}).otx || {}),
      enabled:             document.getElementById('otx_enabled').checked,
      skip_private:        document.getElementById('otx_skip_private').checked,
      api_key:             document.getElementById('otx_api_key').value,
      rate_limit_warnings: document.getElementById('otx_rate_limit_warnings').checked,
    },
  };

  const res = await authFetch('/api/config', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(config) });
  const data = await res.json();
  showStatus(data.ok ? '[OK] Saved' : '[ERR] ' + data.error, data.ok ? 'ok' : 'err', activeConfigStatusId());
}

// ---------------------------------------------------------------------------
// Hosts panel — host inventory with notes and anonymization aliases
// ---------------------------------------------------------------------------
async function loadHosts() {
  const res = await authFetch('/api/hosts');
  hosts = await res.json();
  renderHosts();
  // Populate the Wazuh API card (top of this tab). It reads config.json's
  // wazuh_api block, so make sure config is loaded first — if the operator
  // lands on the Hosts tab before ever opening the Config tab, config may
  // not be populated yet.
  if (!config.processing) { await loadConfig(); }
  else { populateWazuhApi(config); }
}

async function loadNetworks() {
  if (!hosts.hosts) {
    const res = await authFetch('/api/hosts');
    hosts = await res.json();
  }
  renderNetworks();
}

async function saveNetworks() {
  const netCount = (hosts.networks || []).length;
  hosts.networks = [];
  for (let i = 0; i < netCount; i++) {
    hosts.networks.push({
      cidr: document.getElementById(`n_cidr_${i}`)?.value || '',
      name: document.getElementById(`n_name_${i}`)?.value || '',
      role: document.getElementById(`n_role_${i}`)?.value || '',
    });
  }
  const res = await authFetch('/api/hosts', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(hosts) });
  const data = await res.json();
  showStatus(data.ok ? '[OK] Networks saved' : '[ERR] ' + data.error, data.ok ? 'ok' : 'err', 'status-bar');
}

function renderHosts() {
  const container = document.getElementById('hosts-container');
  container.innerHTML = '';
  // Sort the host array alphabetically by name (case-insensitive) before
  // rendering. We sort the ARRAY (not just the display) on purpose: renderHosts
  // and saveHosts share the array index (h_name_${i} etc.), so display order and
  // array order must stay aligned — sorting the array keeps them consistent and
  // also writes hosts.json in sorted order on the next save (easier to scan and
  // diff). Sort is stable and only reorders entries; no host data changes.
  (hosts.hosts || []).sort((a, b) =>
    (a.name || '').toLowerCase().localeCompare((b.name || '').toLowerCase()));
  (hosts.hosts || []).forEach((h, i) => {
    container.innerHTML += `
    <div class="card" id="host-card-${i}">
      <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
        <span>${escapeHtml(h.name || 'New Host')}</span>
        <button class="btn btn-red" style="font-size:10px;padding:3px 10px" onclick="removeHost(${i})">Remove</button>
      </div>
      <div class="grid3">
        <div class="field"><label>Name</label><input type="text" id="h_name_${i}" value="${escapeHtml(h.name||'')}"></div>
        <div class="field"><label>OS</label><input type="text" id="h_os_${i}" value="${escapeHtml(h.os||'')}"></div>
        <div class="field"><label>VLAN</label><input type="number" id="h_vlan_${i}" value="${escapeHtml(h.vlan||'')}"></div>
      </div>
      <div class="field">
        <label>Roles <span style="color:var(--textdim);font-size:10px;font-weight:400">(pick an existing role or type a new one — new roles are created on save. A host can have several.)</span></label>
        <div id="h_roles_${i}"></div>
        <button type="button" class="btn btn-dim" style="font-size:10px;padding:3px 10px;margin-top:4px" onclick="addHostRole(${i})">+ Add Role</button>
      </div>
      <div class="grid2">
        <div class="field"><label>Static IP <span style="color:var(--textdim);font-size:10px;font-weight:400">(if no DNS — comma-separate multiple e.g. LAN + VPN)</span></label><input type="text" id="h_ip_${i}" value="${escapeHtml(Array.isArray(h.identifiers?.ip) ? h.identifiers.ip.join(', ') : (h.identifiers?.ip || ''))}"></div>
        <div class="field"><label>Anonymization Alias</label><div class="hint">Leave blank to auto-generate</div><input type="text" id="h_alias_${i}" value="${escapeHtml(h.alias||'')}"></div>
      </div>
      <div class="field"><label>Tags <span style="color:var(--textdim);font-size:10px;font-weight:400">(comma separated — known: auto_updates, untrusted, critical, transit, domain_joined, dmz. Custom tags pass through to the prompt as-is.)</span></label><input type="text" id="h_tags_${i}" value="${escapeHtml((h.tags||[]).join(', '))}"></div>
      <div class="field"><label>Notes</label><textarea id="h_notes_${i}">${escapeHtml(h.notes||'')}</textarea></div>
    </div>`;
  });
  // After cards exist in the DOM, render each host's role combobox rows.
  (hosts.hosts || []).forEach((h, i) => renderHostRoles(i, h.role));
}

// Render the per-host role rows: one combobox (text + shared datalist) per
// role, with a Del button. Accepts role as string, list, or empty.
function renderHostRoles(hostIdx, role) {
  const wrap = document.getElementById(`h_roles_${hostIdx}`);
  if (!wrap) return;
  let list = [];
  if (Array.isArray(role)) list = role.filter(r => typeof r === 'string');
  else if (typeof role === 'string' && role.trim()) list = [role];
  if (list.length === 0) list = [''];  // always show at least one empty row
  wrap.innerHTML = list.map((r, j) => `
    <div style="display:flex;gap:6px;margin-bottom:4px" data-role-row="${j}">
      <input type="text" list="roles-datalist" id="h_role_${hostIdx}_${j}" value="${escapeHtml(r)}" placeholder="role name" style="flex:1">
      <button type="button" class="btn btn-red" style="font-size:10px;padding:3px 10px" onclick="removeHostRole(${hostIdx}, ${j})">Del</button>
    </div>`).join('');
}

// Read the current role-row values back out of the DOM for a host.
function collectHostRoles(hostIdx) {
  const wrap = document.getElementById(`h_roles_${hostIdx}`);
  if (!wrap) return [];
  return Array.from(wrap.querySelectorAll('input'))
    .map(inp => inp.value.trim())
    .filter(Boolean);
}

function addHostRole(hostIdx) {
  // Preserve what's typed, append an empty row, re-render.
  const current = collectHostRoles(hostIdx);
  current.push('');
  renderHostRoles(hostIdx, current);
}

function removeHostRole(hostIdx, j) {
  const current = collectHostRoles(hostIdx);
  current.splice(j, 1);
  renderHostRoles(hostIdx, current.length ? current : ['']);
}

function renderNetworks() {
  const container = document.getElementById('networks-container');
  container.innerHTML = '';
  (hosts.networks || []).forEach((n, i) => {
    const card = document.createElement('div');
    card.className = 'card';
    card.style.marginBottom = '12px';
    card.innerHTML = `
      <div class="grid3">
        <div class="field"><label>CIDR</label>
          <input type="text" id="n_cidr_${i}" value="${escapeHtml(n.cidr||'')}" placeholder="192.168.10.0/24"></div>
        <div class="field"><label>Name</label>
          <input type="text" id="n_name_${i}" value="${escapeHtml(n.name||'')}" placeholder="vlan10"></div>
        <div class="field"><label>Role</label>
          <input type="text" id="n_role_${i}" value="${escapeHtml(n.role||'')}" placeholder="clients"></div>
      </div>
      <div style="text-align:right;margin-top:8px">
        <button class="btn btn-red" style="font-size:10px;padding:3px 10px" onclick="removeNetwork(${i})">Remove</button>
      </div>`;
    container.appendChild(card);
  });
}

function addNetwork() {
  hosts.networks = hosts.networks || [];
  hosts.networks.push({ cidr: '', name: '', role: '' });
  renderNetworks();
}

function removeNetwork(i) {
  if (!confirm('Remove this network?')) return;
  hosts.networks.splice(i, 1);
  renderNetworks();
}

function addHost() {
  hosts.hosts = hosts.hosts || [];
  hosts.hosts.push({ name: '', os: '', role: '', vlan: 10, tags: [], notes: '', alias: '' });
  renderHosts();
  document.getElementById(`host-card-${hosts.hosts.length - 1}`).scrollIntoView({ behavior: 'smooth' });
}

function removeHost(i) {
  if (!confirm('Remove this host?')) return;
  hosts.hosts.splice(i, 1);
  renderHosts();
}

async function saveHosts() {
  const count = (hosts.hosts || []).length;
  hosts.hosts = [];
  for (let i = 0; i < count; i++) {
    const ipRaw = document.getElementById(`h_ip_${i}`)?.value?.trim();
    // Parse comma-separated IPs into a list. Save as a single string
    // when there is only one (keeps hosts.json clean for the common case);
    // save as a list when there are multiple (e.g., a host with both LAN
    // and VPN addresses).
    const ipList = (ipRaw || '').split(',').map(s => s.trim()).filter(Boolean);
    const tags = document.getElementById(`h_tags_${i}`)?.value?.split(',').map(t => t.trim()).filter(Boolean);
    // Collect the host's role rows. Save as a single string when there is
    // one (keeps hosts.json clean for the common single-role case), as a
    // list when there are several (multi-role host) — same convention as IP.
    const roleList = collectHostRoles(i);
    const h = {
      name: document.getElementById(`h_name_${i}`)?.value,
      os: document.getElementById(`h_os_${i}`)?.value,
      vlan: parseInt(document.getElementById(`h_vlan_${i}`)?.value || 10),
      tags: tags || [],
      notes: document.getElementById(`h_notes_${i}`)?.value,
      alias: document.getElementById(`h_alias_${i}`)?.value,
    };
    if (roleList.length === 1) {
      h.role = roleList[0];
    } else if (roleList.length > 1) {
      h.role = roleList;
    }
    if (ipList.length === 1) {
      h.identifiers = { ip: ipList[0] };
    } else if (ipList.length > 1) {
      h.identifiers = { ip: ipList };
    }
    hosts.hosts.push(h);
  }
  const res = await authFetch('/api/hosts', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(hosts) });
  const data = await res.json();
  // Both Hosts-tab save buttons ("Save Hosts" and the Wazuh card's "Save
  // Wazuh Settings") save BOTH the host inventory (hosts.json) AND the Wazuh
  // API connection block (config.json). The two live in different files, so
  // saving both on either click prevents the silent-loss footgun where an
  // operator edits both areas but only clicks one button.
  const wzOk = await saveWazuhApi();
  const bothOk = data.ok && wzOk;
  const msg = bothOk ? '[OK] Saved'
            : !data.ok ? '[ERR] ' + data.error
            : '[ERR] hosts saved but Wazuh API settings failed';
  showStatus(msg, bothOk ? 'ok' : 'err', 'status-bar');
  // Saving hosts may have auto-stubbed new roles server-side; refresh the
  // role list + datalist so the Roles tab and the host comboboxes reflect them.
  if (data.ok) {
    loadRoles();
    // Nudge the operator to give the new role(s) context — a blank role
    // contributes nothing to triage until its description/notes are filled.
    if (data.new_roles && data.new_roles.length) {
      const names = data.new_roles.join(', ');
      const plural = data.new_roles.length > 1 ? 's' : '';
      alert(`Created new role${plural}: ${names}\n\nOpen the Roles tab to add ${data.new_roles.length > 1 ? 'their' : 'its'} description and notes so it provides context to triage. Until then ${data.new_roles.length > 1 ? 'they show' : 'it shows'} as "New".`);
    }
  }
}

// Persist the Wazuh API card (top of the Hosts tab) into config.json's
// top-level `wazuh_api` block. Returns true on success, false on failure.
// Uses the wholesale /api/config write (the server writes the full posted
// config), so we read the current global `config`, update only the
// `wazuh_api` block from the card fields, and post the whole object back —
// nothing else in config.json is disturbed. `config` is page-global and
// loaded at init (loadConfig() runs on page load), so it's populated here
// even though this card lives on the Hosts tab.
async function saveWazuhApi() {
  try {
    config.wazuh_api = {
      ...(config.wazuh_api || {}),
      url:        document.getElementById('wazuh_api_url').value.trim(),
      username:   document.getElementById('wazuh_api_user').value,
      password:   document.getElementById('wazuh_api_pass').value,
      dns_server: document.getElementById('wazuh_api_dns').value.trim(),
      verify_ssl: document.getElementById('wazuh_api_verify_ssl').checked,
    };
    const res = await authFetch('/api/config', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(config) });
    const data = await res.json();
    return !!data.ok;
  } catch (e) {
    return false;
  }
}

// Populate the Wazuh API card from config.wazuh_api. Called from
// populateConfigFields (when config loads) and defensively when the Hosts
// tab opens, so the card shows saved values regardless of tab-visit order.
function populateWazuhApi(config) {
  const w = (config && config.wazuh_api) || {};
  const url  = document.getElementById('wazuh_api_url');
  const user = document.getElementById('wazuh_api_user');
  const pass = document.getElementById('wazuh_api_pass');
  const dns  = document.getElementById('wazuh_api_dns');
  const ssl  = document.getElementById('wazuh_api_verify_ssl');
  if (url)  url.value  = w.url || '';
  if (user) user.value = w.username || '';
  if (pass) pass.value = w.password || '';
  if (dns)  dns.value  = w.dns_server || '';
  if (ssl)  ssl.checked = w.verify_ssl !== false;
}

// ---------------------------------------------------------------------------
// Wazuh agent import modal
//
// A floating black/green card with three independently-scrolling columns:
//   ADDABLE (green)       — clean hosts: select-all / add-selected / per-row +
//   IP MISMATCH (amber)   — name OK, IP disagrees: 3 IP choices (blank default,
//                            DNS IP, agent IP) per row + three bulk "& Add All"
//   NEEDS RECONFIG (red)  — agent name != DNS: loud report, fix on agent host,
//                            no import (only Wazuh-side reconfig can fix it)
// plus a collapsed "already in hosts.json" strip across the bottom.
//
// All Wazuh-API + DNS + classification logic lives server-side in
// wazuh_import.py (called via /api/wazuh/import-preview). This JS only renders
// the returned buckets and turns operator choices into host entries, which it
// adds through the normal hosts flow (saveHosts) so adds stay consistent with
// hand-added hosts. ip_choice mirrors the module: 'blank' | 'dns' | 'agent'.
// ---------------------------------------------------------------------------
let _wzImport = null;  // last preview result, kept for re-render

async function openWazuhImport() {
  _buildWazuhModal();
  _wzSetBody('<div style="padding:40px;text-align:center;color:var(--textdim)">Contacting Wazuh and verifying agents against DNS&hellip;</div>');
  try {
    const res = await authFetch('/api/wazuh/import-preview', {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}'
    });
    const data = await res.json();
    if (!data.ok) {
      _wzSetBody(`<div style="padding:32px;color:var(--red);line-height:1.6">
        <strong>Import failed</strong><br>${escapeHtml(data.error || 'Unknown error')}</div>`);
      return;
    }
    _wzImport = data.result;
    _renderWazuhBuckets();
  } catch (e) {
    _wzSetBody(`<div style="padding:32px;color:var(--red)">Request error: ${escapeHtml(String(e))}</div>`);
  }
}

function _buildWazuhModal() {
  closeWazuhImport(true);   // force-close any prior instance, no guard
  _wzDirty = false;         // fresh modal, no staged changes yet
  const overlay = document.createElement('div');
  overlay.id = 'wz-import-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(5,8,10,0.88);z-index:9000;display:flex;align-items:center;justify-content:center;padding:24px';
  overlay.addEventListener('click', (e) => { if (e.target === overlay) wzClose(); });

  const card = document.createElement('div');
  card.id = 'wz-import-card';
  card.style.cssText = 'background:var(--bg2);border:1px solid var(--green);border-radius:6px;box-shadow:0 0 40px rgba(0,255,136,0.15);width:min(1200px,95vw);max-height:88vh;display:flex;flex-direction:column;overflow:hidden';

  card.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;padding:14px 18px;border-bottom:1px solid var(--border)">
      <span style="font-family:var(--mono);color:var(--green);letter-spacing:2px;font-size:15px">IMPORT AGENTS FROM WAZUH</span>
      <div style="display:flex;gap:8px">
        <button class="btn btn-dim" style="font-size:12px;padding:4px 12px" onclick="wzClose()">Close</button>
        <button class="btn btn-green" style="font-size:12px;padding:4px 12px" onclick="wzCloseAndSave()">Close &amp; Save</button>
      </div>
    </div>
    <div style="padding:10px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px">
      <label class="toggle"><input type="checkbox" id="wz_group_role"><span class="toggle-slider"></span></label>
      <label for="wz_group_role" style="font-size:12px;color:var(--textdim)">Use Wazuh agent groups to pre-fill roles</label>
    </div>
    <div id="wz-body" style="flex:1;overflow:hidden;display:flex;flex-direction:column"></div>`;

  overlay.appendChild(card);
  document.body.appendChild(overlay);
}

// Plain close / click-outside: if there are staged (unsaved) changes, confirm
// discard before throwing them away — Close is an escape hatch, not a trap.
// On discard, reload hosts from disk so the in-memory edits are reverted.
function wzClose() {
  if (_wzDirty) {
    if (!confirm('Discard unsaved imported changes? Nothing has been saved to hosts.json yet.')) return;
    // Revert the in-memory hosts to what's on disk (undo the staged changes).
    loadHosts();
  }
  closeWazuhImport(true);
}

// Close & Save: commit the staged hosts to disk, then close.
async function wzCloseAndSave() {
  if (_wzDirty) {
    const res = await authFetch('/api/hosts', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(hosts) });
    const data = await res.json();
    if (!data.ok) { _wzFlash('Save failed: ' + (data.error||''), 'red'); return; }
    if (typeof loadRoles === 'function') loadRoles();
    renderHosts();
  }
  closeWazuhImport(true);
}

function closeWazuhImport(force) {
  // force=true skips the dirty-guard (used internally after an explicit
  // close/save decision). External callers should use wzClose().
  if (!force && _wzDirty) { wzClose(); return; }
  const el = document.getElementById('wz-import-overlay');
  if (el) el.remove();
  _wzDirty = false;
}

function _wzSetBody(html) {
  const b = document.getElementById('wz-body');
  if (b) b.innerHTML = html;
}

function _wzUseGroupRole() {
  const el = document.getElementById('wz_group_role');
  return !!(el && el.checked);
}

// Build a host entry from an agent + ip choice (client mirror of the module's
// build_host_entry: same shape saveHosts writes; role only if group-role on
// and a real group exists; identifiers only when an IP is chosen).
function _wzBuildHost(agent, ipChoice, nameOverride) {
  // nameOverride: the "Add by DNS name" path (name-mismatch pane) creates the
  // host under its DNS-canonical name instead of the agent's wrong name. PROVEN
  // to work: the pipeline canonicalizes alerts by DNS (PTR on agent.ip) and
  // ignores the agent name, so an alert from the misnamed agent resolves to this
  // DNS name and matches this entry (verified live 6/27: agent fedora-soc, DNS
  // fedora, host fedora -> canonical_hostname=fedora, full context).
  const h = { name: (nameOverride || agent.name || ''), os: agent.os || '', vlan: 10, tags: [], notes: '', alias: '' };
  if (_wzUseGroupRole()) {
    const real = (agent.groups || []).filter(g => g && g.toLowerCase() !== 'default');
    if (real.length) h.role = real[0];
  }
  let ips = [];
  if (ipChoice === 'agent' && agent.ip) ips = [agent.ip];
  else if (ipChoice === 'dns') ips = (agent.dns_ips || []).slice();
  // 'blank' -> no identifiers (resolved at alert time)
  if (ips.length === 1) h.identifiers = { ip: ips[0] };
  else if (ips.length > 1) h.identifiers = { ip: ips };
  return h;
}

// Add a list of {agent, ipChoice} to hosts.json via the normal flow, then
// refresh the host list and re-open the preview so buckets reflect the adds.
// Tracks whether the modal has staged (unsaved) changes to `hosts`. Nothing
// is written to disk until the operator clicks "Close & Save" — consistent
// with the rest of the interface, where edits are in-memory until an explicit
// Save. Plain "Close" discards staged changes (with a confirm).
let _wzDirty = false;

function _wzAddHosts(items) {
  if (!hosts.hosts) hosts.hosts = [];
  const keyOf = (n) => (n||'').split('.')[0].toLowerCase();
  // Index existing hosts by first-label key so we can UPDATE in place rather
  // than refuse a duplicate. The IP-mismatch column exists specifically to FIX
  // an existing host's IP (e.g. blank a roaming host), so "already present"
  // must mean "update it", not "skip it".
  const indexByKey = {};
  hosts.hosts.forEach((h, idx) => { indexByKey[keyOf(h.name)] = idx; });

  const touched = [];   // agents that were added or updated
  let addedN = 0, updatedN = 0;
  for (const it of items) {
    const built = _wzBuildHost(it.agent, it.ipChoice, it.nameOverride);
    // Key off the EFFECTIVE name (the DNS-canonical override when adding by DNS
    // name, otherwise the agent name), so dedup/update target the entry that
    // will actually exist.
    const key = keyOf(it.nameOverride || it.agent.name);
    if (key in indexByKey) {
      // Update existing entry: change ONLY the IP (identifiers) per the
      // operator's choice. Everything else the operator authored — notes,
      // alias, tags, vlan, role, name casing — is left UNTOUCHED. An
      // IP-mismatch fix is surgical: it corrects the IP and nothing else.
      // (Group->role pre-fill applies only when ADDING a new host, never on
      // update, so a deliberate role assignment is never clobbered.)
      const cur = hosts.hosts[indexByKey[key]];
      if ('identifiers' in built) cur.identifiers = built.identifiers;
      else delete cur.identifiers;            // 'blank' -> remove pinned IP
      updatedN++;
    } else {
      hosts.hosts.push(built);
      indexByKey[key] = hosts.hosts.length - 1;
      addedN++;
    }
    touched.push(it.agent);
  }
  if (!touched.length) { _wzFlash('Nothing to do.', 'amber'); return; }

  // STAGE only — do NOT write to disk here. The change lives in the in-memory
  // `hosts` object until "Close & Save". This matches the interface-wide rule
  // that nothing is permanent until an explicit save, and makes plain "Close"
  // a real escape hatch (discard) rather than a forced commit.
  _wzDirty = true;
  renderHosts();  // keep the host list behind the modal in sync (also unsaved)

  // Update the modal IN PLACE: move touched agents out of
  // addable/ip_mismatch/name_mismatch into already_in and re-render.
  const touchedKeys = new Set(touched.map(a => keyOf(a.name)));
  const b = (_wzImport && _wzImport.buckets) || {};
  for (const bk of ['addable', 'ip_mismatch', 'name_mismatch']) {
    b[bk] = (b[bk] || []).filter(a => !touchedKeys.has(keyOf(a.name)));
  }
  const alreadyKeys = new Set((b.already_in||[]).map(a => keyOf(a.name)));
  for (const a of touched) if (!alreadyKeys.has(keyOf(a.name))) { b.already_in.push(a); alreadyKeys.add(keyOf(a.name)); }
  if (_wzImport) _wzImport.counts = {
    already_in: (b.already_in||[]).length, addable: (b.addable||[]).length,
    ip_mismatch: (b.ip_mismatch||[]).length, name_mismatch: (b.name_mismatch||[]).length
  };
  _renderWazuhBuckets();

  // Confirmation that distinguishes added vs updated (staged, not yet saved).
  const parts = [];
  if (addedN) parts.push(`Added ${addedN}`);
  if (updatedN) parts.push(`Updated ${updatedN}`);
  const names = touched.map(a => a.name).join(', ');
  _wzFlash(`\u2713 ${parts.join(' & ')} (unsaved): ${names}`, 'green');
}

// Brief status banner inside the modal (auto-fades). color: 'green'|'amber'|'red'.
function _wzFlash(msg, color) {
  const body = document.getElementById('wz-body');
  if (!body) return;
  let el = document.getElementById('wz-flash');
  if (!el) {
    el = document.createElement('div');
    el.id = 'wz-flash';
    el.style.cssText = 'position:absolute;left:50%;transform:translateX(-50%);top:8px;z-index:10;padding:6px 16px;border-radius:4px;font-size:12px;font-family:var(--mono);box-shadow:0 2px 12px rgba(0,0,0,0.5);pointer-events:none';
    const card = document.getElementById('wz-import-card');
    if (card) { card.style.position = 'relative'; card.appendChild(el); }
  }
  const c = color === 'red' ? 'var(--red)' : color === 'amber' ? 'var(--amber)' : 'var(--green)';
  el.style.background = 'var(--bg3)';
  el.style.border = '1px solid ' + c;
  el.style.color = c;
  el.textContent = msg;
  el.style.opacity = '1';
  clearTimeout(el._t);
  el._t = setTimeout(() => { if (el) el.style.transition = 'opacity 0.6s'; el.style.opacity = '0'; }, 2600);
}

function _renderWazuhBuckets() {
  const r = _wzImport || {};
  const b = r.buckets || {};
  const addable = b.addable || [];
  const ipm = b.ip_mismatch || [];
  const nm = b.name_mismatch || [];
  const already = b.already_in || [];

  const statusBadge = (a) =>
    a.status && a.status !== 'active'
      ? `<span style="color:var(--amber);font-size:9px;border:1px solid var(--amber);border-radius:3px;padding:0 4px;margin-left:6px">${escapeHtml(a.status)}</span>`
      : '';

  // ----- Left column: ADDABLE -----
  // Per-row IP choice (two options — the agent is verified clean so DNS IP and
  // agent IP are the same value): 'dns' (pin the IP, default) or 'blank'
  // (resolve live). Lets the operator NOT auto-pin DHCP hosts at import.
  const addableRows = addable.map((a, i) => `
    <div style="padding:5px 8px;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:8px">
        <input type="checkbox" class="wz-add-chk" data-i="${i}" checked>
        <span style="flex:1;font-size:12px">${escapeHtml(a.name)}${statusBadge(a)}
          <span style="color:var(--textdim);font-size:10px"> ${escapeHtml(a.os||'')} ${escapeHtml(a.ip||'')}</span></span>
        <button class="btn btn-dim" style="font-size:10px;padding:2px 8px" onclick="_wzAddOne('addable',${i},_wzAddableChoice(${i}))">+</button>
      </div>
      <div style="padding-left:24px;margin-top:2px">
        <label style="font-size:10px;color:var(--text);margin-right:10px"><input type="radio" name="wz_add_${i}" value="dns" checked> DNS IP${a.ip?': '+escapeHtml(a.ip):''}</label>
        <label style="font-size:10px;color:var(--text)"><input type="radio" name="wz_add_${i}" value="blank"> blank IP <span style="color:var(--textdim)">(dhcp / resolve live)</span></label>
      </div>
    </div>`).join('') || '<div style="padding:16px;color:var(--textdim);font-size:12px">No new clean agents.</div>';

  // ----- Middle column: IP MISMATCH -----
  const ipmRows = ipm.map((a, i) => `
    <div style="padding:6px 8px;border-bottom:1px solid var(--border)">
      <div style="font-size:12px;margin-bottom:3px">${escapeHtml(a.name)}${statusBadge(a)}</div>
      <label style="display:block;font-size:11px;color:var(--text)"><input type="radio" name="wz_ipm_${i}" value="blank" checked> blank <span style="color:var(--textdim)">(discovered at alert time)</span></label>
      ${(a.dns_ips&&a.dns_ips.length)?`<label style="display:block;font-size:11px;color:var(--text)"><input type="radio" name="wz_ipm_${i}" value="dns"> use DNS IP: ${escapeHtml(a.dns_ips.join(', '))}</label>`:''}
      ${a.ip?`<label style="display:block;font-size:11px;color:var(--text)"><input type="radio" name="wz_ipm_${i}" value="agent"> use agent IP: ${escapeHtml(a.ip)}</label>`:''}
      <button class="btn btn-dim" style="font-size:10px;padding:2px 8px;margin-top:3px" onclick="_wzAddIpm(${i})">+ Add</button>
    </div>`).join('') || '<div style="padding:16px;color:var(--textdim);font-size:12px">No IP mismatches.</div>';

  // ----- Right column: NEEDS RECONFIG -----
  const nmRows = nm.map((a, i) => {
    const dnsShort = a.dns_name ? a.dns_name.split('.')[0] : '';
    return `
    <div style="padding:8px;border-bottom:1px solid var(--border)">
      <div style="font-size:12px;color:var(--red)">&#9888; ${escapeHtml(a.name)}${statusBadge(a)}</div>
      <div style="font-size:11px;color:var(--text);margin-top:3px">Agent name does not match DNS.</div>
      <div style="font-size:11px;color:var(--textdim);margin-top:2px">agent: <span style="color:var(--text)">${escapeHtml(a.name)}</span>${dnsShort?` &nbsp; DNS: <span style="color:var(--text)">${escapeHtml(dnsShort)}</span>`:' &nbsp; (no DNS record)'}</div>
      ${dnsShort ? `
      <button class="btn btn-green" style="font-size:10px;padding:2px 8px;margin-top:5px" onclick="_wzAddByDns(${i})">+ Add as "${escapeHtml(dnsShort)}" (DNS name)</button>
      <div style="font-size:10px;color:var(--textdim);margin-top:4px">Adds the host under its DNS name. The pipeline matches alerts from this agent by DNS, so this works even with the agent misnamed. Recommended hygiene: also fix the agent name in its Wazuh config (ossec.conf) so the two agree.</div>
      ` : `
      <div style="font-size:11px;color:var(--amber);margin-top:4px">No DNS record found for this host, so it can't be added by DNS name. Fix on the agent host: set the agent name in its Wazuh agent config (ossec.conf) to match DNS, then re-register and re-run import.</div>
      `}
    </div>`;
  }).join('') || '<div style="padding:16px;color:var(--textdim);font-size:12px">No agents need reconfiguration.</div>';

  const colHead = 'font-family:var(--mono);font-size:12px;letter-spacing:1px;padding:8px 10px;border-bottom:1px solid var(--border)';
  const colScroll = 'flex:1;overflow-y:auto;min-height:0';
  const col = 'flex:1;display:flex;flex-direction:column;border-right:1px solid var(--border);min-width:0';

  _wzSetBody(`
    <div style="flex:1;display:flex;overflow:hidden;min-height:0">
      <!-- ADDABLE -->
      <div style="${col}">
        <div style="${colHead};color:var(--green)">ADDABLE (${addable.length})</div>
        <div style="padding:6px 10px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:5px">
          <label style="font-size:11px;color:var(--textdim)"><input type="checkbox" id="wz_selall" checked onchange="_wzToggleAll(this.checked)"> Select All</label>
          <div style="display:flex;gap:5px">
            <button class="btn btn-green" style="font-size:10px;padding:3px 8px;flex:1" onclick="_wzAddSelected('dns')">DNS IP &amp; Add Selected</button>
            <button class="btn btn-dim" style="font-size:10px;padding:3px 8px;flex:1" onclick="_wzAddSelected('blank')">Blank IP (dhcp) &amp; Add Selected</button>
          </div>
        </div>
        <div style="${colScroll}">${addableRows}</div>
      </div>
      <!-- IP MISMATCH -->
      <div style="${col}">
        <div style="${colHead};color:var(--amber)">IP MISMATCH (${ipm.length})</div>
        <div style="padding:6px 10px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:4px">
          <button class="btn btn-dim" style="font-size:10px;padding:3px 8px" onclick="_wzAddAllIpm('blank')">IP blank (alert-time) &amp; Add All</button>
          <button class="btn btn-dim" style="font-size:10px;padding:3px 8px" onclick="_wzAddAllIpm('dns')">Use DNS IP &amp; Add All</button>
          <button class="btn btn-dim" style="font-size:10px;padding:3px 8px" onclick="_wzAddAllIpm('agent')">Use Agent IP &amp; Add All</button>
        </div>
        <div style="${colScroll}">${ipmRows}</div>
      </div>
      <!-- NEEDS RECONFIG -->
      <div style="${col};border-right:none">
        <div style="${colHead};color:var(--red)">NEEDS RECONFIG (${nm.length})</div>
        <div style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:10px;color:var(--textdim)">Report only — fix on the agent, then re-import.</div>
        <div style="${colScroll}">${nmRows}</div>
      </div>
    </div>
    <!-- ALREADY IN strip -->
    <div style="border-top:1px solid var(--border);padding:8px 12px">
      <div style="cursor:pointer;font-size:12px;color:var(--textdim)" onclick="var x=document.getElementById('wz-already');x.style.display=x.style.display==='none'?'block':'none'">
        &#9656; ${already.length} agents already in hosts.json</div>
      <div id="wz-already" style="display:none;margin-top:6px;font-size:11px;color:var(--textdim);max-height:120px;overflow-y:auto">
        ${already.map(a=>escapeHtml(a.name)).join(', ') || '—'}</div>
    </div>`);
}

function _wzToggleAll(checked) {
  document.querySelectorAll('.wz-add-chk').forEach(c => { c.checked = checked; });
}

function _wzAddOne(bucket, i, ipChoice) {
  const a = (_wzImport.buckets[bucket]||[])[i];
  if (a) _wzAddHosts([{ agent: a, ipChoice: ipChoice }]);
}

// Read an addable row's per-row IP choice ('dns' default | 'blank').
function _wzAddableChoice(i) {
  const sel = document.querySelector(`input[name="wz_add_${i}"]:checked`);
  return sel ? sel.value : 'dns';
}

// Bulk add the selected addable hosts. ipChoice applies the operator's bulk
// decision to the whole selection ('dns' = pin DNS IP, 'blank' = resolve live).
function _wzAddSelected(ipChoice) {
  const choice = ipChoice || 'dns';
  const items = [];
  document.querySelectorAll('.wz-add-chk').forEach(c => {
    if (c.checked) {
      const a = _wzImport.buckets.addable[parseInt(c.dataset.i)];
      if (a) items.push({ agent: a, ipChoice: choice });
    }
  });
  if (items.length) _wzAddHosts(items);
}

function _wzAddIpm(i) {
  const a = _wzImport.buckets.ip_mismatch[i];
  const sel = document.querySelector(`input[name="wz_ipm_${i}"]:checked`);
  const choice = sel ? sel.value : 'blank';
  if (a) _wzAddHosts([{ agent: a, ipChoice: choice }]);
}

function _wzAddAllIpm(ipChoice) {
  const items = (_wzImport.buckets.ip_mismatch||[]).map(a => ({ agent: a, ipChoice: ipChoice }));
  if (items.length) _wzAddHosts(items);
}

// Add a name-mismatch agent under its DNS-canonical name (the DNS first-label),
// not its wrong agent name. IP left blank: the agent's name is wrong so we don't
// trust its IP either, and the pipeline resolves+matches this host by DNS (PTR on
// the agent IP -> the DNS name -> this entry) at alert time. PROVEN live 6/27.
function _wzAddByDns(i) {
  const a = (_wzImport.buckets.name_mismatch||[])[i];
  if (!a || !a.dns_name) return;
  const dnsShort = a.dns_name.split('.')[0];
  _wzAddHosts([{ agent: a, ipChoice: 'blank', nameOverride: dnsShort }]);
}

// ---------------------------------------------------------------------------
// Renumber modal — reconcile hosts.json STORED IPs against agent+DNS consensus
//
// Different question than the import: this compares the IP STORED in hosts.json
// against what Wazuh + DNS now agree on, catching stale pinned IPs (e.g. after a
// network renumber) the import misses. Consensus-gated: only drifted hosts where
// agent AND DNS agree on a new IP are offered. show-then-confirm-then-save:
// warning -> compute drift -> show the diff -> Close & Save commits / Close
// discards. Per drifted host: Update (pin consensus) / Blank (un-pin) / Leave.
// Reuses the staged-commit (_wzDirty), the surgical update (IP-only, preserves
// operator fields), and the two-close machinery from the import modal.
// ---------------------------------------------------------------------------
let _wzRenum = null;

async function openWazuhRenumber() {
  if (!confirm("This checks each host's stored IP against both Wazuh and DNS. " +
    "Where the Wazuh agent IP and DNS agree on a new IP that differs from " +
    "hosts.json, you'll be able to update it. Hosts without an agent, or where " +
    "Wazuh and DNS disagree, are left unchanged. Continue?")) return;

  const includeBlank = !!document.getElementById('wz_renum_blank')?.checked;
  _buildWazuhModal();   // reuse the same floating-card scaffold
  // Retitle the card for renumber.
  const titleEl = document.querySelector('#wz-import-card span');
  if (titleEl) titleEl.textContent = 'RE-VERIFY IPs (RENUMBER)';
  const groupRow = document.querySelector('#wz-import-card [for="wz_group_role"]');
  if (groupRow && groupRow.parentElement) groupRow.parentElement.style.display = 'none';
  _wzSetBody('<div style="padding:40px;text-align:center;color:var(--textdim)">Checking stored IPs against Wazuh and DNS&hellip;</div>');
  try {
    const res = await authFetch('/api/wazuh/renumber-preview', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ include_blank: includeBlank })
    });
    const data = await res.json();
    if (!data.ok) {
      _wzSetBody(`<div style="padding:32px;color:var(--red);line-height:1.6"><strong>Renumber check failed</strong><br>${escapeHtml(data.error||'Unknown error')}</div>`);
      return;
    }
    _wzRenum = data.result;
    _renderRenumber();
  } catch (e) {
    _wzSetBody(`<div style="padding:32px;color:var(--red)">Request error: ${escapeHtml(String(e))}</div>`);
  }
}

function _renderRenumber() {
  const r = _wzRenum || {};
  const drifted = r.drifted || [];
  const skipped = r.skipped || [];
  const unchanged = r.unchanged || 0;

  const rows = drifted.map((d, i) => {
    const fromTxt = d.currently_blank ? '(blank)' : escapeHtml(d.stored_ip);
    return `
    <div style="padding:7px 10px;border-bottom:1px solid var(--border)">
      <div style="font-size:12px;color:var(--text)">${escapeHtml(d.name)}
        <span style="color:var(--textdim);font-size:11px"> &nbsp; ${fromTxt} &rarr; <span style="color:var(--green)">${escapeHtml(d.consensus_ip)}</span></span></div>
      <div style="margin-top:3px">
        <label style="font-size:10px;color:var(--text);margin-right:10px"><input type="radio" name="wz_rn_${i}" value="update" checked> Update to ${escapeHtml(d.consensus_ip)}</label>
        <label style="font-size:10px;color:var(--text);margin-right:10px"><input type="radio" name="wz_rn_${i}" value="blank"> Blank IP (dhcp)</label>
        <label style="font-size:10px;color:var(--text)"><input type="radio" name="wz_rn_${i}" value="leave"> Leave</label>
      </div>
    </div>`;
  }).join('') || '<div style="padding:24px;color:var(--textdim);font-size:12px">No drift found — every checked host&#39;s stored IP already matches what Wazuh and DNS agree on.</div>';

  const skippedRows = skipped.map(s =>
    `<div style="font-size:11px;color:var(--textdim);padding:2px 0">${escapeHtml(s.name)} — ${escapeHtml(s.reason)}</div>`).join('');

  _wzSetBody(`
    <div style="flex:1;display:flex;flex-direction:column;overflow:hidden;min-height:0">
      <div style="padding:8px 12px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <span style="font-family:var(--mono);font-size:12px;color:var(--amber)">DRIFTED (${drifted.length})</span>
        ${drifted.length ? `
          <button class="btn btn-green" style="font-size:10px;padding:3px 8px;margin-left:auto" onclick="_wzRenumSetAll('update')">Use Consensus IP &amp; Update All</button>
          <button class="btn btn-dim" style="font-size:10px;padding:3px 8px" onclick="_wzRenumSetAll('blank')">Blank All Drifted</button>
        ` : ''}
      </div>
      <div style="flex:1;overflow-y:auto;min-height:0">${rows}</div>
      <div style="border-top:1px solid var(--border);padding:8px 12px;font-size:11px;color:var(--textdim)">
        ${unchanged} unchanged (stored IP already agrees).
        ${skipped.length ? `<div style="margin-top:6px"><span style="cursor:pointer" onclick="var x=document.getElementById('wz-rn-skip');x.style.display=x.style.display==='none'?'block':'none'">&#9656; ${skipped.length} skipped (no agent, or Wazuh/DNS disagree)</span><div id="wz-rn-skip" style="display:none;margin-top:4px;max-height:120px;overflow-y:auto">${skippedRows}</div></div>` : ''}
      </div>
      <div style="border-top:1px solid var(--border);padding:10px 12px;display:flex;justify-content:flex-end;gap:8px">
        <button class="btn btn-dim" style="font-size:12px;padding:4px 12px" onclick="wzClose()">Close</button>
        <button class="btn btn-green" style="font-size:12px;padding:4px 12px" onclick="_wzRenumApply()">Close &amp; Save</button>
      </div>
    </div>`);
}

// Set every drifted row's radio to a given action (bulk buttons).
function _wzRenumSetAll(action) {
  (_wzRenum.drifted || []).forEach((d, i) => {
    const el = document.querySelector(`input[name="wz_rn_${i}"][value="${action}"]`);
    if (el) el.checked = true;
  });
}

// Apply the per-row choices to hosts (staged), save, and close.
function _wzRenumApply() {
  if (!hosts.hosts) hosts.hosts = [];
  const keyOf = (n) => (n||'').split('.')[0].toLowerCase();
  const idx = {};
  hosts.hosts.forEach((h, k) => { idx[keyOf(h.name)] = k; });

  let updated = 0, blanked = 0;
  (_wzRenum.drifted || []).forEach((d, i) => {
    const sel = document.querySelector(`input[name="wz_rn_${i}"]:checked`);
    const action = sel ? sel.value : 'update';
    if (action === 'leave') return;
    const k = idx[keyOf(d.name)];
    if (k === undefined) return;
    const cur = hosts.hosts[k];
    if (action === 'update') {
      // Surgical: change ONLY the IP; preserve notes/role/tags/alias/vlan.
      cur.identifiers = { ip: d.consensus_ip };
      updated++;
    } else if (action === 'blank') {
      delete cur.identifiers;   // un-pin -> resolve live
      blanked++;
    }
  });

  if (!updated && !blanked) { closeWazuhImport(true); return; }

  authFetch('/api/hosts', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(hosts) })
    .then(r => r.json()).then(data => {
      if (!data.ok) { _wzFlash('Save failed: ' + (data.error||''), 'red'); return; }
      if (typeof loadRoles === 'function') loadRoles();
      renderHosts();
      _wzDirty = false;
      closeWazuhImport(true);
    }).catch(e => _wzFlash('Save error: ' + String(e), 'red'));
}

// ---------------------------------------------------------------------------
// Roles panel — reusable host-role definitions (name, description, notes)
// ---------------------------------------------------------------------------
let roles = { roles: [] };

async function loadRoles() {
  const res = await authFetch('/api/roles');
  roles = await res.json();
  if (!roles.roles) roles.roles = [];
  renderRoles();
  refreshRolesDatalist();
}

// Populate the shared <datalist> that every host role combobox reads from,
// so picking an existing role and typing a new one use the same control.
function refreshRolesDatalist() {
  const dl = document.getElementById('roles-datalist');
  if (!dl) return;
  dl.innerHTML = (roles.roles || [])
    .map(r => `<option value="${escapeHtml(r.name || '')}">`)
    .join('');
}

// A role is "New" (un-acknowledged auto-stub) when it has NO saved content
// in either description or notes. Saving either field graduates it.
function roleIsNew(r) {
  const desc = (r.description || '').trim();
  const notes = (r.notes || '').trim();
  return !desc && !notes;
}

function renderRoles() {
  const container = document.getElementById('roles-container');
  container.innerHTML = '';
  (roles.roles || []).forEach((r, i) => {
    const isNew = roleIsNew(r);
    const badge = isNew
      ? `<span style="font-size:10px;color:var(--amber);border:1px solid var(--amber);border-radius:3px;padding:1px 6px;margin-left:8px">New</span>`
      : '';
    container.innerHTML += `
    <div class="card" id="role-card-${i}">
      <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
        <span>${escapeHtml(r.name || 'New Role')}${badge}</span>
        <button class="btn btn-red" style="font-size:10px;padding:3px 10px" onclick="removeRole(${i})">Del</button>
      </div>
      <div class="field"><label>Name</label><input type="text" id="r_name_${i}" value="${escapeHtml(r.name||'')}" placeholder="e.g. vm_host"></div>
      <div class="field"><label>Description <span style="color:var(--textdim);font-size:10px;font-weight:400">(short label of what this role is)</span></label><input type="text" id="r_desc_${i}" value="${escapeHtml(r.description||'')}" placeholder="e.g. Hypervisor / virtual-machine host"></div>
      <div class="field"><label>Notes <span style="color:var(--textdim);font-size:10px;font-weight:400">(what's normal for this kind of host — optional, add once observed)</span></label><textarea id="r_notes_${i}">${escapeHtml(r.notes||'')}</textarea></div>
    </div>`;
  });
}

function addRole() {
  roles.roles = roles.roles || [];
  roles.roles.push({ name: '', description: '', notes: '' });
  renderRoles();
  document.getElementById(`role-card-${roles.roles.length - 1}`).scrollIntoView({ behavior: 'smooth' });
}

function removeRole(i) {
  if (!confirm('Delete this role? Hosts referencing it will keep the name but lose its context.')) return;
  roles.roles.splice(i, 1);
  renderRoles();
}

async function saveRoles() {
  const count = (roles.roles || []).length;
  roles.roles = [];
  for (let i = 0; i < count; i++) {
    roles.roles.push({
      name: document.getElementById(`r_name_${i}`)?.value?.trim() || '',
      description: document.getElementById(`r_desc_${i}`)?.value || '',
      notes: document.getElementById(`r_notes_${i}`)?.value || '',
    });
  }
  const res = await authFetch('/api/roles', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(roles) });
  const data = await res.json();
  showStatus(data.ok ? '[OK] Saved' : '[ERR] ' + data.error, data.ok ? 'ok' : 'err', 'status-bar');
  if (data.ok) { renderRoles(); refreshRolesDatalist(); }
}

// ---------------------------------------------------------------------------
// Rules panel — per-rule escalation control and rate limiting
// ---------------------------------------------------------------------------
async function loadRules() {
  // Rules tab needs the host list for per-host notes dropdowns
  if (!hosts.hosts) {
    const hr = await authFetch('/api/hosts');
    hosts = await hr.json();
  }
  const res = await authFetch('/api/rules');
  rules = await res.json();
  renderRules();
}

function conditionHtml(cond, ri, ci, section) {
  return `<div class="list-item" id="${section}_cond_${ri}_${ci}" style="gap:6px;flex-wrap:wrap">
    <input type="text" id="${section}_field_${ri}_${ci}" value="${escapeHtml(cond.field||'')}" placeholder="field (e.g. external_ips)" style="flex:2;min-width:140px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 8px">
    <select id="${section}_op_${ri}_${ci}" style="flex:1;min-width:100px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 8px">
      ${['exists','not_exists','gt','gte','lt','lte','eq','neq','contains','in'].map(op =>
        `<option value="${op}" ${cond.op===op?'selected':''}>${op}</option>`).join('')}
    </select>
    <input type="text" id="${section}_val_${ri}_${ci}" value="${escapeHtml(cond.value||'')}" placeholder="value" style="flex:2;min-width:100px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 8px">
    <button class="btn-icon" onclick="removeCond('${section}',${ri},${ci})">x</button>
  </div>`;
}

function renderConditions(conditions, ri, section) {
  const el = document.getElementById(`${section}_conds_${ri}`);
  if (!el) return;
  el.innerHTML = (conditions||[]).map((c,ci) => conditionHtml(c,ri,ci,section)).join('');
}

function addCond(section, ri) {
  const key = `${section}_${ri}`;
  if (!window._condState) window._condState = {};
  if (!window._condState[key]) window._condState[key] = [];
  window._condState[key].push({field:'',op:'exists',value:''});
  renderConditions(window._condState[key], ri, section);
}

function removeCond(section, ri, ci) {
  const key = `${section}_${ri}`;
  if (window._condState && window._condState[key]) {
    window._condState[key].splice(ci, 1);
    renderConditions(window._condState[key], ri, section);
  }
}

function getConditions(section, ri) {
  const key = `${section}_${ri}`;
  const count = (window._condState && window._condState[key]) ? window._condState[key].length : 0;
  const result = [];
  for (let ci = 0; ci < count; ci++) {
    const field = document.getElementById(`${section}_field_${ri}_${ci}`)?.value?.trim();
    const op    = document.getElementById(`${section}_op_${ri}_${ci}`)?.value;
    const val   = document.getElementById(`${section}_val_${ri}_${ci}`)?.value?.trim();
    if (field) result.push({field, op: op||'exists', ...(val ? {value: isNaN(val)?val:parseFloat(val)} : {})});
  }
  return result;
}

function renderRules() {
  if (!window._condState) window._condState = {};
  const container = document.getElementById('rules-container');
  container.innerHTML = '';
  (rules || []).forEach((r, i) => {
    // Initialise condition state
    window._condState[`escalate_if_${i}`]       = JSON.parse(JSON.stringify(r.escalate_if||[]));
    window._condState[`force_escalate_if_${i}`] = JSON.parse(JSON.stringify(r.force_escalate_if||[]));

    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
      <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
        <span>Rule ${escapeHtml(r.rule_id || 'New')}</span>
        <button class="btn btn-red" style="font-size:10px;padding:3px 10px" onclick="removeRule(${i})">Remove</button>
      </div>
      <div class="grid3">
        <div class="field"><label>Rule ID</label><input type="text" id="r_id_${i}" value="${escapeHtml(r.rule_id||'')}"></div>
        <div class="field"><label>Dedup Silence (sec)</label><input type="number" id="r_dedup_${i}" value="${escapeHtml(r.dedup_silence_seconds||3600)}"></div>
        <div class="field"><label>Max Escalations/Hour</label><input type="number" id="r_max_${i}" value="${escapeHtml(r.max_escalations_per_hour||'')}"></div>
      </div>
      <div class="grid2">
        <div class="field">
          <label>Rate Limit Scope</label>
          <select id="r_scope_${i}">
            <option value="host" ${(r.rate_limit_scope||'host')==='host'?'selected':''}>Per host</option>
            <option value="global" ${r.rate_limit_scope==='global'?'selected':''}>Global</option>
          </select>
        </div>
        <div class="field">
          <label>Condition Logic</label>
          <select id="r_logic_${i}">
            <option value="AND" ${(r.condition_logic||'AND')==='AND'?'selected':''}>AND (all must pass)</option>
            <option value="OR"  ${r.condition_logic==='OR'?'selected':''}>OR (any must pass)</option>
          </select>
        </div>
      </div>
      <div class="toggle-row" style="margin-bottom:16px">
        <label class="toggle"><input type="checkbox" id="r_never_${i}" ${r.never_escalate?'checked':''}>
        <span class="toggle-slider"></span></label>
        <label style="color:var(--red)">Never Escalate — hard suppress, never reaches LLM</label>
      </div>

      <div class="field">
        <label style="color:var(--amber)">escalate_if <span style="color:var(--textdim);font-size:10px;font-weight:400;text-transform:none;letter-spacing:0">— normal path gating, conditions must pass to escalate</span></label>
        <div id="escalate_if_conds_${i}"></div>
        <button class="btn btn-dim" style="margin-top:6px;font-size:10px;padding:3px 10px" onclick="addCond('escalate_if',${i})">+ Add Condition</button>
      </div>

      <div class="field" style="margin-top:12px">
        <label style="color:var(--green)">force_escalate_if <span style="color:var(--textdim);font-size:10px;font-weight:400;text-transform:none;letter-spacing:0">— bypass min_rule_level, always escalates if conditions met</span></label>
        <div id="force_escalate_if_conds_${i}"></div>
        <button class="btn btn-dim" style="margin-top:6px;font-size:10px;padding:3px 10px" onclick="addCond('force_escalate_if',${i})">+ Add Condition</button>
      </div>

      <div class="field" style="margin-top:12px">
        <label>Comment / Description</label>
        <input type="text" id="r_comment_${i}" value="${escapeHtml(r.comment||'')}">
      </div>
      <div class="field" style="margin-top:8px">
        <label>Site-Specific Note <span style="color:var(--textdim);font-size:10px;font-weight:400">(shown to LLM when this rule fires, regardless of host)</span></label>
        <textarea id="r_note_${i}" rows="4" style="width:100%;font-family:var(--mono-read);font-size:13px;line-height:1.5;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:10px;resize:vertical">${escapeHtml(r.note||'')}</textarea>
      </div>
      <div class="field" style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
        <label>Per-Host Notes <span style="color:var(--textdim);font-size:10px;font-weight:400">(appended to the LLM prompt only when this rule fires on a specific host)</span></label>
        <div id="r_host_notes_${i}" style="margin-top:8px"></div>
        <button class="btn btn-dim" style="font-size:10px;padding:4px 12px;margin-top:8px" onclick="addHostNote(${i})">+ Add Host Note</button>
      </div>`;
    container.appendChild(card);
    // Render existing conditions
    renderConditions(window._condState[`escalate_if_${i}`], i, 'escalate_if');
    renderConditions(window._condState[`force_escalate_if_${i}`], i, 'force_escalate_if');
    // Render existing host notes
    renderHostNotes(i, r.host_notes || {});
  });
}

function addRule() {
  rules = rules || [];
  rules.push({ rule_id: '', dedup_silence_seconds: 3600, max_escalations_per_hour: 2, rate_limit_scope: 'host', never_escalate: false, condition_logic: 'AND', escalate_if: [], force_escalate_if: [], comment: '', note: '', host_notes: {} });
  renderRules();
}

function removeRule(i) {
  if (!confirm('Remove this rule?')) return;
  rules.splice(i, 1);
  renderRules();
}

// Track host notes state per rule index
window._hostNotesState = window._hostNotesState || {};

function renderHostNotes(ruleIdx, hostNotes) {
  window._hostNotesState[ruleIdx] = Object.entries(hostNotes).map(([host, note]) => ({ host, note }));
  redrawHostNotes(ruleIdx);
}

function redrawHostNotes(ruleIdx) {
  const container = document.getElementById(`r_host_notes_${ruleIdx}`);
  if (!container) return;
  const entries = window._hostNotesState[ruleIdx] || [];
  const hostList = (hosts.hosts || []).map(h => h.name).filter(Boolean).sort();
  container.innerHTML = '';
  entries.forEach((entry, hi) => {
    const row = document.createElement('div');
    row.style.cssText = 'margin-bottom:10px;padding:10px;background:var(--surface);border:1px solid var(--border);border-radius:4px';
    const hostOptions = hostList.map(h => `<option value="${escapeHtml(h)}" ${h === entry.host ? 'selected' : ''}>${escapeHtml(h)}</option>`).join('');
    row.innerHTML = `
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:8px">
        <select id="r_hn_host_${ruleIdx}_${hi}" style="flex:0 0 240px;font-family:var(--mono);font-size:12px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:3px;padding:6px 10px">
          <option value="">-- select host --</option>
          ${hostOptions}
        </select>
        <button class="btn btn-red" style="font-size:10px;padding:3px 10px" onclick="removeHostNote(${ruleIdx}, ${hi})">Remove</button>
      </div>
      <textarea id="r_hn_note_${ruleIdx}_${hi}" rows="3" style="width:100%;font-family:var(--mono-read);font-size:13px;line-height:1.5;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:3px;padding:10px;resize:vertical">${escapeHtml(entry.note || '')}</textarea>
    `;
    container.appendChild(row);
  });
}

function addHostNote(ruleIdx) {
  captureHostNotesFromUI(ruleIdx);
  window._hostNotesState[ruleIdx] = window._hostNotesState[ruleIdx] || [];
  window._hostNotesState[ruleIdx].push({ host: '', note: '' });
  redrawHostNotes(ruleIdx);
}

function removeHostNote(ruleIdx, hi) {
  captureHostNotesFromUI(ruleIdx);
  window._hostNotesState[ruleIdx].splice(hi, 1);
  redrawHostNotes(ruleIdx);
}

function captureHostNotesFromUI(ruleIdx) {
  const entries = window._hostNotesState[ruleIdx] || [];
  entries.forEach((entry, hi) => {
    const hostEl = document.getElementById(`r_hn_host_${ruleIdx}_${hi}`);
    const noteEl = document.getElementById(`r_hn_note_${ruleIdx}_${hi}`);
    if (hostEl) entry.host = hostEl.value;
    if (noteEl) entry.note = noteEl.value;
  });
}

function collectHostNotes(ruleIdx) {
  captureHostNotesFromUI(ruleIdx);
  const entries = window._hostNotesState[ruleIdx] || [];
  const result = {};
  entries.forEach(entry => {
    if (entry.host && entry.note.trim()) {
      result[entry.host] = entry.note.trim();
    }
  });
  return result;
}

async function saveRules() {
  const count = rules.length;
  const newRules = [];
  for (let i = 0; i < count; i++) {
    const maxEsc = document.getElementById(`r_max_${i}`)?.value;
    const dedup  = document.getElementById(`r_dedup_${i}`)?.value;
    const rule = {
      rule_id:  document.getElementById(`r_id_${i}`)?.value,
      comment:  document.getElementById(`r_comment_${i}`)?.value || '',
      note:     document.getElementById(`r_note_${i}`)?.value || '',
    };
    const hostNotes = collectHostNotes(i);
    if (Object.keys(hostNotes).length > 0) rule.host_notes = hostNotes;
    if (dedup)  rule.dedup_silence_seconds    = parseInt(dedup);
    if (maxEsc) rule.max_escalations_per_hour = parseInt(maxEsc);
    const scope = document.getElementById(`r_scope_${i}`)?.value;
    if (scope && scope !== 'host') rule.rate_limit_scope = scope;
    const logic = document.getElementById(`r_logic_${i}`)?.value;
    if (logic && logic !== 'AND') rule.condition_logic = logic;
    if (document.getElementById(`r_never_${i}`)?.checked) rule.never_escalate = true;
    const esc_if = getConditions('escalate_if', i);
    if (esc_if.length) rule.escalate_if = esc_if;
    const force_esc = getConditions('force_escalate_if', i);
    if (force_esc.length) rule.force_escalate_if = force_esc;
    newRules.push(rule);
  }
  const res = await authFetch('/api/rules', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(newRules) });
  const data = await res.json();
  showStatus(data.ok ? '[OK] Saved' : '[ERR] ' + data.error, data.ok ? 'ok' : 'err', 'status-bar');
}

// ---------------------------------------------------------------------------
// Anonymization panel — master switches, users, domains, IP aliases
// ---------------------------------------------------------------------------
async function loadAnon() {
  const [ac, uc, dc] = await Promise.all([
    authFetch('/api/anon').then(r => r.json()),
    authFetch('/api/users').then(r => r.json()),
    authFetch('/api/domains').then(r => r.json()),
  ]);
  loadIpAliases();
  anonCfg = ac;
  users = uc.users || [];
  domains = dc.domains || [];

  document.getElementById('anon_hostnames').checked = ac.hostnames ?? false;
  document.getElementById('anon_users').checked = ac.users ?? false;
  document.getElementById('anon_domain').checked = ac.domain ?? false;
  document.getElementById('anon_ips').checked = ac.ips ?? false;

  renderUsers();
  renderDomains();
}

function renderUsers() {
  const tbody = document.getElementById('users-tbody');
  tbody.innerHTML = users.map((u, i) => `
    <tr>
      <td><input type="text" id="u_name_${i}" value="${escapeHtml(u.name||'')}" style="background:var(--bg3);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 8px;width:100%"></td>
      <td><input type="text" id="u_alias_${i}" value="${escapeHtml(u.alias||'')}" placeholder="auto" style="background:var(--bg3);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 8px;width:100%"></td>
      <td><button class="btn-icon" onclick="removeUser(${i})">x</button></td>
    </tr>`).join('');
}

function addAnonUser() {
  users.push({ name: '', alias: '' });
  renderUsers();
}

function removeUser(i) {
  users.splice(i, 1);
  renderUsers();
}

async function saveUsers() {
  const newUsers = users.map((_, i) => ({
    name: document.getElementById(`u_name_${i}`)?.value || '',
    alias: document.getElementById(`u_alias_${i}`)?.value || '',
  }));
  const res = await authFetch('/api/users', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ users: newUsers }) });
  const data = await res.json();
  showStatus(data.ok ? '[OK] Users saved' : '[ERR] ' + data.error, data.ok ? 'ok' : 'err', 'status-bar');
}

function renderDomains() {
  const tbody = document.getElementById('domains-tbody');
  tbody.innerHTML = domains.map((d, i) => `
    <tr>
      <td><input type="text" id="d_name_${i}" value="${escapeHtml(d.name||'')}" style="background:var(--bg3);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 8px;width:100%"></td>
      <td><input type="text" id="d_alias_${i}" value="${escapeHtml(d.alias||'')}" placeholder="auto" style="background:var(--bg3);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 8px;width:100%"></td>
      <td><button class="btn-icon" onclick="removeDomain(${i})">x</button></td>
    </tr>`).join('');
}

function addDomain() {
  domains.push({ name: '', alias: '' });
  renderDomains();
}

function removeDomain(i) {
  domains.splice(i, 1);
  renderDomains();
}

async function saveDomains() {
  const newDomains = domains.map((_, i) => ({
    name: document.getElementById(`d_name_${i}`)?.value || '',
    alias: document.getElementById(`d_alias_${i}`)?.value || '',
  }));
  const res = await authFetch('/api/domains', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ domains: newDomains }) });
  const data = await res.json();
  showStatus(data.ok ? '[OK] Domains saved' : '[ERR] ' + data.error, data.ok ? 'ok' : 'err', 'status-bar');
}

let ipAliases = [];

async function loadIpAliases() {
  const res = await authFetch('/api/ipaliases');
  const data = await res.json();
  ipAliases = data.ips || [];
  renderIpAliases();
}

function renderIpAliases() {
  const tbody = document.getElementById('ipaliases-tbody');
  tbody.innerHTML = ipAliases.map((ip, i) => `
    <tr>
      <td><input type="text" id="ip_orig_${i}" value="${escapeHtml(ip.original||'')}" placeholder="192.168.10.101" style="background:var(--bg3);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 8px;width:100%"></td>
      <td><input type="text" id="ip_alias_${i}" value="${escapeHtml(ip.alias||'')}" placeholder="192.168.10.47" style="background:var(--bg3);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 8px;width:100%"></td>
      <td><button class="btn-icon" onclick="removeIpAlias(${i})">x</button></td>
    </tr>`).join('');
}

function addIpAlias() {
  ipAliases.push({ original: '', alias: '' });
  renderIpAliases();
}

function removeIpAlias(i) {
  ipAliases.splice(i, 1);
  renderIpAliases();
}

async function saveIpAliases() {
  const newAliases = ipAliases.map((_, i) => ({
    original: document.getElementById(`ip_orig_${i}`)?.value || '',
    alias: document.getElementById(`ip_alias_${i}`)?.value || '',
  }));
  const res = await authFetch('/api/ipaliases', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ ips: newAliases }) });
  const data = await res.json();
  showStatus(data.ok ? '[OK] IP aliases saved' : '[ERR] ' + data.error, data.ok ? 'ok' : 'err', 'status-bar');
}

async function saveAnon() {
  anonCfg.hostnames = document.getElementById('anon_hostnames').checked;
  anonCfg.users = document.getElementById('anon_users').checked;
  anonCfg.domain = document.getElementById('anon_domain').checked;
  anonCfg.ips = document.getElementById('anon_ips').checked;
  const res = await authFetch('/api/anon', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(anonCfg) });
  const data = await res.json();
  showStatus(data.ok ? '[OK] Saved' : '[ERR] ' + data.error, data.ok ? 'ok' : 'err', 'status-bar');
}

// ---------------------------------------------------------------------------
// Journal — live SSE stream from journalctl, with filter and color coding
// ---------------------------------------------------------------------------
function toggleJournal() {
  if (journalRunning) stopJournal();
  else startJournal();
}

function startJournal() {
  const box = document.getElementById('journal-box');
  const btn = document.getElementById('journal-btn');
  journalRunning = true;
  btn.textContent = 'Stop Stream';
  btn.className = 'btn btn-red';

  journalEs = new EventSource('/api/journal');
  journalEs.onmessage = (e) => {
    const filter = document.getElementById('journal-filter').value.toLowerCase();
    const line = e.data;
    if (filter && !line.toLowerCase().includes(filter)) return;

    const div = document.createElement('div');
    if (line.includes('[ERROR]') || line.includes('error') || line.includes('Error')) div.className = 'log-error';
    else if (line.includes('[WARNING]') || line.includes('Warning')) div.className = 'log-warning';
    else if (line.includes('[OK]') || line.includes('responded') || line.includes('Shipped')) div.className = 'log-green';
    else if (line.includes('[INFO]')) div.className = 'log-info';
    else div.className = 'log-dim';
    div.textContent = line;
    const wasAtBottom = box.scrollHeight - box.scrollTop <= box.clientHeight + 50;
    box.appendChild(div);
    // Keep last 500 lines
    while (box.children.length > 500) box.removeChild(box.firstChild);
    if (wasAtBottom) box.scrollTop = box.scrollHeight;
  };

  journalEs.onerror = () => stopJournal();
}

function stopJournal() {
  journalRunning = false;
  if (journalEs) { journalEs.close(); journalEs = null; }
  document.getElementById('journal-btn').textContent = 'Start Stream';
  document.getElementById('journal-btn').className = 'btn btn-green';
}

function clearJournal() {
  document.getElementById('journal-box').innerHTML = '';
}

// ---------------------------------------------------------------------------
// Maintenance — shells out to maintenance.py via /api/maintenance endpoints
// ---------------------------------------------------------------------------
let maintRefreshTimer = null;

async function loadMaintenance() {
  // Populate host dropdown from hosts.json (one-time on first load)
  const hostSelect = document.getElementById('maint-host');
  if (hostSelect.options.length <= 1) {
    try {
      const res = await authFetch('/api/hosts');
      const data = await res.json();
      (data.hosts || []).forEach(h => {
        if (!h.name) return;
        const opt = document.createElement('option');
        opt.value = h.name;
        opt.textContent = h.name;
        hostSelect.appendChild(opt);
      });
    } catch (e) { /* dropdown stays empty besides placeholder */ }
    // Once the dropdown is populated, wire up change listeners that
    // clear any stale status banner when the operator picks a new host
    // or duration. Prevents confusion where green "Maintenance set: X"
    // text lingers next to a freshly-selected Y the operator hasn't
    // committed yet.
    hostSelect.addEventListener('change', clearMaintenanceStatus);
    document.getElementById('maint-minutes').addEventListener('change', clearMaintenanceStatus);
  }
  // Refresh active list
  await refreshMaintenanceList();
}

function clearMaintenanceStatus() {
  const status = document.getElementById('status-bar-maint');
  status.style.display = 'none';
  status.textContent = '';
}

async function refreshMaintenanceList() {
  const listDiv = document.getElementById('maint-active-list');
  try {
    const res = await authFetch('/api/maintenance');
    const data = await res.json();
    const active = data.active || [];
    if (active.length === 0) {
      listDiv.innerHTML = '<div style="color:var(--textdim);padding:8px 0">No hosts currently in maintenance mode.</div>';
      return;
    }
    let html = '<table style="width:100%;border-collapse:collapse">';
    html += '<tr style="border-bottom:1px solid var(--border)">';
    html += '<th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Host</th>';
    html += '<th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Remaining</th>';
    html += '<th style="padding:6px 8px;color:var(--textdim);text-align:left;font-weight:normal">Set By</th>';
    html += '<th style="padding:6px 8px;text-align:right"></th>';
    html += '</tr>';
    active.forEach(h => {
      const mins = h.remaining_minutes;
      const safeHost = escapeHtml(h.host);
      html += '<tr style="border-bottom:1px solid var(--border)">';
      html += '<td style="padding:8px">' + safeHost + '</td>';
      html += '<td style="padding:8px;color:var(--red)">' + mins + 'm</td>';
      html += '<td style="padding:8px;color:var(--textdim)">' + escapeHtml(h.set_by || '') + '</td>';
      html += '<td style="padding:8px;text-align:right"><button class="btn btn-red maint-clear-btn" style="font-size:10px;padding:3px 10px" data-host="' + safeHost + '">Clear</button></td>';
      html += '</tr>';
    });
    html += '</table>';
    listDiv.innerHTML = html;
    // Wire up Clear buttons via event delegation. Using data-host +
    // addEventListener avoids inline-onclick string-escaping pitfalls
    // when host names contain quotes or other awkward characters.
    listDiv.querySelectorAll('.maint-clear-btn').forEach(btn => {
      btn.addEventListener('click', () => clearMaintenance(btn.dataset.host));
    });
  } catch (e) {
    listDiv.innerHTML = '<div style="color:var(--red);padding:8px 0">Failed to load maintenance status.</div>';
  }
}

function startMaintenanceRefresh() {
  stopMaintenanceRefresh();
  maintRefreshTimer = setInterval(refreshMaintenanceList, 30000);
}

function stopMaintenanceRefresh() {
  if (maintRefreshTimer) {
    clearInterval(maintRefreshTimer);
    maintRefreshTimer = null;
  }
}

async function setMaintenance() {
  const host = document.getElementById('maint-host').value;
  const minutes = parseInt(document.getElementById('maint-minutes').value);
  const status = document.getElementById('status-bar-maint');
  if (!host) {
    status.style.display = 'block';
    status.style.background = 'rgba(248,81,73,0.15)';
    status.style.color = 'var(--red)';
    status.textContent = 'Select a host first';
    return;
  }
  status.style.display = 'block';
  status.style.background = 'rgba(255,170,0,0.15)';
  status.style.color = 'var(--amber)';
  status.textContent = 'Setting maintenance...';
  try {
    const res = await authFetch('/api/maintenance/set', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({host, minutes})
    });
    const data = await res.json();
    if (data.ok) {
      status.style.background = 'rgba(0,255,136,0.15)';
      status.style.color = 'var(--green)';
      status.textContent = 'Maintenance set: ' + host + ' (' + minutes + 'm)';
      await refreshMaintenanceList();
    } else {
      status.style.background = 'rgba(248,81,73,0.15)';
      status.style.color = 'var(--red)';
      status.textContent = 'Failed: ' + (data.error || 'unknown error');
    }
  } catch (e) {
    status.style.background = 'rgba(248,81,73,0.15)';
    status.style.color = 'var(--red)';
    status.textContent = 'Failed: ' + e.message;
  }
}

async function clearMaintenance(host) {
  if (!confirm('Clear maintenance mode for ' + host + '? Alerts from this host will resume normal LLM triage immediately.')) {
    return;
  }
  try {
    const res = await authFetch('/api/maintenance/clear', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({host})
    });
    const data = await res.json();
    if (data.ok) {
      await refreshMaintenanceList();
    } else {
      alert('Failed to clear: ' + (data.error || 'unknown error'));
    }
  } catch (e) {
    alert('Failed to clear: ' + e.message);
  }
}

// ---------------------------------------------------------------------------
// Send Test Email — shells out to the email_sender.py smoke test (synthetic
// NOTIFY through the saved config) and shows its output. No streaming needed;
// the smoke test returns in seconds (15s SMTP timeout worst case).
// ---------------------------------------------------------------------------
async function testEmail() {
  const output = document.getElementById('test-email-output');
  output.style.display = 'block';
  output.textContent = '[ Sending test email through saved config... ]';
  try {
    const res = await authFetch('/api/test-email', { method: 'POST' });
    const data = await res.json();
    output.textContent = data.output || (data.ok ? '[ Sent ]' : '[ Failed - no output ]');
  } catch (e) {
    output.textContent = '[ Error: ' + e + ' ]';
  }
}

// Restart — systemctl restart + capture startup output, service status
// ---------------------------------------------------------------------------
async function restartService() {
  const output = document.getElementById('restart-output');
  output.style.display = 'block';
  output.textContent = '[ Restarting jrsoctriage.service... ]\\n[ Waiting for graceful drain (typically 30-90s, up to 3 min)... ]\\n';

  // Tick a counter every second so the operator sees the page is alive
  // during the silent gap between clicking Restart and the new instance
  // logging its first line. Without this, a 90-second wait looks like a
  // hung browser. We update a single line in place rather than appending
  // to keep the output readable once journalctl content arrives.
  const startTime = Date.now();
  let tickInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    // Replace the trailing "Waiting..." line with a live counter.
    const lines = output.textContent.split('\\n');
    // Find the "Waiting for graceful drain" line and update it. If
    // journalctl content has started arriving (more lines after it),
    // stop ticking — operator can now see real progress.
    const waitLineIdx = lines.findIndex(l => l.startsWith('[ Waiting'));
    const hasStreamingContent = waitLineIdx >= 0 && waitLineIdx < lines.length - 2;
    if (hasStreamingContent) {
      clearInterval(tickInterval);
      return;
    }
    if (waitLineIdx >= 0) {
      lines[waitLineIdx] = `[ Waiting for graceful drain (typically 30-90s, up to 3 min)... ${elapsed}s elapsed ]`;
      output.textContent = lines.join('\\n');
    }
  }, 1000);

  try {
    const res = await authFetch('/api/restart', { method: 'POST' });
    const reader = res.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      output.textContent += decoder.decode(value);
      output.scrollTop = output.scrollHeight;
    }
  } finally {
    clearInterval(tickInterval);
  }
}

async function serviceStatus() {
  const output = document.getElementById('restart-output');
  output.style.display = 'block';
  output.textContent = '[ Checking service status... ]';
  const res = await authFetch('/api/status');
  const data = await res.json();
  output.textContent += data.output;
}

// ---------------------------------------------------------------------------
// Lookup panel — reverse lookup anonymized aliases
// ---------------------------------------------------------------------------

let lookupData = null;

async function loadLookup() {
  const res = await authFetch('/api/lookup');
  lookupData = await res.json();
  renderLookupTable('lookup-hosts-table',   lookupData.hosts,   'hostname', 'alias');
  renderLookupTable('lookup-users-table',   lookupData.users,   'username', 'alias');
  renderLookupTable('lookup-domains-table', lookupData.domains, 'domain',   'alias');
  renderLookupTable('lookup-ips-table',     lookupData.ips,     'ip',       'alias');
}

function renderLookupTable(tableId, rows, realKey, aliasKey) {
  const table = document.getElementById(tableId);
  if (!table) return;
  // Remove old rows (keep header)
  while (table.rows.length > 1) table.deleteRow(1);
  (rows || []).forEach(row => {
    const tr = table.insertRow();
    tr.style.borderBottom = '1px solid var(--border)';
    const td1 = tr.insertCell(); td1.style.cssText = 'padding:5px 8px;color:var(--text)';
    const td2 = tr.insertCell(); td2.style.cssText = 'padding:5px 8px;color:var(--amber)';
    td1.textContent = row[realKey]  || '—';
    td2.textContent = row[aliasKey] || '—';
  });
  if (!rows || rows.length === 0) {
    const tr = table.insertRow();
    const td = tr.insertCell();
    td.colSpan = 2;
    td.style.cssText = 'padding:8px;color:var(--textdim);font-size:11px';
    td.textContent = 'No aliases configured';
  }
}

function runLookup() {
  const q = (document.getElementById('lookup-query')?.value || '').trim().toLowerCase();
  const el = document.getElementById('lookup-result');
  if (!el) return;
  if (!q || !lookupData) { el.textContent = ''; return; }

  const results = [];

  // Search hosts
  (lookupData.hosts || []).forEach(r => {
    if (r.hostname?.toLowerCase().includes(q) || r.alias?.toLowerCase().includes(q))
      results.push(`HOST: ${r.hostname} ↔ ${r.alias || '(no alias)'}`);
  });
  // Search users
  (lookupData.users || []).forEach(r => {
    if (r.username?.toLowerCase().includes(q) || r.alias?.toLowerCase().includes(q))
      results.push(`USER: ${r.username} ↔ ${r.alias || '(no alias)'}`);
  });
  // Search domains
  (lookupData.domains || []).forEach(r => {
    if (r.domain?.toLowerCase().includes(q) || r.alias?.toLowerCase().includes(q))
      results.push(`DOMAIN: ${r.domain} ↔ ${r.alias || '(no alias)'}`);
  });
  // Search IPs
  (lookupData.ips || []).forEach(r => {
    if (r.ip?.toLowerCase().includes(q) || r.alias?.toLowerCase().includes(q))
      results.push(`IP: ${r.ip} ↔ ${r.alias || '(no alias)'}`);
  });

  el.style.color = results.length ? 'var(--green)' : 'var(--textdim)';
  el.textContent = results.length ? results.join('  |  ') : 'No matches found';
}

// ---------------------------------------------------------------------------
// Users panel — manage web interface authentication
// ---------------------------------------------------------------------------

async function loadUsers() {
  const res = await authFetch('/api/auth/users');
  const data = await res.json();
  const container = document.getElementById('users-container');
  container.innerHTML = '';
  // data-username + event delegation avoids quoting hazards. Compare
  // to inline onclick="deleteUser('${username}')" which is dangerous
  // if a username contains apostrophes, quotes, or HTML metacharacters
  // — even when escaped, the layered HTML/JS decoding can re-introduce
  // problematic characters in the JS context.
  (data.users || []).forEach(u => {
    container.innerHTML += `
    <div class="card">
      <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
        <span>${escapeHtml(u.username)} ${u.role === 'admin' ? '<span style="color:var(--amber);font-size:10px">ADMIN</span>' : ''}</span>
        ${u.username !== currentUser ? `<button class="btn btn-red user-delete-btn" style="font-size:10px;padding:3px 10px" data-username="${escapeHtml(u.username)}">Remove</button>` : '<span style="color:var(--textdim);font-size:10px">current session</span>'}
      </div>
      <div style="font-size:12px;color:var(--textdim)">TOTP: ${u.totp_verified ? '<span style="color:var(--green)">verified</span>' : '<span style="color:var(--amber)">pending</span>'}</div>
    </div>`;
  });
  // Wire up Remove buttons via event delegation. The username comes
  // from data-username (decoded by browser, no JS injection risk).
  container.querySelectorAll('.user-delete-btn').forEach(btn => {
    btn.addEventListener('click', () => deleteUser(btn.dataset.username));
  });
}

function resetAddUserForm() {
  // Shared reset: opening the form and closing it both start from a
  // clean slate. Prevents the confusing post-success state where the
  // filled-in form and an active Create button sat below the QR,
  // inviting a resubmit that errored "already exists".
  document.getElementById('new_username').value = '';
  document.getElementById('new_password').value = '';
  document.getElementById('new_username').disabled = false;
  document.getElementById('new_password').disabled = false;
  document.getElementById('new-user-qr').style.display = 'none';
  document.getElementById('create-user-btn').style.display = '';
  document.getElementById('create-user-cancel-btn').style.display = '';
  document.getElementById('create-user-done-btn').style.display = 'none';
}

function addUser() {
  resetAddUserForm();
  document.getElementById('add-user-form').style.display = 'block';
}

function cancelAddUser() {
  resetAddUserForm();
  document.getElementById('add-user-form').style.display = 'none';
}

async function createUser() {
  // try/catch is load-bearing: authFetch THROWS on any non-2xx response
  // (e.g. a server 500). Without it the rejection vanishes into the
  // console and the button silently "does nothing".
  try {
    const username = document.getElementById('new_username').value.trim();
    const password = document.getElementById('new_password').value;
    if (!username || !password) { showStatus('[ERR] Username and password required', 'err', 'status-bar-users'); return; }
    const res = await authFetch('/api/auth/users', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action: 'add', username, password})
    });
    const data = await res.json();
    if (data.ok) {
      document.getElementById('new-user-qr').style.display = 'block';
      const img = document.getElementById('qr-image');
      if (data.qr_image) {
        img.style.display = '';
        img.src = data.qr_image;
      } else {
        // Server created the user but couldn't render the QR PNG
        // (missing Pillow). The manual key still enrolls.
        img.style.display = 'none';
      }
      document.getElementById('totp-secret-display').value = data.totp_secret;
      // Lock the form: creation happened. The only action left is Done
      // (which resets and closes). Without this, the still-active
      // Create button below the QR invited a resubmit that errored
      // "Username already exists".
      document.getElementById('new_username').disabled = true;
      document.getElementById('new_password').disabled = true;
      document.getElementById('create-user-btn').style.display = 'none';
      document.getElementById('create-user-cancel-btn').style.display = 'none';
      document.getElementById('create-user-done-btn').style.display = '';
      const note = data.qr_image
        ? '[OK] User created — have them scan the QR code, then click Done'
        : '[OK] User created — ' + (data.qr_error || 'use the manual secret key');
      showStatus(note, 'ok', 'status-bar-users');
      loadUsers();
    } else {
      showStatus('[ERR] ' + data.error, 'err', 'status-bar-users');
    }
  } catch (e) {
    showStatus('[ERR] Create failed: ' + e.message, 'err', 'status-bar-users');
  }
}

async function deleteUser(username) {
  if (!confirm(`Remove user "${username}"?`)) return;
  const res = await authFetch('/api/auth/users', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: 'delete', username})
  });
  const data = await res.json();
  showStatus(data.ok ? '[OK] User removed' : '[ERR] ' + data.error, data.ok ? 'ok' : 'err', 'status-bar-users');
  if (data.ok) loadUsers();
}

let currentUser = '';

// ---------------------------------------------------------------------------
// Init — load config on page load
// ---------------------------------------------------------------------------
loadConfig();
authFetch('/api/auth/me').then(r => r.json()).then(d => { currentUser = d.username || ''; }).catch(() => {});

// Initialize scroll buttons visibility for the default-active panel.
// The Config panel is active by default (set in HTML), but showPanel()
// is the function that controls scroll-btns display state, and it does
// not run on initial page load — it only fires when the operator clicks
// a nav button. So on a fresh page load (or hard refresh), the scroll
// buttons stay at their initial inline display:none even though Config
// is one of the panels that should show them.
//
// This caused an intermittent "arrows present 30% of the time" symptom:
// arrows appeared after clicking any other tab and back, but were
// missing on fresh page loads where the operator stayed on Config.
//
// Crucial detail: this <script> tag lives BEFORE the scroll-btns div
// in the HTML, so getElementById('scroll-btns') returns null at script
// execution time. We must defer to DOMContentLoaded so the element
// exists in the DOM before we touch it. (loadConfig and the auth/me
// fetch above don't have this problem because they manipulate elements
// that are inside the panel divs which DO precede this script.)
//
// Hardcoding 'flex' here is correct because Config is in the list of
// scrollPanels in showPanel(). If the default-active panel ever
// changes, this should match that panel's behavior.
document.addEventListener('DOMContentLoaded', () => {
  const _initialScrollBtns = document.getElementById('scroll-btns');
  if (_initialScrollBtns) _initialScrollBtns.style.display = 'flex';
});

// ---------------------------------------------------------------------------
// Session liveness check — protects against stale data on unattended screens
// ---------------------------------------------------------------------------
//
// The 30-minute idle timeout invalidates the server-side session, but a
// browser tab still displays whatever was rendered before. An attacker
// with physical access to an unattended screen could read sensitive data
// (host inventory, rule notes, anonymization mappings) even though they
// could not modify anything.
//
// Server restart has the same exposure: secret_key regenerates, the old
// cookie is dead, but the browser keeps showing the previous session's
// data until the operator interacts with it.
//
// Two complementary checks close this gap:
//
//   1. Every 30 seconds, ping /api/auth/check. If the session is dead,
//      authFetch returns 401, which redirects to /login automatically.
//      Worst-case data exposure = 30 seconds of passive viewing.
//
//   2. When the tab regains focus or becomes visible (operator returns
//      to the keyboard, switches back from another window, etc.), check
//      immediately. Catches the most common scenario instantly.
//
// CRITICAL: /api/auth/check is a PASSIVE endpoint that does NOT bump
// last_activity. We deliberately use it instead of /api/auth/me because
// auth/me goes through @require_auth, which touches last_activity on
// every successful authenticated request. A heartbeat to auth/me would
// reset the idle timer every 30 seconds and effectively disable the
// idle timeout — defeating the timeout's purpose. Always use
// auth/check for liveness pings, never auth/me.
//
// authFetch handles the redirect on 401, so we just call it and ignore
// successes. Failures during navigation away are expected and harmless.

// 5 seconds: this is both the session-death detection bound AND the
// outage detection bound for an idle page (the operator expectation is
// "the page locks within ~5s of the interface dying"). The werkzeug
// request-log noise this would generate (12 lines/min/tab) is filtered
// server-side — see _KeepaliveLogFilter in the Python.
const SESSION_CHECK_INTERVAL_MS = 5000;

function checkSessionLiveness() {
  // Use auth/check (passive) NOT auth/me (active). See note above.
  authFetch('/api/auth/check').catch(() => {});
}

setInterval(checkSessionLiveness, SESSION_CHECK_INTERVAL_MS);

// Check immediately when the operator returns to the tab.
window.addEventListener('focus', checkSessionLiveness);
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) checkSessionLiveness();
});
</script>
  <div class="scroll-btns" id="scroll-btns" style="display:none">
    <button class="scroll-btn" onclick="window.scrollTo({top:0,behavior:'smooth'})" title="Top">▲</button>
    <button class="scroll-btn" onclick="window.scrollTo({top:document.body.scrollHeight,behavior:'smooth'})" title="Bottom">▼</button>
  </div>

</body>
</html>"""


# ---------------------------------------------------------------------------
# File helpers — load/save JSON, resolve all config file paths
# ---------------------------------------------------------------------------

def get_paths(config_path):
    """Load config and return all file paths."""
    try:
        with open(config_path) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}

    paths = cfg.get("paths", {})
    base = str(Path(config_path).parent)

    return {
        "config":    config_path,
        "hosts":     paths.get("hosts_file",        f"{base}/hosts.json"),
        "roles":     paths.get("roles_file",         f"{base}/roles.json"),
        "rules":     paths.get("rules_file",         f"{base}/rules.json"),
        "anon":      paths.get("anonymization_file", f"{base}/anonymization.json"),
        "users":     paths.get("users_file",         f"{base}/users.json"),
        "domains":   paths.get("domain_file",        f"{base}/domain.json"),
        "ip_aliases": paths.get("ip_aliases_file",   f"{base}/ip_aliases.json"),
    }


def load_json(path, default=None):
    """Load JSON from disk with a typed default fallback.

    Returns the file contents on success. On failure (missing, corrupt,
    or unreadable), returns the default with an _error key inserted IF
    the default is a dict. If the default is a list (or any non-dict),
    returns the default as-is — the caller already knows what shape they
    want, and adding an _error key isn't possible.
    """
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        if isinstance(default, dict):
            return {"_error": f"File not found: {path}", **default}
        return default if default is not None else {}
    except json.JSONDecodeError as e:
        if isinstance(default, dict):
            return {"_error": f"JSON parse error in {path}: {e}", **default}
        return default if default is not None else {}
    except Exception as e:
        if isinstance(default, dict):
            return {"_error": str(e), **default}
        return default if default is not None else {}


def save_json(path, data):
    """Write JSON to disk atomically and lock down file permissions.

    All jrSOCtriage state files (config.json, hosts.json, rules.json,
    users.json, domain.json, ip_aliases.json, anonymization.json) are
    written through this function. Mode 600 ensures only the file owner
    (typically root, since the pipeline runs as root) can read or modify
    them. This protects:
      - Credentials (config.json: API keys, SMTP/ntopng/Graylog passwords)
      - Operational integrity (hosts.json, rules.json: an attacker who
        could modify these would silently degrade LLM triage quality
        without triggering errors)
      - Anonymization mappings (users/domain/ip_aliases.json: identify
        real names from aliases, useful to an attacker reconnoitering)

    Permission failures are logged but don't abort the write — losing
    the perm tightening is less bad than losing the data the operator
    just tried to save. The startup integrity check will flag it.

    Atomicity: writes to a sibling tmp file, fsyncs, chmods 600, then
    renames atomically over the destination. A crash mid-write leaves
    the original file intact rather than a half-written or empty file
    that breaks the next pipeline restart. The tmp file is best-effort
    cleaned up on failure paths so we don't accumulate .tmp leftovers
    in the install directory.
    """
    tmp = f"{path}.tmp"
    # Strip the _error transport key before writing. load_json() injects
    # _error into GET responses for missing/corrupt files so the UI can
    # show a banner; if a tab's save path posts the loaded object back,
    # the key would otherwise be persisted into the state file and
    # resurface in every future GET as a stale "error". It is UI-transport
    # vocabulary, never valid state.
    if isinstance(data, dict):
        data.pop("_error", None)
    try:
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError as e:
            # Logger isn't always set up at this point; print is safe.
            print(f"WARNING: could not chmod 600 on {tmp}: {e}")
        os.replace(tmp, path)
    except Exception:
        # Best-effort tmp cleanup so a write failure doesn't leave
        # path.tmp lying around.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def get_request_json_or_error():
    """Validate that the incoming request has a parseable JSON body.

    Returns (data, error_response). On success, error_response is None.
    On failure, error_response is a Flask response with HTTP 400.

    Defends against:
      - POST with no body: request.json is None, a downstream save would
        write literal `null` to disk and corrupt the state file.
      - POST with non-JSON Content-Type: request.json raises BadRequest;
        we catch and return a clean 400 instead of leaking a stack trace.
      - POST with malformed JSON: same as above.
      - POST with valid JSON but a non-object root (e.g. a bare number
        or string): pass-through is allowed since some routes legitimately
        accept arrays (rules.json) — the route's own validation handles
        deeper structure checks.
    """
    try:
        data = request.get_json(silent=False)
    except Exception:
        return None, (jsonify({"ok": False, "error": "Request body must be valid JSON"}), 400)
    if data is None:
        return None, (jsonify({"ok": False, "error": "Request body is empty or not JSON"}), 400)
    return data, None


# ---------------------------------------------------------------------------
# Auth routes — login, logout
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_authenticated():
        return redirect("/")
    error = None
    if request.method == "POST":
        # Rate-limit by (client IP, username). We use request.remote_addr
        # directly rather than trusting X-Forwarded-For — anyone can spoof
        # that header, and for a typical lab deployment without a trusted
        # reverse proxy, remote_addr is the right source. The username is
        # part of the key because tunneled users all share 127.0.0.1 — see
        # the keying note at the rate-limit constants.
        client_ip = request.remote_addr or "unknown"
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        totp     = request.form.get("totp", "").strip()
        rate_key = _login_rate_key(client_ip, username)
        allowed, rl_msg = _check_login_rate_limit(rate_key)
        if not allowed:
            return render_template_string(LOGIN_HTML, error=rl_msg)

        ok, msg  = verify_login(username, password, totp)
        _record_login_result(rate_key, ok)
        if ok:
            # totp_verified backfill: a successful login IS proof the
            # authenticator works (verify_login requires a valid code),
            # so the flag becomes truthful — "has completed at least one
            # TOTP login". Best-effort: a failed save must never block a
            # valid login, so failures only warn.
            try:
                auth_data = load_auth()
                for u in auth_data.get("users", []):
                    if u["username"] == username and not u.get("totp_verified", False):
                        u["totp_verified"] = True
                        save_auth(auth_data)
                        break
            except Exception as e:
                logger.warning(f"totp_verified backfill failed for {username}: {e}")
            # Clear any pre-existing session contents before promoting to
            # authenticated. This defends against session fixation: an
            # attacker who set a known session ID on the victim's browser
            # before login (e.g., via a crafted link or a stale shared
            # device) would otherwise end up sharing the authenticated
            # session afterward. session.clear() forces Flask to issue a
            # fresh signed session cookie, so the attacker's pre-set ID
            # is no longer valid.
            session.clear()
            session["authenticated"] = True
            session["username"]      = username
            # Initialize idle timer on login. Subsequent authenticated
            # requests bump this via _touch_session() in require_auth.
            session["last_activity"] = datetime.now(timezone.utc).isoformat()
            # Flagged accounts land directly on the change form; the
            # require_auth gate would bounce them there anyway, this just
            # skips the intermediate redirect.
            fresh = get_user(username)
            if fresh and fresh.get("force_password_change", False):
                return redirect("/change-password")
            return redirect("/")
        error = msg
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/logout", methods=["POST"])
def logout():
    """Log out the current session.

    POST-only by design. Allowing logout via GET would let an attacker
    log a user out via a crafted link or img tag (CSRF on logout). Not
    destructive — they just get redirected to login next time they use
    the GUI — but annoying enough to warrant the small POST conversion.
    """
    session.clear()
    return redirect("/login")


CHANGE_PASSWORD_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>jrSOCtriage — Change Password</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #161b22; border: 1px solid #21262d; border-radius: 8px;
            padding: 40px; width: 360px; }
    .logo { font-family: monospace; font-size: 13px; color: #3fb950; letter-spacing: 2px;
            text-transform: uppercase; margin-bottom: 8px; }
    .subtitle { color: #8b949e; font-size: 12px; margin-bottom: 32px; }
    label { display: block; font-size: 12px; color: #8b949e; margin-bottom: 6px;
            text-transform: uppercase; letter-spacing: 1px; }
    input { width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 4px;
            color: #c9d1d9; font-size: 14px; padding: 10px 12px; margin-bottom: 20px; }
    input:focus { outline: none; border-color: #3fb950; }
    button { width: 100%; background: #238636; border: none; border-radius: 4px;
             color: #fff; font-size: 14px; font-weight: 600; padding: 12px;
             cursor: pointer; letter-spacing: 1px; }
    button:hover { background: #2ea043; }
    .error { background: rgba(248,81,73,0.1); border: 1px solid rgba(248,81,73,0.4);
             border-radius: 4px; color: #f85149; font-size: 13px; padding: 10px 12px;
             margin-bottom: 20px; }
    .notice { background: rgba(63,185,80,0.08); border: 1px solid rgba(63,185,80,0.35);
              border-radius: 4px; color: #3fb950; font-size: 13px; padding: 10px 12px;
              margin-bottom: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">jrSOCtriage</div>
    <div class="subtitle">Change password — {{ username }}</div>
    {% if forced %}<div class="notice">An administrator requires you to set a new
    password before continuing.</div>{% endif %}
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST">
      <label>Current password</label>
      <input type="password" name="current_password" required autofocus>
      <label>New password</label>
      <input type="password" name="new_password" required>
      <label>Confirm new password</label>
      <input type="password" name="confirm_password" required>
      <button type="submit">Change Password</button>
    </form>
  </div>
</body>
</html>"""


@app.route("/change-password", methods=["GET", "POST"])
@require_auth
def change_password():
    """Change the logged-in user's password.

    Serves two purposes with one form:
      - Voluntary rotation for any user, any time.
      - The enforcement mechanism for force_password_change: the
        require_auth gate funnels flagged users here (this path and
        /logout are its only exemptions), and a successful change
        clears the flag.

    Safety properties (deliberate — see the lockout analysis in the
    v1.0 audit record):
      - Complexity rules apply only to the NEW password. A legacy
        password that predates the complexity code keeps working for
        login and is accepted as the "current password" here; it is
        never retroactively judged.
      - The swap is a single atomic save_auth; there is no state where
        neither password works.
      - Requires the current password even though the user is already
        authenticated — an unattended logged-in browser can't be used
        to silently take over the account.
    """
    username = session.get("username", "")
    user = get_user(username)
    if user is None:
        session.clear()
        return redirect("/login")
    forced = user.get("force_password_change", False)
    error = None
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new     = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not bcrypt.checkpw(current.encode(), user["password_hash"].encode()):
            error = "Current password is incorrect."
        else:
            ok, msg = _check_password_complexity(new)
            if not ok:
                error = msg
            elif new == current:
                # Reusing the current password defeats the purpose of the
                # rotation — for forced changes the current password is
                # the admin-chosen temporary one, and "changed" must mean
                # the admin no longer knows it. Plain string compare is
                # exact here: `current` was just verified against the
                # stored hash. (No password history beyond this — only
                # the immediate reuse is blocked.)
                error = "New password must be different from the current password."
            elif new != confirm:
                error = "New passwords do not match."
            else:
                auth_data = load_auth()
                for u in auth_data.get("users", []):
                    if u["username"] == username:
                        u["password_hash"] = bcrypt.hashpw(
                            new.encode(), bcrypt.gensalt()).decode()
                        u["force_password_change"] = False
                        break
                save_auth(auth_data)
                logger.info(f"Password changed for user:{username}"
                            f"{' (forced rotation)' if forced else ''}")
                return redirect("/")
    return render_template_string(CHANGE_PASSWORD_HTML, username=username,
                                  forced=forced, error=error)


# ---------------------------------------------------------------------------
# API Routes — REST endpoints for all config files + service control
# ---------------------------------------------------------------------------

CONFIG_PATH = DEFAULT_CONFIG


FAVICON_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="8" fill="#0a0e12"/>
  <text x="32" y="46" font-family="monospace" font-size="40" font-weight="900" fill="#00ff88" text-anchor="middle">jr</text>
</svg>'''


@app.route("/favicon.svg")
def favicon_svg():
    return Response(FAVICON_SVG, mimetype="image/svg+xml")


@app.route("/favicon.ico")
def favicon_ico():
    # Some browsers still request /favicon.ico — redirect to SVG.
    return Response(FAVICON_SVG, mimetype="image/svg+xml")


@app.route("/")
@require_auth
def index():
    return render_template_string(HTML)


@app.route("/api/config", methods=["GET", "POST"])
@require_auth
def api_config():
    paths = get_paths(CONFIG_PATH)
    if request.method == "GET":
        data = load_json(paths["config"])
        # Merge with defaults so missing fields are populated in the UI.
        # User values always win; defaults only fill gaps.
        defaults = _default_config_template()
        merged = _deep_merge(defaults, data)
        return jsonify(merged)
    try:
        data, err = get_request_json_or_error()
        if err:
            return err
        # Minimal v1.0 server-side guard for the small set of fields where
        # we've seen client-side bugs cause silent value corruption (the
        # JS-falsy-coercion class — `0 || 6` returning 6, etc.). This is
        # intentionally narrow: we only reject NaN / null / wrong-type
        # values on fields where `0` is operationally meaningful, and we
        # fall back to a safe default for that single field rather than
        # rejecting the whole save. Other fields pass through unchanged
        # so this guard never blocks a legitimate save.
        #
        # A proper schema-validation module is on the v1.1 roadmap and
        # will replace this. Treat this as a load-bearing comment: when
        # validation.py lands, delete this block entirely.
        _coerce_critical_int(data, "filtering", "min_rule_level", default=6, lo=0, hi=15)
        _coerce_critical_int(data, "processing", "dedup_silence_seconds", default=240, lo=0, hi=86400)
        _coerce_critical_int(data, "filtering", "abuse_escalation_threshold", default=50, lo=0, hi=100)
        _coerce_critical_int(data, "processing", "min_baseline_days", default=3, lo=0, hi=365)
        _coerce_critical_int(data, "filtering", "first_seen_lookback_days", default=14, lo=0, hi=365)
        # observability.lag_log_interval_seconds: 0 is operationally
        # meaningful (disables lag emission). Guard against JS-falsy
        # coercion turning a deliberate 0 into the default 30.
        _coerce_critical_int(data, "observability", "lag_log_interval_seconds", default=30, lo=0, hi=3600)
        save_json(paths["config"], data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


def _coerce_critical_int(data, section, key, default, lo, hi):
    """
    Validate one critical integer field in `data[section][key]`. If the
    value is not a valid int in [lo, hi], replace it with `default` and
    log a warning. Mutates `data` in place. Missing section/key is a
    no-op (don't manufacture sections that didn't exist on the wire).

    `default` should match the value used in the load-side JS for the
    same field, so a coerced save round-trips to the same display.

    Why narrow scope rather than full validation? See the comment in
    api_config above — this is a v1.0 stopgap targeting a known bug
    class. v1.1 replaces it with a real validation module.
    """
    section_dict = data.get(section)
    if not isinstance(section_dict, dict):
        return
    if key not in section_dict:
        return
    raw = section_dict[key]
    try:
        coerced = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            f"api_config: {section}.{key}={raw!r} is not a valid int; "
            f"using default {default}"
        )
        section_dict[key] = default
        return
    if coerced < lo or coerced > hi:
        logger.warning(
            f"api_config: {section}.{key}={coerced} is outside "
            f"valid range [{lo}, {hi}]; using default {default}"
        )
        section_dict[key] = default
        return
    # Coerced value is valid — write it back as int (in case JS sent a
    # string that happens to parse as a valid int)
    section_dict[key] = coerced


def _deep_merge(defaults, user):
    """Deep merge user dict over defaults. User values always win."""
    if not isinstance(user, dict):
        return user if user is not None else defaults
    result = dict(defaults) if isinstance(defaults, dict) else {}
    for key, default_val in (defaults or {}).items():
        if key in user:
            if isinstance(default_val, dict) and isinstance(user[key], dict):
                result[key] = _deep_merge(default_val, user[key])
            else:
                result[key] = user[key]
        else:
            result[key] = default_val
    # Include user keys not in defaults
    for key, val in user.items():
        if key not in result:
            result[key] = val
    return result


def _detect_host_tz():
    """
    Return (offset_hours, tz_name) for the host's local timezone.

    Used to populate the default timezone fields in the config template
    so a fresh install on EST/PST/GMT/JST/etc. doesn't start with a
    Central-Time bias. Falls back to UTC offset 0 / "UTC" if the host
    timezone is unavailable for any reason.

    Note that runtime code in zeek_fetch.py defaults to None and uses
    datetime.astimezone() at call time when zeek_local_tz_offset is
    missing from config, so this helper only affects what new
    installations see in the UI.
    """
    try:
        now_local = datetime.now().astimezone()
        offset = now_local.utcoffset()
        if offset is None:
            return 0, "UTC"
        offset_hours = int(offset.total_seconds() // 3600)
        # tzname() returns the abbreviation if available (e.g. "CST",
        # "EDT", "JST"). May return numeric offset like "+05:30" on some
        # systems; fall back to "local" in that case for readability.
        tz_name = now_local.tzname() or "local"
        if tz_name.startswith(("+", "-")) or ":" in tz_name:
            tz_name = "local"
        return offset_hours, tz_name
    except Exception:
        return 0, "UTC"


def _default_config_template():
    """Return the default config template used for merging and /api/config/default.

    Path defaults are absolute, computed from the install directory
    (where this interface.py lives). This matches what get_paths()
    does at runtime when a config has no explicit paths set, and
    keeps the displayed defaults consistent with what the runtime
    would actually use. An operator who clicks Save without editing
    the path fields persists working absolute paths to config.json
    rather than relative paths that depend on the process's current
    working directory.

    Operators who want to relocate jrSOCtriage's working files (e.g.
    onto a different volume) edit the path fields in the UI and Save.
    """
    tz_offset, tz_name = _detect_host_tz()
    install_dir = os.path.dirname(os.path.abspath(__file__))
    return {
        "deployment": {"org": "", "security_domain": ""},
        "wazuh_api": {"url": "", "username": "", "password": "", "dns_server": "", "verify_ssl": True},
        "sources": {
            "wazuh": {"enabled": True, "alerts_file": "/mnt/appdata/jrsoctriage/alerts.json"},
            "zeek": {"enabled": True, "current_log_dir": "/opt/zeek/logs/current", "archive_log_dir": ""},
            "ntopng": {"enabled": False, "endpoint": "http://127.0.0.1:3001", "ifid": 0,
                       "verify_ssl": True,
                       "skip_networks": [],
                       "auth": {"username": "admin", "password": ""}},
            "graylog": {"enabled": False, "endpoint": "http://127.0.0.1:9000",
                        "context_window_minutes": 0.5, "max_results": 100, "verify_ssl": True,
                        "auth": {"username": "admin", "password": ""}}
        },
        "processing": {
            "poll_interval_seconds": 30, "max_batch_size": 250,
            "dedup_silence_seconds": 240, "baseline_multiplier": 2.0,
            "min_baseline_days": 3, "escalation_multiplier": 4.0,
            "max_workers": 1,
            "sensor_agent_names": ["wazuh.manager", "wazuh-manager", "suricata"]
        },
        "filtering": {
            "min_rule_level": 6, "abuse_escalation_threshold": 50,
            "escalate_first_seen_rule": True, "first_seen_lookback_days": 14,
            "frequency_escalation_enabled": True,
            "always_include": {"networks": [], "hosts": []}
        },
        "enrichment": {
            "enable_host_lookup": True, "enable_network_lookup": True,
            "geo_ip": {"enabled": True, "provider": "ip-api.com", "skip_private": True},
            "whois": {"enabled": True, "skip_private": True},
            "rdns": {"enabled": True, "skip_private": False},
            "abuseipdb": {"enabled": False, "api_key": "", "score_threshold": 25, "skip_private": True},
            "cisa_kev": {"enabled": False},
            "greynoise": {"enabled": False, "api_key": "", "skip_private": True, "rate_limit_warnings": True},
            "epss": {"enabled": False},
            "virustotal": {"enabled": False, "api_key": "", "per_alert_cap": 4, "skip_private": True, "rate_limit_warnings": False},
            "otx": {"enabled": False, "api_key": "", "skip_private": True, "rate_limit_warnings": False}
        },
        "llm": {
            "enabled": True, "strategy": "round_robin",
            "endpoints": []
        },
        "email": {
            "enabled": False, "smtp_host": "smtp.gmail.com", "smtp_port": 587,
            "use_tls": True, "smtp_security": "starttls", "username": "", "password": "",
            "from_address": "", "to_address": "", "note_address": "",
            "subject_prefix": "[jrSOC ALERT]",
            "subject_prefix_notify": "[jrSOC ALERT]",
            "subject_prefix_note": "[jrSOC NOTE]",
            "min_confidence_to_email": "MEDIUM", "min_confidence_to_note": "LOW"
        },
        "output": {"graylog": {"enabled": False, "host": "127.0.0.1", "port": 12201}},
        "prompt_customization": {
            "strip_redundant_fields": True,
            "sensor_context": [
                "Suricata is running on a SPAN/mirror port",
                "SPAN sensors may generate TCP anomaly alerts (invalid ACK, RST, checksum errors) due to packet capture artifacts rather than actual malicious activity",
                "TCP stream alerts at Priority 3 on SPAN deployments should be weighted accordingly for TCP-level anomalies only \u2014 application-layer protocol failures (Applayer alerts) from external IPs with high abuse scores or suspicious rdns should not be dismissed as SPAN artifacts.",
                "Flow direction on SPAN may not always reflect true initiator \u2014 however this does not apply to clearly directional inbound connections from external IPs to DMZ hosts.",
                "Wazuh agents report from individual hosts; alerts without src/dst IP are host-local events",
                "Wazuh rootcheck rule 510 is a known false positive source on modern Linux \u2014 generic signatures match legitimate PAM library references in standard system binaries such as /bin/passwd, /bin/ls, and /usr/bin/ls. Verify with dpkg -V or rpm -V before acting.",
            ],
            "network_notes": [],
            "triage_guidance": [
                "The SPAN artifact explanation does not apply when the source IP has a high abuse score or known malicious rdns. Treat application-layer protocol anomalies from suspicious external IPs as potentially intentional evasion, not sensor noise.",
                "ntopng L7 protocol labels (e.g., TLS.Azure, HTTP.Google) reflect the destination service infrastructure, not the source intent. When alert is about an external ip - always cross-reference external IP rdns and abuse score before using L7 labels to justify a SUPPRESS verdict on inbound external connections. ntopng data is realtime — flows shown reflect current activity at prompt-build time, not necessarily what was happening at alert time. For Wazuh syscheck (FIM) alerts, the actual file change may have occurred minutes before the alert was emitted, and ntopng flows visible now may be unrelated to the event. Use Zeek connection records or host logs as primary evidence for time-of-event correlation; treat ntopng as supporting context for current-state assessment.",
            ],
        },
        "timezone": {"zeek_local_tz_offset": tz_offset, "zeek_local_tz_name": tz_name},
        "logging": {"level": "info", "log_file": os.path.join(install_dir, "jrsoc.log"), "prompt_log_mode": "anonymized", "debug_llm_payload": False},
        "observability": {
            # Periodic pipeline-health snapshot emitter. Writes one [LAG] line
            # to the main jrSOCtriage log every N seconds with queue depth,
            # oldest-queued age, last-processed age, cycle duration, LLM
            # in-flight count, and rolling LLM latency mean. 0 disables.
            # 30s is the recommended default — fine-grained enough to catch
            # surge behavior, coarse enough to avoid log bloat.
            "lag_log_interval_seconds": 30
        },
        "interface": {
            "session_timeout_minutes": 30
        },
        "database": {
            # When false, jrSOCtriage runs fully stateless: no DB
            # writes (no alert history, no escalation log), and all
            # DB reads fail open (no baseline frequency context,
            # rule rate-limiting and maintenance-mode suppression
            # disabled). In-memory dedup is UNAFFECTED — core noise
            # suppression still works. Because there is no write
            # path, DB-related failure modes are removed entirely.
            # Recommended for high-alert-volume deployments that
            # prefer to remove DB write pressure as a reliability
            # variable. Expect higher LLM call volume (rate-limit fails
            # open). Default true (stateful, full features).
            "enabled": True
        },
        "paths": {
            "hosts_file":         os.path.join(install_dir, "hosts.json"),
            "rules_file":         os.path.join(install_dir, "rules.json"),
            "db_file":            os.path.join(install_dir, "jrsoc.db"),
            "users_file":         os.path.join(install_dir, "users.json"),
            "domain_file":        os.path.join(install_dir, "domain.json"),
            "anonymization_file": os.path.join(install_dir, "anonymization.json"),
            "ip_aliases_file":    os.path.join(install_dir, "ip_aliases.json"),
            "position_file":      os.path.join(install_dir, ".ingest_position"),
        }
    }


@app.route("/api/genpaths")
@require_auth
def api_genpaths():
    """Return auto-generated paths based on running directory."""
    base = str(Path(CONFIG_PATH).parent)
    return jsonify({
        "hosts_file":         f"{base}/hosts.json",
        "rules_file":         f"{base}/rules.json",
        "db_file":            f"{base}/jrsoc.db",
        "users_file":         f"{base}/users.json",
        "domain_file":        f"{base}/domain.json",
        "anonymization_file": f"{base}/anonymization.json",
        "ip_aliases_file":    f"{base}/ip_aliases.json",
        "position_file":      f"{base}/.ingest_position",
        "log_file":           f"{base}/jrsoc.log",
    })


@app.route("/api/config/default")
@require_auth
def api_config_default():
    """Return a complete default config template."""
    template = _default_config_template()
    # Include a sample endpoint for discoverability
    template["llm"]["endpoints"] = [
        {"name": "primary", "enabled": True, "url": "http://127.0.0.1:11434",
         "model": "gemma4:26b", "type": "ollama", "priority": 1,
         "timeout_seconds": 60, "keep_alive": -1, "max_concurrent": 1,
         "anonymize": False}
    ]
    return jsonify(template)


@app.route("/api/hosts", methods=["GET", "POST"])
@require_auth
def api_hosts():
    paths = get_paths(CONFIG_PATH)
    if request.method == "GET":
        return jsonify(load_json(paths["hosts"], {"hosts": [], "networks": []}))
    try:
        data, err = get_request_json_or_error()
        if err:
            return err
        save_json(paths["hosts"], data)
        # Keep roles.json in sync: every role referenced by a host must
        # exist in roles.json. Saving hosts ensures (idempotently) a blank
        # stub for any newly-referenced role, so a host and its role entry
        # come into existence together and the two files can't desync.
        # Existing roles (and their authored description/notes) are left
        # untouched — this only ADDS missing names, never blanks present ones.
        new_roles = _ensure_role_stubs(paths["roles"], data)
        return jsonify({"ok": True, "new_roles": new_roles})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


def _host_role_names(hosts_data):
    """Collect the set of role names referenced across all hosts. A host's
    `role` may be a single string or a list of strings (multi-role)."""
    names = set()
    for h in (hosts_data or {}).get("hosts", []):
        role = h.get("role")
        if isinstance(role, list):
            for r in role:
                if isinstance(r, str) and r.strip():
                    names.add(r.strip())
        elif isinstance(role, str) and role.strip():
            names.add(role.strip())
    return names


def _ensure_role_stubs(roles_path, hosts_data):
    """Ensure roles.json has an entry for every role referenced by a host.
    Idempotent: existing roles are matched case-insensitively by name and
    left completely untouched (description/notes preserved); only genuinely
    missing names are appended as blank stubs (description+notes empty →
    they show as 'New' on the Roles tab until the operator fills them in).
    Returns the list of role names newly created this call (for notifying
    the operator to go fill them out), empty if none."""
    referenced = _host_role_names(hosts_data)
    if not referenced:
        return []
    roles_doc = load_json(roles_path, {"roles": []})
    if not isinstance(roles_doc, dict):
        roles_doc = {"roles": []}
    existing = roles_doc.get("roles", [])
    existing_lower = {
        (r.get("name") or "").strip().lower()
        for r in existing if isinstance(r, dict)
    }
    new_names = []
    for name in referenced:
        if name.lower() not in existing_lower:
            existing.append({"name": name, "description": "", "notes": ""})
            existing_lower.add(name.lower())
            new_names.append(name)
    if new_names:
        roles_doc["roles"] = existing
        save_json(roles_path, roles_doc)
    return new_names


@app.route("/api/wazuh/import-preview", methods=["POST"])
@require_auth
def api_wazuh_import_preview():
    """
    Fetch the Wazuh agent list and classify it against DNS + hosts.json into
    the four import buckets (already_in / addable / ip_mismatch / name_mismatch).

    Thin plumbing by design: this route loads config + hosts and calls
    wazuh_import.import_preview(); ALL Wazuh-API, DNS-verification, and
    classification logic lives in wazuh_import.py (the single Wazuh-API
    boundary). The module is imported lazily so a deployment without it (or an
    import error) can't break interface startup — the feature is independently
    optional.

    Returns {"ok": True, "result": {...}} on success, or
    {"ok": False, "error": "..."} with a human-readable message on failure
    (invalid credentials, can't connect, etc.) for the UI to display.
    """
    paths = get_paths(CONFIG_PATH)
    try:
        import wazuh_import
    except Exception as e:  # pragma: no cover - defensive
        return jsonify({"ok": False,
                        "error": f"Wazuh import module unavailable: {e}"})
    config = load_json(paths["config"], {})
    hosts = load_json(paths["hosts"], {"hosts": [], "networks": []})
    result, err = wazuh_import.import_preview(config, hosts)
    if err:
        return jsonify({"ok": False, "error": err})
    return jsonify({"ok": True, "result": result})


@app.route("/api/wazuh/renumber-preview", methods=["POST"])
@require_auth
def api_wazuh_renumber_preview():
    """
    Compare hosts.json STORED IPs against current Wazuh-agent + DNS consensus
    and return the renumber classification (drifted / unchanged / skipped).

    Different question than import-preview: this checks the IP STORED in
    hosts.json against what the agent and DNS now agree on, catching stale
    pinned IPs the import misses. Thin plumbing — all logic in wazuh_import.

    Body: {"include_blank": bool} — when true, also examine blank hosts (offer
    to PIN ones with a stable consensus IP); default false (skip blank, they
    trivially differ and are already renumber-safe).
    """
    paths = get_paths(CONFIG_PATH)
    try:
        import wazuh_import
    except Exception as e:  # pragma: no cover - defensive
        return jsonify({"ok": False,
                        "error": f"Wazuh import module unavailable: {e}"})
    body = request.get_json(silent=True) or {}
    include_blank = bool(body.get("include_blank", False))
    config = load_json(paths["config"], {})
    hosts = load_json(paths["hosts"], {"hosts": [], "networks": []})
    result, err = wazuh_import.renumber_preview(config, hosts,
                                                include_blank=include_blank)
    if err:
        return jsonify({"ok": False, "error": err})
    return jsonify({"ok": True, "result": result})


@app.route("/api/roles", methods=["GET", "POST"])
@require_auth
def api_roles():
    paths = get_paths(CONFIG_PATH)
    if request.method == "GET":
        return jsonify(load_json(paths["roles"], {"roles": []}))
    try:
        data, err = get_request_json_or_error()
        if err:
            return err
        # Normalize to {"roles": [...]} and ensure each entry has the three
        # fields, so a hand-posted payload can't desync the shape.
        if isinstance(data, list):
            data = {"roles": data}
        for r in data.get("roles", []):
            r.setdefault("name", "")
            r.setdefault("description", "")
            r.setdefault("notes", "")
        save_json(paths["roles"], data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/rules", methods=["GET", "POST"])
@require_auth
def api_rules():
    paths = get_paths(CONFIG_PATH)
    if request.method == "GET":
        data = load_json(paths["rules"], [])
        # Handle both {"rules": [...]} and plain array formats
        if isinstance(data, dict) and "rules" in data:
            data = data["rules"]
        return jsonify(data)
    try:
        # Save as {"rules": [...]} to match existing format
        payload, err = get_request_json_or_error()
        if err:
            return err
        if isinstance(payload, list):
            payload = {"rules": payload}
        save_json(paths["rules"], payload)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/anon", methods=["GET", "POST"])
@require_auth
def api_anon():
    paths = get_paths(CONFIG_PATH)
    if request.method == "GET":
        return jsonify(load_json(paths["anon"], {}))
    try:
        data, err = get_request_json_or_error()
        if err:
            return err
        save_json(paths["anon"], data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/users", methods=["GET", "POST"])
@require_auth
def api_users():
    paths = get_paths(CONFIG_PATH)
    if request.method == "GET":
        return jsonify(load_json(paths["users"], {"users": []}))
    try:
        data, err = get_request_json_or_error()
        if err:
            return err
        save_json(paths["users"], data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/domains", methods=["GET", "POST"])
@require_auth
def api_domains():
    paths = get_paths(CONFIG_PATH)
    if request.method == "GET":
        return jsonify(load_json(paths["domains"], {"domains": []}))
    try:
        data, err = get_request_json_or_error()
        if err:
            return err
        save_json(paths["domains"], data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/journal")
@require_auth
def api_journal():
    """Server-Sent Events stream from journalctl.

    Stream lifecycle: client disconnect is only detected when the NEXT
    journal line is yielded and the socket write fails — until then the
    request thread and its journalctl -f child linger. How long that is
    depends on how often the service writes anything to its journal. The
    guaranteed periodic emitters while the service RUNS are the [DEDUP]
    heartbeat (every cycle, processing.poll_interval_seconds, default 30)
    and the lag line (observability.lag_log_interval_seconds, default 30;
    0 disables it — a supported config). So with the service up,
    disconnect detection lags by up to ~one poll interval even with lag
    emission disabled. Indefinite linger requires the service to be
    stopped or wedged — possible exactly when an operator might leave a
    Journal tab open watching for it to come back. Bounded in practice
    by one stream per open Journal tab per user. A read-timeout heartbeat
    would make detection deterministic — v1.1 polish, not load-bearing."""
    def generate():
        proc = subprocess.Popen(
            ["journalctl", "-u", "jrsoctriage", "-f", "--no-pager", "-n", "50"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        try:
            for line in proc.stdout:
                yield f"data: {line.rstrip()}\n\n"
        finally:
            proc.terminate()
            # Reap the child so it doesn't sit as a zombie until this
            # thread happens to exit. terminate() alone only signals.
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/test-email", methods=["POST"])
@require_auth
def api_test_email():
    """Run the email_sender.py smoke test (a synthetic NOTIFY) against the
    saved config and return its output. Mirrors how /api/maintenance shells
    out to a sibling CLI: invokes /usr/bin/python3 (the interpreter the
    pipeline service runs under per jrsoctriage.service) rather than
    sys.executable (the interface venv, which lacks the pipeline deps). The
    email smoke test is stdlib-only so it would run under either, but using
    the same interpreter as the other shell-outs keeps one consistent story.
    The smoke test reads config.json and is side-effect-free (no DB write,
    no ingest-position movement), so it is safe to run against a live
    pipeline. cwd is the install dir so its relative load_config("config.json")
    resolves."""
    try:
        result = subprocess.run(
            ["/usr/bin/python3", "email_sender.py"],
            cwd=_INSTALL_DIR,
            capture_output=True, text=True, timeout=30,
        )
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        return jsonify({"ok": result.returncode == 0, "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False,
                        "output": "Test timed out after 30s (SMTP connection hung?)."})
    except Exception as e:
        return jsonify({"ok": False, "output": f"Failed to run test: {e}"})


@app.route("/api/restart", methods=["POST"])
@require_auth
def api_restart():
    """Restart jrsoctriage and stream startup output."""
    def generate():
        # daemon-reload first
        subprocess.run(["systemctl", "daemon-reload"],
                       capture_output=True, text=True)

        yield "[ Running: systemctl restart jrsoctriage ]\n"

        # Capture the moment just before restart. journalctl --since uses
        # this so the displayed output always starts at the actual restart,
        # regardless of how long startup takes. Earlier versions used
        # `-n 80` (last 80 lines) which produced an unpredictable display
        # window — fast restarts showed pre-restart noise, slow restarts
        # truncated the startup itself.
        #
        # journalctl --since accepts "YYYY-MM-DD HH:MM:SS" in local time.
        # Second precision is fine because restart events are well-separated.
        restart_marker = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        result = subprocess.run(
            ["systemctl", "restart", "jrsoctriage"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            yield f"[ ERROR: {result.stderr.strip()} ]\n"
            return

        yield "[ Service restarting - capturing startup output... ]\n\n"

        # Follow mode: shows lines as they're written. Critical because
        # startup can take up to 3 minutes if there are in-flight LLM
        # calls draining at shutdown. A non-follow read would only show
        # whatever has landed at read time, missing the rest of the
        # 3-minute startup arc.
        proc = subprocess.Popen(
            ["journalctl", "-u", "jrsoctriage", "--no-pager", "-f",
             "--since", restart_marker],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        # Stop conditions, whichever fires first:
        #   1. We see the "Pipeline ready - entering main loop" marker
        #      that main.py logs at the end of startup. This is the
        #      authoritative "done" signal.
        #   2. Five-minute timeout backstop. Startup taking longer than
        #      this means something is wrong and we should not hang the
        #      SSE forever. Operator can re-run /api/restart or watch
        #      /api/journal directly to see what's happening.
        #
        # Display gating: journalctl --since starts at the captured marker
        # which is *before* the systemctl restart command ran. That window
        # therefore includes the stop sequence — the previous process
        # finishing in-flight work, systemd's stop-sigterm timeout, the
        # SIGKILL, etc. None of that is what the operator wants to see
        # under "restart output." We capture all of it (so we don't miss
        # anything if marker timing is off), but suppress display until
        # we see systemd's "Started jrsoctriage.service" line, which is
        # the authoritative "the new process has begun" signal.
        #
        # Note on the timeout: we can't rely on checking time.monotonic()
        # inside the read loop, because `for line in proc.stdout` blocks
        # waiting for the next line. If the journal goes quiet for any
        # reason, the loop sits there past the deadline. A separate
        # watchdog thread terminates the subprocess from outside, which
        # unblocks the read loop with EOF.
        STARTED_MARKER = "Started jrsoctriage.service"
        READY_MARKER   = "Pipeline ready - entering main loop"
        MAX_WAIT_SECS  = 300

        def _watchdog():
            time.sleep(MAX_WAIT_SECS)
            # Race-safe: if the main loop already exited and called
            # terminate(), this is a no-op. If the main loop is still
            # waiting on stdout, this terminates the process and the
            # read loop sees EOF.
            try:
                if proc.poll() is None:
                    proc.terminate()
            except Exception:
                pass

        watchdog = threading.Thread(target=_watchdog, daemon=True)
        watchdog.start()

        saw_started = False
        saw_ready   = False
        timed_out   = False
        count       = 0

        try:
            for line in proc.stdout:
                # Suppress the stop sequence — only show output from
                # the moment the new process actually starts.
                if not saw_started:
                    if STARTED_MARKER in line:
                        saw_started = True
                        yield line
                        count += 1
                    continue
                yield line
                count += 1
                if READY_MARKER in line:
                    saw_ready = True
                    break
        finally:
            # Detect whether the watchdog beat us to it. If proc was
            # terminated externally, treat as timeout for the user message.
            if not saw_ready and proc.poll() is not None:
                timed_out = True
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        if saw_ready:
            yield f"\n[ Done - {count} startup lines captured, pipeline ready ]\n"
        elif timed_out:
            yield (
                f"\n[ Timeout after {MAX_WAIT_SECS}s — startup still in "
                "progress. Check Journal tab for live output. ]\n"
            )
        elif not saw_started:
            yield (
                "\n[ Restart did not begin within window — check service "
                "status. ]\n"
            )
        else:
            yield f"\n[ Captured {count} lines but did not see ready marker ]\n"

    return Response(generate(), mimetype="text/plain")


# -----------------------------------------------------------------------------
# Maintenance mode — thin shell-out wrappers around maintenance.py CLI
# -----------------------------------------------------------------------------
# These endpoints exist so operators can manage maintenance from the GUI
# without SSHing to the host. The actual logic lives in maintenance.py;
# we just shell out to it the same way an operator would from the terminal.
# Keeping it that way avoids drift between two implementations of "set
# maintenance mode" and keeps interface.py from absorbing more responsibility.

_INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))


def _run_maintenance_cli(args, timeout=10):
    """Shell out to maintenance.py with the given arg list. Returns
    (returncode, stdout, stderr). Runs from the install directory so
    maintenance.py can import its sibling modules (ingest, database).

    NOTE: We invoke /usr/bin/python3 explicitly rather than sys.executable.
    sys.executable points at the interface venv's Python, which only has
    the interface's own dependencies. maintenance.py imports the pipeline
    modules (database -> graylog_fetch -> requests, etc.) which live in
    the system Python where the pipeline service runs them. Calling the
    same Python the pipeline uses keeps the dependency story sane and
    avoids dragging pipeline deps into the interface venv just to support
    a CLI shell-out."""
    cmd = ["/usr/bin/python3", os.path.join(_INSTALL_DIR, "maintenance.py")] + list(args)
    try:
        result = subprocess.run(
            cmd,
            cwd=_INSTALL_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "maintenance.py timed out"
    except Exception as e:
        return 1, "", f"maintenance.py invocation failed: {e}"


def _parse_status_output(stdout):
    """Parse maintenance.py --status text output into a list of dicts.

    The CLI prints something like:
        HOST                  REMAINING  SET BY
        ---------------------------------------------
        dmz-web-01                 58m  manual
        Domain_Controller          12m  manual

    We parse it back into structured data for the GUI. If the output
    is the empty-state message, return an empty list.
    """
    lines = stdout.strip().splitlines()
    if not lines or "No hosts currently in maintenance mode" in stdout:
        return []
    active = []
    for line in lines:
        # Skip header line and separator
        if line.startswith("HOST") or line.startswith("-"):
            continue
        # Match: HOST<spaces>NUMBERm<spaces>SET_BY
        m = re.match(r"^(\S+)\s+(\d+)m\s+(.+)$", line.strip())
        if m:
            active.append({
                "host": m.group(1),
                "remaining_minutes": int(m.group(2)),
                "set_by": m.group(3).strip(),
            })
    return active


@app.route("/api/maintenance", methods=["GET"])
@require_auth
def api_maintenance_status():
    """List hosts currently in maintenance mode."""
    rc, stdout, stderr = _run_maintenance_cli(["--status"])
    if rc != 0:
        return jsonify({"ok": False, "error": stderr.strip() or "status query failed", "active": []}), 500
    return jsonify({"ok": True, "active": _parse_status_output(stdout)})


@app.route("/api/maintenance/set", methods=["POST"])
@require_auth
def api_maintenance_set():
    """Put a host into maintenance mode. Body: {host, minutes}."""
    data, err = get_request_json_or_error()
    if err:
        return err
    host = (data.get("host") or "").strip()
    minutes = data.get("minutes")
    if not host:
        return jsonify({"ok": False, "error": "host required"}), 400
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "minutes must be an integer"}), 400
    if minutes < 1 or minutes > 1440:
        return jsonify({"ok": False, "error": "minutes must be between 1 and 1440"}), 400
    rc, stdout, stderr = _run_maintenance_cli(["--host", host, "--minutes", str(minutes)])
    if rc != 0:
        return jsonify({"ok": False, "error": stderr.strip() or "set failed"}), 500
    user = session.get("username", "unknown")
    logger.info(f"Maintenance set: {host} for {minutes}m by user:{user}")
    return jsonify({"ok": True, "stdout": stdout.strip()})


@app.route("/api/maintenance/clear", methods=["POST"])
@require_auth
def api_maintenance_clear():
    """Remove a host from maintenance mode. Body: {host}."""
    data, err = get_request_json_or_error()
    if err:
        return err
    host = (data.get("host") or "").strip()
    if not host:
        return jsonify({"ok": False, "error": "host required"}), 400
    rc, stdout, stderr = _run_maintenance_cli(["--host", host, "--clear"])
    if rc != 0:
        return jsonify({"ok": False, "error": stderr.strip() or "clear failed"}), 500
    user = session.get("username", "unknown")
    logger.info(f"Maintenance cleared: {host} by user:{user}")
    return jsonify({"ok": True, "stdout": stdout.strip()})


@app.route("/api/ipaliases", methods=["GET", "POST"])
@require_auth
def api_ipaliases():
    paths = get_paths(CONFIG_PATH)
    if request.method == "GET":
        return jsonify(load_json(paths.get("ip_aliases", paths["config"].replace("config.json", "ip_aliases.json")), {"ips": []}))
    try:
        data, err = get_request_json_or_error()
        if err:
            return err
        save_json(paths.get("ip_aliases", paths["config"].replace("config.json", "ip_aliases.json")), data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/status")
@require_auth
def api_status():
    result = subprocess.run(
        ["systemctl", "status", "jrsoctriage", "--no-pager", "-l"],
        capture_output=True, text=True
    )
    return jsonify({"output": result.stdout + result.stderr})


# ---------------------------------------------------------------------------
# Lookup API route — reverse alias lookup tables
# ---------------------------------------------------------------------------

@app.route("/api/lookup")
@require_auth
def api_lookup():
    """Return all alias mappings for the lookup tab."""
    paths  = get_paths(CONFIG_PATH)
    result = {"hosts": [], "users": [], "domains": [], "ips": []}

    # Hosts
    try:
        hdata = load_json(paths["hosts"], {"hosts": []})
        for h in hdata.get("hosts", []):
            if h.get("alias"):
                result["hosts"].append({"hostname": h.get("name", ""), "alias": h["alias"]})
    except Exception:
        pass

    # Users
    try:
        udata = load_json(paths["users"], {"users": []})
        for u in udata.get("users", []):
            if u.get("alias"):
                result["users"].append({"username": u.get("name", u.get("username", "")), "alias": u["alias"]})
    except Exception:
        pass

    # Domains
    try:
        ddata = load_json(paths["domains"], {"domains": []})
        for d in ddata.get("domains", []):
            if d.get("alias"):
                result["domains"].append({"domain": d.get("name", d.get("domain", "")), "alias": d["alias"]})
    except Exception:
        pass

    # IPs
    try:
        idata = load_json(paths["ip_aliases"], {"ips": []})
        for entry in idata.get("ips", []):
            if entry.get("alias"):
                result["ips"].append({"ip": entry.get("ip", ""), "alias": entry["alias"]})
    except Exception:
        pass

    return jsonify(result)


# ---------------------------------------------------------------------------
# Auth API routes — user management
# ---------------------------------------------------------------------------

@app.route("/api/auth/me")
@require_auth
def api_auth_me():
    return jsonify({"username": session.get("username", "")})


@app.route("/api/auth/check")
def api_auth_check():
    """Passive session liveness check — does NOT bump last_activity.

    Used by the JS heartbeat to verify the session is still alive without
    extending it. Critical distinction:

      /api/auth/me uses @require_auth, which calls _touch_session(). If
      the heartbeat used auth/me, every 30s the timer would reset and
      the idle timeout would never fire — operator stays logged in
      indefinitely as long as the browser tab is open. That defeats the
      whole point of the timeout.

      /api/auth/check skips @require_auth entirely. It calls
      is_authenticated() directly to check current state, returns 200 if
      alive or 401 if not, and does not touch the session at all. The
      idle timer continues to count down.

    Returns:
      200 OK with {"alive": True} if session is currently authenticated
        AND not idle-expired.
      401 with {"ok": False, "auth_required": True} otherwise. authFetch
        on the client side picks this up and redirects to /login.
    """
    if is_authenticated():
        return jsonify({"alive": True})
    return jsonify({
        "ok": False,
        "error": "Session expired or not authenticated",
        "auth_required": True,
    }), 401


@app.route("/api/auth/users", methods=["GET", "POST"])
@require_auth
def api_auth_users():
    auth = load_auth()
    if request.method == "GET":
        safe = [{"username": u["username"], "role": u.get("role","user"),
                 "totp_verified": u.get("totp_verified", False)}
                for u in auth.get("users", [])]
        return jsonify({"users": safe})

    data, err = get_request_json_or_error()
    if err:
        return err
    action = data.get("action")

    if action == "add":
        username = data.get("username", "").strip()
        password = data.get("password", "")
        if not username or not password:
            return jsonify({"ok": False, "error": "Username and password required"})
        # Apply the same complexity check as terminal flows so the GUI
        # never ships a weaker bar than the CLI.
        ok, msg = _check_password_complexity(password)
        if not ok:
            return jsonify({"ok": False, "error": msg})
        if any(u["username"] == username for u in auth.get("users", [])):
            return jsonify({"ok": False, "error": "Username already exists"})
        totp_secret = pyotp.random_base32()
        totp        = pyotp.TOTP(totp_secret)
        otp_uri     = totp.provisioning_uri(name=username, issuer_name="jrSOCtriage")
        # Generate QR as data URI — BEST EFFORT. PNG rendering needs the
        # Pillow image backend (the CLI flow renders ASCII and never
        # needs it; this GUI path is the only PNG consumer, which is how
        # a missing Pillow stayed invisible until the GUI flow was first
        # exercised). If rendering fails, the user is STILL created and
        # the manual secret key still enrolls an authenticator — the QR
        # is a convenience, not the credential. pillow is now listed in
        # interface_requirements.txt; this guard covers venvs installed
        # before it was.
        import io, base64
        qr_image = None
        qr_error = None
        try:
            qr = qrcode.make(otp_uri)
            buf = io.BytesIO()
            qr.save(buf, format="PNG")
            qr_image = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
        except Exception as e:
            qr_error = ("QR image unavailable (install 'pillow' in the "
                        "interface venv) — use the manual secret key below.")
            logger.warning(f"QR PNG generation failed for new user "
                           f"'{username}': {e}")
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        auth.setdefault("users", []).append({
            "username":            username,
            "password_hash":       pw_hash,
            "totp_secret":         totp_secret,
            # Both flags below are ENFORCED: require_auth funnels
            # force_password_change users to /change-password until they
            # rotate the admin-chosen password, and totp_verified flips
            # true on their first successful TOTP login (backfill in
            # login()). role remains informational until RBAC lands.
            "totp_verified":       False,
            "force_password_change": True,
            "role":                "user",
        })
        save_auth(auth)
        return jsonify({"ok": True, "totp_secret": totp_secret,
                        "qr_image": qr_image, "qr_error": qr_error})

    if action == "delete":
        username = data.get("username", "")
        if username == session.get("username"):
            return jsonify({"ok": False, "error": "Cannot delete your own account"})
        auth["users"] = [u for u in auth.get("users", []) if u["username"] != username]
        save_auth(auth)
        return jsonify({"ok": True})

    return jsonify({"ok": False, "error": "Unknown action"})


def _check_sensitive_file_permissions(config_path):
    """Warn the operator about sensitive files with overly-permissive modes.

    Runs at interface startup. Walks the list of state files referenced
    by config.json and reports any that are world-readable, group-readable,
    or world-writable.

    Does NOT modify permissions automatically — the file owner may differ
    from what we expect (e.g., a config in a user homedir during testing),
    and silently chmod'ing files an operator chose to share could surprise
    them. We just warn loudly. The save_json/save_auth functions handle
    NEW writes; this catches files that already existed before the
    permission policy was tightened.

    Reports paths only. Continues startup even on errors — the warning
    output is the actionable item.
    """
    if not os.path.exists(config_path):
        return

    try:
        with open(config_path) as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError):
        # Config unreadable; not our problem to diagnose here.
        return

    base = str(Path(config_path).parent)
    paths_cfg = cfg.get("paths", {})

    # Files to check, with the rationale shown to operators.
    to_check = [
        (config_path, "credentials (API keys, SMTP/ntopng/Graylog passwords)"),
        (os.path.join(base, AUTH_FILENAME), "bcrypt hashes + TOTP secrets"),
    ]

    # Optional state files - only warn if they exist
    for key, label in [
        ("hosts_file", "host inventory (LLM context)"),
        ("rules_file", "rules engine config"),
        ("users_file", "anonymization aliases (username -> alias)"),
        ("domain_file", "anonymization aliases (domain -> alias)"),
        ("ip_aliases_file", "anonymization aliases (ip -> alias)"),
        ("anonymization_file", "anonymization master settings"),
    ]:
        rel = paths_cfg.get(key, "")
        if not rel:
            continue
        path = rel if os.path.isabs(rel) else os.path.join(base, rel)
        to_check.append((path, label))

    issues = []
    for path, label in to_check:
        if not os.path.exists(path):
            continue
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            continue
        # Anything non-zero in group or world bits is a concern.
        if mode & 0o077:
            issues.append((path, mode, label))

    if not issues:
        return

    print()
    print("  WARNING: Sensitive files have permissive modes.")
    print("  Recommended: mode 600 (owner-only read/write).")
    print()
    for path, mode, label in issues:
        print(f"    {oct(mode)} {path}")
        print(f"            ^ {label}")
    print()
    print("  Fix with:")
    for path, _, _ in issues:
        print(f"    sudo chmod 600 {path}")
    print()
    print("  See running_instructions.txt -> SECURITY: FILE PROTECTION")
    print()


# ---------------------------------------------------------------------------
# Entry point — parse args, print startup info, run Flask
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="jrSOCtriage Web Interface")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument(
        "--add-user",
        action="store_true",
        help="Add a new authentication user via terminal prompts and exit. "
             "Use this to add additional users without deleting the existing "
             "auth file. Requires existing auth file (run without this flag "
             "for first-run setup).",
    )
    args = parser.parse_args()

    CONFIG_PATH = args.config

    # CLI subcommand: add a user, then exit. Does not start the web server.
    if args.add_user:
        sys.exit(add_user_cli())

    # Run first-time setup if no auth file exists
    auth_file = os.path.join(str(Path(CONFIG_PATH).parent), AUTH_FILENAME)
    if not os.path.exists(auth_file):
        setup_first_user()

    # Warn if sensitive files have permissive modes. Doesn't auto-fix —
    # we don't know who SHOULD own these files in every deployment scenario.
    _check_sensitive_file_permissions(CONFIG_PATH)

    print(f"\n  jrSOCtriage Web Interface")
    print(f"  ─────────────────────────")
    print(f"  Config : {CONFIG_PATH}")
    print(f"  URL    : http://127.0.0.1:{args.port}")
    print(f"  Stop   : Ctrl+C\n")

    app.run(host="127.0.0.1", port=args.port, debug=False, threaded=True)
