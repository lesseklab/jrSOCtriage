#!/usr/bin/env bash
# jrSOCtriage interface setup
#
# Sets up both halves of a jrSOCtriage install.
#
# The pipeline (main.py) runs on SYSTEM Python so the systemd unit can
# find it when running as root. It needs two third-party packages,
# `requests` and `dnspython`, which this script installs system-wide
# from requirements.txt.
#
# The web interface (interface.py) runs from a venv at ./venv so its
# Flask/bcrypt/pyotp/qrcode dependencies do not pollute system Python.
#
# This script:
#   1. Verifies Python 3.12+ is installed (3.13 and 3.14 formally tested)
#   2. Verifies every runtime module is present
#   3. Installs PIPELINE dependencies system-wide (requirements.txt)
#   4. Creates a Python venv at ./venv
#   5. Installs INTERFACE dependencies into it (interface_requirements.txt)
#   6. Sets restrictive permissions (mode 600) on existing config files
#   7. Initializes state files from their .sample templates
#   8. Patches the systemd unit files with the real install path
#   9. Smoke-tests that both halves actually import
#  10. Prints next steps
#
# Re-running this script is safe — it skips work that's already done.
#
# Override the Python binary with: PYTHON_BIN=python3.14 bash setup.sh

set -euo pipefail

INSTALL_DIR="$(pwd)"
VENV_DIR="$INSTALL_DIR/venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "==============================================="
echo "  jrSOCtriage interface setup"
echo "==============================================="
echo "  Install dir : $INSTALL_DIR"
echo "  Python      : $PYTHON_BIN"
echo

# --- Check Python version ----------------------------------------------------
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "ERROR: $PYTHON_BIN not found. Install Python 3.12 or newer and retry."
    exit 1
fi

PY_VERSION=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$("$PYTHON_BIN" -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$("$PYTHON_BIN" -c 'import sys; print(sys.version_info.minor)')

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 12 ]; }; then
    echo "ERROR: Python $PY_VERSION found, but jrSOCtriage requires 3.12+."
    echo "Formally tested versions: 3.13, 3.14. Install one of those and retry."
    exit 1
fi

# Warn on 3.12 (untested but probably works) and on anything beyond 3.14
# (forward-compat unknown).
if [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -eq 12 ]; then
    echo "[!!] Python $PY_VERSION found. This version has not been formally"
    echo "     tested. Formally tested versions: 3.13, 3.14. Continuing anyway"
    echo "     since the version is above the minimum requirement."
elif [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -gt 14 ]; then
    echo "[!!] Python $PY_VERSION found, which is newer than the most recently"
    echo "     tested version (3.14). Forward compatibility is not guaranteed."
fi

echo "[OK] Python $PY_VERSION"

# --- Required source files ---------------------------------------------------
# Every runtime module is listed explicitly. An incomplete distribution is
# otherwise invisible until the service starts and fails on an import deep
# in a call path — check it here, where the error can say something useful.
REQUIRED_FILES="
requirements.txt
interface_requirements.txt
main.py
interface.py
anonymize.py
database.py
dedup.py
email_sender.py
enrich.py
gelf_shipper.py
graylog_fetch.py
ingest.py
lag_logger.py
llm_caller.py
maintenance.py
merge_hosts.py
ntopng_fetch.py
prompt_builder.py
rules.py
wazuh_import.py
zeek_fetch.py
"

MISSING=""
for f in $REQUIRED_FILES; do
    if [ ! -f "$INSTALL_DIR/$f" ]; then
        MISSING="$MISSING $f"
    fi
done

if [ -n "$MISSING" ]; then
    echo "ERROR: the following required files are missing from $INSTALL_DIR:"
    for f in $MISSING; do
        echo "    $f"
    done
    echo
    echo "Either this is not the jrSOCtriage source directory, or the"
    echo "distribution is incomplete. Re-download or re-clone before retrying."
    exit 1
fi

echo "[OK] Source files present"

# --- Install PIPELINE dependencies system-wide -------------------------------
# The pipeline runs under /usr/bin/python3 as root via systemd, so its
# dependencies must be on the system interpreter, not in the venv.
# Newer distros mark system Python as externally managed (PEP 668) and
# refuse a plain pip install; retry with --break-system-packages, which is
# the documented escape hatch for exactly this case.
echo "[..] Installing pipeline dependencies system-wide (requirements.txt)"
if "$PYTHON_BIN" -m pip install -r "$INSTALL_DIR/requirements.txt" --quiet 2>/dev/null; then
    echo "[OK] pipeline dependencies installed"
elif "$PYTHON_BIN" -m pip install -r "$INSTALL_DIR/requirements.txt" \
        --break-system-packages --quiet 2>/dev/null; then
    echo "[OK] pipeline dependencies installed (--break-system-packages)"
else
    echo "[!!] Could not install pipeline dependencies automatically."
    echo "     Install them by hand before starting the pipeline service:"
    echo "         sudo $PYTHON_BIN -m pip install -r requirements.txt --break-system-packages"
    echo "     or via your distro packages:"
    echo "         sudo apt install python3-requests python3-dnspython"
    echo "         sudo dnf install python3-requests python3-dns"
fi

# --- Create venv -------------------------------------------------------------
if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/python3" ]; then
    echo "[OK] venv already exists at $VENV_DIR"
else
    echo "[..] Creating venv at $VENV_DIR"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    echo "[OK] venv created"
fi

# --- Upgrade pip first -------------------------------------------------------
echo "[..] Upgrading pip in venv"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
echo "[OK] pip upgraded"

# --- Install interface dependencies ------------------------------------------
echo "[..] Installing interface dependencies (interface_requirements.txt)"
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/interface_requirements.txt" --quiet
echo "[OK] interface dependencies installed"

# --- Lock down permissions on existing config files --------------------------
echo "[..] Setting mode 600 on sensitive files (if they exist)"
for f in config.json interface_auth.json hosts.json rules.json users.json domain.json ip_aliases.json anonymization.json; do
    if [ -f "$INSTALL_DIR/$f" ]; then
        chmod 600 "$INSTALL_DIR/$f" 2>/dev/null || sudo chmod 600 "$INSTALL_DIR/$f"
        echo "    chmod 600 $f"
    fi
done
echo "[OK] permissions checked"

# --- Initialize state files from .sample if missing --------------------------
# <name>.json.sample files in the distribution are templates. On first install,
# copy each into its working <name>.json so the operator has a starting point.
# Existing working files are never overwritten — the guard is the [ ! -f ]
# test below, so re-running this script is safe.
#
# Older distributions shipped these templates under several inconsistent
# names (name_json.sample, name_json_sample.txt). Those alternatives are
# accepted here so an upgrade-in-place from such a tree still initializes.
echo "[..] Initializing state files from samples (if missing)"
SAMPLES_FOUND=0
for f in config hosts roles rules users domain anonymization; do
    TARGET="$INSTALL_DIR/${f}.json"
    [ -f "$TARGET" ] && continue

    SRC=""
    for candidate in "${f}.json.sample" "${f}_json.sample" "${f}_json_sample.txt"; do
        if [ -f "$INSTALL_DIR/$candidate" ]; then
            SRC="$INSTALL_DIR/$candidate"
            break
        fi
    done

    if [ -n "$SRC" ]; then
        cp "$SRC" "$TARGET"
        chmod 600 "$TARGET" 2>/dev/null || sudo chmod 600 "$TARGET"
        echo "    initialized ${f}.json from $(basename "$SRC")"
        SAMPLES_FOUND=$((SAMPLES_FOUND + 1))
    fi
done

if [ "$SAMPLES_FOUND" -eq 0 ]; then
    echo "    (nothing to initialize — working files already present)"
fi
echo "[OK] state files checked"

# --- Fix systemd service paths -----------------------------------------------
# Both unit files ship with /mnt/appdata/jrsoctriage as the default install
# path. If the operator is running setup.sh from a different location, the
# unit files would be wrong on copy. Patch them in place so they reflect the
# actual install location.
echo "[..] Updating systemd service files with install path"

# jrsoctriage.service (pipeline)
if [ -f "$INSTALL_DIR/jrsoctriage.service" ]; then
    sed -i "s|^WorkingDirectory=.*|WorkingDirectory=$INSTALL_DIR|" "$INSTALL_DIR/jrsoctriage.service"
    sed -i "s|^ExecStart=.*|ExecStart=/usr/bin/python3 main.py|" "$INSTALL_DIR/jrsoctriage.service"
    echo "    updated jrsoctriage.service"
else
    echo "    WARNING: jrsoctriage.service not found"
fi

# jrsoctriage-interface.service (web interface)
if [ -f "$INSTALL_DIR/jrsoctriage-interface.service" ]; then
    sed -i "s|^WorkingDirectory=.*|WorkingDirectory=$INSTALL_DIR|" "$INSTALL_DIR/jrsoctriage-interface.service"
    sed -i "s|^ExecStart=.*interface.py.*|ExecStart=$VENV_DIR/bin/python3 interface.py|" "$INSTALL_DIR/jrsoctriage-interface.service"
    echo "    updated jrsoctriage-interface.service"
else
    echo "    WARNING: jrsoctriage-interface.service not found"
fi

echo "[OK] service files updated"

# --- Smoke test --------------------------------------------------------------
# Two checks, because neither alone is sufficient.
#
# (1) Resolve the LOCAL import graph statically. main.py imports its sibling
#     modules INSIDE functions rather than at module level, so `import main`
#     succeeds even when half the distribution is missing — an omitted module
#     then surfaces only when the service starts and hits that code path.
#     Walking the AST finds those deferred imports; a plain import cannot.
#     This is the check that would have caught the missing lag_logger.
#
# (2) Import each pipeline module for real, which is what catches a missing
#     third-party dependency.
echo "[..] Verifying the distribution is complete"
SMOKE_FAIL=0

RESOLVE=$("$PYTHON_BIN" - "$INSTALL_DIR" <<'SMOKE_PY' 2>&1
import ast
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
local = {p.stem for p in root.glob("*.py")}
missing = set()

for path in sorted(root.glob("*.py")):
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError as exc:
        print("SYNTAX %s: %s" % (path.name, exc))
        continue

    guarded = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for inner in ast.walk(node):
                guarded.add(id(inner))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module.split(".")[0]]
        else:
            continue
        if id(node) in guarded:
            continue
        for name in names:
            if name in local:
                continue
            if (root / (name + ".py")).exists():
                continue
            try:
                __import__(name)
            except ImportError:
                missing.add("%s needs %s" % (path.name, name))
            except Exception:
                pass

for item in sorted(missing):
    print("MISSING " + item)
SMOKE_PY
)

if [ -n "$RESOLVE" ]; then
    echo "    [!!] the distribution references things it does not contain:"
    echo "$RESOLVE" | sed 's/^/         /'
    SMOKE_FAIL=1
else
    echo "    import graph resolves (including deferred imports)"
fi

PIPELINE_MODULES="anonymize database dedup email_sender enrich gelf_shipper graylog_fetch ingest lag_logger llm_caller main ntopng_fetch prompt_builder rules zeek_fetch"

IMPORT_FAIL=0
for m in $PIPELINE_MODULES; do
    if ! (cd "$INSTALL_DIR" && "$PYTHON_BIN" -c "import $m" >/dev/null 2>&1); then
        echo "    [!!] pipeline module '$m' failed to import:"
        (cd "$INSTALL_DIR" && "$PYTHON_BIN" -c "import $m" 2>&1 | tail -2 | sed 's/^/         /')
        IMPORT_FAIL=1
        SMOKE_FAIL=1
    fi
done
[ "$IMPORT_FAIL" -eq 0 ] && echo "    all pipeline modules import (system Python)"

if (cd "$INSTALL_DIR" && "$VENV_DIR/bin/python3" -c "import interface" >/dev/null 2>&1); then
    echo "    interface imports (venv Python)"
else
    echo "    [!!] interface failed to import:"
    (cd "$INSTALL_DIR" && "$VENV_DIR/bin/python3" -c "import interface" 2>&1 | tail -2 | sed 's/^/         /')
    SMOKE_FAIL=1
fi

if [ "$SMOKE_FAIL" -eq 0 ]; then
    echo "[OK] distribution is complete and imports cleanly"
else
    echo "[!!] Setup finished, but the checks above found problems that will stop"
    echo "     the service from starting. Fix them before enabling the services."
fi

# --- Done --------------------------------------------------------------------
cat <<EOF

===============================================
  Setup complete!
===============================================

The interface venv is at:
    $VENV_DIR

Run the interface manually (REQUIRED for first-run user creation):
    sudo $VENV_DIR/bin/python3 interface.py

This step creates the initial admin user and TOTP setup.
The interface service will NOT work correctly until this is done.

------------------------------------------------------------

Systemd service installation:

1. Copy service files:
    sudo cp jrsoctriage.service /etc/systemd/system/
    sudo cp jrsoctriage-interface.service /etc/systemd/system/

2. Reload systemd:
    sudo systemctl daemon-reload

3. Enable services to start on boot:
    sudo systemctl enable jrsoctriage-interface
    sudo systemctl enable jrsoctriage

4. Start the interface service:
    sudo systemctl start jrsoctriage-interface

5. Start the pipeline service:
    sudo systemctl start jrsoctriage

------------------------------------------------------------

Notes:

- Service files have been updated automatically with:
      WorkingDirectory = $INSTALL_DIR

- The interface uses the venv Python:
      $VENV_DIR/bin/python3

- The pipeline (main.py) uses system Python:
      /usr/bin/python3

EOF
