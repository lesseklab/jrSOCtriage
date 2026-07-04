#!/usr/bin/env bash
# jrSOCtriage interface setup
#
# Sets up the Python venv for the WEB INTERFACE (interface.py).
# The pipeline (main.py) does not need a venv — its only third-party
# dependency is `requests`, which is typically already available on
# any modern Linux host. Install requests via pip or your distro
# package manager separately if needed:
#     sudo apt install python3-requests        # Debian/Ubuntu
#     sudo dnf install python3-requests        # Fedora/RHEL
#     pip install requests --break-system-packages    # any distro
#
# This script:
#   1. Verifies Python 3.12+ is installed (3.13, 3.14, 3.14.4 tested)
#   2. Creates a Python venv at ./venv
#   3. Installs interface dependencies from interface_requirements.txt
#   4. Sets restrictive permissions (mode 600) on existing config files
#   5. Prints next steps
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
    echo "Tested versions: 3.13, 3.14, 3.14.4. Install one of those and retry."
    exit 1
fi

# Warn on 3.12 (untested but probably works) and on anything beyond 3.14
# (forward-compat unknown).
if [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -eq 12 ]; then
    echo "[!!] Python $PY_VERSION found. This version has not been formally"
    echo "     tested. Tested versions: 3.13, 3.14, 3.14.4. Continuing anyway"
    echo "     since the version is above the minimum requirement."
elif [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -gt 14 ]; then
    echo "[!!] Python $PY_VERSION found, which is newer than the most recently"
    echo "     tested version (3.14). Forward compatibility is not guaranteed."
fi

echo "[OK] Python $PY_VERSION"

# --- Required source files ---------------------------------------------------
for f in interface_requirements.txt interface.py; do
    if [ ! -f "$INSTALL_DIR/$f" ]; then
        echo "ERROR: $f not found in $INSTALL_DIR"
        echo "Run this script from the jrSOCtriage source directory."
        exit 1
    fi
done

echo "[OK] Source files present"

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
# .json.sample files in the repo are templates. On first install, copy them
# into the working .json names so the operator has a starting point.
# Subsequent runs leave existing .json files alone.
echo "[..] Initializing state files from samples (if missing)"
for f in config hosts rules users domain anonymization; do
    if [ -f "$INSTALL_DIR/${f}.json.sample" ] && [ ! -f "$INSTALL_DIR/${f}.json" ]; then
        cp "$INSTALL_DIR/${f}.json.sample" "$INSTALL_DIR/${f}.json"
        chmod 600 "$INSTALL_DIR/${f}.json" 2>/dev/null || sudo chmod 600 "$INSTALL_DIR/${f}.json"
        echo "    initialized ${f}.json from sample"
    fi
done
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
