#!/usr/bin/env bash
# ==============================================================================
# MetaScan — OSINT Dependencies Installer (Linux / macOS / Git Bash)
# Installs PyPI dependencies (Sherlock, Maigret) and external tools (Blackbird)
# into standard user directory without polluting the MetaScan workspace.
# ==============================================================================

set -euo pipefail

if [ -z "${VIRTUAL_ENV:-}" ]; then
    echo "[-] Error: No virtual environment is active. Please activate a virtual environment first." >&2
    exit 1
fi

echo "=================================================="
echo "  MetaScan: Installing OSINT Dependencies"
echo "=================================================="

# 1. Install PyPI dependencies (Sherlock, Maigret, core packages)
echo "[*] Installing requirements from requirements.txt..."
python3 -m pip install -r "$(dirname "$0")/requirements.txt"

# 2. Setup Blackbird (not available on PyPI)
# Standard location: ~/.local/share/metascan/blackbird
INSTALL_DIR="${HOME}/.local/share/metascan/blackbird"
BIN_DIR="${HOME}/.local/bin"

echo "[*] Setting up Blackbird in external directory: ${INSTALL_DIR}..."
mkdir -p "$(dirname "$INSTALL_DIR")"
mkdir -p "$BIN_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "[*] Blackbird repository already exists. Updating..."
    git -C "$INSTALL_DIR" pull --ff-only || true
else
    echo "[*] Cloning Blackbird from GitHub..."
    git clone https://github.com/p1ngul1n0/blackbird.git "$INSTALL_DIR"
fi

echo "[*] Installing Blackbird Python dependencies..."
python3 -m pip install -r "${INSTALL_DIR}/requirements.txt"

# 3. Create convenient CLI wrapper in ~/.local/bin/blackbird
WRAPPER_SCRIPT="${BIN_DIR}/blackbird"
cat << 'EOF' > "$WRAPPER_SCRIPT"
#!/usr/bin/env bash
SCRIPT_DIR="${HOME}/.local/share/metascan/blackbird"
exec python3 "${SCRIPT_DIR}/blackbird.py" "$@"
EOF
chmod +x "$WRAPPER_SCRIPT"

echo "=================================================="
echo "  Installation Complete!"
echo "  - Sherlock: $(command -v sherlock || echo 'installed in python venv')"
echo "  - Maigret:  $(command -v maigret || echo 'installed in python venv')"
echo "  - Blackbird: ${INSTALL_DIR}/blackbird.py"
echo "               (Wrapper created at ${WRAPPER_SCRIPT})"
echo "=================================================="
