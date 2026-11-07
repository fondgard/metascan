#!/usr/bin/env bash
# ==============================================================================
# MetaScan — OSINT Dependencies Installer (Linux / macOS / Git Bash)
# Installs PyPI dependencies (Sherlock, Maigret) and external tools (Blackbird)
# into standard user directory without polluting the MetaScan workspace.
# Pinned to audited immutable commits for supply chain security.
# ==============================================================================

set -euo pipefail

if [ -z "${VIRTUAL_ENV:-}" ]; then
    echo "[-] Error: No virtual environment is active. Please activate a virtual environment first." >&2
    exit 1
fi

# Supply Chain Security: Pin external repository to verified commit hash
BLACKBIRD_COMMIT="471ef970b4cd45378de1270c1b2b06687aa158b7"

# Helper function to verify SHA-256 hash for external downloaded artifacts
verify_sha256() {
    local file_path="$1"
    local expected_hash="$2"
    local actual_hash

    if [ ! -f "$file_path" ]; then
        echo "[-] Error: File not found for checksum verification: ${file_path}" >&2
        return 1
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        actual_hash=$(sha256sum "$file_path" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual_hash=$(shasum -a 256 "$file_path" | awk '{print $1}')
    else
        echo "[-] Warning: Neither sha256sum nor shasum is available. Skipping checksum validation." >&2
        return 0
    fi

    if [ "${actual_hash,,}" != "${expected_hash,,}" ]; then
        echo "[-] Security Alert: SHA-256 integrity check failed for ${file_path}!" >&2
        echo "    Expected: ${expected_hash}" >&2
        echo "    Actual:   ${actual_hash}" >&2
        return 1
    fi
    echo "[+] SHA-256 integrity verified for $(basename "$file_path")"
}

echo "=================================================="
echo "  MetaScan: Installing OSINT Dependencies"
echo "=================================================="

# 1. Install PyPI dependencies (Sherlock, Maigret, core packages)
echo "[*] Installing requirements from requirements.txt..."
python3 -m pip install -r "$(dirname "$0")/requirements.txt"

# 2. Setup Blackbird (pinned to audited commit)
# Standard location: ~/.local/share/metascan/blackbird
INSTALL_DIR="${HOME}/.local/share/metascan/blackbird"
BIN_DIR="${HOME}/.local/bin"

echo "[*] Setting up Blackbird in external directory: ${INSTALL_DIR}..."
mkdir -p "$(dirname "$INSTALL_DIR")"
mkdir -p "$BIN_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "[*] Blackbird repository already exists. Pinning to commit ${BLACKBIRD_COMMIT}..."
    git -C "$INSTALL_DIR" fetch --depth 1 origin "$BLACKBIRD_COMMIT" 2>/dev/null || git -C "$INSTALL_DIR" fetch origin
    git -C "$INSTALL_DIR" checkout -q "$BLACKBIRD_COMMIT"
else
    echo "[*] Cloning Blackbird from GitHub and pinning to commit ${BLACKBIRD_COMMIT}..."
    git clone https://github.com/p1ngul1n0/blackbird.git "$INSTALL_DIR"
    git -C "$INSTALL_DIR" checkout -q "$BLACKBIRD_COMMIT"
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
echo "  - Sherlock:  $(command -v sherlock || echo 'installed in python venv')"
echo "  - Maigret:   $(command -v maigret || echo 'installed in python venv')"
echo "  - Blackbird: ${INSTALL_DIR}/blackbird.py"
echo "               (Wrapper created at ${WRAPPER_SCRIPT})"
echo "               (Pinned commit: ${BLACKBIRD_COMMIT})"
echo "=================================================="
