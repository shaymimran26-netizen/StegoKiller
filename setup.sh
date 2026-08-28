#!/usr/bin/env bash
# ==============================================================================
# StegoKiller Ultra Suite v4.0.0 - Automated Toolchain Installer
# Author: Knight_S
# ==============================================================================

set -e

echo "[*] Initializing StegoKiller Ultra Toolchain Setup (70 Specialized Tools)..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS=$(uname -s)
fi

echo "[+] Detected OS: $OS"

# 1. Install OS-level Forensic & Stego Packages
if command -v apt-get &>/dev/null; then
    echo "[+] Installing APT packages..."
    sudo apt-get update -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        git \
        curl \
        wget \
        ruby \
        ruby-dev \
        libimage-exiftool-perl \
        foremost \
        binwalk \
        steghide \
        outguess \
        stegsnow \
        sox \
        libsox-fmt-all \
        multimon-ng \
        ffmpeg \
        p7zip-full \
        golang \
        tshark \
        zbar-tools \
        qpdf \
        default-jre \
        wordlists || true
fi

# 2. Extract rockyou.txt wordlist if compressed
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "[+] Decompressing rockyou.txt..."
    sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz || true
fi

# 3. Install Ruby Gems (zsteg)
echo "[+] Installing Ruby stego tools (zsteg)..."
if command -v gem &>/dev/null; then
    sudo gem install zsteg || true
fi

# 4. Install Go Tools (jsteg)
echo "[+] Installing Go stego tools (jsteg)..."
if command -v go &>/dev/null; then
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
    go install github.com/lukechampine/jsteg@latest || true
    if [ -f "$GOPATH/bin/jsteg" ]; then
        sudo cp "$GOPATH/bin/jsteg" /usr/local/bin/ || true
    fi
fi

# 5. Install StegSeek (Debian/Ubuntu binary)
if ! command -v stegseek &>/dev/null; then
    echo "[+] Installing StegSeek..."
    ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
    STEGSEEK_URL="https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1_${ARCH}.deb"
    wget -q -O /tmp/stegseek.deb "$STEGSEEK_URL" || true
    if [ -f /tmp/stegseek.deb ]; then
        sudo dpkg -i /tmp/stegseek.deb || sudo apt-get install -f -y || true
        rm -f /tmp/stegseek.deb
    fi
fi

# 6. Python Environment & Dependencies
echo "[+] Installing Python dependencies..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pip3 install --upgrade pip --break-system-packages 2>/dev/null || pip3 install --upgrade pip
pip3 install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages 2>/dev/null || pip3 install -r "$SCRIPT_DIR/requirements.txt"

# 7. Create output staging directory
mkdir -p /tmp/stego_mcp_output
chmod 777 /tmp/stego_mcp_output

echo "================================================================================"
echo "  StegoKiller Ultra Suite Setup Complete! (70 Specialized Tools Ready)"
echo "  Launch: python3 $SCRIPT_DIR/server.py"
echo "================================================================================"
