# ==============================================================================
# StegoKiller MCP Suite - Production Docker Container
# Author: Knight_S
# Version: 4.0.0 (70 Specialized Tools)
# ==============================================================================

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

# Install core system packages & forensic utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
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
    default-jre-headless \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download rockyou.txt wordlist
RUN mkdir -p /usr/share/wordlists && \
    wget -q -O /usr/share/wordlists/rockyou.txt.gz "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz" && \
    gunzip /usr/share/wordlists/rockyou.txt.gz

# Install Ruby steganography tool (zsteg)
RUN gem install zsteg

# Install Go steganography tool (jsteg)
RUN go install github.com/lukechampine/jsteg@latest && \
    cp /root/go/bin/jsteg /usr/local/bin/ || true

# Install StegSeek (High-speed Steghide cracker)
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q -O /tmp/stegseek.deb "https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1_${ARCH}.deb" && \
    (dpkg -i /tmp/stegseek.deb || apt-get install -f -y) && \
    rm -f /tmp/stegseek.deb

# Setup Workspace
WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy server code
COPY . .

# Setup temporary staging directory
RUN mkdir -p /tmp/stego_mcp_output && chmod 777 /tmp/stego_mcp_output

# Entrypoint for MCP stdio client
ENTRYPOINT ["python3", "server.py"]
