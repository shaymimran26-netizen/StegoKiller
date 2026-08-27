---
title: StegoKiller Ultra Suite
emoji: ⚡
colorFrom: blue
colorTo: purple
sdk: gradio
sdk_version: 4.44.0
app_file: app.py
pinned: false
license: apache-2.0
---

<div align="center">

# ⚡ StegoKiller MCP Server
### The Ultimate Steganography, Digital Forensics & Covert-Channel Suite

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg?style=for-the-badge)](LICENSE)
[![FastMCP](https://img.shields.io/badge/FastMCP-2025%20Ready-orange.svg?style=for-the-badge)](https://github.com/jlowin/fastmcp)
[![Tools](https://img.shields.io/badge/Tools-44%20Specialized%20Engines-06b6d4?style=for-the-badge&logo=shield)](https://shaymimran26-netizen.github.io/StegoKiller/)
[![Docker](https://img.shields.io/badge/Docker-GHCR%20Published-a855f7?style=for-the-badge&logo=docker)](https://github.com/shaymimran26-netizen/StegoKiller/pkgs/container/stegokiller)
[![Smithery](https://img.shields.io/badge/Smithery-Install%20Ready-f43f5e?style=for-the-badge)](https://smithery.ai)

<p align="center">
  <a href="https://shaymimran26-netizen.github.io/StegoKiller/">🌐 <strong>Live Interactive Documentation & Matrix Website</strong></a> •
  <a href="#quickstart">🚀 <strong>Quick Start</strong></a> •
  <a href="#remote-hosting">☁️ <strong>Free Remote Hosting</strong></a> •
  <a href="#tool-matrix">🛠️ <strong>60 Tools Matrix</strong></a>
</p>

</div>

---

## 📖 Overview

**StegoKiller** is an enterprise-grade Model Context Protocol (MCP) server engineered specifically for CTF players, security researchers, and forensic analysts. Built using the official `FastMCP` framework, it integrates **44 specialized steganography, digital forensics, and covert-channel extraction tools** across Images, Audio, Video, Network PCAPs, Documents, Fonts, Git, AI Models, and Text.

---

## ⚡ Quick Start & Installation

### Option 1: 1-Click Install via Smithery CLI
```bash
npx -y @smithery/cli install stegokiller --client claude
```

### Option 2: Local Stdio Configuration (Claude Desktop / Cursor)
Clone the repository and run setup:
```bash
git clone https://github.com/shaymimran26-netizen/StegoKiller.git
cd StegoKiller
chmod +x setup.sh && ./setup.sh
```

Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "stegokiller": {
      "command": "python3",
      "args": [
        "/path/to/StegoKiller/server.py"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

### Option 3: Docker Container via GitHub Container Registry (GHCR)
Run instantly without installing OS dependencies:
```json
{
  "mcpServers": {
    "stegokiller": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "/tmp/stego_mcp_output:/tmp/stego_mcp_output",
        "ghcr.io/shaymimran26-netizen/stegokiller:latest"
      ]
    }
  }
}
```

---

## ☁️ Free Remote Hosting & Public Deployment

Want to host **StegoKiller** on the cloud for free with remote SSE / HTTP access?

| Platform | Type | How to Deploy |
| :--- | :--- | :--- |
| **[Smithery.ai](https://smithery.ai)** | One-Click MCP Hosting | Connect your GitHub repo `shaymimran26-netizen/StegoKiller`. Smithery builds `smithery.yaml` and gives you a hosted proxy endpoint. |
| **[Glama.ai](https://glama.ai/mcp/servers)** | Community Registry | Submit repository URL to be listed in the global MCP index. |
| **[HuggingFace Spaces](https://huggingface.co/spaces)** | Free 24/7 Docker Hosting | Create a new Docker Space, push this repo, and expose port `8000` via SSE. |
| **[Render.com](https://render.com) / [Railway.app](https://railway.app)** | Free Cloud Web Service | Deploy Docker container with start command: `mcp run server.py --transport sse --port 8000`. |

---

## 🛠️ Comprehensive 44-Tool Matrix

### 1. Core Triage, Integrity & Polyglots (7 Tools)
* `auto_triage_challenge(file_path)`: **Autonomous 5-stage master pipeline** running structure analysis, flag regex search, metadata extraction, polyglot check, and signature scan in one shot.
* `inspect_file_structure(file_path)`: Validates 25+ magic byte signatures, calculates quadrant and global Shannon entropy, and carves trailing EOF overlay bytes.
* `detect_polyglots(file_path)`: Multi-format polyglot detector (ZIP+JPG, PDF+ZIP, GIF+JS, HTML+PNG, RAR+JPEG).
* `extract_metadata(file_path)`: Deep EXIF/XMP/IPTC and comment extraction via `exiftool` with PIL fallback.
* `scan_and_carve_binwalk(file_path, extract)`: Signature discovery and recursive archive carving.
* `carve_foremost(file_path)`: Header/footer carving for images, documents, and archives.
* `grep_flag_patterns(file_path, regex)`: Multi-encoding regex flag sweep across ASCII, UTF-8, and UTF-16LE/BE.

### 2. Image Steganography (Spatial, LSB & Steganalysis) (9 Tools)
* `statistical_steganalysis(file_path)`: **Chi-Square ($\chi^2$), Sample Pairs (SPA), and PoV tests** to estimate hidden LSB payload percentage.
* `solve_png_ihdr(file_path, output_path)`: Brute-forces PNG dimensions against IHDR CRC32 checksum to fix cropped images.
* `extract_bitplanes(file_path, output_dir)`: Deconstructs all 8 bitplanes across R, G, B, and Alpha channels (32 images).
* `analyze_png_chunks(file_path)`: Parses ancillary chunks (`tEXt`, `zTXt`, `iTXt`, `pHYs`, `sRGB`), validates CRCs, and detects hidden chunks.
* `analyze_gif_apng_frames(file_path)`: Deconstructs frames, extracts frame duration delays (ASCII flag data), and calculates frame deltas.
* `image_math_combine(image_1, image_2, mode)`: Visual cryptography combiner (`xor`, `subtract`, `add`, `difference`).
* `run_zsteg_analysis(file_path, all_modes)`: Exhaustive LSB/MSB/channel/permutation analyzer on PNG/BMP.
* `run_stegpy(file_path, password)`: Python LSB stego payload extraction.
* `run_cloaked_pixel(file_path, password)`: Recovers LSB payloads scattered across PRNG pixel matrices.

### 3. Image Steganography (Frequency & DCT Domain) (6 Tools)
* `run_stegseek(file_path, wordlist)`: Multithreaded RockYou Steghide passphrase cracker.
* `run_steghide(file_path, passphrase)`: Direct Steghide payload extraction from JPEG/BMP/WAV.
* `run_outguess(file_path, key)`: Redundant DCT coefficient stego extraction.
* `run_jsteg(file_path)`: Quantized DCT coefficient LSB extraction.
* `run_f5_stego(file_path, password)`: Matrix-encoding extraction via F5 algorithm.
* `analyze_jpeg_quantization_tables(file_path)`: Extracts JPEG DQT and DHT tables to identify compression artifacts.

### 4. Audio & Acoustic Steganography (8 Tools)
* `generate_audio_spectrogram(audio_path, output_path, cmap)`: High-resolution log/linear spectrogram rendering.
* `decode_dtmf_tones(audio_path)`: DTMF dial tone decoder (Goertzel / FFT frequency energy peak engine).
* `decode_sstv(audio_path, output_path)`: Slow-Scan TV (Robot36, Martin, Scottie) audio-to-image decoder.
* `decode_audio_morse(audio_path)`: Acoustic CW Morse code tone decoder converting audio energy envelopes to plaintext.
* `extract_deepsound(audio_path, password)`: AES-encrypted carrier extraction from WAV/FLAC containers.
* `run_mp3stego(mp3_path, password)`: MP3 layer-3 bit allocation table payload recovery.
* `audio_channel_phase_diff(audio_path, output_path)`: Stereo phase inversion & channel subtraction ($L - R$).
* `audio_lsb_extract(audio_path, num_bits)`: Direct PCM sample LSB extraction (8-bit, 16-bit, 24-bit).

### 5. Text, Whitespace, & Linguistic Steganography (5 Tools)
* `decode_zero_width_chars(text)`: Decodes `\u200B` (ZWSP), `\u200C` (ZWNJ), `\u200D` (ZWJ), `\uFEFF` (BOM), and `\u2060` (WJ).
* `run_stegsnow(file_path, password)`: Trailing whitespace and tab steganography extraction via SNOW.
* `detect_homoglyphs(text)`: Identifies Cyrillic, Greek, or lookalike Unicode characters and normalizes text.
* `solve_bacon_cipher(ciphertext)`: Solves Bacon's cipher across 24-letter and 26-letter alphabets.
* `decode_spammimic(text)`: SpamMimic spam text steganography payload decoder.

### 6. Network, PCAP & Covert Channels (2 Tools)
* `extract_pcap_covert_channels(pcap_path)`: Carves ICMP payloads, DNS subdomains/TXT exfiltration, and TCP SYN ISN leaks.
* `detect_network_tunneling(pcap_path)`: Heuristic detector for DNS tunneling (`dnscat2`, `iodine`) and ICMP tunneling (`ptunnel`).

### 7. Document, Font, & Container Steganography (4 Tools)
* `inspect_office_xml(file_path)`: Inspects DOCX/XLSX/PPTX structures for `<w:vanish/>`, white fonts, and hidden media.
* `inspect_pdf_stego(file_path)`: Analyzes PDF incremental update revisions (%%EOF count) and decompresses FlateDecode streams.
* `analyze_font_stego(font_path)`: Inspects TrueType / OpenType font files (`.ttf`, `.otf`) for hidden `cmap` table mappings.
* `inspect_git_stego(git_repo_path)`: Audits `.git` repositories for hidden dangling commits and unreachable objects.

### 8. AI Model, QR Code & Automated Decoding (3 Tools)
* `inspect_ai_model_stego(model_path)`: Forensics on PyTorch (`.pt`/`.pth`), SafeTensors, and ONNX models for metadata injection.
* `repair_and_read_qr(image_path)`: Reads and repairs corrupted QR codes (inverted polarity, thresholding).
* `auto_decode_payload(raw_data)`: Master CyberChef transform engine testing Base64, Base32, Base85, Base91, Base58, Hex, URL, 25 Caesar shifts, Zlib, and Single-byte XOR keys.

---

## 📄 License & Author

* **Author:** Knight_S
* **License:** Apache License 2.0
* **Repository:** [https://github.com/shaymimran26-netizen/StegoKiller](https://github.com/shaymimran26-netizen/StegoKiller)
* **Website:** [https://shaymimran26-netizen.github.io/StegoKiller/](https://shaymimran26-netizen.github.io/StegoKiller/)
