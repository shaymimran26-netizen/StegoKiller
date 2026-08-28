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
### The Ultimate Steganography, Digital Forensics & Covert-Channel Suite (v4.5.0)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg?style=for-the-badge)](LICENSE)
[![FastMCP](https://img.shields.io/badge/FastMCP-2025%20Ready-orange.svg?style=for-the-badge)](https://github.com/jlowin/fastmcp)
[![Tools](https://img.shields.io/badge/Tools-70%20Specialized%20Engines-06b6d4?style=for-the-badge&logo=shield)](https://shaymimran26-netizen.github.io/StegoKiller/)
[![Docker](https://img.shields.io/badge/Docker-GHCR%20Published-a855f7?style=for-the-badge&logo=docker)](https://github.com/shaymimran26-netizen/StegoKiller/pkgs/container/stegokiller)
[![Smithery](https://img.shields.io/badge/Smithery-Install%20Ready-f43f5e?style=for-the-badge)](https://smithery.ai)

<p align="center">
  <a href="https://shaymimran26-netizen.github.io/StegoKiller/">🌐 <strong>Live Interactive Documentation & Matrix Website</strong></a> •
  <a href="#quickstart">🚀 <strong>Quick Start</strong></a> •
  <a href="#full-auto-solve">🎯 <strong>Full Auto-Solve</strong></a> •
  <a href="#remote-hosting">☁️ <strong>Free Remote Hosting</strong></a> •
  <a href="#tool-matrix">🛠️ <strong>70 Tools Matrix</strong></a>
</p>

</div>

---

## 📖 Overview

**StegoKiller** is an enterprise-grade Model Context Protocol (MCP) server engineered specifically for CTF players, security researchers, and forensic analysts. Built using the official `FastMCP` framework, it integrates **70 specialized steganography, digital forensics, covert-channel extraction, and automated solving engines** across Images, Audio, Video, Network PCAPs, Documents, Fonts, Git, AI Models, Memory Dumps, and Text.

---

## 🎯 Full Autonomous Solving (`full_auto_solve`)

The centerpiece of **StegoKiller v4.5.0** is the **`full_auto_solve`** engine. Instead of manually guessing tools, simply pass any file path:

```python
full_auto_solve("/path/to/challenge.png")
```

`full_auto_solve` automatically executes a multi-stage forensic pipeline:
1. **File Identification & Entropy Analysis** (Magic bytes, quadrant entropy, overlay carver)
2. **Metadata & Comment Extraction** (ExifTool / IPTC / XMP)
3. **String & Multi-Encoding Flag Grep** (ASCII, UTF-8, UTF-16LE/BE)
4. **Polyglot & Dual-Signature Detection** (Corkami forensic patterns)
5. **Deep Binwalk Signature Carving**
6. **Format-Specific Deep Analysis**:
   - **PNG/BMP/GIF**: IHDR dimensions recovery, chunk anomalies, scanline filter byte stego, parallel LSB (zsteg, stegpy, openstego), 32-bitplane extraction, statistical steganalysis ($\chi^2$/SPA), alpha channel forensics, repeating tile detection, PVD steganalysis, color palette PLTE analysis, 2D FFT frequency analysis, QR repair & unmasking.
   - **JPEG**: Quantization tables (DQT/DHT), double compression ghosts, steghide dictionary attack (30+ CTF passwords), StegSeek RockYou crack, Jsteg, OutGuess, F5 algorithm.
   - **Audio (WAV/MP3/FLAC)**: High-resolution log spectrogram, CW Morse code demodulation, DTMF dial tone decoder, PCM sample LSB, stereo phase difference ($L - R$), DeepSound AES extraction, MP3Stego bit allocation.
   - **PDF/Documents**: Incremental update revisions, FlateDecode streams, Optional Content Groups (`/OCG`), embedded JavaScript, OLE VBA macros, Office XML vanishing text.
   - **Archives/PCAP**: Recursive archive unpacking (up to 15 levels), archive timestamp modulation, ICMP/DNS/TCP covert channels, network tunneling heuristics, covert HTTP headers.
7. **Single/Multi-Byte XOR Brute Force** (255-key sweep with auto flag detection)
8. **Automated CyberChef Transform Pipeline** (Base64/32/85/58, Hex, Caesar/ROT, Zlib, Bacon)
9. **Final Consolidated Report with Flag Highlighting**

---

## ⚡ Quick Start & Installation

### Option 1: 1-Click Install via Smithery CLI
```bash
npx -y @smithery/cli install @shaymimran26/stegokiller --client claude
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

### Option 3: Remote Cloud SSE (Render.com / Self-Hosted)
Connect directly to the live hosted cloud instance without local dependencies:
```json
{
  "mcpServers": {
    "stegokiller_cloud": {
      "url": "https://stegokiller.onrender.com/sse"
    }
  }
}
```

### Option 4: Docker Container via GitHub Container Registry (GHCR)
Run instantly in an isolated container:
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

| Platform | Type | How to Deploy |
| :--- | :--- | :--- |
| **[Render.com](https://render.com)** | Live Cloud Service | Deployed at `https://stegokiller.onrender.com/sse` using `render.yaml` blueprint. |
| **[Smithery.ai](https://smithery.ai)** | One-Click MCP Hosting | Available at `@shaymimran26/stegokiller` with auto-discovered 70-tool card. |
| **[Glama.ai](https://glama.ai/mcp/servers)** | Community Registry | Listed in global MCP index with `glama.json` manifest. |
| **[HuggingFace Spaces](https://huggingface.co/spaces)** | Free 24/7 Docker Hosting | Deploy Docker Space using included `Dockerfile`. |

---

## 🛠️ Comprehensive 70-Tool Matrix

### 1. Autonomous Master Pipelines & Auto-Solvers (3 Tools)
* `full_auto_solve(file_path)`: **Ultimate automated challenge solver.** Executes 16+ forensic stages, chains outputs, and extracts flags without manual intervention.
* `auto_triage_challenge(file_path)`: Autonomous 5-stage triage: structure audit, flag regex, metadata dump, polyglot audit, and binwalk signatures.
* `auto_decode_payload(raw_data)`: CyberChef heuristic engine: Base64, Base32, Base85, Base91, Base58, Hex, URL, 25 Caesar/ROT shifts, Zlib, and Single-byte XOR.

### 2. Core Triage, Integrity & File Carving (6 Tools)
* `inspect_file_structure(file_path)`: Validates 25+ magic headers, calculates quadrant and global Shannon entropy, and carves EOF overlay bytes.
* `detect_polyglots(file_path)`: Multi-format polyglot detector (ZIP+JPG, PDF+ZIP, GIF+JS, HTML+PNG, RAR+JPEG).
* `extract_metadata(file_path)`: Deep EXIF/XMP/IPTC metadata and thumbnail extraction via ExifTool.
* `scan_and_carve_binwalk(file_path, extract)`: Signature discovery and recursive archive carving.
* `carve_foremost(file_path)`: Header/footer raw file carving for images, documents, and archives.
* `grep_flag_patterns(file_path, regex)`: Multi-encoding regex flag sweep across ASCII, UTF-8, and UTF-16LE/BE.

### 3. Image Steganography: Spatial, LSB & Heuristics (13 Tools)
* `solve_png_ihdr(file_path, output_path)`: Brute-forces PNG dimensions against IHDR CRC32 checksum to fix cropped images.
* `extract_bitplanes(file_path, output_dir)`: Deconstructs and exports all 8 bitplanes across R, G, B, and Alpha channels (32 images).
* `extract_lsb_payload(file_path, channels, bit_order, bits, pixel_order)`: Direct LSB extraction with custom channel, bit-depth, and traversal control.
* `multi_tool_lsb_scan(file_path)`: Parallel LSB scan running `zsteg`, `stegpy`, `openstego`, and manual bit extraction.
* `analyze_png_chunks(file_path)`: Parses ancillary chunks (`tEXt`, `zTXt`, `pHYs`, `sRGB`), validates CRCs, and detects hidden chunks.
* `png_filter_byte_analysis(file_path)`: Scanline filter byte steganography extractor (0-4) with binary and base-5 decoders.
* `statistical_steganalysis(file_path)`: Chi-Square ($\chi^2$), Sample Pairs (SPA), and PoV tests to estimate hidden payload ratio.
* `detect_repeating_pixel_pattern(file_path)`: Auto-detects repeating pixel tile patterns and extracts the core payload.
* `detect_pvd_steganography(file_path)`: Pixel Value Differencing and edge-adaptive steganalysis.
* `analyze_color_palette_stego(file_path)`: Palette sorting, PLTE permutations, and index parity (EzStego/Cloak).
* `analyze_alpha_channel(file_path)`: Deep alpha channel forensics (binary transparency, LSB, and isolated plane export).
* `analyze_gif_apng_frames(file_path)`: Deconstructs frames, extracts frame delays (ASCII flag data), and calculates deltas.
* `run_zsteg_analysis(file_path, all_modes)`: Exhaustive LSB/MSB/channel/permutation analyzer on PNG/BMP.

### 4. Image Steganography: Specialized Tools & DCT/Frequency (10 Tools)
* `fft_frequency_analysis(file_path)`: 2D FFT magnitude and phase spectrum analyzer for frequency-domain watermarks.
* `detect_jpeg_ghosts(file_path, quality_start, quality_end)`: JPEG double compression variance and ghosting artifact detector.
* `analyze_jpeg_quantization_tables(file_path)`: Extracts JPEG DQT and DHT tables to identify compression anomalies.
* `steghide_dictionary_attack(file_path, wordlist_path, common_only)`: Dictionary attack testing 30+ common CTF passwords against Steghide.
* `stegseek_rockyou_crack(file_path, wordlist)`: Ultra-fast Steghide cracker testing millions of passwords per second.
* `run_stegseek(file_path, wordlist_path)`: Multithreaded RockYou Steghide passphrase cracker.
* `run_steghide(file_path, passphrase)`: Direct Steghide payload extraction from JPEG/BMP/WAV.
* `run_outguess(file_path, key)`: Redundant DCT coefficient stego extraction.
* `run_jsteg(file_path)`: Quantized DCT coefficient LSB extraction.
* `run_f5_stego(file_path, password)`: Matrix-encoding extraction via F5 algorithm.
* `run_stegpy(file_path, password)`: Python LSB stego payload extraction.
* `run_cloaked_pixel(file_path, password)`: Recovers LSB payloads scattered across PRNG pixel matrices.

### 5. Visual Cryptography & Matrix Solvers (3 Tools)
* `image_math_combine(image_path_1, image_path_2, mode)`: Visual cryptography combiner (`xor`, `subtract`, `add`, `difference`).
* `reconstruct_visual_crypto_2x2(share1_path, share2_path)`: Sub-pixel $2	imes2$ black-and-white visual cryptography share reconstructor.
* `repair_and_read_qr(image_path)`: Reads and repairs corrupted QR codes (inverted polarity, thresholding).

### 6. Audio, Acoustic & Radio Steganography (9 Tools)
* `generate_audio_spectrogram(audio_path, output_img_path, cmap)`: High-resolution log/linear spectrogram rendering.
* `decode_dtmf_tones(audio_path)`: DTMF dial tone decoder (Goertzel / FFT frequency energy peak engine).
* `decode_sstv(audio_path, output_img_path)`: Slow-Scan TV (Robot36, Martin, Scottie) audio-to-image decoder.
* `decode_audio_morse(audio_path)`: Acoustic CW Morse code tone decoder converting audio energy envelopes to plaintext.
* `decode_audio_fsk_afsk(audio_path, baud_rate)`: FSK/AFSK telemetry demodulator (Bell 103, Bell 202, RTTY).
* `descramble_audio_inversion(audio_path, carrier_freq)`: Frequency-inverted voice/audio descrambler.
* `extract_deepsound(audio_path, password)`: AES-encrypted carrier extraction from WAV/FLAC containers.
* `run_mp3stego(mp3_path, password)`: MP3 layer-3 bit allocation table payload recovery.
* `audio_channel_phase_diff(audio_path, output_path)`: Stereo phase inversion & channel subtraction ($L - R$).
* `audio_lsb_extract(audio_path, num_bits)`: Direct PCM sample LSB extraction (8-bit, 16-bit, 24-bit).

### 7. Document, Office & PDF Steganography (5 Tools)
* `inspect_office_xml(file_path)`: Inspects DOCX/XLSX/PPTX structures for `<w:vanish/>`, white fonts, and hidden media.
* `inspect_ole_vba_macros(file_path)`: OLE Compound File Binary (.doc, .xls, .ppt) stream and obfuscated VBA macro inspector.
* `inspect_pdf_stego(file_path)`: Analyzes PDF incremental update revisions (%%EOF count) and decompresses FlateDecode streams.
* `inspect_pdf_layers_and_js(file_path)`: PDF Optional Content Groups (`/OCG`), `/Launch` actions, and embedded JavaScript streams.
* `analyze_font_stego(font_path)`: TrueType / OpenType font files (`.ttf`, `.otf`) `cmap` table stego inspector.

### 8. Archives, Memory & Forensics (5 Tools)
* `recursive_archive_unpacker(archive_path, max_depth)`: Recursively unpacks nested archives (ZIP, 7z, TAR, GZ, BZ2, XZ, RAR) up to 15 levels deep.
* `extract_archive_metadata_covert(archive_path)`: TAR and ZIP header timestamp, UID/GID, and NTFS extra field covert channel extractor.
* `carve_memory_dump_secrets(dump_path)`: RAM memory core dump scanner for SSL master secrets, SSH keys, env vars, and flags.
* `inspect_git_stego(git_repo_path)`: Audits `.git` repositories for hidden dangling commits and unreachable objects.
* `inspect_ai_model_stego(model_path)`: Forensics on PyTorch (`.pt`/`.pth`), SafeTensors, and ONNX models for metadata injection and weight LSB tampering.

### 9. Network, PCAP & Covert Channels (3 Tools)
* `extract_pcap_covert_channels(pcap_path)`: Carves ICMP payloads, DNS subdomains/TXT exfiltration, and TCP SYN ISN leaks.
* `detect_network_tunneling(pcap_path)`: Heuristic detector for DNS tunneling (`dnscat2`, `iodine`) and ICMP tunneling (`ptunnel`).
* `detect_covert_http_headers(pcap_or_log_path)`: Custom HTTP exfiltration headers (`X-Flag`), Base64 cookies, and chunked trailing padding.

### 10. Obscure Ciphers, Whitespace & Linguistics (8 Tools)
* `xor_bruteforce(file_path, max_key_len)`: Single-byte and multi-byte XOR key brute-forcer (255 keys, auto flag detection).
* `decode_zero_width_chars(text)`: Decodes `​` (ZWSP), `‌` (ZWNJ), `‍` (ZWJ), `﻿` (BOM), and `⁠` (WJ).
* `run_stegsnow(file_path, password)`: Trailing whitespace and tab steganography extraction via SNOW.
* `detect_homoglyphs(text)`: Identifies Cyrillic, Greek, or lookalike Unicode characters and normalizes text.
* `solve_bacon_cipher(ciphertext)`: Solves Bacon's cipher across 24-letter and 26-letter alphabets.
* `decode_spammimic(text)`: SpamMimic spam text steganography payload decoder.
* `decode_dna_steganography(sequence)`: DNA nucleotide sequence ($A=00, C=01, G=10, T=11$) and Amino Acid Codon decoder.
* `decode_baudot_murray_code(raw_bits_or_text)`: 5-bit ITA2 Baudot/Murray teleprinter punch tape code decoder with LTRS/FIGS shifts.
* `decode_braille_steganography(text)`: Unicode Braille patterns ($U+2800$ to $U+28FF$) to English alphanumeric text.
* `decode_morse_in_whitespace(text)`: Multi-radix whitespace Morse code decoder (Spaces=dot, Tabs=dash).

---

## 📄 License & Author

* **Author:** Knight_S
* **License:** Apache License 2.0
* **Repository:** [https://github.com/shaymimran26-netizen/StegoKiller](https://github.com/shaymimran26-netizen/StegoKiller)
* **Website:** [https://shaymimran26-netizen.github.io/StegoKiller/](https://shaymimran26-netizen.github.io/StegoKiller/)
