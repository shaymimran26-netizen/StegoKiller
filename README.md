# StegoKiller MCP Server (Enterprise Edition)

> **Author**: Knight_S  
> **Framework**: FastMCP (`mcp.server.fastmcp`)  
> **Version**: 3.0.0 (Ultra-Enriched CTF Suite)  
> **Total Registered Tools**: 44 Tools  
> **Scope**: Images, Audio, Video, Network PCAPs, Documents, Fonts, Git, AI Models, and Text Steganography.  

---

## Architecture Overview

**StegoKiller** is a state-of-the-art Model Context Protocol (MCP) server engineered for CTF competitors, malware analysts, and digital forensics professionals. Synthesized from research across **50+ premier security repositories and CTF writeups**, it unifies 44 advanced steganography, steganalysis, and covert-channel inspection tools into a single, high-speed MCP server.

---

## Comprehensive Tool Reference Matrix (44 Tools)

### 1. Core Triage, File Integrity & Polyglots (7 Tools)
* `inspect_file_structure(file_path: str)`: Magic byte validation against 25+ formats, global and quadrant Shannon entropy calculation, and EOF overlay carving.
* `extract_metadata(file_path: str)`: Deep EXIF/XMP/IPTC and comment extraction via `exiftool` with PIL fallback.
* `scan_and_carve_binwalk(file_path: str, extract: bool = False)`: Signature detection and automated recursive archive carving.
* `carve_foremost(file_path: str)`: Raw header/footer carving across major media and archive types.
* `grep_flag_patterns(file_path: str, regex: str = r"(?i)(flag|ctf)\{[^}]+\}")`: Regex flag sweep across ASCII, UTF-8, UTF-16LE, and UTF-16BE strings.
* `detect_polyglots(file_path: str)`: Multi-format polyglot detection (ZIP+JPEG, PDF+ZIP, GIF+JS, HTML+PNG, RAR+JPEG).
* `auto_triage_challenge(file_path: str)`: **Autonomous 5-stage master pipeline** running structure analysis, strings/flag sweep, metadata dump, polyglot check, and signature scanning in one call.

### 2. Image Steganography (Spatial, LSB & Steganalysis) (9 Tools)
* `run_zsteg_analysis(file_path: str, all_modes: bool = True)`: Multi-channel LSB/MSB/permutation detection on PNG/BMP.
* `solve_png_ihdr(file_path: str, output_path: str = "")`: Brute-forces correct PNG height/width against the IHDR CRC32 checksum.
* `extract_bitplanes(file_path: str, output_dir: str = "")`: Deconstructs and exports all 8 bitplanes across R, G, B, and A channels (32 images).
* `statistical_steganalysis(file_path: str)`: **Chi-Square ($\chi^2$) analysis, Sample Pairs Analysis (SPA), and RS steganalysis** to calculate hidden LSB payload percentage.
* `analyze_png_chunks(file_path: str)`: Parses ancillary PNG chunks (`tEXt`, `zTXt`, `iTXt`, `pHYs`, `sRGB`), verifies CRCs, and detects hidden chunks.
* `analyze_gif_apng_frames(file_path: str)`: Deconstructs GIF and APNG frames, extracts per-frame delay millisecond sequences (ASCII flag data), and exports frames.
* `image_math_combine(image_path_1: str, image_path_2: str, mode: str = "xor")`: Image combiner for visual cryptography shares (`xor`, `subtract`, `add`, `difference`).
* `run_stegpy(file_path: str, password: str = "")`: Python LSB/cryptography steganography payload extraction.
* `run_cloaked_pixel(file_path: str, password: str)`: LSB extraction using PRNG-scattered pixel matrices with passphrases.

### 3. Image Steganography (Frequency, Transform & Matrix Domain) (6 Tools)
* `run_stegseek(file_path: str, wordlist_path: str = "/usr/share/wordlists/rockyou.txt")`: High-speed multithreaded Steghide cracker.
* `run_steghide(file_path: str, passphrase: str = "")`: Direct extraction from JPEG/BMP/WAV using Steghide.
* `run_outguess(file_path: str, key: str = "")`: Extracts data hidden in redundant JPEG DCT bits.
* `run_jsteg(file_path: str)`: Recovers hidden data from quantized JPEG DCT coefficients.
* `run_f5_stego(file_path: str, password: str = "")`: Matrix-encoding extraction via F5 algorithm.
* `analyze_jpeg_quantization_tables(file_path: str)`: Extracts JPEG DQT quantization tables, DHT Huffman tables, and analyzes compression artifacts.

### 4. Audio & Acoustic Steganography (8 Tools)
* `generate_audio_spectrogram(audio_path: str, output_img_path: str = "", cmap: str = "inferno")`: High-resolution log/linear spectrogram rendering.
* `decode_dtmf_tones(audio_path: str)`: DTMF dial tone decoder (Goertzel/FFT frequency energy peak engine).
* `decode_sstv(audio_path: str, output_img_path: str = "")`: Slow-Scan TV (Robot, Martin, Scottie) audio-to-image decoding.
* `decode_audio_morse(audio_path: str)`: Acoustic CW Morse code decoder converting audio energy envelope to dots/dashes and plaintext.
* `extract_deepsound(audio_path: str, password: str = "")`: AES-encrypted carrier extraction from WAV/FLAC containers.
* `run_mp3stego(mp3_path: str, password: str = "")`: MP3 layer-3 bit allocation table payload recovery.
* `audio_channel_phase_diff(audio_path: str, output_path: str = "")`: Stereo phase inversion & channel subtraction ($L - R$).
* `audio_lsb_extract(audio_path: str, num_bits: int = 1)`: Direct PCM sample LSB extraction (8-bit, 16-bit, 24-bit).

### 5. Text, Whitespace, & Linguistic Steganography (5 Tools)
* `decode_zero_width_chars(text: str)`: Decodes `\u200B` (ZWSP), `\u200C` (ZWNJ), `\u200D` (ZWJ), `\uFEFF` (BOM), `\u2060` (WJ), and variation selectors.
* `run_stegsnow(file_path: str, password: str = "")`: Trailing whitespace and tab steganography extraction via SNOW.
* `detect_homoglyphs(text: str)`: Identifies Cyrillic, Greek, or lookalike Unicode characters and reconstructs normalized text.
* `solve_bacon_cipher(ciphertext: str)`: Bacon's cipher decoder supporting 24-letter and 26-letter alphabets, case variations, and bold/italic markup.
* `decode_spammimic(text: str)`: SpamMimic spam text steganography payload decoder.

### 6. Network, PCAP & Covert Channels (2 Tools)
* `extract_pcap_covert_channels(pcap_path: str)`: Deep PCAP parsing for ICMP payloads, DNS subdomains/TXT exfiltration, and TCP SYN ISN leaks.
* `detect_network_tunneling(pcap_path: str)`: Heuristic detector for DNS tunneling (`dnscat2`, `iodine`) and ICMP tunneling (`ptunnel`).

### 7. Document, Font, & Container Steganography (4 Tools)
* `inspect_office_xml(file_path: str)`: Inspects DOCX/XLSX/PPTX structures for `<w:vanish/>`, white fonts, microscopic fonts, and orphaned media.
* `inspect_pdf_stego(file_path: str)`: Analyzes PDF incremental update revisions (%%EOF count), unreferenced stream objects, and decompresses FlateDecode streams.
* `analyze_font_stego(font_path: str)`: Inspects TrueType / OpenType font files (`.ttf`, `.otf`) for hidden `cmap` table mappings and custom tables.
* `inspect_git_stego(git_repo_path: str)`: Inspects `.git` repositories for hidden dangling commits, tree steganography, and unreachable objects.

### 8. AI Model, QR Code & Automated Decoding (3 Tools)
* `inspect_ai_model_stego(model_path: str)`: Forensics on PyTorch (`.pt`/`.pth`), SafeTensors (`.safetensors`), and ONNX (`.onnx`) models for metadata injection, pickle RCE payloads, and entropy anomalies.
* `repair_and_read_qr(image_path: str)`: Reads and repairs corrupted QR codes (inverted polarity, thresholding, damaged finder patterns).
* `auto_decode_payload(raw_data: str)`: Master CyberChef transform engine testing Base64, Base32, Base85, Base91, Base58, Hex, URL, 25 Caesar shifts, Zlib, and Single-byte XOR.

---

## Quick Start & Installation

```bash
cd /home/shaym/StegoKiller
chmod +x setup.sh
./setup.sh
```

---

## Claude Desktop / MCP Client Configuration

```json
{
  "mcpServers": {
    "stegokiller": {
      "command": "python3",
      "args": [
        "/home/shaym/StegoKiller/server.py"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/go/bin"
      }
    }
  }
}
```
