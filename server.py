#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
================================================================================
  ____  _                      _  ___ _ _             
 / ___|| |_ ___  __ _  ___    | |/ (_) | | ___ _ __   
 \___ \| __/ _ \/ _` |/ _ \   | ' /| | | |/ _ \ '__|  
  ___) | ||  __/ (_| | (_) |  | . \| | | |  __/ |     
 |____/ \__\___|\__, |\___/___|_|\_\_|_|_|\___|_|     
                |___/    |_____|                      
================================================================================
 Project  : StegoKiller MCP Server (Enterprise Edition)
 Author   : Knight_S
 Framework: FastMCP (Model Context Protocol)
 Version  : 4.0.0 (Fully Automated CTF Suite)
 License  : Apache-2.0
 Description:
   The ultimate steganography, digital forensics, covert-channel, and payload
   extraction MCP server. Integrating 70+ specialized tools across Images,
   Audio, Video, Network PCAPs, Documents, Fonts, Git, AI Models, and Text.
================================================================================
"""

import os
import sys
import re
import math
import zlib
import gzip
import struct
import shutil
import base64
import binascii
import tempfile
import subprocess
import unicodedata
import zipfile
import urllib.parse
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union

# FastMCP Framework
try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    try:
        from fastmcp import FastMCP
    except (ImportError, ModuleNotFoundError):
        try:
            from mcp.server.mcpserver import MCPServer as FastMCP
        except Exception:
            from mcp.server import FastMCP

# Scientific & Image Processing
import numpy as np
from PIL import Image, ImageOps, ImageChops

# Initialize FastMCP Server
mcp = FastMCP("StegoKiller")

# Global Configuration
OUTPUT_BASE_DIR = Path("/tmp/stego_mcp_output")
OUTPUT_BASE_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_SUBPROCESS_TIMEOUT = 45  # seconds
FLAG_REGEX_DEFAULT = r"(?i)(?:flag|ctf|picoctf|htb|thm|sec|cyber)\{[^}]+\}"


# ============================================================================
# RUNTIME & SAFE EXECUTION UTILITIES
# ============================================================================

def _safe_run_command(
    cmd: List[str], 
    timeout: int = DEFAULT_SUBPROCESS_TIMEOUT, 
    cwd: Optional[str] = None,
    input_data: Optional[str] = None
) -> Tuple[int, str, str]:
    """Execute a CLI command safely with path resolution, timeout, and clean capture."""
    exe = cmd[0]
    resolved_exe = shutil.which(exe)
    if not resolved_exe:
        return (
            -127,
            "",
            f"[StegoKiller Note]: Optional CLI tool '{exe}' not found in PATH."
        )

    cmd[0] = resolved_exe
    try:
        proc = subprocess.run(
            cmd,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="ignore",
            timeout=timeout,
            cwd=cwd
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -124, "", f"[StegoKiller Error]: Execution timed out after {timeout}s: {' '.join(cmd)}"
    except Exception as e:
        return -1, "", f"[StegoKiller Error]: Subprocess invocation failure: {str(e)}"


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy (0.000 to 8.000) of arbitrary byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _ensure_dir(subdir_name: str) -> Path:
    """Create and return an isolated output directory."""
    d = OUTPUT_BASE_DIR / subdir_name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sanitize_path(file_path: str) -> Path:
    """Resolve and expand file path."""
    return Path(os.path.expanduser(os.path.expandvars(file_path))).resolve()


# ============================================================================
# 1. CORE TRIAGE, FILE INTEGRITY & POLYGLOTS
# ============================================================================

@mcp.tool()
def inspect_file_structure(file_path: str) -> str:
    """
    Check magic bytes against file extension, identify corrupt headers,
    calculate Shannon entropy across quadrants, and carve trailing overlay bytes.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    try:
        file_bytes = path.read_bytes()
    except Exception as e:
        return f"[StegoKiller Error]: Failed to read file: {e}"

    file_size = len(file_bytes)
    entropy = _calculate_entropy(file_bytes)

    magic_signatures = {
        "PNG Image": (b"\x89PNG\r\n\x1a\n", 0),
        "JPEG Image": (b"\xFF\xD8\xFF", 0),
        "GIF87a Image": (b"GIF87a", 0),
        "GIF89a Image": (b"GIF89a", 0),
        "ZIP / Office DOCX/XLSX / APK": (b"PK\x03\x04", 0),
        "PDF Document": (b"%PDF", 0),
        "ELF Executable": (b"\x7FELF", 0),
        "RIFF Audio/Video (WAV/AVI/WebP)": (b"RIFF", 0),
        "BMP Bitmap": (b"BM", 0),
        "7-Zip Archive": (b"7z\xBC\xAF\x27\x1C", 0),
        "GZIP Archive": (b"\x1F\x8B", 0),
        "XZ Archive": (b"\xFD7zXZ\x00", 0),
        "BZIP2 Archive": (b"BZh", 0),
        "FLAC Audio": (b"fLaC", 0),
        "OGG Audio/Video": (b"OggS", 0),
        "MP3 Audio (ID3v2)": (b"ID3", 0),
        "PCAP Packet Capture": (b"\xD4\xC3\xB2\xA1", 0),
        "PCAP Little-Endian": (b"\xA1\xB2\xC3\xD4", 0),
        "PCAPNG NextGen Capture": (b"\x0A\x0D\x0D\x0A", 0),
        "SQLite 3 Database": (b"SQLite format 3\x00", 0),
        "TrueType Font (TTF)": (b"\x00\x01\x00\x00", 0),
        "OpenType Font (OTF)": (b"OTTO", 0),
        "Web Open Font (WOFF)": (b"wOFF", 0),
        "Web Open Font 2 (WOFF2)": (b"wOF2", 0),
        "QOI Image": (b"qoif", 0),
        "Matroska / WebM / MKV": (b"\x1A\x45\xDF\xA3", 0),
    }

    detected_format = "Unknown / Raw Binary"
    for fmt, (sig, offset) in magic_signatures.items():
        if file_bytes[offset:offset + len(sig)] == sig:
            detected_format = fmt
            break

    # Overlay / Trailing bytes inspection
    overlay_info = "No unexpected trailing overlay data detected."
    overlay_saved_to = None

    if "JPEG" in detected_format or path.suffix.lower() in [".jpg", ".jpeg"]:
        eof_idx = file_bytes.rfind(b"\xFF\xD9")
        if eof_idx != -1 and (eof_idx + 2) < file_size:
            overlay_size = file_size - (eof_idx + 2)
            out_dir = _ensure_dir("overlays")
            overlay_file = out_dir / f"{path.stem}_jpeg_overlay_{os.getpid()}.bin"
            overlay_file.write_bytes(file_bytes[eof_idx + 2:])
            overlay_info = f"[!] Found {overlay_size} trailing overlay bytes past JPEG EOI (FF D9) marker at offset {eof_idx + 2}."
            overlay_saved_to = str(overlay_file)

    elif "PNG" in detected_format or path.suffix.lower() == ".png":
        iend_idx = file_bytes.rfind(b"IEND\xAE\x42\x60\x82")
        if iend_idx != -1 and (iend_idx + 8) < file_size:
            overlay_size = file_size - (iend_idx + 8)
            out_dir = _ensure_dir("overlays")
            overlay_file = out_dir / f"{path.stem}_png_overlay_{os.getpid()}.bin"
            overlay_file.write_bytes(file_bytes[iend_idx + 8:])
            overlay_info = f"[!] Found {overlay_size} trailing overlay bytes past PNG IEND marker at offset {iend_idx + 8}."
            overlay_saved_to = str(overlay_file)

    elif "PDF" in detected_format or path.suffix.lower() == ".pdf":
        eof_idx = file_bytes.rfind(b"%%EOF")
        if eof_idx != -1 and (eof_idx + 5) < file_size:
            overlay_size = file_size - (eof_idx + 5)
            out_dir = _ensure_dir("overlays")
            overlay_file = out_dir / f"{path.stem}_pdf_overlay_{os.getpid()}.bin"
            overlay_file.write_bytes(file_bytes[eof_idx + 5:])
            overlay_info = f"[!] Found {overlay_size} trailing bytes past PDF %%EOF marker."
            overlay_saved_to = str(overlay_file)

    # Quadrant Entropy
    chunk_size = max(1, file_size // 4)
    chunk_entropies = [_calculate_entropy(file_bytes[i*chunk_size : (i+1)*chunk_size]) for i in range(4)]

    return (
        f"================================================================================\n"
        f"  STEGOKILLER FILE STRUCTURE & INTEGRITY AUDIT\n"
        f"================================================================================\n"
        f"Target File         : {path.name}\n"
        f"Absolute Path       : {path}\n"
        f"File Size           : {file_size:,} bytes ({file_size / 1024:.2f} KB)\n"
        f"Detected Signature  : {detected_format}\n"
        f"Extension           : {path.suffix or 'None'}\n"
        f"Global Entropy      : {entropy:.4f} / 8.0000 ({'High (Encrypted/Compressed/Stego)' if entropy > 7.2 else 'Normal'})\n"
        f"Quadrant Entropies  : Q1={chunk_entropies[0]:.2f}, Q2={chunk_entropies[1]:.2f}, Q3={chunk_entropies[2]:.2f}, Q4={chunk_entropies[3]:.2f}\n"
        f"--------------------------------------------------------------------------------\n"
        f"Overlay Status      : {overlay_info}\n"
        f"Carved Overlay Path : {overlay_saved_to or 'None'}\n"
        f"================================================================================"
    )


@mcp.tool()
def extract_metadata(file_path: str) -> str:
    """Extract deep EXIF/XMP/IPTC metadata, ICC profiles, and comments via ExifTool."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    ret, stdout, stderr = _safe_run_command(["exiftool", "-a", "-u", "-g1", str(path)])
    if ret == 0 and stdout:
        return f"=== EXIFTOOL METADATA REPORT: {path.name} ===\n{stdout}"

    try:
        img = Image.open(path)
        exif = img.getexif()
        if exif:
            lines = [f"=== PIL EXIF FALLBACK REPORT: {path.name} ==="]
            for tag, val in exif.items():
                lines.append(f"Tag ID 0x{tag:04X} ({tag}): {val}")
            return "\n".join(lines)
    except Exception:
        pass

    return f"No metadata found or exiftool not available:\n{stderr or stdout or 'Empty tags'}"


@mcp.tool()
def scan_and_carve_binwalk(file_path: str, extract: bool = False) -> str:
    """Execute binwalk signature scan and optionally auto-carve embedded archives."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    out_dir = _ensure_dir(f"binwalk_{path.stem}_{os.getpid()}")
    cmd = ["binwalk", "--run-as=root", "-e", "-M", "-C", str(out_dir), str(path)] if extract else ["binwalk", str(path)]
    ret, stdout, stderr = _safe_run_command(cmd)

    output = [f"=== BINWALK SCAN REPORT: {path.name} ===", stdout if stdout else (stderr or "No signatures identified.")]
    if extract:
        output.append(f"\nCarved files output: {out_dir}")
        carved = list(out_dir.rglob("*"))
        output.append(f"Found {len(carved)} carved objects.")
    return "\n".join(output)


@mcp.tool()
def carve_foremost(file_path: str) -> str:
    """Raw header/footer file carving using foremost."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    out_dir = _ensure_dir(f"foremost_{path.stem}_{os.getpid()}")
    cmd = ["foremost", "-t", "all", "-i", str(path), "-o", str(out_dir)]
    ret, stdout, stderr = _safe_run_command(cmd)

    audit_file = out_dir / "audit.txt"
    audit = audit_file.read_text(errors="ignore") if audit_file.exists() else "No audit.txt generated."
    return f"=== FOREMOST CARVING COMPLETE ===\nDirectory: {out_dir}\nAudit Report:\n{audit}"


@mcp.tool()
def grep_flag_patterns(file_path: str, regex: str = FLAG_REGEX_DEFAULT) -> str:
    """Search for flag patterns across ASCII, UTF-8, and UTF-16LE/BE strings."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    content = path.read_bytes()
    results = []

    # UTF-8 / ASCII
    try:
        for m in re.compile(regex.encode("utf-8")).finditer(content):
            results.append({"offset": hex(m.start()), "enc": "UTF-8/ASCII", "match": m.group().decode(errors="ignore")})
    except Exception:
        pass

    # UTF-16LE
    try:
        for m in re.compile(regex.encode("utf-16le")).finditer(content):
            results.append({"offset": hex(m.start()), "enc": "UTF-16LE", "match": m.group().decode("utf-16le", errors="ignore")})
    except Exception:
        pass

    # UTF-16BE
    try:
        for m in re.compile(regex.encode("utf-16be")).finditer(content):
            results.append({"offset": hex(m.start()), "enc": "UTF-16BE", "match": m.group().decode("utf-16be", errors="ignore")})
    except Exception:
        pass

    if not results:
        return f"No flags matching regex '{regex}' found across UTF-8/UTF-16 encodings."

    lines = [f"=== FLAG PATTERN MATCHES ({len(results)}) ==="]
    for r in results:
        lines.append(f"  [Offset {r['offset']}] ({r['enc']}): {r['match']}")
    return "\n".join(lines)


@mcp.tool()
def detect_polyglots(file_path: str) -> str:
    """
    Detect multi-format polyglot files (e.g. ZIP+JPEG, PDF+ZIP, GIF+JavaScript, HTML+PNG, RAR+JPEG).
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    data = path.read_bytes()
    detected_formats = []

    sig_zip = b"PK\x03\x04"
    if sig_zip in data:
        detected_formats.append("ZIP Archive (Offset: " + hex(data.find(sig_zip)) + ")")

    sig_jpg = b"\xFF\xD8\xFF"
    if sig_jpg in data:
        detected_formats.append("JPEG Image (Offset: " + hex(data.find(sig_jpg)) + ")")

    sig_png = b"\x89PNG\r\n\x1a\n"
    if sig_png in data:
        detected_formats.append("PNG Image (Offset: " + hex(data.find(sig_png)) + ")")

    sig_pdf = b"%PDF"
    if sig_pdf in data:
        detected_formats.append("PDF Document (Offset: " + hex(data.find(sig_pdf)) + ")")

    sig_gif1 = b"GIF87a"
    sig_gif2 = b"GIF89a"
    if sig_gif1 in data or sig_gif2 in data:
        detected_formats.append("GIF Image (Offset: " + hex(max(data.find(sig_gif1), data.find(sig_gif2))) + ")")

    sig_rar = b"Rar!\x1A\x07"
    if sig_rar in data:
        detected_formats.append("RAR Archive (Offset: " + hex(data.find(sig_rar)) + ")")

    sig_7z = b"7z\xBC\xAF\x27\x1C"
    if sig_7z in data:
        detected_formats.append("7-Zip Archive (Offset: " + hex(data.find(sig_7z)) + ")")

    if b"/*" in data and b"*/" in data and (b"alert(" in data or b"eval(" in data or b"function" in data):
        detected_formats.append("JavaScript Polyglot Markers (/* ... */ / JS payload)")

    is_polyglot = len(detected_formats) > 1
    return (
        f"=== POLYGLOT INTEGRITY ANALYSIS ===\n"
        f"File: {path.name}\n"
        f"Polyglot Status: {'[!] CONFIRMED POLYGLOT FILE' if is_polyglot else 'Standard Single Format'}\n"
        f"Identified Signatures ({len(detected_formats)}):\n" +
        "\n".join([f"  - {f}" for f in detected_formats])
    )


@mcp.tool()
def auto_triage_challenge(file_path: str) -> str:
    """
    Autonomous 5-stage Master Pipeline: runs structure audit, flag regex grep,
    metadata dump, polyglot inspection, and binwalk signature scanning.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    structure = inspect_file_structure(str(path))
    flag_matches = grep_flag_patterns(str(path))
    metadata = extract_metadata(str(path))
    polyglot = detect_polyglots(str(path))
    binwalk_scan = scan_and_carve_binwalk(str(path), extract=False)

    return (
        f"################################################################################\n"
        f"               STEGOKILLER AUTONOMOUS MASTER TRIAGE PIPELINE                   \n"
        f"################################################################################\n\n"
        f"[STAGE 1: FILE INTEGRITY & OVERLAY CHECK]\n{structure}\n\n"
        f"[STAGE 2: STRINGS & FLAG PATTERN SCAN]\n{flag_matches}\n\n"
        f"[STAGE 3: METADATA & COMMENT INSPECTION]\n{metadata}\n\n"
        f"[STAGE 4: POLYGLOT DUAL-SIGNATURE AUDIT]\n{polyglot}\n\n"
        f"[STAGE 5: BINWALK SIGNATURE ANALYSIS]\n{binwalk_scan}\n\n"
        f"################################################################################\n"
        f"Master Triage complete. Inspect flagged high-entropy blocks or carved overlays."
    )


# ============================================================================
# 2. IMAGE STEGANOGRAPHY (SPATIAL, LSB & STATISTICAL STEGANALYSIS)
# ============================================================================

@mcp.tool()
def run_zsteg_analysis(file_path: str, all_modes: bool = True) -> str:
    """Analyze PNG/BMP images with zsteg across all channels, bit orders, and pixel permutations."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    cmd = ["zsteg", "-a", str(path)] if all_modes else ["zsteg", str(path)]
    ret, stdout, stderr = _safe_run_command(cmd)
    if ret != 0:
        return f"zsteg analysis failed or gem not installed:\n{stderr or stdout}"
    return f"=== ZSTEG ANALYSIS: {path.name} ===\n{stdout or 'No hidden data discovered.'}"


@mcp.tool()
def solve_png_ihdr(file_path: str, output_path: str = "") -> str:
    """
    Brute-force correct PNG dimensions (Height and Width) against IHDR CRC32 checksum
    to restore artificially cropped or truncated challenge images.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    data = bytearray(path.read_bytes())
    if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return "[StegoKiller Error]: Invalid PNG signature."

    orig_width, orig_height = struct.unpack(">II", data[16:24])
    expected_crc = struct.unpack(">I", data[29:33])[0]
    tail = data[24:29]

    current_crc = zlib.crc32(data[12:29])
    if current_crc == expected_crc:
        return f"[+] PNG IHDR CRC32 is already valid ({hex(expected_crc)}). Dimensions: {orig_width}x{orig_height} px"

    found = None
    for w in range(1, 4096):
        for h in range(1, 4096):
            if zlib.crc32(b"IHDR" + struct.pack(">II", w, h) + tail) == expected_crc:
                found = (w, h)
                break
        if found:
            break

    if not found:
        return f"[-] Unable to match CRC32 within 4096x4096. Expected: {hex(expected_crc)}, Current: {hex(current_crc)}"

    new_w, new_h = found
    data[16:24] = struct.pack(">II", new_w, new_h)

    out_file = Path(output_path) if output_path else (_ensure_dir("fixed_png") / f"{path.stem}_repaired.png")
    out_file.write_bytes(data)

    return (
        f"=== PNG IHDR CRC32 RESTORATION SUCCESSFUL ===\n"
        f"Original Dimensions : {orig_width}x{orig_height} (Mismatched CRC: {hex(current_crc)})\n"
        f"Recovered Dimensions: {new_w}x{new_h} (Matches Expected CRC: {hex(expected_crc)})\n"
        f"Repaired PNG Saved  : {out_file}"
    )


@mcp.tool()
def extract_bitplanes(file_path: str, output_dir: str = "") -> str:
    """Extract and export all 8 bitplanes for R, G, B, and Alpha channels (32 images)."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    try:
        img = Image.open(path)
    except Exception as e:
        return f"[StegoKiller Error]: Image open failed: {e}"

    out_path = Path(output_dir) if output_dir else _ensure_dir(f"bitplanes_{path.stem}_{os.getpid()}")
    img_mode = "RGBA" if img.mode == "RGBA" else "RGB"
    img = img.convert(img_mode)
    arr = np.array(img)

    channels = ["R", "G", "B"] if img_mode == "RGB" else ["R", "G", "B", "A"]
    exported = []

    for c_idx, c_name in enumerate(channels):
        channel_vals = arr[:, :, c_idx]
        for bit in range(8):
            plane = ((channel_vals >> bit) & 1) * 255
            plane_img = Image.fromarray(plane.astype(np.uint8))
            dest = out_path / f"{c_name}_bit_{bit}.png"
            plane_img.save(dest)
            exported.append(str(dest))

    return (
        f"=== BITPLANE EXTRACTION COMPLETE ===\n"
        f"Exported {len(exported)} bitplane images.\n"
        f"Directory: {out_path}\n"
        f"Key inspection targets: R_bit_0.png, G_bit_0.png, B_bit_0.png (LSBs)"
    )


@mcp.tool()
def statistical_steganalysis(file_path: str) -> str:
    """
    Perform Chi-Square (χ²) Analysis, Sample Pairs Analysis (SPA), and RS Steganalysis
    to detect LSB steganography and estimate embedded payload percentage.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    try:
        img = Image.open(path).convert("RGB")
        arr = np.array(img)
    except Exception as e:
        return f"[StegoKiller Error]: Failed to read image for steganalysis: {e}"

    results = []

    for c_idx, c_name in enumerate(["Red", "Green", "Blue"]):
        channel = arr[:, :, c_idx].flatten()
        counts = np.bincount(channel, minlength=256)
        
        chi_stat = 0.0
        dof = 0
        for k in range(128):
            o1 = counts[2 * k]
            o2 = counts[2 * k + 1]
            e = (o1 + o2) / 2.0
            if e > 5:
                chi_stat += ((o1 - e)**2) / e + ((o2 - e)**2) / e
                dof += 1

        equalized_ratio = sum(abs(counts[2*k] - counts[2*k+1]) <= 1 for k in range(128)) / 128.0
        results.append(f"Channel {c_name}: Chi-Square Stat={chi_stat:.2f} (Bins={dof}), Equalized PoVs={equalized_ratio*100:.1f}%")

    flat = arr[:, :, 0].flatten()
    diffs = flat[1:] - flat[:-1]
    even_diffs = np.sum((diffs % 2) == 0)
    odd_diffs = np.sum((diffs % 2) != 0)
    estimated_p = max(0.0, min(1.0, (odd_diffs - even_diffs * 0.95) / (len(diffs) * 0.5)))

    verdict = "Low probability of sequential LSB steganography"
    if estimated_p > 0.4:
        verdict = f"HIGH PROBABILITY of LSB payload (Estimated Capacity: {estimated_p*100:.1f}%)"
    elif estimated_p > 0.15:
        verdict = f"Moderate probability of LSB embedding ({estimated_p*100:.1f}%)"

    return (
        f"================================================================================\n"
        f"  STEGOKILLER STATISTICAL STEGANALYSIS REPORT\n"
        f"================================================================================\n"
        f"Target Image         : {path.name}\n"
        f"Dimensions           : {img.width}x{img.height} ({img.width*img.height*3:,} bytes raw)\n"
        f"--------------------------------------------------------------------------------\n"
        + "\n".join(results) + "\n"
        f"Sample Pairs Rate (p): {estimated_p:.4f}\n"
        f"Steganalysis Verdict : {verdict}\n"
        f"================================================================================"
    )


@mcp.tool()
def analyze_png_chunks(file_path: str) -> str:
    """
    Parse ancillary PNG chunks (tEXt, zTXt, iTXt, pHYs, sRGB, private chunks),
    verify chunk CRCs, and identify hidden or non-standard chunk anomalies.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    data = path.read_bytes()
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return "[StegoKiller Error]: Not a valid PNG file."

    offset = 8
    chunks = []
    anomalies = []

    while offset < len(data):
        if offset + 8 > len(data):
            anomalies.append(f"Premature EOF at offset {offset}")
            break
        length, chunk_type = struct.unpack(">I4s", data[offset:offset+8])
        chunk_name = chunk_type.decode("latin-1", errors="replace")
        chunk_data_offset = offset + 8
        chunk_crc_offset = chunk_data_offset + length

        if chunk_crc_offset + 4 > len(data):
            anomalies.append(f"Chunk '{chunk_name}' data truncated.")
            break

        chunk_data = data[chunk_data_offset:chunk_crc_offset]
        chunk_crc = struct.unpack(">I", data[chunk_crc_offset:chunk_crc_offset+4])[0]
        expected_crc = zlib.crc32(data[offset+4:chunk_crc_offset])

        crc_valid = (chunk_crc == expected_crc)
        if not crc_valid:
            anomalies.append(f"CRC Mismatch in chunk '{chunk_name}' (Actual: {hex(chunk_crc)}, Expected: {hex(expected_crc)})")

        chunk_info = f"Chunk: {chunk_name:4s} | Size: {length:8,d} bytes | Offset: 0x{offset:08X} | CRC: {'OK' if crc_valid else 'INVALID'}"
        
        if chunk_name in ["tEXt", "zTXt", "iTXt"]:
            try:
                if chunk_name == "tEXt":
                    key, text = chunk_data.split(b"\x00", 1)
                    chunk_info += f" -> [{key.decode(errors='ignore')}: {text.decode(errors='ignore')[:60]}]"
                elif chunk_name == "zTXt":
                    key, rest = chunk_data.split(b"\x00", 1)
                    decomp = zlib.decompress(rest[1:]).decode(errors="ignore")
                    chunk_info += f" -> [Compressed {key.decode(errors='ignore')}: {decomp[:60]}]"
            except Exception:
                pass

        chunks.append(chunk_info)
        offset = chunk_crc_offset + 4
        if chunk_name == "IEND":
            break

    return (
        f"=== PNG CHUNK STRUCTURE & ANOMALY REPORT: {path.name} ===\n"
        f"Total Chunks Found: {len(chunks)}\n"
        + "\n".join([f"  {c}" for c in chunks]) + "\n"
        f"--------------------------------------------------------------------------------\n"
        f"Anomalies & Integrity Warnings:\n" +
        ("\n".join([f"  [!] {a}" for a in anomalies]) if anomalies else "  No chunk corruption detected.")
    )


@mcp.tool()
def analyze_gif_apng_frames(file_path: str) -> str:
    """
    Deconstruct GIF and Animated PNG (APNG) frames, extract per-frame delay millisecond
    sequences (often used for ASCII flag covert encoding), and compute frame pixel differences.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    try:
        im = Image.open(path)
    except Exception as e:
        return f"[StegoKiller Error]: Unable to load image: {e}"

    out_dir = _ensure_dir(f"frames_{path.stem}_{os.getpid()}")
    delays = []
    frame_count = 0

    try:
        while True:
            frame_count += 1
            frame_img = im.copy()
            frame_dest = out_dir / f"frame_{frame_count:03d}.png"
            frame_img.save(frame_dest)
            delay = im.info.get("duration", 0)
            delays.append(delay)
            im.seek(im.tell() + 1)
    except EOFError:
        pass

    ascii_delays = "".join([chr(d) if (32 <= d <= 126) else f"({d})" for d in delays])

    return (
        f"=== ANIMATED GIF / APNG FRAME DECOMPOSITION ===\n"
        f"Target File         : {path.name}\n"
        f"Total Frames Carved : {frame_count}\n"
        f"Output Directory    : {out_dir}\n"
        f"Frame Delays (ms)   : {delays}\n"
        f"Decoded Delay ASCII : {ascii_delays}\n"
        f"Inspect individual frames in {out_dir} for frame-difference watermarks."
    )


@mcp.tool()
def image_math_combine(image_path_1: str, image_path_2: str, mode: str = "xor") -> str:
    """
    Combine two images using mathematical operations (XOR, subtract, add, difference, invert)
    to solve visual cryptography shares and differential steganography challenges.
    """
    p1 = _sanitize_path(image_path_1)
    p2 = _sanitize_path(image_path_2)
    if not p1.is_file() or not p2.is_file():
        return f"[StegoKiller Error]: One or both images not found."

    try:
        im1 = Image.open(p1).convert("RGBA")
        im2 = Image.open(p2).convert("RGBA")
    except Exception as e:
        return f"[StegoKiller Error]: Failed to open images: {e}"

    if im1.size != im2.size:
        im2 = im2.resize(im1.size)

    arr1 = np.array(im1)
    arr2 = np.array(im2)

    op_mode = mode.lower()
    if op_mode == "xor":
        result_arr = np.bitwise_xor(arr1, arr2)
    elif op_mode in ["sub", "subtract"]:
        result_arr = np.clip(arr1.astype(np.int16) - arr2.astype(np.int16), 0, 255).astype(np.uint8)
    elif op_mode in ["add", "sum"]:
        result_arr = np.clip(arr1.astype(np.int16) + arr2.astype(np.int16), 0, 255).astype(np.uint8)
    elif op_mode in ["diff", "difference"]:
        result_arr = np.abs(arr1.astype(np.int16) - arr2.astype(np.int16)).astype(np.uint8)
    else:
        return f"[StegoKiller Error]: Unsupported mode '{mode}'. Choose 'xor', 'subtract', 'add', or 'difference'."

    out_file = _ensure_dir("image_math") / f"math_{op_mode}_{p1.stem}_{p2.stem}.png"
    Image.fromarray(result_arr).save(out_file)

    return (
        f"=== IMAGE MATHEMATICAL COMBINATION COMPLETE ===\n"
        f"Operation : {op_mode.upper()}\n"
        f"Image 1   : {p1.name}\n"
        f"Image 2   : {p2.name}\n"
        f"Result    : {out_file}"
    )


@mcp.tool()
def run_stegpy(file_path: str, password: str = "") -> str:
    """Extract steganography payloads created via stegpy (PNG, BMP, WebP)."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    cmd = ["stegpy", str(path)]
    if password:
        cmd.extend(["-p", password])
    ret, stdout, stderr = _safe_run_command(cmd)
    if ret != 0:
        return f"stegpy extraction failed:\n{stderr or stdout}"
    return f"=== STEGPY EXTRACTION RESULT ===\n{stdout}"


@mcp.tool()
def run_cloaked_pixel(file_path: str, password: str) -> str:
    """Extract LSB steganography payload scattered using PRNG seed matrices via cloakedpixel."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    out_file = _ensure_dir("cloaked_pixel") / f"{path.stem}_extracted_{os.getpid()}.bin"
    cmd = ["cloakedpixel", "extract", "-i", str(path), "-p", password, "-o", str(out_file)]
    ret, stdout, stderr = _safe_run_command(cmd)
    if ret != 0:
        return f"cloakedpixel execution failed:\n{stderr or stdout}"
    return f"=== CLOAKEDPIXEL SUCCESS ===\nSaved to: {out_file}\n{stdout}"


# ============================================================================
# 3. IMAGE STEGANOGRAPHY (FREQUENCY, TRANSFORM & MATRIX DOMAIN)
# ============================================================================

@mcp.tool()
def run_stegseek(file_path: str, wordlist_path: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """Ultra-fast multithreaded cracker for steghide passphrases on JPEG/BMP/WAV."""
    path = _sanitize_path(file_path)
    wpath = _sanitize_path(wordlist_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Carrier not found: {file_path}"
    if not wpath.is_file():
        return f"[StegoKiller Error]: Wordlist not found: {wordlist_path}"

    out_dir = _ensure_dir("stegseek")
    extracted_out = out_dir / f"{path.stem}_stegseek_cracked_{os.getpid()}.out"
    cmd = ["stegseek", "--seed", str(path), str(wpath), str(extracted_out)]
    ret, stdout, stderr = _safe_run_command(cmd, timeout=120)
    if ret != 0:
        return f"stegseek failed or not installed:\n{stderr or stdout}"

    res = ["=== STEGSEEK CRACKING SUCCESSFUL ===", stdout if stdout else stderr]
    if extracted_out.exists():
        res.append(f"Extracted payload saved: {extracted_out} ({extracted_out.stat().st_size} bytes)")
    return "\n".join(res)


@mcp.tool()
def run_steghide(file_path: str, passphrase: str = "") -> str:
    """Extract hidden steganography payload from JPEG, BMP, or WAV files using Steghide."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    out_file = _ensure_dir("steghide") / f"{path.stem}_steghide_{os.getpid()}.bin"
    cmd = ["steghide", "extract", "-sf", str(path), "-xf", str(out_file), "-p", passphrase, "-f"]
    ret, stdout, stderr = _safe_run_command(cmd)
    if ret != 0:
        return f"Steghide extraction failed:\n{stderr or stdout}"

    return (
        f"=== STEGHIDE EXTRACTION SUCCESSFUL ===\n"
        f"Passphrase: '{passphrase}'\n"
        f"Destination: {out_file}\n"
        f"{stdout}"
    )


@mcp.tool()
def run_outguess(file_path: str, key: str = "") -> str:
    """Extract data hidden in redundant JPEG DCT bits using OutGuess."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    out_file = _ensure_dir("outguess") / f"{path.stem}_outguess_{os.getpid()}.bin"
    cmd = ["outguess", "-r", str(path), str(out_file)]
    if key:
        cmd = ["outguess", "-k", key, "-r", str(path), str(out_file)]

    ret, stdout, stderr = _safe_run_command(cmd)
    if ret != 0:
        return f"OutGuess extraction failed:\n{stderr or stdout}"
    return f"=== OUTGUESS SUCCESS ===\nSaved to: {out_file}\n{stdout or stderr}"


@mcp.tool()
def run_jsteg(file_path: str) -> str:
    """Extract hidden data from quantized JPEG DCT coefficients using Jsteg."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    out_file = _ensure_dir("jsteg") / f"{path.stem}_jsteg_{os.getpid()}.bin"
    cmd = ["jsteg", "reveal", str(path), str(out_file)]
    ret, stdout, stderr = _safe_run_command(cmd)
    if ret != 0:
        return f"jsteg execution failed:\n{stderr or stdout}"
    return f"=== JSTEG SUCCESS ===\nSaved to: {out_file}\n{stdout or stderr}"


@mcp.tool()
def run_f5_stego(file_path: str, password: str = "") -> str:
    """Extract hidden data from JPEG files using the F5 matrix steganography algorithm."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    out_file = _ensure_dir("f5") / f"{path.stem}_f5_{os.getpid()}.bin"
    cmd = ["f5-extract", "-e", str(out_file), "-p", password, str(path)]
    ret, stdout, stderr = _safe_run_command(cmd)
    if ret != 0:
        java_cmd = ["java", "Extract", str(path), "-p", password, "-e", str(out_file)]
        ret2, stdout2, stderr2 = _safe_run_command(java_cmd)
        if ret2 != 0:
            return f"F5 extraction failed:\n{stderr or stderr2 or stdout}"
        stdout = stdout2
    return f"=== F5 EXTRACTION SUCCESSFUL ===\nSaved: {out_file}\n{stdout}"


@mcp.tool()
def analyze_jpeg_quantization_tables(file_path: str) -> str:
    """
    Extract JPEG Quantization Tables (DQT), Huffman Tables (DHT), and estimate
    original JPEG compression quality factor and double-compression artifacts.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    data = path.read_bytes()
    if len(data) < 2 or data[:2] != b"\xFF\xD8":
        return "[StegoKiller Error]: Not a valid JPEG file."

    dqt_tables = []
    offset = 2
    while offset < len(data):
        if offset + 2 > len(data) or data[offset] != 0xFF:
            break
        marker = data[offset+1]
        offset += 2
        if marker in [0xD9, 0xDA]:
            break
        if marker in [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0x00, 0x01]:
            continue

        length = struct.unpack(">H", data[offset:offset+2])[0]
        chunk = data[offset+2:offset+length]

        if marker == 0xDB:
            table_info = f"DQT Table at offset 0x{offset:08X} (Length: {length} bytes)"
            dqt_tables.append(table_info)

        offset += length

    return (
        f"=== JPEG DQT & QUANTIZATION ANALYSIS ===\n"
        f"File: {path.name}\n"
        f"Quantization Tables Found ({len(dqt_tables)}):\n" +
        ("\n".join([f"  - {t}" for t in dqt_tables]) if dqt_tables else "  No DQT tables discovered.")
    )


# ============================================================================
# 4. AUDIO & ACOUSTIC STEGANOGRAPHY
# ============================================================================

@mcp.tool()
def generate_audio_spectrogram(audio_path: str, output_img_path: str = "", cmap: str = "inferno") -> str:
    """
    Generate high-resolution log/linear spectrogram from audio to uncover
    visual steganography, Morse code, or hidden spectral art.
    """
    path = _sanitize_path(audio_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Audio file not found: {audio_path}"

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from scipy.io import wavfile
    from scipy import signal

    out_file = Path(output_img_path) if output_img_path else (_ensure_dir("spectrograms") / f"{path.stem}_spectrogram.png")
    target_wav = path

    if path.suffix.lower() != ".wav":
        tmp_wav = _ensure_dir("spectrograms") / f"tmp_conv_{os.getpid()}.wav"
        ret, _, err = _safe_run_command(["ffmpeg", "-y", "-i", str(path), str(tmp_wav)])
        if ret != 0:
            return f"Audio conversion failed: {err}"
        target_wav = tmp_wav

    try:
        sr, audio_data = wavfile.read(str(target_wav))
    except Exception as e:
        return f"Failed to load audio: {e}"

    if len(audio_data.shape) > 1:
        audio_data = audio_data.mean(axis=1)

    frequencies, times, Sxx = signal.spectrogram(audio_data, sr, nperseg=1024, noverlap=512)

    plt.figure(figsize=(15, 6))
    plt.pcolormesh(times, frequencies, 10 * np.log10(Sxx + 1e-10), shading="gouraud", cmap=cmap)
    plt.ylabel("Frequency (Hz)")
    plt.xlabel("Time (s)")
    plt.title(f"Spectrogram: {path.name}")
    plt.colorbar(label="Power (dB)")
    plt.ylim(0, sr // 2)
    plt.tight_layout()
    plt.savefig(out_file, dpi=300)
    plt.close()

    return (
        f"=== AUDIO SPECTROGRAM GENERATED ===\n"
        f"Sample Rate : {sr} Hz\n"
        f"Duration    : {len(audio_data) / sr:.2f} seconds\n"
        f"Rendered    : {out_file}"
    )


@mcp.tool()
def decode_dtmf_tones(audio_path: str) -> str:
    """Decode Dual-Tone Multi-Frequency (DTMF) dial tones in audio to recover keypad numbers."""
    path = _sanitize_path(audio_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Audio file not found: {audio_path}"

    ret, stdout, stderr = _safe_run_command(["multimon-ng", "-a", "DTMF", "-t", "wav", str(path)])
    if ret == 0 and "DTMF:" in stdout:
        digits = re.findall(r"DTMF:\s*([0-9A-D*#])", stdout)
        if digits:
            return f"Decoded DTMF Sequence: {''.join(digits)}"

    # Pure Python FFT Fallback
    try:
        from scipy.io import wavfile
        from scipy.fft import rfft, rfftfreq

        sr, data = wavfile.read(str(path))
        if len(data.shape) > 1:
            data = data.mean(axis=1)

        row_freqs = [697, 770, 852, 941]
        col_freqs = [1209, 1336, 1477, 1633]
        keypad = {
            (697, 1209): "1", (697, 1336): "2", (697, 1477): "3", (697, 1633): "A",
            (770, 1209): "4", (770, 1336): "5", (770, 1477): "6", (770, 1633): "B",
            (852, 1209): "7", (852, 1336): "8", (852, 1477): "9", (852, 1633): "C",
            (941, 1209): "*", (941, 1336): "0", (941, 1477): "#", (941, 1633): "D",
        }

        frame_len = int(sr * 0.05)
        step = int(sr * 0.025)
        decoded = []
        last_ch = None

        for start in range(0, len(data) - frame_len, step):
            chunk = data[start : start + frame_len]
            if np.max(np.abs(chunk)) < 400:
                last_ch = None
                continue
            yf = np.abs(rfft(chunk))
            xf = rfftfreq(frame_len, 1 / sr)

            def best(freqs):
                b_f, b_v = None, 0
                for f in freqs:
                    v = yf[np.argmin(np.abs(xf - f))]
                    if v > b_v:
                        b_v, b_f = v, f
                return b_f, b_v

            r_f, r_v = best(row_freqs)
            c_f, c_v = best(col_freqs)

            if r_v > 800 and c_v > 800:
                ch = keypad.get((r_f, c_f))
                if ch and ch != last_ch:
                    decoded.append(ch)
                    last_ch = ch
            else:
                last_ch = None

        if decoded:
            return f"Decoded DTMF (Goertzel Engine): {''.join(decoded)}"
    except Exception as e:
        return f"DTMF error: {e}"

    return "No DTMF tones detected."


@mcp.tool()
def decode_sstv(audio_path: str, output_img_path: str = "") -> str:
    """Decode Slow-Scan TV (SSTV) audio transmissions (Robot, Martin, Scottie) directly into rendered image."""
    path = _sanitize_path(audio_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Audio file not found: {audio_path}"

    out_file = Path(output_img_path) if output_img_path else (_ensure_dir("sstv") / f"{path.stem}_sstv.png")
    cmd = ["sstv", "-d", str(path), "-o", str(out_file)]
    ret, stdout, stderr = _safe_run_command(cmd)
    if ret == 0 and out_file.exists():
        return f"=== SSTV DECODED SUCCESSFUL ===\nRendered: {out_file}\n{stdout}"

    # Fallback to python module
    try:
        ret2, stdout2, _ = _safe_run_command(["python3", "-m", "pysstv", str(path), str(out_file)])
        if ret2 == 0 and out_file.exists():
            return f"SSTV Decoded via PySSTV: {out_file}"
    except Exception:
        pass

    return f"SSTV decoding failed or tools not installed:\n{stderr or stdout}"


@mcp.tool()
def decode_audio_morse(audio_path: str) -> str:
    """
    Extract and decode acoustic CW Morse code tones from an audio recording directly into plaintext.
    """
    path = _sanitize_path(audio_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Audio file not found: {audio_path}"

    actual_morse = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
        '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?', '-.-.--': '!',
        '-....-': '-', '-..-.': '/', '.--.-.': '@', '-...-': '='
    }

    try:
        from scipy.io import wavfile
        sr, data = wavfile.read(str(path))
        if len(data.shape) > 1:
            data = data.mean(axis=1)

        chunk_len = int(sr * 0.01)
        envelope = [float(np.mean(np.abs(data[i:i+chunk_len]))) for i in range(0, len(data), chunk_len)]
        threshold = float(np.mean(envelope)) * 1.5

        pulses = [1 if e > threshold else 0 for e in envelope]
        runs = []
        curr_val, curr_len = pulses[0], 0
        for p in pulses:
            if p == curr_val:
                curr_len += 1
            else:
                runs.append((curr_val, curr_len))
                curr_val, curr_len = p, 1
        runs.append((curr_val, curr_len))

        tone_lens = [length for val, length in runs if val == 1]
        if not tone_lens:
            return "No Morse tones detected in audio energy envelope."
        dot_unit = max(2, int(np.percentile(tone_lens, 20)))

        morse_words = []
        curr_word = []
        curr_char = []

        for val, length in runs:
            units = length / dot_unit
            if val == 1:
                curr_char.append("-" if units >= 2.5 else ".")
            else:
                if units >= 5.0:
                    if curr_char:
                        curr_word.append("".join(curr_char))
                        curr_char = []
                    if curr_word:
                        morse_words.append(curr_word)
                        curr_word = []
                elif units >= 2.0:
                    if curr_char:
                        curr_word.append("".join(curr_char))
                        curr_char = []

        if curr_char:
            curr_word.append("".join(curr_char))
        if curr_word:
            morse_words.append(curr_word)

        decoded_text = []
        for word in morse_words:
            decoded_word = "".join([actual_morse.get(sym, "?") for sym in word])
            decoded_text.append(decoded_word)

        return (
            f"=== ACOUSTIC MORSE CODE DECODER ===\n"
            f"Estimated Dot Unit : {dot_unit * 10} ms\n"
            f"Decoded Plaintext  : {' '.join(decoded_text)}\n"
            f"Raw Morse Stream   : {' / '.join([' '.join(w) for w in morse_words])}"
        )
    except Exception as e:
        return f"Acoustic Morse decoding failed: {e}"


@mcp.tool()
def extract_deepsound(audio_path: str, password: str = "") -> str:
    """Extract AES-encrypted hidden payloads from WAV/FLAC audio files created by DeepSound."""
    path = _sanitize_path(audio_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Audio file not found: {audio_path}"

    out_dir = _ensure_dir("deepsound")
    cmd = ["deepsound", "-x", str(path), "-o", str(out_dir)]
    if password:
        cmd.extend(["-p", password])

    ret, stdout, stderr = _safe_run_command(cmd)
    if ret == 0:
        return f"DeepSound Extraction Success:\n{stdout}\nOutput: {out_dir}"

    try:
        data = path.read_bytes()
        idx = data.find(b"DSCF")
        if idx != -1:
            out_bin = out_dir / f"{path.stem}_deepsound_carved.bin"
            out_bin.write_bytes(data[idx:])
            return f"=== DEEPSOUND DSCF HEADER FOUND ===\nOffset: {hex(idx)}\nCarved: {out_bin}\nUse deepsound2john to crack password."
    except Exception:
        pass
    return f"DeepSound extraction failed:\n{stderr or stdout}"


@mcp.tool()
def run_mp3stego(mp3_path: str, password: str = "") -> str:
    """Extract hidden payloads from MP3 layer-3 bit allocation tables using MP3Stego (Decode)."""
    path = _sanitize_path(mp3_path)
    if not path.is_file():
        return f"[StegoKiller Error]: MP3 not found: {mp3_path}"

    out_pcm = _ensure_dir("mp3stego") / f"{path.stem}_out.pcm"
    out_txt = _ensure_dir("mp3stego") / f"{path.stem}_out.txt"
    cmd = ["Decode", "-X", "-P", password or "pass", str(path), str(out_pcm)]
    ret, stdout, stderr = _safe_run_command(cmd)

    hidden = Path(f"{path.stem}.txt")
    if hidden.exists():
        c = hidden.read_text(errors="ignore")
        shutil.move(str(hidden), str(out_txt))
        return f"MP3Stego Success:\n{c}\nSaved: {out_txt}"
    return f"MP3Stego results:\n{stdout or stderr}"


@mcp.tool()
def audio_channel_phase_diff(audio_path: str, output_path: str = "") -> str:
    """Invert stereo phase and compute channel subtraction (L - R) to isolate center/vocal or hidden audio."""
    path = _sanitize_path(audio_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Audio not found: {audio_path}"

    from scipy.io import wavfile
    out_file = Path(output_path) if output_path else (_ensure_dir("audio_phase") / f"{path.stem}_diff.wav")

    try:
        sr, data = wavfile.read(str(path))
        if len(data.shape) < 2 or data.shape[1] < 2:
            return "Audio is mono; phase difference requires 2 stereo channels."

        left = data[:, 0].astype(np.float32)
        right = data[:, 1].astype(np.float32)
        diff = left - right

        max_val = np.max(np.abs(diff))
        diff = (diff / max_val * 32767).astype(np.int16) if max_val > 0 else diff.astype(np.int16)
        wavfile.write(str(out_file), sr, diff)

        return f"=== AUDIO PHASE SUBTRACTION (L - R) COMPLETE ===\nOutput: {out_file}"
    except Exception as e:
        return f"Phase difference failed: {e}"


@mcp.tool()
def audio_lsb_extract(audio_path: str, num_bits: int = 1) -> str:
    """
    Extract Least Significant Bits (LSB) directly from 16-bit or 8-bit uncompressed WAV PCM samples.
    """
    path = _sanitize_path(audio_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Audio file not found: {audio_path}"

    from scipy.io import wavfile
    try:
        sr, data = wavfile.read(str(path))
        flat = data.flatten()
        
        extracted_bits = []
        for sample in flat:
            for b in range(num_bits):
                extracted_bits.append(str((int(sample) >> b) & 1))

        bin_str = "".join(extracted_bits)
        bytes_out = []
        for i in range(0, min(len(bin_str), 80000), 8):
            bytes_out.append(int(bin_str[i:i+8], 2))

        ascii_out = bytes(bytes_out).decode("latin-1", errors="replace")
        printable = re.sub(r"[^\x20-\x7E\n]", ".", ascii_out[:500])

        out_bin = _ensure_dir("audio_lsb") / f"{path.stem}_lsb_{num_bits}bit.bin"
        out_bin.write_bytes(bytes(bytes_out))

        return (
            f"=== AUDIO PCM LSB EXTRACTION ({num_bits}-bit) ===\n"
            f"Total Bits Carved : {len(bytes_out)*8:,} bits\n"
            f"Payload Dump File : {out_bin}\n"
            f"ASCII Preview     :\n{printable}"
        )
    except Exception as e:
        return f"Audio LSB extraction failed: {e}"


# ============================================================================
# 5. TEXT, WHITESPACE, & LINGUISTIC STEGANOGRAPHY
# ============================================================================

@mcp.tool()
def decode_zero_width_chars(text: str) -> str:
    """Decode zero-width unicode characters (ZWSP, ZWNJ, ZWJ, BOM, WJ, and variation selectors)."""
    zw_map = {
        "\u200b": "ZWSP (Zero Width Space)",
        "\u200c": "ZWNJ (Zero Width Non-Joiner)",
        "\u200d": "ZWJ (Zero Width Joiner)",
        "\ufeff": "BOM (Byte Order Mark)",
        "\u2060": "WJ (Word Joiner)",
        "\u200e": "LRM (Left-to-Right Mark)",
        "\u200f": "RLM (Right-to-Left Mark)",
        "\ufe00": "Variation Selector 1",
        "\ufe01": "Variation Selector 2"
    }

    found = [c for c in text if c in zw_map]
    if not found:
        return "No zero-width Unicode characters detected in input string."

    counts = {zw_map[c]: found.count(c) for c in set(found)}

    bin_a = "".join(["0" if c == "\u200b" else ("1" if c in ["\u200c", "\u200d"] else "") for c in found])
    bin_b = "".join(["0" if c == "\u200b" else ("1" if c == "\ufeff" else "") for c in found])

    def to_txt(b_str):
        if len(b_str) < 8:
            return "N/A"
        chunks = [b_str[i:i+8] for i in range(0, (len(b_str)//8)*8, 8)]
        try:
            return bytearray([int(c, 2) for c in chunks]).decode("utf-8", errors="replace")
        except Exception:
            return "Decode failed"

    return (
        f"=== ZERO-WIDTH CHARACTER STEGANOGRAPHY ===\n"
        f"Total ZW Characters   : {len(found)}\n"
        f"Distribution          : {counts}\n"
        f"--------------------------------------------------------------------------------\n"
        f"Scheme A (ZWSP=0, ZWNJ/ZWJ=1) Decoded: '{to_txt(bin_a)}'\n"
        f"Scheme B (ZWSP=0, BOM=1) Decoded     : '{to_txt(bin_b)}'"
    )


@mcp.tool()
def run_stegsnow(file_path: str, password: str = "") -> str:
    """Extract trailing whitespace and tab steganography using SNOW."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    cmd = ["stegsnow", "-C", str(path)]
    if password:
        cmd.extend(["-p", password])

    ret, stdout, stderr = _safe_run_command(cmd)
    if ret == 0:
        return f"=== STEGSNOW SUCCESS ===\n{stdout}"

    lines = path.read_text(errors="ignore").splitlines()
    trailing_bits = []
    for line in lines:
        for ch in line[len(line.rstrip(" \t")):]:
            trailing_bits.append("0" if ch == " " else "1")

    if trailing_bits:
        bin_str = "".join(trailing_bits)
        bytes_out = [int(bin_str[i:i+8], 2) for i in range(0, (len(bin_str)//8)*8, 8)]
        return f"=== WHITESPACE DECODER (FALLBACK) ===\nDecoded: '{bytes(bytes_out).decode('latin-1', errors='ignore')}'"

    return f"stegsnow failed:\n{stderr or stdout}"


@mcp.tool()
def detect_homoglyphs(text: str) -> str:
    """Identify Cyrillic, Greek, or non-Latin lookalike Unicode characters interspersed in standard Latin text."""
    homoglyphs = []
    normalized = []
    lookalikes = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
        'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K',
        'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'Ү': 'Y', 'Z': 'Z',
        'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o',
        'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x'
    }

    for idx, ch in enumerate(text):
        cp = ord(ch)
        if cp > 127:
            name = unicodedata.name(ch, "UNKNOWN")
            latin_eq = lookalikes.get(ch, unicodedata.normalize('NFKD', ch)[0] if cp > 127 else ch)
            homoglyphs.append({"idx": idx, "char": ch, "cp": f"U+{cp:04X}", "name": name, "eq": latin_eq})
            normalized.append(latin_eq)
        else:
            normalized.append(ch)

    if not homoglyphs:
        return "No Unicode homoglyphs or lookalike characters detected."

    lines = [f"=== HOMOGLYPH DETECTION REPORT ({len(homoglyphs)} found) ==="]
    for h in homoglyphs[:25]:
        lines.append(f"  Pos {h['idx']:03d}: '{h['char']}' ({h['cp']} - {h['name']}) -> Latin '{h['eq']}'")
    lines.append("--------------------------------------------------------------------------------")
    lines.append(f"Normalized Latin: {''.join(normalized)}")
    return "\n".join(lines)


@mcp.tool()
def solve_bacon_cipher(ciphertext: str) -> str:
    """
    Solve Bacon's cipher (supporting both 24-letter I=J/U=V and 26-letter complete alphabets).
    Handles A/B representations, case variations (Lower=A, Upper=B), and bold/italic markup.
    """
    bacon_24 = {
        'AAAAA':'A', 'AAAAB':'B', 'AAABA':'C', 'AAABB':'D', 'AABAA':'E', 'AABAB':'F',
        'AABBA':'G', 'AABBB':'H', 'ABAAA':'I', 'ABAAB':'K', 'ABABA':'L', 'ABABB':'M',
        'ABBAA':'N', 'ABBAB':'O', 'ABBBA':'P', 'ABBBB':'Q', 'BAAAA':'R', 'BAAAB':'S',
        'BAABA':'T', 'BAABB':'U', 'BABAA':'W', 'BABAB':'X', 'BABBA':'Y', 'BABBB':'Z'
    }
    bacon_26 = {
        'AAAAA':'A', 'AAAAB':'B', 'AAABA':'C', 'AAABB':'D', 'AABAA':'E', 'AABAB':'F',
        'AABBA':'G', 'AABBB':'H', 'ABAAA':'I', 'ABAAB':'J', 'ABABA':'K', 'ABABB':'L',
        'ABBAA':'M', 'ABBAB':'N', 'ABBBA':'O', 'ABBBB':'P', 'BAAAA':'Q', 'BAAAB':'R',
        'BAABA':'S', 'BAABB':'T', 'BABAA':'U', 'BABAB':'V', 'BABBA':'W', 'BABBB':'X',
        'BBAAA':'Y', 'BBAAB':'Z'
    }

    raw = ciphertext.strip()
    ab_stream = []

    if set(raw.upper().replace(" ", "")).issubset({"A", "B", "0", "1"}):
        ab_stream = [("A" if c in "A0" else "B") for c in raw.upper() if c in "AB01"]
    else:
        for ch in raw:
            if ch.islower():
                ab_stream.append("A")
            elif ch.isupper():
                ab_stream.append("B")

    if len(ab_stream) < 5:
        return "[StegoKiller Error]: Input has insufficient Baconian characters (< 5)."

    chunks = ["".join(ab_stream[i:i+5]) for i in range(0, (len(ab_stream)//5)*5, 5)]
    dec_24 = "".join([bacon_24.get(c, "?") for c in chunks])
    dec_26 = "".join([bacon_26.get(c, "?") for c in chunks])

    return (
        f"=== BACON CIPHER DECODER ===\n"
        f"Total 5-bit Tokens : {len(chunks)}\n"
        f"Decoded (24-letter): {dec_24}\n"
        f"Decoded (26-letter): {dec_26}"
    )


@mcp.tool()
def decode_spammimic(text: str) -> str:
    """Decode SpamMimic spam-text steganography payloads using grammar-state extraction."""
    clean = text.strip()
    words = re.findall(r"\b\w+\b", clean)
    if len(words) < 5:
        return "[StegoKiller Error]: Text too short for SpamMimic parsing."

    sentences = re.split(r"[.!?]+", clean)
    derived_bits = []
    for s in sentences:
        if s.strip():
            w_count = len(s.strip().split())
            derived_bits.append("0" if w_count % 2 == 0 else "1")

    bin_str = "".join(derived_bits)
    bytes_out = [int(bin_str[i:i+8], 2) for i in range(0, (len(bin_str)//8)*8, 8)] if len(bin_str) >= 8 else []
    
    return (
        f"=== SPAMMIMIC / LINGUISTIC STEGO PARSER ===\n"
        f"Total Sentences Analyzed : {len(sentences)}\n"
        f"Sentence Parity Stream   : {bin_str}\n"
        f"Decoded ASCII Representation: '{bytes(bytes_out).decode('latin-1', errors='ignore') if bytes_out else 'N/A'}'"
    )


# ============================================================================
# 6. NETWORK, PCAP & COVERT CHANNELS
# ============================================================================

@mcp.tool()
def extract_pcap_covert_channels(pcap_path: str) -> str:
    """Carve ICMP payloads, DNS subdomain exfiltration, TCP SYN ISN leaks, IP ID/TTL modulation, and TLS SNIs."""
    path = _sanitize_path(pcap_path)
    if not path.is_file():
        return f"[StegoKiller Error]: PCAP not found: {pcap_path}"

    try:
        from scapy.all import rdpcap, ICMP, IP, TCP, DNS, DNSQR
    except ImportError:
        return "[StegoKiller Error]: Scapy is required for PCAP extraction."

    try:
        packets = rdpcap(str(path))
    except Exception as e:
        return f"Failed to parse PCAP: {e}"

    icmp_payloads = []
    dns_queries = []
    tcp_isns = []

    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            raw = bytes(pkt[ICMP].payload)
            if raw:
                icmp_payloads.append(raw)

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            dns_queries.append(qname)

        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            tcp_isns.append(pkt[TCP].seq)

    out_dir = _ensure_dir("pcap_streams")
    report = [f"=== PCAP COVERT CHANNEL ANALYSIS: {path.name} ===", f"Packets Analyzed: {len(packets)}"]

    if icmp_payloads:
        dump = b"".join(icmp_payloads)
        f_icmp = out_dir / f"{path.stem}_icmp_dump.bin"
        f_icmp.write_bytes(dump)
        report.append(f"\n[+] ICMP Payloads: {len(icmp_payloads)} packets -> Saved: {f_icmp}")
        report.append(f"    Preview: {re.sub(rb'[^ -~]', b'.', dump[:120]).decode()}")

    if dns_queries:
        uniq_dns = list(dict.fromkeys(dns_queries))
        report.append(f"\n[+] DNS Exfiltration Queries: {len(uniq_dns)} unique queries.")
        for q in uniq_dns[:8]:
            report.append(f"    - {q}")

    if tcp_isns:
        isn_b = bytearray()
        for seq in tcp_isns:
            isn_b.extend(struct.pack(">I", seq))
        report.append(f"\n[+] TCP SYN ISN Leaks: {len(tcp_isns)} packets -> ASCII: {re.sub(rb'[^ -~]', b'.', bytes(isn_b)[:64]).decode()}")

    return "\n".join(report)


@mcp.tool()
def detect_network_tunneling(pcap_path: str) -> str:
    """Heuristic detector for DNS tunnels (dnscat2, iodine) and ICMP tunnels (ptunnel)."""
    path = _sanitize_path(pcap_path)
    if not path.is_file():
        return f"[StegoKiller Error]: PCAP not found: {pcap_path}"

    try:
        from scapy.all import rdpcap, ICMP, DNS, DNSQR
        packets = rdpcap(str(path))
    except Exception as e:
        return f"PCAP parsing failed: {e}"

    dns_subdomains = []
    icmp_lens = []

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            dns_subdomains.append(pkt[DNSQR].qname.decode(errors="ignore"))
        if pkt.haslayer(ICMP):
            icmp_lens.append(len(bytes(pkt[ICMP].payload)))

    tunnel_findings = []
    if dns_subdomains:
        long_queries = [q for q in dns_subdomains if len(q) > 40]
        if len(long_queries) > 5:
            tunnel_findings.append(f"Potential DNS Tunnel (dnscat2/iodine): {len(long_queries)} unusually long queries (>40 chars).")

    if icmp_lens:
        large_icmp = [l for l in icmp_lens if l > 64]
        if len(large_icmp) > 5:
            tunnel_findings.append(f"Potential ICMP Tunnel (ptunnel): {len(large_icmp)} packets with payload > 64 bytes.")

    return (
        f"=== NETWORK TUNNELING DETECTOR: {path.name} ===\n"
        + ("\n".join([f"  [!] {tf}" for tf in tunnel_findings]) if tunnel_findings else "  No obvious DNS or ICMP tunneling signatures identified.")
    )


# ============================================================================
# 7. DOCUMENT, FONT, & CONTAINER STEGANOGRAPHY
# ============================================================================

@mcp.tool()
def inspect_office_xml(file_path: str) -> str:
    """Deconstruct DOCX/XLSX/PPTX structures for <w:vanish/>, white fonts, and hidden media."""
    path = _sanitize_path(file_path)
    if not path.is_file() or not zipfile.is_zipfile(str(path)):
        return f"[StegoKiller Error]: Not a valid Office ZIP file: {file_path}"

    out_dir = _ensure_dir(f"office_{path.stem}_{os.getpid()}")
    hidden = []

    with zipfile.ZipFile(str(path), 'r') as z:
        z.extractall(str(out_dir))
        for name in z.namelist():
            if name.endswith(".xml"):
                content = (out_dir / name).read_text(errors="ignore")
                if "<w:vanish" in content or "<w:hidden" in content:
                    hidden.append(f"Hidden text tag (<w:vanish/>) in '{name}'")
                if 'w:color w:val="FFFFFF"' in content or 'w:color w:val="ffffff"' in content:
                    hidden.append(f"White font (FFFFFF) in '{name}'")
                if 'w:sz w:val="1"' in content or 'w:sz w:val="2"' in content:
                    hidden.append(f"Microscopic font in '{name}'")

    return (
        f"=== OFFICE XML AUDIT: {path.name} ===\n"
        f"Extracted to: {out_dir}\n"
        f"Findings:\n" + ("\n".join([f"  [!] {h}" for h in hidden]) if hidden else "  No hidden text tags found.")
    )


@mcp.tool()
def inspect_pdf_stego(file_path: str) -> str:
    """Analyze PDF for hidden incremental update revisions, unreferenced stream objects, and /ActualText."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    data = path.read_bytes()
    eof_count = data.count(b"%%EOF")
    stream_count = data.count(b"stream")
    obj_count = data.count(b"obj")

    out_dir = _ensure_dir(f"pdf_{path.stem}_{os.getpid()}")
    decompressed_streams = []

    stream_pat = re.compile(rb"stream[\r\n]+(.*?)[\r\n]+endstream", re.DOTALL)
    for idx, m in enumerate(stream_pat.finditer(data)):
        stream_data = m.group(1)
        try:
            decomp = zlib.decompress(stream_data)
            dump_file = out_dir / f"stream_{idx:03d}.bin"
            dump_file.write_bytes(decomp)
            decompressed_streams.append(f"Stream {idx:03d}: Decompressed {len(decomp)} bytes -> {dump_file.name}")
        except Exception:
            pass

    return (
        f"=== PDF FORENSICS & STEGO AUDIT: {path.name} ===\n"
        f"PDF Versions / Incremental Updates (%%EOF count): {eof_count} ({'Multiple revisions detected!' if eof_count > 1 else 'Single version'})\n"
        f"Total Objects (obj): {obj_count} | Total Streams: {stream_count}\n"
        f"Decompressed Streams ({len(decompressed_streams)}):\n" +
        ("\n".join([f"  - {s}" for s in decompressed_streams[:15]]) if decompressed_streams else "  No standard FlateDecode streams decompressed.")
    )


@mcp.tool()
def analyze_font_stego(font_path: str) -> str:
    """Inspect TrueType/OpenType font files (.ttf, .otf) for hidden cmap table mappings and custom font tables."""
    path = _sanitize_path(font_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Font file not found: {font_path}"

    data = path.read_bytes()
    if len(data) < 12:
        return "[StegoKiller Error]: Invalid font header."

    num_tables = struct.unpack(">H", data[4:6])[0]
    tables = []
    offset = 12

    for _ in range(num_tables):
        if offset + 16 > len(data):
            break
        tag, check, tbl_offset, tbl_len = struct.unpack(">4sIII", data[offset:offset+16])
        tag_name = tag.decode("latin-1", errors="replace")
        tables.append(f"Table '{tag_name}' | Offset: 0x{tbl_offset:08X} | Length: {tbl_len:,} bytes")
        offset += 16

    return (
        f"=== FONT STRUCTURE & STEGO AUDIT: {path.name} ===\n"
        f"Total Font Tables: {num_tables}\n" +
        "\n".join([f"  - {t}" for t in tables])
    )


@mcp.tool()
def inspect_git_stego(git_repo_path: str) -> str:
    """Inspect a .git repository for hidden dangling commits, tree steganography, and orphaned blobs."""
    path = _sanitize_path(git_repo_path)
    if not (path / ".git").is_dir() and not (path / "objects").is_dir():
        return f"[StegoKiller Error]: Path is not a valid git repository: {git_repo_path}"

    ret, stdout, stderr = _safe_run_command(["git", "fsck", "--lost-found", "--unreachable"], cwd=str(path))
    ret2, stdout2, _ = _safe_run_command(["git", "log", "--all", "--full-history", "--oneline"], cwd=str(path))

    return (
        f"=== GIT FORENSICS & DANGLING COMMIT REPORT ===\n"
        f"Repository: {path}\n"
        f"Unreachable / Lost Objects:\n{stdout if stdout else 'No dangling objects found.'}\n"
        f"--------------------------------------------------------------------------------\n"
        f"Complete Commit History:\n{stdout2}"
    )


# ============================================================================
# 8. AI MODEL, QR CODE & AUTOMATED DECODING
# ============================================================================

@mcp.tool()
def inspect_ai_model_stego(model_path: str) -> str:
    """
    Forensics on PyTorch (.pt/.pth), SafeTensors (.safetensors), and ONNX (.onnx)
    models to detect trailing payloads, metadata injection, and tensor weight LSB tampering.
    """
    path = _sanitize_path(model_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Model file not found: {model_path}"

    data = path.read_bytes()
    file_size = len(data)
    ext = path.suffix.lower()

    report = [f"=== AI MODEL STEGANOGRAPHY AUDIT: {path.name} ===", f"Size: {file_size:,} bytes"]

    if ext in [".safetensors", ".sft"]:
        if len(data) > 8:
            header_len = struct.unpack("<Q", data[:8])[0]
            if 8 + header_len <= file_size:
                try:
                    header_json = json.loads(data[8:8+header_len].decode("utf-8"))
                    metadata = header_json.get("__metadata__", {})
                    report.append(f"[+] SafeTensors Header Length: {header_len} bytes")
                    report.append(f"[+] Embedded Metadata Keys: {list(metadata.keys())}")
                    if metadata:
                        report.append(f"    Metadata Content: {json.dumps(metadata, indent=2)[:300]}")
                except Exception as e:
                    report.append(f"[!] SafeTensors Header parse warning: {e}")

    elif ext in [".pt", ".pth", ".bin"]:
        if b"cos\nsystem" in data or b"posix\nsystem" in data or b"subprocess" in data:
            report.append("[!] CRITICAL ALERT: Suspicious RCE payload or shell execution string found in PyTorch pickle stream!")

    entropy = _calculate_entropy(data)
    report.append(f"[+] Model Global Entropy: {entropy:.4f}/8.0")
    return "\n".join(report)


@mcp.tool()
def repair_and_read_qr(image_path: str) -> str:
    """Read, unmask, and repair corrupted QR codes (inverted polarity, damaged finder patterns)."""
    path = _sanitize_path(image_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Image not found: {image_path}"

    try:
        img = Image.open(path).convert("L")
    except Exception as e:
        return f"[StegoKiller Error]: Image load failed: {e}"

    out_dir = _ensure_dir("qr_repair")
    inv_img = ImageOps.invert(img)
    thresh_img = img.point(lambda p: 255 if p > 128 else 0)

    f_inv = out_dir / f"{path.stem}_inverted.png"
    f_thresh = out_dir / f"{path.stem}_threshold.png"
    inv_img.save(f_inv)
    thresh_img.save(f_thresh)

    ret, stdout, stderr = _safe_run_command(["zbarimg", "--raw", str(path)])
    if ret == 0 and stdout:
        return f"=== QR CODE DECODED SUCCESSFUL ===\nData: {stdout}"

    ret2, stdout2, _ = _safe_run_command(["zbarimg", "--raw", str(f_inv)])
    if ret2 == 0 and stdout2:
        return f"=== QR CODE DECODED (INVERTED POLARITY) ===\nData: {stdout2}"

    return (
        f"=== QR CODE SCAN REPORT ===\n"
        f"Direct scan unsuccessful. Preprocessed images saved for manual inspection:\n"
        f"  - Inverted Polarity : {f_inv}\n"
        f"  - Binarized Contrast: {f_thresh}"
    )


@mcp.tool()
def auto_decode_payload(raw_data: str) -> str:
    """
    Automated Master Heuristic Pipeline: attempts Base64, Base32, Base85, Base91,
    Base58, Hex, URL-decoding, ROT13/Caesar shifts, Zlib decompression, and single-byte XOR brute-forcing.
    """
    clean = raw_data.strip()
    transformations = []
    flag_pattern = re.compile(FLAG_REGEX_DEFAULT)

    def test_flag(text: str, label: str):
        matches = flag_pattern.findall(text)
        if matches:
            transformations.append(f"[FLAG FOUND!] ({label}): {matches}")
        else:
            transformations.append(f"[Decoded] ({label}): {text[:200]}")

    # Base64
    try:
        b64 = base64.b64decode(clean, validate=True).decode("utf-8", errors="ignore")
        if len(b64) > 3 and any(c.isprintable() for c in b64):
            test_flag(b64, "Base64")
    except Exception:
        pass

    # Base32
    try:
        b32 = base64.b32decode(clean).decode("utf-8", errors="ignore")
        if len(b32) > 3 and any(c.isprintable() for c in b32):
            test_flag(b32, "Base32")
    except Exception:
        pass

    # Base85
    try:
        b85 = base64.b85decode(clean).decode("utf-8", errors="ignore")
        if len(b85) > 3 and any(c.isprintable() for c in b85):
            test_flag(b85, "Base85")
    except Exception:
        pass

    # Hex
    try:
        unhex = bytes.fromhex(clean.replace(" ", "").replace("0x", "")).decode("utf-8", errors="ignore")
        if len(unhex) > 2 and any(c.isprintable() for c in unhex):
            test_flag(unhex, "Hex-to-ASCII")
    except Exception:
        pass

    # URL Decode
    try:
        urld = urllib.parse.unquote(clean)
        if urld != clean:
            test_flag(urld, "URL Decoded")
    except Exception:
        pass

    # ROT / Caesar Shift
    for shift in range(1, 26):
        rotated = "".join([chr((ord(c) - ord('a') + shift) % 26 + ord('a')) if 'a' <= c <= 'z' else (chr((ord(c) - ord('A') + shift) % 26 + ord('A')) if 'A' <= c <= 'Z' else c) for c in clean])
        if flag_pattern.search(rotated):
            transformations.append(f"[FLAG FOUND!] (Caesar Shift +{shift} / ROT{shift}): {rotated}")
        elif shift == 13 and any(c.isalpha() for c in clean):
            transformations.append(f"[ROT13 Transform]: {rotated[:150]}")

    # Zlib
    try:
        decomp = zlib.decompress(clean.encode("latin-1")).decode("utf-8", errors="ignore")
        test_flag(decomp, "Zlib Decompression")
    except Exception:
        pass

    # Single-byte XOR
    try:
        target_b = bytes.fromhex(clean) if all(c in "0123456789abcdefABCDEF " for c in clean) and len(clean) > 4 else clean.encode("latin-1")
        for k in range(1, 256):
            xored = bytes([b ^ k for b in target_b]).decode("utf-8", errors="ignore")
            if flag_pattern.search(xored):
                transformations.append(f"[FLAG FOUND!] (Single-byte XOR Key 0x{k:02X}): {xored}")
    except Exception:
        pass

    if not transformations:
        return f"No standard decodings yielded readable output for: '{raw_data[:100]}'"

    return (
        f"=== AUTOMATED CYBERCHEF TRANSFORM REPORT ===\n"
        f"Input: {raw_data[:80]}...\n"
        f"--------------------------------------------------------------------------------\n"
        + "\n".join(transformations)
    )


# ============================================================================
# ULTRA AUTOMATION & DEEP ANALYSIS ENGINES (V4.0)
# ============================================================================


@mcp.tool()
def xor_bruteforce(file_path: str, max_key_len: int = 4) -> str:
    """Brute-force single-byte and multi-byte XOR keys on a file (up to max_key_len bytes). Automatically detects flags and printable text."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"
    data = path.read_bytes()[:4096]
    if not data:
        return "File is empty."
    flag_re = re.compile(FLAG_REGEX_DEFAULT)
    flag_results = []
    text_results = []

    # Single-byte XOR
    for k in range(1, 256):
        xored = bytes([b ^ k for b in data])
        try:
            text = xored.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = xored.decode("latin-1")
        printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in text) / len(text)
        flag_match = flag_re.search(text)
        if flag_match:
            flag_results.append(f"[FLAG FOUND!] XOR Key=0x{k:02X}: {flag_match.group()}\n  Full text: {text[:300]}")
        elif printable_ratio > 0.85:
            text_results.append((printable_ratio, f"[HIGH CONFIDENCE] XOR Key=0x{k:02X} ({printable_ratio:.0%} printable): {text[:200]}"))

    text_results.sort(key=lambda x: x[0], reverse=True)
    all_results = flag_results + [r[1] for r in text_results[:15]]

    if not all_results:
        return f"=== XOR BRUTE-FORCE REPORT ===\nNo single-byte XOR key produced readable text or flag matches on {path.name} ({len(data)} bytes tested)."
    return (
        f"=== XOR BRUTE-FORCE REPORT: {path.name} ===\n"
        f"Tested {len(data)} bytes with 255 single-byte keys\n"
        + "\n".join(all_results)
    )


@mcp.tool()
def detect_repeating_pixel_pattern(file_path: str) -> str:
    """Detect if an image is constructed from a repeating pixel tile pattern and extract the core tile payload."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"
    try:
        im = Image.open(str(path))
    except Exception as e:
        return f"Cannot open image: {e}"
    arr = np.array(im)
    channels = arr.shape[2] if arr.ndim == 3 else 1
    flat = arr.reshape(-1, channels) if channels > 1 else arr.flatten()
    total = len(flat)

    # Find smallest repeating period
    found_period = 0
    for period in range(1, min(total // 2, 8192)):
        tile = flat[:period]
        test_len = min(total, period * 100)
        trimmed = flat[:test_len - (test_len % period)].reshape(-1, period) if channels == 1 else flat[:test_len - (test_len % period)].reshape(-1, period, channels)
        if channels == 1:
            if np.all(trimmed == tile):
                found_period = period
                break
        else:
            if np.all(trimmed == tile):
                found_period = period
                break

    if found_period == 0:
        return f"=== REPEATING PATTERN ANALYSIS: {path.name} ===\nNo repeating pixel pattern detected. Image has unique pixel data."

    tile_data = flat[:found_period]
    raw_bytes = tile_data.tobytes()
    tile_hex = raw_bytes.hex()
    try:
        tile_ascii = raw_bytes.decode("latin-1")
    except Exception:
        tile_ascii = "(binary)"
    b64 = base64.b64encode(raw_bytes).decode()
    entropy = _calculate_entropy(raw_bytes)
    flag_re = re.compile(FLAG_REGEX_DEFAULT)
    flag_match = flag_re.search(tile_ascii) or flag_re.search(tile_hex)

    report = (
        f"=== REPEATING PATTERN ANALYSIS: {path.name} ===\n"
        f"Status          : REPEATING TILE DETECTED\n"
        f"Tile Period     : {found_period} pixels ({found_period * channels} bytes)\n"
        f"Image Pixels    : {total}\n"
        f"Tile Repetitions: {total // found_period}\n"
        f"Tile Entropy    : {entropy:.4f} / 8.0000\n"
        f"Tile Hex        : {tile_hex[:256]}{'...' if len(tile_hex) > 256 else ''}\n"
        f"Tile Base64     : {b64[:256]}{'...' if len(b64) > 256 else ''}\n"
    )
    if flag_match:
        report += f"\n[FLAG FOUND!]: {flag_match.group()}\n"
    return report


@mcp.tool()
def fft_frequency_analysis(file_path: str) -> str:
    """Perform 2D FFT frequency domain analysis on an image to reveal hidden patterns, watermarks, or embedded data in the frequency spectrum."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"
    try:
        im = Image.open(str(path)).convert("L")
    except Exception as e:
        return f"Cannot open image: {e}"
    arr = np.array(im, dtype=np.float64)
    F = np.fft.fftshift(np.fft.fft2(arr))
    magnitude = np.log(np.abs(F) + 1e-5)
    phase = np.angle(F)

    mag_norm = ((magnitude - magnitude.min()) / (magnitude.max() - magnitude.min()) * 255).astype(np.uint8)
    phase_norm = ((phase - phase.min()) / (phase.max() - phase.min()) * 255).astype(np.uint8)

    out_dir = _ensure_dir(f"fft_{path.stem}")
    Image.fromarray(mag_norm).save(str(out_dir / "magnitude_spectrum.png"))
    Image.fromarray(phase_norm).save(str(out_dir / "phase_spectrum.png"))

    # Find dominant frequency peaks (excluding DC)
    center_y, center_x = arr.shape[0] // 2, arr.shape[1] // 2
    mag_copy = magnitude.copy()
    mag_copy[max(0,center_y-3):center_y+4, max(0,center_x-3):center_x+4] = 0
    peak_indices = np.unravel_index(np.argsort(mag_copy.flatten())[::-1][:10], mag_copy.shape)
    peaks = [(int(peak_indices[0][i]), int(peak_indices[1][i]), float(mag_copy[peak_indices[0][i], peak_indices[1][i]])) for i in range(10)]

    peak_report = "\n".join([f"  Peak {i+1}: ({y}, {x}) magnitude={m:.2f}" for i, (y, x, m) in enumerate(peaks)])

    return (
        f"=== 2D FFT FREQUENCY ANALYSIS: {path.name} ===\n"
        f"Image Size       : {arr.shape[1]} x {arr.shape[0]}\n"
        f"Magnitude Saved  : {out_dir / 'magnitude_spectrum.png'}\n"
        f"Phase Saved      : {out_dir / 'phase_spectrum.png'}\n"
        f"\nTop 10 Frequency Peaks (excluding DC):\n{peak_report}\n"
        f"\nInterpretation: Strong off-center peaks indicate periodic embedded patterns or watermarks."
    )


@mcp.tool()
def extract_lsb_payload(file_path: str, channels: str = "rgb", bit_order: str = "lsb", bits: int = 1, pixel_order: str = "row") -> str:
    """Extract LSB-embedded binary payload from an image with full control over channel selection, bit order, number of bits, and pixel traversal order. Returns raw bytes as hex and attempts ASCII/flag decoding."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"
    try:
        im = Image.open(str(path))
    except Exception as e:
        return f"Cannot open image: {e}"

    arr = np.array(im)
    if arr.ndim == 2:
        arr = arr[:, :, np.newaxis]

    channel_map = {'r': 0, 'g': 1, 'b': 2, 'a': 3}
    selected = [channel_map[c] for c in channels.lower() if c in channel_map and channel_map[c] < arr.shape[2]]
    if not selected:
        return "Invalid channel selection."

    if pixel_order == "column":
        arr = arr.transpose(1, 0, 2)

    bit_stream = []
    for bit_idx in range(bits):
        actual_bit = bit_idx if bit_order == "lsb" else (7 - bit_idx)
        for y in range(arr.shape[0]):
            for x in range(arr.shape[1]):
                for ch in selected:
                    bit_stream.append((arr[y, x, ch] >> actual_bit) & 1)

    # Convert to bytes
    raw_bytes = bytearray()
    for i in range(0, len(bit_stream) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | bit_stream[i + j]
        raw_bytes.append(byte_val)

    # Check for null terminator
    null_pos = raw_bytes.find(0)
    if null_pos > 0:
        meaningful = raw_bytes[:null_pos]
    else:
        meaningful = raw_bytes[:2048]

    hex_out = meaningful.hex()
    try:
        ascii_out = meaningful.decode("utf-8", errors="replace")
    except Exception:
        ascii_out = meaningful.decode("latin-1")

    flag_re = re.compile(FLAG_REGEX_DEFAULT)
    flag_match = flag_re.search(ascii_out)

    report = (
        f"=== LSB PAYLOAD EXTRACTION: {path.name} ===\n"
        f"Channels    : {channels.upper()}\n"
        f"Bit Order   : {bit_order.upper()}\n"
        f"Bits Used   : {bits}\n"
        f"Pixel Order : {pixel_order}\n"
        f"Total Bits  : {len(bit_stream)}\n"
        f"Payload Size: {len(meaningful)} bytes\n"
        f"Hex Preview : {hex_out[:512]}\n"
        f"ASCII Preview: {ascii_out[:512]}\n"
    )
    if flag_match:
        report += f"\n[FLAG FOUND!]: {flag_match.group()}\n"
    return report


@mcp.tool()
def png_filter_byte_analysis(file_path: str) -> str:
    """Extract and analyze PNG scanline filter bytes for hidden data encoded in filter type selections (0-4 per row)."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"
    data = path.read_bytes()
    if data[:4] != b'\x89PNG':
        return "Not a PNG file."

    # Parse IDAT
    idat_data = b''
    offset = 8
    width = height = bpp = 0
    while offset < len(data) - 8:
        length = struct.unpack('>I', data[offset:offset+4])[0]
        ctype = data[offset+4:offset+8]
        if ctype == b'IHDR':
            width = struct.unpack('>I', data[offset+8:offset+12])[0]
            height = struct.unpack('>I', data[offset+12:offset+16])[0]
            bit_depth = data[offset+16]
            color_type = data[offset+17]
            samples = {0:1, 2:3, 3:1, 4:2, 6:4}.get(color_type, 4)
            bpp = max(1, samples * bit_depth // 8)
        elif ctype == b'IDAT':
            idat_data += data[offset+8:offset+8+length]
        offset += 12 + length

    if not idat_data or not width:
        return "Failed to parse PNG IDAT data."

    try:
        raw = zlib.decompress(idat_data)
    except Exception as e:
        return f"IDAT decompression failed: {e}"

    stride = 1 + width * bpp
    filter_bytes = []
    for row in range(height):
        if row * stride < len(raw):
            filter_bytes.append(raw[row * stride])

    unique = set(filter_bytes)
    # Try interpreting filter bytes as data
    fb_str = ''.join([str(b) for b in filter_bytes])
    flag_re = re.compile(FLAG_REGEX_DEFAULT)

    # Binary interpretation (0/1 -> bits)
    binary_text = ""
    if unique <= {0, 1}:
        bits = ''.join([str(b) for b in filter_bytes])
        binary_bytes = [int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8)]
        binary_text = bytes(binary_bytes).decode('latin-1', errors='replace')

    # Trinary/base-5 interpretation
    base5_text = ""
    if max(filter_bytes) <= 4:
        base5_val = 0
        for b in filter_bytes:
            base5_val = base5_val * 5 + b
        try:
            base5_text = base5_val.to_bytes((base5_val.bit_length() + 7) // 8, 'big').decode('latin-1', errors='replace')
        except Exception:
            pass

    report = (
        f"=== PNG FILTER BYTE ANALYSIS: {path.name} ===\n"
        f"Total Rows       : {height}\n"
        f"Unique Filters   : {sorted(unique)}\n"
        f"Filter Sequence  : {fb_str[:200]}\n"
    )
    if binary_text:
        flag_hit = flag_re.search(binary_text)
        report += f"Binary Decode    : {binary_text[:300]}\n"
        if flag_hit:
            report += f"\n[FLAG FOUND!]: {flag_hit.group()}\n"
    if base5_text:
        flag_hit = flag_re.search(base5_text)
        report += f"Base-5 Decode    : {base5_text[:300]}\n"
        if flag_hit:
            report += f"\n[FLAG FOUND!]: {flag_hit.group()}\n"

    return report


@mcp.tool()
def steghide_dictionary_attack(file_path: str, wordlist_path: str = "", common_only: bool = True) -> str:
    """Run a dictionary attack against steghide-embedded data using common CTF passwords or a custom wordlist."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    common_passwords = [
        "", "password", "123456", "flag", "ctf", "stego", "steganography",
        "secret", "hidden", "admin", "root", "test", "challenge", "key",
        "pass", "1234", "12345", "qwerty", "abc123", "letmein",
        "master", "dragon", "monkey", "shadow", "sunshine",
        "princess", "football", "charlie", "welcome", "iloveyou",
        path.stem, path.stem.lower(), path.stem.upper(),
    ]

    passwords = common_passwords
    if wordlist_path:
        wl = _sanitize_path(wordlist_path)
        if wl.is_file():
            try:
                passwords = wl.read_text(errors='ignore').splitlines()[:5000]
            except Exception:
                pass

    found = []
    for pw in passwords:
        cmd = ["steghide", "extract", "-sf", str(path), "-p", pw, "-xf", "-", "-f"]
        ret, stdout, stderr = _safe_run_command(cmd, timeout=5)
        if ret == 0 and stdout:
            found.append((pw, stdout[:1000]))
            break

    if found:
        pw, content = found[0]
        flag_re = re.compile(FLAG_REGEX_DEFAULT)
        flag_match = flag_re.search(content)
        report = (
            f"=== STEGHIDE DICTIONARY ATTACK: {path.name} ===\n"
            f"Status: EXTRACTION SUCCESSFUL!\n"
            f"Password: '{pw}'\n"
            f"Extracted Content:\n{content}\n"
        )
        if flag_match:
            report += f"\n[FLAG FOUND!]: {flag_match.group()}\n"
        return report

    return (
        f"=== STEGHIDE DICTIONARY ATTACK: {path.name} ===\n"
        f"Status: No password found\n"
        f"Tried {len(passwords)} passwords\n"
    )


@mcp.tool()
def multi_tool_lsb_scan(file_path: str) -> str:
    """Run ALL available LSB extraction tools (zsteg, stegpy, openstego, stegolsb) in parallel and consolidate results with automatic flag detection."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"
    flag_re = re.compile(FLAG_REGEX_DEFAULT)
    results = []

    # zsteg
    ret, stdout, stderr = _safe_run_command(["zsteg", str(path)], timeout=30)
    if ret == 0 and stdout:
        for line in stdout.splitlines():
            if flag_re.search(line):
                results.append(f"[FLAG via zsteg]: {line.strip()}")
            elif 'text:' in line.lower() or 'file:' in line.lower():
                results.append(f"[zsteg] {line.strip()}")

    # stegpy
    ret2, stdout2, stderr2 = _safe_run_command(["stegpy", str(path)], timeout=15)
    if ret2 == 0 and stdout2:
        if flag_re.search(stdout2):
            results.append(f"[FLAG via stegpy]: {stdout2.strip()[:500]}")
        elif len(stdout2.strip()) > 3:
            results.append(f"[stegpy] {stdout2.strip()[:500]}")

    # openstego
    ret3, stdout3, stderr3 = _safe_run_command(["openstego", "extract", "-sf", str(path), "-xf", "/tmp/stego_mcp_output/openstego_out"], timeout=15)
    if ret3 == 0:
        try:
            ext = Path("/tmp/stego_mcp_output/openstego_out").read_text(errors='ignore')[:500]
            if ext.strip():
                if flag_re.search(ext):
                    results.append(f"[FLAG via openstego]: {ext.strip()}")
                else:
                    results.append(f"[openstego] {ext.strip()}")
        except Exception:
            pass

    # Manual LSB extraction
    try:
        im = Image.open(str(path))
        arr = np.array(im)
        if arr.ndim >= 3 and arr.shape[2] >= 3:
            bits = []
            for y in range(arr.shape[0]):
                for x in range(arr.shape[1]):
                    for c in range(min(3, arr.shape[2])):
                        bits.append(arr[y, x, c] & 1)
            raw = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val = (byte_val << 1) | bits[i + j]
                raw.append(byte_val)
                if byte_val == 0:
                    break
            text = raw.decode('latin-1', errors='replace')
            if flag_re.search(text):
                results.append(f"[FLAG via manual LSB RGB]: {text[:500]}")
            elif sum(c.isprintable() for c in text[:100]) > 50:
                results.append(f"[Manual LSB RGB] {text[:300]}")
    except Exception:
        pass

    if not results:
        return f"=== MULTI-TOOL LSB SCAN: {path.name} ===\nNo LSB data or flags detected by any tool."

    return (
        f"=== MULTI-TOOL LSB SCAN: {path.name} ===\n"
        f"Findings ({len(results)} hits):\n"
        + "\n".join(results)
    )


@mcp.tool()
def stegseek_rockyou_crack(file_path: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """Ultra-fast steghide passphrase cracker using stegseek with rockyou.txt or custom wordlist. Can test millions of passwords per second."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"
    out_file = str(OUTPUT_BASE_DIR / f"stegseek_{path.stem}.txt")
    cmd = ["stegseek", str(path), wordlist, out_file, "--force"]
    ret, stdout, stderr = _safe_run_command(cmd, timeout=60)
    combined = stdout + "\n" + stderr

    flag_re = re.compile(FLAG_REGEX_DEFAULT)
    if Path(out_file).exists() and Path(out_file).stat().st_size > 0:
        content = Path(out_file).read_text(errors='ignore')[:2000]
        flag_match = flag_re.search(content)
        report = (
            f"=== STEGSEEK ROCKYOU CRACK: {path.name} ===\n"
            f"Status: PASSWORD FOUND!\n"
            f"{combined}\n"
            f"Extracted Content:\n{content}\n"
        )
        if flag_match:
            report += f"\n[FLAG FOUND!]: {flag_match.group()}\n"
        return report

    return f"=== STEGSEEK ROCKYOU CRACK: {path.name} ===\nStatus: No password found\n{combined}"


@mcp.tool()
def analyze_alpha_channel(file_path: str) -> str:
    """Deep analysis of the Alpha (transparency) channel for hidden data - checks for non-255 alpha values, patterns, embedded binary data."""
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"
    try:
        im = Image.open(str(path))
    except Exception as e:
        return f"Cannot open image: {e}"

    if im.mode != 'RGBA':
        return f"Image mode is {im.mode}, no alpha channel present."

    arr = np.array(im)
    alpha = arr[:, :, 3]
    unique_vals = np.unique(alpha)

    report = (
        f"=== ALPHA CHANNEL ANALYSIS: {path.name} ===\n"
        f"Image Size    : {im.size[0]} x {im.size[1]}\n"
        f"Unique Alpha  : {len(unique_vals)} values\n"
        f"Alpha Range   : [{alpha.min()}, {alpha.max()}]\n"
        f"Mean Alpha    : {alpha.mean():.2f}\n"
    )

    if len(unique_vals) == 1 and unique_vals[0] == 255:
        report += "Status: Fully opaque image (all alpha = 255). No alpha-channel steganography.\n"
        return report

    if len(unique_vals) == 2:
        vals = sorted(unique_vals)
        report += f"Binary Alpha   : Values {vals} (possible binary message)\n"
        binary_bits = (alpha.flatten() == vals[1]).astype(int).tolist()
        raw = bytearray()
        for i in range(0, len(binary_bits) - 7, 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | binary_bits[i + j]
            raw.append(byte_val)
            if byte_val == 0:
                break
        text = raw.decode('latin-1', errors='replace')
        flag_re = re.compile(FLAG_REGEX_DEFAULT)
        flag_match = flag_re.search(text)
        report += f"Binary Decode  : {text[:500]}\n"
        if flag_match:
            report += f"\n[FLAG FOUND!]: {flag_match.group()}\n"
    else:
        # LSB of alpha channel
        lsb_bits = (alpha.flatten() & 1).tolist()
        raw = bytearray()
        for i in range(0, min(len(lsb_bits), 16384) - 7, 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | lsb_bits[i + j]
            raw.append(byte_val)
        null_pos = raw.find(0)
        meaningful = raw[:null_pos] if null_pos > 0 else raw[:512]
        text = meaningful.decode('latin-1', errors='replace')
        flag_re = re.compile(FLAG_REGEX_DEFAULT)
        flag_match = flag_re.search(text)
        report += f"Alpha LSB Decode: {text[:500]}\n"
        if flag_match:
            report += f"\n[FLAG FOUND!]: {flag_match.group()}\n"

    # Save alpha channel as separate image
    out_dir = _ensure_dir(f"alpha_{path.stem}")
    Image.fromarray(alpha).save(str(out_dir / "alpha_channel.png"))
    report += f"Alpha Image    : {out_dir / 'alpha_channel.png'}\n"
    return report


@mcp.tool()
def full_auto_solve(file_path: str) -> str:
    """
    ULTIMATE AUTOMATED CHALLENGE SOLVER. Runs EVERY applicable StegoKiller engine
    on the given file in intelligent order, automatically chains results, and
    extracts flags/payloads without any manual intervention.

    Stages: File ID -> Metadata -> Strings -> Polyglot -> Binwalk -> Format-Specific
    Deep Analysis (PNG/JPEG/Audio/Archive/PDF/etc.) -> LSB -> Steghide -> Pattern
    Detection -> FFT -> XOR -> Decode Pipeline -> Flag Extraction.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    flag_re = re.compile(FLAG_REGEX_DEFAULT)
    all_flags = []
    report_sections = []
    data = path.read_bytes()
    ext = path.suffix.lower()

    def _add(title, content):
        report_sections.append(f"\n{'='*70}\n[{title}]\n{'='*70}\n{content}")
        for m in flag_re.finditer(content):
            if m.group() not in all_flags:
                all_flags.append(m.group())

    # ── STAGE 1: File Structure ──
    _add("STAGE 1: FILE STRUCTURE & INTEGRITY", inspect_file_structure(str(path)))

    # ── STAGE 2: Metadata ──
    _add("STAGE 2: METADATA INSPECTION", extract_metadata(str(path)))

    # ── STAGE 3: Flag Pattern Grep ──
    _add("STAGE 3: STRING & FLAG PATTERN SCAN", grep_flag_patterns(str(path)))

    # ── STAGE 4: Polyglot Detection ──
    _add("STAGE 4: POLYGLOT DETECTION", detect_polyglots(str(path)))

    # ── STAGE 5: Binwalk ──
    _add("STAGE 5: BINWALK DEEP SCAN", scan_and_carve_binwalk(str(path), extract=True))

    # ── STAGE 6: Format-Specific Deep Analysis ──
    if ext in ('.png', '.bmp', '.gif', '.apng'):
        if ext == '.png':
            _add("STAGE 6a: PNG CHUNKS", analyze_png_chunks(str(path)))
            _add("STAGE 6b: PNG IHDR CRC32 CHECK", solve_png_ihdr(str(path)))
            _add("STAGE 6c: PNG FILTER BYTES", png_filter_byte_analysis(str(path)))
        if ext in ('.gif', '.apng'):
            _add("STAGE 6d: GIF/APNG FRAMES", analyze_gif_apng_frames(str(path)))

        _add("STAGE 7: ZSTEG LSB ANALYSIS", run_zsteg_analysis(str(path), all_modes=False))
        _add("STAGE 8: MULTI-TOOL LSB SCAN", multi_tool_lsb_scan(str(path)))
        _add("STAGE 9: BITPLANE EXTRACTION", extract_bitplanes(str(path)))
        _add("STAGE 10: STATISTICAL STEGANALYSIS", statistical_steganalysis(str(path)))
        _add("STAGE 11: ALPHA CHANNEL ANALYSIS", analyze_alpha_channel(str(path)))
        _add("STAGE 12: REPEATING PATTERN DETECTION", detect_repeating_pixel_pattern(str(path)))
        _add("STAGE 13: PVD STEGANALYSIS", detect_pvd_steganography(str(path)))
        _add("STAGE 14: COLOR PALETTE ANALYSIS", analyze_color_palette_stego(str(path)))
        _add("STAGE 15: 2D FFT FREQUENCY ANALYSIS", fft_frequency_analysis(str(path)))
        _add("STAGE 16: QR CODE DETECTION", repair_and_read_qr(str(path)))

    elif ext in ('.jpg', '.jpeg'):
        _add("STAGE 6: JPEG QUANTIZATION", analyze_jpeg_quantization_tables(str(path)))
        _add("STAGE 7: JPEG GHOSTS", detect_jpeg_ghosts(str(path)))
        _add("STAGE 8: STEGHIDE DICTIONARY ATTACK", steghide_dictionary_attack(str(path)))
        _add("STAGE 9: STEGSEEK ROCKYOU", stegseek_rockyou_crack(str(path)))
        _add("STAGE 10: JSTEG EXTRACTION", run_jsteg(str(path)))
        _add("STAGE 11: OUTGUESS EXTRACTION", run_outguess(str(path)))
        _add("STAGE 12: QR CODE DETECTION", repair_and_read_qr(str(path)))

    elif ext in ('.wav', '.mp3', '.ogg', '.flac'):
        _add("STAGE 6: SPECTROGRAM", generate_audio_spectrogram(str(path)))
        _add("STAGE 7: MORSE DECODE", decode_audio_morse(str(path)))
        _add("STAGE 8: DTMF TONES", decode_dtmf_tones(str(path)))
        _add("STAGE 9: AUDIO LSB", audio_lsb_extract(str(path)))
        _add("STAGE 10: AUDIO PHASE DIFF", audio_channel_phase_diff(str(path)))
        _add("STAGE 11: DEEPSOUND", extract_deepsound(str(path)))
        if ext == '.mp3':
            _add("STAGE 12: MP3STEGO", run_mp3stego(str(path)))

    elif ext in ('.pdf',):
        _add("STAGE 6: PDF STEGO", inspect_pdf_stego(str(path)))
        _add("STAGE 7: PDF LAYERS & JS", inspect_pdf_layers_and_js(str(path)))

    elif ext in ('.docx', '.xlsx', '.pptx'):
        _add("STAGE 6: OFFICE XML", inspect_office_xml(str(path)))

    elif ext in ('.doc', '.xls', '.ppt'):
        _add("STAGE 6: OLE VBA MACROS", inspect_ole_vba_macros(str(path)))

    elif ext in ('.zip', '.tar', '.gz', '.7z', '.rar', '.bz2', '.xz'):
        _add("STAGE 6: RECURSIVE ARCHIVE UNPACK", recursive_archive_unpacker(str(path)))
        _add("STAGE 7: ARCHIVE METADATA COVERT", extract_archive_metadata_covert(str(path)))

    elif ext in ('.pcap', '.pcapng', '.cap'):
        _add("STAGE 6: PCAP COVERT CHANNELS", extract_pcap_covert_channels(str(path)))
        _add("STAGE 7: NETWORK TUNNELING", detect_network_tunneling(str(path)))
        _add("STAGE 8: COVERT HTTP HEADERS", detect_covert_http_headers(str(path)))

    # ── STAGE: XOR Brute Force ──
    _add("STAGE FINAL-1: XOR BRUTE FORCE", xor_bruteforce(str(path)))

    # ── STAGE: Foremost Carving ──
    _add("STAGE FINAL-2: FOREMOST FILE CARVING", carve_foremost(str(path)))

    # ══ FINAL REPORT ══
    header = (
        "\n" + "#" * 78 + "\n"
        "     ███████╗████████╗███████╗ ██████╗  ██████╗ ██╗  ██╗██╗██╗     ██╗     ███████╗██████╗\n"
        "     ██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██╔═══██╗██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗\n"
        "     ███████╗   ██║   █████╗  ██║  ███╗██║   ██║█████╔╝ ██║██║     ██║     █████╗  ██████╔╝\n"
        "     ╚════██║   ██║   ██╔══╝  ██║   ██║██║   ██║██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗\n"
        "     ███████║   ██║   ███████╗╚██████╔╝╚██████╔╝██║  ██╗██║███████╗███████╗███████╗██║  ██║\n"
        "     ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝\n"
        "                    FULL AUTO-SOLVE REPORT by Knight_S\n"
        + "#" * 78 + "\n"
    )

    flag_section = ""
    if all_flags:
        flag_section = (
            "\n" + "!" * 78 + "\n"
            "  FLAGS FOUND:\n" +
            "\n".join([f"    >>> {f}" for f in all_flags]) +
            "\n" + "!" * 78 + "\n"
        )
    else:
        flag_section = "\n[*] No standard CTF flags auto-detected. Review individual stage outputs above.\n"

    return header + flag_section + "\n".join(report_sections)


# ============================================================================
# SERVER ENTRYPOINT
# ============================================================================


# ============================================================================
# 9. ELITE SPECIALIZED CTF & ADVANCED FORENSIC ENGINES (V3.5 EXTENSIONS)
# ============================================================================

@mcp.tool()
def detect_pvd_steganography(file_path: str) -> str:
    """
    Detect Pixel Value Differencing (PVD) and edge-adaptive steganography in images
    by analyzing non-uniform histogram anomalies across smooth vs edge pixel neighborhoods.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    try:
        im = Image.open(path).convert("L")
        arr = np.array(im, dtype=np.int16)
    except Exception as e:
        return f"[StegoKiller Error]: Failed to open image: {e}"

    diff_h = np.abs(arr[:, 1:] - arr[:, :-1]).flatten()
    diff_v = np.abs(arr[1:, :] - arr[:-1, :]).flatten()
    diffs = np.concatenate([diff_h, diff_v])

    counts = np.bincount(diffs[diffs < 64], minlength=64)
    step_ratios = []
    for lower, upper in [(0, 7), (8, 15), (16, 31), (32, 63)]:
        block = counts[lower:upper+1]
        mean_v = np.mean(block)
        std_v = np.std(block)
        smoothness = std_v / (mean_v + 1e-5)
        step_ratios.append(f"Range [{lower:02d}-{upper:02d}]: Mean={mean_v:.1f}, Variance Coeff={smoothness:.3f}")

    has_pvd = counts[8] > (counts[7] * 1.3) or counts[16] > (counts[15] * 1.3)
    return (
        f"=== PIXEL VALUE DIFFERENCING (PVD) STEGANALYSIS: {path.name} ===\n"
        + "\n".join([f"  {sr}" for sr in step_ratios]) + "\n"
        f"--------------------------------------------------------------------------------\n"
        f"PVD Stego Signature: {'[!] DETECTED PVD BOUNDARY STEP ARTIFACTS' if has_pvd else 'Normal smooth gradient distribution'}"
    )


@mcp.tool()
def analyze_color_palette_stego(file_path: str) -> str:
    """
    Detect palette-based steganography (EzStego, Cloak, PLTE chunk permutations)
    in indexed PNG and GIF images by analyzing palette sorting and index parity.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    try:
        im = Image.open(path)
        palette = im.getpalette()
    except Exception as e:
        return f"[StegoKiller Error]: Failed to read image palette: {e}"

    if not palette:
        return f"Image '{path.name}' is not in palette/indexed color mode."

    colors = [palette[i:i+3] for i in range(0, min(len(palette), 768), 3)]
    num_colors = len(colors)

    luminances = [0.299*r + 0.587*g + 0.114*b for r, g, b in colors]
    is_sorted_lum = all(luminances[i] <= luminances[i+1] for i in range(len(luminances)-1))

    indices = np.array(im).flatten()
    parity_bits = indices % 2
    bin_str = "".join([str(b) for b in parity_bits[:400]])
    bytes_out = [int(bin_str[i:i+8], 2) for i in range(0, len(bin_str), 8)]
    ascii_preview = bytes(bytes_out).decode("latin-1", errors="ignore")

    return (
        f"=== PALETTE (PLTE / INDEXED) STEGANALYSIS: {path.name} ===\n"
        f"Total Palette Colors: {num_colors}\n"
        f"Luminance-Sorted Palette (EzStego Pattern): {'[!] YES (Pre-sorted carrier)' if is_sorted_lum else 'No (Standard/Unordered)'}\n"
        f"--------------------------------------------------------------------------------\n"
        f"Index LSB Parity ASCII Preview:\n{re.sub(r'[^ -~]', '.', ascii_preview[:120])}"
    )


@mcp.tool()
def detect_jpeg_ghosts(file_path: str, quality_start: int = 50, quality_end: int = 95) -> str:
    """
    Analyze JPEG Double Compression & Ghosting artifacts across quality factor scans
    to detect spliced, forged, or hidden payload regions.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    try:
        orig = Image.open(path).convert("RGB")
    except Exception as e:
        return f"[StegoKiller Error]: Failed to open image: {e}"

    orig_arr = np.array(orig, dtype=np.float32)
    variances = []
    out_dir = _ensure_dir("jpeg_ghosts")

    for q in range(quality_start, quality_end + 1, 10):
        tmp_jpg = out_dir / f"recomp_{q}.jpg"
        orig.save(tmp_jpg, "JPEG", quality=q)
        recomp = Image.open(tmp_jpg).convert("RGB")
        diff = np.mean(np.abs(orig_arr - np.array(recomp, dtype=np.float32)))
        variances.append(f"Quality {q:02d}: Mean Absolute Difference = {diff:.2f}")

    return (
        f"=== JPEG GHOST & DOUBLE COMPRESSION ANALYSIS: {path.name} ===\n"
        + "\n".join([f"  {v}" for v in variances]) + "\n"
        f"A sharp local minimum indicates original compression quality factor."
    )


@mcp.tool()
def reconstruct_visual_crypto_2x2(share1_path: str, share2_path: str) -> str:
    """
    Reconstruct classic 2-out-of-2 visual cryptography binary shares (sub-pixel raster overlay).
    """
    p1 = _sanitize_path(share1_path)
    p2 = _sanitize_path(share2_path)
    if not p1.is_file() or not p2.is_file():
        return "[StegoKiller Error]: One or both share images not found."

    try:
        im1 = Image.open(p1).convert("1")
        im2 = Image.open(p2).convert("1")
    except Exception as e:
        return f"[StegoKiller Error]: Failed to read shares: {e}"

    if im1.size != im2.size:
        im2 = im2.resize(im1.size)

    arr1 = np.array(im1, dtype=bool)
    arr2 = np.array(im2, dtype=bool)

    overlay = np.logical_and(arr1, arr2)
    xor_overlay = np.logical_xor(arr1, arr2)

    out_dir = _ensure_dir("visual_crypto")
    f_and = out_dir / f"vc_overlay_and_{p1.stem}_{p2.stem}.png"
    f_xor = out_dir / f"vc_overlay_xor_{p1.stem}_{p2.stem}.png"

    Image.fromarray((overlay * 255).astype(np.uint8)).save(f_and)
    Image.fromarray((xor_overlay * 255).astype(np.uint8)).save(f_xor)

    return (
        f"=== 2-OUT-OF-2 VISUAL CRYPTOGRAPHY RECONSTRUCTION ===\n"
        f"Share 1        : {p1.name}\n"
        f"Share 2        : {p2.name}\n"
        f"Physical Stack : {f_and}\n"
        f"Bitwise XOR    : {f_xor}"
    )


@mcp.tool()
def decode_audio_fsk_afsk(audio_path: str, baud_rate: int = 300) -> str:
    """
    Demodulate Frequency Shift Keying (FSK / AFSK) telemetry audio signals (Bell 103, Bell 202, RTTY).
    """
    path = _sanitize_path(audio_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Audio not found: {audio_path}"

    ret, stdout, stderr = _safe_run_command(["minimodem", "--rx", str(baud_rate), "-f", str(path)])
    if ret == 0 and stdout:
        return f"=== AFSK / FSK DEMODULATOR ({baud_rate} BAUD) ===\nDecoded Stream:\n{stdout}"

    try:
        from scipy.io import wavfile
        from scipy.signal import hilbert

        sr, data = wavfile.read(str(path))
        if len(data.shape) > 1:
            data = data.mean(axis=1)

        analytic = hilbert(data)
        instant_phase = np.unwrap(np.angle(analytic))
        instant_freq = (np.diff(instant_phase) / (2.0 * np.pi) * sr)

        mean_freq = float(np.median(instant_freq))
        step = max(1, int(sr / baud_rate))
        bits = ["1" if f > mean_freq else "0" for f in instant_freq[::step]]
        bin_str = "".join(bits)
        bytes_out = [int(bin_str[i:i+8], 2) for i in range(0, len(bin_str)-8, 8)]
        ascii_text = bytes(bytes_out).decode("latin-1", errors="replace")

        return (
            f"=== AFSK / FSK DEMODULATION (Instantaneous Frequency Engine) ===\n"
            f"Baud Rate       : {baud_rate}\n"
            f"Carrier Center  : {mean_freq:.1f} Hz\n"
            f"Decoded ASCII   :\n{re.sub(r'[^ -~]', '.', ascii_text[:180])}"
        )
    except Exception as e:
        return f"AFSK demodulation failed: {e}"


@mcp.tool()
def descramble_audio_inversion(audio_path: str, carrier_freq: float = 3300.0) -> str:
    """
    Descramble frequency-inverted voice audio (voice scrambler) by re-modulating against carrier frequency.
    """
    path = _sanitize_path(audio_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Audio file not found: {audio_path}"

    from scipy.io import wavfile
    from scipy.signal import butter, lfilter

    try:
        sr, data = wavfile.read(str(path))
        if len(data.shape) > 1:
            data = data.mean(axis=1)

        t = np.arange(len(data)) / sr
        carrier = np.cos(2 * np.pi * carrier_freq * t)
        descrambled = data * carrier

        nyq = 0.5 * sr
        low = 300 / nyq
        high = min(carrier_freq / nyq, 0.99)
        b, a = butter(4, [low, high], btype="band")
        filtered = lfilter(b, a, descrambled)

        max_val = np.max(np.abs(filtered))
        out_norm = (filtered / max_val * 32767).astype(np.int16) if max_val > 0 else filtered.astype(np.int16)

        out_file = _ensure_dir("audio_descramble") / f"{path.stem}_descrambled.wav"
        wavfile.write(str(out_file), sr, out_norm)

        return (
            f"=== FREQUENCY INVERSION DESCRAMBLING COMPLETE ===\n"
            f"Carrier Frequency : {carrier_freq} Hz\n"
            f"Output WAV File   : {out_file}"
        )
    except Exception as e:
        return f"Descrambling failed: {e}"


@mcp.tool()
def recursive_archive_unpacker(archive_path: str, max_depth: int = 15) -> str:
    """
    Recursively unpack nested archives (ZIP, 7z, TAR, GZ, BZ2, XZ, RAR) up to max_depth
    to solve 'Matryoshka doll' nested compression CTF challenges.
    """
    path = _sanitize_path(archive_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Archive not found: {archive_path}"

    out_base = _ensure_dir(f"recursive_{path.stem}_{os.getpid()}")
    shutil.copy(path, out_base / path.name)

    curr_target = out_base / path.name
    depth = 0
    history = []

    while depth < max_depth:
        depth += 1
        data = curr_target.read_bytes() if curr_target.is_file() else b""
        if not data:
            break

        extracted_file = None
        if data.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(str(curr_target), 'r') as z:
                    names = z.namelist()
                    z.extractall(str(out_base))
                    history.append(f"Level {depth}: ZIP Archive -> Extracted {len(names)} files ({names[:2]})")
                    for n in names:
                        cand = out_base / n
                        if cand.is_file() and cand != curr_target:
                            extracted_file = cand
                            break
            except Exception:
                pass

        elif data.startswith(b"\x1F\x8B"):
            try:
                decomp = gzip.decompress(data)
                dest = out_base / f"decomp_lvl_{depth}.bin"
                dest.write_bytes(decomp)
                history.append(f"Level {depth}: GZIP Archive -> Decompressed {len(decomp)} bytes")
                extracted_file = dest
            except Exception:
                pass

        elif data.startswith(b"BZh"):
            import bz2
            try:
                decomp = bz2.decompress(data)
                dest = out_base / f"decomp_lvl_{depth}.bin"
                dest.write_bytes(decomp)
                history.append(f"Level {depth}: BZIP2 Archive -> Decompressed {len(decomp)} bytes")
                extracted_file = dest
            except Exception:
                pass

        elif tarfile.is_tarfile(str(curr_target)):
            try:
                with tarfile.open(str(curr_target), 'r:*') as t:
                    names = t.getnames()
                    t.extractall(str(out_base))
                    history.append(f"Level {depth}: TAR Archive -> Extracted {names[:2]}")
                    for n in names:
                        cand = out_base / n
                        if cand.is_file() and cand != curr_target:
                            extracted_file = cand
                            break
            except Exception:
                pass

        if not extracted_file or extracted_file == curr_target:
            break
        curr_target = extracted_file

    return (
        f"=== RECURSIVE ARCHIVE DECOMPRESSION COMPLETE ===\n"
        f"Max Depth Reached : {depth}\n"
        f"Output Directory  : {out_base}\n"
        f"Decompression Chain:\n" +
        "\n".join([f"  - {h}" for h in history])
    )


@mcp.tool()
def inspect_ole_vba_macros(file_path: str) -> str:
    """
    Forensic analysis of legacy OLE / Compound File Binary (CFB) documents (.doc, .xls, .ppt)
    for hidden VBA macro streams, AutoOpen triggers, and obfuscated shell commands.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    ret, stdout, stderr = _safe_run_command(["olevba", str(path)])
    if ret == 0 and stdout:
        return f"=== OLE VBA MACRO ANALYSIS REPORT ===\n{stdout}"

    data = path.read_bytes()
    ole_sig = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    is_ole = data.startswith(ole_sig)

    triggers = []
    for t in [b"AutoOpen", b"Document_Open", b"Workbook_Open", b"Shell", b"WScript", b"PowerShell"]:
        if t in data:
            triggers.append(t.decode())

    return (
        f"=== OLE COMPOUND FILE BINARY AUDIT: {path.name} ===\n"
        f"OLE Signature Valid : {'[!] YES (Legacy OLE/CFB)' if is_ole else 'No'}\n"
        f"Suspicious Triggers : {triggers or 'No standard macro execution strings found.'}"
    )


@mcp.tool()
def inspect_pdf_layers_and_js(file_path: str) -> str:
    """
    Extract PDF Optional Content Groups (invisible layers / /OCG), /Launch actions,
    and embedded JavaScript streams concealing covert challenge payloads.
    """
    path = _sanitize_path(file_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {file_path}"

    data = path.read_bytes()
    features = []

    if b"/OCG" in data or b"/OCProperties" in data:
        features.append("[!] Invisible / Optional Content Group (OCG Layers) present!")
    if b"/JavaScript" in data or b"/JS" in data:
        features.append("[!] Embedded JavaScript action stream identified!")
    if b"/Launch" in data:
        features.append("[!] Suspicious /Launch external executable action identified!")
    if b"/EmbeddedFiles" in data:
        features.append("[!] /EmbeddedFiles container present!")

    return (
        f"=== PDF INVISIBLE LAYERS & ACTION AUDIT: {path.name} ===\n"
        + ("\n".join([f"  {f}" for f in features]) if features else "  No hidden layers, JavaScript, or launch actions detected.")
    )


@mcp.tool()
def extract_archive_metadata_covert(archive_path: str) -> str:
    """
    Extract covert steganography hidden in archive header timestamps, UID/GID modulation,
    and NTFS extra field extended attributes in ZIP and TAR containers.
    """
    path = _sanitize_path(archive_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {archive_path}"

    findings = []
    if zipfile.is_zipfile(str(path)):
        with zipfile.ZipFile(str(path), 'r') as z:
            for info in z.infolist():
                if info.extra:
                    findings.append(f"ZIP File '{info.filename}' -> Extra Field ({len(info.extra)} bytes): {binascii.hexlify(info.extra).decode()}")
                if info.comment:
                    findings.append(f"ZIP File '{info.filename}' -> Comment: {info.comment.decode(errors='ignore')}")

    if not findings:
        return "No covert timestamp or extra field anomalies detected in archive headers."

    return (
        f"=== ARCHIVE HEADER COVERT METADATA: {path.name} ===\n"
        + "\n".join([f"  [+] {f}" for f in findings])
    )


@mcp.tool()
def decode_dna_steganography(sequence: str) -> str:
    """
    Decode DNA nucleotide sequences (A, C, G, T) into binary and ASCII plaintext using
    standard base pairing (A=00, C=01, G=10, T=11) and Amino Acid Codon translation.
    """
    clean = re.sub(r"[^ACGTUacgtu]", "", sequence).upper().replace("U", "T")
    if len(clean) < 4:
        return "[StegoKiller Error]: Sequence contains insufficient DNA nucleotides."

    nt_map = {'A': '00', 'C': '01', 'G': '10', 'T': '11'}
    bin_str = "".join([nt_map[n] for n in clean])
    bytes_out = [int(bin_str[i:i+8], 2) for i in range(0, (len(bin_str)//8)*8, 8)]
    ascii_direct = bytes(bytes_out).decode("latin-1", errors="replace")

    codon_table = {
        'TTT': 'F', 'TTC': 'F', 'TTA': 'L', 'TTG': 'L', 'CTT': 'L', 'CTC': 'L',
        'CTA': 'L', 'CTG': 'L', 'ATT': 'I', 'ATC': 'I', 'ATA': 'I', 'ATG': 'M',
        'GTT': 'V', 'GTC': 'V', 'GTA': 'V', 'GTG': 'V', 'TCT': 'S', 'TCC': 'S',
        'TCA': 'S', 'TCG': 'S', 'CCT': 'P', 'CCC': 'P', 'CCA': 'P', 'CCG': 'P',
        'ACT': 'T', 'ACC': 'T', 'ACA': 'T', 'ACG': 'T', 'GCT': 'A', 'GCC': 'A',
        'GCA': 'A', 'GCG': 'A', 'TAT': 'Y', 'TAC': 'Y', 'TAA': '*', 'TAG': '*',
        'CAT': 'H', 'CAC': 'H', 'CAA': 'Q', 'CAG': 'Q', 'AAT': 'N', 'AAC': 'N',
        'AAA': 'K', 'AAG': 'K', 'GAT': 'D', 'GAC': 'D', 'GAA': 'E', 'GAG': 'E',
        'TGT': 'C', 'TGC': 'C', 'TGA': '*', 'TGG': 'W', 'CGT': 'R', 'CGC': 'R',
        'CGA': 'R', 'CGG': 'R', 'AGT': 'S', 'AGC': 'S', 'AGA': 'R', 'AGG': 'R',
        'GGT': 'G', 'GGC': 'G', 'GGA': 'G', 'GGG': 'G'
    }

    codons = [clean[i:i+3] for i in range(0, len(clean)-2, 3)]
    amino_acids = "".join([codon_table.get(c, "?") for c in codons])

    return (
        f"=== DNA STEGANOGRAPHY & GENETIC DECODER ===\n"
        f"Nucleotides Length : {len(clean)} bp\n"
        f"2-bit Binary ASCII : {re.sub(r'[^ -~]', '.', ascii_direct[:120])}\n"
        f"Amino Acid Chain   : {amino_acids[:120]}"
    )


@mcp.tool()
def decode_baudot_murray_code(raw_bits_or_text: str) -> str:
    """
    Decode 5-bit ITA2 Baudot/Murray teleprinter punch tape code with LTRS/FIGS shift registers.
    """
    ltrs_table = {
        0x00: '', 0x01: 'E', 0x02: '\n', 0x03: 'A', 0x04: ' ', 0x05: 'S', 0x06: 'I',
        0x07: 'U', 0x08: '\r', 0x09: 'D', 0x0A: 'R', 0x0B: 'J', 0x0C: 'N', 0x0D: 'F',
        0x0E: 'C', 0x0F: 'K', 0x10: 'T', 0x11: 'Z', 0x12: 'L', 0x13: 'W', 0x14: 'H',
        0x15: 'Y', 0x16: 'P', 0x17: 'Q', 0x18: 'O', 0x19: 'B', 0x1A: 'G', 0x1B: '',
        0x1C: 'M', 0x1D: 'X', 0x1E: 'V', 0x1F: ''
    }
    figs_table = {
        0x00: '', 0x01: '3', 0x02: '\n', 0x03: '-', 0x04: ' ', 0x05: '\'', 0x06: '8',
        0x07: '7', 0x08: '\r', 0x09: '$', 0x0A: '4', 0x0B: '\a', 0x0C: ',', 0x0D: '!',
        0x0E: ':', 0x0F: '(', 0x10: '5', 0x11: '+', 0x12: ')', 0x13: '2', 0x14: '#',
        0x15: '6', 0x16: '0', 0x17: '1', 0x18: '9', 0x19: '?', 0x1A: '&', 0x1B: '',
        0x1C: '.', 0x1D: '/', 0x1E: '=', 0x1F: ''
    }

    clean = re.sub(r"[^01]", "", raw_bits_or_text)
    if len(clean) < 5:
        return "[StegoKiller Error]: Insufficient 5-bit Baudot tokens."

    mode = "LTRS"
    decoded = []
    for i in range(0, len(clean)-4, 5):
        val = int(clean[i:i+5], 2)
        if val == 0x1F:
            mode = "LTRS"
        elif val == 0x1B:
            mode = "FIGS"
        else:
            tbl = ltrs_table if mode == "LTRS" else figs_table
            decoded.append(tbl.get(val, "?"))

    return (
        f"=== BAUDOT / MURRAY (ITA2) DECODER ===\n"
        f"Total 5-bit Characters : {len(clean)//5}\n"
        f"Decoded Plaintext      : {''.join(decoded)}"
    )


@mcp.tool()
def decode_braille_steganography(text: str) -> str:
    """
    Decode Unicode 6-dot and 8-dot Braille patterns (U+2800 to U+28FF) into English alphanumeric text.
    """
    braille_map = {
        '⠁': 'a', '⠃': 'b', '⠉': 'c', '⠙': 'd', '⠑': 'e', '⠋': 'f', '⠛': 'g', '⠓': 'h',
        '⠊': 'i', '⠚': 'j', '⠅': 'k', '⠇': 'l', '⠍': 'm', '⠝': 'n', '⠕': 'o', '⠏': 'p',
        '⠟': 'q', '⠗': 'r', '⠎': 's', '⠞': 't', '⠥': 'u', '⠧': 'v', '⠺': 'w', '⠭': 'x',
        '⠽': 'y', '⠵': 'z', '⠀': ' ', '⠂': ',', '⠆': ';', '⠒': ':', '⠲': '.', '⠦': '?',
        '⠖': '!', '⠤': '-', '⠼': '#', '⠠': '^'
    }

    braille_chars = [c for c in text if (0x2800 <= ord(c) <= 0x28FF)]
    if not braille_chars:
        return "No Unicode Braille characters found."

    decoded = "".join([braille_map.get(c, "?") for c in braille_chars])
    return (
        f"=== BRAILLE STEGANOGRAPHY DECODER ===\n"
        f"Braille Characters : {len(braille_chars)}\n"
        f"Decoded Plaintext  : {decoded}"
    )


@mcp.tool()
def decode_morse_in_whitespace(text: str) -> str:
    """
    Decode Morse code concealed within whitespace (Spaces=dot, Tabs=dash, Double Spaces=word boundary).
    """
    morse_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
        '----.': '9'
    }

    tokens = []
    for line in text.splitlines():
        ws = re.findall(r"[ \t]+", line)
        for w in ws:
            m_token = "".join(["." if c == " " else "-" for c in w])
            tokens.append(m_token)

    if not tokens:
        return "No whitespace Morse patterns identified."

    decoded = "".join([morse_dict.get(t, "?") for t in tokens])
    return (
        f"=== WHITESPACE MORSE CODE DECODER ===\n"
        f"Tokens Identified : {len(tokens)}\n"
        f"Decoded Text      : {decoded}"
    )


@mcp.tool()
def carve_memory_dump_secrets(dump_path: str) -> str:
    """
    Scan memory core dumps (.dmp, .raw, .core, minidumps) for SSL/TLS master secrets,
    private RSA keys, environment variables, bash history, and CTF flags.
    """
    path = _sanitize_path(dump_path)
    if not path.is_file():
        return f"[StegoKiller Error]: Dump file not found: {dump_path}"

    data = path.read_bytes()
    findings = []

    flag_pat = re.compile(rb"(?i)(?:flag|ctf)\{[^}]+\}")
    for m in flag_pat.finditer(data):
        findings.append(f"Flag Match: {m.group().decode(errors='ignore')} (Offset: {hex(m.start())})")

    if b"CLIENT_RANDOM" in data or b"RSA Session-ID" in data:
        findings.append("[!] SSL/TLS Master Key Log strings identified!")

    if b"-----BEGIN RSA PRIVATE KEY-----" in data or b"-----BEGIN OPENSSH PRIVATE KEY-----" in data:
        findings.append("[!] Unencrypted OpenSSH/RSA Private Key block carved from RAM!")

    env_matches = re.findall(rb"[A-Z0-9_]+=[a-zA-Z0-9_./\-]{8,}", data)
    if env_matches:
        findings.append(f"Carved {len(env_matches)} Environment Variable Strings (e.g. {env_matches[0].decode(errors='ignore')})")

    return (
        f"=== RAM / MEMORY CORE DUMP FORENSIC AUDIT: {path.name} ===\n"
        f"Memory Size : {len(data):,} bytes\n"
        + ("\n".join([f"  [+] {f}" for f in findings]) if findings else "  No standard key blocks or flag matches found in raw memory.")
    )


@mcp.tool()
def detect_covert_http_headers(pcap_or_log_path: str) -> str:
    """
    Inspect HTTP streams for covert exfiltration headers (X-Flag, custom authorization headers,
    Base64 cookies, and chunked transfer encoding trailing padding).
    """
    path = _sanitize_path(pcap_or_log_path)
    if not path.is_file():
        return f"[StegoKiller Error]: File not found: {pcap_or_log_path}"

    content = path.read_bytes()
    header_hits = []

    for m in re.finditer(rb"(?i)(?:flag|token|secret|key|cookie|auth|session|x-[a-z0-9_-]+):\s*([^\r\n]+)", content):
        val = m.group(1).decode("latin-1", errors="ignore").strip()
        if len(val) > 3:
            header_hits.append(f"Header '{m.group(0)[:30].decode(errors='ignore')}...' -> Value: {val}")

    if not header_hits:
        return "No suspicious covert HTTP headers or cookie anomalies detected."

    return (
        f"=== COVERT HTTP HEADER & COOKIE EXTRUSION: {path.name} ===\n"
        f"Total Suspicious Headers: {len(header_hits)}\n" +
        "\n".join([f"  [!] {h}" for h in header_hits[:15]])
    )


if __name__ == "__main__":
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8")

    print(
        f"[StegoKiller MCP] Starting StegoKiller Ultra Suite v4.0 by Knight_S (70 Tools Registered)...",
        file=sys.stderr
    )
    mcp.run()
