#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 StegoKiller Master Verification & Automated Test Suite (v4.0.0 - 70 Tools)
 Author: Knight_S
================================================================================
"""

import sys
import os
import json
import struct
import zlib
import numpy as np
from PIL import Image
from scipy.io import wavfile
from pathlib import Path

# Add server directory
sys.path.insert(0, str(Path(__file__).resolve().parent))

from server import (
    solve_png_ihdr,
    generate_audio_spectrogram,
    decode_audio_morse,
    decode_zero_width_chars,
    detect_homoglyphs,
    solve_bacon_cipher,
    image_math_combine,
    analyze_gif_apng_frames,
    statistical_steganalysis,
    analyze_png_chunks,
    auto_decode_payload,
    detect_polyglots,
    inspect_file_structure,
    grep_flag_patterns,
    auto_triage_challenge,
    detect_pvd_steganography,
    analyze_color_palette_stego,
    detect_jpeg_ghosts,
    reconstruct_visual_crypto_2x2,
    decode_dna_steganography,
    decode_baudot_murray_code,
    decode_braille_steganography,
    decode_morse_in_whitespace,
    carve_memory_dump_secrets,
    detect_covert_http_headers,
    xor_bruteforce,
    detect_repeating_pixel_pattern,
    fft_frequency_analysis,
    extract_lsb_payload,
    png_filter_byte_analysis,
    steghide_dictionary_attack,
    analyze_alpha_channel,
    full_auto_solve,
    mcp
)

TEST_DIR = Path("/tmp/stegokiller_tests")
TEST_DIR.mkdir(parents=True, exist_ok=True)

PASSED = 0
FAILED = 0
TESTS = []

def record(name, status, details=""):
    global PASSED, FAILED
    if status:
        PASSED += 1
        print(f"  [✓ PASS] {name}")
    else:
        FAILED += 1
        print(f"  [✗ FAIL] {name} -> {details}")
    TESTS.append({"test": name, "passed": status, "details": details})

print("\n" + "="*80)
print("       STEGOKILLER MCP SERVER — MASTER 70-TOOL AUTOMATED TEST HARNESS")
print("="*80 + "\n")

# Setup synthetic files
# 1. Corrupt PNG
w_real, h_real = 100, 100
arr = np.zeros((h_real, w_real, 3), dtype=np.uint8)
arr[:50, :, 0] = 255
img = Image.fromarray(arr)
tmp_png = TEST_DIR / "temp_valid.png"
img.save(tmp_png)
raw_png = bytearray(tmp_png.read_bytes())
raw_png[20:24] = struct.pack(">I", 30)
corrupt_png = TEST_DIR / "challenge_ihdr_corrupt.png"
corrupt_png.write_bytes(raw_png)

# 2. Synthetic Morse WAV
sr = 44100
def make_tone(freq, duration):
    t = np.linspace(0, duration, int(sr * duration), False)
    return (np.sin(2 * np.pi * freq * t) * 32767 * 0.7).astype(np.int16)

def make_silence(duration):
    return np.zeros(int(sr * duration), dtype=np.int16)

dot = make_tone(800, 0.1)
dash = make_tone(800, 0.3)
sym_p = make_silence(0.1)
char_p = make_silence(0.3)

morse_sos = np.concatenate([
    dot, sym_p, dot, sym_p, dot, char_p,
    dash, sym_p, dash, sym_p, dash, char_p,
    dot, sym_p, dot, sym_p, dot
])
morse_wav = TEST_DIR / "challenge_morse_sos.wav"
wavfile.write(morse_wav, sr, morse_sos)

# 3. Shares
share1_arr = np.random.randint(0, 256, (60, 60, 4), dtype=np.uint8)
secret_arr = np.zeros((60, 60, 4), dtype=np.uint8)
secret_arr[10:50, 10:50] = [0, 255, 0, 255]
share2_arr = np.bitwise_xor(share1_arr, secret_arr)
share1 = TEST_DIR / "share1.png"
share2 = TEST_DIR / "share2.png"
Image.fromarray(share1_arr).save(share1)
Image.fromarray(share2_arr).save(share2)

# 4. Animated GIF
frames = [Image.fromarray(np.full((30, 30, 3), c * 50, dtype=np.uint8)) for c in range(4)]
gif_file = TEST_DIR / "challenge_delays.gif"
frames[0].save(gif_file, save_all=True, append_images=frames[1:], duration=[70, 70, 70, 70], loop=0)

# 5. XOR Brute-Force test file
xor_plain = b"This is a secret message containing flag{xor_automation_success_2026}!"
xor_key = 0x5A
xor_cipher = bytes([b ^ xor_key for b in xor_plain])
xor_file = TEST_DIR / "xor_test.bin"
xor_file.write_bytes(xor_cipher)

# 6. Repeating pattern image
tile = np.array([[128, 64, 32, 255], [200, 100, 50, 255]], dtype=np.uint8)
tiled_arr = np.tile(tile, (40, 20, 1))
tiled_img_file = TEST_DIR / "repeating_tile.png"
Image.fromarray(tiled_arr).save(tiled_img_file)

# 7. Alpha channel test image
alpha_arr = np.full((50, 50, 4), 200, dtype=np.uint8)
alpha_arr[:, :, 3] = 250
alpha_arr[:10, :10, 3] = 251
alpha_img_file = TEST_DIR / "alpha_test.png"
Image.fromarray(alpha_arr).save(alpha_img_file)

# --- EXECUTE TEST CASES ---

# Test 1: Registered Tools Count
total_tools = len(mcp._tool_manager.list_tools())
record("Registered Tools Count >= 70", total_tools >= 70, f"Found {total_tools} tools")

# Test 2: PNG IHDR CRC32 Recovery
ihdr_res = solve_png_ihdr(str(corrupt_png))
record("solve_png_ihdr Dimensions Recovery", "100x100" in ihdr_res, ihdr_res[:100])

# Test 3: Audio Spectrogram Generation
out_spec = TEST_DIR / "test_spectrogram.png"
spec_res = generate_audio_spectrogram(str(morse_wav), output_img_path=str(out_spec))
record("generate_audio_spectrogram", out_spec.exists(), spec_res[:100])

# Test 4: Acoustic Morse Code Decoder
morse_res = decode_audio_morse(str(morse_wav))
record("decode_audio_morse Tone Engine", "S O S" in morse_res or "SOS" in morse_res, morse_res)

# Test 5: Visual Cryptography Image XOR
xor_res = image_math_combine(str(share1), str(share2), mode="xor")
record("image_math_combine (XOR Share Solver)", "COMPLETE" in xor_res, xor_res)

# Test 6: Animated GIF Frame Decomposition
gif_res = analyze_gif_apng_frames(str(gif_file))
record("analyze_gif_apng_frames", "FRAME DECOMPOSITION" in gif_res, gif_res)

# Test 7: Statistical Steganalysis (Chi-Square & SPA)
steg_res = statistical_steganalysis(str(share1))
record("statistical_steganalysis (Chi-Square/PoV)", "STEGANALYSIS REPORT" in steg_res, steg_res[:100])

# Test 8: Zero-Width Unicode Decoder
zw_text = "Hidden\u200b\u200c\u200b\u200b\u200b\u200b\u200c\u200cText"
zw_res = decode_zero_width_chars(zw_text)
record("decode_zero_width_chars", "ZERO-WIDTH" in zw_res, zw_res)

# Test 9: Unicode Homoglyphs Detector
homo_text = "Hello аdmіn"
homo_res = detect_homoglyphs(homo_text)
record("detect_homoglyphs", "HOMOGLYPH DETECTION" in homo_res, homo_res)

# Test 10: Bacon Cipher Decoder
bacon_cipher = "aAbAbAbAbAaaaaaaAbBa"
bacon_res = solve_bacon_cipher(bacon_cipher)
record("solve_bacon_cipher (24-letter / 26-letter)", "FLAG" in bacon_res, bacon_res)

# Test 11: Master CyberChef Auto Decoder
b64_payload = "ZmxhZ3tzdGVnb19tYXN0ZXJfMjAyNn0="
cyber_res = auto_decode_payload(b64_payload)
record("auto_decode_payload (CyberChef Master Pipeline)", "FLAG FOUND" in cyber_res, cyber_res)

# Test 12: File Structure & Overlay Carving
struct_res = inspect_file_structure(str(corrupt_png))
record("inspect_file_structure", "FILE STRUCTURE" in struct_res, struct_res[:100])

# Test 13: Polyglot Dual-Signature Detector
poly_res = detect_polyglots(str(corrupt_png))
record("detect_polyglots", "POLYGLOT" in poly_res, poly_res)

# Test 14: Autonomous Master Triage Pipeline
triage_res = auto_triage_challenge(str(corrupt_png))
record("auto_triage_challenge (5-Stage Master)", "AUTONOMOUS MASTER TRIAGE" in triage_res, triage_res[:100])

# Test 15: Pixel Value Differencing (PVD)
pvd_res = detect_pvd_steganography(str(share1))
record("detect_pvd_steganography", "PIXEL VALUE DIFFERENCING" in pvd_res, pvd_res[:100])

# Test 16: JPEG Ghost & Double Compression
jpg_test = TEST_DIR / "test_ghost.jpg"
Image.fromarray(arr).save(jpg_test, "JPEG", quality=85)
ghost_res = detect_jpeg_ghosts(str(jpg_test))
record("detect_jpeg_ghosts", "JPEG GHOST" in ghost_res, ghost_res[:100])

# Test 17: DNA Nucleotide & Genetic Stego Decoder
dna_seq = "CACGCATACAACCACT"
dna_res = decode_dna_steganography(dna_seq)
record("decode_dna_steganography", "FLAG" in dna_res, dna_res)

# Test 18: Baudot / Murray ITA2 Teleprinter Decoder
baudot_bits = "000010001110000"
baudot_res = decode_baudot_murray_code(baudot_bits)
record("decode_baudot_murray_code", "EAT" in baudot_res, baudot_res)

# Test 19: Unicode Braille Steganography Decoder
braille_str = "⠉⠞⠋"
braille_res = decode_braille_steganography(braille_str)
record("decode_braille_steganography", "ctf" in braille_res, braille_res)

# Test 20: Memory Dump Secrets & Key Carver
mem_dump = TEST_DIR / "ram_test.dmp"
mem_dump.write_bytes(b"\x00\xFF" * 100 + b"flag{ram_forensics_pwn_2026}" + b"\x11" * 50 + b"CLIENT_RANDOM 12345678")
mem_res = carve_memory_dump_secrets(str(mem_dump))
record("carve_memory_dump_secrets", "flag{ram_forensics_pwn_2026}" in mem_res, mem_res)

# Test 21: Covert HTTP Headers & Cookie Detector
http_log = TEST_DIR / "http_stream.log"
http_log.write_bytes(b"GET /index.html HTTP/1.1\r\nHost: ctf.local\r\nX-Flag-Secret: flag{http_covert_header}\r\n\r\n")
http_res = detect_covert_http_headers(str(http_log))
record("detect_covert_http_headers", "flag{http_covert_header}" in http_res, http_res)

# Test 22: XOR Brute Force Engine
xor_b_res = xor_bruteforce(str(xor_file))
record("xor_bruteforce (255-key sweep)", "flag{xor_automation_success_2026}" in xor_b_res, xor_b_res)

# Test 23: Repeating Pixel Pattern Detector
pattern_res = detect_repeating_pixel_pattern(str(tiled_img_file))
record("detect_repeating_pixel_pattern", "REPEATING TILE DETECTED" in pattern_res, pattern_res)

# Test 24: 2D FFT Frequency Analysis
fft_res = fft_frequency_analysis(str(tiled_img_file))
record("fft_frequency_analysis", "2D FFT FREQUENCY ANALYSIS" in fft_res, fft_res)

# Test 25: Direct LSB Payload Extraction
lsb_ext_res = extract_lsb_payload(str(tiled_img_file), channels="rgb", bits=1)
record("extract_lsb_payload", "LSB PAYLOAD EXTRACTION" in lsb_ext_res, lsb_ext_res)

# Test 26: PNG Scanline Filter Byte Analysis
filter_res = png_filter_byte_analysis(str(tmp_png))
record("png_filter_byte_analysis", "PNG FILTER BYTE ANALYSIS" in filter_res, filter_res)

# Test 27: Steghide Dictionary Attack
dict_res = steghide_dictionary_attack(str(tmp_png))
record("steghide_dictionary_attack", "STEGHIDE DICTIONARY ATTACK" in dict_res, dict_res)

# Test 28: Deep Alpha Channel Forensics
alpha_res = analyze_alpha_channel(str(alpha_img_file))
record("analyze_alpha_channel", "ALPHA CHANNEL ANALYSIS" in alpha_res, alpha_res)

# Test 29: Full Autonomous Challenge Solver
auto_res = full_auto_solve(str(corrupt_png))
record("full_auto_solve Master Pipeline", "FULL AUTO-SOLVE REPORT" in auto_res, auto_res[:100])

print("\n" + "="*80)
print(f"       SUMMARY: {PASSED}/{PASSED+FAILED} TESTS PASSED ({PASSED/(PASSED+FAILED)*100:.1f}%)")
print("="*80 + "\n")

if FAILED == 0:
    print(">>> ALL 29 MASTER INTEGRATION TESTS PASSED WITH 100% SUCCESS! <<<")
else:
    print(f">>> {FAILED} TESTS FAILED. PLEASE REVIEW.")
    sys.exit(1)
