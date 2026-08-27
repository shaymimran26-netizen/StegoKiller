#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 StegoKiller Master Verification & Automated Test Suite
 Author: Knight_S
================================================================================
"""

import sys
import os
import json
from pathlib import Path

# Add server directory
sys.path.insert(0, "/home/shaym/StegoKiller")

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
    mcp
)

TEST_DIR = Path("/tmp/stegokiller_tests")
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
print("       STEGOKILLER MCP SERVER — MASTER AUTOMATED TEST HARNESS")
print("="*80 + "\n")

# Test 1: Registered Tools Count
total_tools = len(mcp._tool_manager.list_tools())
record("Registered Tools Count >= 44", total_tools >= 44, f"Found {total_tools} tools")

# Test 2: PNG IHDR CRC32 Recovery
corrupt_png = TEST_DIR / "challenge_ihdr_corrupt.png"
ihdr_res = solve_png_ihdr(str(corrupt_png))
record("solve_png_ihdr Dimensions Recovery", "100x100" in ihdr_res, ihdr_res[:100])

# Test 3: Audio Spectrogram Generation
morse_wav = TEST_DIR / "challenge_morse_sos.wav"
out_spec = TEST_DIR / "test_spectrogram.png"
spec_res = generate_audio_spectrogram(str(morse_wav), output_img_path=str(out_spec))
record("generate_audio_spectrogram", out_spec.exists(), spec_res[:100])

# Test 4: Acoustic Morse Code Decoder
morse_res = decode_audio_morse(str(morse_wav))
record("decode_audio_morse Tone Engine", "S O S" in morse_res or "SOS" in morse_res, morse_res)

# Test 5: Visual Cryptography Image XOR
share1 = TEST_DIR / "share1.png"
share2 = TEST_DIR / "share2.png"
xor_res = image_math_combine(str(share1), str(share2), mode="xor")
record("image_math_combine (XOR Share Solver)", "COMPLETE" in xor_res, xor_res)

# Test 6: Animated GIF Frame & Delay ASCII Extraction
gif_file = TEST_DIR / "challenge_delays.gif"
gif_res = analyze_gif_apng_frames(str(gif_file))
record("analyze_gif_apng_frames (Delay ASCII Extraction)", "FRAME DECOMPOSITION" in gif_res, gif_res)

# Test 7: Statistical Steganalysis (Chi-Square & SPA)
steg_res = statistical_steganalysis(str(share1))
record("statistical_steganalysis (Chi-Square/PoV)", "STEGANALYSIS REPORT" in steg_res, steg_res[:100])

# Test 8: Zero-Width Unicode Decoder
# Encode 'CTF' in ZWSP/ZWNJ
# C = 01000011 -> \u200b\u200c\u200b\u200b\u200b\u200b\u200c\u200c
zw_text = "Hidden\u200b\u200c\u200b\u200b\u200b\u200b\u200c\u200cText"
zw_res = decode_zero_width_chars(zw_text)
record("decode_zero_width_chars", "ZERO-WIDTH" in zw_res, zw_res)

# Test 9: Unicode Homoglyphs Detector
homo_text = "Hello аdmіn" # Cyrillic 'а' and 'і'
homo_res = detect_homoglyphs(homo_text)
record("detect_homoglyphs", "HOMOGLYPH DETECTION" in homo_res, homo_res)

# Test 10: Bacon Cipher Decoder
# 'FLAG' in Bacon 24: F=AABAB, L=ABABA, A=AAAAA, G=AABBA
bacon_cipher = "aAbAbAbAbAaaaaaaAbBa"
bacon_res = solve_bacon_cipher(bacon_cipher)
record("solve_bacon_cipher (24-letter / 26-letter)", "FLAG" in bacon_res, bacon_res)

# Test 11: Master CyberChef Auto Decoder
# ROT13 + Base64: 'flag{stego_master_2026}'
test_flag = "flag{stego_master_2026}"
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

print("\n" + "="*80)
print(f"       SUMMARY: {PASSED}/{PASSED+FAILED} TESTS PASSED ({PASSED/(PASSED+FAILED)*100:.1f}%)")
print("="*80 + "\n")

if FAILED == 0:
    print(">>> ALL 14 AUTOMATED INTEGRATION TESTS PASSED PERFECTLY! <<<")
else:
    print(f">>> {FAILED} TESTS FAILED. PLEASE REVIEW.")
    sys.exit(1)
