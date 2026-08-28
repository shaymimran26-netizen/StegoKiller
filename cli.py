#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
================================================================================
  ____  _                      _  ___ _ _             ____ _     ___ 
 / ___|| |_ ___  __ _  ___    | |/ (_) | | ___ _ __  / ___| |   |_ _|
 \___ \| __/ _ \/ _` |/ _ \   | ' /| | | |/ _ \ '__|| |   | |    | | 
  ___) | ||  __/ (_| | (_) |  | . \| | | |  __/ |   | |___| |___ | | 
 |____/ \__\___|\__, |\___/___|_|\_\_|_|_|\___|_|    \____|_____|___|
                |___/    |_____|                                      
================================================================================
 StegoKiller CLI — Standalone Steganography & Digital Forensics Suite
 Author: Knight_S • Version: 4.5.0 (70 Specialized Forensic Engines)
 Inspired by sqlmap, binwalk & steghide
================================================================================
"""

import os
import sys
import argparse
import time
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

import server
from server import (
    full_auto_solve,
    auto_triage_challenge,
    auto_decode_payload,
    inspect_file_structure,
    detect_polyglots,
    extract_metadata,
    scan_and_carve_binwalk,
    carve_foremost,
    grep_flag_patterns,
    solve_png_ihdr,
    extract_bitplanes,
    extract_lsb_payload,
    multi_tool_lsb_scan,
    analyze_png_chunks,
    png_filter_byte_analysis,
    statistical_steganalysis,
    detect_repeating_pixel_pattern,
    detect_pvd_steganography,
    analyze_color_palette_stego,
    analyze_alpha_channel,
    analyze_gif_apng_frames,
    run_zsteg_analysis,
    fft_frequency_analysis,
    detect_jpeg_ghosts,
    analyze_jpeg_quantization_tables,
    steghide_dictionary_attack,
    stegseek_rockyou_crack,
    run_steghide,
    run_jsteg,
    run_outguess,
    run_f5_stego,
    run_stegpy,
    run_cloaked_pixel,
    image_math_combine,
    reconstruct_visual_crypto_2x2,
    repair_and_read_qr,
    generate_audio_spectrogram,
    decode_dtmf_tones,
    decode_sstv,
    decode_audio_morse,
    decode_audio_fsk_afsk,
    descramble_audio_inversion,
    extract_deepsound,
    run_mp3stego,
    audio_channel_phase_diff,
    audio_lsb_extract,
    inspect_office_xml,
    inspect_ole_vba_macros,
    inspect_pdf_stego,
    inspect_pdf_layers_and_js,
    analyze_font_stego,
    recursive_archive_unpacker,
    extract_archive_metadata_covert,
    carve_memory_dump_secrets,
    inspect_git_stego,
    inspect_ai_model_stego,
    extract_pcap_covert_channels,
    detect_network_tunneling,
    detect_covert_http_headers,
    xor_bruteforce,
    decode_zero_width_chars,
    run_stegsnow,
    detect_homoglyphs,
    solve_bacon_cipher,
    decode_spammimic,
    decode_dna_steganography,
    decode_baudot_murray_code,
    decode_braille_steganography,
    decode_morse_in_whitespace,
    mcp
)

# --- ANSI COLOR CODES (sqlmap Style) ---
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

def print_banner():
    banner = rf"""{Color.CYAN}{Color.BOLD}
    ___ _                  _  ___ _ _             ____ _     ___ 
   / ___|| |_ ___  __ _  ___  | |/ (_) | | ___ _ __  / ___| |   |_ _|
   \___ \| __/ _ \/ _` |/ _ \ | ' /| | | |/ _ \ '__|| |   | |    | | 
    ___) | ||  __/ (_| | (_) || . \| | | |  __/ |   | |___| |___ | | 
   |____/ \__\___|\__, |\___/_|_|\_\_|_|_|\___|_|    \____|_____|___|
                  |___/   {Color.MAGENTA}v4.5.0 — 70 Forensic Engines{Color.CYAN}
{Color.DIM}   Automatic Steganography, Forensics & Covert-Channel Exploitation Tool
   Author: Knight_S • GitHub: https://github.com/shaymimran26-netizen/StegoKiller{Color.RESET}
"""
    print(banner)

def log_info(msg):
    print(f"{Color.CYAN}[*]{Color.RESET} {msg}")

def log_success(msg):
    print(f"{Color.GREEN}[+]{Color.BOLD} {msg}{Color.RESET}")

def log_warn(msg):
    print(f"{Color.YELLOW}[!]{Color.RESET} {msg}")

def log_error(msg):
    print(f"{Color.RED}[-]{Color.BOLD} {msg}{Color.RESET}")

def log_flag(flag_text):
    box = rf"""
{Color.GREEN}{Color.BOLD}{'='*72}
 [🏆 FLAG RECOVERED 🏆]  >>>  {flag_text}
{'='*72}{Color.RESET}"""
    print(box)

def list_all_tools():
    print_banner()
    tools = mcp._tool_manager.list_tools()
    print(f"{Color.BOLD}Available Forensic Engines ({len(tools)} Registered):{Color.RESET}\n")
    print(f"{'#':<4} {'Tool Name':<35} {'Category':<15}")
    print("-" * 72)
    for i, t in enumerate(sorted(tools, key=lambda x: x.name), 1):
        name = t.name
        cat = "General"
        if any(w in name for w in ["png", "jpg", "jpeg", "image", "bitplane", "zsteg", "pvd", "palette", "alpha", "ghost", "ihdr"]):
            cat = "Image Stego"
        elif any(w in name for w in ["audio", "sound", "wav", "mp3", "sstv", "dtmf", "morse", "fsk"]):
            cat = "Audio & Acoustic"
        elif any(w in name for w in ["pcap", "network", "tunnel", "http"]):
            cat = "Network & Covert"
        elif any(w in name for w in ["doc", "office", "vba", "pdf", "font"]):
            cat = "Documents & PDF"
        elif any(w in name for w in ["archive", "memory", "dump", "git", "ai_model", "carve", "binwalk"]):
            cat = "Forensics & Dump"
        elif any(w in name for w in ["auto", "triage", "decode", "solve"]):
            cat = "Autonomous Solvers"
        elif any(w in name for w in ["bacon", "spammimic", "zero_width", "dna", "baudot", "braille", "homoglyph", "xor", "snow"]):
            cat = "Ciphers & Text"

        color = Color.CYAN if i % 2 == 0 else Color.WHITE
        print(f"{color}{i:<4} {name:<35} {Color.MAGENTA}{cat:<15}{Color.RESET}")
    print()

def interactive_wizard():
    print_banner()
    print(f"{Color.YELLOW}{Color.BOLD}[?] STEGOKILLER INTERACTIVE WIZARD MODE{Color.RESET}\n")
    
    file_path = input(f"{Color.CYAN}[?] Enter target challenge file path: {Color.RESET}").strip()
    if not file_path:
        log_error("No file provided. Exiting.")
        return
    
    p = Path(os.path.expanduser(os.path.expandvars(file_path))).resolve()
    if not p.is_file():
        log_error(f"File not found: {file_path}")
        return
    
    print(f"\n{Color.BOLD}Target:{Color.RESET} {p} ({p.stat().st_size:,} bytes)")
    print(f"""
Select Execution Mode:
  [1] Full Auto-Solve (Autonomous Master Pipeline — Recommended)
  [2] Quick Triage (Magic bytes, Entropy, Strings, Polyglots, Binwalk)
  [3] LSB & Spatial Steganalysis (zsteg, stegpy, bitplanes, SPA, Chi-Square)
  [4] Frequency & DCT Analysis (2D FFT, JPEG DQT, Ghosts)
  [5] Audio / Acoustic Steganography (Morse, DTMF, Spectrogram, SSTV)
  [6] Password & Dictionary Attack (Steghide 30+ CTF Passwords / StegSeek)
  [7] Single/Multi-byte XOR Key Sweep (255 keys)
  [8] Memory Dump Secrets & Key Carver
""")
    choice = input(f"{Color.CYAN}[?] Choice [1-8, Default=1]: {Color.RESET}").strip() or "1"
    
    print("\n" + "="*72)
    start_t = time.time()
    
    if choice == "1":
        log_info(f"Launching Full Auto-Solve Engine on {p.name}...")
        res = full_auto_solve(str(p))
        print(res)
    elif choice == "2":
        log_info(f"Running Autonomous Master Triage...")
        print(auto_triage_challenge(str(p)))
    elif choice == "3":
        log_info(f"Running Parallel LSB & Statistical Steganalysis...")
        print(multi_tool_lsb_scan(str(p)))
        print(statistical_steganalysis(str(p)))
        print(png_filter_byte_analysis(str(p)))
    elif choice == "4":
        log_info(f"Running 2D FFT Frequency Analysis...")
        print(fft_frequency_analysis(str(p)))
    elif choice == "5":
        log_info(f"Running Audio Forensic Suite...")
        print(decode_audio_morse(str(p)))
        print(decode_dtmf_tones(str(p)))
        print(generate_audio_spectrogram(str(p)))
    elif choice == "6":
        log_info(f"Launching Steghide Dictionary Attack...")
        print(steghide_dictionary_attack(str(p)))
    elif choice == "7":
        log_info(f"Brute-forcing 255 XOR keys...")
        print(xor_bruteforce(str(p)))
    elif choice == "8":
        log_info(f"Carving RAM memory dump...")
        print(carve_memory_dump_secrets(str(p)))
    else:
        log_error("Invalid selection.")
        return
        
    elapsed = time.time() - start_t
    print(f"\n{Color.DIM}[*] Execution completed in {elapsed:.2f} seconds.{Color.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="StegoKiller CLI — The Ultimate Steganography & Digital Forensics Suite by Knight_S",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  stegokiller challenge.png                     (Full Auto-Solve)
  stegokiller -f challenge.png --auto           (Full Auto-Solve)
  stegokiller -f image.png --ihdr               (Restore cropped PNG dimensions)
  stegokiller -f audio.wav --morse              (Acoustic CW Morse decoder)
  stegokiller -f cipher.bin --xor               (255-key XOR brute force)
  stegokiller -f suspect.jpg --steghide         (Steghide dictionary attack)
  stegokiller -d "ZmxhZ3tjdGZ9" --decode        (CyberChef heuristic decode)
  stegokiller --wizard                          (Interactive sqlmap-style wizard)
  stegokiller --list-tools                      (List all 70 forensic tools)
  stegokiller --serve --port 8000               (Run FastMCP SSE Web server)
  stegokiller --mcp                             (Run MCP stdio server)
"""
    )

    parser.add_argument("target", nargs="?", help="Target challenge file path (Runs Full Auto-Solve by default)")
    parser.add_argument("-f", "--file", dest="file_path", help="Target input file path")
    parser.add_argument("-a", "--auto", action="store_true", help="Execute 16-Stage Full Autonomous Solver")
    parser.add_argument("-t", "--triage", action="store_true", help="Run 5-Stage Autonomous Master Triage")
    parser.add_argument("-w", "--wizard", action="store_true", help="Launch interactive step-by-step wizard")
    
    # Image Tools
    img_group = parser.add_argument_group("Image Steganography")
    img_group.add_argument("--ihdr", action="store_true", help="Brute-force PNG dimensions against CRC32")
    img_group.add_argument("--lsb", action="store_true", help="Run multithreaded multi-tool LSB scan")
    img_group.add_argument("--bitplanes", action="store_true", help="Extract all 32 RGBA bitplanes")
    img_group.add_argument("--fft", action="store_true", help="Perform 2D FFT Frequency Analysis")
    img_group.add_argument("--pattern", action="store_true", help="Detect repeating pixel tile pattern")
    img_group.add_argument("--alpha", action="store_true", help="Deep alpha channel forensics")
    img_group.add_argument("--filter-bytes", action="store_true", help="Extract PNG scanline filter byte stego")
    img_group.add_argument("--pvd", action="store_true", help="Pixel Value Differencing analysis")
    img_group.add_argument("--zsteg", action="store_true", help="Run zsteg exhaustive analysis")
    img_group.add_argument("--steghide", action="store_true", help="Run Steghide dictionary attack (30+ CTF passwords)")
    img_group.add_argument("--stegseek", action="store_true", help="Ultra-fast StegSeek rockyou.txt cracker")
    img_group.add_argument("--ghosts", action="store_true", help="Detect JPEG double compression ghosts")

    # Audio Tools
    aud_group = parser.add_argument_group("Audio & Acoustic Steganography")
    aud_group.add_argument("--spectrogram", action="store_true", help="Generate log/linear spectrogram image")
    aud_group.add_argument("--morse", action="store_true", help="Decode acoustic CW Morse code tones")
    aud_group.add_argument("--dtmf", action="store_true", help="Decode DTMF dial keypad tones")
    aud_group.add_argument("--sstv", action="store_true", help="Decode SSTV audio transmission to image")
    aud_group.add_argument("--fsk", action="store_true", help="Demodulate Bell 103 / AFSK telemetry audio")
    aud_group.add_argument("--phase-diff", action="store_true", help="Stereo phase subtraction (L - R)")

    # Forensics & Carving
    for_group = parser.add_argument_group("Digital Forensics & Memory Carving")
    for_group.add_argument("--memdump", action="store_true", help="Carve SSL keys, RSA keys, and flags from RAM dump")
    for_group.add_argument("--pcap", action="store_true", help="Extract PCAP ICMP/DNS/TCP covert channels")
    for_group.add_argument("--binwalk", action="store_true", help="Scan & carve embedded signatures via Binwalk")
    for_group.add_argument("--foremost", action="store_true", help="Carve raw file headers/footers via Foremost")
    for_group.add_argument("--polyglot", action="store_true", help="Multi-format polyglot dual signature check")
    for_group.add_argument("--unpack-archive", action="store_true", help="Recursively unpack nested archives (ZIP/TAR/7z)")

    # Ciphers & CyberChef
    ciph_group = parser.add_argument_group("Ciphers & Automated Decoding")
    ciph_group.add_argument("--xor", action="store_true", help="Brute-force 255 single-byte XOR keys")
    ciph_group.add_argument("-d", "--data", dest="raw_data", help="Raw text/hex/base64 data to decode")
    ciph_group.add_argument("--decode", action="store_true", help="Run automated CyberChef master transform pipeline")
    ciph_group.add_argument("--bacon", action="store_true", help="Solve Bacon's cipher (24/26 letter)")
    ciph_group.add_argument("--zero-width", action="store_true", help="Decode zero-width Unicode characters")
    ciph_group.add_argument("--dna", action="store_true", help="Decode DNA nucleotide sequences (A, C, G, T)")
    ciph_group.add_argument("--baudot", action="store_true", help="Decode 5-bit Baudot/ITA2 teleprinter code")
    ciph_group.add_argument("--braille", action="store_true", help="Decode Unicode Braille patterns")

    # Server Modes
    srv_group = parser.add_argument_group("Server & MCP Modes")
    srv_group.add_argument("--mcp", action="store_true", help="Start Model Context Protocol (MCP) Stdio Server")
    srv_group.add_argument("--serve", action="store_true", help="Start FastMCP SSE Remote Web Server")
    srv_group.add_argument("--port", type=int, default=7860, help="Port for SSE Server (Default: 7860)")
    srv_group.add_argument("--list-tools", action="store_true", help="List all 70 registered forensic tools")

    args = parser.parse_args()

    # 1. Wizard Mode
    if args.wizard:
        interactive_wizard()
        return

    # 2. List Tools
    if args.list_tools:
        list_all_tools()
        return

    # 3. Server Modes
    if args.mcp:
        print_banner()
        log_info("Starting StegoKiller MCP Stdio Server (70 Tools Registered)...")
        mcp.run()
        return

    if args.serve:
        print_banner()
        log_info(f"Starting FastMCP SSE Server on port {args.port}...")
        import app
        import uvicorn
        uvicorn.run(app.app, host="0.0.0.0", port=args.port)
        return

    # 4. Direct Data Decoding
    if args.raw_data or (args.decode and args.raw_data):
        print_banner()
        log_info(f"Decoding payload: {args.raw_data[:60]}...")
        print(auto_decode_payload(args.raw_data))
        return

    target = args.file_path or args.target

    if not target:
        print_banner()
        parser.print_help()
        sys.exit(0)

    target_path = Path(os.path.expanduser(os.path.expandvars(target))).resolve()
    if not target_path.is_file() and not target_path.is_dir():
        log_error(f"Target file or directory not found: {target}")
        sys.exit(1)

    print_banner()
    log_info(f"Target: {Color.BOLD}{target_path}{Color.RESET} ({target_path.stat().st_size:,} bytes)")

    # Execute Selected Operation
    start_time = time.time()

    if args.ihdr:
        log_info("Executing PNG IHDR CRC32 recovery...")
        print(solve_png_ihdr(str(target_path)))
    elif args.lsb:
        log_info("Executing multithreaded LSB scan...")
        print(multi_tool_lsb_scan(str(target_path)))
    elif args.bitplanes:
        log_info("Extracting all 32 RGBA bitplanes...")
        print(extract_bitplanes(str(target_path)))
    elif args.fft:
        log_info("Executing 2D FFT Frequency Analysis...")
        print(fft_frequency_analysis(str(target_path)))
    elif args.pattern:
        log_info("Detecting repeating pixel tile patterns...")
        print(detect_repeating_pixel_pattern(str(target_path)))
    elif args.alpha:
        log_info("Analyzing Alpha transparency channel...")
        print(analyze_alpha_channel(str(target_path)))
    elif args.filter_bytes:
        log_info("Extracting PNG scanline filter byte stego...")
        print(png_filter_byte_analysis(str(target_path)))
    elif args.pvd:
        log_info("Running Pixel Value Differencing analysis...")
        print(detect_pvd_steganography(str(target_path)))
    elif args.zsteg:
        log_info("Running zsteg exhaustive scan...")
        print(run_zsteg_analysis(str(target_path)))
    elif args.steghide:
        log_info("Running Steghide dictionary attack (30+ common CTF passwords)...")
        print(steghide_dictionary_attack(str(target_path)))
    elif args.stegseek:
        log_info("Running StegSeek rockyou.txt cracker...")
        print(stegseek_rockyou_crack(str(target_path)))
    elif args.ghosts:
        log_info("Detecting JPEG double compression ghosts...")
        print(detect_jpeg_ghosts(str(target_path)))
    elif args.spectrogram:
        log_info("Generating audio spectrogram...")
        print(generate_audio_spectrogram(str(target_path)))
    elif args.morse:
        log_info("Decoding acoustic CW Morse code...")
        print(decode_audio_morse(str(target_path)))
    elif args.dtmf:
        log_info("Decoding DTMF dial tones...")
        print(decode_dtmf_tones(str(target_path)))
    elif args.sstv:
        log_info("Decoding SSTV audio transmission to image...")
        print(decode_sstv(str(target_path)))
    elif args.fsk:
        log_info("Demodulating FSK/AFSK telemetry audio...")
        print(decode_audio_fsk_afsk(str(target_path)))
    elif args.phase_diff:
        log_info("Executing stereo phase subtraction...")
        print(audio_channel_phase_diff(str(target_path)))
    elif args.memdump:
        log_info("Carving secrets & SSL master keys from RAM dump...")
        print(carve_memory_dump_secrets(str(target_path)))
    elif args.pcap:
        log_info("Extracting covert channels from PCAP...")
        print(extract_pcap_covert_channels(str(target_path)))
    elif args.binwalk:
        log_info("Executing Binwalk signature scan & carve...")
        print(scan_and_carve_binwalk(str(target_path), extract=True))
    elif args.foremost:
        log_info("Carving raw file headers/footers via Foremost...")
        print(carve_foremost(str(target_path)))
    elif args.polyglot:
        log_info("Checking for multi-format polyglot signatures...")
        print(detect_polyglots(str(target_path)))
    elif args.unpack_archive:
        log_info("Recursively unpacking nested archives...")
        print(recursive_archive_unpacker(str(target_path)))
    elif args.xor:
        log_info("Brute-forcing 255 single-byte XOR keys...")
        print(xor_bruteforce(str(target_path)))
    elif args.triage:
        log_info("Running 5-Stage Autonomous Master Triage...")
        print(auto_triage_challenge(str(target_path)))
    else:
        # Default: Full Auto-Solve
        log_info(f"Running {Color.BOLD}16-Stage Full Autonomous Solver{Color.RESET}...")
        print(full_auto_solve(str(target_path)))

    elapsed = time.time() - start_time
    print(f"\n{Color.DIM}[*] Finished in {elapsed:.2f}s.{Color.RESET}")

if __name__ == "__main__":
    main()
