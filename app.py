#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 StegoKiller Ultra Suite - Dual Gradio Web UI + Remote MCP SSE Server
 Author: Knight_S
 Compatible with Hugging Face Spaces (Free Gradio SDK) & Smithery Remote URL
================================================================================
"""

import os
import sys
import tempfile
from pathlib import Path
import gradio as gr
from fastapi import FastAPI
import uvicorn

# Import StegoKiller server tools
from server import (
    mcp,
    auto_triage_challenge,
    inspect_file_structure,
    extract_metadata,
    grep_flag_patterns,
    detect_polyglots,
    scan_and_carve_binwalk,
    statistical_steganalysis,
    solve_png_ihdr,
    extract_bitplanes,
    generate_audio_spectrogram,
    decode_dtmf_tones,
    decode_audio_morse,
    decode_zero_width_chars,
    detect_homoglyphs,
    solve_bacon_cipher,
    auto_decode_payload,
    run_zsteg_analysis
)

# 1. Gradio Web Interface Functions
def run_triage(file_obj):
    if file_obj is None:
        return "Please upload a file to analyze."
    return auto_triage_challenge(file_obj.name)

def run_spectrogram(file_obj, cmap):
    if file_obj is None:
        return "Please upload an audio file (WAV/MP3).", None
    out_dir = Path("/tmp/stego_mcp_output/spectrograms")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_img = out_dir / f"web_spec_{Path(file_obj.name).stem}.png"
    res = generate_audio_spectrogram(file_obj.name, output_img_path=str(out_img), cmap=cmap)
    return res, str(out_img) if out_img.exists() else None

def run_ihdr(file_obj):
    if file_obj is None:
        return "Please upload a PNG file."
    return solve_png_ihdr(file_obj.name)

def run_steganalysis(file_obj):
    if file_obj is None:
        return "Please upload an image."
    return statistical_steganalysis(file_obj.name)

def run_text_tools(text_input, mode):
    if not text_input.strip():
        return "Please enter text or string payload."
    if mode == "Auto Decode (CyberChef)":
        return auto_decode_payload(text_input)
    elif mode == "Zero-Width Unicode":
        return decode_zero_width_chars(text_input)
    elif mode == "Homoglyph Detector":
        return detect_homoglyphs(text_input)
    elif mode == "Bacon Cipher":
        return solve_bacon_cipher(text_input)
    return "Unknown mode selected."

# 2. Build Gradio UI
custom_css = """
body { background-color: #090d16; color: #f8fafc; font-family: 'Inter', sans-serif; }
.gradio-container { max-width: 1200px !important; margin: auto; }
h1, h2, h3 { color: #38bdf8 !important; }
"""

with gr.Blocks(title="StegoKiller Ultra Suite - Web & MCP Server", css=custom_css, theme=gr.themes.Soft(primary_hue="cyan")) as demo:
    gr.Markdown(
        """
        # ⚡ StegoKiller Ultra Suite v3.0 (Web & Remote MCP)
        **Author:** `Knight_S` | **Framework:** FastMCP + Gradio | **44 Specialized Tools**  
        *This Hugging Face Space functions simultaneously as an interactive CTF Steganography Web App AND a Remote MCP Server (`/sse`).*
        """
    )

    with gr.Tabs():
        # Tab 1: Autonomous Triage
        with gr.TabItem("🔍 Autonomous Triage Pipeline"):
            gr.Markdown("### Upload any file for deep 5-stage automated steganography & integrity analysis")
            with gr.Row():
                triage_file = gr.File(label="Upload Challenge File (Image/Audio/Doc/PCAP/Binary)")
                triage_btn = gr.Button("⚡ Run Master Triage", variant="primary")
            triage_out = gr.Textbox(label="Autonomous Analysis Report", lines=18, max_lines=30)
            triage_btn.click(run_triage, inputs=[triage_file], outputs=[triage_out])

        # Tab 2: Audio Steganography
        with gr.TabItem("🎵 Audio & Acoustic Forensics"):
            gr.Markdown("### Spectrogram Visualizer, Morse Code & DTMF Tones")
            with gr.Row():
                with gr.Column():
                    audio_file = gr.File(label="Upload Audio File (WAV/MP3/FLAC)")
                    cmap_choice = gr.Dropdown(["inferno", "magma", "viridis", "plasma", "cividis"], value="inferno", label="Color Map")
                    spec_btn = gr.Button("Generate Spectrogram", variant="primary")
                with gr.Column():
                    spec_img = gr.Image(label="Rendered Spectrogram", type="filepath")
                    spec_log = gr.Textbox(label="Spectrogram Details", lines=3)
            spec_btn.click(run_spectrogram, inputs=[audio_file, cmap_choice], outputs=[spec_log, spec_img])

        # Tab 3: Image Steganalysis & Repair
        with gr.TabItem("🖼️ Image Steganalysis & PNG Repair"):
            gr.Markdown("### Statistical Chi-Square Steganalysis & PNG IHDR Restoration")
            with gr.Row():
                img_file = gr.File(label="Upload Image (PNG/JPG/BMP)")
                with gr.Column():
                    steg_btn = gr.Button("📊 Run Statistical Steganalysis (Chi²/SPA)", variant="primary")
                    ihdr_btn = gr.Button("🛠️ Fix Corrupt PNG IHDR Dimensions", variant="secondary")
            img_out = gr.Textbox(label="Analysis & Restoration Report", lines=12)
            steg_btn.click(run_steganalysis, inputs=[img_file], outputs=[img_out])
            ihdr_btn.click(run_ihdr, inputs=[img_file], outputs=[img_out])

        # Tab 4: Text, Ciphers & CyberChef
        with gr.TabItem("🔤 Text, Unicode & Ciphers"):
            gr.Markdown("### Zero-Width Characters, Homoglyphs, Bacon Cipher & Multi-Decoder")
            with gr.Row():
                text_in = gr.Textbox(label="Enter Raw Text or Extracted Payload", lines=5, placeholder="Paste suspicious string or ciphertext here...")
                tool_choice = gr.Radio(["Auto Decode (CyberChef)", "Zero-Width Unicode", "Homoglyph Detector", "Bacon Cipher"], value="Auto Decode (CyberChef)", label="Select Decoder")
            decode_btn = gr.Button("🔓 Decode Payload", variant="primary")
            text_out = gr.Textbox(label="Decoded Results", lines=10)
            decode_btn.click(run_text_tools, inputs=[text_in, tool_choice], outputs=[text_out])

        # Tab 5: Remote MCP Connection
        with gr.TabItem("☁️ Remote MCP Server Info"):
            gr.Markdown(
                """
                ### Connect this Hugging Face Space to Claude Desktop or Smithery
                
                **1. Remote MCP SSE URL:**  
                `https://YOUR_SPACE_NAME.hf.space/sse`
                
                **2. Claude Desktop Remote Config:**
                ```json
                {
                  "mcpServers": {
                    "stegokiller_remote": {
                      "url": "https://YOUR_SPACE_NAME.hf.space/sse"
                    }
                  }
                }
                ```
                """
            )

# 3. Mount Gradio + FastMCP SSE App together on FastAPI
app = FastAPI(title="StegoKiller MCP & Web App")

# Mount MCP Starlette SSE app at /
mcp_app = mcp.sse_app()
app.mount("/sse", mcp_app)

# Mount Gradio app
app = gr.mount_gradio_app(app, demo, path="/")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    print(f"[StegoKiller] Starting Dual Gradio Web UI + Remote MCP SSE on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port)
