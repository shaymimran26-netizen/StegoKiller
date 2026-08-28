#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 StegoKiller Ultra Suite - Dual Web UI + Remote FastMCP SSE Server
 Author: Knight_S
 Compatible with Hugging Face Spaces, Render, Railway, Smithery & Remote Clients
================================================================================
"""

import os
import sys
import json
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from server import mcp
from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
import uvicorn

def build_tool_manifest():
    """Extract standard JSON schemas for all 70 registered tools."""
    tool_list = []
    try:
        raw_tools = mcp._tool_manager.list_tools()
        for t in raw_tools:
            schema = getattr(t, "parameters", None) or getattr(t, "inputSchema", None) or {"type": "object", "properties": {}}
            tool_list.append({
                "name": t.name,
                "description": (t.description or "").strip(),
                "inputSchema": schema
            })
    except Exception as e:
        print(f"[Warning] Failed to generate full tool manifest: {e}")
    return tool_list

# Pre-generate server card payload with connection and configSchema for Smithery CLI
SERVER_CARD_PAYLOAD = {
    "serverInfo": {
        "name": "stegokiller",
        "version": "4.5.0"
    },
    "description": "StegoKiller Ultra Suite by Knight_S - Ultimate Steganography & Digital Forensics Suite (70 Specialized Tools)",
    "connection": {
        "type": "sse",
        "url": os.environ.get("STEGOKILLER_PUBLIC_URL", "https://stegokiller.onrender.com/sse")
    },
    "transport": {
        "type": "sse",
        "url": os.environ.get("STEGOKILLER_PUBLIC_URL", "https://stegokiller.onrender.com/sse")
    },
    "configSchema": {
        "type": "object",
        "properties": {},
        "required": []
    },
    "tools": build_tool_manifest()
}

async def get_server_card(request):
    """Smithery & MCP discovery server-card schema."""
    return JSONResponse(
        SERVER_CARD_PAYLOAD,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*"
        }
    )

async def health(request):
    """Health check endpoint."""
    return JSONResponse(
        {
            "status": "online",
            "service": "StegoKiller MCP Server",
            "author": "Knight_S",
            "tools": len(SERVER_CARD_PAYLOAD["tools"]),
            "connection": {
                "type": "sse",
                "url": os.environ.get("STEGOKILLER_PUBLIC_URL", "https://stegokiller.onrender.com/sse")
            },
            "endpoints": {
                "sse": "/sse",
                "messages": "/messages",
                "server_card": "/.well-known/mcp/server-card.json"
            }
        },
        headers={"Access-Control-Allow-Origin": "*"}
    )

async def index(request):
    """Landing and web documentation page."""
    docs_html = Path(__file__).parent / "docs" / "index.html"
    if docs_html.exists():
        return HTMLResponse(docs_html.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>StegoKiller MCP Server is Online</h1><p>70 Tools Available at /sse</p>")

# Initialize Starlette FastMCP SSE App
app = mcp.sse_app()

# Add CORS Middleware
allowed_origins_env = os.environ.get("STEGOKILLER_ALLOWED_ORIGINS", "*")
allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Register Discovery, Health & Web Routes
app.routes.insert(0, Route("/.well-known/mcp/server-card.json", get_server_card))
app.routes.insert(1, Route("/server-card.json", get_server_card))
app.routes.insert(2, Route("/health", health))
app.routes.insert(3, Route("/", index))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    print(f"[StegoKiller] Starting Remote FastMCP SSE Server on port {port} (70 Tools Registered)...")
    uvicorn.run(app, host="0.0.0.0", port=port)
