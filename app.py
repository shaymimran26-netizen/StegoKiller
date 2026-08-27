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
from starlette.routing import Route, Mount
import uvicorn

async def get_server_card(request):
    """Smithery & MCP discovery server-card schema containing all 44 tools."""
    tools = await mcp.list_tools()
    tool_list = []
    for t in tools:
        tool_list.append({
            "name": t.name,
            "description": t.description,
            "inputSchema": t.inputSchema
        })
    return JSONResponse({
        "serverInfo": {
            "name": "stegokiller",
            "version": "3.0.0"
        },
        "description": "StegoKiller Ultra Suite by Knight_S - Ultimate Steganography & Digital Forensics Suite (44+ Tools)",
        "tools": tool_list
    })

async def health(request):
    """Health check endpoint."""
    return JSONResponse({
        "status": "online",
        "service": "StegoKiller MCP Server",
        "author": "Knight_S",
        "tools": 44,
        "endpoints": {
            "sse": "/sse",
            "messages": "/messages",
            "server_card": "/.well-known/mcp/server-card.json"
        }
    })

async def index(request):
    """Landing and web documentation page."""
    docs_html = Path(__file__).parent / "docs" / "index.html"
    if docs_html.exists():
        return HTMLResponse(docs_html.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>StegoKiller MCP Server is Online</h1><p>44 Tools Available at /sse</p>")

# Initialize Starlette FastMCP SSE App
app = mcp.sse_app()

# Register Discovery, Health & Web Routes
app.routes.insert(0, Route("/.well-known/mcp/server-card.json", get_server_card))
app.routes.insert(1, Route("/server-card.json", get_server_card))
app.routes.insert(2, Route("/health", health))
app.routes.insert(3, Route("/", index))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    print(f"[StegoKiller] Starting Remote FastMCP SSE Server on port {port} (44 Tools Registered)...")
    uvicorn.run(app, host="0.0.0.0", port=port)
