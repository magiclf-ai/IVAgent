#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [ "fastmcp", "httpx" ]
# ///

"""
Copyright (c) 2025 jadx mcp server developer(s) (https://github.com/zinja-coder/jadx-ai-mcp)
See the file 'LICENSE' for copying permission
"""

import argparse
import sys
from fastmcp import FastMCP
from src.banner import jadx_mcp_server_banner
from src.server import config, tools

# Initialize MCP Server
mcp = FastMCP("JADX-AI-MCP Plugin Reverse Engineering Server")

# Import and register ALL tools using correct FastMCP pattern
from src.server.tools.class_tools import (
    fetch_current_class, get_selected_text, get_class_source,
    get_all_classes, get_methods_of_class, get_fields_of_class, get_smali_of_class,
    get_main_application_classes_names, get_main_application_classes_code, get_main_activity_class
)
from src.server.tools.search_tools import (
    get_method_by_name, search_method_by_name, search_classes_by_keyword
)
from src.server.tools.resource_tools import (
    get_android_manifest, get_strings, get_all_resource_file_names,
    get_resource_file
)
from src.server.tools.refactor_tools import (
    rename_class, rename_method, rename_field, rename_package, rename_variable
)
from src.server.tools.debug_tools import (
    debug_get_stack_frames, debug_get_threads, debug_get_variables
)
from src.server.tools.xrefs_tools import (
    get_xrefs_to_class, get_xrefs_to_method, get_xrefs_to_field
)

@mcp.tool()
async def get_selected_text() -> dict:
    """Returns the currently selected text in the decompiled code view."""
    return await tools.class_tools.get_selected_text()


@mcp.tool()
async def get_method_by_name(class_name: str, method_name: str) -> dict:
    """Fetch the source code of a method from a specific class."""
    return await tools.search_tools.get_method_by_name(class_name, method_name)


@mcp.tool()
async def get_all_classes(offset: int = 0, count: int = 0) -> dict:
    """Returns a list of all classes in the project with pagination support."""
    return await tools.class_tools.get_all_classes(offset, count)


@mcp.tool()
async def get_class_source(class_name: str) -> dict:
    """Fetch the Java source of a specific class."""
    return await tools.class_tools.get_class_source(class_name)


@mcp.tool()
async def get_methods_of_class(class_name: str) -> dict:
    """List all method names in a class."""
    return await tools.class_tools.get_methods_of_class(class_name)

def main():
    parser = argparse.ArgumentParser("MCP Server for Jadx")
    parser.add_argument(
        "--http",
        help="Serve MCP Server over HTTP stream.",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--port", help="Port for --http (default:8651)", default=8651, type=int
    )
    parser.add_argument(
        "--jadx-port",
        help="JADX AI MCP Plugin port (default:8650)",
        default=8650,
        type=int,
    )
    args = parser.parse_args()

    # Configure
    config.set_jadx_port(args.jadx_port)

    # Banner & Health Check
    try:
        print(jadx_mcp_server_banner())
    except:
        print(
            "[JADX AI MCP Server] v3.3.5 | MCP Port:",
            args.port,
            "| JADX Port:",
            args.jadx_port,
        )

    print("Testing JADX AI MCP Plugin connectivity...")
    result = config.health_ping()
    print(f"Health check result: {result}")

    # Run Server
    if args.http:
        mcp.run(transport="streamable-http", port=args.port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
