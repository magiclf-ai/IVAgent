import json
from typing import Optional, Dict, Any, List
from contextlib import AsyncExitStack

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from ...core.cli_logger import CLILogger

class AbcDecompilerClient:
    """
    Client for Abc-Decompiler (Jadx-based) MCP Server.
    
    Provides methods to interact with the decompiler tools.
    """

    def __init__(self, url: str):
        """
        Initialize the client.

        Args:
            url: The URL of the MCP server (e.g., http://localhost:3000/mcp)
        """
        self.url = url
        self.session: Optional[ClientSession] = None
        self._exit_stack: Optional[AsyncExitStack] = None
        self._logger = CLILogger(component="AbcDecompilerClient")

    async def connect(self):
        """Connect to the MCP server."""
        if self.session:
            return

        try:
            self._exit_stack = AsyncExitStack()
            # Connect to SSE/HTTP endpoint
            read, write, _ = await self._exit_stack.enter_async_context(streamable_http_client(self.url))
            # Initialize ClientSession
            self.session = await self._exit_stack.enter_async_context(ClientSession(read, write))
            await self.session.initialize()
            self._logger.info("backend.abc_client.connected", "已连接 Abc-Decompiler MCP 服务", url=self.url)
        except Exception as e:
            self._logger.error("backend.abc_client.connect_failed", str(e), url=self.url)
            if self._exit_stack:
                await self._exit_stack.aclose()
            self._exit_stack = None
            raise

    async def close(self):
        """Close the connection."""
        if self._exit_stack:
            await self._exit_stack.aclose()
            self._exit_stack = None
            self.session = None
            self._logger.info("backend.abc_client.disconnected", "已断开 MCP 服务连接")

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def _call_tool(self, tool_name: str, arguments: Dict[str, Any] = None) -> Any:
        """
        Helper to call a tool and parse the JSON result.

        Args:
            tool_name: Name of the tool to call
            arguments: Dictionary of arguments

        Returns:
            Parsed JSON result (dict or list)

        Raises:
            RuntimeError: If the tool returns an error or client is not connected
            ValueError: If required parameters are missing
        """
        if not self.session:
            raise RuntimeError("Client is not connected")

        # Parameter validation
        arguments = arguments or {}
        self._validate_tool_params(tool_name, arguments)

        try:
            result = await self.session.call_tool(tool_name, arguments)

            # MCP returns a list of content blocks. We expect text content containing JSON.
            # Combine all text blocks if multiple? Usually just one for data return.
            combined_text = ""
            for content in result.content:
                if content.type == "text":
                    combined_text += content.text

            if not combined_text:
                return None

            try:
                parsed_result = json.loads(combined_text)
            except json.JSONDecodeError:
                # Fallback if it's just a string (not JSON)
                return combined_text

            # Check for server-side error response
            if isinstance(parsed_result, dict) and 'error' in parsed_result:
                error_msg = parsed_result['error']
                self._logger.error("backend.abc_client.tool_error", "工具返回错误", tool=tool_name, error=error_msg)
                raise RuntimeError(f"AbcDecompiler tool '{tool_name}' failed: {error_msg}")

            return parsed_result

        except RuntimeError:
            # Re-raise our own exceptions
            raise
        except Exception as e:
            self._logger.error("backend.abc_client.call_failed", str(e), tool=tool_name)
            raise RuntimeError(f"Failed to call tool '{tool_name}': {e}") from e

    def _validate_tool_params(self, tool_name: str, arguments: Dict[str, Any]):
        """Validate required parameters before making the API call."""
        required_params = {
            'get_method_by_name': ['class_name', 'method_name'],
            'get_class_source': ['class_name'],
            'get_methods_of_class': ['class_name'],
        }

        if tool_name in required_params:
            for param in required_params[tool_name]:
                if param not in arguments or arguments[param] is None or arguments[param] == '':
                    raise ValueError(f"Tool '{tool_name}' requires '{param}' parameter")

    # ==================== Tool Methods ====================

    async def get_selected_text(self) -> Dict[str, Any]:
        """Returns the currently selected text in the decompiled code view."""
        return await self._call_tool("get_selected_text")

    async def get_method_by_name(self, class_name: str, method_name: str) -> Dict[str, Any]:
        """Fetch the source code of a method from a specific class."""
        return await self._call_tool("get_method_by_name", {
            "class_name": class_name,
            "method_name": method_name
        })

    async def get_all_classes(self, offset: int = 0, count: int = 0) -> Dict[str, Any]:
        """Returns a list of all classes in the project with pagination support."""
        return await self._call_tool("get_all_classes", {
            "offset": offset,
            "count": count
        })

    async def get_class_source(self, class_name: str) -> Dict[str, Any]:
        """Fetch the Java source of a specific class."""
        return await self._call_tool("get_class_source", {
            "class_name": class_name
        })

    async def get_methods_of_class(self, class_name: str) -> Dict[str, Any]:
        """List all method names in a class."""
        return await self._call_tool("get_methods_of_class", {
            "class_name": class_name
        })
