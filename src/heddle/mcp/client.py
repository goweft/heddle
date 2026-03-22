"""Heddle MCP client — for agents that consume other agents' tools.

When an agent declares 'consumes' in its config, the runtime creates
MCP client connections to those servers. This module handles:
- Connecting to other Heddle agents or external MCP servers
- Tool discovery on connected servers
- Proxied tool calls with audit logging
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from heddle.security.audit import get_audit_logger

logger = logging.getLogger(__name__)


class MCPClientError(Exception):
    """Error communicating with a remote MCP server."""


class LoomMCPClient:
    """Client for calling tools on another Heddle agent or MCP server.

    Supports streamable-http transport for remote Heddle agents.
    """

    def __init__(self, agent_name: str, target_uri: str):
        """Initialize client.

        Args:
            agent_name: Name of the calling agent (for audit).
            target_uri: MCP server URI (e.g. http://localhost:8200/mcp).
        """
        self.agent_name = agent_name
        self.target_uri = target_uri
        self._audit = get_audit_logger()
        self._tools_cache: list[dict] | None = None

    async def list_tools(self) -> list[dict[str, Any]]:
        """List available tools on the remote MCP server."""
        if self._tools_cache is not None:
            return self._tools_cache

        try:
            from fastmcp import Client
            async with Client(self.target_uri) as client:
                tools = await client.list_tools()
                self._tools_cache = [
                    {"name": t.name, "description": t.description}
                    for t in tools
                ]
                return self._tools_cache
        except Exception as exc:
            logger.error("Failed to list tools on %s: %s", self.target_uri, exc)
            raise MCPClientError(f"Cannot connect to {self.target_uri}: {exc}") from exc

    async def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> str:
        """Call a tool on the remote MCP server.

        Returns the tool's text response.
        """
        import time
        start = time.monotonic()
        arguments = arguments or {}

        try:
            from fastmcp import Client
            async with Client(self.target_uri) as client:
                result = await client.call_tool(tool_name, arguments)

                # Extract text from FastMCP 3.x CallToolResult
                if hasattr(result, "content") and result.content:
                    if isinstance(result.content, list):
                        text = result.content[0].text
                    else:
                        text = str(result.content)
                else:
                    text = str(result)

            duration = (time.monotonic() - start) * 1000
            self._audit.log_tool_call(
                self.agent_name, f"remote:{tool_name}",
                parameters=arguments, result_status="success",
                duration_ms=duration,
            )
            return text

        except Exception as exc:
            duration = (time.monotonic() - start) * 1000
            self._audit.log_tool_call(
                self.agent_name, f"remote:{tool_name}",
                parameters=arguments, result_status="error",
                error=str(exc), duration_ms=duration,
            )
            raise MCPClientError(f"Tool call failed ({tool_name} on {self.target_uri}): {exc}") from exc


class AgentMesh:
    """Manages connections to multiple Heddle agents.

    Created from an agent's 'consumes' list. Provides a unified
    interface for calling any tool on any connected agent.
    """

    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self._clients: dict[str, LoomMCPClient] = {}

    def connect(self, uri: str, tool_filter: list[str] | None = None) -> None:
        """Register a connection to a remote MCP server."""
        self._clients[uri] = LoomMCPClient(self.agent_name, uri)
        logger.info("Agent %s connected to %s", self.agent_name, uri)

    async def list_all_tools(self) -> dict[str, list[dict]]:
        """List tools across all connected servers."""
        result = {}
        for uri, client in self._clients.items():
            try:
                tools = await client.list_tools()
                result[uri] = tools
            except MCPClientError as exc:
                result[uri] = [{"error": str(exc)}]
        return result

    async def call(self, uri: str, tool_name: str, arguments: dict | None = None) -> str:
        """Call a tool on a specific connected server."""
        if uri not in self._clients:
            raise MCPClientError(f"Not connected to {uri}")
        return await self._clients[uri].call_tool(tool_name, arguments)

    async def find_and_call(self, tool_name: str, arguments: dict | None = None) -> str:
        """Find a tool by name across all connections and call it.

        Searches all connected servers for the tool. Useful when the
        caller doesn't know which server hosts the tool.
        """
        for uri, client in self._clients.items():
            tools = await client.list_tools()
            if any(t["name"] == tool_name for t in tools):
                return await client.call_tool(tool_name, arguments)
        raise MCPClientError(f"Tool '{tool_name}' not found on any connected server")

    @property
    def connections(self) -> list[str]:
        return list(self._clients.keys())
