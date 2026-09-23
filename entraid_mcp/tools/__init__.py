"""Tool registration for the Entra ID MCP server.

Each ``register`` function wires fastmcp ``@tool`` decorators bound to a
resolved :class:`EntraIDConfig`.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from . import (
    api_tools,
    audit_tools,
    response_tools,
    risky_tools,
    signin_tools,
    user_tools,
)


def register_all(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    signin_tools.register(mcp, config)
    audit_tools.register(mcp, config)
    risky_tools.register(mcp, config)
    user_tools.register(mcp, config)
    response_tools.register(mcp, config)
    api_tools.register(mcp, config)