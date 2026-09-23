"""Read-only escape hatch for Microsoft Graph endpoints without a dedicated tool.

One GET tool covers the rest of the Graph v1.0 API (application/service
principals, conditional-access policies, devices, ...). Only relative Graph
paths are accepted, so the bearer token can never be sent to another host.
Mutating calls are deliberately not exposed here; they live in the dedicated
tools.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def entra_api_get(path: str, params_json: Optional[str] = None) -> dict:
        """Read-only escape hatch: GET any Microsoft Graph v1.0 path and return
        the raw JSON.

        Use for endpoints that do not have a dedicated tool (service principals,
        conditional-access policies, devices, ...). ``path`` must be a relative
        Graph path beginning with '/', e.g. '/identity/conditionalAccess/policies'
        or '/applications'. ``params_json`` is an optional JSON object of query
        parameters, e.g. ``'{"$top": 10}'``.

        Only GET requests are issued; absolute URLs and other hosts are
        rejected, so this cannot modify anything or leak the token elsewhere."""
        client = get_client(config)
        p = str(path or "").strip()
        if not p.startswith("/"):
            raise ValueError(
                "path must be a relative Graph path beginning with '/', e.g. "
                "'/identity/conditionalAccess/policies'.")
        if "://" in p or p.startswith("//"):
            raise ValueError("path must be relative; absolute URLs are not allowed.")
        params = None
        if params_json and params_json.strip():
            try:
                params = json.loads(params_json)
            except json.JSONDecodeError as exc:
                raise ValueError(f"params_json is not valid JSON: {exc}") from exc
            if not isinstance(params, dict):
                raise ValueError("params_json must be a JSON object.")
        data = client.get(p, params=params)
        return {"path": p, "params": params, "response": data}