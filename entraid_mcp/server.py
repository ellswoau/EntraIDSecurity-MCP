"""Entra ID MCP server (FastMCP).

Run via:
    python -m entraid_mcp                          # stdio MCP server
    python -m entraid_mcp config init --config ./entraid.json
    python -m entraid_mcp ping --config ./entraid.json

Environment / config precedence is handled by :mod:`.config`. Credentials come
from ENTRAID_* env vars or a JSON config file written by ``config init``.

By default the network (http/sse/streamable-http) transports are gated behind a
bearer API key (``ENTRAID_MCP_AUTH_TOKEN``); every endpoint except the
credential-free health checks returns 401 without ``Authorization: Bearer <key>``.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
import time

from . import __version__
from .client import clear_client, get_client
from .config import ENV_MCP_TOKEN, ConfigError, configure_interactive, load_config
from .tools import register_all

_PUBLIC_PATHS = ("/health", "/healthz")


class _BearerAuthMiddleware:
    """Pure-ASGI middleware requiring ``Authorization: Bearer <key>`` on all
    HTTP requests except the public health paths. Constant-time comparison."""

    def __init__(self, app, allowed_key: str = "", public_paths=_PUBLIC_PATHS):
        self.app = app
        self.allowed_key = allowed_key
        self.public_paths = public_paths

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        if any(path == p or path.startswith(p + "/") for p in self.public_paths):
            return await self.app(scope, receive, send)

        auth = ""
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                auth = value.decode("latin-1")
                break
        expected = "Bearer " + self.allowed_key
        if not hmac.compare_digest(auth, expected):
            body = json.dumps({"detail": "Not authenticated"}).encode()
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b'Bearer realm="mcp"'),
                    (b"content-length", str(len(body)).encode()),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return
        return await self.app(scope, receive, send)


def _auth_middleware_spec(allowed_key: str):
    if not allowed_key:
        return None
    return (_BearerAuthMiddleware, (), {"allowed_key": allowed_key})


def build_server(config=None):
    """Build a configured FastMCP app."""
    from fastmcp import FastMCP

    if config is None:
        config = load_config()

    mcp = FastMCP(
        "entraid",
        version=__version__,
        instructions=(
            "Tools for Microsoft Entra ID (Azure AD) security investigations. "
            "Start with list_sign_ins / list_user_sign_ins to find sign-in "
            "events, then get_sign_in for the full detail of one event "
            "(conditional-access policies applied, location, device, MFA, risk). "
            "Use list_directory_audits / list_user_audits / get_directory_audit "
            "for the change history, and list_risky_users / get_risky_user / "
            "get_risky_user_history / list_risk_detections for Identity "
            "Protection. Answer 'what access does this user have?' with "
            "get_user_directory_roles, get_user_memberships, "
            "get_user_app_role_assignments, get_user_oauth2_grants and "
            "get_user_authentication_methods. Mutating tools change state -- "
            "confirm the target first. Group/DL/Team membership: list_groups, "
            "get_group, list_group_members, add_group_member, remove_group_member. "
            "SharePoint sites, libraries and folder/file permissions: "
            "list_sharepoint_sites, get_sharepoint_site, list_sharepoint_libraries, "
            "list_sharepoint_folders, list_sharepoint_folder_contents, "
            "list_sharepoint_item_permissions, invite_to_sharepoint_item, "
            "remove_sharepoint_item_permission, list_sharepoint_site_permissions, "
            "update_sharepoint_site_permission, remove_sharepoint_site_permission "
            "(note: a user is granted access to a library/folder with "
            "invite_to_sharepoint_item; Graph cannot make a user a site-collection "
            "owner -- use SharePoint admin/PnP PowerShell for that). Teams owners "
            "and members: list_teams, get_team, list_team_owners, add_team_owner, "
            "remove_team_owner, list_team_members, add_team_member, "
            "remove_team_member, list_team_channels. Permission grants/removals "
            "follow the same authorization gate as group membership (owner / "
            "department manager approves; never self-service) and need confirm=True. "
            "Sessions: revoke_user_sessions. MFA reset: get_user_authentication_methods, "
            "delete_user_auth_method, reset_user_mfa_methods. Mailbox: "
            "get_user_out_of_office, set_user_out_of_office, "
            "unset_user_out_of_office, list_mail_forwarding_rules, "
            "set_mail_forwarding, remove_mail_forwarding_rule. Mailbox DELEGATION "
            "(Exchange Online Admin API, needs Exchange.ManageAsAppV2 + an "
            "Exchange RBAC role, NOT a Graph scope): get_mailbox_delegation, "
            "set_mailbox_send_on_behalf, add_mailbox_send_on_behalf, "
            "remove_mailbox_send_on_behalf (Send on Behalf), and "
            "list_mailbox_folder_permissions, add_mailbox_folder_permission, "
            "set_mailbox_folder_permission, remove_mailbox_folder_permission "
            "(folder/Calendar delegation). Mailbox-level Full Access / Send As "
            "are NOT available in ANY API (Graph or the Admin API) -- only "
            "Exchange Online PowerShell (certificate app-only) can set them. Exchange "
            "message trace (did an email reach the mailbox / where did it go / "
            "was it blocked): list_message_traces then get_message_trace_details "
            "(Graph beta; needs ExchangeMessageTrace.Read.All and a provisioned "
            "service principal). entra_api_get is a read-only "
            "escape hatch for other Graph v1.0 endpoints. All calls need the "
            "corresponding Microsoft Graph application permission with admin consent."
        ),
    )

    register_all(mcp, config)

    @mcp.tool()
    def entraid_config() -> dict:
        """Return a redacted description of the Entra ID tenant/app this server
        is connected to (tenant id, client id, Graph base URL, ssl/timeout).
        Never includes the client secret or MCP auth token."""
        return config.redacted()

    _started_at = time.time()
    _health_body = {"status": "ok", "service": "entraid-mcp", "version": __version__}

    async def _health_response(request):  # noqa: ANN001 - Starlette Request
        from starlette.responses import JSONResponse

        body = dict(_health_body)
        body["uptime_seconds"] = int(time.time() - _started_at)
        body["healthy"] = True
        return JSONResponse(body)

    mcp.custom_route("/health", methods=["GET"], name="health")(_health_response)
    mcp.custom_route("/healthz", methods=["GET"], name="healthz")(_health_response)

    return mcp


def _cmd_config(args: argparse.Namespace) -> int:
    try:
        path = configure_interactive(args.config)
    except ConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Credentials written securely (0600) to: {path}")
    return 0


def _cmd_ping(args: argparse.Namespace) -> int:
    try:
        config = load_config(config_file=args.config)
        client = get_client(config)
        info = client.test_connection()
        if not info.get("connected"):
            print(f"Not connected: {info.get('error', 'authentication failed')}",
                  file=sys.stderr)
            return 1
        print("Connected OK:")
        for k, v in info.items():
            print(f"  {k}: {v}")
        return 0
    except Exception as exc:  # noqa: BLE001 - report any failure to CLI
        print(f"Connection failed: {exc}", file=sys.stderr)
        return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="entraid-mcp",
        description="Entra ID (Microsoft Graph) MCP server (FastMCP).",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", default=None, help="Path to config JSON file")
    parser.add_argument("--transport", default="stdio",
                        choices=["stdio", "sse", "streamable-http", "http"],
                        help="MCP transport for the default run mode (default: stdio)")
    parser.add_argument("--host", default=None, help="Bind host for http/sse transports")
    parser.add_argument("--port", type=int, default=8000, help="Bind port for http/sse transports")
    parser.add_argument("--token", default=None,
                        help="API key that gates the network transport (default: $%s)" % ENV_MCP_TOKEN)
    sub = parser.add_subparsers(dest="command")

    p_cfg = sub.add_parser("config", help="Configure Entra ID credentials")
    cfg_sub = p_cfg.add_subparsers(dest="config_command")
    p_init = cfg_sub.add_parser("init", help="Write a credentials config file (0600)")
    p_init.add_argument("--config", required=True, help="Path to the config JSON file")
    p_init.set_defaults(func=_cmd_config)

    p_ping = sub.add_parser("ping", help="Test connectivity/credentials")
    p_ping.add_argument("--config", default=None, help="Path to config JSON file")
    p_ping.set_defaults(func=_cmd_ping)

    args = parser.parse_args(argv)

    if getattr(args, "command", None) == "config" and getattr(args, "config_command", None) == "init":
        return _cmd_config(args)
    if getattr(args, "command", None) == "ping":
        return _cmd_ping(args)

    try:
        mcp = build_server(config=load_config(config_file=args.config))
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    if args.transport in ("http", "sse", "streamable-http"):
        auth_key = args.token if args.token is not None else os.environ.get(ENV_MCP_TOKEN, "").strip()
        mw = _auth_middleware_spec(auth_key)
        mcp.run(
            transport=args.transport,
            host=args.host or "0.0.0.0",
            port=args.port,
            middleware=[mw] if mw else None,
        )
    else:
        mcp.run(transport="stdio")

    try:
        clear_client(load_config(config_file=args.config).resolved_base_url())
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())