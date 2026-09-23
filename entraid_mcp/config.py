"""Configuration and secure credential handling for the Entra ID MCP server.

Authentication is OAuth2 **client credentials** (app-only) against Microsoft
Entra ID. You need three values from an app registration:

  * tenant id    -- Directory (tenant) ID of the Entra ID tenant
  * client id    -- Application (client) ID of the app registration
  * client secret -- a client secret VALUE generated on that app registration

Credentials can be supplied from (in order of precedence):
  1. Explicit keyword arguments (e.g. when called programmatically)
  2. Environment variables (ENTRAID_*)
  3. A JSON config file (ENTRAID_CONFIG_FILE, or --config)

The client secret is never logged and config files are written with 0600
permissions when created via the ``entraid config init`` wizard.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

ENV_TENANT_ID = "ENTRAID_TENANT_ID"
ENV_CLIENT_ID = "ENTRAID_CLIENT_ID"
ENV_CLIENT_SECRET = "ENTRAID_CLIENT_SECRET"
ENV_BASE_URL = "ENTRAID_BASE_URL"
ENV_AUTHORITY_HOST = "ENTRAID_AUTHORITY_HOST"
ENV_VERIFY_SSL = "ENTRAID_VERIFY_SSL"
ENV_TIMEOUT = "ENTRAID_TIMEOUT"
ENV_CONFIG_FILE = "ENTRAID_CONFIG_FILE"
# Optional bearer key that gates the network MCP endpoints when set. Kept
# strictly separate from the Entra ID app credentials above.
ENV_MCP_TOKEN = "ENTRAID_MCP_AUTH_TOKEN"

DEFAULT_BASE_URL = "https://graph.microsoft.com/v1.0"
DEFAULT_AUTHORITY_HOST = "https://login.microsoftonline.com"
DEFAULT_SCOPE = "https://graph.microsoft.com/.default"

_PASSWORD_TAG = "***REDACTED***"


@dataclass
class EntraIDConfig:
    """Resolved configuration for one Entra ID tenant / app registration."""

    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    # Microsoft Graph service root (v1.0). Override only for a sovereign cloud.
    base_url: str = DEFAULT_BASE_URL
    # Entra ID authority host; override for a sovereign cloud
    # (e.g. https://login.microsoftonline.us).
    authority_host: str = DEFAULT_AUTHORITY_HOST
    # OAuth2 scope requested at the token endpoint. `.default` maps the app's
    # granted application permissions into the token.
    scope: str = DEFAULT_SCOPE
    verify_ssl: bool = True
    timeout: int = 30
    # Optional bearer key that gates the HTTP/streamable-http MCP transport.
    mcp_auth_token: str = ""

    def resolved_base_url(self) -> str:
        """Return the Graph service root without a trailing slash."""
        url = (self.base_url or "").strip() or DEFAULT_BASE_URL
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def resolved_authority_host(self) -> str:
        host = (self.authority_host or "").strip() or DEFAULT_AUTHORITY_HOST
        if not host.startswith(("http://", "https://")):
            host = "https://" + host
        return host.rstrip("/")

    def token_url(self) -> str:
        """OAuth2 v2.0 token endpoint for this tenant."""
        return f"{self.resolved_authority_host()}/{self.tenant_id}/oauth2/v2.0/token"

    def redacted(self) -> dict:
        """Return a dict safe for logging (secret redacted)."""
        d = asdict(self)
        d["client_secret"] = _PASSWORD_TAG if d.get("client_secret") else ""
        d["mcp_auth_token"] = _PASSWORD_TAG if d.get("mcp_auth_token") else ""
        d["base_url"] = self.resolved_base_url()
        d["authority_host"] = self.resolved_authority_host()
        return d

    def is_complete(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)


class ConfigError(Exception):
    """Raised when configuration/credentials are missing or invalid."""


def _as_bool(value: Optional[str], default: bool = True) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def load_config(
    config_file: Optional[str] = None,
    *,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    base_url: Optional[str] = None,
    authority_host: Optional[str] = None,
    scope: Optional[str] = None,
    verify_ssl: Optional[bool] = None,
    timeout: Optional[int] = None,
    mcp_auth_token: Optional[str] = None,
) -> EntraIDConfig:
    """Load and merge configuration from kwargs, env and a config file.

    Raises :class:`ConfigError` if essential credentials are missing.
    """
    cfg = EntraIDConfig()

    # 1. Load from a well-known config file (env or explicit path).
    config_file = config_file or os.environ.get(ENV_CONFIG_FILE)
    if config_file and Path(config_file).exists():
        data = json.loads(Path(config_file).read_text(encoding="utf-8"))
        for key in ("tenant_id", "client_id", "client_secret", "base_url",
                    "authority_host", "scope", "verify_ssl", "timeout",
                    "mcp_auth_token"):
            if key in data and data[key] is not None:
                setattr(cfg, key, data[key])

    # 2. Env variables override the file.
    for env_name, attr in ((ENV_TENANT_ID, "tenant_id"),
                           (ENV_CLIENT_ID, "client_id"),
                           (ENV_CLIENT_SECRET, "client_secret"),
                           (ENV_BASE_URL, "base_url"),
                           (ENV_AUTHORITY_HOST, "authority_host")):
        if os.environ.get(env_name):
            setattr(cfg, attr, os.environ[env_name].strip())
    if os.environ.get(ENV_VERIFY_SSL) is not None:
        cfg.verify_ssl = _as_bool(os.environ[ENV_VERIFY_SSL], True)
    if os.environ.get(ENV_TIMEOUT):
        try:
            cfg.timeout = int(os.environ[ENV_TIMEOUT])
        except ValueError:
            pass
    if os.environ.get(ENV_MCP_TOKEN):
        cfg.mcp_auth_token = os.environ[ENV_MCP_TOKEN].strip()

    # 3. Explicit arguments win.
    if tenant_id is not None:
        cfg.tenant_id = tenant_id.strip()
    if client_id is not None:
        cfg.client_id = client_id.strip()
    if client_secret is not None:
        cfg.client_secret = client_secret.strip()
    if base_url is not None:
        cfg.base_url = base_url.strip()
    if authority_host is not None:
        cfg.authority_host = authority_host.strip()
    if scope is not None:
        cfg.scope = scope.strip()
    if verify_ssl is not None:
        cfg.verify_ssl = bool(verify_ssl)
    if timeout is not None:
        cfg.timeout = int(timeout)
    if mcp_auth_token is not None:
        cfg.mcp_auth_token = mcp_auth_token.strip()

    if not cfg.is_complete():
        missing = [name for name, val in (
            ("tenant_id (" + ENV_TENANT_ID + ")", cfg.tenant_id),
            ("client_id (" + ENV_CLIENT_ID + ")", cfg.client_id),
            ("client_secret (" + ENV_CLIENT_SECRET + ")", cfg.client_secret),
        ) if not val]
        raise ConfigError(
            "Incomplete Entra ID credentials. Missing: " + ", ".join(missing)
            + ". Set the ENTRAID_* env vars or run `python -m entraid_mcp "
              "config init --config <file>`."
        )
    return cfg


def configure_interactive(config_file: str) -> str:
    """Prompt securely for credentials and write a 0600 config file.

    The client secret is requested with ``getpass`` so it is never echoed to
    the terminal, and the resulting file is only readable by the owner.
    """
    import getpass

    data = {}
    p = Path(config_file).expanduser()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}

    print("Entra ID MCP\n-----------")
    print("Create an app registration first (see README). Enter the values:")
    data["tenant_id"] = input(
        f"Directory (tenant) ID [{data.get('tenant_id', '')}]: "
    ).strip() or data.get("tenant_id", "")
    data["client_id"] = input(
        f"Application (client) ID [{data.get('client_id', '')}]: "
    ).strip() or data.get("client_id", "")
    data["client_secret"] = getpass.getpass(
        "Client secret VALUE: "
    ) or data.get("client_secret", "")
    data.setdefault("base_url", DEFAULT_BASE_URL)
    data.setdefault("authority_host", DEFAULT_AUTHORITY_HOST)
    data.setdefault("verify_ssl", True)

    if not (data.get("tenant_id") and data.get("client_id") and data.get("client_secret")):
        raise ConfigError("tenant_id, client_id and client_secret are required.")

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(p, 0o600)
    return str(p)