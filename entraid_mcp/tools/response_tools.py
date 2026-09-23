"""Mutating Identity Protection response tools.

These change state: they confirm or dismiss a user's risk. They are kept in
their own module so an accidental write is impossible from a read-only path.
Each tool requires the IdentityRiskyUser.ReadWrite.All application permission.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c

RISKY_USERS_PATH = "/identityProtection/riskyUsers"


def _resolve_user_id(client, user: str) -> str:
    """Resolve a GUID or a UPN to the risky-user object id."""
    s = str(user).strip()
    if "@" in s:
        data = client.get(RISKY_USERS_PATH, params={
            "$filter": f"userPrincipalName eq {c.odata_quote(s)}", "$top": 1})
        items = client.unwrap(data)
        if not items:
            raise ValueError(
                f"No risky user found with userPrincipalName {user!r}. "
                "Use list_risky_users to find the object id.")
        return items[0].get("id")
    return c.validate_guid(s, 'user')


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def dismiss_risky_user(user: str) -> dict:
        """MUTATING: dismiss the risk for a user (mark as "risk dismissed").

        Use when an investigation concludes the risk was benign. `user` is a
        risky-user object id (GUID) or a userPrincipalName. Requires
        IdentityRiskyUser.ReadWrite.All. This changes Identity Protection state
        -- confirm the target before calling."""
        client = get_client(config)
        uid = _resolve_user_id(client, user)
        client.post(f"{RISKY_USERS_PATH}/dismiss", json_body={"userIds": [uid]})
        return {"action": "dismiss", "user_id": uid, "user": user,
                "result": "dismissed"}

    @mcp.tool()
    def confirm_risky_user_compromised(user: str) -> dict:
        """MUTATING: confirm a user as compromised (mark as "compromised").

        Use when an investigation concludes the account was actually breached.
        `user` is a risky-user object id (GUID) or a userPrincipalName. Requires
        IdentityRiskyUser.ReadWrite.All. This changes Identity Protection state
        -- confirm the target before calling."""
        client = get_client(config)
        uid = _resolve_user_id(client, user)
        client.post(f"{RISKY_USERS_PATH}/confirmCompromised",
                    json_body={"userIds": [uid]})
        return {"action": "confirmCompromised", "user_id": uid, "user": user,
                "result": "confirmed_compromised"}