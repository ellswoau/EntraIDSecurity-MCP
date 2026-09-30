"""Session / token revocation tools.

Revoking a user's sign-in sessions invalidates every refresh token the user
was issued (and their browser session cookies) by resetting the
``signInSessionsValidFromDateTime`` property -- used when a device is lost or
an account is suspected compromised. It forces the user to sign in again on all
devices/apps.

    POST /users/{id|userPrincipalName}/revokeSignInSessions

Requires ``User.RevokeSessions.All`` (application) or
``User.ReadWrite.All``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c


def _resolve_user_id(client, user: str) -> str:
    """Resolve a user reference (object id or UPN) to an object id."""
    s = str(user or "").strip()
    if not s:
        raise ValueError("user is required (an object id or userPrincipalName).")
    if c._GUID_RE.match(s):
        return s
    data = client.get(f"/users/{c.validate_user_ref(s)}", params={"$select": "id"})
    if not isinstance(data, dict) or not data.get("id"):
        raise ValueError(f"No user found for {s!r}.")
    return data["id"]


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def revoke_user_sessions(user: str, confirm: bool = False) -> dict:
        """Revoke (invalidate) all of a user's sign-in sessions and refresh
        tokens, forcing them to sign in again on every device.

        `user` is an object id (GUID) or a userPrincipalName. Set `confirm=True`
        to perform the revoke -- it is a disruptive action. Graph returns 204
        (no content) on success; this tool reports the resulting
        `signInSessionsValidFromDateTime`. Requires User.RevokeSessions.All
        (or User.ReadWrite.All)."""
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {
                "user": user, "revoked": False,
                "message": "Refusing to revoke without confirm=True. Re-call "
                           "with confirm=True to invalidate all sessions.",
            }
        uid = _resolve_user_id(client, user)
        client.post(f"/users/{uid}/revokeSignInSessions")
        after = client.get(f"/users/{uid}",
                           params={"$select": "id,userPrincipalName,"
                                               "signInSessionsValidFromDateTime"})
        return {
            "user": user, "user_id": uid, "revoked": True,
            "sign_in_sessions_valid_from_date_time":
                (after or {}).get("signInSessionsValidFromDateTime"),
            "message": "All refresh tokens and browser sessions were "
                       "invalidated; the user must sign in again everywhere.",
        }
