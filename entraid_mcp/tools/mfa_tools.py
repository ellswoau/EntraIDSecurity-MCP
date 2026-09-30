"""MFA / authentication-method reset tools.

Two shapes of "reset MFA" are supported:

  * **Per-method delete** -- remove ONE registered authentication method:
        DELETE /users/{id}/authentication/{methodType}/{methodId}
    For Microsoft Authenticator the method under the collection is
    ``microsoftAuthenticatorMethods`` and each method must be deleted first
    (the ``#microsoft.graph.microsoftAuthenticatorAuthenticationMethod``
    instance is what enforces that the user has MFA configured).

  * **Bulk wipe** -- ``reset_user_mfa_methods`` deletes every *registered*
    method of a user (phone/email/FIDO/software-oath/Authenticator/Windows
    Hello), optionally skipping Windows Hello if the tenant does not manage it.

    ``/users/{id}/authentication/methods`` returns ``@odata.type`` values that
    map to the concrete collection + method type needed for the DELETE.

Requires ``UserAuthenticationMethod.ReadWrite.All``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client, EntraIDError
from . import _common as c


def _list_methods(client, uid: str) -> List[Dict[str, Any]]:
    data = client.get(f"/users/{uid}/authentication/methods",
                      params={"$top": 100})
    return [m for m in client.unwrap(data) if isinstance(m, dict)]


def _type_of(method: Dict[str, Any]) -> str:
    otype = method.get("@odata.type") or method.get("odata.type") or ""
    return otype.rsplit(".", 1)[-1] if isinstance(otype, str) else ""


# Map the "@odata.type" short name to the concrete authentication collection
# segment used by the DELETE path.
_COLLECTION_SEGMENT = {
    "microsoftAuthenticatorAuthenticationMethod": "microsoftAuthenticatorMethods",
    "phoneAuthenticationMethod": "phoneMethods",
    "emailAuthenticationMethod": "emailMethods",
    "fido2AuthenticationMethod": "fido2Methods",
    "softwareOathAuthenticationMethod": "softwareOathMethods",
    "temporaryAccessPassAuthenticationMethod": "temporaryAccessPassMethods",
    "windowsHelloForBusinessAuthenticationMethod": "windowsHelloForBusinessMethods",
    "passwordAuthenticationMethod": "passwordMethods",
}

# Methods that cannot be deleted through the authentication-methods API.
_NON_DELETABLE = {"passwordAuthenticationMethod"}


def _resolve_user_id(client, user: str) -> str:
    s = str(user or "").strip()
    if not s:
        raise ValueError("user is required (an object id or userPrincipalName).")
    if c._GUID_RE.match(s):
        return s
    data = client.get(f"/users/{c.validate_user_ref(s)}", params={"$select": "id"})
    if not isinstance(data, dict) or not data.get("id"):
        raise ValueError(f"No user found for {s!r}.")
    return data["id"]


def _delete_method(client, uid: str, method: Dict[str, Any]) -> Dict[str, Any]:
    kind = _type_of(method)
    mid = method.get("id")
    segment = _COLLECTION_SEGMENT.get(kind)
    if not segment:
        return {"method_id": mid, "type": kind, "deleted": False,
                "reason": "unsupported method type"}
    if kind in _NON_DELETABLE:
        return {"method_id": mid, "type": kind, "deleted": False,
                "reason": "not deletable via the authentication-methods API"}
    client.delete(f"/users/{uid}/authentication/{segment}/{mid}")
    return {"method_id": mid, "type": kind, "deleted": True}


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def delete_user_auth_method(user: str, method_id: str) -> dict:
        """Delete ONE registered authentication method of a user (MFA reset for
        a single method).

        `user` is an object id (GUID) or a userPrincipalName; `method_id` is the
        method's id from get_user_authentication_methods. The method's type is
        read first so the correct collection is targeted
        (e.g. ``microsoftAuthenticatorMethods``). Requires
        UserAuthenticationMethod.ReadWrite.All. A Microsoft Authenticator
        method must be deleted before a new one can be registered."""
        client = get_client(config)
        uid = _resolve_user_id(client, user)
        methods = _list_methods(client, uid)
        match = next((m for m in methods if m.get("id") == method_id), None)
        if match is None:
            raise ValueError(
                f"No authentication method {method_id!r} on {user!r}. Call "
                "get_user_authentication_methods to list the current ids.")
        result = _delete_method(client, uid, match)
        if not result.get("deleted"):
            raise ValueError(
                f"Method {method_id!r} (type {result.get('type')}) cannot be "
                f"deleted: {result.get('reason')}.")
        return {"user": user, "user_id": uid, "method": result,
                "message": f"Deleted authentication method {method_id}."}

    @mcp.tool()
    def reset_user_mfa_methods(
        user: str, confirm: bool = False, include_windows_hello: bool = False,
    ) -> dict:
        """Wipe a user's registered MFA / passwordless methods (MFA reset).

        `user` is an object id (GUID) or a userPrincipalName. Deletes every
        registered method (phone, email, FIDO2, software OATH, Microsoft
        Authenticator, and -- only when `include_windows_hello=True` -- Windows
        Hello for Business). The password method is never deleted. Set
        `confirm=True` to perform the reset. Requires
        UserAuthenticationMethod.ReadWrite.All. The user will be prompted to
        re-register MFA at next sign-in."""
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"user": user, "reset": False,
                    "message": "Refusing to reset MFA without confirm=True."}
        uid = _resolve_user_id(client, user)
        methods = _list_methods(client, uid)
        deleted: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        for m in methods:
            kind = _type_of(m)
            if kind == "windowsHelloForBusinessAuthenticationMethod" and not include_windows_hello:
                skipped.append({"method_id": m.get("id"), "type": kind,
                                "reason": "windows hello skipped (set "
                                          "include_windows_hello=True to remove)"})
                continue
            res = _delete_method(client, uid, m)
            (deleted if res.get("deleted") else skipped).append(res)
        remaining = _list_methods(client, uid)
        return {
            "user": user, "user_id": uid, "reset": True,
            "deleted_count": len(deleted), "deleted": deleted,
            "skipped": skipped,
            "remaining_methods": [{"id": r.get("id"), "type": _type_of(r)}
                                  for r in remaining],
            "message": "Registered MFA methods removed; the user must "
                       "re-register authentication on next sign-in.",
        }
