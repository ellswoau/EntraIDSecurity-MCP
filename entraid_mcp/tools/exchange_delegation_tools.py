"""Exchange Online mailbox delegation tools (Send on Behalf + folder access).

Microsoft Graph does **not** expose mailbox permissions (see
``mailbox_tools``), so mailbox delegation is performed through the
**Exchange Online Admin API** -- a REST, cmdlet-style surface (preview):

    POST https://outlook.office365.com/adminapi/v2.0/<TenantID>/<Endpoint>

Two endpoints back this module:

  * ``Mailbox``                  -- ``Get-Mailbox`` (read delegate config) and
    ``Set-Mailbox`` ``GrantSendOnBehalfTo`` (add / remove / overwrite the
    **Send on Behalf** delegate list).
  * ``MailboxFolderPermission``  -- ``Get-`` / ``Add-`` / ``Set-`` /
    ``Remove-MailboxFolderPermission`` (delegate a mailbox **folder** such as
    the Calendar -- ``Editor`` / ``PublishingEditor`` / ``Reviewer``).

Auth: the app-only token is minted for the **Exchange** resource
(``https://outlook.office365.com/.default``) from the same app registration,
and needs the ``Exchange.ManageAsAppV2`` **application** permission
(admin-consented) plus an Exchange **RBAC role** on the service principal
(for example Recipient Management) -- *not* a Microsoft Graph scope.

NOT SUPPORTED BY ANY API: mailbox-level **Full Access**
(``Add-MailboxPermission``) and **Send As** (``Add-RecipientPermission``).
Those mailbox permissions exist only in Exchange Online PowerShell
(``Connect-ExchangeOnline``), whose unattended app-only flow requires
**certificate-based** authentication (a client secret is not accepted).
Send on Behalf + folder permissions are what the supported REST surface
covers; Full Access / Send As stay an Exchange-PowerShell change.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c

_BAD_PATH_CHARS = set("\\/:*?\"<>| \t\n\r")
SEND_ON_BEHALF_MODES = ("overwrite", "add", "remove")


# ----------------------------------------------------------------- helpers
def _mailbox_ref(mailbox: str, field: str = "mailbox") -> str:
    """Validate a mailbox reference (UPN / alias / name) for a cmdlet Identity."""
    s = str(mailbox or "").strip()
    if not s or any(ch in _BAD_PATH_CHARS for ch in s):
        raise ValueError(
            f"Invalid {field}: {mailbox!r} (expected a mailbox UPN/alias/name "
            "without path characters).")
    return s


def _principal(value: Any, field: str) -> str:
    """Validate a grantee/delegate principal (UPN, SMTP, or well-known name)."""
    s = str(value or "").strip()
    if not s or any(ch in _BAD_PATH_CHARS for ch in s):
        raise ValueError(
            f"Invalid {field}: {value!r} (expected a UPN/email address or a "
            "well-known principal such as 'Default').")
    return s


def _folder_identity(mailbox: str, folder: str) -> str:
    """Build the ``<mailbox>:\\<FolderPath>`` Identity the cmdlet expects."""
    mb = _mailbox_ref(mailbox)
    f = str(folder or "").strip()
    if not f or any(ch in _BAD_PATH_CHARS for ch in f):
        raise ValueError(
            f"Invalid folder: {folder!r} (expected a folder path such as "
            "'Calendar' or 'Inbox\\Reports').")
    return f"{mb}:\\{f}"


def _cmdlet(cmdlet_name: str, params: Optional[Dict[str, Any]] = None) -> dict:
    return {"CmdletInput": {"CmdletName": cmdlet_name,
                            "Parameters": params or {}}}


def _as_list(data: Any, key: str = "value") -> List[Any]:
    """Normalise an Admin API response into a list of rows."""
    if isinstance(data, dict):
        value = data.get(key)
        if isinstance(value, list):
            return value
        if value is None:
            return [data] if data else []
        return [value]
    if isinstance(data, list):
        return data
    return [data] if data else []


def _summarize_mailbox(m: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(m, dict):
        return {}
    return {
        "identity": m.get("Identity"),
        "id": m.get("Id"),
        "name": m.get("Name"),
        "display_name": m.get("DisplayName"),
        "user_principal_name": m.get("UserPrincipalName"),
        "alias": m.get("Alias"),
        "external_directory_object_id": m.get("ExternalDirectoryObjectId"),
        "recipient_type": m.get("RecipientType"),
        "recipient_type_details": m.get("RecipientTypeDetails"),
        "primary_smtp_address": m.get("PrimarySmtpAddress"),
        "grant_send_on_behalf_to": m.get("GrantSendOnBehalfTo") or [],
        "grant_send_on_behalf_to_with_display_names":
            m.get("GrantSendOnBehalfToWithDisplayNames") or [],
    }


def _summarize_folder_permission(p: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(p, dict):
        return {}
    rights = p.get("AccessRights")
    flags = p.get("SharingPermissionFlags")
    return {
        "identity": p.get("Identity"),
        "folder_name": p.get("FolderName"),
        "user": p.get("User"),
        "access_rights": rights if isinstance(rights, list) else (
            [rights] if rights else []),
        "sharing_permission_flags": flags if isinstance(flags, list) else (
            [flags] if flags else []),
        "is_valid": p.get("IsValid"),
    }


def _access_rights(value: Any) -> Any:
    """Accept a single role ('Editor') or a comma-separated list of rights."""
    s = str(value or "").strip()
    if not s:
        raise ValueError("access_rights is required (a role such as 'Editor' or "
                         "a comma-separated list of granular rights).")
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if any(any(ch in _BAD_PATH_CHARS for ch in p) for p in parts):
        raise ValueError(f"Invalid access_rights: {value!r}.")
    return parts[0] if len(parts) == 1 else parts


def _flags(value: Any) -> Any:
    """Accept '' / a flag / a comma-separated list for SharingPermissionFlags."""
    s = str(value or "").strip()
    if not s:
        return None
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if any(any(ch in _BAD_PATH_CHARS for ch in p) for p in parts):
        raise ValueError(f"Invalid sharing_permission_flags: {value!r}.")
    return parts[0] if len(parts) == 1 else parts


# ------------------------------------------------------- mailbox delegation
def get_mailbox(client, mailbox: str, result_size: int = 0,
                include_display_names: bool = True) -> dict:
    """Read a mailbox's properties + Send-on-Behalf delegate list."""
    mb = _mailbox_ref(mailbox)
    params: Dict[str, Any] = {"Identity": mb}
    if int(result_size or 0) > 0:
        params["ResultSize"] = c.validate_int(result_size, "result_size", minimum=1)
    if c.validate_bool(include_display_names, "include_display_names"):
        params["IncludeGrantSendOnBehalfToWithDisplayNames"] = True
    body = _cmdlet("Get-Mailbox", params)
    data = client.post_exchange("Mailbox", body, anchor_mailbox=mb)
    rows = [m for m in _as_list(data) if isinstance(m, dict)]
    first = rows[0] if rows else {}
    return {
        "mailbox": mailbox,
        "found": bool(first),
        "summary": _summarize_mailbox(first),
        "mailboxes": [_summarize_mailbox(m) for m in rows],
    }


def set_send_on_behalf(client, mailbox: str, delegates: List[str],
                       mode: str = "overwrite") -> dict:
    """Modify the **Send on Behalf** (GrantSendOnBehalfTo) delegate list."""
    me = _mailbox_ref(mailbox)
    chosen = c.validate_choice(mode, SEND_ON_BEHALF_MODES, "mode")
    targets = [c.validate_email(d, "delegate") for d in (delegates or [])]
    if not targets:
        raise ValueError("delegates must contain at least one SMTP address.")
    params: Dict[str, Any] = {"Identity": me}
    if chosen == "overwrite":
        params["GrantSendOnBehalfTo"] = targets
    else:
        table: Dict[str, Any] = {chosen: targets,
                                 "@odata.type": "#Exchange.GenericHashTable"}
        params["GrantSendOnBehalfTo"] = table
    client.post_exchange("Mailbox",
                         _cmdlet("Set-Mailbox", params), anchor_mailbox=me)
    after = get_mailbox(client, me, include_display_names=True)
    return {
        "mailbox": mailbox,
        "mode": chosen,
        "delegates": targets,
        "updated": True,
        "grant_send_on_behalf_to":
            after["summary"].get("grant_send_on_behalf_to", []),
        "grant_send_on_behalf_to_with_display_names":
            after["summary"].get(
                "grant_send_on_behalf_to_with_display_names", []),
    }


# ------------------------------------------------------ folder permissions
def list_folder_permissions(client, mailbox: str, folder: str = "Calendar",
                            result_size: int = 0) -> dict:
    identity = _folder_identity(mailbox, folder)
    params: Dict[str, Any] = {"Identity": identity}
    if int(result_size or 0) > 0:
        params["ResultSize"] = c.validate_int(result_size, "result_size", minimum=1)
    data = client.post_exchange("MailboxFolderPermission",
                                _cmdlet("Get-MailboxFolderPermission", params),
                                anchor_mailbox=_mailbox_ref(mailbox))
    rows = [p for p in _as_list(data) if isinstance(p, dict)]
    return {
        "mailbox": mailbox,
        "folder": folder,
        "identity": identity,
        "count": len(rows),
        "permissions": [_summarize_folder_permission(p) for p in rows],
    }


def _folder_write(client, cmdlet_name: str, mailbox: str, folder: str,
                  user: str, *, access_rights: Any = None,
                  sharing_flags: Any = None,
                  send_notification_to_user: Optional[bool] = None) -> dict:
    identity = _folder_identity(mailbox, folder)
    params: Dict[str, Any] = {"Identity": identity, "User": _principal(user, "user")}
    if access_rights is not None:
        params["AccessRights"] = access_rights
    if sharing_flags is not None:
        params["SharingPermissionFlags"] = sharing_flags
    if send_notification_to_user is not None:
        params["SendNotificationToUser"] = c.validate_bool(
            send_notification_to_user, "send_notification_to_user")
    client.post_exchange("MailboxFolderPermission",
                         _cmdlet(cmdlet_name, params),
                         anchor_mailbox=_mailbox_ref(mailbox))
    after = list_folder_permissions(client, mailbox, folder)
    return {
        "mailbox": mailbox,
        "folder": folder,
        "identity": identity,
        "user": params["User"],
        "applied": True,
        "access_rights": after["permissions"],
        "summary": after,
    }


def add_folder_permission(client, mailbox: str, folder: str, user: str,
                          access_rights: Any, sharing_flags: Any = None,
                          send_notification_to_user: Optional[bool] = None) -> dict:
    return _folder_write(
        client, "Add-MailboxFolderPermission", mailbox, folder, user,
        access_rights=_access_rights(access_rights),
        sharing_flags=_flags(sharing_flags),
        send_notification_to_user=send_notification_to_user)


def set_folder_permission(client, mailbox: str, folder: str, user: str,
                          access_rights: Any, sharing_flags: Any = None,
                          send_notification_to_user: Optional[bool] = None) -> dict:
    return _folder_write(
        client, "Set-MailboxFolderPermission", mailbox, folder, user,
        access_rights=_access_rights(access_rights),
        sharing_flags=_flags(sharing_flags),
        send_notification_to_user=send_notification_to_user)


def remove_folder_permission(client, mailbox: str, folder: str, user: str,
                             send_notification_to_user: Optional[bool] = None) -> dict:
    return _folder_write(
        client, "Remove-MailboxFolderPermission", mailbox, folder, user,
        send_notification_to_user=send_notification_to_user)


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def get_mailbox_delegation(mailbox: str, result_size: int = 0,
                               include_display_names: bool = True) -> dict:
        """Read a mailbox's Send-on-Behalf (delegation) configuration.

        `mailbox` is a UPN, alias or display name. Returns the mailbox
        properties and its ``GrantSendOnBehalfTo`` delegate list (with display
        names when available). Uses the **Exchange Online Admin API**
        (Get-Mailbox); requires the Exchange.ManageAsAppV2 permission + an
        Exchange RBAC role -- not a Graph scope."""
        return get_mailbox(get_client(config), mailbox, result_size,
                           include_display_names)

    @mcp.tool()
    def set_mailbox_send_on_behalf(mailbox: str, delegates: List[str],
                                   mode: str = "overwrite",
                                   confirm: bool = False) -> dict:
        """Set the **Send on Behalf** delegates for a mailbox.

        `mailbox` is a UPN/alias/name; `delegates` is a list of SMTP addresses.
        `mode` is ``overwrite`` (replace the whole list), ``add`` or ``remove``.
        Mutating: requires `confirm=True`. Requires the Exchange.ManageAsAppV2
        permission + an Exchange RBAC role."""
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"mailbox": mailbox, "updated": False,
                    "message": "Refusing to change delegation without confirm=True."}
        return set_send_on_behalf(client, mailbox, delegates, mode)

    @mcp.tool()
    def add_mailbox_send_on_behalf(mailbox: str, delegates: List[str],
                                   confirm: bool = False) -> dict:
        """Add one or more **Send on Behalf** delegates to a mailbox.

        `delegates` is a list of SMTP addresses. Mutating: requires
        `confirm=True`. Requires the Exchange.ManageAsAppV2 permission + an
        Exchange RBAC role."""
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"mailbox": mailbox, "updated": False,
                    "message": "Refusing to change delegation without confirm=True."}
        return set_send_on_behalf(client, mailbox, delegates, "add")

    @mcp.tool()
    def remove_mailbox_send_on_behalf(mailbox: str, delegates: List[str],
                                      confirm: bool = False) -> dict:
        """Remove one or more **Send on Behalf** delegates from a mailbox.

        `delegates` is a list of SMTP addresses. Mutating: requires
        `confirm=True`. Requires the Exchange.ManageAsAppV2 permission + an
        Exchange RBAC role."""
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"mailbox": mailbox, "updated": False,
                    "message": "Refusing to change delegation without confirm=True."}
        return set_send_on_behalf(client, mailbox, delegates, "remove")

    @mcp.tool()
    def list_mailbox_folder_permissions(mailbox: str, folder: str = "Calendar",
                                        result_size: int = 0) -> dict:
        """List the folder permissions (delegates) on a mailbox folder.

        `identity` is ``<mailbox>:\\<folder>``. `folder` defaults to
        ``Calendar`` (also common: ``Inbox``, ``Contacts``). Uses the Exchange
        Online Admin API (Get-MailboxFolderPermission); requires the
        Exchange.ManageAsAppV2 permission + an Exchange RBAC role."""
        return list_folder_permissions(get_client(config), mailbox, folder,
                                       result_size)

    @mcp.tool()
    def add_mailbox_folder_permission(
        mailbox: str, folder: str, user: str, access_rights: str,
        sharing_permission_flags: str = "",
        send_notification_to_user: bool = False, confirm: bool = False,
    ) -> dict:
        """Grant a user/group permission on a mailbox folder (e.g. the Calendar).

        `folder` default usage: ``Calendar``. `user` is a UPN/email or a
        well-known principal (``Default``). `access_rights` is a role
        (``Reviewer``/``Editor``/``PublishingEditor``) or a comma-separated list
        of granular rights. `sharing_permission_flags` (Calendar only):
        ``ViewPrivateItems`` and/or ``ReceiveCopiesOfMeetingMessages``.
        Mutating: requires `confirm=True`. Requires the Exchange.ManageAsAppV2
        permission + an Exchange RBAC role. NOTE: this delegates a *folder*, not
        mailbox-level Full Access -- see the module docstring."""
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"mailbox": mailbox, "applied": False,
                    "message": "Refusing to change folder permissions without confirm=True."}
        return add_folder_permission(
            client, mailbox, folder, user, access_rights,
            sharing_permission_flags, send_notification_to_user)

    @mcp.tool()
    def set_mailbox_folder_permission(
        mailbox: str, folder: str, user: str, access_rights: str,
        sharing_permission_flags: str = "",
        send_notification_to_user: bool = False, confirm: bool = False,
    ) -> dict:
        """Change an existing user's permission on a mailbox folder.

        Same arguments as ``add_mailbox_folder_permission``; use when the
        grantee already has a permission entry. Mutating: requires
        `confirm=True`. Requires the Exchange.ManageAsAppV2 permission + an
        Exchange RBAC role."""
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"mailbox": mailbox, "applied": False,
                    "message": "Refusing to change folder permissions without confirm=True."}
        return set_folder_permission(
            client, mailbox, folder, user, access_rights,
            sharing_permission_flags, send_notification_to_user)

    @mcp.tool()
    def remove_mailbox_folder_permission(
        mailbox: str, folder: str, user: str,
        send_notification_to_user: bool = False, confirm: bool = False,
    ) -> dict:
        """Remove a user's/group's permission from a mailbox folder.

        Mutating: requires `confirm=True`. Requires the Exchange.ManageAsAppV2
        permission + an Exchange RBAC role."""
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"mailbox": mailbox, "applied": False,
                    "message": "Refusing to change folder permissions without confirm=True."}
        return remove_folder_permission(
            client, mailbox, folder, user, send_notification_to_user)
