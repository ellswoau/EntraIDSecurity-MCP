"""Group / distribution-list / mail-enabled-group membership tools.

Covers adding and removing members of Microsoft 365 groups, distribution
lists, mail-enabled security groups and Teams (a Team is backed by a unified
Microsoft 365 group). Membership is changed through the group's ``members``
navigation property.

    GET    /groups                                                    (discover)
    GET    /groups/{id}/members                                       (read)
    POST   /groups/{id}/members/$ref                                  (add)
    DELETE /groups/{id}/members/{memberId}/$ref                       (remove)

Requires ``Group.ReadWrite.All`` (and ``Directory.Read.All`` to list groups).
Removing a user from a *backed-by-group* mailbox or a Team group strips the
membership the group grants; it does not touch Exchange mailbox-level
delegation (see ``mailbox_tools`` for that caveat).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c

GROUP_SELECT = "id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,visibility"


def _summarize_group(g: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(g, dict):
        return {}
    types = g.get("groupTypes") or []
    return {
        "id": g.get("id"),
        "display_name": g.get("displayName"),
        "description": g.get("description"),
        "mail": g.get("mail"),
        "mail_enabled": g.get("mailEnabled"),
        "security_enabled": g.get("securityEnabled"),
        "group_types": types,
        # A unified group backs a Microsoft 365 group/Team; a plain
        # security/mail-enabled group does not.
        "is_unified": "Unified" in types,
        "is_team": "Unified" in types,
        "visibility": g.get("visibility"),
    }


def _find_group_ids_by_mail(client, mail: str, max_pages: int) -> List[str]:
    """Resolve a group's MAIL (email address) to its object id(s)."""
    filt = f"mail eq {c.odata_quote(mail)}"
    items, _ = client.collect("/groups", params={"$filter": filt,
                                                 "$select": "id,displayName,mail"},
                              max_pages=max_pages)
    return [g.get("id") for g in items if isinstance(g, dict) and g.get("id")]


def _resolve_group_id(client, group: str, max_pages: int) -> str:
    """Resolve a group reference (object id, UPN/email, or display name) to id."""
    s = str(group or "").strip()
    if not s:
        raise ValueError("group is required (an object id, mail address, or display name).")
    if c._GUID_RE.match(s):
        return s
    if "@" in s:
        ids = _find_group_ids_by_mail(client, s, max_pages)
        if not ids:
            raise ValueError(f"No group found with mail {s!r}.")
        if len(ids) > 1:
            raise ValueError(
                f"{len(ids)} groups share the mail {s!r}: {ids}. Pass the object id.")
        return ids[0]
    # Display-name lookup (exact match preferred, then substring-free fallback).
    items, _ = client.collect(
        "/groups", params={"$filter": f"displayName eq {c.odata_quote(s)}",
                           "$select": "id,displayName"}, max_pages=max_pages)
    exact = [g["id"] for g in items if isinstance(g, dict) and g.get("id")]
    if len(exact) == 1:
        return exact[0]
    if not exact:
        items, _ = client.collect(
            "/groups",
            params={"$filter": f"startswith(displayName,{c.odata_quote(s)})",
                    "$select": "id,displayName"}, max_pages=max_pages)
        exact = [g["id"] for g in items if isinstance(g, dict) and g.get("id")]
    if not exact:
        raise ValueError(f"No group matched {s!r} by id, mail or display name.")
    if len(exact) > 1:
        raise ValueError(
            f"{len(exact)} groups matched {s!r}: {exact}. Pass the object id.")
    return exact[0]


def _resolve_member_id(client, member: str) -> str:
    """Resolve a member reference (object id or UPN/email) to an object id."""
    s = str(member or "").strip()
    if not s:
        raise ValueError("member is required (an object id or userPrincipalName).")
    if c._GUID_RE.match(s):
        return s
    if "@" not in s:
        raise ValueError(
            f"Invalid member: {member!r} (expected an object id or a "
            "userPrincipalName such as 'user@contoso.com').")
    data = client.get(f"/users/{c.validate_user_ref(s)}", params={"$select": "id"})
    if not isinstance(data, dict) or not data.get("id"):
        raise ValueError(f"No user found for {s!r}.")
    return data["id"]


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def list_groups(
        query: str = "", mail_enabled: Optional[bool] = None,
        security_enabled: Optional[bool] = None, unified_only: bool = False,
        max_pages: int = 1,
    ) -> dict:
        """List Microsoft 365 / security / distribution groups so a group's
        object id or mail can be found before managing membership.

        `query` filters by display-name prefix. `mail_enabled`,
        `security_enabled` and `unified_only` narrow the set (a unified group
        backs a Microsoft 365 group/Team; mail-enabled lists are the
        distribution lists). Requires Directory.Read.All."""
        client = get_client(config)
        clauses = []
        if query and str(query).strip():
            clauses.append(f"startswith(displayName,{c.odata_quote(str(query).strip())})")
        if mail_enabled is not None:
            clauses.append(f"mailEnabled eq {'true' if c.validate_bool(mail_enabled, 'mail_enabled') else 'false'}")
        if security_enabled is not None:
            clauses.append(f"securityEnabled eq {'true' if c.validate_bool(security_enabled, 'security_enabled') else 'false'}")
        if c.validate_bool(unified_only, "unified_only"):
            clauses.append("groupTypes/any(gt:gt eq 'Unified')")
        params: Dict[str, Any] = {"$select": GROUP_SELECT, "$top": 100}
        filt = c.join_filters(clauses)
        if filt:
            params["$filter"] = filt
        items, next_link = client.collect("/groups", params=params,
                                          max_pages=max_pages)
        groups = [_summarize_group(g) for g in items if isinstance(g, dict)]
        return {
            "count": len(groups),
            "groups": groups,
            "more_results": bool(next_link),
        }

    @mcp.tool()
    def get_group(group: str, max_pages: int = 3) -> dict:
        """Return one group's profile (object id, mail, type, unified/Team flag).

        `group` may be an object id (GUID), a mail address, or a display name.
        Requires Directory.Read.All."""
        client = get_client(config)
        gid = _resolve_group_id(client, group, max_pages)
        data = client.get(f"/groups/{gid}", params={"$select": GROUP_SELECT})
        return {"group": group, "group_id": gid, "found": bool(data),
                "summary": _summarize_group(data or {}), "profile": data}

    @mcp.tool()
    def list_group_members(
        group: str, max_pages: int = 1, include_raw: bool = False,
    ) -> dict:
        """List the members of a group / distribution list / Team.

        `group` may be an object id (GUID), a mail address, or a display name.
        Returns each member's id, display name and type. Requires at least
        Directory.Read.All (GroupMember.Read.All for the membership)."""
        client = get_client(config)
        gid = _resolve_group_id(client, group, max_pages)
        items, next_link = client.collect(
            f"/groups/{gid}/members",
            params={"$select": "id,displayName,userPrincipalName,mail", "$top": 100},
            max_pages=max_pages)
        members = []
        for m in items:
            if not isinstance(m, dict):
                continue
            otype = m.get("@odata.type") or m.get("odata.type")
            members.append({
                "id": m.get("id"),
                "display_name": m.get("displayName"),
                "user_principal_name": m.get("userPrincipalName"),
                "mail": m.get("mail"),
                "type": otype.rsplit(".", 1)[-1] if isinstance(otype, str) else None,
            })
        out: Dict[str, Any] = {
            "group": group, "group_id": gid, "count": len(members),
            "members": members, "more_results": bool(next_link),
        }
        if include_raw:
            out["raw"] = items
        return out

    @mcp.tool()
    def add_group_member(group: str, member: str, max_pages: int = 3) -> dict:
        """Add a user to a group / distribution list / Team (membership).

        `group` may be an object id (GUID), a mail address, or a display name.
        `member` is a user object id (GUID) or userPrincipalName. POSTs an
        ``@odata.id`` reference to ``/groups/{id}/members/$ref``. Requires
        Group.ReadWrite.All."""
        client = get_client(config)
        gid = _resolve_group_id(client, group, max_pages)
        mid = _resolve_member_id(client, member)
        body = {"@odata.id":
                f"{client.base_url}/directoryObjects/{mid}"}
        client.post(f"/groups/{gid}/members/$ref", body)
        # Graph returns 204; verify by re-reading membership and re-raise if
        # the add silently 400'd on an already-present member.
        members, _ = client.collect(
            f"/groups/{gid}/members", params={"$select": "id"}, max_pages=1)
        present = any(isinstance(m, dict) and m.get("id") == mid for m in members)
        return {
            "group": group, "group_id": gid, "member": member,
            "member_id": mid, "added": True, "verified_present": present,
        }

    @mcp.tool()
    def remove_group_member(group: str, member: str, max_pages: int = 3) -> dict:
        """Remove a user from a group / distribution list / Team (membership).

        `group` may be an object id (GUID), a mail address, or a display name.
        `member` is a user object id (GUID) or userPrincipalName. DELETEs the
        member reference at ``/groups/{id}/members/{memberId}/$ref``. Requires
        Group.ReadWrite.All."""
        client = get_client(config)
        gid = _resolve_group_id(client, group, max_pages)
        mid = _resolve_member_id(client, member)
        client.delete(f"/groups/{gid}/members/{mid}/$ref")
        members, _ = client.collect(
            f"/groups/{gid}/members", params={"$select": "id"}, max_pages=1)
        still = any(isinstance(m, dict) and m.get("id") == mid for m in members)
        return {
            "group": group, "group_id": gid, "member": member,
            "member_id": mid, "removed": True, "verified_absent": not still,
        }
