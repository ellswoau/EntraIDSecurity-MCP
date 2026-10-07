"""Microsoft Teams membership tools (owners + members).

A Team is backed by a **unified** Microsoft 365 group, so its membership (owners
and members) is managed through the backing group's navigation properties --
this is fully supported app-only and is the same surface ``group_tools`` uses:

    GET    /groups?$filter=resourceProvisioningOptions/Any(c:c eq 'Team')
    GET    /groups/{id}/owners            POST .../owners/$ref
    DELETE /groups/{id}/owners/{id}/$ref
    GET    /groups/{id}/members           POST .../members/$ref
    DELETE /groups/{id}/members/{id}/$ref
    GET    /teams/{id}/channels           (read-only convenience)

*Owners* are the Team-level equivalent of a "site owner" and are the genuinely
new capability here; *members* overlap ``add_group_member`` / ``remove_group_member``
(kept here, Team-scoped, for symmetry).

Requires ``Group.ReadWrite.All`` (owners/members writes) and
``Directory.Read.All`` / ``Group.Read.All`` (listing). Channel *member* management
(``ChannelMember.ReadWrite.All``) is not modelled here.

AUTHORIZATION (same lane as group membership -- see the ``entra-id-ops`` gate)
  A request is not a mandate. Establish standing before any write: the Team
  owner, or the manager / leadership of the department the Team serves, must
  approve. A user can never add themselves, including when the requester is
  IT / Help Desk staff. Every mutating tool refuses unless ``confirm=True``,
  which is the point at which you record *who approved it*.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c
from .group_tools import _resolve_group_id, _resolve_member_id, _summarize_group

GROUP_SELECT = ("id,displayName,description,mail,mailEnabled,securityEnabled,"
                "groupTypes,visibility,resourceProvisioningOptions")

_AUTH_NOTE = (
    "AUTHORIZATION: a request is not a mandate. Before changing Team access, "
    "confirm standing -- the Team owner, or the manager/leadership of the "
    "department the Team serves, must approve; a user can never add themselves "
    "(including IT/Help Desk staff). Re-call with confirm=True once that approval "
    "is recorded."
)

_TEAM_FILTER = "resourceProvisioningOptions/Any(c:c eq 'Team')"


def _is_team(g: Dict[str, Any]) -> bool:
    opts = g.get("resourceProvisioningOptions") or []
    return isinstance(opts, list) and "Team" in opts


def _resolve_team_id(client, team: str, max_pages: int) -> str:
    """Resolve a Team reference to the backing group id, confirming it is a Team."""
    gid = _resolve_group_id(client, team, max_pages)
    g = client.get(f"/groups/{gid}", params={"$select": GROUP_SELECT})
    if not isinstance(g, dict) or not _is_team(g):
        raise ValueError(
            f"{team!r} resolves to group {gid}, which is not a Team "
            "(no 'Team' resourceProvisioningOption). Use the group tools for a "
            "plain group / distribution list.")
    return gid


def _summarize_principal(p: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(p, dict):
        return {}
    otype = p.get("@odata.type") or p.get("odata.type")
    return {
        "id": p.get("id"),
        "display_name": p.get("displayName"),
        "user_principal_name": p.get("userPrincipalName"),
        "mail": p.get("mail"),
        "type": otype.rsplit(".", 1)[-1] if isinstance(otype, str) else None,
    }


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def list_teams(query: str = "", max_pages: int = 1) -> dict:
        """List Microsoft Teams (unified groups with Teams provisioned).

        `query` filters by display-name prefix. Returns each Team's backing group
        id (used by the other Team tools), name, mail and visibility.
        Requires Directory.Read.All / Group.Read.All."""
        client = get_client(config)
        clauses = [_TEAM_FILTER]
        if query and str(query).strip():
            clauses.append(
                f"startswith(displayName,{c.odata_quote(str(query).strip())})")
        params: Dict[str, Any] = {"$select": GROUP_SELECT, "$top": 100,
                                  "$filter": " and ".join(clauses)}
        items, next_link = client.collect("/groups", params=params,
                                          max_pages=max_pages)
        teams = []
        for g in items:
            if isinstance(g, dict) and _is_team(g):
                summary = _summarize_group(g)
                summary["resource_provisioning_options"] = g.get(
                    "resourceProvisioningOptions")
                teams.append(summary)
        return {"query": query, "count": len(teams), "teams": teams,
                "more_results": bool(next_link)}

    @mcp.tool()
    def get_team(team: str, max_pages: int = 3) -> dict:
        """Return one Team's profile (backing group id, name, visibility).

        `team` may be a backing group object id (GUID), a mail address, or a
        display name. Requires Directory.Read.All / Group.Read.All."""
        client = get_client(config)
        gid = _resolve_team_id(client, team, max_pages)
        g = client.get(f"/groups/{gid}", params={"$select": GROUP_SELECT})
        summary = _summarize_group(g or {})
        summary["resource_provisioning_options"] = (g or {}).get(
            "resourceProvisioningOptions")
        return {"team": team, "group_id": gid, "found": bool(g),
                "summary": summary, "profile": g}

    @mcp.tool()
    def list_team_owners(team: str, max_pages: int = 1) -> dict:
        """List a Team's OWNERS (the backing group's owners).

        `team` may be a backing group object id (GUID), a mail address, or a
        display name. Requires Directory.Read.All / Group.Read.All."""
        client = get_client(config)
        gid = _resolve_team_id(client, team, max_pages)
        items, next_link = client.collect(
            f"/groups/{gid}/owners",
            params={"$select": "id,displayName,userPrincipalName,mail",
                    "$top": 100}, max_pages=max_pages)
        owners = [_summarize_principal(o) for o in items
                  if isinstance(o, dict)]
        return {"team": team, "group_id": gid, "count": len(owners),
                "owners": owners, "more_results": bool(next_link)}

    @mcp.tool()
    def list_team_members(team: str, max_pages: int = 1) -> dict:
        """List a Team's MEMBERS (the backing group's members).

        `team` may be a backing group object id (GUID), a mail address, or a
        display name. Requires Directory.Read.All / Group.Read.All."""
        client = get_client(config)
        gid = _resolve_team_id(client, team, max_pages)
        items, next_link = client.collect(
            f"/groups/{gid}/members",
            params={"$select": "id,displayName,userPrincipalName,mail",
                    "$top": 100}, max_pages=max_pages)
        members = [_summarize_principal(m) for m in items
                   if isinstance(m, dict)]
        return {"team": team, "group_id": gid, "count": len(members),
                "members": members, "more_results": bool(next_link)}

    @mcp.tool()
    def list_team_channels(team: str, max_pages: int = 1) -> dict:
        """List a Team's channels (read-only). Requires Group.Read.All and
        Team.ReadBasic.All."""
        client = get_client(config)
        gid = _resolve_team_id(client, team, max_pages)
        items, next_link = client.collect(
            f"/teams/{gid}/channels",
            params={"$select": "id,displayName,description,membershipType,"
                               "webUrl", "$top": 100}, max_pages=max_pages)
        channels = []
        for ch in items:
            if not isinstance(ch, dict):
                continue
            channels.append({
                "id": ch.get("id"),
                "display_name": ch.get("displayName"),
                "description": ch.get("description"),
                "membership_type": ch.get("membershipType"),
                "web_url": ch.get("webUrl"),
            })
        return {"team": team, "group_id": gid, "count": len(channels),
                "channels": channels, "more_results": bool(next_link)}

    @mcp.tool()
    def add_team_owner(team: str, user: str, max_pages: int = 3,
                       confirm: bool = False) -> dict:
        """Add a user as an OWNER of a Team.

        `team` may be a backing group object id (GUID), a mail address, or a
        display name; `user` is a user object id (GUID) or userPrincipalName.
        POSTs an ``@odata.id`` reference to ``/groups/{id}/owners/$ref``. Set
        `confirm=True` to apply. Requires Group.ReadWrite.All.

        """ + _AUTH_NOTE
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"team": team, "user": user, "owner_added": False,
                    "message": "Refusing to add a Team owner without confirm=True. "
                               + _AUTH_NOTE}
        gid = _resolve_team_id(client, team, max_pages)
        uid = _resolve_member_id(client, user)
        body = {"@odata.id": f"{client.base_url}/directoryObjects/{uid}"}
        client.post(f"/groups/{gid}/owners/$ref", body)
        owners, _ = client.collect(
            f"/groups/{gid}/owners", params={"$select": "id"}, max_pages=1)
        present = any(isinstance(o, dict) and o.get("id") == uid for o in owners)
        return {"team": team, "group_id": gid, "user": user, "user_id": uid,
                "owner_added": True, "verified_owner": present}

    @mcp.tool()
    def remove_team_owner(team: str, user: str, max_pages: int = 3,
                          confirm: bool = False) -> dict:
        """Remove a user as an OWNER of a Team.

        `team` may be a backing group object id (GUID), a mail address, or a
        display name; `user` is a user object id (GUID) or userPrincipalName.
        DELETEs the reference at ``/groups/{id}/owners/{memberId}/$ref``. Set
        `confirm=True` to apply. Requires Group.ReadWrite.All.

        """ + _AUTH_NOTE
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"team": team, "user": user, "owner_removed": False,
                    "message": "Refusing to remove a Team owner without "
                               "confirm=True. " + _AUTH_NOTE}
        gid = _resolve_team_id(client, team, max_pages)
        uid = _resolve_member_id(client, user)
        client.delete(f"/groups/{gid}/owners/{uid}/$ref")
        owners, _ = client.collect(
            f"/groups/{gid}/owners", params={"$select": "id"}, max_pages=1)
        still = any(isinstance(o, dict) and o.get("id") == uid for o in owners)
        return {"team": team, "group_id": gid, "user": user, "user_id": uid,
                "owner_removed": True, "verified_absent": not still}

    @mcp.tool()
    def add_team_member(team: str, user: str, max_pages: int = 3,
                        confirm: bool = False) -> dict:
        """Add a user as a MEMBER of a Team (backing group membership).

        Equivalent to ``add_group_member`` but Team-scoped. `team` may be a
        backing group object id (GUID), a mail address, or a display name;
        `user` is a user object id (GUID) or userPrincipalName. Set
        `confirm=True` to apply. Requires Group.ReadWrite.All.

        """ + _AUTH_NOTE
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"team": team, "user": user, "member_added": False,
                    "message": "Refusing to add a Team member without "
                               "confirm=True. " + _AUTH_NOTE}
        gid = _resolve_team_id(client, team, max_pages)
        uid = _resolve_member_id(client, user)
        body = {"@odata.id": f"{client.base_url}/directoryObjects/{uid}"}
        client.post(f"/groups/{gid}/members/$ref", body)
        members, _ = client.collect(
            f"/groups/{gid}/members", params={"$select": "id"}, max_pages=1)
        present = any(isinstance(m, dict) and m.get("id") == uid for m in members)
        return {"team": team, "group_id": gid, "user": user, "user_id": uid,
                "member_added": True, "verified_member": present}

    @mcp.tool()
    def remove_team_member(team: str, user: str, max_pages: int = 3,
                           confirm: bool = False) -> dict:
        """Remove a user as a MEMBER of a Team (backing group membership).

        Equivalent to ``remove_group_member`` but Team-scoped. `team` may be a
        backing group object id (GUID), a mail address, or a display name;
        `user` is a user object id (GUID) or userPrincipalName. Set
        `confirm=True` to apply. Requires Group.ReadWrite.All.

        """ + _AUTH_NOTE
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"team": team, "user": user, "member_removed": False,
                    "message": "Refusing to remove a Team member without "
                               "confirm=True. " + _AUTH_NOTE}
        gid = _resolve_team_id(client, team, max_pages)
        uid = _resolve_member_id(client, user)
        client.delete(f"/groups/{gid}/members/{uid}/$ref")
        members, _ = client.collect(
            f"/groups/{gid}/members", params={"$select": "id"}, max_pages=1)
        still = any(isinstance(m, dict) and m.get("id") == uid for m in members)
        return {"team": team, "group_id": gid, "user": user, "user_id": uid,
                "member_removed": True, "verified_absent": not still}
