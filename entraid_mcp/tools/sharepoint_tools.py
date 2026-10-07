"""SharePoint site / document-library / folder permission tools.

What Microsoft Graph v1.0 can and cannot do for SharePoint permissions:

  * Find sites ................ ``GET /sites?search=`` and ``GET /sites/{id}``
  * List libraries / drives ... ``GET /sites/{id}/drives``
  * List folders / files ...... ``/drives/{drive}/root:/{path}`` and ``.../children``
  * Read folder/file perms .... ``GET /drives/{drive}/items/{item}/permissions``
  * GRANT a user on a folder .. ``POST /drives/{drive}/items/{item}/invite``
                                (roles read | write | owner)
  * REVOKE on a folder ........ ``DELETE /drives/{drive}/items/{item}/permissions/{perm}``
  * Site permissions .......... ``GET/POST/PATCH/DELETE /sites/{id}/permissions``
                                -- but v1.0 only creates/updates an **application**
                                permission here ("you can't use it to create a new
                                user site permission").

Two consequences callers must know:

  1. **A user's access to a site/folder is granted with the driveItem ``invite``
     API, not with site permissions.** Site-level ``permissions`` are for
     *applications* (and sharing links); ``list_sharepoint_site_permissions`` /
     ``update_sharepoint_site_permission`` / ``remove_sharepoint_site_permission``
     manage those, which is what you audit or revoke when hunting a leaked
     sharing link.
  2. **Adding a person as a SharePoint *site-collection owner* is NOT exposed by
     Graph v1.0.** Site-collection admins/owners are a SharePoint concept
     (``Set-PnPSite -Owners`` / the SharePoint admin center / SharePoint REST
     ``/_api/web/...``), not a Microsoft Graph one. To grant access to a *library
     or folder* use ``invite_to_sharepoint_item`` with ``role="owner"``.

Permissions (application, admin-consented):
  * ``Sites.Read.All``       -- list/read sites, drives and items.
  * ``Files.ReadWrite.All``  -- the driveItem ``invite``/permission reads+writes
                                (least privilege per Microsoft's docs).
  * ``Sites.FullControl.All`` -- manage **site** permissions (list/update/delete
                                application permissions & sharing links).
  ``Sites.Selected`` is the least-privilege alternative for a scoped deployment
  (the app is granted access per-site/list by a SharePoint admin).

AUTHORIZATION (same lane as group membership -- see the ``entra-id-ops`` gate)
  A request is not a mandate. Establish standing before any write: the site /
  library / folder owner, or the manager / leadership of the department the site
  serves, must approve. A user can never grant themselves access, including when
  the requester is IT / Help Desk staff. Every mutating tool below refuses unless
  ``confirm=True``, which is the point at which you record *who approved it*.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional
from urllib.parse import quote, urlsplit

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c

SITE_SELECT = ("id,name,displayName,webUrl,description,createdDateTime,"
               "lastModifiedDateTime")
DRIVE_SELECT = "id,name,driveType,webUrl,description"
ITEM_SELECT = ("id,name,webUrl,folder,file,size,createdDateTime,"
               "lastModifiedDateTime,parentReference")

# Roles accepted when inviting a user to a driveItem (folder/file).
ITEM_ROLES = ("read", "write", "owner")
# Roles accepted on a site permission (application permissions / sharing links).
SITE_ROLES = ("read", "write", "owner", "fullControl")

_AUTH_NOTE = (
    "AUTHORIZATION: a request is not a mandate. Before granting or removing access, "
    "confirm standing -- the site/library/folder owner, or the manager/leadership of "
    "the department the site serves, must approve; a user can never request access "
    "for themselves (including IT/Help Desk staff). Re-call with confirm=True once "
    "that approval is recorded."
)


# ------------------------------------------------------------------- helpers
def _clean_drive(drive: str) -> str:
    s = str(drive or "").strip()
    if not s:
        raise ValueError(
            "drive_id is required (a drive id from list_sharepoint_libraries, "
            "e.g. 'b!...').")
    if any(ch in s for ch in " \t\n\r?#/"):
        raise ValueError(f"Invalid drive_id: {drive!r}.")
    return quote(s, safe="!")


def _encode_path(path: str) -> str:
    """Encode a folder path under a drive root (each segment URL-encoded)."""
    parts = [p for p in str(path or "").strip().strip("/").split("/") if p]
    for p in parts:
        if any(ch in p for ch in "\\?#%"):
            raise ValueError(f"Invalid folder path segment: {p!r}.")
    return "/".join(quote(p, safe="") for p in parts)


def _site_ref(site: str) -> str:
    """Normalize a site reference into a Graph ``/sites/{...}`` path segment.

    Accepts an object id / composite id (``host,guid,guid``), a full URL
    (``https://host/sites/x``), or a ``host:/path`` reference.
    """
    s = str(site or "").strip()
    if not s:
        raise ValueError(
            "site is required (an object id, a site URL, or 'host:/path').")
    if s.startswith("http://") or s.startswith("https://"):
        parts = urlsplit(s)
        host = parts.netloc
        path = parts.path or "/"
        return f"{host}:/{path.lstrip('/')}"
    if ":/" in s:
        host, _, path = s.partition(":/")
        return f"{host}:/{path.lstrip('/')}"
    if any(ch in s for ch in " \t\n\r?#"):
        raise ValueError(f"Invalid site reference: {site!r}.")
    return quote(s, safe=",!")


def _item_path(drive: str, folder_path: str) -> str:
    enc = _encode_path(folder_path)
    return f"/drives/{drive}/root" + (f":/{enc}" if enc else "")


def _resolve_item_id(client, drive: str, item_id: str, folder_path: str) -> str:
    """Resolve a driveItem id from an explicit id or a folder path."""
    if str(item_id or "").strip():
        return str(item_id).strip()
    data = client.get(_item_path(drive, folder_path),
                      params={"$select": "id,name,webUrl,folder"})
    if not isinstance(data, dict) or not data.get("id"):
        raise ValueError(
            f"No folder/file found at path {folder_path!r} in drive {drive!r}.")
    return data["id"]


def _summarize_item(item: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    parent = item.get("parentReference") or {}
    is_folder = isinstance(item.get("folder"), dict)
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "web_url": item.get("webUrl"),
        "is_folder": is_folder,
        "child_count": (item.get("folder") or {}).get("childCount")
            if is_folder else None,
        "size": item.get("size"),
        "created_date_time": item.get("createdDateTime"),
        "last_modified_date_time": item.get("lastModifiedDateTime"),
        "parent_path": parent.get("path") if isinstance(parent, dict) else None,
        "drive_id": parent.get("driveId") if isinstance(parent, dict) else None,
    }


def _summarize_drive(d: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(d, dict):
        return {}
    return {
        "id": d.get("id"),
        "name": d.get("name"),
        "drive_type": d.get("driveType"),
        "web_url": d.get("webUrl"),
        "description": d.get("description"),
    }


def _identity_of(identity_set: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a grantedTo/grantedToIdentities identity set into a summary."""
    if not isinstance(identity_set, dict):
        return {}
    out: Dict[str, Any] = {}
    for key in ("user", "group", "application", "device", "siteGroup",
                "siteUser"):
        ident = identity_set.get(key)
        if isinstance(ident, dict):
            out[key] = {
                "id": ident.get("id"),
                "display_name": ident.get("displayName"),
                "email": ident.get("email"),
                "login_name": ident.get("loginName"),
            }
    return out


def _summarize_permission(perm: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(perm, dict):
        return {}
    identities = (perm.get("grantedToIdentitiesV2")
                  or perm.get("grantedToIdentities") or [])
    single = perm.get("grantedToV2") or perm.get("grantedTo") or {}
    link = perm.get("link") or {}
    invitation = perm.get("invitation") or {}
    return {
        "id": perm.get("id"),
        "roles": perm.get("roles"),
        "granted_to": _identity_of(single) if single else {},
        "granted_to_identities": [_identity_of(i) for i in identities
                                  if isinstance(i, dict)],
        "link": {
            "type": link.get("type"),
            "scope": link.get("scope"),
            "web_url": link.get("webUrl"),
            "prevents_download": link.get("preventsDownload"),
        } if isinstance(link, dict) and link else None,
        "invitation": {
            "email": invitation.get("email"),
            "sign_in_required": invitation.get("signInRequired"),
        } if isinstance(invitation, dict) and invitation else None,
        "inherited_from": perm.get("inheritedFrom"),
    }


def _resolve_site_id(client, site: str) -> str:
    """Return a concrete site id, resolving a URL/``host:/path`` reference."""
    ref = _site_ref(site)
    if ":/" in ref:  # host:/path -> look it up to get the canonical id
        data = client.get(f"/sites/{ref}", params={"$select": "id,name,webUrl"})
        if not isinstance(data, dict) or not data.get("id"):
            raise ValueError(f"No SharePoint site found for {site!r}.")
        return data["id"]
    return ref


def _resolve_drive_id(client, site: str, library: str) -> str:
    """Resolve a document library name (or id) to a drive id for a site."""
    sid = _resolve_site_id(client, site)
    name = str(library or "").strip()
    if name and name.startswith("b!") and " " not in name:
        return name
    drives, _ = client.collect(f"/sites/{sid}/drives",
                               params={"$select": DRIVE_SELECT, "$top": 100},
                               max_pages=1)
    docs = [d for d in drives if isinstance(d, dict)]
    if name:
        for d in docs:
            if str(d.get("name", "")).lower() == name.lower():
                return d.get("id")
        # Fall back to a drive *id* match, then a prefix match.
        for d in docs:
            if str(d.get("id", "")).lower() == name.lower():
                return d.get("id")
        raise ValueError(
            f"No document library named {library!r} on the site. Libraries: "
            + ", ".join(repr(d.get("name")) for d in docs))
    for d in docs:
        if d.get("driveType") == "documentLibrary":
            return d.get("id")
    if docs:
        return docs[0].get("id")
    raise ValueError("The site has no document libraries (drives).")


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def list_sharepoint_sites(query: str = "*", max_pages: int = 1) -> dict:
        """List/find SharePoint sites (site collections).

        `query` is a search term; the default ``*`` lists all sites. Returns
        each site's id (needed by the other SharePoint tools), name, web URL and
        description. Requires Sites.Read.All."""
        client = get_client(config)
        q = str(query or "").strip() or "*"
        items, next_link = client.collect(
            "/sites", params={"search": q, "$select": SITE_SELECT, "$top": 100},
            max_pages=max_pages)
        sites = []
        for s in items:
            if not isinstance(s, dict):
                continue
            sites.append({
                "id": s.get("id"),
                "name": s.get("name"),
                "display_name": s.get("displayName"),
                "web_url": s.get("webUrl"),
                "description": s.get("description"),
                "created_date_time": s.get("createdDateTime"),
                "last_modified_date_time": s.get("lastModifiedDateTime"),
            })
        return {"query": q, "count": len(sites), "sites": sites,
                "more_results": bool(next_link)}

    @mcp.tool()
    def get_sharepoint_site(site: str) -> dict:
        """Return one SharePoint site's profile (id, name, web URL).

        `site` is a site object id, a site URL
        (``https://host/sites/name``), or a ``host:/path`` reference.
        Requires Sites.Read.All."""
        client = get_client(config)
        ref = _site_ref(site)
        data = client.get(f"/sites/{ref}", params={"$select": SITE_SELECT})
        return {"site": site, "found": bool(data), "profile": data}

    @mcp.tool()
    def list_sharepoint_libraries(site: str, max_pages: int = 1) -> dict:
        """List a site's document libraries (drives).

        Returns each library's drive id (used by the folder/permission tools),
        name, type and web URL. Requires Sites.Read.All."""
        client = get_client(config)
        sid = _resolve_site_id(client, site)
        items, next_link = client.collect(
            f"/sites/{sid}/drives",
            params={"$select": DRIVE_SELECT, "$top": 100}, max_pages=max_pages)
        libs = [_summarize_drive(d) for d in items if isinstance(d, dict)]
        return {"site": site, "site_id": sid, "count": len(libs),
                "libraries": libs, "more_results": bool(next_link)}

    @mcp.tool()
    def list_sharepoint_folders(
        site: str, library: str = "", folder_path: str = "",
        max_pages: int = 1,
    ) -> dict:
        """List the FOLDERS inside a site's document library (or a subfolder).

        `site` is a site id/URL; `library` names the document library (default:
        the site's first document library); `folder_path` is an optional
        subfolder path under the library root (e.g. ``Shared Documents/HR``).
        Returns only the folders (not files). Requires Sites.Read.All."""
        client = get_client(config)
        drive = _resolve_drive_id(client, site, library)
        base = _item_path(drive, folder_path)
        items, next_link = client.collect(
            f"{base}/children",
            params={"$select": ITEM_SELECT, "$top": 200}, max_pages=max_pages)
        folders = [_summarize_item(i) for i in items
                   if isinstance(i, dict) and isinstance(i.get("folder"), dict)]
        return {"site": site, "drive_id": drive, "folder_path": folder_path,
                "count": len(folders), "folders": folders,
                "more_results": bool(next_link)}

    @mcp.tool()
    def list_sharepoint_folder_contents(
        drive_id: str, folder_path: str = "", max_pages: int = 1,
    ) -> dict:
        """List the files AND folders in a drive (library) or subfolder.

        `drive_id` comes from ``list_sharepoint_libraries``. `folder_path` is an
        optional path under the drive root. Requires Sites.Read.All."""
        client = get_client(config)
        drive = _clean_drive(drive_id)
        base = _item_path(drive, folder_path)
        items, next_link = client.collect(
            f"{base}/children",
            params={"$select": ITEM_SELECT, "$top": 200}, max_pages=max_pages)
        return {"drive_id": drive_id, "folder_path": folder_path,
                "count": len(items),
                "items": [_summarize_item(i) for i in items
                          if isinstance(i, dict)],
                "more_results": bool(next_link)}

    @mcp.tool()
    def list_sharepoint_item_permissions(
        drive_id: str, item_id: str = "", folder_path: str = "",
        max_pages: int = 1,
    ) -> dict:
        """List the permissions on a folder or file (a driveItem).

        Identify the item with `item_id` or `folder_path` (relative to the drive
        root; empty = the library root). Returns each permission's id, roles, the
        granted identity (user/group/site-group/application) and any sharing
        link. Requires Files.ReadWrite.All (or Sites.Read.All to read)."""
        client = get_client(config)
        drive = _clean_drive(drive_id)
        iid = _resolve_item_id(client, drive, item_id, folder_path)
        items, next_link = client.collect(
            f"/drives/{drive}/items/{iid}/permissions", max_pages=max_pages)
        perms = [_summarize_permission(p) for p in items
                 if isinstance(p, dict)]
        return {"drive_id": drive_id, "item_id": iid,
                "folder_path": folder_path, "count": len(perms),
                "permissions": perms, "more_results": bool(next_link)}

    @mcp.tool()
    def invite_to_sharepoint_item(
        drive_id: str, recipients: Optional[List[str]] = None, role: str = "write",
        item_id: str = "", folder_path: str = "", send_invitation: bool = False,
        confirm: bool = False,
    ) -> dict:
        """Grant a user (or users) access to a SharePoint folder/file.

        This is how a person gets access to a library or folder -- the driveItem
        ``invite`` API. `drive_id` from ``list_sharepoint_libraries``; identify
        the item with `item_id` or `folder_path` (empty = the library root).
        `recipients` is one or more email addresses (existing users; new guests
        cannot be invited app-only). `role` is one of ``read``, ``write``,
        ``owner``. `send_invitation=True` emails the recipients. Set
        `confirm=True` to apply. Requires Files.ReadWrite.All.

        """ + _AUTH_NOTE
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"drive_id": drive_id, "folder_path": folder_path,
                    "recipients": recipients, "granted": False,
                    "message": "Refusing to grant access without confirm=True. "
                               + _AUTH_NOTE}
        r = c.validate_choice(role, ITEM_ROLES, "role")
        addrs = [c.validate_email(x, "recipients") for x in (recipients or [])]
        if not addrs:
            raise ValueError("recipients must list at least one email address.")
        drive = _clean_drive(drive_id)
        iid = _resolve_item_id(client, drive, item_id, folder_path)
        body = {
            "requireSignIn": True,
            "sendInvitation": c.validate_bool(send_invitation, "send_invitation"),
            "roles": [r],
            "recipients": [{"email": a} for a in addrs],
        }
        result = client.post(f"/drives/{drive}/items/{iid}/invite", body)
        granted = [_summarize_permission(p) for p in client.unwrap(result or {})
                   if isinstance(p, dict)]
        # Re-read so the returned state is the real, post-write state.
        after, _ = client.collect(
            f"/drives/{drive}/items/{iid}/permissions", max_pages=1)
        return {
            "drive_id": drive_id, "item_id": iid, "folder_path": folder_path,
            "recipients": addrs, "role": r, "granted": True,
            "invitation_results": granted,
            "permissions": [_summarize_permission(p) for p in after
                            if isinstance(p, dict)],
        }

    @mcp.tool()
    def remove_sharepoint_item_permission(
        drive_id: str, permission_id: str, item_id: str = "",
        folder_path: str = "", confirm: bool = False,
    ) -> dict:
        """Remove a permission from a SharePoint folder/file.

        `permission_id` comes from ``list_sharepoint_item_permissions``. Identify
        the item with `item_id` or `folder_path`. Set `confirm=True` to apply.
        Requires Files.ReadWrite.All.

        """ + _AUTH_NOTE
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"drive_id": drive_id, "permission_id": permission_id,
                    "removed": False,
                    "message": "Refusing to remove a permission without "
                               "confirm=True. " + _AUTH_NOTE}
        pid = str(permission_id or "").strip()
        if not pid:
            raise ValueError("permission_id is required "
                             "(from list_sharepoint_item_permissions).")
        drive = _clean_drive(drive_id)
        iid = _resolve_item_id(client, drive, item_id, folder_path)
        client.delete(f"/drives/{drive}/items/{iid}/permissions/{quote(pid, safe='')}")
        after, _ = client.collect(
            f"/drives/{drive}/items/{iid}/permissions", max_pages=1)
        remaining = [p.get("id") for p in after if isinstance(p, dict)]
        return {"drive_id": drive_id, "item_id": iid,
                "permission_id": pid, "removed": True,
                "permission_removed": pid not in remaining,
                "permissions_remaining": remaining}

    @mcp.tool()
    def list_sharepoint_site_permissions(site: str, max_pages: int = 1) -> dict:
        """List the *application* permissions and sharing links on a site.

        This is the audit view for a leaked sharing link or an over-permissioned
        app on a site collection (v1.0 does not expose *user* site permissions
        here; user access lives on the driveItems). Returns each permission's id,
        roles, granted application/identity and link. Requires
        Sites.FullControl.All (Sites.Read.All to read)."""
        client = get_client(config)
        sid = _resolve_site_id(client, site)
        items, next_link = client.collect(
            f"/sites/{sid}/permissions", max_pages=max_pages)
        perms = [_summarize_permission(p) for p in items
                 if isinstance(p, dict)]
        return {"site": site, "site_id": sid, "count": len(perms),
                "permissions": perms, "more_results": bool(next_link)}

    @mcp.tool()
    def update_sharepoint_site_permission(
        site: str, permission_id: str, role: str, confirm: bool = False,
    ) -> dict:
        """Change the role of an application permission / sharing link on a site.

        v1.0 can update only a *non-user* site permission (an application
        permission or a sharing link). `permission_id` from
        ``list_sharepoint_site_permissions``; `role` is one of ``read``,
        ``write``, ``owner``, ``fullControl``. Set `confirm=True` to apply.
        Requires Sites.FullControl.All.

        """ + _AUTH_NOTE
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"site": site, "permission_id": permission_id,
                    "updated": False,
                    "message": "Refusing to update a site permission without "
                               "confirm=True. " + _AUTH_NOTE}
        r = c.validate_choice(role, SITE_ROLES, "role")
        pid = str(permission_id or "").strip()
        if not pid:
            raise ValueError("permission_id is required.")
        sid = _resolve_site_id(client, site)
        client.patch(
            f"/sites/{sid}/permissions/{quote(pid, safe='')}", {"roles": [r]})
        after = client.get(
            f"/sites/{sid}/permissions/{quote(pid, safe='')}")
        return {"site": site, "site_id": sid, "permission_id": pid,
                "updated": True, "role": r,
                "permission": _summarize_permission(after or {})}

    @mcp.tool()
    def remove_sharepoint_site_permission(
        site: str, permission_id: str, confirm: bool = False,
    ) -> dict:
        """Delete an application permission / sharing link from a site.

        The revoke path for a leaked site sharing link. `permission_id` from
        ``list_sharepoint_site_permissions``. Set `confirm=True` to apply.
        Requires Sites.FullControl.All.

        """ + _AUTH_NOTE
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"site": site, "permission_id": permission_id,
                    "removed": False,
                    "message": "Refusing to remove a site permission without "
                               "confirm=True. " + _AUTH_NOTE}
        pid = str(permission_id or "").strip()
        if not pid:
            raise ValueError("permission_id is required.")
        sid = _resolve_site_id(client, site)
        client.delete(f"/sites/{sid}/permissions/{quote(pid, safe='')}")
        after, _ = client.collect(f"/sites/{sid}/permissions", max_pages=1)
        remaining = [p.get("id") for p in after if isinstance(p, dict)]
        return {"site": site, "site_id": sid, "permission_id": pid,
                "removed": True, "permission_removed": pid not in remaining,
                "permissions_remaining": remaining}
