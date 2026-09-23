"""User permission/access tools (`/users/{id}/...`).

Answers "what type of permissions and access does this user have?": group and
directory-role membership, enterprise-app role assignments, OAuth2 delegated
permission grants, and registered authentication methods.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c

USER_SELECT = (
    "id,displayName,userPrincipalName,mail,jobTitle,department,companyName,"
    "officeLocation,mobilePhone,businessPhones,accountEnabled,createdDateTime,"
    "onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesDomainName,"
    "lastPasswordChangeDateTime,usageLocation,userType,preferredLanguage"
)


def _collect_path(client, path: str, params: Optional[Dict[str, Any]],
                  max_pages: int) -> tuple[List[Any], Optional[str]]:
    return client.collect(path, params=params, max_pages=max_pages)


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def get_user(user: str) -> dict:
        """Return one user's Entra ID profile.

        `user` is an object id (GUID) or a userPrincipalName. Returns the
        account profile (display name, UPN/mail, title, department, enabled
        state, sync source and on-premises sAMAccountName, last password change).
        Requires User.Read.All."""
        client = get_client(config)
        ref = c.validate_user_ref(user)
        data = client.get(f"/users/{ref}", params={"$select": USER_SELECT})
        return {
            "user": user,
            "found": bool(data),
            "summary": c.summarize_user(data or {}),
            "profile": data,
        }

    @mcp.tool()
    def get_user_manager(user: str) -> dict:
        """Return a user's manager (display name, UPN, mail, title).

        `user` is an object id (GUID) or a userPrincipalName. Requires
        User.Read.All."""
        client = get_client(config)
        ref = c.validate_user_ref(user)
        data = client.get(f"/users/{ref}/manager",
                          params={"$select": USER_SELECT})
        return {
            "user": user,
            "has_manager": bool(data),
            "manager": c.summarize_user(data or {}) if data else None,
        }

    @mcp.tool()
    def get_user_memberships(
        user: str, max_pages: int = 1, include_raw: bool = False,
    ) -> dict:
        """List every group/role the user belongs to, including via nesting
        (`transitiveMemberOf`).

        `user` is an object id (GUID) or a userPrincipalName. Returns each
        object's id, display name and `@odata.type` (so directory roles are
        distinguishable from security/M365 groups). Requires at least
        Directory.Read.All (or User.Read.All for direct memberships)."""
        client = get_client(config)
        ref = c.validate_user_ref(user)
        items, next_link = _collect_path(
            client, f"/users/{ref}/transitiveMemberOf",
            {"$select": "id,displayName,description"}, max_pages)
        memberships = []
        for m in items:
            if not isinstance(m, dict):
                continue
            otype = m.get("@odata.type") or m.get("odata.type")
            memberships.append({
                "id": m.get("id"),
                "display_name": m.get("displayName"),
                "description": m.get("description"),
                "type": otype.rsplit(".", 1)[-1] if isinstance(otype, str) else None,
            })
        out: Dict[str, Any] = {
            "user": user,
            "count": len(memberships),
            "memberships": memberships,
            "more_results": bool(next_link),
        }
        if include_raw:
            out["raw"] = items
        return out

    @mcp.tool()
    def get_user_directory_roles(user: str) -> dict:
        """List the Entra ID directory (admin) ROLES a user holds (direct or
        nested), e.g. Global Administrator, Helpdesk Administrator.

        `user` is an object id (GUID) or a userPrincipalName. Returns each
        role's id, display name and description. This is the key "what
        administrative access does this account have?" check. Requires
        Directory.Read.All."""
        client = get_client(config)
        ref = c.validate_user_ref(user)
        data = client.get(
            f"/users/{ref}/transitiveMemberOf/microsoft.graph.directoryRole",
            params={"$select": "id,displayName,description", "$top": 100})
        items = client.unwrap(data)
        roles = [{
            "id": r.get("id"),
            "display_name": r.get("displayName"),
            "description": r.get("description"),
        } for r in items if isinstance(r, dict)]
        return {"user": user, "count": len(roles), "directory_roles": roles}

    @mcp.tool()
    def get_user_app_role_assignments(
        user: str, max_pages: int = 1,
    ) -> dict:
        """List the enterprise-application ROLES assigned to a user
        (`appRoleAssignments`).

        `user` is an object id (GUID) or a userPrincipalName. Each entry shows
        the resource (enterprise app) service principal, the app role id and the
        app role's display name where available. Requires Directory.Read.All
        (or AppRoleAssignment.ReadWrite.All)."""
        client = get_client(config)
        ref = c.validate_user_ref(user)
        items, next_link = _collect_path(
            client, f"/users/{ref}/appRoleAssignments", None, max_pages)
        assignments = []
        for a in items:
            if not isinstance(a, dict):
                continue
            assignments.append({
                "id": a.get("id"),
                "app_role_id": a.get("appRoleId"),
                "resource_display_name": a.get("resourceDisplayName"),
                "resource_id": a.get("resourceId"),
                "principal_display_name": a.get("principalDisplayName"),
                "created_date_time": a.get("createdDateTime"),
            })
        return {
            "user": user,
            "count": len(assignments),
            "app_role_assignments": assignments,
            "more_results": bool(next_link),
        }

    @mcp.tool()
    def get_user_oauth2_grants(
        user: str, max_pages: int = 1,
    ) -> dict:
        """List the OAuth2 DELEGATED permission grants a user has consented to
        (`oauth2PermissionGrants`).

        `user` is an object id (GUID) or a userPrincipalName. Each grant shows
        the resource (API/enterprise app), the client app id and the granted
        `scope` list (e.g. 'Mail.Read User.Read', 'Files.ReadWrite.All') -- i.e.
        which third-party/enterprise apps can act on the user's behalf. Requires
        Directory.Read.All."""
        client = get_client(config)
        ref = c.validate_user_ref(user)
        items, next_link = _collect_path(
            client, f"/users/{ref}/oauth2PermissionGrants", None, max_pages)
        grants = []
        for g in items:
            if not isinstance(g, dict):
                continue
            grants.append({
                "id": g.get("id"),
                "client_id": g.get("clientId"),
                "resource_id": g.get("resourceId"),
                "consent_type": g.get("consentType"),
                "principal_id": g.get("principalId"),
                "scopes": (g.get("scope") or "").split() or [],
            })
        return {
            "user": user,
            "count": len(grants),
            "oauth2_grants": grants,
            "more_results": bool(next_link),
        }

    @mcp.tool()
    def get_user_authentication_methods(
        user: str, max_pages: int = 1,
    ) -> dict:
        """List the authentication methods registered for a user (passwordless
        / MFA strength).

        `user` is an object id (GUID) or a userPrincipalName. Returns each
        method's `@odata.type` (e.g. `#microsoft.graph.microsoftAuthenticatorAuthenticationMethod`,
        `#microsoft.graph.phoneAuthenticationMethod`, `#microsoft.graph.fido2AuthenticationMethod`,
        `#microsoft.graph.passwordAuthenticationMethod`), id and key details.
        Requires UserAuthenticationMethod.Read.All."""
        client = get_client(config)
        ref = c.validate_user_ref(user)
        items, next_link = _collect_path(
            client, f"/users/{ref}/authentication/methods", None, max_pages)
        methods = []
        for m in items:
            if not isinstance(m, dict):
                continue
            otype = m.get("@odata.type") or m.get("odata.type")
            methods.append({
                "id": m.get("id"),
                "type": otype.rsplit(".", 1)[-1] if isinstance(otype, str) else None,
                "display_name": m.get("displayName"),
                "phone_number": m.get("phoneNumber"),
                "phone_type": m.get("phoneType"),
                "device_tag": m.get("deviceTag"),
                "created_date_time": m.get("createdDateTime"),
            })
        return {
            "user": user,
            "count": len(methods),
            "authentication_methods": methods,
            "more_results": bool(next_link),
        }