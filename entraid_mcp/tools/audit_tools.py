"""Directory audit log tools (`/auditLogs/directoryAudits`).

Covers: all directory audit events, one event by id, and the audit events that
touch a given user (as actor or as target).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c

AUDITS_PATH = "/auditLogs/directoryAudits"
DEFAULT_AUDIT_SELECT = (
    "id,activityDateTime,activityDisplayName,category,result,resultReason,"
    "operationType,loggedByService,initiatedBy,targetResources"
)


def _sort_desc(items: List[Any]) -> List[Any]:
    def key(d: Any) -> str:
        return str(d.get("activityDateTime") or "") if isinstance(d, dict) else ""
    return sorted(items, key=key, reverse=True)


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def list_directory_audits(
        activity_display_name: Optional[str] = None,
        category: Optional[str] = None,
        initiated_by_upn: Optional[str] = None,
        target_id: Optional[str] = None,
        target_display_name: Optional[str] = None,
        result: Optional[str] = None,
        logged_by_service: Optional[str] = None,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
        top: int = 100,
        max_pages: int = 1,
        include_raw: bool = False,
    ) -> dict:
        """List Microsoft Entra ID directory audit events (newest first).

        Filter by `activity_display_name` (e.g. 'Add member to role', 'Update
        user', 'Consent to application'), `category` (e.g. RoleManagement,
        UserManagement, ApplicationManagement), the acting user's UPN via
        `initiated_by_upn`, the affected object via `target_id`/`target_display_name`,
        `result` (success|failure), `logged_by_service`, and a
        `created_after`/`created_before` window (YYYY-MM-DD or ISO-8601).

        Returns compact summaries (actor + target resources + modified
        properties). `top` caps events per page (max 1000); raise `max_pages` to
        page forward. Set `include_raw=True` for the untouched Graph objects.
        Requires AuditLog.Read.All."""
        client = get_client(config)
        parts: List[Optional[str]] = []
        if activity_display_name:
            parts.append(f"activityDisplayName eq {c.odata_quote(activity_display_name)}")
        if category:
            parts.append(f"category eq {c.odata_quote(category)}")
        if initiated_by_upn:
            parts.append("initiatedBy/user/userPrincipalName eq " + c.odata_quote(initiated_by_upn))
        if target_id:
            tid = c.validate_guid(target_id, 'target_id')
            parts.append(f"targetResources/any(t:t/id eq {c.odata_quote(tid)})")
        if target_display_name:
            parts.append("targetResources/any(t:t/displayName eq "
                         + c.odata_quote(target_display_name) + ")")
        if result:
            parts.append(f"result eq {c.odata_quote(result)}")
        if logged_by_service:
            parts.append(f"loggedByService eq {c.odata_quote(logged_by_service)}")
        if created_after:
            parts.append(f"activityDateTime ge {c.normalize_iso(created_after, 'created_after')}")
        if created_before:
            parts.append(f"activityDateTime le {c.normalize_iso(created_before, 'created_before')}")
        filt = c.join_filters(parts)

        top = c.validate_int(top, 'top', minimum=1, maximum=1000)
        params: Dict[str, Any] = {"$top": top, "$select": DEFAULT_AUDIT_SELECT}
        if filt:
            params["$filter"] = filt
        items, next_link = client.collect(AUDITS_PATH, params=params,
                                          max_pages=max_pages)
        items = _sort_desc(items)
        result_out: Dict[str, Any] = {
            "count": len(items),
            "filter": filt,
            "audits": [c.summarize_audit(a) for a in items],
            "more_results": bool(next_link),
        }
        if include_raw:
            result_out["raw"] = items
        return result_out

    @mcp.tool()
    def get_directory_audit(audit_id: str) -> dict:
        """Return ONE directory audit event in full by its id.

        Use an `id` from `list_directory_audits` / `list_user_audits`. Returns
        the complete Graph object (under `audit`) plus a parsed `summary` with
        the actor (`initiated_by`) and every `target_resource` (including each
        `modified_properties` old/new value). Requires AuditLog.Read.All."""
        client = get_client(config)
        aid = c.validate_guid(audit_id, 'audit_id')
        data = client.get(AUDITS_PATH, params={
            "$filter": f"id eq {c.odata_quote(aid)}", "$top": 1})
        items = client.unwrap(data)
        audit = items[0] if items else {}
        return {
            "found": bool(items),
            "audit_id": aid,
            "summary": c.summarize_audit(audit),
            "audit": audit,
        }

    @mcp.tool()
    def list_user_audits(
        user: str,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
        activity_display_name: Optional[str] = None,
        top: int = 100,
        max_pages: int = 1,
    ) -> dict:
        """List directory audit events where a user was EITHER the actor OR a
        target.

        `user` is an object id (GUID) or a userPrincipalName. Useful to build a
        timeline of what an account did and what was done to it (role changes,
        group membership changes, credential/consent changes). Optionally narrow
        by `activity_display_name` and a `created_after`/`created_before` window.
        Requires AuditLog.Read.All."""
        client = get_client(config)
        ref = c.validate_user_ref(user)
        if "@" in user:
            upn = c.odata_quote(user)
            actor = f"initiatedBy/user/userPrincipalName eq {upn}"
            target = f"targetResources/any(t:t/userPrincipalName eq {upn})"
        else:
            guid = c.odata_quote(ref)
            actor = f"initiatedBy/user/id eq {guid}"
            target = f"targetResources/any(t:t/id eq {guid})"
        parts: List[Optional[str]] = [f"({actor} or {target})"]
        if activity_display_name:
            parts.append(f"activityDisplayName eq {c.odata_quote(activity_display_name)}")
        if created_after:
            parts.append(f"activityDateTime ge {c.normalize_iso(created_after, 'created_after')}")
        if created_before:
            parts.append(f"activityDateTime le {c.normalize_iso(created_before, 'created_before')}")
        filt = " and ".join(p for p in parts if p)

        top = c.validate_int(top, 'top', minimum=1, maximum=1000)
        params: Dict[str, Any] = {"$top": top, "$select": DEFAULT_AUDIT_SELECT,
                                  "$filter": filt}
        items, next_link = client.collect(AUDITS_PATH, params=params,
                                          max_pages=max_pages)
        items = _sort_desc(items)
        return {
            "user": user,
            "count": len(items),
            "filter": filt,
            "audits": [c.summarize_audit(a) for a in items],
            "more_results": bool(next_link),
        }