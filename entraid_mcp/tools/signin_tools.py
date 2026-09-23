"""Sign-in log tools (`/auditLogs/signIns`).

Covers: all sign-ins, sign-ins for one user, and the full activity detail of a
single sign-in event (conditional-access policies applied, location, device,
MFA and risk).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import EntraIDError, get_client
from . import _common as c

SIGN_INS_PATH = "/auditLogs/signIns"

# A curated field set keeps list payloads manageable while still carrying the
# fields an investigation needs (location, device, CA status, risk, status).
# A curated field set keeps list payloads manageable while still carrying the
# fields an investigation needs (location, device, CA status, risk, status).
# NB: only properties that Graph v1.0 marks selectable on microsoft.graph.signIn
# may appear here -- originalRequestId, tokenIssuerName, tokenIssuerType,
# authenticationRequirement, mfaDetail and clientCredentialType are NOT
# selectable there and are only available on the full object (get_sign_in).
DEFAULT_SIGNIN_SELECT = (
    "id,createdDateTime,userDisplayName,userPrincipalName,userId,"
    "appDisplayName,appId,resourceDisplayName,ipAddress,clientAppUsed,"
    "isInteractive,conditionalAccessStatus,appliedConditionalAccessPolicies,"
    "riskDetail,riskLevelAggregated,riskLevelDuringSignIn,riskState,"
    "riskEventTypes_v2,status,location,deviceDetail,correlationId,resourceId"
)


def _build_signin_filter(
    user_principal_name: Optional[str] = None,
    user_id: Optional[str] = None,
    app_display_name: Optional[str] = None,
    ip_address: Optional[str] = None,
    error_code: Optional[int] = None,
    conditional_access_status: Optional[str] = None,
    risk_state: Optional[str] = None,
    risk_level: Optional[str] = None,
    client_app_used: Optional[str] = None,
    location_country: Optional[str] = None,
    created_after: Optional[str] = None,
    created_before: Optional[str] = None,
    is_interactive: Optional[bool] = None,
) -> Optional[str]:
    parts: List[Optional[str]] = []
    if user_id:
        parts.append(f"userId eq {c.odata_quote(c.validate_guid(user_id, 'user_id'))}")
    if user_principal_name:
        parts.append(f"userPrincipalName eq {c.odata_quote(user_principal_name)}")
    if app_display_name:
        parts.append(f"appDisplayName eq {c.odata_quote(app_display_name)}")
    if ip_address:
        parts.append(f"ipAddress eq {c.odata_quote(ip_address)}")
    if error_code is not None:
        parts.append(f"status/errorCode eq {c.validate_int(error_code, 'error_code')}")
    if conditional_access_status:
        parts.append("conditionalAccessStatus eq " + c.odata_quote(
            c.validate_choice(conditional_access_status,
                              c.CONDITIONAL_ACCESS_STATUSES,
                              'conditional_access_status')))
    if risk_state:
        parts.append("riskState eq " + c.odata_quote(
            c.validate_choice(risk_state, c.RISK_STATES, 'risk_state')))
    if risk_level:
        parts.append("riskLevelAggregated eq " + c.odata_quote(
            c.validate_choice(risk_level, c.RISK_LEVELS, 'risk_level')))
    if client_app_used:
        parts.append(f"clientAppUsed eq {c.odata_quote(client_app_used)}")
    if location_country:
        parts.append(f"location/countryOrRegion eq {c.odata_quote(location_country)}")
    if created_after:
        parts.append(f"createdDateTime ge {c.normalize_iso(created_after, 'created_after')}")
    if created_before:
        parts.append(f"createdDateTime le {c.normalize_iso(created_before, 'created_before')}")
    if is_interactive is not None:
        parts.append("isInteractive eq " + ("true" if c.validate_bool(is_interactive, 'is_interactive') else "false"))
    return c.join_filters(parts)


def _sort_desc(items: List[Any]) -> List[Any]:
    def key(d: Any) -> str:
        return str(d.get("createdDateTime") or "") if isinstance(d, dict) else ""
    return sorted(items, key=key, reverse=True)


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def list_sign_ins(
        user_principal_name: Optional[str] = None,
        user_id: Optional[str] = None,
        app_display_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        error_code: Optional[int] = None,
        conditional_access_status: Optional[str] = None,
        risk_state: Optional[str] = None,
        risk_level: Optional[str] = None,
        client_app_used: Optional[str] = None,
        location_country: Optional[str] = None,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
        is_interactive: Optional[bool] = None,
        top: int = 100,
        max_pages: int = 1,
        include_raw: bool = False,
    ) -> dict:
        """List Microsoft Entra ID sign-in events (newest first), optionally
        filtered.

        Filter by user (`user_principal_name` or `user_id`), `app_display_name`,
        `ip_address`, `error_code` (e.g. 50126 = bad password, 50074 = MFA
        required, 53003 = blocked by conditional access), `conditional_access_status`
        (success|failure|notApplied), `risk_state`, `risk_level`,
        `client_app_used`, `location_country`, an `created_after`/`created_before`
        window (YYYY-MM-DD or ISO-8601) and `is_interactive`.

        Returns compact per-event summaries (location, device, CA status, MFA,
        risk, error). `top` caps events per page (max 1000); raise `max_pages`
        to page forward while more results exist. Set `include_raw=True` for the
        untouched Graph objects. Requires the AuditLog.Read.All application
        permission."""
        client = get_client(config)
        filt = _build_signin_filter(
            user_principal_name=user_principal_name, user_id=user_id,
            app_display_name=app_display_name, ip_address=ip_address,
            error_code=error_code,
            conditional_access_status=conditional_access_status,
            risk_state=risk_state, risk_level=risk_level,
            client_app_used=client_app_used, location_country=location_country,
            created_after=created_after, created_before=created_before,
            is_interactive=is_interactive)
        top = c.validate_int(top, 'top', minimum=1, maximum=1000)
        params: Dict[str, Any] = {"$top": top, "$select": DEFAULT_SIGNIN_SELECT}
        if filt:
            params["$filter"] = filt
        items, next_link = client.collect(SIGN_INS_PATH, params=params,
                                          max_pages=max_pages)
        items = _sort_desc(items)
        result = {
            "count": len(items),
            "filter": filt,
            "sign_ins": [c.summarize_signin(s) for s in items],
            "more_results": bool(next_link),
        }
        if include_raw:
            result["raw"] = items
        return result

    @mcp.tool()
    def list_user_sign_ins(
        user: str,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
        conditional_access_status: Optional[str] = None,
        risk_state: Optional[str] = None,
        error_code: Optional[int] = None,
        top: int = 200,
        max_pages: int = 1,
    ) -> dict:
        """List a single user's sign-in events (newest first).

        `user` is an object id (GUID) or a userPrincipalName such as
        'jdoe@contoso.com'. Optionally bound by `created_after`/`created_before`
        (YYYY-MM-DD or ISO-8601) and filter by `conditional_access_status`,
        `risk_state` or `error_code`. Returns compact per-event summaries.
        Requires AuditLog.Read.All."""
        client = get_client(config)
        ref = c.validate_user_ref(user)
        upn = None
        # Search by UPN when a UPN was supplied, else resolve the GUID's UPN.
        if "@" in user:
            upn = user
        filt = _build_signin_filter(
            user_principal_name=upn, user_id=None if upn else ref,
            created_after=created_after, created_before=created_before,
            conditional_access_status=conditional_access_status,
            risk_state=risk_state, error_code=error_code)
        top = c.validate_int(top, 'top', minimum=1, maximum=1000)
        params: Dict[str, Any] = {"$top": top, "$select": DEFAULT_SIGNIN_SELECT,
                                  "$filter": filt}
        items, next_link = client.collect(SIGN_INS_PATH, params=params,
                                          max_pages=max_pages)
        items = _sort_desc(items)
        return {
            "user": user,
            "count": len(items),
            "filter": filt,
            "sign_ins": [c.summarize_signin(s) for s in items],
            "more_results": bool(next_link),
        }

    @mcp.tool()
    def get_sign_in(sign_in_id: str) -> dict:
        """Return the full activity detail of ONE sign-in event by its id.

        Use a sign-in `id` from `list_sign_ins` / `list_user_sign_ins`. Returns
        the complete Graph object (under `sign_in`) plus a parsed `summary`
        covering: conditional-access `applied_conditional_access_policies`
        (each policy's display name + result), `location` (city/state/country +
        geo coordinates), `device_detail` (device id/OS/browser/compliance/managed
        state/trust type), MFA `authMethod`/`authDetail`, `risk_*` fields,
        `status` (errorCode/failureReason/additionalDetails), `client_app_used`,
        `authentication_requirement`, `correlation_id` and token issuer.
        Requires AuditLog.Read.All."""
        client = get_client(config)
        sid = c.validate_guid(sign_in_id, 'sign_in_id')
        data = client.get(SIGN_INS_PATH, params={
            "$filter": f"id eq {c.odata_quote(sid)}", "$top": 1})
        items = client.unwrap(data)
        sign_in = items[0] if items else {}
        return {
            "found": bool(items),
            "sign_in_id": sid,
            "summary": c.summarize_signin(sign_in),
            "sign_in": sign_in,
        }