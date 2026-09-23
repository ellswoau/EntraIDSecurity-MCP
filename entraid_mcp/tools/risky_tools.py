"""Identity Protection tools (`/identityProtection`).

Covers: risky users, a single risky user, a risky user's risk history, and
risk detections. All read-only.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c

RISKY_USERS_PATH = "/identityProtection/riskyUsers"
RISK_DETECTIONS_PATH = "/identityProtection/riskDetections"
DEFAULT_RISKY_SELECT = (
    "id,userPrincipalName,userDisplayName,riskLevel,riskState,riskDetail,"
    "riskLastUpdatedDateTime,isDeleted,isProcessing"
)
DEFAULT_DETECTION_SELECT = (
    "id,riskEventType,riskLevel,riskState,riskDetail,detectedDateTime,"
    "activityDateTime,detectionTimingType,userPrincipalName,userDisplayName,"
    "ipAddress,location,activity,tokenIssuerType,source"
)


def _sort_desc(items: List[Any], field: str) -> List[Any]:
    def key(d: Any) -> str:
        return str(d.get(field) or "") if isinstance(d, dict) else ""
    return sorted(items, key=key, reverse=True)


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def list_risky_users(
        risk_state: Optional[str] = None,
        risk_level: Optional[str] = None,
        user_principal_name: Optional[str] = None,
        top: int = 100,
        max_pages: int = 1,
        include_raw: bool = False,
    ) -> dict:
        """List users flagged at risk by Entra ID Identity Protection.

        Filter by `risk_state` (e.g. atRisk, confirmedCompromised, remediated,
        dismissed, confirmedSafe) or `risk_level` (low|medium|high|hidden) and
        `user_principal_name`. Returns each user's current risk level/state and
        `risk_detail`. Requires the IdentityRiskyUser.Read.All application
        permission."""
        client = get_client(config)
        parts: List[Optional[str]] = []
        if risk_state:
            parts.append("riskState eq " + c.odata_quote(
                c.validate_choice(risk_state, c.RISK_STATES, 'risk_state')))
        if risk_level:
            parts.append("riskLevel eq " + c.odata_quote(
                c.validate_choice(risk_level, c.RISK_LEVELS, 'risk_level')))
        if user_principal_name:
            parts.append(f"userPrincipalName eq {c.odata_quote(user_principal_name)}")
        filt = c.join_filters(parts)
        top = c.validate_int(top, 'top', minimum=1, maximum=500)
        params: Dict[str, Any] = {"$top": top, "$select": DEFAULT_RISKY_SELECT}
        if filt:
            params["$filter"] = filt
        items, next_link = client.collect(RISKY_USERS_PATH, params=params,
                                          max_pages=max_pages)
        items = _sort_desc(items, "riskLastUpdatedDateTime")
        out: Dict[str, Any] = {
            "count": len(items),
            "filter": filt,
            "risky_users": [c.summarize_risky_user(u) for u in items],
            "more_results": bool(next_link),
        }
        if include_raw:
            out["raw"] = items
        return out

    @mcp.tool()
    def get_risky_user(user: str) -> dict:
        """Return one risky user's current Identity Protection record.

        `user` is the risky-user object `id` (a GUID) or a userPrincipalName.
        Requires IdentityRiskyUser.Read.All."""
        client = get_client(config)
        if "@" in str(user):
            data = client.get(RISKY_USERS_PATH, params={
                "$filter": f"userPrincipalName eq {c.odata_quote(user)}", "$top": 1})
        else:
            data = client.get(f"{RISKY_USERS_PATH}/{c.validate_guid(user, 'user')}")
        items = client.unwrap(data) if isinstance(data, dict) else ([data] if data else [])
        rec = items[0] if items else {}
        return {
            "found": bool(items),
            "user": user,
            "summary": c.summarize_risky_user(rec),
            "risky_user": rec,
        }

    @mcp.tool()
    def get_risky_user_history(user_id: str) -> dict:
        """Return the risk HISTORY of one risky user (each past risk state
        change with its level, state, detail and timestamp).

        `user_id` is the risky-user object id (a GUID) from `list_risky_users`.
        Returns the raw history events plus a compact timeline. Requires
        IdentityRiskyUser.Read.All."""
        client = get_client(config)
        uid = c.validate_guid(user_id, 'user_id')
        items, _ = client.collect(f"{RISKY_USERS_PATH}/{uid}/history")
        timeline = [c.summarize_risky_user(h) for h in items]
        return {
            "user_id": uid,
            "count": len(items),
            "history": timeline,
            "raw": items,
        }

    @mcp.tool()
    def list_risk_detections(
        user_principal_name: Optional[str] = None,
        risk_event_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        risk_state: Optional[str] = None,
        ip_address: Optional[str] = None,
        detected_after: Optional[str] = None,
        detected_before: Optional[str] = None,
        top: int = 100,
        max_pages: int = 1,
        include_raw: bool = False,
    ) -> dict:
        """List Identity Protection risk detections.

        A detection is the specific signal behind a risky user: leaked
        credentials, impossible travel, anonymized IP, unfamiliar sign-in
        properties, malware-linked IP, password spray, etc.

        Filter by `user_principal_name`, `risk_event_type` (e.g.
        'leakedCredentials', 'impossibleTravel', 'anonymizedIPAddress',
        'unfamiliarFeatures', 'malwareInfectedIPAddress', 'passwordSpray'),
        `risk_level`, `risk_state`, `ip_address` and a
        `detected_after`/`detected_before` window (YYYY-MM-DD or ISO-8601).
        Requires IdentityRiskEvent.Read.All."""
        client = get_client(config)
        parts: List[Optional[str]] = []
        if user_principal_name:
            parts.append(f"userPrincipalName eq {c.odata_quote(user_principal_name)}")
        if risk_event_type:
            parts.append(f"riskEventType eq {c.odata_quote(risk_event_type)}")
        if risk_level:
            parts.append("riskLevel eq " + c.odata_quote(
                c.validate_choice(risk_level, c.RISK_LEVELS, 'risk_level')))
        if risk_state:
            parts.append("riskState eq " + c.odata_quote(
                c.validate_choice(risk_state, c.RISK_STATES, 'risk_state')))
        if ip_address:
            parts.append(f"ipAddress eq {c.odata_quote(ip_address)}")
        if detected_after:
            parts.append(f"detectedDateTime ge {c.normalize_iso(detected_after, 'detected_after')}")
        if detected_before:
            parts.append(f"detectedDateTime le {c.normalize_iso(detected_before, 'detected_before')}")
        filt = c.join_filters(parts)
        top = c.validate_int(top, 'top', minimum=1, maximum=500)
        params: Dict[str, Any] = {"$top": top, "$select": DEFAULT_DETECTION_SELECT}
        if filt:
            params["$filter"] = filt
        items, next_link = client.collect(RISK_DETECTIONS_PATH, params=params,
                                          max_pages=max_pages)
        items = _sort_desc(items, "detectedDateTime")
        out: Dict[str, Any] = {
            "count": len(items),
            "filter": filt,
            "risk_detections": [c.summarize_risk_detection(d) for d in items],
            "more_results": bool(next_link),
        }
        if include_raw:
            out["raw"] = items
        return out