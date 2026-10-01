"""Shared validation + summary helpers for tool implementations."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Characters that must never appear in a single path segment.
_UNSAFE_PATH = set("/\\?#% \t\n\r")

CONDITIONAL_ACCESS_STATUSES = ("success", "failure", "notApplied")
RISK_LEVELS = ("low", "medium", "high", "hidden", "none")
RISK_STATES = ("none", "confirmedSafe", "remediated", "dismissed",
               "atRisk", "confirmedCompromised")
AUDIT_CATEGORIES = (
    "UserManagement", "GroupManagement", "ApplicationManagement",
    "RoleManagement", "DirectoryManagement", "Policy", "Authentication",
    "Authorization", "DeviceConfiguration", "Other",
)

# Exchange message-trace delivery statuses (exchangeMessageTraceStatus).
MESSAGE_TRACE_STATUSES = (
    "gettingStatus", "pending", "failed", "delivered", "expanded",
    "quarantined", "filteredAsSpam", "unknownFutureValue",
)
# Subject-filter functions the message trace API supports.
MESSAGE_TRACE_SUBJECT_FILTERS = ("contains", "startsWith", "endsWith")

# A simple, conservative SMTP address shape (local part + dotted domain).
_EMAIL_RE = re.compile(r"^[^\s@<>()\[\]\\,;:\"]+@[^\s@<>()\[\]\\,;:\"]+\.[^\s@<>()\[\]\\,;:\"]+$")


def validate_email(value: Any, field: str = "email") -> str:
    """Validate an SMTP email address before it is interpolated into a filter."""
    s = str(value or "").strip()
    if not _EMAIL_RE.match(s):
        raise ValueError(
            f"Invalid {field}: {value!r} (expected an SMTP address such as "
            "'user@contoso.com').")
    return s


def validate_guid(value: Any, field: str = "id") -> str:
    """Validate an Entra ID object id (a GUID)."""
    s = str(value).strip()
    if not _GUID_RE.match(s):
        raise ValueError(
            f"Invalid {field}: {value!r} (expected a GUID, e.g. "
            "'00000000-0000-0000-0000-000000000000').")
    return s


def validate_user_ref(value: Any, field: str = "user") -> str:
    """Validate a user reference: a GUID (object id) or a UPN/email address.

    Returns the URL-encoded path segment so a UPN's ``@`` and any reserved
    characters cannot break out of the path.
    """
    s = str(value or "").strip()
    if not s:
        raise ValueError(f"{field} is required (an object id or userPrincipalName).")
    if _GUID_RE.match(s):
        return s
    if any(c in _UNSAFE_PATH for c in s):
        raise ValueError(
            f"Invalid {field}: {value!r} (expected an object id or a "
            "userPrincipalName such as 'user@contoso.com').")
    if "@" not in s:
        raise ValueError(
            f"Invalid {field}: {value!r} (expected an object id or a "
            "userPrincipalName such as 'user@contoso.com').")
    return quote(s, safe="")


def odata_quote(value: Any) -> str:
    """Wrap a string literal for an OData ``$filter`` (single-quote escaping)."""
    return "'" + str(value).replace("'", "''") + "'"


def normalize_iso(value: Any, field: str = "date") -> str:
    """Accept a date (YYYY-MM-DD) or ISO-8601 datetime and return UTC ISO-8601.

    A bare date is treated as midnight UTC. A naive datetime is assumed UTC.
    """
    s = str(value or "").strip()
    if not s:
        raise ValueError(f"{field} must be a date or ISO-8601 datetime.")
    candidate = s
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        candidate = s + "T00:00:00Z"
    try:
        dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"Invalid {field}: {value!r} (expected YYYY-MM-DD or ISO-8601).") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_int(value: Any, field: str, *, minimum: int = 0,
                 maximum: Optional[int] = None) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {field}: {value!r} (expected an integer).") from exc
    if n < minimum or (maximum is not None and n > maximum):
        bound = f"{minimum}..{maximum}" if maximum is not None else f">= {minimum}"
        raise ValueError(f"Invalid {field}: {n} (expected {bound}).")
    return n


def validate_choice(value: Any, allowed: tuple, field: str) -> str:
    s = str(value).strip()
    if s not in allowed:
        raise ValueError(f"Invalid {field}: {value!r}. Allowed: {', '.join(allowed)}.")
    return s


def validate_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("true", "1", "yes"):
        return True
    if s in ("false", "0", "no"):
        return False
    raise ValueError(f"Invalid {field}: {value!r} (expected true/false).")


def validate_hours(value: Any, field: str = "hours", *, maximum: int = 2160) -> int:
    """Validate a rolling-window length in hours (default max 90 days)."""
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {field}: {value!r} (expected an integer).") from exc
    if n < 1 or n > maximum:
        raise ValueError(f"Invalid {field}: {n} (expected 1..{maximum}).")
    return n


def date_window_hours(start_iso: str, end_iso: str) -> float:
    """Return (end - start) in hours for two normalized UTC ISO-8601 values."""
    a = datetime.strptime(start_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    b = datetime.strptime(end_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (b - a).total_seconds() / 3600.0


def join_filters(parts: List[Optional[str]]) -> Optional[str]:
    """Join non-empty filter clauses with ' and '."""
    clauses = [p for p in parts if p]
    if not clauses:
        return None
    return " and ".join(clauses)


# ------------------------------------------------------------------ summaries
def _applied_ca_policies(signin: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for p in (signin.get("appliedConditionalAccessPolicies") or []):
        if not isinstance(p, dict):
            continue
        out.append({
            "display_name": p.get("displayName"),
            "result": p.get("result"),
            "enforced_grant_controls": p.get("enforcedGrantControls"),
            "enforced_session_controls": p.get("enforcedSessionControls"),
            "id": p.get("id"),
        })
    return out


def summarize_location(signin: Dict[str, Any]) -> Dict[str, Any]:
    loc = signin.get("location") or {}
    if not isinstance(loc, dict):
        return {}
    geo = loc.get("geoCoordinates") or {}
    return {
        "city": loc.get("city"),
        "state": loc.get("state"),
        "country_or_region": loc.get("countryOrRegion"),
        "latitude": geo.get("latitude") if isinstance(geo, dict) else None,
        "longitude": geo.get("longitude") if isinstance(geo, dict) else None,
    }


def summarize_device(signin: Dict[str, Any]) -> Dict[str, Any]:
    dev = signin.get("deviceDetail") or {}
    if not isinstance(dev, dict):
        return {}
    return {
        "device_id": dev.get("deviceId"),
        "display_name": dev.get("displayName"),
        "operating_system": dev.get("operatingSystem"),
        "browser": dev.get("browser"),
        "is_compliant": dev.get("isCompliant"),
        "is_managed": dev.get("isManaged"),
        "trust_type": dev.get("trustType"),
        "is_domain_joined": dev.get("isDomainJoined"),
    }


def summarize_signin(s: Dict[str, Any]) -> Dict[str, Any]:
    """Investigation-oriented summary of one sign-in event."""
    if not isinstance(s, dict):
        return {}
    status = s.get("status") or {}
    mfa = s.get("mfaDetail") or {}
    return {
        "id": s.get("id"),
        "created_date_time": s.get("createdDateTime"),
        "user_display_name": s.get("userDisplayName"),
        "user_principal_name": s.get("userPrincipalName"),
        "user_id": s.get("userId"),
        "app_display_name": s.get("appDisplayName"),
        "app_id": s.get("appId"),
        "resource_display_name": s.get("resourceDisplayName"),
        "ip_address": s.get("ipAddress"),
        "client_app_used": s.get("clientAppUsed"),
        "is_interactive": s.get("isInteractive"),
        "conditional_access_status": s.get("conditionalAccessStatus"),
        "applied_conditional_access_policies": _applied_ca_policies(s),
        "risk_detail": s.get("riskDetail"),
        "risk_level_aggregated": s.get("riskLevelAggregated"),
        "risk_level_during_signin": s.get("riskLevelDuringSignIn"),
        "risk_state": s.get("riskState"),
        "risk_event_types": s.get("riskEventTypes") or s.get("riskEventTypes_v2"),
        "error_code": status.get("errorCode") if isinstance(status, dict) else None,
        "failure_reason": status.get("failureReason") if isinstance(status, dict) else None,
        "additional_details": status.get("additionalDetails") if isinstance(status, dict) else None,
        "mfa_auth_method": mfa.get("authMethod") if isinstance(mfa, dict) else None,
        "mfa_auth_detail": mfa.get("authDetail") if isinstance(mfa, dict) else None,
        "authentication_requirement": s.get("authenticationRequirement"),
        "location": summarize_location(s),
        "device_detail": summarize_device(s),
        "correlation_id": s.get("correlationId"),
        "original_request_id": s.get("originalRequestId"),
        "token_issuer_name": s.get("tokenIssuerName"),
        "token_issuer_type": s.get("tokenIssuerType"),
    }


def summarize_audit(a: Dict[str, Any]) -> Dict[str, Any]:
    """Compact summary of a directory-audit event."""
    if not isinstance(a, dict):
        return {}
    initiated_by = a.get("initiatedBy") or {}
    actor = {}
    if isinstance(initiated_by, dict):
        user = initiated_by.get("user") or {}
        app = initiated_by.get("app") or {}
        actor = {
            "user_principal_name": user.get("userPrincipalName") if isinstance(user, dict) else None,
            "user_display_name": user.get("displayName") if isinstance(user, dict) else None,
            "user_id": user.get("id") if isinstance(user, dict) else None,
            "app_display_name": app.get("displayName") if isinstance(app, dict) else None,
            "app_service_principal_id": app.get("servicePrincipalId") if isinstance(app, dict) else None,
        }
    targets = []
    for t in (a.get("targetResources") or []):
        if not isinstance(t, dict):
            continue
        modified = []
        for m in (t.get("modifiedProperties") or []):
            if isinstance(m, dict):
                modified.append({
                    "display_name": m.get("displayName"),
                    "old_value": m.get("oldValue"),
                    "new_value": m.get("newValue"),
                })
        targets.append({
            "id": t.get("id"),
            "display_name": t.get("displayName"),
            "type": t.get("type"),
            "user_principal_name": t.get("userPrincipalName"),
            "modified_properties": modified,
        })
    return {
        "id": a.get("id"),
        "activity_date_time": a.get("activityDateTime"),
        "activity_display_name": a.get("activityDisplayName"),
        "category": a.get("category"),
        "result": a.get("result"),
        "result_reason": a.get("resultReason"),
        "operation_type": a.get("operationType"),
        "logged_by_service": a.get("loggedByService"),
        "initiated_by": actor,
        "target_resources": targets,
    }


def summarize_risky_user(u: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(u, dict):
        return {}
    return {
        "id": u.get("id"),
        "user_principal_name": u.get("userPrincipalName"),
        "user_display_name": u.get("userDisplayName"),
        "risk_level": u.get("riskLevel"),
        "risk_state": u.get("riskState"),
        "risk_detail": u.get("riskDetail"),
        "risk_last_updated_date_time": u.get("riskLastUpdatedDateTime"),
        "is_deleted": u.get("isDeleted"),
        "is_processing": u.get("isProcessing"),
    }


def summarize_risk_detection(d: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(d, dict):
        return {}
    loc = d.get("location") or {}
    return {
        "id": d.get("id"),
        "risk_event_type": d.get("riskEventType"),
        "risk_level": d.get("riskLevel"),
        "risk_state": d.get("riskState"),
        "risk_detail": d.get("riskDetail"),
        "detected_date_time": d.get("detectedDateTime"),
        "activity_date_time": d.get("activityDateTime"),
        "detection_timing_type": d.get("detectionTimingType"),
        "user_principal_name": d.get("userPrincipalName"),
        "user_display_name": d.get("userDisplayName"),
        "ip_address": d.get("ipAddress"),
        "location_city": loc.get("city") if isinstance(loc, dict) else None,
        "location_country": loc.get("countryOrRegion") if isinstance(loc, dict) else None,
        "activity": d.get("activity"),
        "token_issuer_type": d.get("tokenIssuerType"),
        "additional_info": d.get("additionalInfo"),
        "source": d.get("source"),
    }


def summarize_user(u: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(u, dict):
        return {}
    return {
        "id": u.get("id"),
        "display_name": u.get("displayName"),
        "user_principal_name": u.get("userPrincipalName"),
        "mail": u.get("mail"),
        "job_title": u.get("jobTitle"),
        "department": u.get("department"),
        "company_name": u.get("companyName"),
        "office_location": u.get("officeLocation"),
        "mobile_phone": u.get("mobilePhone"),
        "business_phones": u.get("businessPhones"),
        "account_enabled": u.get("accountEnabled"),
        "created_date_time": u.get("createdDateTime"),
        "on_premises_sync_enabled": u.get("onPremisesSyncEnabled"),
        "on_premises_sam_account_name": u.get("onPremisesSamAccountName"),
        "on_premises_domain_name": u.get("onPremisesDomainName"),
        "last_password_change_date_time": u.get("lastPasswordChangeDateTime"),
        "usage_location": u.get("usageLocation"),
        "user_type": u.get("userType"),
        "preferred_language": u.get("preferredLanguage"),
    }