"""Exchange message-trace tools (Exchange Online tracing).

Microsoft Graph exposes Exchange Online *message trace* -- the lifecycle of an
email as it passes through the tenant -- on the **beta** endpoint only:

    GET /admin/exchange/tracing/messageTraces
        List exchangeMessageTrace rows (who sent what to whom, status, IPs).
        $filter on: id, messageId, receivedDateTime (ge/le), recipientAddress,
        senderAddress, status, subject (contains/startsWith/endsWith), toIP.
        $top 1..5000. Queries up to 10 days of data per request; trace data is
        retained 90 days. Without parameters it returns the last 48 hours.

    GET /admin/exchange/tracing/messageTraces/{id}/getDetailsByRecipient(
            recipientAddress='x@contoso.com')
        The per-message processing steps (Receive, Deliver, Transport rule, ...)
        as exchangeMessageTraceDetail rows.

Service root: ``config.resolved_beta_url()`` (the message trace API is not in
v1.0). Permission: **ExchangeMessageTrace.Read.All** (application) with admin
consent, PLUS a service principal provisioned in the tenant for Microsoft app
id ``8bd644d1-64a1-4d4b-ae52-2e0cbf64e373`` (provisioning can take hours; until
it completes the API returns 401 "service principal ... was not found").

Throttling: 100 requests / 5 minutes per tenant, tracked separately for the
list and detail APIs.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from urllib.parse import quote

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c

TRACE_PATH = "/admin/exchange/tracing/messageTraces"
# The API refuses a single query window wider than 10 days.
MAX_WINDOW_HOURS = 10 * 24
MAX_WINDOW_SECONDS = MAX_WINDOW_HOURS * 3600
# Trace data is retained for 90 days.
MAX_LOOKBACK_HOURS = 90 * 24
DEFAULT_TOP = 1000


# ------------------------------------------------------------------- helpers
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_window(start: str, end: str, hours: Any
                    ) -> Dict[str, str]:
    """Resolve a (start, end) UTC ISO window from start/end or a trailing hours.

    * both start and end given  -> use them (validated, <= 10 days apart).
    * neither given             -> last ``hours`` (default 48) ending now.
    * only one given            -> error (need both, or neither).
    """
    s = str(start or "").strip()
    e = str(end or "").strip()
    if bool(s) != bool(e):
        raise ValueError("Provide BOTH start and end (ISO-8601), or neither "
                         "and use the hours parameter.")
    if s and e:
        start_iso = c.normalize_iso(s, "start")
        end_iso = c.normalize_iso(e, "end")
    else:
        span = c.validate_hours(hours, "hours", maximum=MAX_LOOKBACK_HOURS)
        end_dt = _utcnow()
        start_dt = end_dt - timedelta(hours=span)
        start_iso, end_iso = _fmt(start_dt), _fmt(end_dt)

    if c.date_window_hours(start_iso, end_iso) > MAX_WINDOW_HOURS:
        raise ValueError(
            f"The message trace window is {start_iso}..{end_iso}, which is wider "
            "than the API's 10-day per-request limit. Split it into <= 10-day "
            "queries (or lower the hours value).")
    if c.date_window_hours(start_iso, end_iso) <= 0:
        raise ValueError("start must be earlier than end.")
    return {"start": start_iso, "end": end_iso}


def _build_filter(start_iso: str, end_iso: str, *, message_id: str = "",
                  sender: str = "", recipient: str = "", status: str = "",
                  subject: str = "", subject_filter: str = "contains",
                  to_ip: str = "", trace_id: str = "") -> str:
    """Compose the OData ``$filter`` for the message trace list call."""
    parts: List[str] = [
        f"receivedDateTime ge {start_iso}",
        f"receivedDateTime le {end_iso}",
    ]
    if trace_id:
        parts.append(f"id eq {c.odata_quote(trace_id)}")
    if message_id:
        parts.append(f"messageId eq {c.odata_quote(message_id)}")
    if sender:
        parts.append(f"senderAddress eq {c.odata_quote(c.validate_email(sender, 'sender'))}")
    if recipient:
        parts.append(
            f"recipientAddress eq {c.odata_quote(c.validate_email(recipient, 'recipient'))}")
    if status:
        parts.append(
            f"status eq {c.odata_quote(c.validate_choice(status, c.MESSAGE_TRACE_STATUSES, 'status'))}")
    if to_ip:
        ip = str(to_ip).strip()
        if any(ch in ip for ch in "'\"\\/ "):
            raise ValueError(f"Invalid to_ip: {to_ip!r}")
        parts.append(f"toIP eq {c.odata_quote(ip)}")
    if subject:
        fn = c.validate_choice(subject_filter, c.MESSAGE_TRACE_SUBJECT_FILTERS,
                               "subject_filter")
        parts.append(f"{fn}(subject, {c.odata_quote(subject)})")
    return " and ".join(parts)


def _summarize_trace(t: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(t, dict):
        return {}
    return {
        "id": t.get("id"),
        "message_id": t.get("messageId"),
        "received_date_time": t.get("receivedDateTime"),
        "sender_address": t.get("senderAddress"),
        "recipient_address": t.get("recipientAddress"),
        "subject": t.get("subject"),
        "status": t.get("status"),
        "size": t.get("size"),
        "from_ip": t.get("fromIP"),
        "to_ip": t.get("toIP"),
    }


def _summarize_detail(d: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(d, dict):
        return {}
    return {
        "id": d.get("id"),
        "message_id": d.get("messageId"),
        "date_time": d.get("dateTime"),
        "event": d.get("event"),
        "action": d.get("action"),
        "description": d.get("description"),
        "data": d.get("data"),
    }


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    beta_url = config.resolved_beta_url()

    @mcp.tool()
    def list_message_traces(
        start: str = "", end: str = "", hours: int = 48,
        sender: str = "", recipient: str = "", status: str = "",
        subject: str = "", subject_filter: str = "contains",
        message_id: str = "", trace_id: str = "", to_ip: str = "",
        top: int = DEFAULT_TOP, max_pages: int = 1,
    ) -> dict:
        """Trace email messages through Exchange Online (last 90 days).

        Returns the message-trace rows for a time window: sender/recipient,
        subject, delivery status, size, and the source/destination IPs. Use it
        to answer "did this email reach the mailbox / where did it go / was it
        blocked or quarantined".

        Window: pass `start`+`end` (ISO-8601, e.g. '2026-09-20' or
        '2026-09-20T00:00:00Z') OR leave both empty and set `hours` (default 48).
        The API allows at most 10 days per request -- for a longer span, issue
        several calls with adjacent windows.

        Filters (all optional): `sender`, `recipient` (exact SMTP address),
        `status` (delivered/failed/pending/quarantined/expanded/filteredAsSpam/
        gettingStatus), `subject` with `subject_filter` (contains|startsWith|
        endsWith), `message_id` (the Message-ID header), `trace_id` (a trace id),
        `to_ip`. `top` is the page size (1-5000); `max_pages` follows
        @odata.nextLink up to that many pages (returns `next_link` if more
        remain). Requires ExchangeMessageTrace.Read.All."""
        client = get_client(config)
        window = _resolve_window(start, end, hours)
        top_n = c.validate_int(top, "top", minimum=1, maximum=5000)
        pages = c.validate_int(max_pages, "max_pages", minimum=1, maximum=100)
        flt = _build_filter(window["start"], window["end"], message_id=message_id,
                            sender=sender, recipient=recipient, status=status,
                            subject=subject, subject_filter=subject_filter,
                            to_ip=to_ip, trace_id=trace_id)
        items, next_link = client.collect(
            TRACE_PATH, params={"$filter": flt, "$top": top_n},
            max_pages=pages, base_url=beta_url)
        rows = [_summarize_trace(t) for t in items if isinstance(t, dict)]
        return {
            "window": window,
            "filter": flt,
            "count": len(rows),
            "traces": rows,
            "next_link": next_link,
        }

    @mcp.tool()
    def get_message_trace_details(trace_id: str, recipient: str) -> dict:
        """Get the per-message processing steps for one traced message.

        `trace_id` is the message-trace id from list_message_traces; `recipient`
        is the SMTP address the message was sent to. Returns the ordered
        exchangeMessageTraceDetail rows (event = Receive/Deliver/Transport rule/
        Fail/... with a description and raw `data`), i.e. the story of what
        Exchange did with the message. Requires ExchangeMessageTrace.Read.All."""
        client = get_client(config)
        tid = str(trace_id or "").strip()
        if any(ch in tid for ch in "/\\?#'\" "):
            raise ValueError(f"Invalid trace_id: {trace_id!r}")
        rcpt = c.validate_email(recipient, "recipient")
        path = (f"{TRACE_PATH}/{tid}/getDetailsByRecipient("
                f"recipientAddress={quote(rcpt, safe='')})")
        data = client.get(path, base_url=beta_url)
        details = [_summarize_detail(d) for d in client.unwrap(data)
                   if isinstance(d, dict)]
        return {
            "trace_id": tid,
            "recipient": rcpt,
            "count": len(details),
            "details": details,
            "raw_response": data,
        }
