"""Mailbox tools: out-of-office (automatic replies) and email forwarding.

Out-of-office
    GET   /users/{id|upn}/mailboxSettings                       (read)
    PATCH /users/{id|upn}/mailboxSettings                       (set/clear)

Forwarding
    A forwarding rule is an Inbox message rule whose actions include
    ``forwardTo`` / ``redirectTo`` (or ``forwardAsAttachmentTo``). Graph can
    CREATE such a rule but cannot filter rules by their action, so this module
    finds forwarding rules by listing the Inbox rules and inspecting each one:

        GET    /users/{id}/mail/mailFolders/inbox/messageRules
        POST   /users/{id}/mail/mailFolders/inbox/messageRules
        DELETE /users/{id}/mail/mailFolders/inbox/messageRules/{ruleId}

    (server-side ``$filter`` on messageRules is not supported -> list + match
    locally.)

Permissions: MailboxSettings.ReadWrite (out-of-office),
Mail.ReadWrite (mailbox rules). Forwarding uses Mail.ReadWrite, not Mail.Send.

SHARED MAILBOXES -- IMPORTANT
    Adding/removing a *user's delegation* on a shared mailbox (Full Access /
    Send As / Send on Behalf) is NOT exposed by Microsoft Graph; those are
    Exchange Online mailbox-permission operations and require Exchange Online
    PowerShell (Add-MailboxPermission / Add-RecipientPermission). There is no
    supported Graph endpoint. What Graph *can* do for a shared mailbox is treat
    it as a normal mailbox target and read/change its own settings (mailbox
    settings, rules, messages), addressed by the shared mailbox's id/UPN.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import EntraIDConfig

from ..client import get_client
from . import _common as c

MAILBOX_SETTINGS = ("automaticRepliesSetting,timeZone,language,dateFormat,timeFormat,workingHours")

# Rule-action keys that represent forwarding/redirection.
_FORWARD_ACTIONS = ("forwardTo", "forwardAsAttachmentTo", "redirectTo")


def _resolve_mailbox_ref(client, mailbox: str) -> str:
    """Return a URL-encoded mailbox path segment (accepts id or UPN)."""
    return c.validate_user_ref(mailbox)


def _summarize_autoreply(settings: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(settings, dict):
        return {}
    ar = settings.get("automaticRepliesSetting") or {}
    if not isinstance(ar, dict):
        return {}
    msg = ar.get("internalReplyMessage")
    sched = ar.get("scheduledStartDateTime") or {}
    return {
        "status": ar.get("status"),
        "external_audience": ar.get("externalAudience"),
        "internal_reply_message": msg,
        "external_reply_message": ar.get("externalReplyMessage"),
        "scheduled_start": sched.get("dateTime") if isinstance(sched, dict) else None,
        "scheduled_start_tz": sched.get("timeZone") if isinstance(sched, dict) else None,
        "scheduled_end": (ar.get("scheduledEndDateTime") or {}).get("dateTime")
            if isinstance(ar.get("scheduledEndDateTime"), dict) else None,
    }


def _recipient(email: str) -> Dict[str, Any]:
    return {"emailAddress": {"address": str(email).strip()}}


def _is_forwarding_rule(rule: Dict[str, Any]) -> bool:
    actions = rule.get("actions") or {}
    if not isinstance(actions, dict):
        return False
    return any(actions.get(k) for k in _FORWARD_ACTIONS)


def _summarize_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(rule, dict):
        return {}
    actions = rule.get("actions") or {}
    fwd: List[str] = []
    if isinstance(actions, dict):
        for k in _FORWARD_ACTIONS:
            for r in (actions.get(k) or []):
                addr = ((r or {}).get("emailAddress") or {}).get("address")
                if addr:
                    fwd.append(f"{k}:{addr}")
    return {
        "id": rule.get("id"),
        "display_name": rule.get("displayName"),
        "sequence": rule.get("sequence"),
        "is_enabled": rule.get("isEnabled"),
        "has_error": rule.get("hasError"),
        "is_forwarding_rule": _is_forwarding_rule(rule),
        "forward_targets": fwd,
        "conditions": rule.get("conditions"),
        "actions": actions,
    }


def _list_inbox_rules(client, ref: str) -> List[Dict[str, Any]]:
    data = client.get(f"/users/{ref}/mail/mailFolders/inbox/messageRules",
                      params={"$top": 100})
    return [r for r in client.unwrap(data) if isinstance(r, dict)]


def register(mcp: "FastMCP", config: "EntraIDConfig") -> None:
    @mcp.tool()
    def get_user_out_of_office(mailbox: str) -> dict:
        """Read a user's (or shared mailbox's) out-of-office / automatic-replies
        setting.

        `mailbox` is an object id (GUID) or userPrincipalName; a shared
        mailbox is addressed by its own UPN. Returns status
        (disabled/alwaysEnabled/scheduled), audience, and the internal/external
        messages. Requires MailboxSettings.Read (or .ReadWrite)."""
        client = get_client(config)
        ref = _resolve_mailbox_ref(client, mailbox)
        data = client.get(f"/users/{ref}/mailboxSettings",
                          params={"$select": MAILBOX_SETTINGS})
        return {
            "mailbox": mailbox,
            "automatic_replies": _summarize_autoreply(data or {}),
            "mailbox_settings": data,
        }

    @mcp.tool()
    def set_user_out_of_office(
        mailbox: str, internal_message: str, external_message: str = "",
        external_audience: str = "all", start: str = "", end: str = "",
        time_zone: str = "UTC",
    ) -> dict:
        """Set a user's out-of-office / automatic replies.

        `mailbox` is an object id (GUID) or userPrincipalName. `internal_message`
        is required. `external_audience` is one of ``none``, ``contactsOnly``,
        ``all``. Leave `start`/`end` empty for an "always on" reply, or pass
        ISO-8601 datetimes for a scheduled reply (`time_zone` is the IANA or
        Windows zone for those timestamps). Requires MailboxSettings.ReadWrite."""
        client = get_client(config)
        ref = _resolve_mailbox_ref(client, mailbox)
        audience = c.validate_choice(
            external_audience,
            ("none", "contactsOnly", "all"), "external_audience")
        s = str(start or "").strip()
        e = str(end or "").strip()
        if bool(s) != bool(e):
            raise ValueError("Provide BOTH start and end for a scheduled reply, "
                             "or neither for an always-on reply.")
        ar: Dict[str, Any] = {
            "status": "scheduled" if (s and e) else "alwaysEnabled",
            "externalAudience": audience,
            "internalReplyMessage": internal_message,
            "externalReplyMessage": external_message or internal_message,
        }
        if s and e:
            ar["scheduledStartDateTime"] = {"dateTime": c.normalize_iso(s, "start"),
                                            "timeZone": time_zone}
            ar["scheduledEndDateTime"] = {"dateTime": c.normalize_iso(e, "end"),
                                          "timeZone": time_zone}
        client.patch(f"/users/{ref}/mailboxSettings",
                     {"automaticRepliesSetting": ar})
        after = client.get(f"/users/{ref}/mailboxSettings",
                           params={"$select": MAILBOX_SETTINGS})
        return {
            "mailbox": mailbox, "updated": True,
            "automatic_replies": _summarize_autoreply(after or {}),
        }

    @mcp.tool()
    def unset_user_out_of_office(mailbox: str) -> dict:
        """Turn OFF a user's out-of-office / automatic replies.

        `mailbox` is an object id (GUID) or userPrincipalName. Requires
        MailboxSettings.ReadWrite."""
        client = get_client(config)
        ref = _resolve_mailbox_ref(client, mailbox)
        client.patch(f"/users/{ref}/mailboxSettings",
                     {"automaticRepliesSetting": {"status": "disabled"}})
        after = client.get(f"/users/{ref}/mailboxSettings",
                           params={"$select": MAILBOX_SETTINGS})
        return {
            "mailbox": mailbox, "updated": True, "disabled": True,
            "automatic_replies": _summarize_autoreply(after or {}),
        }

    @mcp.tool()
    def list_mail_forwarding_rules(mailbox: str) -> dict:
        """List a mailbox's Inbox rules that forward or redirect mail.

        `mailbox` is an object id (GUID) or userPrincipalName. Graph cannot
        filter message rules server-side by action, so every Inbox rule is
        listed and the forwarding/redirect ones are returned (with their
        targets and rule id, so they can be removed). Requires Mail.ReadWrite."""
        client = get_client(config)
        ref = _resolve_mailbox_ref(client, mailbox)
        rules = _list_inbox_rules(client, ref)
        forwarding = [_summarize_rule(r) for r in rules if _is_forwarding_rule(r)]
        return {
            "mailbox": mailbox,
            "total_rules": len(rules),
            "forwarding_rule_count": len(forwarding),
            "forwarding_rules": forwarding,
        }

    @mcp.tool()
    def set_mail_forwarding(mailbox: str, forward_to: str,
                            keep_copy: bool = True,
                            display_name: str = "EntraID-MCP forwarding") -> dict:
        """Create an Inbox rule that forwards all mail from a mailbox to another
        address.

        `mailbox` is an object id (GUID) or userPrincipalName. `forward_to` is
        the destination email address. `keep_copy=True` uses
        ``forwardTo`` (a copy stays in the mailbox); False uses ``redirectTo``
        (the message is redirected and not kept). Requires Mail.ReadWrite.
        Note: to forward *out* from a shared mailbox you generally also need
        the mailbox itself; this sets the rule on the given mailbox."""
        client = get_client(config)
        ref = _resolve_mailbox_ref(client, mailbox)
        dest = str(forward_to or "").strip()
        if "@" not in dest or any(ch in dest for ch in " <>(),;"):
            raise ValueError(f"Invalid forward_to email address: {forward_to!r}")
        action_key = "forwardTo" if c.validate_bool(keep_copy, "keep_copy") else "redirectTo"
        body = {
            "displayName": display_name,
            "sequence": 1,
            "isEnabled": True,
            "conditions": {},
            "actions": {action_key: [_recipient(dest)]},
        }
        created = client.post(
            f"/users/{ref}/mail/mailFolders/inbox/messageRules", body)
        rules = _list_inbox_rules(client, ref)
        return {
            "mailbox": mailbox,
            "forward_to": dest,
            "mode": action_key,
            "created_rule": _summarize_rule(created or {}) if isinstance(created, dict) else None,
            "forwarding_rules": [_summarize_rule(r) for r in rules
                                 if _is_forwarding_rule(r)],
        }

    @mcp.tool()
    def remove_mail_forwarding_rule(mailbox: str, rule_id: str,
                                    confirm: bool = False) -> dict:
        """Delete an Inbox forwarding/redirect rule from a mailbox.

        `mailbox` is an object id (GUID) or userPrincipalName; `rule_id` comes
        from list_mail_forwarding_rules. `confirm=True` required. Requires
        Mail.ReadWrite."""
        client = get_client(config)
        if not c.validate_bool(confirm, "confirm"):
            return {"mailbox": mailbox, "rule_id": rule_id, "removed": False,
                    "message": "Refusing to delete a rule without confirm=True."}
        ref = _resolve_mailbox_ref(client, mailbox)
        client.delete(f"/users/{ref}/mail/mailFolders/inbox/messageRules/{rule_id}")
        remaining = _list_inbox_rules(client, ref)
        return {
            "mailbox": mailbox, "rule_id": rule_id, "removed": True,
            "forwarding_rules_remaining":
                [r.get("id") for r in remaining if _is_forwarding_rule(r)],
        }
