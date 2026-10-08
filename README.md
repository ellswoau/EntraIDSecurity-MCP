# Entra ID MCP Server (Python / FastMCP)

A [Model Context Protocol](https://modelcontextprotocol.io) server exposing
**Microsoft Entra ID (Azure AD) security-investigation** tools, built with
Python [FastMCP](https://github.com/jlowin/fastmcp). It targets
**Microsoft Graph v1.0** and authenticates with the OAuth2
**client-credentials** (app-only) flow.

It is intended as the data layer for a security-investigations skill: pull the
sign-in and audit history for an account, see exactly which conditional-access
policies fired and where/what device a sign-in came from, check Identity
Protection risk, and enumerate the permissions and access a user actually holds.

> Runs both as a direct `python -m` process **and** as a Docker container.

## Tools (57)

**Sign-in logs** (`/auditLogs/signIns`)
- `list_sign_ins` — all sign-ins, filter by user/app/IP/error code/CA status/risk/date window.
- `list_user_sign_ins` — one user's sign-ins.
- `get_sign_in` — full detail of ONE event: conditional-access policies applied,
  location (+ geo), device detail, MFA method, risk, status/error, token issuer.

**Directory audit logs** (`/auditLogs/directoryAudits`)
- `list_directory_audits` — changes (role/group/app/consent), filter by activity,
  category, actor UPN, target, result, date window.
- `list_user_audits` — events where a user was the actor **or** the target.
- `get_directory_audit` — one event in full, incl. modified properties (old→new).

**Identity Protection**
- `list_risky_users` — users flagged at risk (level/state).
- `get_risky_user` — one risky user by id or UPN.
- `get_risky_user_history` — that user's risk timeline.
- `list_risk_detections` — the underlying detections (leaked credentials,
  impossible travel, anonymized IP, password spray, …).
- `dismiss_risky_user` — **mutating**: dismiss the user's risk.
- `confirm_risky_user_compromised` — **mutating**: confirm compromise.

**User permissions / access**
- `get_user` — profile.
- `get_user_manager` — manager.
- `get_user_memberships` — all groups/roles (transitive).
- `get_user_directory_roles` — admin directory roles held.
- `get_user_app_role_assignments` — enterprise-app role assignments.
- `get_user_oauth2_grants` — delegated OAuth2 scopes an app can use on their behalf.
- `get_user_authentication_methods` — registered MFA / passwordless methods.

**Group / distribution-list / Team membership** (`/groups`)
- `list_groups` — find groups/DLs/Teams (by name prefix, mail-enabled /
  security / unified).
- `get_group` — one group's profile (id, mail, type, unified/Team flag).
- `list_group_members` — members of a group / DL / Team.
- `add_group_member` — **mutating**: add a user to a group / DL / Team.
- `remove_group_member` — **mutating**: remove a user from a group / DL / Team.

**Session revocation**
- `revoke_user_sessions` — **mutating**: invalidate all of a user's refresh
  tokens / browser sessions (forces re-sign-in everywhere). Needs `confirm=True`.

**MFA reset**
- `delete_user_auth_method` — **mutating**: delete ONE registered auth method.
- `reset_user_mfa_methods` — **mutating**: wipe all registered MFA/passwordless
  methods. Needs `confirm=True`.

**Mailbox (out-of-office + forwarding)**
- `get_user_out_of_office` — read automatic replies.
- `set_user_out_of_office` — **mutating**: set an always-on or scheduled OOO.
- `unset_user_out_of_office` — **mutating**: turn OOO off.
- `list_mail_forwarding_rules` — Inbox rules that forward/redirect mail.
- `set_mail_forwarding` — **mutating**: create a forward/redirect rule.
- `remove_mail_forwarding_rule` — **mutating**: delete a forwarding rule.
  Needs `confirm=True`.

**Mailbox delegation (Send on Behalf + folder access)** — Exchange Online
**Admin API** (`outlook.office365.com/adminapi/v2.0`, preview)
- `get_mailbox_delegation` — read a mailbox's Send-on-Behalf delegates.
- `set_mailbox_send_on_behalf` — **mutating**: overwrite/add/remove the Send on
  Behalf delegate list (`mode` = `overwrite`|`add`|`remove`). Needs `confirm=True`.
- `add_mailbox_send_on_behalf` / `remove_mailbox_send_on_behalf` — **mutating**
  convenience wrappers. Need `confirm=True`.
- `list_mailbox_folder_permissions` — folder permissions (delegates) on a
  mailbox folder (default `Calendar`).
- `add_mailbox_folder_permission` — **mutating**: grant a role (`Reviewer` /
  `Editor` / `PublishingEditor`) on a folder. Needs `confirm=True`.
- `set_mailbox_folder_permission` — **mutating**: change an existing grantee's
  folder role. Needs `confirm=True`.
- `remove_mailbox_folder_permission` — **mutating**: revoke a folder permission.
  Needs `confirm=True`.

> These are the mailbox-delegation tools. They use the **Exchange Online Admin
> API**, not Graph, and need a different permission (see *Mailbox delegation*
> below). Mailbox-level **Full Access** and **Send As** are **not** available
> here (or anywhere in an API) — see the caveat below.

**Exchange message trace** (`/admin/exchange/tracing/messageTraces` — Graph **beta**)
- `list_message_traces` — trace email through Exchange Online (last 90 days):
  sender/recipient, subject, delivery status, size, source/destination IPs.
  Filter by sender, recipient, status, subject, Message-ID, trace id, to-IP and
  a time window (max 10 days per request).
- `get_message_trace_details` — the per-message processing steps (Receive,
  Deliver, Transport rule, Fail, ...) for one traced message + recipient.

**SharePoint sites / libraries / folder permissions** (`/sites`, `/drives`)
- `list_sharepoint_sites` — find sites (search term; id, name, web URL).
- `get_sharepoint_site` — one site by id, URL, or `host:/path`.
- `list_sharepoint_libraries` — a site's document libraries (drive ids).
- `list_sharepoint_folders` — the folders in a site's library (or subfolder).
- `list_sharepoint_folder_contents` — files **and** folders in a drive/folder.
- `list_sharepoint_item_permissions` — permissions on a folder/file.
- `invite_to_sharepoint_item` — **mutating**: grant a user `read`/`write`/
  `owner` on a folder/file (the driveItem `invite` API). Needs `confirm=True`.
- `remove_sharepoint_item_permission` — **mutating**: revoke a folder/file
  permission. Needs `confirm=True`.
- `list_sharepoint_site_permissions` — a site's application permissions and
  sharing links (the leaked-link audit view).
- `update_sharepoint_site_permission` — **mutating**: change an app permission /
  sharing link role. Needs `confirm=True`.
- `remove_sharepoint_site_permission` — **mutating**: delete an app permission /
  sharing link. Needs `confirm=True`.

**Teams membership (owners + members)** (`/groups`, `/teams`)
- `list_teams` — Teams (unified groups with Teams provisioned), by name prefix.
- `get_team` — one Team's profile (backing group id, name, visibility).
- `list_team_owners` / `list_team_members` — a Team's owners / members.
- `add_team_owner` / `remove_team_owner` — **mutating**: add/remove a Team
  owner. Need `confirm=True`.
- `add_team_member` / `remove_team_member` — **mutating**: add/remove a Team
  member (Team-scoped equivalent of `add_group_member`). Need `confirm=True`.
- `list_team_channels` — a Team's channels (read-only).

**Misc**
- `entra_api_get` — read-only GET escape hatch for any other Graph v1.0 path.
- `entraid_config` — redacted view of the configured tenant/app.

## Register the app in your tenant

You need **Privileged Role Administrator** or **Global Administrator** to grant
admin consent.

1. Sign in to the **Entra admin center** → <https://entra.microsoft.com> →
   **Applications → App registrations → New registration**.
   - Name: e.g. `EntraID-MCP (Security Investigations)`
   - Supported account types: **Accounts in this organizational directory only** (single tenant)
   - Redirect URI: leave blank
   - **Register**.
2. On the app's **Overview** page copy:
   - **Application (client) ID** → `ENTRAID_CLIENT_ID`
   - **Directory (tenant) ID** → `ENTRAID_TENANT_ID`
3. **API permissions → Add a permission → Microsoft Graph → Application
   permissions** → add each permission below → **Add permissions**.
4. Click **Grant admin consent for <your tenant>**. Every permission must show a
   green ✓ under Status.
5. **Certificates & secrets → Client secrets → New client secret**. Copy the
   secret **Value** immediately (it is shown only once) → `ENTRAID_CLIENT_SECRET`.
   The secret **ID** is not used.

### Required Microsoft Graph **application** permissions

Least-privilege set for a **read-only** investigation server:

| Permission | Used by |
|---|---|
| `AuditLog.Read.All` | `list_sign_ins`, `list_user_sign_ins`, `get_sign_in`, `list_directory_audits`, `list_user_audits`, `get_directory_audit` |
| `IdentityRiskyUser.Read.All` | `list_risky_users`, `get_risky_user`, `get_risky_user_history` |
| `IdentityRiskEvent.Read.All` | `list_risk_detections` |
| `Directory.Read.All` | `get_user`, `get_user_manager`, `get_user_memberships`, `get_user_directory_roles`, `get_user_app_role_assignments`, `get_user_oauth2_grants` |
| `UserAuthenticationMethod.Read.All` | `get_user_authentication_methods` |
| `Organization.Read.All` | `entraid_config`, `ping` connection test |

| `ExchangeMessageTrace.Read.All` | `list_message_traces`, `get_message_trace_details` (see the service-principal note below) |

### Mailbox delegation (Exchange Online Admin API — not a Graph scope)

The mailbox-delegation tools (`get_mailbox_delegation`,
`*_mailbox_send_on_behalf`, `*_mailbox_folder_permission`) call the **Exchange
Online Admin API**, which is a **different resource** from Graph. They mint an
app-only token for `https://outlook.office365.com/.default` and need:

| Permission | Used by |
|---|---|
| `Office 365 Exchange Online → Exchange.ManageAsAppV2` (**application**, admin-consented) | every mailbox-delegation tool |
| An **Exchange RBAC role** on the service principal (e.g. `Recipient Management`) | the same tools (assign with `New-ServicePrincipal` + `Add-RoleGroupMember` in Exchange Online PowerShell) |

Add only if you want the two mutating tools enabled:

| Permission | Used by |
|---|---|
| `IdentityRiskyUser.ReadWrite.All` | `dismiss_risky_user`, `confirm_risky_user_compromised` |

### Additional permissions for the admin/management tools

These are the **write** permissions the management tools need. Grant them
(application permissions + admin consent) the same way:

| Permission | Used by |
|---|---|
| `Group.ReadWrite.All` | `add_group_member`, `remove_group_member` (also needs `Directory.Read.All` for `list_groups`/`list_group_members`/`get_group`) |
| `User.RevokeSessions.All` | `revoke_user_sessions` (or `User.ReadWrite.All`) |
| `UserAuthenticationMethod.ReadWrite.All` | `delete_user_auth_method`, `reset_user_mfa_methods` |
| `MailboxSettings.ReadWrite` | `set_user_out_of_office`, `unset_user_out_of_office` (Read is enough for `get_user_out_of_office`) |
| `Mail.ReadWrite` | `list_mail_forwarding_rules`, `set_mail_forwarding`, `remove_mail_forwarding_rule` |

### Additional permissions for the SharePoint / Teams permission tools

| Permission | Used by |
|---|---|
| `Sites.Read.All` | `list_sharepoint_sites`, `get_sharepoint_site`, `list_sharepoint_libraries`, `list_sharepoint_folders`, `list_sharepoint_folder_contents`, `list_sharepoint_item_permissions` |
| `Files.ReadWrite.All` | `invite_to_sharepoint_item`, `remove_sharepoint_item_permission` (least privilege for the driveItem `invite`/permission APIs) |
| `Sites.FullControl.All` | `list_sharepoint_site_permissions`, `update_sharepoint_site_permission`, `remove_sharepoint_site_permission` (managing *site* permissions is FullControl-only app-side) |
| `Group.ReadWrite.All` *(already listed)* | `add_team_owner`, `remove_team_owner`, `add_team_member`, `remove_team_member` |
| `Directory.Read.All` / `Group.Read.All` *(already listed)* | `list_teams`, `get_team`, `list_team_owners`, `list_team_members`, `list_team_channels` |

> `Sites.Selected` is the least-privilege alternative to `Sites.FullControl.All`
> for a scoped deployment: the app is granted access per site/list by a
> SharePoint admin (`POST /sites/{id}/permissions` with the app identity).

### What Graph cannot do for SharePoint permissions (important)

- **A user's access to a site or folder is granted with the driveItem `invite`
  API, not site permissions.** `POST /sites/{id}/permissions` in Graph v1.0
  creates only an *application* permission ("you can't use it to create a new
  user site permission"); the site-permission tools here manage application
  permissions and sharing links.
- **Adding a person as a SharePoint *site-collection owner* is not exposed by
  Graph v1.0.** Site owners / site-collection admins are a SharePoint concept:
  use the SharePoint admin center, PnP PowerShell
  (`Set-PnPSite -Identity <site> -Owners <upn>`), or the SharePoint REST API
  (`/_api/web/...`). To give a person access to a **library or folder**, use
  `invite_to_sharepoint_item` with `role="owner"`.
- New (not-yet-existing) **guests** cannot be invited app-only; existing users
  and existing guests can.

### Teams owners and members

A Team is backed by a **unified** Microsoft 365 group, so its owners and members
are managed through the backing group (`/groups/{id}/owners` and `/members`).
This is fully supported app-only and needs `Group.ReadWrite.All`. Channel-level
membership (`ChannelMember.ReadWrite.All`) is not modelled here.

> **Mail forwarding uses `Mail.ReadWrite`, not `Mail.Send`** — a forwarding
> rule is an Inbox message rule, not a send operation.

### Exchange message trace needs a provisioned service principal

The Graph-based **message trace API is beta-only** and has an extra onboarding
step beyond the app permission: a service principal must exist in the tenant for
Microsoft's multi-tenant message-trace app, id
`8bd644d1-64a1-4d4b-ae52-2e0cbf64e373`. Create it once (admin):

```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"
Import-Module Microsoft.Graph.Applications
New-MgServicePrincipal -BodyAppId "8bd644d1-64a1-4d4b-ae52-2e0cbf64e373"
```

Until the service principal finishes provisioning (can take a few hours), the
two message-trace tools return `401`:
`Service principal-less authentication failed: The service principal for App ID
8bd644d1-64a1-4d4b-ae52-2e0cbf64e373 was not found.`

Message trace is throttled at **100 requests / 5 minutes** per tenant (the list
and detail APIs have separate buckets). Data is retained 90 days; each request
spans at most 10 days (call with adjacent windows for longer ranges).

### What Graph cannot do — and what the Admin API can (important)

**Microsoft Graph exposes no mailbox permissions at all.** Adding or removing a
user's **Full Access**, **Send As** or **Send on Behalf** on a (shared) mailbox
is an Exchange Online mailbox-permission operation.

The supported **REST** surface for this is the **Exchange Online Admin API**
(preview), which the delegation tools here use. It covers:

- **Send on Behalf** — `Set-Mailbox -GrantSendOnBehalfTo`
  (`*_mailbox_send_on_behalf`).
- **Mailbox folder permissions** — `Add-/Set-/Remove-MailboxFolderPermission`
  (`*_mailbox_folder_permission`), i.e. delegating the Calendar/Inbox.

It does **not** cover mailbox-level **Full Access** (`Add-MailboxPermission`)
or **Send As** (`Add-RecipientPermission`) — those two exist only in
**Exchange Online PowerShell**:

```powershell
Add-MailboxPermission -Identity "shared@contoso.com" -User "user@contoso.com" `
  -AccessRights FullAccess -AutoMapping $false
Add-RecipientPermission -Identity "shared@contoso.com" -Trustee "user@contoso.com" `
  -AccessRights SendAs
```

`Connect-ExchangeOnline` app-only requires **certificate** authentication (a
client secret is not accepted), so Full Access / Send As stay an Exchange
PowerShell change rather than an MCP call.

Graph *can* read/change a shared mailbox's **own** settings (out-of-office,
Inbox rules, messages) by addressing it with its id/UPN — that is what the
mailbox tools above do. Membership in a **group-backed** mailbox (a
mail-enabled security group / Microsoft 365 group) *is* manageable via
`add_group_member` / `remove_group_member`.

### Licensing note

Reading **sign-in logs** through Graph requires an **Entra ID P1 or P2**
license; **Identity Protection** (`riskyUsers` / `riskDetections`) requires
**Entra ID P2**. The API returns `403` if the tenant lacks the license.

### Alternative to a client secret

For stronger assurance, use a **certificate** instead of a client secret and
swap the client-credentials assertion accordingly. The secret path is what this
server implements by default.

## Configure credentials

Credentials never live in code or the repo. Put them in the `0600` env file:

```
~/.openclaw/entraid-mcp.env
```

Fill in `ENTRAID_TENANT_ID`, `ENTRAID_CLIENT_ID`, `ENTRAID_CLIENT_SECRET`
(`ENTRAID_MCP_AUTH_TOKEN` is already generated). Then prove auth:

```bash
python -m entraid_mcp ping            # reads ENTRAID_* from the environment
```

Or, without env vars, use the masked wizard (writes a `0600` JSON file):

```bash
python -m entraid_mcp config init --config ./entraid.json
```

## Running

```bash
# stdio (embedded MCP client)
python -m entraid_mcp

# network daemon (what the house servers use)
python -m entraid_mcp --transport http --host 0.0.0.0 --port 8000 \
  --token "$ENTRAID_MCP_AUTH_TOKEN"

# docker
docker compose up -d            # host port 8008 -> container 8000
```

Health checks are credential-free: `GET /health` → 200. Every other path
requires `Authorization: Bearer <ENTRAID_MCP_AUTH_TOKEN>` (401 otherwise).

## Register with OpenClaw

```bash
openclaw mcp add entraid-mcp --url http://127.0.0.1:8008/mcp \
  --transport streamable-http \
  --header "Authorization=Bearer <ENTRAID_MCP_AUTH_TOKEN>" --timeout 60
openclaw mcp reload && openclaw mcp probe entraid-mcp
```

## Tests

Offline, no network:

```bash
python -m unittest -v tests_sanity
```