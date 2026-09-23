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

## Tools (21)

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

Add only if you want the two mutating tools enabled:

| Permission | Used by |
|---|---|
| `IdentityRiskyUser.ReadWrite.All` | `dismiss_risky_user`, `confirm_risky_user_compromised` |

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