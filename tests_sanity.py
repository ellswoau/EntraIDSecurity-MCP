"""Offline sanity tests for the Entra ID MCP server.

These never touch the network. They exercise:
  * credential/redaction and validation behaviour,
  * the OAuth2 client-credentials token flow (cache, 401 -> re-mint -> retry,
    403 permission failure fails fast),
  * the exact Graph request each tool builds (captured via a fake session),
  * URL vetting for the read-only escape hatch.

Run with:

    python -m unittest -v tests_sanity
"""
from __future__ import annotations

import time
import unittest

from entraid_mcp.client import EntraIDClient, EntraIDError, get_client
from entraid_mcp.config import ConfigError, EntraIDConfig, load_config
from entraid_mcp.tools import (
    api_tools,
    audit_tools,
    response_tools,
    risky_tools,
    signin_tools,
    user_tools,
)
from entraid_mcp.tools import _common as c

TENANT = "11111111-1111-1111-1111-111111111111"
GUID = "22222222-2222-2222-2222-222222222222"


# --------------------------------------------------------------- test doubles
class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None,
                 has_content=True):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.content = b"x" if has_content else b""

    def json(self):
        if self._payload is None:
            raise ValueError("no json body")
        return self._payload


class FakeSession:
    """Records requests and replays queued responses; mints tokens on post()."""

    def __init__(self, responses=None, token_payload=None):
        self.requests = []
        self.posts = []
        self._responses = list(responses or [])
        self._token_payload = token_payload or {
            "access_token": "new-access", "expires_in": 3599,
            "token_type": "Bearer",
        }

    def request(self, method, url, params=None, json=None, headers=None,
                timeout=None, verify=None):
        self.requests.append({"method": method, "url": url, "params": params,
                              "json": json, "headers": headers})
        if self._responses:
            return self._responses.pop(0)
        return FakeResponse(200, {"value": []})

    def post(self, url, data=None, headers=None, timeout=None, verify=None):
        self.posts.append({"url": url, "data": data, "headers": headers})
        return FakeResponse(200, dict(self._token_payload))


class FakeMCP:
    """Captures @mcp.tool()-decorated functions instead of serving them."""

    def __init__(self):
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco

    def custom_route(self, *a, **k):  # pragma: no cover - not used in tests
        def deco(fn):
            return fn
        return deco


def _config(**kw):
    base = dict(tenant_id=TENANT, client_id="app-client-id",
                client_secret="the-secret", verify_ssl=False)
    base.update(kw)
    return EntraIDConfig(**base)


def _setup(responses=None, seed_token=False, **cfg_kw):
    """Build the tool set with a captured tool registry and a fake transport."""
    cfg = _config(**cfg_kw)
    client = get_client(cfg)
    client._session = FakeSession(responses=responses)
    client._access_token = "seeded-access" if seed_token else ""
    client._expires_at = (time.time() + 3600) if seed_token else 0.0
    mcp = FakeMCP()
    signin_tools.register(mcp, cfg)
    audit_tools.register(mcp, cfg)
    risky_tools.register(mcp, cfg)
    user_tools.register(mcp, cfg)
    response_tools.register(mcp, cfg)
    api_tools.register(mcp, cfg)
    return cfg, client, mcp


# ------------------------------------------------------------------- config
class TestConfig(unittest.TestCase):
    def test_redacted_hides_secret(self):
        cfg = _config(mcp_auth_token="bearer")
        red = cfg.redacted()
        self.assertEqual(red["client_secret"], "***REDACTED***")
        self.assertEqual(red["mcp_auth_token"], "***REDACTED***")
        self.assertNotIn("the-secret", str(red))
        self.assertEqual(red["tenant_id"], TENANT)

    def test_incomplete_raises(self):
        import os
        for k in ("ENTRAID_TENANT_ID", "ENTRAID_CLIENT_ID", "ENTRAID_CLIENT_SECRET"):
            os.environ.pop(k, None)
        with self.assertRaises(ConfigError):
            load_config(tenant_id="", client_id="", client_secret="")

    def test_token_url(self):
        cfg = _config(authority_host="https://login.microsoftonline.us")
        self.assertEqual(
            cfg.token_url(),
            f"https://login.microsoftonline.us/{TENANT}/oauth2/v2.0/token")


# --------------------------------------------------------------- validation
class TestValidation(unittest.TestCase):
    def test_guid(self):
        self.assertEqual(c.validate_guid(GUID), GUID)
        with self.assertRaises(ValueError):
            c.validate_guid("not-a-guid")

    def test_user_ref_accepts_upn_and_guid(self):
        self.assertEqual(c.validate_user_ref(GUID), GUID)
        self.assertEqual(c.validate_user_ref("jdoe@contoso.com"),
                         "jdoe%40contoso.com")

    def test_user_ref_rejects_junk(self):
        for bad in ("", "bad name", "a/b", "no-at-sign"):
            with self.assertRaises(ValueError):
                c.validate_user_ref(bad)

    def test_normalize_iso(self):
        self.assertEqual(c.normalize_iso("2026-09-01"), "2026-09-01T00:00:00Z")
        self.assertEqual(c.normalize_iso("2026-09-01T05:00:00Z"),
                         "2026-09-01T05:00:00Z")
        with self.assertRaises(ValueError):
            c.normalize_iso("yesterday")

    def test_odata_quote_escapes(self):
        self.assertEqual(c.odata_quote("O'Brien"), "'O''Brien'")


# ---------------------------------------------------------------- sign-ins
class TestSignins(unittest.TestCase):
    def test_list_sign_ins_builds_filter_and_select(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": []})])
        out = mcp.tools["list_sign_ins"](
            user_principal_name="jdoe@contoso.com", error_code=50126,
            conditional_access_status="failure", created_after="2026-09-01")
        req = client._session.requests[0]
        self.assertEqual(req["method"], "GET")
        self.assertTrue(req["url"].endswith("/auditLogs/signIns"))
        self.assertEqual(
            req["params"]["$filter"],
            "userPrincipalName eq 'jdoe@contoso.com' and status/errorCode eq 50126 "
            "and conditionalAccessStatus eq 'failure' "
            "and createdDateTime ge 2026-09-01T00:00:00Z")
        self.assertIn("deviceDetail", req["params"]["$select"])
        self.assertEqual(out["count"], 0)

    def test_list_sign_ins_sorts_newest_first(self):
        payload = {"value": [
            {"id": GUID, "createdDateTime": "2026-09-01T00:00:00Z"},
            {"id": GUID, "createdDateTime": "2026-09-10T00:00:00Z"},
        ]}
        cfg, client, mcp = _setup(responses=[FakeResponse(200, payload)])
        out = mcp.tools["list_sign_ins"]()
        self.assertEqual(out["sign_ins"][0]["created_date_time"],
                         "2026-09-10T00:00:00Z")

    def test_get_sign_in_uses_id_filter_and_summarizes(self):
        event = {
            "id": GUID,
            "createdDateTime": "2026-09-10T12:00:00Z",
            "userPrincipalName": "jdoe@contoso.com",
            "conditionalAccessStatus": "failure",
            "appliedConditionalAccessPolicies": [
                {"displayName": "Require MFA", "result": "failure"}],
            "location": {"city": "Detroit", "countryOrRegion": "US",
                         "geoCoordinates": {"latitude": 42.3, "longitude": -83.0}},
            "deviceDetail": {"operatingSystem": "Windows 11", "browser": "Edge",
                             "isCompliant": True, "isManaged": True,
                             "trustType": "AzureAD"},
            "status": {"errorCode": 53003, "failureReason": "Blocked by CA"},
            "mfaDetail": {"authMethod": "PhoneAppNotification"},
        }
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": [event]})])
        out = mcp.tools["get_sign_in"](GUID)
        req = client._session.requests[0]
        self.assertEqual(req["params"]["$filter"], f"id eq '{GUID}'")
        self.assertTrue(out["found"])
        self.assertEqual(out["summary"]["location"]["city"], "Detroit")
        self.assertEqual(out["summary"]["device_detail"]["operating_system"],
                         "Windows 11")
        self.assertEqual(
            out["summary"]["applied_conditional_access_policies"][0]["display_name"],
            "Require MFA")
        self.assertEqual(out["summary"]["error_code"], 53003)

    def test_list_user_sign_ins_by_upn(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": []})])
        mcp.tools["list_user_sign_ins"]("jdoe@contoso.com")
        req = client._session.requests[0]
        self.assertEqual(req["params"]["$filter"],
                         "userPrincipalName eq 'jdoe@contoso.com'")


# ------------------------------------------------------------------ audits
class TestAudits(unittest.TestCase):
    def test_list_directory_audits_builds_filter(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": []})])
        mcp.tools["list_directory_audits"](
            category="RoleManagement", result="success",
            target_id=GUID, created_after="2026-09-01")
        req = client._session.requests[0]
        self.assertTrue(req["url"].endswith("/auditLogs/directoryAudits"))
        self.assertEqual(
            req["params"]["$filter"],
            "category eq 'RoleManagement' and targetResources/any(t:t/id eq "
            f"'{GUID}') and result eq 'success' and activityDateTime ge "
            "2026-09-01T00:00:00Z")

    def test_list_user_audits_actor_or_target(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": []})])
        mcp.tools["list_user_audits"]("jdoe@contoso.com")
        req = client._session.requests[0]
        self.assertEqual(
            req["params"]["$filter"],
            "(initiatedBy/user/userPrincipalName eq 'jdoe@contoso.com' or "
            "targetResources/any(t:t/userPrincipalName eq 'jdoe@contoso.com'))")

    def test_get_directory_audit_summarizes(self):
        event = {
            "id": GUID, "activityDateTime": "2026-09-10T12:00:00Z",
            "activityDisplayName": "Add member to role", "category": "RoleManagement",
            "result": "success", "loggedByService": "Core Directory",
            "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com",
                                     "displayName": "Admin"}},
            "targetResources": [{"id": GUID, "displayName": "Global Administrator",
                                 "type": "Role",
                                 "modifiedProperties": [
                                     {"displayName": "Role.DisplayName",
                                      "oldValue": None, "newValue": "Global Admin"}]}],
        }
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": [event]})])
        out = mcp.tools["get_directory_audit"](GUID)
        self.assertEqual(out["summary"]["initiated_by"]["user_principal_name"],
                         "admin@contoso.com")
        self.assertEqual(out["summary"]["target_resources"][0]["display_name"],
                         "Global Administrator")


# ------------------------------------------------------- identity protection
class TestRisky(unittest.TestCase):
    def test_list_risky_users_filter(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": []})])
        mcp.tools["list_risky_users"](risk_state="atRisk", risk_level="high")
        req = client._session.requests[0]
        self.assertTrue(req["url"].endswith("/identityProtection/riskyUsers"))
        self.assertEqual(req["params"]["$filter"],
                         "riskState eq 'atRisk' and riskLevel eq 'high'")

    def test_risky_user_history_path(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": []})])
        mcp.tools["get_risky_user_history"](GUID)
        self.assertTrue(client._session.requests[0]["url"].endswith(
            f"/identityProtection/riskyUsers/{GUID}/history"))

    def test_dismiss_risky_user_posts_body(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {})])
        out = mcp.tools["dismiss_risky_user"](GUID)
        req = client._session.requests[0]
        self.assertEqual(req["method"], "POST")
        self.assertTrue(req["url"].endswith(
            "/identityProtection/riskyUsers/dismiss"))
        self.assertEqual(req["json"], {"userIds": [GUID]})
        self.assertEqual(out["result"], "dismissed")

    def test_confirm_compromised_posts_body(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {})])
        mcp.tools["confirm_risky_user_compromised"](GUID)
        req = client._session.requests[0]
        self.assertTrue(req["url"].endswith(
            "/identityProtection/riskyUsers/confirmCompromised"))
        self.assertEqual(req["json"], {"userIds": [GUID]})

    def test_dismiss_resolves_upn_to_id(self):
        cfg, client, mcp = _setup(responses=[
            FakeResponse(200, {"value": [{"id": GUID,
                                          "userPrincipalName": "jdoe@contoso.com"}]}),
            FakeResponse(200, {}),
        ])
        out = mcp.tools["dismiss_risky_user"]("jdoe@contoso.com")
        self.assertEqual(out["user_id"], GUID)
        self.assertTrue(client._session.requests[1]["url"].endswith("/dismiss"))

    def test_list_risk_detections_filter(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": []})])
        mcp.tools["list_risk_detections"](
            risk_event_type="leakedCredentials", detected_after="2026-09-01")
        req = client._session.requests[0]
        self.assertTrue(req["url"].endswith("/identityProtection/riskDetections"))
        self.assertEqual(
            req["params"]["$filter"],
            "riskEventType eq 'leakedCredentials' and detectedDateTime ge "
            "2026-09-01T00:00:00Z")


# ------------------------------------------------------------------- users
class TestUsers(unittest.TestCase):
    def test_get_user_path_and_select(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"id": GUID})])
        mcp.tools["get_user"]("jdoe@contoso.com")
        req = client._session.requests[0]
        self.assertTrue(req["url"].endswith("/users/jdoe%40contoso.com"))
        self.assertIn("displayName", req["params"]["$select"])

    def test_directory_roles_uses_cast_segment(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": []})])
        mcp.tools["get_user_directory_roles"](GUID)
        self.assertTrue(client._session.requests[0]["url"].endswith(
            f"/users/{GUID}/transitiveMemberOf/microsoft.graph.directoryRole"))

    def test_oauth2_grants_parses_scopes(self):
        payload = {"value": [{"id": "g1", "resourceId": "r1", "clientId": "c1",
                              "scope": "Mail.Read User.Read"}]}
        cfg, client, mcp = _setup(responses=[FakeResponse(200, payload)])
        out = mcp.tools["get_user_oauth2_grants"](GUID)
        self.assertEqual(out["oauth2_grants"][0]["scopes"],
                         ["Mail.Read", "User.Read"])

    def test_authentication_methods_path(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": []})])
        mcp.tools["get_user_authentication_methods"](GUID)
        self.assertTrue(client._session.requests[0]["url"].endswith(
            f"/users/{GUID}/authentication/methods"))


# ------------------------------------------------------------------ tokens
class TestTokenFlow(unittest.TestCase):
    def test_401_remints_and_retries_once(self):
        cfg, client, mcp = _setup(seed_token=True, responses=[
            FakeResponse(401, {"error": {"code": "InvalidAuthenticationToken",
                                          "message": "Access token has expired"}}),
            FakeResponse(200, {"value": [{"id": GUID,
                                          "createdDateTime": "2026-09-10T00:00:00Z"}]}),
        ])
        out = mcp.tools["list_sign_ins"]()
        self.assertEqual(out["count"], 1)
        self.assertEqual(len(client._session.requests), 2)
        self.assertTrue(client._session.posts)  # re-minted

    def test_403_permission_fails_fast(self):
        cfg, client, mcp = _setup(responses=[
            FakeResponse(403, {"error": {"code": "Authorization_RequestDenied",
                                         "message": "Insufficient privileges to complete the operation."}}),
        ])
        with self.assertRaises(EntraIDError) as ctx:
            mcp.tools["list_sign_ins"]()
        self.assertIn("permission", str(ctx.exception).lower())
        self.assertEqual(len(client._session.requests), 1)

    def test_token_email_style_error_surfaced(self):
        client = EntraIDClient(_config(client_secret="wrong"))
        client._session = FakeSession()
        client._session.post = lambda *a, **k: FakeResponse(
            401, {"error": "invalid_client",
                  "error_description": "AADSTS7000215: Invalid client secret provided."})
        with self.assertRaises(EntraIDError) as ctx:
            client.authenticate()
        self.assertIn("AADSTS7000215", str(ctx.exception))

    def test_token_is_cached(self):
        cfg, client, mcp = _setup(responses=[FakeResponse(200, {"value": []})])
        client.ensure_token()
        client.ensure_token()
        self.assertEqual(len(client._session.posts), 1)

    def test_token_post_uses_form_content_type(self):
        # Regression: a session-level Content-Type of application/json leaking
        # onto the form-encoded token POST made Entra return AADSTS9000410
        # "Malformed JSON". The token request must set the form content type.
        cfg, client, mcp = _setup()
        client.authenticate()
        headers = client._session.posts[0]["headers"] or {}
        self.assertEqual(headers.get("Content-Type"),
                         "application/x-www-form-urlencoded")


# ------------------------------------------------------------- url vetting
class TestUrlVetting(unittest.TestCase):
    def test_rejects_foreign_absolute_url(self):
        client = EntraIDClient(_config())
        with self.assertRaises(EntraIDError):
            client.get("https://evil.example.com/v1.0/users")

    def test_allows_graph_absolute_url(self):
        client = EntraIDClient(_config())
        url = client._url("https://graph.microsoft.com/v1.0/users")
        self.assertEqual(url, "https://graph.microsoft.com/v1.0/users")

    def test_pagination_follows_nextlink(self):
        pages = [
            FakeResponse(200, {"value": [{"id": "a"}],
                               "@odata.nextLink":
                                   "https://graph.microsoft.com/v1.0/next"}),
            FakeResponse(200, {"value": [{"id": "b"}]}),
        ]
        cfg, client, mcp = _setup(responses=pages)
        out = mcp.tools["list_sign_ins"](max_pages=2)
        self.assertEqual(len(client._session.requests), 2)
        self.assertEqual(out["count"], 2)

    def test_escape_hatch_accepts_relative_path(self):
        cfg, client, mcp = _setup(responses=[
            FakeResponse(200, {"value": []})])
        mcp.tools["entra_api_get"]("/identity/conditionalAccess/policies")
        self.assertTrue(client._session.requests[0]["url"].endswith(
            "/identity/conditionalAccess/policies"))

    def test_escape_hatch_rejects_absolute_and_scheme(self):
        cfg, client, mcp = _setup()
        for bad in ("https://graph.microsoft.com/v1.0/users",
                    "//graph.microsoft.com/users", "users"):
            with self.assertRaises(ValueError):
                mcp.tools["entra_api_get"](bad)

    def test_escape_hatch_rejects_bad_params_json(self):
        cfg, client, mcp = _setup()
        with self.assertRaises(ValueError):
            mcp.tools["entra_api_get"]("/users", "{not json}")


if __name__ == "__main__":
    unittest.main(verbosity=2)