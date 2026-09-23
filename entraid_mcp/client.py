"""Thin REST client for Microsoft Graph (Entra ID) security APIs.

Authentication is OAuth2 **client credentials** (app-only). The client mints an
application access token from the tenant id + app (client) id + client secret
at ``https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`` with scope
``https://graph.microsoft.com/.default``. Client-credentials tokens carry **no
refresh token**, so a lapsed token is simply re-minted from the same
credentials.

Token / error rules implemented here:
  * Only an *expired* access token is a 401 worth retrying: on a 401 we re-mint
    once and retry the request at most once -- never in a loop.
  * A 403 (or an ``Authorization_RequestDenied`` / ``Insufficient privileges``
    body) is a *permissions* problem, not expiry: re-minting cannot add a scope,
    so we fail fast with a message naming the required application permission.

No secret is ever logged. Errors keep Graph's own ``error.code`` /
``error.message`` strings verbatim so a caller can act on the real message.

Graph conventions:
  * Collection responses are ``{"value": [...], "@odata.nextLink": "..."}``;
    ``nextLink`` is an absolute URL that already carries the paging state, so
    page walkers follow it directly.
  * ``$filter`` / ``$top`` are supported on the audit and identity-protection
    collections; ``$orderby`` is not, so tools sort locally.

See https://learn.microsoft.com/graph/api/resources/azure-ad-auditlog-overview
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import requests

from .config import EntraIDConfig


class EntraIDError(Exception):
    """Raised for Graph/token errors, carrying status + parsed detail."""

    def __init__(self, status: Optional[int], message: str, detail: Any = None,
                 error_code: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.detail = detail
        self.error_code = error_code

    def __repr__(self) -> str:  # pragma: no cover - helper
        return (f"EntraIDError(status={self.status}, "
                f"error_code={self.error_code!r}, message={self.message!r})")


class EntraIDClient:
    """Stateful client bound to one Entra ID tenant/app config."""

    GRANT_CLIENT_CREDENTIALS = "client_credentials"
    MAX_RETRIES = 3
    RATE_LIMIT_MIN_BACKOFF = 1.0
    RATE_LIMIT_MAX_BACKOFF = 20.0
    # Renew this many seconds before the stated expiry to avoid a race.
    TOKEN_SKEW_SECONDS = 60
    # Substrings that indicate an authorization (permission) problem rather than
    # an expired token.
    _PERMISSION_HINTS = ("authorization_requestdenied", "insufficient privileges",
                         "insufficientprivileges", "forbidden", "access denied",
                         "does not have")

    def __init__(self, config: EntraIDConfig):
        self.config = config
        self.base_url = config.resolved_base_url()
        self.verify_ssl = config.verify_ssl
        self.timeout = config.timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self._access_token = ""
        self._expires_at = 0.0
        self._token_info: Dict[str, Any] = {}
        self._token_lock = threading.Lock()

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _parse(resp: requests.Response) -> Any:
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    @staticmethod
    def _detail_str(detail: Any) -> str:
        return json.dumps(detail) if isinstance(detail, (dict, list)) else str(detail)

    @staticmethod
    def _graph_error(body: Any) -> Tuple[Optional[str], Optional[str]]:
        """Extract (code, message) from a Graph error envelope."""
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            err = body["error"]
            return err.get("code"), err.get("message")
        if isinstance(body, dict):
            return body.get("code"), body.get("message")
        return None, None

    def _looks_like_permission_error(self, body: Any) -> bool:
        code, message = self._graph_error(body)
        text = f"{code} {message} {self._detail_str(body)}".lower()
        return any(h in text for h in self._PERMISSION_HINTS)

    # ------------------------------------------------------------------ token
    def _store_token(self, payload: Dict[str, Any]) -> None:
        self._access_token = payload.get("access_token", "") or self._access_token
        try:
            expires_in = int(payload.get("expires_in"))
        except (TypeError, ValueError):
            expires_in = 3599
        self._expires_at = time.time() + max(0, expires_in)
        self._token_info = {
            "token_type": payload.get("token_type"),
            "expires_in": expires_in,
            "scope": payload.get("scope"),
        }

    def authenticate(self) -> Dict[str, Any]:
        """Mint a fresh app access token via the client-credentials grant."""
        if not (self.config.tenant_id and self.config.client_id
                and self.config.client_secret):
            raise EntraIDError(
                None,
                "Cannot authenticate: missing tenant_id/client_id/client_secret. "
                "Set the ENTRAID_* env vars or run `entraid config init`.",
            )
        resp = self._session.post(
            self.config.token_url(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": self.GRANT_CLIENT_CREDENTIALS,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "scope": self.config.scope,
            },
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        body = self._parse(resp)
        if resp.status_code < 200 or resp.status_code >= 300:
            code = body.get("error") if isinstance(body, dict) else None
            desc = None
            if isinstance(body, dict):
                desc = body.get("error_description") or body.get("error")
            raise EntraIDError(
                resp.status_code,
                f"Entra ID token error {resp.status_code} ({code}): "
                f"{desc or self._detail_str(body)}",
                body, code,
            )
        if not isinstance(body, dict) or not body.get("access_token"):
            raise EntraIDError(
                resp.status_code,
                "Entra ID token endpoint returned no access_token: "
                + self._detail_str(body),
                body,
            )
        self._store_token(body)
        return body

    def _token_valid(self) -> bool:
        return bool(self._access_token) and time.time() < (
            self._expires_at - self.TOKEN_SKEW_SECONDS)

    def ensure_token(self) -> str:
        """Return a usable access token, minting one if needed."""
        with self._token_lock:
            if self._token_valid():
                return self._access_token
            self.authenticate()
            return self._access_token

    def token_info(self) -> Dict[str, Any]:
        """Return redacted metadata about the current token (never the token)."""
        return dict(self._token_info)

    # ---------------------------------------------------------------- request
    def _url(self, path: str) -> str:
        """Resolve a relative Graph path, or vet an absolute (nextLink) URL.

        An absolute URL is accepted only when it targets this client's Graph
        origin -- so a caller-supplied ``https://evil.example/...`` can never
        receive the bearer token.
        """
        if path.startswith("http://") or path.startswith("https://"):
            parts = urlsplit(self.base_url)
            origin = f"{parts.scheme}://{parts.netloc}"
            if not path.startswith(origin + "/"):
                raise EntraIDError(
                    None,
                    f"Refusing to call a non-Graph URL: {path!r} "
                    f"(expected it to start with {origin}/).",
                )
            return path
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base_url}{path}"

    def _request(self, method: str, path: str, *,
                 params: Optional[Dict[str, Any]] = None,
                 json_body: Any = None,
                 _renewed: bool = False) -> requests.Response:
        url = self._url(path)
        token = self.ensure_token()
        headers = {"Authorization": f"Bearer {token}"}
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}

        resp = None
        attempt = 0
        while True:
            attempt += 1
            resp = self._session.request(
                method, url, params=clean_params or None, json=json_body,
                headers=headers, timeout=self.timeout, verify=self.verify_ssl,
            )
            if resp.status_code != 429:
                break
            if attempt >= self.MAX_RETRIES:
                break
            wait = self.RATE_LIMIT_MIN_BACKOFF * (2 ** (attempt - 1))
            if "Retry-After" in resp.headers:
                try:
                    wait = max(wait, float(resp.headers["Retry-After"]))
                except ValueError:
                    pass
            time.sleep(min(wait, self.RATE_LIMIT_MAX_BACKOFF))

        if resp.status_code == 429:
            raise EntraIDError(
                429,
                f"Microsoft Graph rate limit exceeded for {url} (retried "
                f"{self.MAX_RETRIES} times). Wait and retry.",
            )

        if resp.status_code == 401 and not _renewed:
            detail = self._parse(resp)
            # A permission failure masquerading as 401 is permanent for this
            # app: re-minting keeps the same roles, so fail fast.
            if self._looks_like_permission_error(detail):
                code, message = self._graph_error(detail)
                raise EntraIDError(
                    401,
                    f"Entra ID authorization failed for {url}: {message or code}. "
                    "The app registration is missing a required Microsoft Graph "
                    "application permission (and admin consent); grant it in the "
                    "Entra admin center and restart the server.",
                    detail, code,
                )
            # Otherwise the app access token lapsed: re-mint once, retry once.
            with self._token_lock:
                self.authenticate()
            return self._request(method, path, params=params,
                                 json_body=json_body, _renewed=True)

        if resp.status_code < 200 or resp.status_code >= 300:
            body = self._parse(resp)
            code, message = self._graph_error(body)
            hint = ""
            if resp.status_code in (401, 403) and self._looks_like_permission_error(body):
                hint = (
                    " This is a Microsoft Graph permissions problem: the app "
                    "registration needs the corresponding application permission "
                    "with admin consent; re-run the permission grant and restart."
                )
            raise EntraIDError(
                resp.status_code,
                f"Microsoft Graph {resp.status_code} for {url}: "
                f"{message or code or self._detail_str(body)}.{hint}",
                body, code,
            )
        return resp

    # --------------------------------------------------------- convenience API
    def get(self, path: str, *, params: Optional[Dict[str, Any]] = None) -> Any:
        return self._parse(self._request("GET", path, params=params))

    def post(self, path: str, json_body: Any = None, *,
             params: Optional[Dict[str, Any]] = None) -> Any:
        return self._parse(self._request("POST", path, params=params,
                                         json_body=json_body))

    # ------------------------------------------------------------- pagination
    @staticmethod
    def unwrap(data: Any, key: str = "value") -> List[Any]:
        """Return the items list from a Graph ``{"value": [...]}`` envelope."""
        if isinstance(data, dict):
            value = data.get(key)
            if isinstance(value, list):
                return value
            if value is None:
                return []
            return [value]
        if isinstance(data, list):
            return data
        return [data] if data else []

    @staticmethod
    def next_link(data: Any) -> Optional[str]:
        if isinstance(data, dict):
            nxt = data.get("@odata.nextLink") or data.get("odata.nextLink")
            if isinstance(nxt, str) and nxt:
                return nxt
        return None

    def collect(self, path: str, *, params: Optional[Dict[str, Any]] = None,
                max_pages: int = 1) -> Tuple[List[Any], Optional[str]]:
        """Fetch up to ``max_pages`` pages, following ``@odata.nextLink``.

        Returns ``(items, next_link)`` where ``next_link`` is non-None only when
        more results exist beyond the pages fetched.
        """
        items: List[Any] = []
        batch = self.get(path, params=params)
        pages = 0
        next_link = None
        while True:
            items.extend(self.unwrap(batch))
            pages += 1
            next_link = self.next_link(batch)
            if not next_link or pages >= max(1, int(max_pages)):
                break
            batch = self.get(next_link)
        return items, next_link

    def test_connection(self) -> Dict[str, Any]:
        """Authenticate and probe Graph; never includes secrets."""
        try:
            token = self.ensure_token()
            info = self.token_info()
            org = self.get("/organization", params={"$top": 1,
                                                    "$select": "id,displayName"})
        except EntraIDError as exc:
            return {
                "connected": False,
                "base_url": self.base_url,
                "tenant_id": self.config.tenant_id,
                "error": exc.message,
                "error_code": exc.error_code,
            }
        orgs = self.unwrap(org)
        first = orgs[0] if orgs and isinstance(orgs[0], dict) else {}
        return {
            "connected": True,
            "base_url": self.base_url,
            "tenant_id": self.config.tenant_id,
            "token_present": bool(token),
            "token_scope": info.get("scope"),
            "organization_id": first.get("id"),
            "organization_name": first.get("displayName"),
        }


# Registry so tools share one client per config (keyed by a secret-free id).
_client_registry: Dict[str, EntraIDClient] = {}
_client_registry_lock = threading.Lock()


def _client_key(config: EntraIDConfig) -> str:
    return f"{config.resolved_base_url()}|{config.tenant_id}|{config.client_id}"


def get_client(config: EntraIDConfig) -> EntraIDClient:
    key = _client_key(config)
    with _client_registry_lock:
        client = _client_registry.get(key)
        if client is None or client.config != config:
            client = EntraIDClient(config)
            _client_registry[key] = client
        return client


def clear_client(key: str) -> None:
    """Drop a cached client (used on shutdown)."""
    with _client_registry_lock:
        for k in list(_client_registry):
            if k == key or k.endswith(key):
                _client_registry.pop(k, None)