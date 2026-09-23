"""Entra ID (Microsoft Graph) MCP server.

Exposes Microsoft Entra ID security-investigation tools over the Model Context
Protocol using FastMCP: sign-in logs, directory audit logs, Identity Protection
(risky users, risk detections), a user's permissions/access (group + directory
role membership, enterprise-app role assignments and OAuth2 delegated grants,
registered authentication methods) and full activity detail for a single
sign-in (conditional-access policies applied, location, device, MFA, risk).
"""

__version__ = "0.1.0"