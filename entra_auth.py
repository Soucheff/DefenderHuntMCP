import asyncio
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import jwt
from jwt import PyJWKClient

from auth_context import RequestIdentity

SigningKeyResolver = Callable[[str], Awaitable[object]]


class AuthenticationError(Exception):
    """Raised when an inbound Entra access token cannot be trusted."""


@dataclass(frozen=True, slots=True)
class EntraAuthSettings:
    tenant_id: str
    audience: str
    issuer: str
    required_user_scope: str = "Mcp.Access"
    required_agent_role: str = "Mcp.Invoke"
    agent_client_ids: frozenset[str] = frozenset()

    @classmethod
    def from_environment(cls) -> "EntraAuthSettings":
        tenant_id = os.getenv("AZURE_TENANT_ID", "")
        audience = os.getenv("ENTRA_MCP_AUDIENCE") or os.getenv("AZURE_CLIENT_ID", "")
        issuer = os.getenv("ENTRA_MCP_ISSUER") or (
            f"https://login.microsoftonline.com/{tenant_id}/v2.0" if tenant_id else ""
        )
        if not tenant_id or not audience or not issuer:
            raise ValueError(
                "AZURE_TENANT_ID and ENTRA_MCP_AUDIENCE (or AZURE_CLIENT_ID) are required"
            )
        return cls(
            tenant_id=tenant_id,
            audience=audience,
            issuer=issuer,
            required_user_scope=os.getenv("ENTRA_MCP_USER_SCOPE", "Mcp.Access"),
            required_agent_role=os.getenv("ENTRA_MCP_AGENT_ROLE", "Mcp.Invoke"),
            agent_client_ids=frozenset(
                client_id.strip()
                for client_id in os.getenv("ENTRA_AGENT_CLIENT_IDS", "").split(",")
                if client_id.strip()
            ),
        )


class EntraTokenValidator:
    def __init__(
        self,
        settings: EntraAuthSettings,
        signing_key_resolver: SigningKeyResolver | None = None,
    ) -> None:
        self.settings = settings
        self._jwks_client = PyJWKClient(
            f"https://login.microsoftonline.com/{settings.tenant_id}/discovery/v2.0/keys",
            cache_keys=True,
            lifespan=3600,
        )
        self._signing_key_resolver = signing_key_resolver or self._resolve_signing_key

    async def validate(self, token: str) -> RequestIdentity:
        try:
            signing_key = await self._signing_key_resolver(token)
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self.settings.audience,
                issuer=self.settings.issuer,
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "tid"]},
            )
        except Exception as error:
            raise AuthenticationError("Invalid bearer token") from error

        if claims.get("tid") != self.settings.tenant_id:
            raise AuthenticationError("Token tenant is not allowed")

        scopes = frozenset(filter(None, str(claims.get("scp", "")).split()))
        roles = frozenset(str(role) for role in claims.get("roles", []))
        subject_id = str(claims.get("oid") or claims.get("sub") or "")
        client_id = str(claims.get("azp") or claims.get("appid") or "")
        if not subject_id or not client_id:
            raise AuthenticationError("Token identity claims are incomplete")

        if scopes:
            if self.settings.required_user_scope not in scopes:
                raise AuthenticationError("Required delegated scope is missing")
            is_delegated_agent = client_id in self.settings.agent_client_ids
            return RequestIdentity(
                tenant_id=self.settings.tenant_id,
                actor_type="delegated_agent" if is_delegated_agent else "user",
                subject_id=subject_id,
                client_id=client_id,
                agent_id=client_id if is_delegated_agent else None,
                scopes=scopes,
                roles=roles,
                user_assertion=token,
            )

        if self.settings.required_agent_role not in roles:
            raise AuthenticationError("Required application role is missing")
        is_autonomous_agent = client_id in self.settings.agent_client_ids
        return RequestIdentity(
            tenant_id=self.settings.tenant_id,
            actor_type="autonomous_agent",
            subject_id=subject_id,
            client_id=client_id,
            agent_id=client_id if is_autonomous_agent else None,
            scopes=scopes,
            roles=roles,
        )

    async def _resolve_signing_key(self, token: str) -> object:
        signing_key = await asyncio.to_thread(self._jwks_client.get_signing_key_from_jwt, token)
        return signing_key.key
